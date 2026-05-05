// SocketCAN.cpp — CANdle-SDK SocketCAN transport backend (Phase 07.1 D-02)
//
// See SocketCAN.hpp for architectural contract and pitfall mitigations.
//
// Envelope strip pattern (load-bearing, from RESEARCH.md Q1):
//
//   The Candle class never hands down raw CAN frames. It ALWAYS prepends the
//   USB-dongle 5-byte header before calling m_bus->transfer():
//
//     {GENERIC_CAN_FRAME=4, u8(payload_len + 2), timeout_u8,
//      u8(canId), u8(canId >> 8), payload[0..N-1]}
//
//   (The "+2" in the length field accounts for the two CAN-ID bytes that are
//    counted as part of the "data" from the USB dongle's perspective.)
//
//   This backend STRIPS that header and reconstructs the raw canfd_frame:
//
//     canfd_frame.can_id = data[ENV_ID_LO] | (data[ENV_ID_HI] << 8)
//     canfd_frame.len    = data[ENV_LEN] - 2   (subtract the 2 id bytes)
//     canfd_frame.flags  = CANFD_BRS            (bit-rate switch for FD data phase)
//     canfd_frame.data   = data[ENV_PAYLOAD ..]
//
//   The synthetic CANDLE_CONFIG_DATARATE response:
//     legacyCheckConnection() sends {cmd=2, datarate_enum, useRegularCanFrames}
//     and reads back 6 bytes. The USB dongle returns a 6-byte ACK. SocketCAN
//     has no counterpart; we return {0,0,0,0,0,0} which passes the SDK's
//     busTransfer() error check (return OK).
//
//   The receive packing contract (Candle::transferCANFrame at candle.cpp:259):
//     buffer.at(1) != 0x01 → CAN_DEVICE_NOT_RESPONDING
//     So response must be {0x00, 0x01, rxf.data[0..N-1], zeros...}
//
// Platform: Linux only (AF_CAN kernel subsystem).

#ifndef WIN32

#include <cerrno>
#include <cstring>
#include <thread>
#include <chrono>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "I_communication_interface.hpp"
#include "logger.hpp"
#include "SocketCAN.hpp"

namespace mab
{

// ─────────────────────────────────────────────────────────────────────────────
// Construction / Destruction
// ─────────────────────────────────────────────────────────────────────────────

SocketCAN::SocketCAN(std::string_view ifname) : m_ifname(ifname)
{
}

SocketCAN::SocketCAN(std::string_view ifname, std::optional<canId_t> filter_id)
    : m_ifname(ifname), m_filter_id(filter_id)
{
}

SocketCAN::~SocketCAN()
{
    disconnect();
}

// ─────────────────────────────────────────────────────────────────────────────
// connect()
// ─────────────────────────────────────────────────────────────────────────────

I_CommunicationInterface::Error_t SocketCAN::connect()
{
    m_logger.info("SocketCAN: connecting to interface '%s'", m_ifname.c_str());

    // Step 1: Create AF_CAN raw socket.
    m_sockfd = socket(AF_CAN, SOCK_RAW, CAN_RAW);
    if (m_sockfd < 0)
    {
        m_logger.error("SocketCAN: socket() failed: %s", strerror(errno));
        m_sockfd = -1;
        return Error_t::INITIALIZATION_ERROR;
    }

    // Step 2: Enable CAN-FD frames (required for CANFD_BRS + 64-byte payloads).
    int enable = 1;
    if (setsockopt(m_sockfd, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable, sizeof(enable)) < 0)
    {
        m_logger.error("SocketCAN: CAN_RAW_FD_FRAMES setsockopt failed: %s", strerror(errno));
        close(m_sockfd);
        m_sockfd = -1;
        return Error_t::INITIALIZATION_ERROR;
    }

    // Step 3: Look up interface index + MTU (Pitfall 1: interface must be UP).
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, m_ifname.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(m_sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        m_logger.error("SocketCAN: SIOCGIFINDEX failed for '%s': %s",
                       m_ifname.c_str(), strerror(errno));
        close(m_sockfd);
        m_sockfd = -1;
        return Error_t::INITIALIZATION_ERROR;
    }
    const int ifindex = ifr.ifr_ifindex;

    // Step 4: MTU check — reject classic CAN (mtu=16) (Pitfall 2).
    if (ioctl(m_sockfd, SIOCGIFMTU, &ifr) < 0)
    {
        m_logger.error("SocketCAN: SIOCGIFMTU failed for '%s': %s",
                       m_ifname.c_str(), strerror(errno));
        close(m_sockfd);
        m_sockfd = -1;
        return Error_t::INITIALIZATION_ERROR;
    }
    if (ifr.ifr_mtu < MIN_FD_MTU)
    {
        m_logger.error("SocketCAN: interface '%s' MTU=%d < %d — not CAN-FD capable. "
                       "Run: ip link set %s mtu 72",
                       m_ifname.c_str(), ifr.ifr_mtu, MIN_FD_MTU, m_ifname.c_str());
        close(m_sockfd);
        m_sockfd = -1;
        return Error_t::INITIALIZATION_ERROR;
    }

    // Step 5: Bind to named interface.
    struct sockaddr_can addr{};
    addr.can_family   = AF_CAN;
    addr.can_ifindex  = ifindex;
    if (bind(m_sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        m_logger.error("SocketCAN: bind() failed for '%s': %s",
                       m_ifname.c_str(), strerror(errno));
        close(m_sockfd);
        m_sockfd = -1;
        return Error_t::INITIALIZATION_ERROR;
    }

    // Step 6: Suppress loopback (we don't want to receive our own TX frames).
    // CAN_RAW_LOOPBACK is on by default; suppress to avoid confusing recvfrom.
    int loopback = 0;
    setsockopt(m_sockfd, SOL_CAN_RAW, CAN_RAW_LOOPBACK, &loopback, sizeof(loopback));

    // Step 7: Phase 07.1.3 D-11 — apply optional per-socket motor_id filter.
    // When the constructor was given filter_id (approach b2 per-motor sockets),
    // call set_can_id_filter now (post-bind, post-RAW_FD_FRAMES). Failure here
    // is fatal: close the socket and return error so the caller does not get
    // a half-initialized fd that delivers cross-talk frames.
    if (m_filter_id.has_value())
    {
        const Error_t fe = set_can_id_filter(*m_filter_id);
        if (fe != Error_t::OK)
        {
            m_logger.error("SocketCAN: optional ctor filter setup failed for motor_id=0x%X — closing socket",
                           static_cast<unsigned>(*m_filter_id));
            close(m_sockfd);
            m_sockfd = -1;
            return fe;
        }
    }

    m_logger.info("SocketCAN: connected to '%s' (ifindex=%d, mtu=%d)",
                  m_ifname.c_str(), ifindex, ifr.ifr_mtu);
    return Error_t::OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// set_can_id_filter() — Phase 07.1.3 D-11 approach b2 per-socket motor_id filter
// ─────────────────────────────────────────────────────────────────────────────
//
// Applies a single-motor CAN_RAW_FILTER on the socket so the kernel only delivers
// frames whose can_id matches @p motor_id (mask = CAN_SFF_MASK = 0x7FF, 11-bit
// standard CAN). This prevents response cross-talk between worker threads in
// AsyncIoPool (RESEARCH §1.5 + §7 Example 1; Pitfall 2).
//
// Linux kernel reference: linux/can/raw.h struct can_filter { canid_t can_id;
// canid_t can_mask; }; setsockopt(SOL_CAN_RAW, CAN_RAW_FILTER, &filter, sizeof(filter)).
//
// MUST be called AFTER connect() succeeds (m_sockfd >= 0). Calling before connect()
// returns NOT_CONNECTED.
I_CommunicationInterface::Error_t SocketCAN::set_can_id_filter(canId_t motor_id)
{
    if (m_sockfd < 0)
    {
        m_logger.error("SocketCAN: set_can_id_filter called before connect");
        return Error_t::NOT_CONNECTED;
    }

    // CANdle-SDK uses 11-bit IDs for motor IDs (CAN_SFF_MASK = 0x7FF).
    // Filter: accept only frames with can_id matching motor_id (mask = SFF mask).
    struct can_filter rfilter;
    rfilter.can_id   = static_cast<canid_t>(motor_id);
    rfilter.can_mask = CAN_SFF_MASK;
    if (setsockopt(m_sockfd, SOL_CAN_RAW, CAN_RAW_FILTER,
                   &rfilter, sizeof(rfilter)) < 0)
    {
        m_logger.error("SocketCAN: CAN_RAW_FILTER setsockopt failed: %s",
                       strerror(errno));
        return Error_t::INITIALIZATION_ERROR;
    }
    m_logger.info("SocketCAN: filter set for motor_id=0x%X (mask=0x%X)",
                  static_cast<unsigned>(motor_id),
                  static_cast<unsigned>(CAN_SFF_MASK));
    return Error_t::OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// disconnect()
// ─────────────────────────────────────────────────────────────────────────────

I_CommunicationInterface::Error_t SocketCAN::disconnect()
{
    if (m_sockfd >= 0)
    {
        close(m_sockfd);
        m_sockfd = -1;
        m_logger.info("SocketCAN: disconnected from '%s'", m_ifname.c_str());
    }
    return Error_t::OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// send_can_frame() — internal helper
// ─────────────────────────────────────────────────────────────────────────────

I_CommunicationInterface::Error_t SocketCAN::send_can_frame(const std::vector<u8> & data)
{
    // Validate envelope minimum size
    if (data.size() < MIN_ENV_SIZE)
    {
        m_logger.error("SocketCAN: send_can_frame: envelope too short (%zu < %zu)",
                       data.size(), MIN_ENV_SIZE);
        return Error_t::DATA_EMPTY;
    }

    // Parse envelope. CORRECTION (Plan 07.1-03 live debug 2026-05-05):
    // Plan 02 originally read this as "env_len = payload_bytes + 2". WRONG.
    // The SDK's sendCanFrameHeader (candle.hpp:174) builds the envelope as:
    //   {GENERIC_CAN_FRAME, u8(length /*id + DLC*/), timeout, u8(id), u8(id >> 8)}
    // where `length` = `dataToSend.size()` from the call site — the ACTUAL
    // user payload length, not payload+2. The "/* id + DLC */" comment in the
    // SDK is misleading; it's not adding bytes for the ID. Empirical evidence:
    // a 4-byte READ_REGISTER frame [0x41, 0x00, reg_lo, reg_hi] arrives here
    // with env_len=4 (not 6), and we previously dropped to len=2, sending only
    // [0x41, 0x00] over the wire — motor sees malformed frame, never responds.
    const uint8_t env_len    = data[ENV_LEN];
    const uint8_t id_lo      = data[ENV_ID_LO];
    const uint8_t id_hi      = data[ENV_ID_HI];
    const uint32_t can_id    = static_cast<uint32_t>(id_lo) |
                               (static_cast<uint32_t>(id_hi) << 8);
    const uint8_t payload_len = env_len;  // Direct: env_len IS the payload size.

    if (data.size() < ENV_PAYLOAD + payload_len)
    {
        m_logger.error("SocketCAN: send_can_frame: envelope payload underrun "
                       "(env_len=%u, data.size=%zu)", env_len, data.size());
        return Error_t::DATA_TOO_LONG;
    }

    // CAN-FD requires `len` to be a valid DLC: 0..8, 12, 16, 20, 24, 32, 48, 64.
    // Non-DLC values are silently dropped by the kernel TX layer (counted in
    // `ip -s link show <iface>` under TX dropped). Pad up to the next DLC.
    auto pad_to_dlc = [](uint8_t n) -> uint8_t {
        if (n <= 8)  return n;
        if (n <= 12) return 12;
        if (n <= 16) return 16;
        if (n <= 20) return 20;
        if (n <= 24) return 24;
        if (n <= 32) return 32;
        if (n <= 48) return 48;
        return 64;
    };
    const uint8_t dlc_len = pad_to_dlc(payload_len);

    // Build canfd_frame
    struct canfd_frame txf{};
    txf.can_id = can_id;  // standard 11-bit or 29-bit; kernel handles EFF flag
    txf.len    = dlc_len;
    // CANFD_FDF (0x04) marks the frame as CAN-FD format (some kernels require
    // this explicitly even with CAN_RAW_FD_FRAMES setsockopt enabled).
    // CANFD_BRS  (0x01) enables data-phase bit-rate switch (5M on X8).
    txf.flags  = CANFD_BRS | CANFD_FDF;
    if (payload_len > 0)
    {
        std::memcpy(txf.data, data.data() + ENV_PAYLOAD, payload_len);
        // Pad bytes already zero-initialized by `{}` above.
    }

    // Phase 07.1-03 diagnostic: dump TX frame at ERROR so we can see what's
    // actually being sent (Logger default verbosity filters INFO/DEBUG).
    {
        char hex[256];
        size_t off = 0;
        for (size_t i = 0; i < dlc_len && off + 3 < sizeof(hex); ++i) {
            off += static_cast<size_t>(std::snprintf(hex + off, sizeof(hex) - off,
                                                     "%02X ", txf.data[i]));
        }
        std::fprintf(stderr,
                     "[SocketCAN-DIAG] TX canfd_frame id=0x%03X dlc_len=%u (orig payload_len=%u) "
                     "flags=0x%02X data=[ %s]\n",
                     can_id, static_cast<unsigned>(dlc_len),
                     static_cast<unsigned>(payload_len),
                     static_cast<unsigned>(txf.flags), hex);
    }

    // Write with ENOBUFS retry (Pitfall 3: kernel TX ring full under high load)
    ssize_t written = write(m_sockfd, &txf, sizeof(txf));
    if (written < 0)
    {
        if (errno == ENOBUFS)
        {
            // One retry after 1 ms (kernel TX queue drain)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            written = write(m_sockfd, &txf, sizeof(txf));
            if (written < 0)
            {
                m_logger.error("SocketCAN: write() ENOBUFS after retry — TX queue full: %s",
                               strerror(errno));
                return Error_t::TRANSMITTER_ERROR;
            }
        }
        else
        {
            m_logger.error("SocketCAN: write() failed: %s", strerror(errno));
            return Error_t::TRANSMITTER_ERROR;
        }
    }

    // Diagnostic: report short-write (kernel may have truncated to classic CAN if
    // CAN_RAW_FD_FRAMES setsockopt failed silently or was reset).
    if (written != static_cast<ssize_t>(sizeof(txf)))
    {
        m_logger.error("SocketCAN: short write — wrote %zd of %zu bytes (kernel may have "
                       "fallen back to classic CAN; verify CAN_RAW_FD_FRAMES is enabled)",
                       written, sizeof(txf));
    }

    return Error_t::OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// recv_can_frame() — internal helper
// ─────────────────────────────────────────────────────────────────────────────

std::pair<std::vector<u8>, I_CommunicationInterface::Error_t>
SocketCAN::recv_can_frame(u32 timeoutMs, size_t expectedSize)
{
    std::vector<u8> result(expectedSize, 0);

    // Phase 07.1.2 follow-up — enforce a minimum recv timeout that accounts for
    // the X8H7 SPI bridge round-trip latency. The CANdle SDK was designed for
    // USB-CANdle's ~1ms latency profile, so DEFAULT_CAN_TIMEOUT=1ms + the SDK's
    // +10 padding gives 11ms passed in here. The X8 SPI bridge has ~95ms total
    // round-trip per Phase 07.1.2 dmesg analysis (start_xmit @ t0, motor
    // response delivered to can1 @ t0+94.5ms). At 11ms the recvfrom() returns
    // EAGAIN BEFORE the motor's response arrives at the kernel — the response
    // is then orphaned in the kernel buffer. Floor the timeout at 200ms so the
    // SPI bridge round-trip has comfortable headroom.
    constexpr u32 SPI_BRIDGE_MIN_TIMEOUT_MS = 200;
    const u32 effective_timeout = (timeoutMs < SPI_BRIDGE_MIN_TIMEOUT_MS)
                                  ? SPI_BRIDGE_MIN_TIMEOUT_MS : timeoutMs;

    // Set per-call receive timeout via SO_RCVTIMEO
    struct timeval tv{};
    tv.tv_sec  = static_cast<long>(effective_timeout / 1000U);
    tv.tv_usec = static_cast<long>((effective_timeout % 1000U) * 1000L);
    setsockopt(m_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct canfd_frame rxf{};
    ssize_t n = recvfrom(m_sockfd, &rxf, sizeof(rxf), 0, nullptr, nullptr);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        {
            m_logger.error("SocketCAN: recvfrom() timeout after %u ms (caller asked %u ms; floored to SPI-bridge minimum)",
                           effective_timeout, timeoutMs);
            return {result, Error_t::TIMEOUT};
        }
        m_logger.error("SocketCAN: recvfrom() failed: %s", strerror(errno));
        return {result, Error_t::RECEIVER_ERROR};
    }

    // Pack response: {0x00, 0x01, data[0..rxf.len-1], zeros...padded to expectedSize}
    // Candle::transferCANFrame checks buffer.at(1) != 0x01 at candle.cpp:259.
    size_t data_bytes = static_cast<size_t>(rxf.len);
    if (data_bytes > CANFD_MAX_DLEN)
        data_bytes = CANFD_MAX_DLEN;

    // Ensure result is large enough for at least 2 header bytes + data bytes
    size_t min_size = 2 + data_bytes;
    if (result.size() < min_size)
        result.resize(min_size, 0);

    result[0] = RESP_HDR_0;  // 0x00
    result[1] = RESP_HDR_1;  // 0x01 — mandatory for Candle::transferCANFrame check
    for (size_t i = 0; i < data_bytes && (2 + i) < result.size(); ++i)
    {
        result[2 + i] = rxf.data[i];
    }

    m_logger.debug("SocketCAN: RX canfd_frame id=0x%03X len=%u", rxf.can_id & CAN_EFF_MASK, rxf.len);
    return {result, Error_t::OK};
}

// ─────────────────────────────────────────────────────────────────────────────
// transfer() — fire-and-forget (no expected response)
// ─────────────────────────────────────────────────────────────────────────────

I_CommunicationInterface::Error_t SocketCAN::transfer(std::vector<u8> data, const u32 timeoutMs)
{
    return transfer(std::move(data), timeoutMs, 0).second;
}

// ─────────────────────────────────────────────────────────────────────────────
// transfer() — send + receive
// ─────────────────────────────────────────────────────────────────────────────

std::pair<std::vector<u8>, I_CommunicationInterface::Error_t>
SocketCAN::transfer(std::vector<u8> data, const u32 timeoutMs,
                    const size_t expectedReceivedDataSize)
{
    std::vector<u8> empty_result(expectedReceivedDataSize, 0);

    if (m_sockfd < 0)
    {
        m_logger.error("SocketCAN: transfer called but not connected");
        return {empty_result, Error_t::NOT_CONNECTED};
    }

    if (data.empty())
    {
        m_logger.error("SocketCAN: transfer called with empty data");
        return {empty_result, Error_t::DATA_EMPTY};
    }

    const uint8_t cmd = data[0];

    // ── cmd=2: CANDLE_CONFIG_DATARATE — synthesize response (Pitfall 4) ──────
    // legacyCheckConnection() sends this and expects 6 bytes back.
    // The 6-byte buffer is also parsed by Candle::getCandleVersion() during
    // MD::init():
    //   buffer[2] = version.tag
    //   buffer[3] = version.revision
    //   buffer[4] = version.minor
    //   buffer[5] = version.major
    // If this resolves to major<2 OR (major==2 AND minor<4) the SDK fires the
    // "old CANdle firmware" warning AND switches MD::init() onto the legacy
    // v1 register protocol — which modern motor firmware (v2.5.x+) does not
    // speak, causing readRegister() to time out silently.
    //
    // SocketCAN has no real USB-dongle handshake; we synthesize CANdle v2.5.0
    // (major=2, minor=5) so the SDK uses its modern register protocol path.
    if (cmd == CANDLE_CONFIG_DATARATE)
    {
        m_logger.info("SocketCAN: CANDLE_CONFIG_DATARATE (cmd=2) — synthesizing 6-byte response "
                      "with CANdle v2.5.0 version (no USB-dongle on SOCKETCAN)");
        const size_t resp_size = (expectedReceivedDataSize > 0) ? expectedReceivedDataSize : 6;
        std::vector<u8> synth(resp_size, 0);
        if (resp_size >= 6)
        {
            synth[2] = 0;  // tag
            synth[3] = 0;  // revision
            synth[4] = 5;  // minor (v2.5)
            synth[5] = 2;  // major (v2)
        }
        return {synth, Error_t::OK};
    }

    // ── cmd=4: GENERIC_CAN_FRAME — strip envelope, send raw canfd_frame ──────
    if (cmd == GENERIC_CAN_FRAME)
    {
        Error_t send_err = send_can_frame(data);
        if (send_err != Error_t::OK)
        {
            return {empty_result, send_err};
        }

        // If no response expected, done.
        if (expectedReceivedDataSize == 0)
        {
            return {std::vector<u8>(), Error_t::OK};
        }

        // Wait for motor response
        return recv_can_frame(timeoutMs, expectedReceivedDataSize);
    }

    // ── Unknown cmd byte ─────────────────────────────────────────────────────
    m_logger.error("SocketCAN: unrecognized cmd byte 0x%02X — only GENERIC_CAN_FRAME(4) "
                   "and CANDLE_CONFIG_DATARATE(2) are supported over SocketCAN",
                   static_cast<unsigned>(cmd));
    return {empty_result, Error_t::UNKNOWN_ERROR};
}

}  // namespace mab

#endif  // WIN32
