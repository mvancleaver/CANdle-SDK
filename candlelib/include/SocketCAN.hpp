#pragma once
// SocketCAN.hpp — CANdle-SDK SocketCAN transport backend (Phase 07.1 D-02)
//
// Implements I_CommunicationInterface over a Linux AF_CAN/SOCK_RAW socket
// (CAN_RAW_FD_FRAMES enabled) on a named SocketCAN network device (e.g. can1).
//
// Critical architectural contract:
//   The Candle class wraps every MD frame in a 5-byte USB-dongle envelope:
//     {cmd_byte, length, timeout, id_lo, id_hi, payload...}
//   and sends it via m_bus->transfer(). This class MUST:
//
//   - cmd=4 (GENERIC_CAN_FRAME): strip the envelope, extract the raw CAN ID
//     and payload, compose a canfd_frame with CANFD_BRS, write() to the
//     AF_CAN socket. On receive: read canfd_frame, re-wrap into the 2-byte
//     response header {0x00, 0x01} + data that Candle::transferCANFrame
//     expects (buffer.at(1) != 0x01 is the failure check at candle.cpp:259).
//
//   - cmd=2 (CANDLE_CONFIG_DATARATE): return a synthetic 6-byte OK response
//     WITHOUT touching the socket. This satisfies Candle::init() /
//     legacyCheckConnection() without real USB-dongle hardware.
//
//   - Other cmd bytes: log WARN + return UNKNOWN_ERROR.
//
// The actual CAN bus bitrate (1M arb / 5M data per fleet decision) must be
// configured at the kernel netdev level BEFORE connecting:
//   ip link set can1 type can bitrate 1000000 dbitrate 5000000 fd on
// (handled by X8 container entrypoint or systemd unit — Plan 03 scope).
//
// Pitfall mitigations (RESEARCH.md):
//   Pitfall 1: interface not up → SIOCGIFINDEX fails → INITIALIZATION_ERROR
//   Pitfall 2: classic CAN MTU (16) vs FD MTU (72) → MTU check → INITIALIZATION_ERROR
//   Pitfall 3: ENOBUFS on write → 1-ms delay + one retry → TRANSMITTER_ERROR on 2nd fail
//   Pitfall 4: synthetic CANDLE_CONFIG_DATARATE response = exactly 6 zero bytes

#ifndef WIN32

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "I_communication_interface.hpp"
#include "logger.hpp"
#include "mab_types.hpp"

namespace mab
{

class SocketCAN final : public I_CommunicationInterface
{
  public:
    /// @brief Construct a SocketCAN backend bound to the named CAN-FD network interface.
    /// @param ifname Interface name (e.g. "can1" or "vcan0"). Default "can1" for X8.
    explicit SocketCAN(std::string_view ifname = "can1");

    /// @brief Construct a SocketCAN backend bound to the named CAN-FD network interface
    ///        with an optional per-socket CAN_RAW_FILTER (Phase 07.1.3 D-11 approach b2).
    ///        When @p filter_id is set, connect() will apply CAN_RAW_FILTER to accept
    ///        only frames matching that motor_id (mask=CAN_SFF_MASK).
    /// @param ifname Interface name (e.g. "can1" or "vcan0").
    /// @param filter_id Motor CAN ID (11-bit standard frame) to filter on; std::nullopt = no filter.
    SocketCAN(std::string_view ifname, std::optional<canId_t> filter_id);

    ~SocketCAN() override;

    // No copy/move — socket ownership is exclusive.
    SocketCAN(const SocketCAN &)            = delete;
    SocketCAN & operator=(const SocketCAN &) = delete;
    SocketCAN(SocketCAN &&)                 = delete;
    SocketCAN & operator=(SocketCAN &&)     = delete;

    /// @brief Open AF_CAN SOCK_RAW socket, enable CAN-FD, bind to interface.
    ///        Returns INITIALIZATION_ERROR if:
    ///          - socket() fails
    ///          - CAN_RAW_FD_FRAMES setsockopt fails
    ///          - Interface not found / not up (SIOCGIFINDEX)
    ///          - MTU < MIN_FD_MTU (classic CAN, not FD-capable)
    ///          - bind() fails
    Error_t connect() override;

    /// @brief Close the AF_CAN socket.
    Error_t disconnect() override;

    /// @brief Send a frame (no response expected).
    ///   cmd=4 (GENERIC_CAN_FRAME): strip USB envelope, send canfd_frame.
    ///   cmd=2 (CANDLE_CONFIG_DATARATE): return OK without touching socket.
    ///   other: log WARN, return UNKNOWN_ERROR.
    Error_t transfer(std::vector<u8> data, const u32 timeoutMs) override;

    /// @brief Send a frame and wait for a response.
    ///   cmd=4: strip envelope, send, recvfrom with timeout, pack response.
    ///   cmd=2: return synthetic {0,...} (6 bytes) OK immediately.
    ///   other: log WARN, return UNKNOWN_ERROR.
    std::pair<std::vector<u8>, Error_t> transfer(
        std::vector<u8> data,
        const u32       timeoutMs,
        const size_t    expectedReceivedDataSize) override;

    /// @brief Apply a per-socket CAN_RAW_FILTER for a single motor_id.
    ///        Phase 07.1.3 D-11 (approach b2): per-motor SocketCAN sockets with
    ///        kernel-level can_id isolation, avoiding response cross-talk between
    ///        worker threads (RESEARCH §1.5 + Pitfall 2).
    ///        Returns NOT_CONNECTED if called before connect().
    ///        Returns INITIALIZATION_ERROR if setsockopt fails.
    ///        See linux/can/raw.h CAN_RAW_FILTER + CAN_SFF_MASK.
    Error_t set_can_id_filter(canId_t motor_id);

    /// @brief Enable/disable local loopback of this socket's TX frames (CAN_RAW_LOOPBACK).
    ///        Persistent (07.4.42.2-02): stored and re-applied by every connect(), so it
    ///        survives Candle::init()'s disconnect()+connect(). Applied immediately when
    ///        already connected. Default false = production behaviour.
    ///        vcan tests only; production sockets keep loopback off (a vcan frame sent
    ///        with loopback off reaches no local socket).
    ///        Returns OK (stored) before connect; INITIALIZATION_ERROR if setsockopt fails.
    Error_t set_loopback(bool enable);

    /// @brief Turn this socket into a TX-only socket (CAN_RAW_FILTER with zero filters),
    ///        then drain anything already queued.
    ///        TX-only socket for the 07.4.42.2 fire-and-forget write lane; survives
    ///        Candle::init() reconnect (connect() re-applies it and skips the ctor filter_id).
    ///        Returns OK (stored) before connect; INITIALIZATION_ERROR if setsockopt fails.
    Error_t disable_rx();

    /// @brief Bound the POLLOUT wait taken once on ENOBUFS before the single TX retry.
    ///        Clamped to >= 0; default 100 ms (current behaviour). 0 = no wait: the frame
    ///        is dropped immediately (TRANSMITTER_ERROR) and counted, for the no-wait lane.
    void set_enobufs_wait_ms(int ms);

    /// @brief Raw socket fd (-1 when not connected). Tests/diagnostics only; do not close.
    int native_handle() const noexcept { return m_sockfd; }

  private:
    /// @brief Parse the USB-dongle envelope (cmd=4) and write canfd_frame to socket.
    ///        Returns OK on success, TRANSMITTER_ERROR on failure (with 1 ENOBUFS retry).
    Error_t send_can_frame(const std::vector<u8> & data);

    /// @brief Receive the reply frame from the socket with timeout.
    ///        Loops until the deadline: CAN error frames (CAN_ERR_FLAG) are skipped and,
    ///        when @p expectedId is set, frames whose 11-bit id differs are discarded.
    ///        Packs into {0x00, 0x01, data[0..len-1], zeros...padded}.
    ///        Returns TIMEOUT if no matching frame arrives; RECEIVER_ERROR on socket error.
    std::pair<std::vector<u8>, Error_t> recv_can_frame(
        u32 timeoutMs, size_t expectedSize, std::optional<uint32_t> expectedId);

    /// @brief Drain every frame already queued on the socket (non-blocking).
    ///        Returns the number of frames discarded.
    size_t flush_stale_rx();

    std::string             m_ifname;
    int                     m_sockfd{-1};
    std::optional<canId_t>  m_filter_id;  ///< Phase 07.1.3 D-11: optional per-socket motor_id filter applied in connect()
    bool                    m_loopback{false};      ///< 07.4.42.2-02: CAN_RAW_LOOPBACK applied by connect()
    bool                    m_rx_disabled{false};   ///< 07.4.42.2-02: TX-only socket (zero CAN_RAW_FILTER)
    int                     m_enobufs_wait_ms{100}; ///< 07.4.42.2-02: POLLOUT wait before the ENOBUFS retry

    Logger m_logger = Logger(Logger::ProgramLayer_E::BOTTOM, "SocketCAN");

    // CANdle command byte constants (match Candle::CandleCommands_t enum in candle.hpp)
    static constexpr uint8_t GENERIC_CAN_FRAME      = 4;
    static constexpr uint8_t CANDLE_CONFIG_DATARATE  = 2;

    // Minimum interface MTU for CAN-FD (sizeof(canfd_frame) = 72).
    // Classic CAN interfaces report MTU=16; FD-enabled interfaces report MTU=72.
    // Reject MTU < 72 to avoid silent frame truncation (Pitfall 2).
    static constexpr int MIN_FD_MTU = 72;

    // Envelope byte offsets
    static constexpr size_t ENV_CMD      = 0;
    static constexpr size_t ENV_LEN      = 1;
    static constexpr size_t ENV_TIMEOUT  = 2;
    static constexpr size_t ENV_ID_LO    = 3;
    static constexpr size_t ENV_ID_HI    = 4;
    static constexpr size_t ENV_PAYLOAD  = 5;
    static constexpr size_t ENV_HDR_SIZE = 5;  // bytes before payload

    // Minimum envelope size: cmd + len + timeout + id_lo + id_hi = 5 bytes
    static constexpr size_t MIN_ENV_SIZE = ENV_HDR_SIZE;

    // Response header that Candle::transferCANFrame() checks at buffer.at(1)
    static constexpr uint8_t RESP_HDR_0 = 0x00;
    static constexpr uint8_t RESP_HDR_1 = 0x01;  // buffer.at(1) != 0x01 → CAN_DEVICE_NOT_RESPONDING
};

}  // namespace mab

// 07.4.42.2-02 reply-validation / TX-drop counters (relaxed atomics in SocketCAN.cpp).
// phase_7_4_42_2_reset_rx_counters() zeroes the three RX counters (not tx_enobufs_dropped).
extern "C"
{
    uint64_t phase_7_4_42_2_get_err_frames_skipped(void);
    uint64_t phase_7_4_42_2_get_foreign_frames_discarded(void);
    uint64_t phase_7_4_42_2_get_stale_frames_flushed(void);
    uint64_t phase_7_4_42_2_get_tx_enobufs_dropped(void);
    void     phase_7_4_42_2_reset_rx_counters(void);
}

#else  // WIN32

#include <optional>
#include <utility>
#include <vector>
#include "I_communication_interface.hpp"
#include "logger.hpp"
#include "mab_types.hpp"

namespace mab
{

class SocketCAN final : public I_CommunicationInterface
{
  public:
    explicit SocketCAN(std::string_view /*ifname*/ = "can1") {}
    SocketCAN(std::string_view /*ifname*/, std::optional<canId_t> /*filter_id*/) {}
    ~SocketCAN() override {}

    Error_t connect() override { return Error_t::INITIALIZATION_ERROR; }
    Error_t disconnect() override { return Error_t::INITIALIZATION_ERROR; }
    Error_t transfer(std::vector<u8> /*data*/, const u32 /*timeoutMs*/) override
    {
        return Error_t::INITIALIZATION_ERROR;
    }
    std::pair<std::vector<u8>, Error_t> transfer(
        std::vector<u8> /*data*/,
        const u32       /*timeoutMs*/,
        const size_t    /*expectedReceivedDataSize*/) override
    {
        return {std::vector<u8>(), Error_t::INITIALIZATION_ERROR};
    }
    Error_t set_can_id_filter(canId_t /*motor_id*/) { return Error_t::INITIALIZATION_ERROR; }
    Error_t set_loopback(bool /*enable*/) { return Error_t::INITIALIZATION_ERROR; }
    Error_t disable_rx() { return Error_t::INITIALIZATION_ERROR; }
    void    set_enobufs_wait_ms(int /*ms*/) {}
    int     native_handle() const noexcept { return -1; }

  private:
    Logger m_logger = Logger(Logger::ProgramLayer_E::BOTTOM, "SocketCAN");
};

}  // namespace mab

#endif  // WIN32
