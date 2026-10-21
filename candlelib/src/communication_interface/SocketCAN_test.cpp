// SocketCAN_test.cpp — gtest suite for CANdle-SDK SocketCAN transport backend
//
// Tests 1-4: connection/lifecycle (require vcan0 or a SocketCAN-capable interface).
// Tests 5-8: envelope-strip + response-pack + timeout logic.
//
// vcan0 setup (run as root before colcon test, or let the fixture attempt it):
//   modprobe vcan
//   ip link add dev vcan0 type vcan
//   ip link set vcan0 mtu 72
//   ip link set vcan0 up
//
// Tests that need vcan0 skip gracefully (GTEST_SKIP) if the interface is not
// present AND the process is not running as root. This keeps CI clean on x86_64
// builders that lack the vcan kernel module.

#ifndef WIN32

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <thread>
#include <vector>

#include <linux/can.h>
#include <linux/can/error.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "SocketCAN.hpp"

// ── Helpers ──────────────────────────────────────────────────────────────────

static bool vcan0_available()
{
    int fd = socket(AF_CAN, SOCK_RAW, CAN_RAW);
    if (fd < 0) return false;
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, "vcan0", IFNAMSIZ - 1);
    bool ok = (ioctl(fd, SIOCGIFINDEX, &ifr) == 0);
    close(fd);
    return ok;
}

static void setup_vcan0()
{
    // Attempt to bring up vcan0 — only works as root / with CAP_NET_ADMIN.
    // Failures are intentionally silent; the test fixture checks availability
    // after this and skips if vcan0 is still not present.
    system("modprobe vcan 2>/dev/null");
    system("ip link add dev vcan0 type vcan 2>/dev/null");
    system("ip link set vcan0 mtu 72 2>/dev/null");
    system("ip link set vcan0 up 2>/dev/null");
}

/// Open a raw CAN-FD socket on vcan0 for a sibling send/receive in tests 6-8.
static int open_sibling_fd()
{
    int fd = socket(AF_CAN, SOCK_RAW, CAN_RAW);
    if (fd < 0) return -1;
    int enable = 1;
    setsockopt(fd, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable, sizeof(enable));
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, "vcan0", IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    struct sockaddr_can addr{};
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    return fd;
}

/// Wait up to timeout_ms for one frame on fd (classic or FD). Returns false on timeout/error.
static bool wait_frame(int fd, int timeout_ms, canfd_frame & out)
{
    struct pollfd pfd = { fd, POLLIN, 0 };
    if (::poll(&pfd, 1, timeout_ms) <= 0) return false;
    std::memset(&out, 0, sizeof(out));
    return read(fd, &out, sizeof(out)) > 0;
}

/// Write one classic CAN frame (struct can_frame) with the given id and payload.
static void send_classic(int fd, canid_t id, std::initializer_list<uint8_t> bytes)
{
    struct can_frame cf{};
    cf.can_id  = id;
    cf.can_dlc = static_cast<uint8_t>(std::min<size_t>(bytes.size(), CAN_MAX_DLEN));
    std::copy_n(bytes.begin(), cf.can_dlc, cf.data);
    [[maybe_unused]] ssize_t w = write(fd, &cf, sizeof(cf));
}

using SocketCANErr = mab::I_CommunicationInterface::Error_t;

// ── Fixture ───────────────────────────────────────────────────────────────────

class SocketCANTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Attempt vcan0 setup (no-op if already present or if no CAP_NET_ADMIN).
        setup_vcan0();
    }
    void TearDown() override {}
};

// ── Test 1: Construction does not throw; not yet connected ────────────────────

TEST_F(SocketCANTest, SocketCANBackendConstructs)
{
    EXPECT_NO_THROW({
        mab::SocketCAN sc("vcan0");
        (void)sc;
    });
}

// ── Test 2: connect() fails gracefully on non-existent interface ──────────────

TEST_F(SocketCANTest, ConnectFailsOnMissingInterface)
{
    mab::SocketCAN sc("nonexistent_can99");
    auto result = sc.connect();
    EXPECT_EQ(result, mab::I_CommunicationInterface::Error_t::INITIALIZATION_ERROR);
}

// ── Test 3: connect() + disconnect() succeed on vcan0 ────────────────────────

TEST_F(SocketCANTest, ConnectSucceedsOnVcan0)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available (need root + modprobe vcan). Skipping.";
    }
    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), mab::I_CommunicationInterface::Error_t::OK);
    EXPECT_EQ(sc.disconnect(), mab::I_CommunicationInterface::Error_t::OK);
}

// ── Test 4: MTU check rejects classic CAN (mtu=16, not FD) ──────────────────

TEST_F(SocketCANTest, MtuCheckRejectsClassicCAN)
{
    if (geteuid() != 0) {
        GTEST_SKIP() << "Need root to create a classic-CAN vcan interface. Skipping.";
    }
    // Create a classic CAN vcan interface with MTU 16.
    // Repaired 07.4.42.2-02: stale expectation — a fresh vcan on recent host kernels
    // (spark 6.17) comes up with MTU 72, so the classic MTU must be set explicitly.
    system("ip link add dev vcan_classic type vcan 2>/dev/null");
    system("ip link set vcan_classic mtu 16 2>/dev/null");
    system("ip link set vcan_classic up 2>/dev/null");

    mab::SocketCAN sc("vcan_classic");
    auto result = sc.connect();
    EXPECT_EQ(result, mab::I_CommunicationInterface::Error_t::INITIALIZATION_ERROR)
        << "Expected INITIALIZATION_ERROR: classic CAN MTU is 16, below the FD minimum 72";

    // Cleanup
    system("ip link delete vcan_classic 2>/dev/null");
}

// ── Test 5: Synthesize legacy-check-connection OK (no socket needed) ─────────
//
// cmd=2 (CANDLE_CONFIG_DATARATE) must return ({0,0,0,0,0,0}, OK)
// without touching the socket. This satisfies Candle::init()::legacyCheckConnection.

TEST_F(SocketCANTest, SynthesizesLegacyCheckConnectionOk)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }
    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), mab::I_CommunicationInterface::Error_t::OK);

    // CANDLE_CONFIG_DATARATE = 2
    // legacyCheckConnection sends {cmd=2, datarate_enum, useRegularCanFrames}
    std::vector<uint8_t> cmd{2, 0x01, 0x00};
    auto [data, err] = sc.transfer(cmd, 100, 6);

    EXPECT_EQ(err, mab::I_CommunicationInterface::Error_t::OK)
        << "CANDLE_CONFIG_DATARATE must succeed synthetically";
    ASSERT_EQ(data.size(), 6u)
        << "legacyCheckConnection expects exactly 6 bytes back";
    // All zeros is a valid synthetic OK (the USB dongle returns non-error pattern)
    // The only requirement is err==OK and size==6; content doesn't matter to caller.

    sc.disconnect();
}

// ── Test 6: Strips USB-dongle envelope and sends raw canfd_frame ──────────────
//
// transfer({cmd=4, len=0x0C, timeout=50, id_lo=0x37, id_hi=0x01, 12 data bytes}, 100ms)
// Backend must emit canfd_frame{can_id=0x0137, len=12, flags=CANFD_BRS|CANFD_FDF,
//                               data={DE AD BE EF 11 22 33 44 55 66 77 88}} on vcan0.
// Verified by a sibling SOCK_RAW fd.
//
// Repaired 07.4.42.2-02 (stale expectation since Plan 07.1-03 env_len correction /
// loopback-off on vcan): env_len IS the payload size (no "+2"); an 8-byte payload is
// sent as a classic can_frame (no BRS) since Phase 7.4.26, so the FD path is exercised
// with a 12-byte payload; and the SDK socket must enable loopback, otherwise vcan
// delivers its TX to no local socket.

TEST_F(SocketCANTest, StripsEnvelopeAndSendsRawFrame)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }

    int sibling = open_sibling_fd();
    ASSERT_GE(sibling, 0) << "Could not open sibling socket on vcan0";

    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), mab::I_CommunicationInterface::Error_t::OK);
    ASSERT_EQ(sc.set_loopback(true), mab::I_CommunicationInterface::Error_t::OK);

    // Build the USB-dongle wrapped frame:
    //   {GENERIC_CAN_FRAME=4, len=0x0C (payload bytes), timeout=50,
    //    id_lo=0x37, id_hi=0x01, data[12]}
    std::vector<uint8_t> frame{
        4,           // GENERIC_CAN_FRAME
        0x0C,        // len = 12 payload bytes
        50,          // timeout
        0x37, 0x01,  // CAN ID = 0x0137 (little-endian)
        0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44,  // 12 data bytes
        0x55, 0x66, 0x77, 0x88
    };

    // Send — no expected response
    auto err = sc.transfer(frame, 100);
    EXPECT_EQ(err, mab::I_CommunicationInterface::Error_t::OK);

    // Receive on sibling with short timeout
    struct timeval tv{0, 50000};  // 50 ms
    setsockopt(sibling, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct canfd_frame rxf{};
    ssize_t n = recv(sibling, &rxf, sizeof(rxf), 0);
    ASSERT_GT(n, 0) << "Sibling did not receive any frame on vcan0";

    EXPECT_EQ(rxf.can_id & CAN_EFF_MASK, 0x0137u) << "Wrong CAN ID";
    EXPECT_EQ(rxf.len, 12u) << "Wrong data length";
    EXPECT_EQ(rxf.flags & CANFD_BRS, CANFD_BRS) << "CANFD_BRS flag must be set";
    EXPECT_EQ(rxf.data[0], 0xDE);
    EXPECT_EQ(rxf.data[1], 0xAD);
    EXPECT_EQ(rxf.data[7], 0x44);
    EXPECT_EQ(rxf.data[11], 0x88);

    close(sibling);
    sc.disconnect();
}

// ── Test 7: Packs received canfd_frame into SDK response format ───────────────
//
// {0x00, 0x01, rxf.data[0..len-1], 0...(pad)} is what Candle::transferCANFrame
// checks: buffer.at(1) != 0x01 means failure. We pre-send from sibling so the
// backend's recvfrom() picks it up.
//
// Repaired 07.4.42.2-02 (stale expectation since Plan 07.1-03 env_len correction /
// loopback-off on vcan): len byte is the payload size (0x08), and loopback is enabled
// so the responder actually sees the request instead of timing out.

TEST_F(SocketCANTest, PacksRecvIntoSdkResponse)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }

    int sibling = open_sibling_fd();
    ASSERT_GE(sibling, 0);

    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), mab::I_CommunicationInterface::Error_t::OK);
    ASSERT_EQ(sc.set_loopback(true), mab::I_CommunicationInterface::Error_t::OK);

    // Pre-arrange sibling to send a response canfd_frame shortly after backend sends.
    // We spawn a thread that waits for a frame on vcan0, then echoes a response.
    std::thread responder([sibling]() {
        // Wait for any frame (the one the backend sends)
        struct canfd_frame rxf{};
        struct timeval tv{0, 200000};  // 200 ms
        setsockopt(sibling, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        recv(sibling, &rxf, sizeof(rxf), 0);

        // Send the response frame
        struct canfd_frame txf{};
        txf.can_id = 0x0137 | CAN_EFF_FLAG;  // extended frame
        txf.len = 4;
        txf.flags = CANFD_BRS;
        txf.data[0] = 0xCA;
        txf.data[1] = 0xFE;
        txf.data[2] = 0xBE;
        txf.data[3] = 0xEF;
        send(sibling, &txf, sizeof(txf), 0);
    });

    // Build the request frame
    std::vector<uint8_t> frame{
        4,           // GENERIC_CAN_FRAME
        0x08,        // len = 8 payload bytes
        50,          // timeout
        0x37, 0x01,  // CAN ID = 0x0137
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    // transfer with expected response (14 bytes = 2 header + up to 12 data)
    auto [data, err] = sc.transfer(frame, 500, 14);

    responder.join();

    EXPECT_EQ(err, mab::I_CommunicationInterface::Error_t::OK)
        << "transfer with expected response should succeed";
    ASSERT_GE(data.size(), 6u) << "Response must be at least 6 bytes (header + 4 data)";
    EXPECT_EQ(data[0], 0x00u) << "Response byte[0] must be 0x00";
    EXPECT_EQ(data[1], 0x01u) << "Response byte[1] must be 0x01 (Candle::transferCANFrame check)";
    EXPECT_EQ(data[2], 0xCAu) << "data[2] = first CAN payload byte";
    EXPECT_EQ(data[3], 0xFEu);
    EXPECT_EQ(data[4], 0xBEu);
    EXPECT_EQ(data[5], 0xEFu);

    close(sibling);
    sc.disconnect();
}

// ── Test 8: Timeout returned when no responder present ────────────────────────

// Repaired 07.4.42.2-02 (stale expectation since Plan 07.1-03 env_len correction):
// len byte is the payload size (0x08), not payload+2.
TEST_F(SocketCANTest, TimeoutOnNoResponse)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }

    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), mab::I_CommunicationInterface::Error_t::OK);

    std::vector<uint8_t> frame{
        4, 0x08, 5, 0x37, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00
    };

    auto t0 = std::chrono::steady_clock::now();
    auto [data, err] = sc.transfer(frame, 5, 14);  // 5 ms timeout
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    EXPECT_EQ(err, mab::I_CommunicationInterface::Error_t::TIMEOUT)
        << "Should return TIMEOUT when no responder on vcan0";
    EXPECT_LE(elapsed, 100) << "Timeout took too long (>100ms for a 5ms request)";

    sc.disconnect();
}

// ── Phase 07.4.42.2-02 Task 1: reply validation (RESEARCH P0-2, P0-3, P1-10) ──
//
// Common shape: the SDK socket (no ctor filter, loopback on so a sibling can see its
// request) sends a READ_REGISTER-shaped request to 0x137; a responder thread on a
// sibling socket waits for that request and then answers with a hostile frame
// followed by the genuine reply. transfer() must return the genuine reply.

static const std::vector<uint8_t> kReadReq{4, 0x04, 5, 0x37, 0x01, 0x41, 0x00, 0x03, 0x08};

TEST_F(SocketCANTest, ErrFrameSkipped)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }

    // Precheck: does this kernel deliver a userspace-injected error frame on vcan0?
    {
        int probe    = open_sibling_fd();
        int injector = open_sibling_fd();
        ASSERT_GE(probe, 0);
        ASSERT_GE(injector, 0);
        can_err_mask_t all = CAN_ERR_MASK;
        setsockopt(probe, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &all, sizeof(all));
        send_classic(injector, CAN_ERR_FLAG | CAN_ERR_BUSOFF, {0, 0, 0, 0, 0, 0, 0, 0});
        canfd_frame got{};
        const bool delivered = wait_frame(probe, 100, got) && (got.can_id & CAN_ERR_FLAG);
        close(probe);
        close(injector);
        if (!delivered) {
            GTEST_SKIP() << "kernel does not deliver injected error frames on vcan0";
        }
    }

    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), SocketCANErr::OK);
    ASSERT_EQ(sc.set_loopback(true), SocketCANErr::OK);
    // Test-only: subscribe the SDK fd to error frames so one can land between request
    // and reply. Production SDK sockets never enable this (07.4.42.2 P0-2: the
    // MotorStateListener owns error-frame delivery).
    can_err_mask_t all = CAN_ERR_MASK;
    ASSERT_EQ(setsockopt(sc.native_handle(), SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &all, sizeof(all)), 0);

    int inj = open_sibling_fd();
    ASSERT_GE(inj, 0);
    std::thread responder([inj]() {
        canfd_frame req{};
        if (!wait_frame(inj, 300, req)) return;
        send_classic(inj, CAN_ERR_FLAG | CAN_ERR_BUSOFF, {0, 0, 0, 0, 0, 0, 0, 0});
        send_classic(inj, 0x137, {0xA0, 0x11, 0x22, 0x33});
    });

    const auto before = phase_7_4_42_2_get_err_frames_skipped();
    auto [data, err]  = sc.transfer(kReadReq, 300, 66);
    responder.join();
    const auto after = phase_7_4_42_2_get_err_frames_skipped();

    EXPECT_EQ(err, SocketCANErr::OK);
    ASSERT_GE(data.size(), 4u);
    EXPECT_EQ(data[2], 0xA0u) << "the error frame must never be returned as the reply";
    EXPECT_EQ(data[3], 0x11u);
    EXPECT_EQ(after - before, 1u) << "exactly one error frame must have been skipped";

    close(inj);
    sc.disconnect();
}

TEST_F(SocketCANTest, ForeignIdDiscarded)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }

    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), SocketCANErr::OK);
    ASSERT_EQ(sc.set_loopback(true), SocketCANErr::OK);

    int inj = open_sibling_fd();
    ASSERT_GE(inj, 0);
    std::thread responder([inj]() {
        canfd_frame req{};
        if (!wait_frame(inj, 300, req)) return;
        send_classic(inj, 0x138, {0xA0, 0xEE, 0xEE, 0xEE});  // another motor's ACK
        send_classic(inj, 0x137, {0xA0, 0x11, 0x22, 0x33});  // the target's ACK
    });

    const auto before = phase_7_4_42_2_get_foreign_frames_discarded();
    auto [data, err]  = sc.transfer(kReadReq, 300, 66);
    responder.join();
    const auto after = phase_7_4_42_2_get_foreign_frames_discarded();

    EXPECT_EQ(err, SocketCANErr::OK);
    ASSERT_GE(data.size(), 4u);
    EXPECT_EQ(data[2], 0xA0u);
    EXPECT_EQ(data[3], 0x11u) << "a reply from motor 0x138 must never satisfy a 0x137 transaction";
    EXPECT_GE(after - before, 1u);

    close(inj);
    sc.disconnect();
}

TEST_F(SocketCANTest, StaleReplyFlushed)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }

    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), SocketCANErr::OK);
    ASSERT_EQ(sc.set_loopback(true), SocketCANErr::OK);

    int inj = open_sibling_fd();
    ASSERT_GE(inj, 0);

    // A late reply left over from an earlier (timed-out) transaction, same motor id.
    // Sent from inj itself so the responder below never sees it (no RECV_OWN_MSGS).
    send_classic(inj, 0x137, {0xA0, 0xEE, 0xEE, 0xEE});
    std::this_thread::sleep_for(std::chrono::milliseconds(20));  // settle: queued on sc

    std::thread responder([inj]() {
        canfd_frame req{};
        if (!wait_frame(inj, 300, req)) return;
        send_classic(inj, 0x137, {0xA0, 0x11, 0x22, 0x33});  // fresh reply
    });

    const auto before = phase_7_4_42_2_get_stale_frames_flushed();
    auto [data, err]  = sc.transfer(kReadReq, 300, 66);
    responder.join();
    const auto after = phase_7_4_42_2_get_stale_frames_flushed();

    EXPECT_EQ(err, SocketCANErr::OK);
    ASSERT_GE(data.size(), 4u);
    EXPECT_EQ(data[2], 0xA0u);
    EXPECT_EQ(data[3], 0x11u) << "a stale queued reply must never answer the next request";
    EXPECT_GE(after - before, 1u);

    close(inj);
    sc.disconnect();
}

TEST_F(SocketCANTest, NoResponseWriteSendsOnce) { GTEST_SKIP() << "WAVE0-STUB: implemented by 07.4.42.2-02 Task 2"; }

#endif  // WIN32
