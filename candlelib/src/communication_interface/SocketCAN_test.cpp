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

#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
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
    // Create a classic CAN vcan interface with default MTU (16).
    system("ip link add dev vcan_classic type vcan 2>/dev/null");
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
// transfer({cmd=4, len=0x0A, timeout=50, id_lo=0x37, id_hi=0x01,
//            0xDE,0xAD,0xBE,0xEF,0x11,0x22,0x33,0x44}, 100ms)
// Backend must emit canfd_frame{can_id=0x0137, len=8, flags=CANFD_BRS,
//                               data={DE AD BE EF 11 22 33 44}} on vcan0.
// Verified by a sibling SOCK_RAW fd.

TEST_F(SocketCANTest, StripsEnvelopeAndSendsRawFrame)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }

    int sibling = open_sibling_fd();
    ASSERT_GE(sibling, 0) << "Could not open sibling socket on vcan0";

    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), mab::I_CommunicationInterface::Error_t::OK);

    // Build the USB-dongle wrapped frame:
    //   {GENERIC_CAN_FRAME=4, len=0x0A (8 data + 2 for id bytes), timeout=50,
    //    id_lo=0x37, id_hi=0x01, data[8]}
    // len field: the Candle SDK puts (payload_bytes + 2 for the 2-byte CAN-ID) in len.
    std::vector<uint8_t> frame{
        4,           // GENERIC_CAN_FRAME
        0x0A,        // len = 8 payload + 2 id bytes
        50,          // timeout
        0x37, 0x01,  // CAN ID = 0x0137 (little-endian)
        0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44  // 8 data bytes
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
    EXPECT_EQ(rxf.len, 8u) << "Wrong data length";
    EXPECT_EQ(rxf.flags & CANFD_BRS, CANFD_BRS) << "CANFD_BRS flag must be set";
    EXPECT_EQ(rxf.data[0], 0xDE);
    EXPECT_EQ(rxf.data[1], 0xAD);
    EXPECT_EQ(rxf.data[7], 0x44);

    close(sibling);
    sc.disconnect();
}

// ── Test 7: Packs received canfd_frame into SDK response format ───────────────
//
// {0x00, 0x01, rxf.data[0..len-1], 0...(pad)} is what Candle::transferCANFrame
// checks: buffer.at(1) != 0x01 means failure. We pre-send from sibling so the
// backend's recvfrom() picks it up.

TEST_F(SocketCANTest, PacksRecvIntoSdkResponse)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }

    int sibling = open_sibling_fd();
    ASSERT_GE(sibling, 0);

    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), mab::I_CommunicationInterface::Error_t::OK);

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
        0x0A,        // len = 8 payload + 2 id bytes
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

TEST_F(SocketCANTest, TimeoutOnNoResponse)
{
    if (!vcan0_available()) {
        GTEST_SKIP() << "vcan0 not available. Skipping.";
    }

    mab::SocketCAN sc("vcan0");
    ASSERT_EQ(sc.connect(), mab::I_CommunicationInterface::Error_t::OK);

    std::vector<uint8_t> frame{
        4, 0x0A, 5, 0x37, 0x01,
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

// ── Phase 07.4.42.2 Wave 0 stubs — bodies land in 07.4.42.2-02 (SDK RX hardening) ──
TEST_F(SocketCANTest, ErrFrameSkipped)          { GTEST_SKIP() << "WAVE0-STUB: implemented by 07.4.42.2-02 Task 1"; }
TEST_F(SocketCANTest, ForeignIdDiscarded)       { GTEST_SKIP() << "WAVE0-STUB: implemented by 07.4.42.2-02 Task 1"; }
TEST_F(SocketCANTest, StaleReplyFlushed)        { GTEST_SKIP() << "WAVE0-STUB: implemented by 07.4.42.2-02 Task 1"; }
TEST_F(SocketCANTest, NoResponseWriteSendsOnce) { GTEST_SKIP() << "WAVE0-STUB: implemented by 07.4.42.2-02 Task 2"; }

#endif  // WIN32
