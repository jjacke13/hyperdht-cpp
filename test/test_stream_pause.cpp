// Read-side backpressure: SecretStreamDuplex::pause_read/resume_read and the
// hyperdht_stream_pause/resume C API on top of them.
//
// The transport-level effect (peer congestion window closes) is already
// exercised by the loopback stream tests; what needs proving here is the
// state machine: idempotence, correct no-ops outside the started window,
// and null-safety at the FFI boundary.
//
// Loop/udx setup is the `DuplexLoopback` idiom from test_secret_stream.cpp,
// trimmed to a single duplex — pause/resume never needs a completed Noise
// handshake, so a zeroed DuplexHandshake is enough.

#include <gtest/gtest.h>

#include "hyperdht/hyperdht.h"
#include "hyperdht/secret_stream.hpp"

#include <uv.h>

#include <cstring>

using namespace hyperdht::secret_stream;

namespace {

// Two loopback UDX sockets on one libuv loop. `stream1` is the one under
// test; `stream2` only exists so `stream1` has a real peer address to be
// connected to. No packets need to flow.
struct PauseLoopback {
    uv_loop_t loop;
    udx_t udx;
    udx_socket_t sock1;
    udx_socket_t sock2;
    udx_stream_t stream1;
    udx_stream_t stream2;

    // Set when the duplex already destroyed stream1 (destroy() calls
    // udx_stream_destroy), so the destructor doesn't destroy it twice.
    bool stream1_destroyed = false;

    PauseLoopback() {
        uv_loop_init(&loop);
        udx_init(&loop, &udx, nullptr);
        udx_socket_init(&udx, &sock1, nullptr);
        udx_socket_init(&udx, &sock2, nullptr);

        struct sockaddr_in a{};
        uv_ip4_addr("127.0.0.1", 0, &a);
        udx_socket_bind(&sock1, reinterpret_cast<const struct sockaddr*>(&a), 0);
        udx_socket_bind(&sock2, reinterpret_cast<const struct sockaddr*>(&a), 0);

        udx_stream_init(&udx, &stream1, 1, nullptr, nullptr);
        udx_stream_init(&udx, &stream2, 2, nullptr, nullptr);

        struct sockaddr_in b1{}, b2{};
        int len = sizeof(b1);
        udx_socket_getsockname(&sock1, reinterpret_cast<struct sockaddr*>(&b1), &len);
        len = sizeof(b2);
        udx_socket_getsockname(&sock2, reinterpret_cast<struct sockaddr*>(&b2), &len);

        udx_stream_connect(&stream1, &sock1, 2,
                           reinterpret_cast<const struct sockaddr*>(&b2));
        udx_stream_connect(&stream2, &sock2, 1,
                           reinterpret_cast<const struct sockaddr*>(&b1));
    }

    ~PauseLoopback() {
        if (!stream1_destroyed) udx_stream_destroy(&stream1);
        udx_stream_destroy(&stream2);
        udx_socket_close(&sock1);
        udx_socket_close(&sock2);
        uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop);
    }
};

}  // namespace

// Before start() there is no udx read to stop, so both calls must do
// nothing at all — including leaving the paused flag clear, so a later
// start() is not silently shadowed by a stale pause.
TEST(SecretStreamPause, NoOpBeforeStart) {
    PauseLoopback lb;
    SecretStreamDuplex duplex(&lb.stream1, DuplexHandshake{}, &lb.loop);

    duplex.pause_read();
    duplex.pause_read();
    EXPECT_FALSE(duplex.is_read_paused());

    duplex.resume_read();
    duplex.resume_read();
    EXPECT_FALSE(duplex.is_read_paused());
}

// The state machine after start(): both directions idempotent, the flag
// tracks reality.
TEST(SecretStreamPause, IdempotentAfterStart) {
    PauseLoopback lb;
    SecretStreamDuplex duplex(&lb.stream1, DuplexHandshake{}, &lb.loop);

    // The udx read must stay armed across pause/resume. It used to be stopped
    // here, and that is the bug: libudx's process_data_packet() bumps
    // stream->ack before checking on_read (udx.c:1345-1353), so a stopped read
    // acknowledges data to the peer and then drops it. Backpressure lives one
    // layer up now — recv_buf_ holds the bytes and frame extraction stops.
    // The data-level contract is covered by
    // SecretStreamDuplex.PausedReaderLosesNoBytes.
    auto udx_reading = [&lb]() {
        return (lb.stream1.status & UDX_STREAM_READING) != 0;
    };

    duplex.start();
    EXPECT_FALSE(duplex.is_read_paused()) << "reads start armed";
    EXPECT_TRUE(udx_reading());

    duplex.pause_read();
    EXPECT_TRUE(duplex.is_read_paused());
    EXPECT_TRUE(udx_reading()) << "pause must NOT stop the udx read — that loses data";
    duplex.pause_read();
    EXPECT_TRUE(duplex.is_read_paused()) << "second pause must not change state";
    EXPECT_TRUE(udx_reading());

    duplex.resume_read();
    EXPECT_FALSE(duplex.is_read_paused());
    EXPECT_TRUE(udx_reading());
    duplex.resume_read();
    EXPECT_FALSE(duplex.is_read_paused()) << "second resume must not change state";
    EXPECT_TRUE(udx_reading());

    duplex.pause_read();
    EXPECT_TRUE(duplex.is_read_paused());
    duplex.resume_read();
    EXPECT_FALSE(duplex.is_read_paused());
    EXPECT_TRUE(udx_reading());

    duplex.destroy(0);
    lb.stream1_destroyed = true;
}

// After destroy() the raw stream is gone; touching it would be a
// use-after-free, so both calls must bail out.
TEST(SecretStreamPause, NoOpAfterDestroy) {
    PauseLoopback lb;
    SecretStreamDuplex duplex(&lb.stream1, DuplexHandshake{}, &lb.loop);

    duplex.start();
    duplex.pause_read();
    ASSERT_TRUE(duplex.is_read_paused());

    duplex.destroy(0);
    lb.stream1_destroyed = true;

    duplex.resume_read();
    EXPECT_TRUE(duplex.is_read_paused()) << "resume after destroy is a no-op";
    duplex.pause_read();
    EXPECT_TRUE(duplex.is_read_paused());
}

// FFI boundary: a null (or already-closed) stream handle must not crash.
TEST(CAPIStreamPause, NullIsSafe) {
    hyperdht_stream_pause(nullptr);
    hyperdht_stream_resume(nullptr);
    SUCCEED();
}

// The new connect option defaults to off and survives the defaults helper.
TEST(CAPIConnectOpts, ReusableSocketDefaultsOff) {
    hyperdht_connect_opts_t opts;
    memset(&opts, 0xAA, sizeof(opts));
    hyperdht_connect_opts_default(&opts);
    EXPECT_EQ(opts.reusable_socket, 0);
}
