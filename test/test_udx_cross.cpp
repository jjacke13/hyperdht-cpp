#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include "hyperdht/udx.hpp"

using namespace hyperdht::udx;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static struct sockaddr_in make_addr(const char* ip, uint16_t port) {
    struct sockaddr_in addr{};
    uv_ip4_addr(ip, port, &addr);
    return addr;
}

static uint16_t get_port(UdxSocket& sock) {
    struct sockaddr_in addr{};
    int len = sizeof(addr);
    sock.getsockname(reinterpret_cast<struct sockaddr*>(&addr), &len);
    return ntohs(addr.sin_port);
}

// ---------------------------------------------------------------------------
// Cross-test context
// ---------------------------------------------------------------------------

struct CrossCtx {
    bool port_received = false;
    uint16_t js_port = 0;
    bool read_called = false;
    bool eof_received = false;
    std::string received_data;
    std::string pipe_buf;
    std::string payload;  // data to send (set per test)

    UdxSocket* sock = nullptr;
    UdxStream* stream = nullptr;
    uv_process_t* process = nullptr;
    uv_pipe_t* stdout_pipe = nullptr;
    int streams_closed = 0;
};

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

static void on_stream_read(udx_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

static void on_alloc(uv_handle_t*, size_t suggested, uv_buf_t* buf) {
    buf->base = new char[suggested];
    buf->len = static_cast<unsigned int>(suggested);
}

static void on_pipe_read(uv_stream_t* pipe, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<CrossCtx*>(pipe->data);

    if (nread > 0) {
        ctx->pipe_buf.append(buf->base, static_cast<size_t>(nread));

        auto pos = ctx->pipe_buf.find("PORT:");
        if (pos != std::string::npos) {
            auto nl = ctx->pipe_buf.find('\n', pos);
            if (nl != std::string::npos) {
                auto port_str = ctx->pipe_buf.substr(pos + 5, nl - pos - 5);
                ctx->js_port = static_cast<uint16_t>(std::stoi(port_str));
                ctx->port_received = true;

                uv_read_stop(pipe);

                // Connect our stream to the JS side
                auto js_addr = make_addr("127.0.0.1", ctx->js_port);
                ctx->stream->connect(*ctx->sock, 1,
                    reinterpret_cast<const struct sockaddr*>(&js_addr));

                // Start reading echoed data
                ctx->stream->read_start(on_stream_read);

                // Write payload and signal end
                uv_buf_t wbuf = uv_buf_init(
                    const_cast<char*>(ctx->payload.data()),
                    static_cast<unsigned int>(ctx->payload.size()));
                auto* write_req = static_cast<udx_stream_write_t*>(
                    malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
                udx_stream_write_end(write_req, ctx->stream->handle(), &wbuf, 1, nullptr);
            }
        }
    }

    delete[] buf->base;
}

static void on_stream_read(udx_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<CrossCtx*>(stream->data);

    if (nread == UV_EOF) {
        ctx->eof_received = true;
        return;
    }
    if (nread < 0) return;

    ctx->read_called = true;
    ctx->received_data.append(buf->base, static_cast<size_t>(nread));
}

static void on_close_handle(uv_handle_t*) {}

static void on_stream_close(udx_stream_t* stream, int) {
    auto* ctx = static_cast<CrossCtx*>(stream->data);
    ctx->streams_closed++;

    uv_process_kill(ctx->process, SIGTERM);
    uv_close(reinterpret_cast<uv_handle_t*>(ctx->process), on_close_handle);
    uv_close(reinterpret_cast<uv_handle_t*>(ctx->stdout_pipe), on_close_handle);
    ctx->sock->close();
}

static void on_process_exit(uv_process_t*, int64_t, int) {}

static int on_firewall(udx_stream_t*, udx_socket_t*, const struct sockaddr*) {
    return 0;  // allow all
}

// ---------------------------------------------------------------------------
// Helper: run a cross-test echo round-trip with the given payload
// ---------------------------------------------------------------------------

static void run_echo_round_trip(CrossCtx& ctx) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    Udx udx(&loop);
    UdxSocket sock(udx);

    auto bind_addr = make_addr("127.0.0.1", 0);
    ASSERT_EQ(sock.bind(reinterpret_cast<const struct sockaddr*>(&bind_addr)), 0);
    uint16_t our_port = get_port(sock);
    ASSERT_NE(our_port, 0);

    // Stream ID=2, firewall allows all, read_start after connect (in pipe callback)
    UdxStream stream(udx, 2, on_stream_close, nullptr);
    stream.firewall(on_firewall);

    ctx.sock = &sock;
    ctx.stream = &stream;
    stream.handle()->data = &ctx;

    // Spawn JS echo server with our port as argument
    uv_pipe_t stdout_pipe;
    uv_pipe_init(&loop, &stdout_pipe, 0);
    stdout_pipe.data = &ctx;
    ctx.stdout_pipe = &stdout_pipe;

    uv_process_t process;
    ctx.process = &process;

    std::string test_dir = __FILE__;
    test_dir = test_dir.substr(0, test_dir.rfind('/'));
    std::string script = test_dir + "/js/udx_echo_server.js";
    std::string port_arg = std::to_string(our_port);

    char* args[] = {
        const_cast<char*>("node"),
        const_cast<char*>(script.c_str()),
        const_cast<char*>(port_arg.c_str()),
        nullptr
    };

    uv_process_options_t opts{};
    uv_stdio_container_t stdio[3];
    stdio[0].flags = UV_IGNORE;
    // UV_WRITABLE_PIPE: child writes to stdout, parent reads
    stdio[1].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
    stdio[1].data.stream = reinterpret_cast<uv_stream_t*>(&stdout_pipe);
    stdio[2].flags = UV_INHERIT_FD;
    stdio[2].data.fd = 2;
    opts.stdio_count = 3;
    opts.stdio = stdio;
    opts.file = "node";
    opts.args = args;
    opts.exit_cb = on_process_exit;

    int rc = uv_spawn(&loop, &process, &opts);
    ASSERT_EQ(rc, 0) << "Failed to spawn node: " << uv_strerror(rc);

    uv_read_start(reinterpret_cast<uv_stream_t*>(&stdout_pipe), on_alloc, on_pipe_read);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(ctx.port_received) << "Never received PORT line from JS";
    EXPECT_TRUE(ctx.read_called) << "Never received echoed data";
    EXPECT_TRUE(ctx.eof_received) << "Never received EOF from JS";

    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Test: C++ ↔ JS UDX echo round-trip
// ---------------------------------------------------------------------------

TEST(UdxCross, EchoRoundTrip) {
    CrossCtx ctx;
    ctx.payload = "cross-test";
    run_echo_round_trip(ctx);
    EXPECT_EQ(ctx.received_data, "cross-test");
}

// ---------------------------------------------------------------------------
// Test: Large structured payload — proves no truncation or corruption
// ---------------------------------------------------------------------------

TEST(UdxCross, LargeStructuredPayload) {
    std::string payload;
    payload.reserve(1000);
    for (int i = 0; i < 100; i++) {
        payload += "ABCDEFGHIJ";
    }
    ASSERT_EQ(payload.size(), 1000u);

    CrossCtx ctx;
    ctx.payload = payload;
    run_echo_round_trip(ctx);
    EXPECT_EQ(ctx.received_data.size(), 1000u);
    EXPECT_EQ(ctx.received_data, payload);
}

// ---------------------------------------------------------------------------
// Mismatched stream ID — negative test context and callbacks
// ---------------------------------------------------------------------------

struct MismatchCtx {
    bool port_received = false;
    uint16_t js_port = 0;
    bool read_called = false;
    bool timed_out = false;
    std::string received_data;
    std::string pipe_buf;

    UdxSocket* sock = nullptr;
    UdxStream* stream = nullptr;
    uv_process_t* process = nullptr;
    uv_pipe_t* stdout_pipe = nullptr;
    uv_timer_t* timer = nullptr;
};

static void mm_on_close(uv_handle_t*) {}

static void mm_on_stream_read(udx_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<MismatchCtx*>(stream->data);
    if (nread > 0) {
        ctx->read_called = true;
        ctx->received_data.append(buf->base, static_cast<size_t>(nread));
    }
}

static void mm_force_cleanup(uv_timer_t* timer) {
    auto* ctx = static_cast<MismatchCtx*>(timer->data);
    ctx->timed_out = true;

    // Destroy the stream (it won't close cleanly since IDs don't match)
    udx_stream_destroy(ctx->stream->handle());

    uv_process_kill(ctx->process, SIGTERM);
    uv_close(reinterpret_cast<uv_handle_t*>(ctx->process), mm_on_close);
    uv_close(reinterpret_cast<uv_handle_t*>(ctx->stdout_pipe), mm_on_close);
    uv_close(reinterpret_cast<uv_handle_t*>(timer), mm_on_close);
    ctx->sock->close();
}

static void mm_on_pipe_read(uv_stream_t* pipe, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<MismatchCtx*>(pipe->data);

    if (nread > 0) {
        ctx->pipe_buf.append(buf->base, static_cast<size_t>(nread));

        auto pos = ctx->pipe_buf.find("PORT:");
        if (pos != std::string::npos) {
            auto nl = ctx->pipe_buf.find('\n', pos);
            if (nl != std::string::npos) {
                auto port_str = ctx->pipe_buf.substr(pos + 5, nl - pos - 5);
                ctx->js_port = static_cast<uint16_t>(std::stoi(port_str));
                ctx->port_received = true;

                uv_read_stop(pipe);

                // Connect with remote_id=1 (correct JS stream ID) but our
                // local stream has ID=999 — JS expects remote_id=2, so
                // packets it sends targeting stream 2 won't reach us.
                auto js_addr = make_addr("127.0.0.1", ctx->js_port);
                ctx->stream->connect(*ctx->sock, 1,
                    reinterpret_cast<const struct sockaddr*>(&js_addr));

                ctx->stream->read_start(mm_on_stream_read);

                // Write data + end
                static const std::string msg = "should-fail";
                uv_buf_t wbuf = uv_buf_init(const_cast<char*>(msg.data()),
                    static_cast<unsigned int>(msg.size()));
                auto* wr = static_cast<udx_stream_write_t*>(
                    malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
                udx_stream_write_end(wr, ctx->stream->handle(), &wbuf, 1, nullptr);

                // Start the 2s cleanup timer — the mismatched connection
                // won't close cleanly, so we force-stop the loop
                uv_timer_start(ctx->timer, mm_force_cleanup, 2000, 0);
            }
        }
    }

    delete[] buf->base;
}

// ---------------------------------------------------------------------------
// Test: Mismatched stream ID — proves stream IDs matter
// ---------------------------------------------------------------------------

TEST(UdxCross, MismatchedStreamIdFails) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    Udx udx(&loop);
    UdxSocket sock(udx);

    auto bind_addr = make_addr("127.0.0.1", 0);
    ASSERT_EQ(sock.bind(reinterpret_cast<const struct sockaddr*>(&bind_addr)), 0);
    uint16_t our_port = get_port(sock);
    ASSERT_NE(our_port, 0);

    // Wrong stream ID: 999 instead of 2 (JS expects remote_id=2)
    UdxStream stream(udx, 999, nullptr, nullptr);
    stream.firewall(on_firewall);

    MismatchCtx ctx;
    ctx.sock = &sock;
    ctx.stream = &stream;
    stream.handle()->data = &ctx;

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;

    uv_pipe_t stdout_pipe;
    uv_pipe_init(&loop, &stdout_pipe, 0);
    stdout_pipe.data = &ctx;
    ctx.stdout_pipe = &stdout_pipe;

    uv_process_t process;
    ctx.process = &process;

    std::string test_dir = __FILE__;
    test_dir = test_dir.substr(0, test_dir.rfind('/'));
    std::string script = test_dir + "/js/udx_echo_server.js";
    std::string port_arg = std::to_string(our_port);

    char* args[] = {
        const_cast<char*>("node"),
        const_cast<char*>(script.c_str()),
        const_cast<char*>(port_arg.c_str()),
        nullptr
    };

    uv_process_options_t opts{};
    uv_stdio_container_t stdio[3];
    stdio[0].flags = UV_IGNORE;
    stdio[1].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
    stdio[1].data.stream = reinterpret_cast<uv_stream_t*>(&stdout_pipe);
    stdio[2].flags = UV_INHERIT_FD;
    stdio[2].data.fd = 2;
    opts.stdio_count = 3;
    opts.stdio = stdio;
    opts.file = "node";
    opts.args = args;
    opts.exit_cb = on_process_exit;

    int rc = uv_spawn(&loop, &process, &opts);
    ASSERT_EQ(rc, 0) << "Failed to spawn node: " << uv_strerror(rc);

    uv_read_start(reinterpret_cast<uv_stream_t*>(&stdout_pipe), on_alloc, mm_on_pipe_read);

    uv_run(&loop, UV_RUN_DEFAULT);

    // We got the port (JS started fine) but no echoed data came back
    EXPECT_TRUE(ctx.port_received) << "Never received PORT line from JS";
    EXPECT_TRUE(ctx.received_data.empty()) << "Should not receive data with wrong stream ID";
    EXPECT_FALSE(ctx.read_called) << "Read callback should not fire with wrong stream ID";
    EXPECT_TRUE(ctx.timed_out) << "Should have timed out (no clean close with wrong IDs)";

    uv_loop_close(&loop);
}
