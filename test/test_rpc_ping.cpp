#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

#include <uv.h>

#include "hyperdht/rpc.hpp"

using namespace hyperdht::rpc;
using namespace hyperdht::messages;
using namespace hyperdht::compact;
using namespace hyperdht::routing;

// ---------------------------------------------------------------------------
// Context for the cross-test
// ---------------------------------------------------------------------------

struct PingCtx {
    RpcSocket* rpc = nullptr;
    uint16_t js_port = 0;
    bool port_received = false;
    bool response_received = false;
    uint16_t response_tid = 0;
    std::string pipe_buf;
    bool cleaning_up = false;

    uv_pipe_t stdout_pipe;
    uv_process_t process;
    uv_timer_t* timer = nullptr;
};

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

static void on_alloc(uv_handle_t*, size_t suggested, uv_buf_t* buf) {
    buf->base = new char[suggested];
    buf->len = static_cast<unsigned int>(suggested);
}

static void on_close(uv_handle_t*) {}

static void on_process_exit(uv_process_t*, int64_t, int) {}

static void cleanup(PingCtx* ctx) {
    if (ctx->cleaning_up) return;
    ctx->cleaning_up = true;

    ctx->rpc->close();
    uv_process_kill(&ctx->process, SIGTERM);
    uv_close(reinterpret_cast<uv_handle_t*>(&ctx->process), on_close);
    uv_close(reinterpret_cast<uv_handle_t*>(&ctx->stdout_pipe), on_close);
    if (ctx->timer) {
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer), on_close);
    }
}

static void on_pipe_read(uv_stream_t* pipe, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<PingCtx*>(pipe->data);

    if (nread > 0) {
        ctx->pipe_buf.append(buf->base, static_cast<size_t>(nread));

        auto pos = ctx->pipe_buf.find("PORT:");
        if (pos != std::string::npos) {
            auto nl = ctx->pipe_buf.find('\n', pos);
            if (nl != std::string::npos && !ctx->port_received) {
                auto port_str = ctx->pipe_buf.substr(pos + 5, nl - pos - 5);
                ctx->js_port = static_cast<uint16_t>(std::stoi(port_str));
                ctx->port_received = true;

                uv_read_stop(pipe);

                // Send PING to JS node
                Request req;
                req.to.addr = Ipv4Address::from_string("127.0.0.1", ctx->js_port);
                req.command = CMD_PING;

                ctx->rpc->request(req,
                    [ctx](const Response& resp) {
                        ctx->response_received = true;
                        ctx->response_tid = resp.tid;
                        cleanup(ctx);
                    },
                    [ctx](uint16_t) {
                        cleanup(ctx);
                    });
            }
        }
    }

    delete[] buf->base;
}

// ---------------------------------------------------------------------------
// Test: C++ sends PING to JS dht-rpc node, receives response
// ---------------------------------------------------------------------------

TEST(RpcPing, CrossTestWithJS) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Create RPC socket with random node ID
    NodeId our_id{};
    our_id.fill(0x42);
    RpcSocket rpc(&loop, our_id);
    ASSERT_EQ(rpc.bind(0), 0);

    PingCtx ctx;
    ctx.rpc = &rpc;

    // Spawn JS dht-rpc node
    uv_pipe_init(&loop, &ctx.stdout_pipe, 0);
    ctx.stdout_pipe.data = &ctx;

    std::string test_dir = __FILE__;
    test_dir = test_dir.substr(0, test_dir.rfind('/'));
    std::string script = test_dir + "/js/dht_ping_server.js";

    char* args[] = {
        const_cast<char*>("node"),
        const_cast<char*>(script.c_str()),
        nullptr
    };

    uv_process_options_t opts{};
    uv_stdio_container_t stdio[3];
    stdio[0].flags = UV_IGNORE;
    stdio[1].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
    stdio[1].data.stream = reinterpret_cast<uv_stream_t*>(&ctx.stdout_pipe);
    stdio[2].flags = UV_INHERIT_FD;
    stdio[2].data.fd = 2;
    opts.stdio_count = 3;
    opts.stdio = stdio;
    opts.file = "node";
    opts.args = args;
    opts.exit_cb = on_process_exit;

    int rc = uv_spawn(&loop, &ctx.process, &opts);
    ASSERT_EQ(rc, 0) << "Failed to spawn node: " << uv_strerror(rc);

    uv_read_start(reinterpret_cast<uv_stream_t*>(&ctx.stdout_pipe),
                  on_alloc, on_pipe_read);

    // Timeout timer
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<PingCtx*>(t->data);
        c->timer = nullptr;  // Timer is closing itself
        cleanup(c);
    }, 5000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(ctx.port_received) << "Should receive PORT from JS";
    EXPECT_TRUE(ctx.response_received) << "Should receive PING response from JS dht-rpc";

    uv_loop_close(&loop);
}
