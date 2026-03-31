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
// Context
// ---------------------------------------------------------------------------

struct BootstrapCtx {
    RpcSocket* rpc = nullptr;
    bool response_received = false;
    bool has_id = false;
    bool has_closer_nodes = false;
    size_t closer_count = 0;
    std::string remote_id_hex;
    bool cleaning_up = false;
    uv_timer_t* timer = nullptr;
};

static void on_close(uv_handle_t*) {}

static void cleanup(BootstrapCtx* ctx) {
    if (ctx->cleaning_up) return;
    ctx->cleaning_up = true;
    ctx->rpc->close();
    if (ctx->timer) {
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer), on_close);
    }
}

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(h[data[i] >> 4]);
        out.push_back(h[data[i] & 0x0F]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Test: PING a live HyperDHT bootstrap node
// ---------------------------------------------------------------------------

TEST(RpcBootstrap, PingNode1) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId our_id{};
    our_id.fill(0x42);
    RpcSocket rpc(&loop, our_id);
    ASSERT_EQ(rpc.bind(0), 0);

    BootstrapCtx ctx;
    ctx.rpc = &rpc;

    // PING bootstrap node 1: 88.99.3.86:49737
    Request req;
    req.to.addr = Ipv4Address::from_string("88.99.3.86", 49737);
    req.command = CMD_PING;

    rpc.request(req,
        [&ctx](const Response& resp) {
            ctx.response_received = true;
            ctx.has_id = resp.id.has_value();
            if (resp.id.has_value()) {
                ctx.remote_id_hex = to_hex(resp.id->data(), resp.id->size());
            }
            cleanup(&ctx);
        },
        [&ctx](uint16_t) {
            cleanup(&ctx);
        });

    // 5s timeout (network request)
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<BootstrapCtx*>(t->data);
        c->timer = nullptr;
        cleanup(c);
    }, 5000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    if (ctx.response_received) {
        printf("  Bootstrap node responded!\n");
        if (ctx.has_id) {
            printf("  Node ID: %s\n", ctx.remote_id_hex.c_str());
        }
        EXPECT_TRUE(ctx.has_id) << "Bootstrap should include its node ID";
    } else {
        printf("  Bootstrap node did not respond (network issue?)\n");
        // Don't fail the test if the bootstrap is unreachable
        GTEST_SKIP() << "Bootstrap node unreachable — skipping";
    }

    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Test: FIND_NODE against a live bootstrap node
// ---------------------------------------------------------------------------

TEST(RpcBootstrap, FindNode) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId our_id{};
    our_id.fill(0x42);
    RpcSocket rpc(&loop, our_id);
    ASSERT_EQ(rpc.bind(0), 0);

    BootstrapCtx ctx;
    ctx.rpc = &rpc;

    // FIND_NODE with our own ID as target
    Request req;
    req.to.addr = Ipv4Address::from_string("88.99.3.86", 49737);
    req.command = CMD_FIND_NODE;
    req.target = our_id;

    rpc.request(req,
        [&ctx](const Response& resp) {
            ctx.response_received = true;
            ctx.has_id = resp.id.has_value();
            ctx.has_closer_nodes = !resp.closer_nodes.empty();
            ctx.closer_count = resp.closer_nodes.size();
            if (resp.id.has_value()) {
                ctx.remote_id_hex = to_hex(resp.id->data(), resp.id->size());
            }
            cleanup(&ctx);
        },
        [&ctx](uint16_t) {
            cleanup(&ctx);
        });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<BootstrapCtx*>(t->data);
        c->timer = nullptr;
        cleanup(c);
    }, 5000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    if (ctx.response_received) {
        printf("  Bootstrap responded to FIND_NODE!\n");
        if (ctx.has_id) {
            printf("  Node ID: %s\n", ctx.remote_id_hex.c_str());
        }
        printf("  Closer nodes returned: %zu\n", ctx.closer_count);
        EXPECT_TRUE(ctx.has_closer_nodes)
            << "FIND_NODE should return closer nodes from a bootstrap";
    } else {
        GTEST_SKIP() << "Bootstrap node unreachable — skipping";
    }

    uv_loop_close(&loop);
}
