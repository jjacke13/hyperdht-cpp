#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include <uv.h>

#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"

using namespace hyperdht::rpc;
using namespace hyperdht::messages;
using namespace hyperdht::compact;
using namespace hyperdht::routing;

// ---------------------------------------------------------------------------
// Test: handlers respond to self-sent requests (loopback)
// ---------------------------------------------------------------------------

struct LoopbackCtx {
    RpcSocket* server = nullptr;
    RpcSocket* client = nullptr;
    bool response_received = false;
    bool has_id = false;
    bool has_token = false;
    size_t closer_count = 0;
    bool cleaning_up = false;
    uv_timer_t* timer = nullptr;
};

static void on_close(uv_handle_t*) {}

static void loopback_cleanup(LoopbackCtx* ctx) {
    if (ctx->cleaning_up) return;
    ctx->cleaning_up = true;
    ctx->server->close();
    ctx->client->close();
    if (ctx->timer) {
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer), on_close);
        ctx->timer = nullptr;
    }
}

TEST(RpcHandlers, PingReply) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0x11);
    RpcSocket server(&loop, server_id);
    server.bind(0);

    RpcHandlers handlers(server);
    handlers.install();

    NodeId client_id{};
    client_id.fill(0x22);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    LoopbackCtx ctx;
    ctx.server = &server;
    ctx.client = &client;

    Request req;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    req.command = CMD_PING;
    req.internal = true;

    client.request(req,
        [&ctx, &server_id](const Response& resp) {
            ctx.response_received = true;
            ctx.has_id = resp.id.has_value();
            ctx.has_token = resp.token.has_value();
            if (ctx.has_id) {
                // Verify server returned its own ID
                EXPECT_EQ(*resp.id, server_id);
            }
            loopback_cleanup(&ctx);
        },
        [&ctx](uint16_t) { loopback_cleanup(&ctx); });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<LoopbackCtx*>(t->data);
        c->timer = nullptr;
        loopback_cleanup(c);
    }, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(ctx.response_received) << "Should receive PING response";
    EXPECT_TRUE(ctx.has_id) << "PING response should include node ID";
    EXPECT_TRUE(ctx.has_token) << "PING response should include token";

    uv_loop_close(&loop);
}

TEST(RpcHandlers, FindNodeReply) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0x11);
    RpcSocket server(&loop, server_id);
    server.bind(0);

    // Add some nodes to the server's routing table
    for (int i = 1; i <= 5; i++) {
        Node node;
        node.id.fill(0x00);
        node.id[0] = static_cast<uint8_t>(i);
        node.host = "192.168.1." + std::to_string(i);
        node.port = static_cast<uint16_t>(8000 + i);
        server.table().add(node);
    }

    RpcHandlers handlers(server);
    handlers.install();

    NodeId client_id{};
    client_id.fill(0x22);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    LoopbackCtx ctx;
    ctx.server = &server;
    ctx.client = &client;

    Request req;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    req.command = CMD_FIND_NODE;
    req.internal = true;
    std::array<uint8_t, 32> target{};
    target.fill(0x00);
    target[0] = 0x03;  // Close to nodes we added
    req.target = target;

    client.request(req,
        [&ctx](const Response& resp) {
            ctx.response_received = true;
            ctx.has_id = resp.id.has_value();
            ctx.has_token = resp.token.has_value();
            ctx.closer_count = resp.closer_nodes.size();
            loopback_cleanup(&ctx);
        },
        [&ctx](uint16_t) { loopback_cleanup(&ctx); });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<LoopbackCtx*>(t->data);
        c->timer = nullptr;
        loopback_cleanup(c);
    }, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(ctx.response_received) << "Should receive FIND_NODE response";
    EXPECT_TRUE(ctx.has_id) << "Response should include node ID";
    EXPECT_TRUE(ctx.has_token) << "Response should include token";
    EXPECT_EQ(ctx.closer_count, 5u) << "Should return all 5 nodes";

    uv_loop_close(&loop);
}
