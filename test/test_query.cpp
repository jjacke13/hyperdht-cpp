#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

#include <uv.h>

#include "hyperdht/query.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"

using namespace hyperdht;
using namespace hyperdht::query;
using namespace hyperdht::rpc;
using namespace hyperdht::routing;
using namespace hyperdht::messages;
using namespace hyperdht::compact;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; i++) {
        out.push_back(h[data[i] >> 4]);
        out.push_back(h[data[i] & 0x0F]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Test: loopback query between two C++ nodes
// ---------------------------------------------------------------------------

TEST(Query, LoopbackFindNode) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Create "server" node with some peers in its routing table
    NodeId server_id{};
    server_id.fill(0x11);
    RpcSocket server(&loop, server_id);
    server.bind(0);
    RpcHandlers handlers(server);
    handlers.install();

    // Populate server's routing table with fake nodes
    for (int i = 1; i <= 10; i++) {
        Node node;
        node.id.fill(0x00);
        node.id[0] = static_cast<uint8_t>(i);
        node.host = "10.0.0." + std::to_string(i);
        node.port = static_cast<uint16_t>(9000 + i);
        server.table().add(node);
    }

    // Create "client" node
    NodeId client_id{};
    client_id.fill(0x22);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    // Add the server as a bootstrap node
    NodeId target{};
    target.fill(0x00);
    target[0] = 0x05;  // Close to some of the fake nodes

    bool query_done = false;
    size_t replies_count = 0;
    std::vector<QueryReply> final_closest;

    Query q(client, target, CMD_FIND_NODE);
    q.set_internal(true);
    q.add_bootstrap(Ipv4Address::from_string("127.0.0.1", server.port()));

    q.on_reply([&](const QueryReply&) {
        replies_count++;
    });

    q.on_done([&](const std::vector<QueryReply>& closest) {
        query_done = true;
        final_closest = closest;
        // Cleanup
        server.close();
        client.close();
    });

    q.start();

    // Timeout
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    struct TimerCtx { RpcSocket* s; RpcSocket* c; uv_timer_t* t; };
    TimerCtx tctx{&server, &client, &timer};
    timer.data = &tctx;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* ctx = static_cast<TimerCtx*>(t->data);
        ctx->s->close();
        ctx->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 5000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(query_done) << "Query should complete";
    EXPECT_GE(replies_count, 1u) << "Should get at least one reply";

    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Test: iterative FIND_NODE against live bootstrap
// ---------------------------------------------------------------------------

TEST(Query, LiveBootstrapFindNode) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId our_id{};
    our_id.fill(0x42);
    RpcSocket rpc(&loop, our_id);
    rpc.bind(0);

    // Target: random-ish key
    NodeId target{};
    target.fill(0x77);

    bool query_done = false;
    size_t replies_count = 0;
    size_t total_closer_nodes = 0;
    std::vector<QueryReply> final_closest;

    Query q(rpc, target, CMD_FIND_NODE);
    q.set_internal(true);
    q.set_concurrency(5);

    // Seed with all 3 bootstrap nodes
    q.add_bootstrap(Ipv4Address::from_string("88.99.3.86", 49737));
    q.add_bootstrap(Ipv4Address::from_string("142.93.90.113", 49737));
    q.add_bootstrap(Ipv4Address::from_string("138.68.147.8", 49737));

    q.on_reply([&](const QueryReply& reply) {
        replies_count++;
        total_closer_nodes += reply.closer_nodes.size();
    });

    q.on_done([&](const std::vector<QueryReply>& closest) {
        query_done = true;
        final_closest = closest;
        rpc.close();
    });

    q.start();

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &rpc;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* r = static_cast<RpcSocket*>(t->data);
        r->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 15000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    if (query_done) {
        printf("  Iterative FIND_NODE completed!\n");
        printf("  Total replies: %zu\n", replies_count);
        printf("  Total closer nodes discovered: %zu\n", total_closer_nodes);
        printf("  Final closest replies: %zu\n", final_closest.size());
        if (!final_closest.empty()) {
            printf("  Closest node ID: %s\n",
                   to_hex(final_closest[0].from_id.data(), 8).c_str());
        }
        EXPECT_GE(replies_count, 3u) << "Should get multiple replies from iteration";
        EXPECT_GE(final_closest.size(), 1u);
    } else {
        GTEST_SKIP() << "Network unreachable — skipping";
    }

    uv_loop_close(&loop);
}
