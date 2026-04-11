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

    auto q = Query::create(client, target, CMD_FIND_NODE);
    q->set_internal(true);
    q->add_bootstrap(Ipv4Address::from_string("127.0.0.1", server.port()));

    q->on_reply([&](const QueryReply&) {
        replies_count++;
    });

    q->on_done([&](const std::vector<QueryReply>& closest) {
        query_done = true;
        final_closest = closest;
        server.close();
        client.close();
    });

    q->start();

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

    auto q = Query::create(rpc, target, CMD_FIND_NODE);
    q->set_internal(true);
    q->set_concurrency(5);

    // Seed with all 3 bootstrap nodes
    q->add_bootstrap(Ipv4Address::from_string("88.99.3.86", 49737));
    q->add_bootstrap(Ipv4Address::from_string("142.93.90.113", 49737));
    q->add_bootstrap(Ipv4Address::from_string("138.68.147.8", 49737));

    q->on_reply([&](const QueryReply& reply) {
        replies_count++;
        total_closer_nodes += reply.closer_nodes.size();
    });

    q->on_done([&](const std::vector<QueryReply>& closest) {
        query_done = true;
        final_closest = closest;
        rpc.close();
    });

    q->start();

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

// ---------------------------------------------------------------------------
// §1a regression: closest_nodes() returns the `from_addr` of each closest
// reply in the same XOR-distance order as closest_replies().
// JS parity: dht-rpc/lib/query.js:72-80.
// ---------------------------------------------------------------------------

TEST(Query, ClosestNodesMirrorsClosestReplies) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0x33);
    RpcSocket server(&loop, server_id);
    server.bind(0);
    RpcHandlers handlers(server);
    handlers.install();

    for (int i = 1; i <= 10; i++) {
        Node node;
        node.id.fill(0x00);
        node.id[0] = static_cast<uint8_t>(i);
        node.host = "10.0.0." + std::to_string(i);
        node.port = static_cast<uint16_t>(9000 + i);
        server.table().add(node);
    }

    NodeId client_id{};
    client_id.fill(0x44);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    NodeId target{};
    target.fill(0x00);
    target[0] = 0x05;

    bool query_done = false;
    std::vector<Ipv4Address> final_nodes;
    std::vector<QueryReply> final_replies;

    auto q = Query::create(client, target, CMD_FIND_NODE);
    q->set_internal(true);
    q->add_bootstrap(Ipv4Address::from_string("127.0.0.1", server.port()));

    q->on_done([&](const std::vector<QueryReply>& closest) {
        query_done = true;
        final_replies = closest;
        final_nodes = q->closest_nodes();
        server.close();
        client.close();
    });

    q->start();

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    struct Ctx { RpcSocket* s; RpcSocket* c; };
    Ctx ctx{&server, &client};
    timer.data = &ctx;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->s->close();
        c->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 5000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(query_done);
    ASSERT_EQ(final_nodes.size(), final_replies.size());
    for (size_t i = 0; i < final_nodes.size(); i++) {
        EXPECT_EQ(final_nodes[i].host, final_replies[i].from_addr.host);
        EXPECT_EQ(final_nodes[i].port, final_replies[i].from_addr.port);
    }

    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// §1b regression: a query that seeds from the routing table has from_table_
// set to true after start(), and slowdown_ stays off (the slowdown only
// applies to externally-seeded queries).
// JS parity: dht-rpc/lib/query.js:36, 111-120, 189-191.
// ---------------------------------------------------------------------------

TEST(Query, FromTableFlagWhenSeededFromRoutingTable) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId our_id{};
    our_id.fill(0x55);
    RpcSocket rpc(&loop, our_id);
    rpc.bind(0);

    // Populate our own routing table so seed_from_table has something
    // to add. These nodes don't need to respond — we only care about
    // the flag state immediately after start().
    for (int i = 1; i <= 5; i++) {
        Node node;
        node.id.fill(0x00);
        node.id[0] = static_cast<uint8_t>(i);
        node.host = "10.0.0." + std::to_string(i);
        node.port = static_cast<uint16_t>(9000 + i);
        rpc.table().add(node);
    }

    NodeId target{};
    target.fill(0x22);
    auto q = Query::create(rpc, target, CMD_FIND_NODE);
    q->set_internal(true);

    EXPECT_FALSE(q->from_table());
    EXPECT_FALSE(q->slowdown_engaged());

    q->start();

    // Table seed happened during start() — flag should flip.
    EXPECT_TRUE(q->from_table());
    // Slowdown is gated on !from_table_, so it must stay off.
    EXPECT_FALSE(q->slowdown_engaged());

    rpc.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// §1b regression: when the caller pre-seeds the frontier with >= k nodes,
// seed_from_table() early-returns without setting from_table_, and the
// cold-start slowdown engages on the first read_more tick.
// JS parity: dht-rpc/lib/query.js:111-120, 189-191.
// ---------------------------------------------------------------------------

TEST(Query, SlowdownEngagesOnExternallySeededQuery) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId our_id{};
    our_id.fill(0x66);
    RpcSocket rpc(&loop, our_id);
    rpc.bind(0);

    NodeId target{};
    target.fill(0xAA);
    auto q = Query::create(rpc, target, CMD_FIND_NODE);
    q->set_internal(true);

    // Pre-seed with enough nodes that _addFromTable must early-return.
    // Addresses are bogus on purpose — we just need the frontier to
    // reach k entries before start().
    for (int i = 0; i < static_cast<int>(routing::K); i++) {
        NodeId id{};
        id.fill(0x00);
        id[0] = static_cast<uint8_t>(i + 1);
        auto addr = Ipv4Address::from_string(
            "203.0.113." + std::to_string(i + 1), 54321);
        q->add_seed_node(id, addr);
    }

    q->start();

    // from_table_ must stay false because the caller filled pending to k.
    EXPECT_FALSE(q->from_table());
    // slowdown_ must engage on the first read_more tick (no replies yet).
    EXPECT_TRUE(q->slowdown_engaged());

    // Clean up without running the loop — the in-flight requests will be
    // torn down by close().
    rpc.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// §1c regression: an externally-seeded query whose seeds all fail (> 3/4 of
// the cached nodes come back with error responses) must re-seed from the
// routing table and continue walking. We use a pair of loopback servers:
//   - "reject_server" accepts any incoming request and replies with error=1,
//     so seeded requests resolve fast and count as errors_++ (no wait for
//     the 4s retry budget to expire).
//   - "live_server" acts as the real DHT peer reachable via the client's
//     routing table. It's the only way to reach a success after §1c fires.
//
// JS parity: dht-rpc/lib/query.js:200-205.
// ---------------------------------------------------------------------------

TEST(Query, TableRetryAfterExternalSeedFlood) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // ---- Reject server: immediately replies with error=1 to every request.
    //      Bound on 0.0.0.0 so that 127.0.0.X aliases on the loopback
    //      interface all land here, letting us flood past k with unique
    //      host:port keys while keeping exactly one server process.
    NodeId reject_id{};
    reject_id.fill(0xEE);
    RpcSocket reject_server(&loop, reject_id);
    reject_server.bind(0, "0.0.0.0");
    reject_server.on_request([&](const Request& req) {
        Response resp;
        resp.tid = req.tid;
        resp.from.addr = req.from.addr;
        resp.id = reject_id;
        resp.error = 1;  // Non-zero → Query counts as error, not success.
        reject_server.reply(resp);
    });

    // ---- Live server: real DHT node, reachable only via client's routing
    //      table. Reaching it is proof that §1c's table-retry fired.
    NodeId live_id{};
    live_id.fill(0x99);
    RpcSocket live_server(&loop, live_id);
    live_server.bind(0);
    RpcHandlers live_handlers(live_server);
    live_handlers.install();

    // ---- Client with the live server installed as a table peer.
    NodeId client_id{};
    client_id.fill(0xAA);
    RpcSocket client(&loop, client_id);
    client.bind(0);
    Node server_as_peer;
    server_as_peer.id = live_id;
    server_as_peer.host = "127.0.0.1";
    server_as_peer.port = live_server.port();
    client.table().add(server_as_peer);

    NodeId target{};
    target.fill(0x05);

    auto q = Query::create(client, target, CMD_FIND_NODE);
    q->set_internal(true);

    // Flood the external seed with >= k reject addresses so seed_from_table
    // in start() must early-return (_addFromTable's pending >= k guard).
    // Each entry uses a different 127.0.0.X host so the seen_ map keys
    // stay unique while all packets actually land at the single reject
    // server bound on 0.0.0.0:reject_port.
    const uint16_t reject_port = reject_server.port();
    for (int i = 0; i < static_cast<int>(routing::K); i++) {
        NodeId fake_id{};
        fake_id.fill(0x00);
        fake_id[0] = static_cast<uint8_t>(i + 1);
        // 127.0.0.1 is the normal loopback; 127.0.0.2..20 are also loopback
        // aliases on Linux and route to the reject_server's 0.0.0.0 bind.
        auto addr = Ipv4Address::from_string(
            "127.0.0." + std::to_string(i + 1), reject_port);
        q->add_seed_node(fake_id, addr);
    }

    bool query_done = false;
    bool saw_from_table_flip = false;
    int saw_successes = 0;
    int saw_errors = 0;
    q->on_done([&](const std::vector<QueryReply>& /*closest*/) {
        query_done = true;
        saw_from_table_flip = q->from_table();
        saw_successes = q->successes();
        saw_errors = q->errors();
        reject_server.close();
        live_server.close();
        client.close();
    });

    q->start();
    // Immediately after start(): caller filled pending past k, so
    // from_table_ must still be false.
    EXPECT_FALSE(q->from_table());
    // slowdown engages on the first tick because we're not from_table.
    EXPECT_TRUE(q->slowdown_engaged());

    // Safety deadline: the query should complete in well under a second
    // (reject replies are microseconds, live FIND_NODE is milliseconds),
    // so a short deadline keeps the test fast without being flaky.
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    struct Ctx { rpc::RpcSocket* rj; rpc::RpcSocket* lv; rpc::RpcSocket* c; };
    Ctx ctx{&reject_server, &live_server, &client};
    timer.data = &ctx;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->rj->close();
        c->lv->close();
        c->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(query_done) << "query never terminated";
    // §1c fires only when successes_ < K/4 (strictly less). The reject
    // server replies with error=1 to every request, so in the happy path
    // all K pre-seeds bump errors_, not successes_. Allow a small slack
    // in case one seeded packet got reordered through the retry loop.
    const int min_errors = static_cast<int>(routing::K) * 3 / 4 + 1;
    EXPECT_GE(saw_errors, min_errors)
        << "expected most seeded requests to error (got "
        << saw_errors << ", need >= " << min_errors << ")";
    // After the retry fires, from_table_ must have flipped — the only way
    // to reach the live server was through the §1c fallback path.
    EXPECT_TRUE(saw_from_table_flip)
        << "table retry fallback did not engage — §1c not wired";
    // And once the retry fires, we should get at least one success from
    // the live server reachable through the routing table.
    EXPECT_GE(saw_successes, 1) << "no live reply received after §1c retry";

    uv_loop_close(&loop);
}
