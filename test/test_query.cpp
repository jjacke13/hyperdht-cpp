#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

#include <uv.h>

#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/noise_wrap.hpp"
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

// Transition a socket from ephemeral to persistent by feeding the NAT sampler
// 3 consistent loopback samples. Must be called after bind().
static void make_persistent(RpcSocket& socket) {
    auto our_addr = Ipv4Address::from_string("127.0.0.1", socket.port());
    for (int i = 1; i <= 3; i++) {
        auto from = Ipv4Address::from_string(
            "10.0.0." + std::to_string(i), 49737);
        socket.nat_sampler().add(our_addr, from);
        socket.ring_sampler().add(our_addr.host_string(), our_addr.port);
    }
    socket.force_check_persistent();
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
    make_persistent(server);
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

    // Keep the walk's give-up fast: the fake 10.0.0.x nodes never answer, and
    // the query default of 5 retries (6 × 1s) would exceed the 5s deadline.
    q->set_retries(1);

    q->on_reply([&](const QueryReply&) {
        replies_count++;
    });

    q->on_done([&](int /*error*/, const std::vector<QueryReply>& closest) {
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
// Commit-timeout regression: a commit whose store request never gets a
// response (packet lost / node down) must still settle the query. Before the
// fix the commit only wired on_response, so commit_inflight_ never reached
// zero and on_done never fired — announce()/put() hung forever and leaked the
// Query. JS decrements on both ondone and onerror (query.js:236-247).
// ---------------------------------------------------------------------------

TEST(Query, CommitTimeoutStillCompletes) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0x11);
    RpcSocket server(&loop, server_id);
    server.bind(0);
    make_persistent(server);  // persistent → replies carry a token
    RpcHandlers handlers(server);
    handlers.install();
    // No routing entries on the server: its own reply carries a token, so
    // the walk completes in one round with exactly one tokened node to
    // commit to — keeping the test about commit settlement, not walk speed.

    NodeId client_id{};
    client_id.fill(0x22);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    NodeId target{};
    target.fill(0x00);
    target[0] = 0x05;

    bool query_done = false;
    int commits_seen = 0;

    auto q = Query::create(client, target, CMD_FIND_NODE);
    q->set_internal(true);
    q->add_bootstrap(Ipv4Address::from_string("127.0.0.1", server.port()));

    // Simulate a totally lost commit: fire the timeout path, never the
    // response path. Synchronous on_timeout also exercises do_commit's
    // "counter fully set before any settle" guarantee.
    q->set_commit([&](const QueryReply&,
                      rpc::OnResponseCallback,
                      rpc::OnTimeoutCallback on_timeout) {
        commits_seen++;
        on_timeout(0);
    });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);

    q->on_done([&](int /*error*/, const std::vector<QueryReply>&) {
        query_done = true;
        // Cancel the safety net so a prompt completion returns uv_run
        // early — leaving deadline_hit false only if we did NOT hang.
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&timer))) {
            uv_close(reinterpret_cast<uv_handle_t*>(&timer), nullptr);
        }
        server.close();
        client.close();
    });

    q->start();

    // Safety net: force-close if the query hangs (the pre-fix regression).
    bool deadline_hit = false;
    struct Ctx { RpcSocket* s; RpcSocket* c; bool* hit; };
    Ctx cx{&server, &client, &deadline_hit};
    timer.data = &cx;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        *c->hit = true;
        c->s->close();
        c->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_GE(commits_seen, 1) << "walk should reach commit with ≥1 tokened node";
    EXPECT_TRUE(query_done) << "query must complete even when every commit times out";
    EXPECT_FALSE(deadline_hit) << "query must settle via commit, not the deadline";

    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Query early termination — JS `query.destroy()` equivalent. Calling
// destroy() from an on_reply handler must:
//   - immediately mark the query done
//   - invoke on_done exactly once
//   - drop any late responses (no further on_reply dispatches)
// JS: dht-rpc/lib/query.js:385-390 (_destroy)
// ---------------------------------------------------------------------------

TEST(Query, DestroyFromOnReplyEndsWalk) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Server with a fat routing table so the walk *would* take many steps
    // if we didn't short-circuit.
    NodeId server_id{};
    server_id.fill(0x11);
    RpcSocket server(&loop, server_id);
    server.bind(0);
    make_persistent(server);
    RpcHandlers handlers(server);
    handlers.install();

    for (int i = 1; i <= 30; i++) {
        Node node;
        node.id.fill(0x00);
        node.id[0] = static_cast<uint8_t>(i);
        node.host = "10.0.0." + std::to_string(i);
        node.port = static_cast<uint16_t>(9000 + i);
        server.table().add(node);
    }

    NodeId client_id{};
    client_id.fill(0x22);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    NodeId target{};
    target.fill(0x05);

    bool query_done = false;
    int on_done_count = 0;
    int on_reply_count = 0;

    auto q = Query::create(client, target, CMD_FIND_NODE);
    q->set_internal(true);
    q->add_bootstrap(Ipv4Address::from_string("127.0.0.1", server.port()));

    // Destroy on the first reply.
    auto q_weak = std::weak_ptr<Query>(q);
    q->on_reply([&, q_weak](const QueryReply&) {
        on_reply_count++;
        if (auto qp = q_weak.lock()) qp->destroy();
    });

    q->on_done([&](int /*error*/, const std::vector<QueryReply>&) {
        query_done = true;
        on_done_count++;
        server.close();
        client.close();
    });

    q->start();

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
    }, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(query_done) << "destroy() must fire on_done";
    EXPECT_EQ(on_done_count, 1) << "on_done must be invoked exactly once";
    EXPECT_EQ(on_reply_count, 1) << "no on_reply dispatches allowed after destroy()";
    EXPECT_TRUE(q->is_done());

    uv_loop_close(&loop);
}

TEST(Query, DestroyIsIdempotent) {
    // destroy() called twice (e.g. from two concurrent on_reply handlers
    // in the final tick) must not fire on_done twice.
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId client_id{};
    client_id.fill(0x22);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    NodeId target{};
    target.fill(0xAA);

    int on_done_count = 0;
    auto q = Query::create(client, target, CMD_FIND_NODE);
    q->set_internal(true);
    q->on_done([&](int /*error*/, const std::vector<QueryReply>&) { on_done_count++; });

    q->destroy();
    q->destroy();
    q->destroy();

    EXPECT_TRUE(q->is_done());
    EXPECT_EQ(on_done_count, 1);

    client.close();
    uv_run(&loop, UV_RUN_DEFAULT);
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

    q->on_done([&](int /*error*/, const std::vector<QueryReply>& closest) {
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
    make_persistent(server);
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

    // Fake 10.0.0.x nodes never answer; cap retries so the walk finishes well
    // under the 5s deadline (default 5 retries would run ~6s).
    q->set_retries(1);

    q->on_done([&](int /*error*/, const std::vector<QueryReply>& closest) {
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
    make_persistent(live_server);
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
    q->on_done([&](int /*error*/, const std::vector<QueryReply>& /*closest*/) {
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

// ===========================================================================
// Parity-sweep bucket: commit-1, announce-client (B), query-1..4, downhint-1.
// ===========================================================================

// A persistent handler node whose routing id == peer.id(127.0.0.1:port). This
// is what makes its LOOKUP/FIND_NODE replies validate at the client (io.js
// validateId) and land in `closest` — a node with an arbitrary id has its
// reply id nulled and never enters the frontier's closest set.
struct IdNode {
    std::unique_ptr<RpcSocket> sock;
    std::unique_ptr<RpcHandlers> handlers;
    uint16_t port = 0;
    NodeId id{};
    bool bound = false;
    // Observed incoming (command, internal) pairs — for wire assertions.
    std::vector<std::pair<uint32_t, bool>> reqs;
    std::vector<bool> announce_had_token;  // token presence per CMD_ANNOUNCE

    IdNode(uv_loop_t* loop, uint16_t p) : port(p) {
        id = rpc::compute_peer_id(Ipv4Address::from_string("127.0.0.1", p));
        sock = std::make_unique<RpcSocket>(loop, id);
        if (sock->bind(p, "127.0.0.1") != 0) return;
        bound = true;
        make_persistent(*sock);
        handlers = std::make_unique<RpcHandlers>(*sock);
        // Observe every request, then delegate to the real handler so the node
        // still answers LOOKUP with a token+id and stores ANNOUNCE.
        auto* self = this;
        auto* hp = handlers.get();
        sock->on_request([self, hp](const Request& req) {
            self->reqs.emplace_back(req.command, req.internal);
            if (!req.internal && req.command == CMD_ANNOUNCE) {
                self->announce_had_token.push_back(req.token.has_value());
            }
            hp->handle(req);
        });
    }
    Ipv4Address addr() const {
        return Ipv4Address::from_string("127.0.0.1", port);
    }
    void close() { if (sock) sock->close(); }
};

// Run `loop`, closing every socket (exactly once) as soon as `*done` is set or
// `deadline_ms` elapses, whichever comes first — so a prompt completion returns
// immediately instead of stalling out the whole deadline. `done` may be null.
static void run_with_deadline(uv_loop_t& loop, const bool* done,
                              uint64_t deadline_ms,
                              std::vector<RpcSocket*> sockets) {
    struct Ctx {
        const bool* done;
        std::vector<RpcSocket*> sockets;
        uint64_t elapsed;
        uint64_t deadline;
        bool closed;
    };
    auto* ctx = new Ctx{done, std::move(sockets), 0, deadline_ms, false};
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = ctx;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->elapsed += 25;
        const bool finished = (c->done && *c->done) || c->elapsed >= c->deadline;
        if (!finished) return;
        if (!c->closed) {
            c->closed = true;
            for (auto* s : c->sockets) s->close();
        }
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 25, 25);
    uv_run(&loop, UV_RUN_DEFAULT);
    delete ctx;
}

// ---------------------------------------------------------------------------
// announce-client (B) + per-node signing: a value-less LOOKUP walk that signs
// a FRESH ANNOUNCE per closest node. Two handler nodes must BOTH verify the
// signature and store the record — impossible with the old single-fixed-value
// commit. Also asserts the walk is CMD_LOOKUP and every CMD_ANNOUNCE carries a
// token (no token-less ANNOUNCE leaks onto the walk).
// ---------------------------------------------------------------------------
TEST(QueryAnnounce, MultiNodePerNodeSigningStores) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    IdNode n1(&loop, 46011);
    IdNode n2(&loop, 46012);
    if (!n1.bound || !n2.bound) {
        n1.close(); n2.close();
        uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop);
        GTEST_SKIP() << "could not bind fixed loopback ports";
    }

    NodeId client_id{};
    client_id.fill(0xC1);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    // Seed the client's table with both nodes so the walk visits them (and
    // add_default_bootstrap's table-empty guard does not add public nodes).
    for (IdNode* n : {&n1, &n2}) {
        Node peer;
        peer.id = n->id;
        peer.host = "127.0.0.1";
        peer.port = n->port;
        client.table().add(peer);
    }

    noise::Seed seed{}; seed.fill(0xA5);
    auto kp = noise::generate_keypair(seed);

    NodeId target{};
    target.fill(0x33);

    bool done = false;
    int done_error = -1;
    auto q = dht_ops::announce(
        client, target, kp, /*relay_addresses=*/{}, /*bump=*/0,
        [&](int error, const std::vector<QueryReply>&) {
            done = true;
            done_error = error;
        });

    run_with_deadline(loop, &done, 4000,
                      {n1.sock.get(), n2.sock.get(), &client});

    EXPECT_TRUE(done);
    EXPECT_EQ(done_error, QUERY_OK) << "announce to reachable nodes must succeed";

    // BOTH nodes must have verified + stored our record (per-node signing).
    announce::TargetKey key{};
    std::copy(target.begin(), target.end(), key.begin());
    for (IdNode* n : {&n1, &n2}) {
        auto recs = n->handlers->store().get(key);
        ASSERT_EQ(recs.size(), 1u) << "node did not store the announce";
        auto pr = dht_messages::decode_peer_record(
            recs[0].value.data(), recs[0].value.size());
        EXPECT_EQ(pr.public_key, kp.public_key);
    }

    // Wire shape: the walk is CMD_LOOKUP (external); every CMD_ANNOUNCE carried
    // a token — no token-less ANNOUNCE ever hit the walk (the old-code bug).
    for (IdNode* n : {&n1, &n2}) {
        bool saw_lookup = false, saw_announce = false;
        for (auto& [cmd, internal] : n->reqs) {
            if (!internal && cmd == CMD_LOOKUP) saw_lookup = true;
            if (!internal && cmd == CMD_ANNOUNCE) saw_announce = true;
        }
        EXPECT_TRUE(saw_lookup) << "walk must use CMD_LOOKUP";
        EXPECT_TRUE(saw_announce) << "commit must send CMD_ANNOUNCE";
        for (bool had : n->announce_had_token) {
            EXPECT_TRUE(had) << "every CMD_ANNOUNCE must carry a token";
        }
    }

    uv_loop_close(&loop);
}

// A node bound to a fixed port with id == peer.id(127.0.0.1:port). Each request
// is passed to a caller-supplied responder returning an optional Response
// (nullopt = stay silent). Since we set resp.id ourselves, the client validates
// it and the reply lands in `closest` — no RpcHandlers needed.
struct ReplyNode {
    using Fn = std::function<std::optional<Response>(const Request&, ReplyNode&)>;
    std::unique_ptr<RpcSocket> sock;
    uint16_t port = 0;
    NodeId id{};
    bool bound = false;
    int requests = 0;

    ReplyNode(uv_loop_t* loop, uint16_t p, Fn fn) : port(p) {
        id = rpc::compute_peer_id(Ipv4Address::from_string("127.0.0.1", p));
        sock = std::make_unique<RpcSocket>(loop, id);
        if (sock->bind(p, "127.0.0.1") != 0) return;
        bound = true;
        auto* self = this;
        sock->on_request([self, fn](const Request& req) {
            self->requests++;
            auto r = fn(req, *self);
            if (r) self->sock->reply(*r, req.from_server);
        });
    }
    Ipv4Address addr() const {
        return Ipv4Address::from_string("127.0.0.1", port);
    }
    void close() { if (sock) sock->close(); }
};

// Build a success reply carrying our (validated) id, an optional fake token,
// and optional closer nodes.
static Response reply_ok(const Request& req, const NodeId& id, bool with_token,
                         std::vector<Ipv4Address> closer = {},
                         uint32_t error = 0) {
    Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    resp.id = id;
    if (with_token) {
        std::array<uint8_t, 32> tok{};
        tok.fill(0x7A);
        resp.token = tok;
    }
    resp.closer_nodes = std::move(closer);
    if (error) resp.error = error;
    return resp;
}

// ---------------------------------------------------------------------------
// commit-1: the commit phase must SIGNAL FAILURE. JS query.js:225-248.
// ---------------------------------------------------------------------------

// (d) Success path unchanged: one tokened closest reply, commit resolves.
TEST(QueryCommit, SuccessReportsOk) {
    uv_loop_t loop; uv_loop_init(&loop);
    ReplyNode node(&loop, 46021, [](const Request& req, ReplyNode& self) {
        return std::optional<Response>(reply_ok(req, self.id, /*token=*/true));
    });
    if (!node.bound) { node.close(); uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop); GTEST_SKIP() << "bind failed"; }

    NodeId cid{}; cid.fill(0xC2);
    RpcSocket client(&loop, cid); client.bind(0);
    NodeId target{}; target.fill(0x44);

    bool done = false; int err = -1; int commits = 0;
    auto q = Query::create(client, target, CMD_LOOKUP);
    q->add_bootstrap(node.addr());
    q->set_commit([&](const QueryReply&, rpc::OnResponseCallback on_resp,
                      rpc::OnTimeoutCallback) {
        commits++;
        Response empty; on_resp(empty);      // resolve
    });
    q->on_done([&](int e, const std::vector<QueryReply>&) { done = true; err = e; });
    q->start();
    run_with_deadline(loop, &done, 3000, {node.sock.get(), &client});

    EXPECT_TRUE(done);
    EXPECT_EQ(err, QUERY_OK);
    EXPECT_GE(commits, 1);
    uv_loop_close(&loop);
}

// (b) All commits fail (store lost) → 'Too few nodes responded'.
TEST(QueryCommit, AllCommitsFailReportsError) {
    uv_loop_t loop; uv_loop_init(&loop);
    ReplyNode node(&loop, 46022, [](const Request& req, ReplyNode& self) {
        return std::optional<Response>(reply_ok(req, self.id, /*token=*/true));
    });
    if (!node.bound) { node.close(); uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop); GTEST_SKIP() << "bind failed"; }

    NodeId cid{}; cid.fill(0xC3);
    RpcSocket client(&loop, cid); client.bind(0);
    NodeId target{}; target.fill(0x44);

    bool done = false; int err = -1; int commits = 0;
    auto q = Query::create(client, target, CMD_LOOKUP);
    q->add_bootstrap(node.addr());
    q->set_commit([&](const QueryReply&, rpc::OnResponseCallback,
                      rpc::OnTimeoutCallback on_to) {
        commits++;
        on_to(0);                            // every commit fails
    });
    q->on_done([&](int e, const std::vector<QueryReply>&) { done = true; err = e; });
    q->start();
    run_with_deadline(loop, &done, 3000, {node.sock.get(), &client});

    EXPECT_TRUE(done);
    EXPECT_EQ(err, QUERY_ERR_TOO_FEW_NODES);
    EXPECT_GE(commits, 1);
    uv_loop_close(&loop);
}

// (c) Only tokenless closest replies → all count as failed commits (JS
// autoCommit rejects a tokenless reply). The commit fn is never invoked.
TEST(QueryCommit, TokenlessClosestReportsError) {
    uv_loop_t loop; uv_loop_init(&loop);
    ReplyNode node(&loop, 46023, [](const Request& req, ReplyNode& self) {
        // Valid id, but NO token.
        return std::optional<Response>(reply_ok(req, self.id, /*token=*/false));
    });
    if (!node.bound) { node.close(); uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop); GTEST_SKIP() << "bind failed"; }

    NodeId cid{}; cid.fill(0xC4);
    RpcSocket client(&loop, cid); client.bind(0);
    NodeId target{}; target.fill(0x44);

    bool done = false; int err = -1; int commits = 0;
    auto q = Query::create(client, target, CMD_LOOKUP);
    q->add_bootstrap(node.addr());
    q->set_commit([&](const QueryReply&, rpc::OnResponseCallback on_resp,
                      rpc::OnTimeoutCallback) {
        commits++;
        Response empty; on_resp(empty);      // would succeed IF ever called
    });
    q->on_done([&](int e, const std::vector<QueryReply>&) { done = true; err = e; });
    q->start();
    run_with_deadline(loop, &done, 3000, {node.sock.get(), &client});

    EXPECT_TRUE(done);
    EXPECT_EQ(err, QUERY_ERR_TOO_FEW_NODES);
    EXPECT_EQ(commits, 0) << "tokenless reply must not invoke the commit fn";
    uv_loop_close(&loop);
}

// (a) Empty closest set (no node responded) → 'Too few nodes responded'.
TEST(QueryCommit, EmptyClosestReportsError) {
    uv_loop_t loop; uv_loop_init(&loop);
    NodeId cid{}; cid.fill(0xC5);
    RpcSocket client(&loop, cid); client.bind(0);
    NodeId target{}; target.fill(0x44);

    bool done = false; int err = -1; int commits = 0;
    auto q = Query::create(client, target, CMD_LOOKUP);
    // Silent bootstrap: nothing listens, so the walk yields no closest reply.
    q->add_bootstrap(Ipv4Address::from_string("127.0.0.1", 46098));
    q->set_retries(0);                       // 1 send, ~1s give-up
    q->set_commit([&](const QueryReply&, rpc::OnResponseCallback,
                      rpc::OnTimeoutCallback on_to) { commits++; on_to(0); });
    q->on_done([&](int e, const std::vector<QueryReply>&) { done = true; err = e; });
    q->start();
    run_with_deadline(loop, &done, 4000, {&client});

    EXPECT_TRUE(done);
    EXPECT_EQ(err, QUERY_ERR_TOO_FEW_NODES);
    EXPECT_EQ(commits, 0) << "no closest reply ⇒ commit fn never runs";
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// query-1: a query-walk request retries 5 times ⇒ 6 transmissions to a silent
// node (JS query.js:28-29,380 + io.js oncycle).
// ---------------------------------------------------------------------------
TEST(QueryWalk, RetriesSixTransmissionsToSilentNode) {
    uv_loop_t loop; uv_loop_init(&loop);
    ReplyNode silent(&loop, 46031, [](const Request&, ReplyNode&) {
        return std::optional<Response>{};    // never reply
    });
    if (!silent.bound) { silent.close(); uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop); GTEST_SKIP() << "bind failed"; }

    NodeId cid{}; cid.fill(0xC6);
    RpcSocket client(&loop, cid); client.bind(0);
    NodeId target{}; target.fill(0x44);

    bool done = false;
    auto q = Query::create(client, target, CMD_LOOKUP);   // default retries = 5
    q->add_bootstrap(silent.addr());
    q->on_done([&](int, const std::vector<QueryReply>&) { done = true; });
    q->start();
    run_with_deadline(loop, &done, 9000, {silent.sock.get(), &client});

    EXPECT_TRUE(done);
    EXPECT_EQ(silent.requests, 6)
        << "5 retries ⇒ 6 transmissions (sent at 1..6, give up when sent>5)";
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// query-2: error replies (m.error != 0) are NOT surfaced to on_reply, but their
// closerNodes ARE merged into the frontier (JS query.js:287-294).
// ---------------------------------------------------------------------------
TEST(QueryWalk, ErrorReplyNotSurfacedButCloserMerged) {
    uv_loop_t loop; uv_loop_init(&loop);

    ReplyNode silent(&loop, 46042, [](const Request&, ReplyNode&) {
        return std::optional<Response>{};    // the "closer" node — never replies
    });
    ReplyNode errn(&loop, 46041, [&](const Request& req, ReplyNode& self) {
        // error reply that still carries a closer node
        return std::optional<Response>(
            reply_ok(req, self.id, /*token=*/false,
                     {silent.addr()}, /*error=*/1));
    });
    if (!errn.bound || !silent.bound) { errn.close(); silent.close();
        uv_run(&loop, UV_RUN_DEFAULT); uv_loop_close(&loop);
        GTEST_SKIP() << "bind failed"; }

    NodeId cid{}; cid.fill(0xC7);
    RpcSocket client(&loop, cid); client.bind(0);
    NodeId target{}; target.fill(0x44);

    int replies = 0; bool done = false;
    auto q = Query::create(client, target, CMD_LOOKUP);
    q->set_retries(1);                        // silent gives up fast
    q->add_bootstrap(errn.addr());
    q->on_reply([&](const QueryReply&) { replies++; });
    q->on_done([&](int, const std::vector<QueryReply>&) { done = true; });
    q->start();
    run_with_deadline(loop, &done, 5000,
                      {errn.sock.get(), silent.sock.get(), &client});

    EXPECT_TRUE(done);
    EXPECT_EQ(replies, 0) << "error reply must not reach on_reply";
    EXPECT_GE(silent.requests, 1) << "the error reply's closer node must be visited";
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// query-4: onlyClosestNodes visits only the seeded frontier and never expands
// from a reply's closerNodes (JS query.js:141).
// ---------------------------------------------------------------------------
TEST(QueryWalk, OnlyClosestNodesDoesNotExpandFrontier) {
    uv_loop_t loop; uv_loop_init(&loop);

    ReplyNode silent(&loop, 46052, [](const Request&, ReplyNode&) {
        return std::optional<Response>{};    // would be the expansion target
    });
    ReplyNode seed(&loop, 46051, [&](const Request& req, ReplyNode& self) {
        return std::optional<Response>(
            reply_ok(req, self.id, /*token=*/false, {silent.addr()}));
    });
    if (!seed.bound || !silent.bound) { seed.close(); silent.close();
        uv_run(&loop, UV_RUN_DEFAULT); uv_loop_close(&loop);
        GTEST_SKIP() << "bind failed"; }

    NodeId cid{}; cid.fill(0xC8);
    RpcSocket client(&loop, cid); client.bind(0);
    NodeId target{}; target.fill(0x44);

    int replies = 0; bool done = false;
    auto q = Query::create(client, target, CMD_LOOKUP);
    q->set_only_closest_nodes(true);
    q->add_seed_node(seed.id, seed.addr());
    q->on_reply([&](const QueryReply&) { replies++; });
    q->on_done([&](int, const std::vector<QueryReply>&) { done = true; });
    q->start();
    run_with_deadline(loop, &done, 3000,
                      {seed.sock.get(), silent.sock.get(), &client});

    EXPECT_TRUE(done);
    EXPECT_GE(replies, 1) << "the seeded node is still visited";
    EXPECT_EQ(silent.requests, 0)
        << "onlyClosestNodes must not expand to the reply's closerNodes";
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// downhint-1: when a referred node times out, a DOWN_HINT is emitted to the
// referrer with the dead node's 6-byte address (JS query.js:298-332).
// ---------------------------------------------------------------------------
TEST(QueryWalk, DownHintEmittedToReferrerOnTimeout) {
    uv_loop_t loop; uv_loop_init(&loop);

    const auto dead = Ipv4Address::from_string("127.0.0.1", 46099);  // unbound
    int dh_count = 0;
    std::vector<uint8_t> dh_value;
    ReplyNode ref(&loop, 46061, [&](const Request& req, ReplyNode& self)
                      -> std::optional<Response> {
        if (req.internal && req.command == CMD_DOWN_HINT) {
            dh_count++;
            if (req.value) dh_value = *req.value;
            return std::nullopt;              // fire-and-forget
        }
        // LOOKUP walk: refer the client to the (dead) node.
        return reply_ok(req, self.id, /*token=*/false, {dead});
    });
    if (!ref.bound) { ref.close(); uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop); GTEST_SKIP() << "bind failed"; }

    NodeId cid{}; cid.fill(0xC9);
    RpcSocket client(&loop, cid); client.bind(0);
    NodeId target{}; target.fill(0x44);

    bool done = false;
    auto q = Query::create(client, target, CMD_LOOKUP);
    q->set_retries(1);                        // dead node gives up in ~2s
    q->add_bootstrap(ref.addr());
    q->on_done([&](int, const std::vector<QueryReply>&) { done = true; });
    q->start();
    run_with_deadline(loop, &done, 6000, {ref.sock.get(), &client});

    EXPECT_TRUE(done);
    EXPECT_GE(dh_count, 1) << "a DOWN_HINT must be sent to the referrer";
    ASSERT_GE(dh_value.size(), 6u);
    auto s = State::for_decode(dh_value.data(), dh_value.size());
    auto decoded = Ipv4Addr::decode(s);
    EXPECT_EQ(decoded.port, dead.port) << "DOWN_HINT must carry the dead address";
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// query-3: with k closest replies satisfied and every remaining in-flight
// request slow (retried), the flush/commit starts BEFORE the slow nodes exhaust
// their full retry budget (JS query.js:196-199). We fill closest to k with fast
// responders and leave two silent nodes; the query must finish well under the
// silent nodes' 6s (retries=5) timeout.
// ---------------------------------------------------------------------------
TEST(QueryWalk, SlowRequestsAllowEarlyFlush) {
    uv_loop_t loop; uv_loop_init(&loop);

    std::vector<std::unique_ptr<ReplyNode>> nodes;
    bool all_bound = true;
    for (int i = 0; i < static_cast<int>(routing::K); i++) {
        auto n = std::make_unique<ReplyNode>(
            &loop, static_cast<uint16_t>(46200 + i),
            [](const Request& req, ReplyNode& self) {
                return std::optional<Response>(
                    reply_ok(req, self.id, /*token=*/false));
            });
        if (!n->bound) all_bound = false;
        nodes.push_back(std::move(n));
    }
    std::vector<RpcSocket*> socks;
    for (auto& n : nodes) if (n->sock) socks.push_back(n->sock.get());
    if (!all_bound) {
        for (auto& n : nodes) n->close();
        uv_run(&loop, UV_RUN_DEFAULT); uv_loop_close(&loop);
        GTEST_SKIP() << "could not bind K fixed ports";
    }

    NodeId cid{}; cid.fill(0xCA);
    RpcSocket client(&loop, cid); client.bind(0);
    socks.push_back(&client);
    NodeId target{}; target.fill(0x44);

    auto q = Query::create(client, target, CMD_LOOKUP);   // default retries = 5
    q->set_concurrency(static_cast<int>(routing::K) + 4);
    // Seed the K responders first (visited first ⇒ fill closest), then two
    // silent addresses that will go slow.
    for (auto& n : nodes) q->add_seed_node(n->id, n->addr());
    NodeId sid{}; sid.fill(0xF0);
    q->add_seed_node(sid, Ipv4Address::from_string("127.0.0.1", 46097));
    NodeId sid2{}; sid2.fill(0xF1);
    q->add_seed_node(sid2, Ipv4Address::from_string("127.0.0.1", 46096));

    bool done = false;
    q->on_done([&](int, const std::vector<QueryReply>&) { done = true; });
    q->start();

    // Deadline 4s < the silent nodes' 6s retry budget. If the early flush did
    // NOT fire, the query would only finish at ~6s and `done` would still be
    // false when the deadline force-closes the sockets.
    run_with_deadline(loop, &done, 4000, socks);

    EXPECT_TRUE(done)
        << "query must flush early once k is satisfied and the rest are slow";
    uv_loop_close(&loop);
}
