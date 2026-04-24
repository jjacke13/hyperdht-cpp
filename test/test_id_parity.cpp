// Verification tests for routing table ID parity with JS dht-rpc.
//
// Each test proves a specific protocol-level behavior change:
//   1. Initial table ID is random (not the Ed25519 public key)
//   2. Ephemeral nodes suppress their ID in responses
//   3. Persistent transition rebuilds the table with BLAKE2b(host:port)
//   4. Wire IDs that don't match BLAKE2b(from_addr) are rejected
//   5. Storage commands are dropped when ephemeral

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/dht.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"

using namespace hyperdht;
using namespace hyperdht::rpc;
using namespace hyperdht::routing;
using namespace hyperdht::messages;
using namespace hyperdht::compact;

// ---------------------------------------------------------------------------
// Helper: transition a socket from ephemeral to persistent
// ---------------------------------------------------------------------------

static void make_persistent(RpcSocket& socket) {
    auto our_addr = Ipv4Address::from_string("127.0.0.1", socket.port());
    for (int i = 1; i <= 3; i++) {
        auto from = Ipv4Address::from_string(
            "10.0.0." + std::to_string(i), 49737);
        socket.nat_sampler().add(our_addr, from);
    }
    socket.force_check_persistent();
}

static std::string id_hex(const NodeId& id) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    for (uint8_t b : id) {
        out.push_back(h[b >> 4]);
        out.push_back(h[b & 0x0F]);
    }
    return out;
}

// ===========================================================================
// Gap 1: Initial table ID must be random, NOT the Ed25519 public key
// ===========================================================================

TEST(IdParity, InitialIdIsRandomNotPublicKey) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Create a DHT with a known seed → deterministic keypair
    DhtOptions opts;
    noise::Seed seed{};
    seed.fill(0x42);
    opts.seed = seed;
    HyperDHT dht(&loop, opts);

    // The keypair is deterministic from the seed
    auto expected_pubkey = dht.default_keypair().public_key;

    // The table ID must NOT be the public key
    auto table_id = dht.socket().table().id();
    EXPECT_NE(table_id, expected_pubkey)
        << "Table ID should be random, not the Ed25519 public key.\n"
           "  table_id: " << id_hex(table_id) << "\n"
           "  pubkey:   " << id_hex(expected_pubkey);

    // Verify it's actually random (different across instances)
    HyperDHT dht2(&loop, opts);
    EXPECT_NE(dht.socket().table().id(), dht2.socket().table().id())
        << "Two DHT instances with same seed should have different random table IDs";

    dht.destroy();
    dht2.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ===========================================================================
// Gap 2: Ephemeral responses must NOT include ID; persistent ones must
// ===========================================================================

TEST(IdParity, EphemeralSuppressesIdInResponse) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Server starts ephemeral
    NodeId sid{};
    sid.fill(0x11);
    RpcSocket server(&loop, sid);
    server.bind(0);
    ASSERT_TRUE(server.is_ephemeral()) << "Server should start ephemeral";

    RpcHandlers handlers(server);
    handlers.install();

    NodeId cid{};
    cid.fill(0x22);
    RpcSocket client(&loop, cid);
    client.bind(0);

    // Phase 1: PING while ephemeral — response should have NO id
    struct Ctx {
        RpcSocket* s;
        RpcSocket* c;
        bool done = false;
        bool has_id = false;
    };
    Ctx ctx{&server, &client};

    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping.command = CMD_PING;
    ping.internal = true;

    client.request(ping,
        [&ctx](const Response& resp) {
            ctx.has_id = resp.id.has_value();
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        },
        [&ctx](uint16_t) {
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        });

    uv_timer_t t;
    uv_timer_init(&loop, &t);
    t.data = &ctx;
    uv_timer_start(&t, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->s->close();
        c->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 2000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    ASSERT_TRUE(ctx.done) << "PING should complete";
    EXPECT_FALSE(ctx.has_id)
        << "Ephemeral server MUST NOT include ID in response "
           "(JS: io.js:488 — id only when ephemeral === false)";

    uv_loop_close(&loop);
}

TEST(IdParity, PersistentIncludesIdInResponse) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId sid{};
    sid.fill(0x11);
    RpcSocket server(&loop, sid);
    server.bind(0);
    make_persistent(server);
    ASSERT_FALSE(server.is_ephemeral()) << "Server should be persistent";

    RpcHandlers handlers(server);
    handlers.install();

    NodeId cid{};
    cid.fill(0x22);
    RpcSocket client(&loop, cid);
    client.bind(0);

    struct Ctx {
        RpcSocket* s;
        RpcSocket* c;
        bool done = false;
        bool has_id = false;
        std::optional<NodeId> received_id;
    };
    Ctx ctx{&server, &client};

    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping.command = CMD_PING;
    ping.internal = true;

    client.request(ping,
        [&ctx](const Response& resp) {
            ctx.has_id = resp.id.has_value();
            if (resp.id.has_value()) ctx.received_id = *resp.id;
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        },
        [&ctx](uint16_t) {
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        });

    uv_timer_t t;
    uv_timer_init(&loop, &t);
    t.data = &ctx;
    uv_timer_start(&t, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->s->close();
        c->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 2000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    ASSERT_TRUE(ctx.done) << "PING should complete";
    EXPECT_TRUE(ctx.has_id)
        << "Persistent server MUST include ID in response";

    // The ID must match the server's current table ID
    ASSERT_TRUE(ctx.received_id.has_value());
    EXPECT_EQ(*ctx.received_id, server.table().id())
        << "Response ID must match server's table ID";

    uv_loop_close(&loop);
}

// ===========================================================================
// Gap 3: After persistent transition, table ID = BLAKE2b(host:port)
// ===========================================================================

TEST(IdParity, PersistentIdIsBlake2bOfAddress) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId sid{};
    sid.fill(0x33);
    RpcSocket socket(&loop, sid);
    socket.bind(0);

    // Before transition: table ID is the random one from construction
    auto initial_id = socket.table().id();

    make_persistent(socket);

    // After transition: table ID must be BLAKE2b(127.0.0.1:port)
    auto expected_id = compute_peer_id(
        Ipv4Address::from_string("127.0.0.1", socket.port()));
    auto actual_id = socket.table().id();

    EXPECT_NE(actual_id, initial_id)
        << "Table ID should change after persistent transition";
    EXPECT_EQ(actual_id, expected_id)
        << "Table ID must be BLAKE2b(host:port) after persistent transition.\n"
           "  expected (BLAKE2b): " << id_hex(expected_id) << "\n"
           "  actual:             " << id_hex(actual_id) << "\n"
           "This is what JS's validateId() will check.";

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(IdParity, TableRebuildPreservesNodes) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId sid{};
    sid.fill(0x44);
    RpcSocket socket(&loop, sid);
    socket.bind(0);

    // Add nodes before transition
    for (int i = 1; i <= 5; i++) {
        Node node;
        node.id.fill(static_cast<uint8_t>(i));
        node.host = "10.0.0." + std::to_string(i);
        node.port = static_cast<uint16_t>(8000 + i);
        socket.table().add(node);
    }
    ASSERT_EQ(socket.table().size(), 5u);

    make_persistent(socket);

    // Nodes should survive the rebuild (possibly all, maybe fewer if
    // a bucket filled up — but at least most should migrate)
    EXPECT_GE(socket.table().size(), 4u)
        << "Most nodes should survive the table rebuild";

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ===========================================================================
// Gap 4: Wire IDs that don't match BLAKE2b(from_addr) are rejected
// ===========================================================================

TEST(IdParity, ValidateIdRejectsMismatch) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Server sends its public key as ID (the OLD broken behavior).
    // The client should reject it because it doesn't match BLAKE2b(host:port).
    NodeId bad_id{};
    bad_id.fill(0xDE);  // Arbitrary — won't match BLAKE2b(127.0.0.1:port)
    RpcSocket server(&loop, bad_id);
    server.bind(0);

    // Custom handler: reply with the raw bad_id (simulating the old bug)
    server.on_request([&](const Request& req) {
        Response resp;
        resp.tid = req.tid;
        resp.from.addr = req.from.addr;
        resp.id = bad_id;  // This won't match compute_peer_id(server_addr)
        server.reply(resp);
    });

    NodeId cid{};
    cid.fill(0xAA);
    RpcSocket client(&loop, cid);
    client.bind(0);

    size_t table_size_before = client.table().size();

    struct Ctx {
        RpcSocket* s;
        RpcSocket* c;
        bool done = false;
        bool resp_had_id = false;
    };
    Ctx ctx{&server, &client};

    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping.command = CMD_PING;
    ping.internal = true;

    client.request(ping,
        [&ctx](const Response& resp) {
            // resp.id should have been cleared by validateId (mismatch)
            ctx.resp_had_id = resp.id.has_value();
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        },
        [&ctx](uint16_t) {
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        });

    uv_timer_t t;
    uv_timer_init(&loop, &t);
    t.data = &ctx;
    uv_timer_start(&t, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->s->close();
        c->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 2000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    ASSERT_TRUE(ctx.done);
    EXPECT_FALSE(ctx.resp_had_id)
        << "resp.id must be cleared when wire ID doesn't match "
           "BLAKE2b(from_host:from_port) — JS: io.js:627-630 validateId";

    EXPECT_EQ(client.table().size(), table_size_before)
        << "Node with mismatched ID must NOT be added to our routing table";

    uv_loop_close(&loop);
}

TEST(IdParity, ValidateIdAcceptsCorrectId) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Server is persistent → sends correct BLAKE2b(host:port) as ID
    NodeId sid{};
    sid.fill(0x55);
    RpcSocket server(&loop, sid);
    server.bind(0);
    make_persistent(server);

    RpcHandlers handlers(server);
    handlers.install();

    NodeId cid{};
    cid.fill(0xBB);
    RpcSocket client(&loop, cid);
    client.bind(0);

    size_t table_size_before = client.table().size();

    struct Ctx {
        RpcSocket* s;
        RpcSocket* c;
        bool done = false;
        bool resp_had_id = false;
    };
    Ctx ctx{&server, &client};

    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping.command = CMD_PING;
    ping.internal = true;

    client.request(ping,
        [&ctx](const Response& resp) {
            ctx.resp_had_id = resp.id.has_value();
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        },
        [&ctx](uint16_t) {
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        });

    uv_timer_t t;
    uv_timer_init(&loop, &t);
    t.data = &ctx;
    uv_timer_start(&t, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->s->close();
        c->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 2000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    ASSERT_TRUE(ctx.done);
    EXPECT_TRUE(ctx.resp_had_id)
        << "resp.id should be preserved when wire ID matches BLAKE2b(from_addr)";

    EXPECT_GT(client.table().size(), table_size_before)
        << "Node with valid ID should be added to our routing table";

    uv_loop_close(&loop);
}

// ===========================================================================
// Gap 5: Storage commands must be dropped when ephemeral
// ===========================================================================

TEST(IdParity, EphemeralDropsStorageCommands) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Server stays ephemeral (no make_persistent)
    NodeId sid{};
    sid.fill(0x66);
    RpcSocket server(&loop, sid);
    server.bind(0);
    ASSERT_TRUE(server.is_ephemeral());

    RpcHandlers handlers(server);
    handlers.install();

    NodeId cid{};
    cid.fill(0x77);
    RpcSocket client(&loop, cid);
    client.bind(0);

    struct Ctx {
        RpcSocket* s;
        RpcSocket* c;
        bool done = false;
        bool got_response = false;
    };
    Ctx ctx{&server, &client};

    // Send FIND_PEER (a storage command) to the ephemeral server
    Request req;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    req.command = CMD_FIND_PEER;
    req.internal = false;
    std::array<uint8_t, 32> target{};
    target.fill(0xAA);
    req.target = target;

    client.request(req,
        [&ctx](const Response&) {
            ctx.got_response = true;
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        },
        [&ctx](uint16_t) {
            // Timeout = server dropped the request (expected!)
            ctx.got_response = false;
            ctx.done = true;
            ctx.s->close();
            ctx.c->close();
        });

    uv_timer_t t;
    uv_timer_init(&loop, &t);
    t.data = &ctx;
    uv_timer_start(&t, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->s->close();
        c->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 5000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    ASSERT_TRUE(ctx.done);
    EXPECT_FALSE(ctx.got_response)
        << "Ephemeral server MUST drop storage commands (FIND_PEER, ANNOUNCE, etc.) — "
           "JS: hyperdht/index.js:404 'if (this._persistent === null) return false'";

    uv_loop_close(&loop);
}
