#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/noise_wrap.hpp"
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

// ============================================================================
// ANNOUNCE signature verification tests
// ============================================================================

// Helper: two-phase loopback — PING to get a token, then ANNOUNCE/UNANNOUNCE
struct AnnounceCtx {
    RpcSocket* server = nullptr;
    RpcSocket* client = nullptr;
    RpcHandlers* handlers = nullptr;
    bool ping_done = false;
    bool announce_done = false;
    bool announce_accepted = false;
    std::array<uint8_t, 32> token{};
    std::array<uint8_t, 32> server_id{};
    bool cleaning_up = false;
    uv_timer_t* timer = nullptr;
};

static void ann_cleanup(AnnounceCtx* ctx) {
    if (ctx->cleaning_up) return;
    ctx->cleaning_up = true;
    ctx->server->close();
    ctx->client->close();
    if (ctx->timer) {
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer), on_close);
        ctx->timer = nullptr;
    }
}

// Send ANNOUNCE after getting token from PING
static void send_announce(AnnounceCtx* ctx, const std::vector<uint8_t>& value) {
    std::array<uint8_t, 32> target{};
    target.fill(0xAA);

    Request req;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", ctx->server->port());
    req.command = CMD_ANNOUNCE;
    req.internal = false;
    req.target = target;
    req.token = ctx->token;
    req.value = value;

    ctx->client->request(req,
        [ctx](const Response& resp) {
            ctx->announce_done = true;
            ctx->announce_accepted = resp.id.has_value();  // Server replies with ID on success
            ann_cleanup(ctx);
        },
        [ctx](uint16_t) {
            ctx->announce_done = true;
            ctx->announce_accepted = false;  // Timeout = rejected
            ann_cleanup(ctx);
        });
}

// Send UNANNOUNCE after getting token from PING
static void send_unannounce(AnnounceCtx* ctx, const std::vector<uint8_t>& value) {
    std::array<uint8_t, 32> target{};
    target.fill(0xAA);

    Request req;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", ctx->server->port());
    req.command = CMD_UNANNOUNCE;
    req.internal = false;
    req.target = target;
    req.token = ctx->token;
    req.value = value;

    ctx->client->request(req,
        [ctx](const Response& resp) {
            ctx->announce_done = true;
            ctx->announce_accepted = resp.id.has_value();
            ann_cleanup(ctx);
        },
        [ctx](uint16_t) {
            ctx->announce_done = true;
            ctx->announce_accepted = false;
            ann_cleanup(ctx);
        });
}

// Build a signed AnnounceMessage value
static std::vector<uint8_t> build_signed_announce(
    const hyperdht::noise::Keypair& kp,
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const std::array<uint8_t, 32>& token,
    bool for_unannounce = false) {

    hyperdht::dht_messages::AnnounceMessage ann;
    hyperdht::dht_messages::PeerRecord peer;
    peer.public_key = kp.public_key;
    ann.peer = peer;

    auto sig = for_unannounce
        ? hyperdht::announce_sig::sign_unannounce(target, node_id,
              token.data(), token.size(), ann, kp)
        : hyperdht::announce_sig::sign_announce(target, node_id,
              token.data(), token.size(), ann, kp);
    ann.signature = sig;

    return hyperdht::dht_messages::encode_announce_msg(ann);
}

// Run the two-phase test: PING then action
static void run_announce_test(AnnounceCtx& ctx, uv_loop_t& loop,
                               std::function<void(AnnounceCtx*)> on_token) {
    // Phase 1: PING to get a token
    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", ctx.server->port());
    ping.command = CMD_PING;
    ping.internal = true;

    ctx.client->request(ping,
        [&ctx, on_token](const Response& resp) {
            if (resp.token.has_value() && resp.id.has_value()) {
                ctx.token = *resp.token;
                ctx.server_id = *resp.id;
                ctx.ping_done = true;
                on_token(&ctx);
            } else {
                ann_cleanup(&ctx);
            }
        },
        [&ctx](uint16_t) { ann_cleanup(&ctx); });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<AnnounceCtx*>(t->data);
        c->timer = nullptr;
        ann_cleanup(c);
    }, 2000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(RpcHandlers, AnnounceValidSignatureAccepted) {
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

    hyperdht::noise::Seed seed{};
    seed.fill(0x42);
    auto kp = hyperdht::noise::generate_keypair(seed);

    AnnounceCtx ctx;
    ctx.server = &server;
    ctx.client = &client;
    ctx.handlers = &handlers;

    std::array<uint8_t, 32> target{};
    target.fill(0xAA);

    run_announce_test(ctx, loop, [&kp, &target](AnnounceCtx* c) {
        auto value = build_signed_announce(kp, target, c->server_id, c->token);
        send_announce(c, value);
    });

    EXPECT_TRUE(ctx.ping_done) << "PING should succeed";
    EXPECT_TRUE(ctx.announce_done) << "ANNOUNCE should complete";
    EXPECT_TRUE(ctx.announce_accepted) << "Valid signature should be accepted";
}

// ---------------------------------------------------------------------------
// §7 polish — `StorageCacheConfig::ann_ttl_ms` is honoured by
// `handle_announce`: each stored `PeerAnnouncement.ttl` reflects the
// config value rather than the hardcoded `announce::DEFAULT_TTL_MS`.
// This matches JS `persistent.records: { maxAge: opts.maxAge }` in
// `hyperdht/index.js:607`, where the per-entry TTL comes from the
// caller's `opts.maxAge`.
// ---------------------------------------------------------------------------

TEST(RpcHandlers, AnnTtlMsPropagatesToStoredEntry) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0x11);
    RpcSocket server(&loop, server_id);
    server.bind(0);

    // Pick a distinctive non-default value. The hardcoded fallback is
    // 20 minutes (announce::DEFAULT_TTL_MS); if the plumbing regressed
    // we'd see that instead of 12345.
    StorageCacheConfig cfg;
    cfg.ann_ttl_ms = 12345;
    RpcHandlers handlers(server, nullptr, cfg);
    handlers.install();

    NodeId client_id{};
    client_id.fill(0x22);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    hyperdht::noise::Seed seed{};
    seed.fill(0x99);
    auto kp = hyperdht::noise::generate_keypair(seed);

    AnnounceCtx ctx;
    ctx.server = &server;
    ctx.client = &client;
    ctx.handlers = &handlers;

    std::array<uint8_t, 32> target{};
    target.fill(0xAA);

    run_announce_test(ctx, loop, [&kp, &target](AnnounceCtx* c) {
        auto value = build_signed_announce(kp, target, c->server_id, c->token);
        send_announce(c, value);
    });

    ASSERT_TRUE(ctx.announce_accepted)
        << "signed announce should have been accepted";

    // Read the stored entry back via the handlers' announce store accessor
    // and verify its TTL reflects our config value.
    hyperdht::announce::TargetKey key{};
    std::copy(target.begin(), target.end(), key.begin());
    auto stored = handlers.store().get(key);
    ASSERT_EQ(stored.size(), 1u)
        << "exactly one stored entry expected after one ANNOUNCE";
    EXPECT_EQ(stored[0].ttl, 12345u)
        << "RpcHandlers did not honour StorageCacheConfig::ann_ttl_ms — "
           "the announce TTL should come from the config, not the hardcoded "
           "announce::DEFAULT_TTL_MS";
}

TEST(RpcHandlers, AnnounceTamperedSignatureRejected) {
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

    hyperdht::noise::Seed seed{};
    seed.fill(0x42);
    auto kp = hyperdht::noise::generate_keypair(seed);

    AnnounceCtx ctx;
    ctx.server = &server;
    ctx.client = &client;

    std::array<uint8_t, 32> target{};
    target.fill(0xAA);

    run_announce_test(ctx, loop, [&kp, &target](AnnounceCtx* c) {
        auto value = build_signed_announce(kp, target, c->server_id, c->token);
        // Tamper with the last byte of the value (inside the signature)
        if (!value.empty()) value.back() ^= 0xFF;
        send_announce(c, value);
    });

    EXPECT_TRUE(ctx.ping_done);
    EXPECT_TRUE(ctx.announce_done);
    EXPECT_FALSE(ctx.announce_accepted) << "Tampered signature should be rejected";
}

TEST(RpcHandlers, AnnounceWrongNamespaceRejected) {
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

    hyperdht::noise::Seed seed{};
    seed.fill(0x42);
    auto kp = hyperdht::noise::generate_keypair(seed);

    AnnounceCtx ctx;
    ctx.server = &server;
    ctx.client = &client;

    std::array<uint8_t, 32> target{};
    target.fill(0xAA);

    run_announce_test(ctx, loop, [&kp, &target](AnnounceCtx* c) {
        // Sign with UNANNOUNCE namespace but send as ANNOUNCE — should fail
        auto value = build_signed_announce(kp, target, c->server_id, c->token,
                                            /*for_unannounce=*/true);
        send_announce(c, value);
    });

    EXPECT_TRUE(ctx.ping_done);
    EXPECT_TRUE(ctx.announce_done);
    EXPECT_FALSE(ctx.announce_accepted) << "Wrong namespace signature should be rejected";
}

TEST(RpcHandlers, AnnounceNoSignatureRejected) {
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

    AnnounceCtx ctx;
    ctx.server = &server;
    ctx.client = &client;

    run_announce_test(ctx, loop, [](AnnounceCtx* c) {
        // Send announce with peer but NO signature
        hyperdht::dht_messages::AnnounceMessage ann;
        hyperdht::dht_messages::PeerRecord peer;
        peer.public_key.fill(0x42);
        ann.peer = peer;
        // ann.signature NOT set
        auto value = hyperdht::dht_messages::encode_announce_msg(ann);
        send_announce(c, value);
    });

    EXPECT_TRUE(ctx.ping_done);
    EXPECT_TRUE(ctx.announce_done);
    EXPECT_FALSE(ctx.announce_accepted) << "Missing signature should be rejected";
}

TEST(RpcHandlers, UnannounceValidSignatureAccepted) {
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

    hyperdht::noise::Seed seed{};
    seed.fill(0x42);
    auto kp = hyperdht::noise::generate_keypair(seed);

    AnnounceCtx ctx;
    ctx.server = &server;
    ctx.client = &client;

    std::array<uint8_t, 32> target{};
    target.fill(0xAA);

    run_announce_test(ctx, loop, [&kp, &target](AnnounceCtx* c) {
        auto value = build_signed_announce(kp, target, c->server_id, c->token,
                                            /*for_unannounce=*/true);
        send_unannounce(c, value);
    });

    EXPECT_TRUE(ctx.ping_done);
    EXPECT_TRUE(ctx.announce_done);
    EXPECT_TRUE(ctx.announce_accepted) << "Valid unannounce signature should be accepted";
}

// ============================================================================
// Mutable/Immutable storage tests
// ============================================================================

// Helper context for mutable/immutable tests (similar to AnnounceCtx)
struct StorageCtx {
    RpcSocket* server = nullptr;
    RpcSocket* client = nullptr;
    RpcHandlers* handlers = nullptr;
    bool ping_done = false;
    bool op_done = false;
    bool op_accepted = false;
    std::array<uint8_t, 32> token{};
    std::array<uint8_t, 32> server_id{};
    std::optional<uint32_t> error_code;
    std::optional<std::vector<uint8_t>> response_value;
    bool cleaning_up = false;
    uv_timer_t* timer = nullptr;
};

static void stor_cleanup(StorageCtx* ctx) {
    if (ctx->cleaning_up) return;
    ctx->cleaning_up = true;
    ctx->server->close();
    ctx->client->close();
    if (ctx->timer) {
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer), on_close);
        ctx->timer = nullptr;
    }
}

static void send_storage_req(StorageCtx* ctx, uint32_t cmd,
                              const std::array<uint8_t, 32>& target,
                              const std::vector<uint8_t>& value,
                              bool need_token = true) {
    Request req;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", ctx->server->port());
    req.command = cmd;
    req.internal = false;
    req.target = target;
    if (need_token) req.token = ctx->token;
    if (!value.empty()) req.value = value;

    ctx->client->request(req,
        [ctx](const Response& resp) {
            ctx->op_done = true;
            ctx->op_accepted = !resp.error.has_value();
            ctx->error_code = resp.error;
            ctx->response_value = resp.value;
            stor_cleanup(ctx);
        },
        [ctx](uint16_t) {
            ctx->op_done = true;
            ctx->op_accepted = false;
            stor_cleanup(ctx);
        });
}

static void run_storage_test(StorageCtx& ctx, uv_loop_t& loop,
                              std::function<void(StorageCtx*)> on_token) {
    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", ctx.server->port());
    ping.command = CMD_PING;
    ping.internal = true;

    ctx.client->request(ping,
        [&ctx, on_token](const Response& resp) {
            if (resp.token.has_value() && resp.id.has_value()) {
                ctx.token = *resp.token;
                ctx.server_id = *resp.id;
                ctx.ping_done = true;
                on_token(&ctx);
            } else {
                stor_cleanup(&ctx);
            }
        },
        [&ctx](uint16_t) { stor_cleanup(&ctx); });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<StorageCtx*>(t->data);
        c->timer = nullptr;
        stor_cleanup(c);
    }, 2000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// Helper: create server + client + handlers
struct TestEnv {
    uv_loop_t loop;
    NodeId server_id;
    std::unique_ptr<RpcSocket> server;
    std::unique_ptr<RpcHandlers> handlers;
    NodeId client_id;
    std::unique_ptr<RpcSocket> client;
    StorageCtx ctx;

    TestEnv() {
        uv_loop_init(&loop);
        server_id.fill(0x11);
        server = std::make_unique<RpcSocket>(&loop, server_id);
        server->bind(0);
        handlers = std::make_unique<RpcHandlers>(*server);
        handlers->install();
        client_id.fill(0x22);
        client = std::make_unique<RpcSocket>(&loop, client_id);
        client->bind(0);
        ctx.server = server.get();
        ctx.client = client.get();
        ctx.handlers = handlers.get();
    }
};

// ---- Immutable tests ----

TEST(RpcHandlers, ImmutablePutGetRoundTrip) {
    TestEnv env;
    std::vector<uint8_t> stored_value = {'h', 'e', 'l', 'l', 'o'};

    // Compute target = BLAKE2b(value)
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32,
                       stored_value.data(), stored_value.size(),
                       nullptr, 0);

    // Phase 1: PUT
    run_storage_test(env.ctx, env.loop, [&](StorageCtx* c) {
        send_storage_req(c, CMD_IMMUTABLE_PUT, target, stored_value);
    });

    EXPECT_TRUE(env.ctx.op_done);
    EXPECT_TRUE(env.ctx.op_accepted) << "Immutable PUT should succeed";

    // Phase 2: GET (new loop + sockets since the old ones are closed)
    TestEnv env2;
    // Manually put the value into the new handler's storage
    env2.handlers->immutables_put(target, stored_value);

    run_storage_test(env2.ctx, env2.loop, [&target](StorageCtx* c) {
        send_storage_req(c, CMD_IMMUTABLE_GET, target, {}, /*need_token=*/false);
    });

    EXPECT_TRUE(env2.ctx.op_done);
    EXPECT_TRUE(env2.ctx.op_accepted);
    ASSERT_TRUE(env2.ctx.response_value.has_value());
    EXPECT_EQ(*env2.ctx.response_value, stored_value);
}

TEST(RpcHandlers, ImmutablePutWrongHashRejected) {
    TestEnv env;
    std::vector<uint8_t> value = {'t', 'e', 's', 't'};

    // Use wrong target (not the hash of value)
    std::array<uint8_t, 32> wrong_target{};
    wrong_target.fill(0xFF);

    run_storage_test(env.ctx, env.loop, [&](StorageCtx* c) {
        send_storage_req(c, CMD_IMMUTABLE_PUT, wrong_target, value);
    });

    EXPECT_TRUE(env.ctx.op_done);
    EXPECT_FALSE(env.ctx.op_accepted) << "Wrong hash should be rejected";
}

// ---- Mutable tests ----

TEST(RpcHandlers, MutablePutGetRoundTrip) {
    TestEnv env;

    hyperdht::noise::Seed seed{};
    seed.fill(0x42);
    auto kp = hyperdht::noise::generate_keypair(seed);

    // target = BLAKE2b(publicKey)
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);

    std::vector<uint8_t> value = {'w', 'o', 'r', 'l', 'd'};
    uint64_t seq = 1;

    // Sign
    auto sig = hyperdht::announce_sig::sign_mutable(
        seq, value.data(), value.size(), kp);

    // Build mutable put request
    hyperdht::dht_messages::MutablePutRequest put;
    put.public_key = kp.public_key;
    put.seq = seq;
    put.value = value;
    put.signature = sig;
    auto encoded = hyperdht::dht_messages::encode_mutable_put(put);

    run_storage_test(env.ctx, env.loop, [&](StorageCtx* c) {
        send_storage_req(c, CMD_MUTABLE_PUT, target, encoded);
    });

    EXPECT_TRUE(env.ctx.op_done);
    EXPECT_TRUE(env.ctx.op_accepted) << "Mutable PUT should succeed";

    // Phase 2: GET
    TestEnv env2;
    // Manually store the value
    hyperdht::dht_messages::MutableGetResponse stored;
    stored.seq = seq;
    stored.value = value;
    stored.signature = sig;
    env2.handlers->mutables_put(target, hyperdht::dht_messages::encode_mutable_get_resp(stored));

    // Request seq=0 (get any version)
    hyperdht::compact::State s;
    hyperdht::compact::Uint::preencode(s, 0);
    std::vector<uint8_t> seq_buf(s.end);
    s.buffer = seq_buf.data();
    s.start = 0;
    hyperdht::compact::Uint::encode(s, 0);

    run_storage_test(env2.ctx, env2.loop, [&target, &seq_buf](StorageCtx* c) {
        send_storage_req(c, CMD_MUTABLE_GET, target, seq_buf, /*need_token=*/false);
    });

    EXPECT_TRUE(env2.ctx.op_done);
    EXPECT_TRUE(env2.ctx.op_accepted);
    ASSERT_TRUE(env2.ctx.response_value.has_value());

    // Decode the response
    auto resp = hyperdht::dht_messages::decode_mutable_get_resp(
        env2.ctx.response_value->data(), env2.ctx.response_value->size());
    EXPECT_EQ(resp.seq, seq);
    EXPECT_EQ(resp.value, value);
}

TEST(RpcHandlers, MutablePutInvalidSignatureRejected) {
    TestEnv env;

    hyperdht::noise::Seed seed{};
    seed.fill(0x42);
    auto kp = hyperdht::noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);

    std::vector<uint8_t> value = {'b', 'a', 'd'};
    hyperdht::dht_messages::MutablePutRequest put;
    put.public_key = kp.public_key;
    put.seq = 1;
    put.value = value;
    put.signature.fill(0xDE);  // Garbage signature
    auto encoded = hyperdht::dht_messages::encode_mutable_put(put);

    run_storage_test(env.ctx, env.loop, [&](StorageCtx* c) {
        send_storage_req(c, CMD_MUTABLE_PUT, target, encoded);
    });

    EXPECT_TRUE(env.ctx.op_done);
    EXPECT_FALSE(env.ctx.op_accepted) << "Invalid signature should be rejected";
}

TEST(RpcHandlers, MutablePutSeqTooLowRejected) {
    TestEnv env;

    hyperdht::noise::Seed seed{};
    seed.fill(0x42);
    auto kp = hyperdht::noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);

    // Pre-store a record at seq=5
    std::vector<uint8_t> old_val = {'o', 'l', 'd'};
    auto old_sig = hyperdht::announce_sig::sign_mutable(
        5, old_val.data(), old_val.size(), kp);
    hyperdht::dht_messages::MutableGetResponse stored;
    stored.seq = 5;
    stored.value = old_val;
    stored.signature = old_sig;
    env.handlers->mutables_put(target, hyperdht::dht_messages::encode_mutable_get_resp(stored));

    // Try to PUT at seq=3 (lower)
    std::vector<uint8_t> new_val = {'n', 'e', 'w'};
    auto new_sig = hyperdht::announce_sig::sign_mutable(
        3, new_val.data(), new_val.size(), kp);
    hyperdht::dht_messages::MutablePutRequest put;
    put.public_key = kp.public_key;
    put.seq = 3;
    put.value = new_val;
    put.signature = new_sig;
    auto encoded = hyperdht::dht_messages::encode_mutable_put(put);

    run_storage_test(env.ctx, env.loop, [&](StorageCtx* c) {
        send_storage_req(c, CMD_MUTABLE_PUT, target, encoded);
    });

    EXPECT_TRUE(env.ctx.op_done);
    EXPECT_FALSE(env.ctx.op_accepted) << "SEQ_TOO_LOW should return an error";
    ASSERT_TRUE(env.ctx.error_code.has_value());
    EXPECT_EQ(*env.ctx.error_code, ERR_SEQ_TOO_LOW);
}

// ============================================================================
// DELAYED_PING — client schedules a ping that the server replies to after a
// configurable delay. Matches JS dht-rpc delayedPing / _ondelayedping.
// ============================================================================

struct DelayedPingCtx {
    RpcSocket* server = nullptr;
    RpcSocket* client = nullptr;
    bool response_received = false;
    bool timed_out = false;
    uint64_t elapsed_ms = 0;
    uint64_t started_at = 0;
    bool cleaning_up = false;
    uv_timer_t* timer = nullptr;
};

static void delayed_ping_cleanup(DelayedPingCtx* ctx) {
    if (ctx->cleaning_up) return;
    ctx->cleaning_up = true;
    ctx->server->close();
    ctx->client->close();
    if (ctx->timer) {
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer), on_close);
        ctx->timer = nullptr;
    }
}

TEST(DelayedPing, ServerRepliesAfterDelay) {
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

    DelayedPingCtx ctx;
    ctx.server = &server;
    ctx.client = &client;
    ctx.started_at = uv_now(&loop);

    constexpr uint32_t DELAY_MS = 200;

    uint16_t tid = client.delayed_ping(
        Ipv4Address::from_string("127.0.0.1", server.port()),
        DELAY_MS,
        [&ctx, &loop](const Response&) {
            ctx.response_received = true;
            ctx.elapsed_ms = uv_now(&loop) - ctx.started_at;
            delayed_ping_cleanup(&ctx);
        },
        [&ctx](uint16_t) {
            ctx.timed_out = true;
            delayed_ping_cleanup(&ctx);
        });
    EXPECT_NE(tid, 0) << "delayed_ping should allocate a TID";

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<DelayedPingCtx*>(t->data);
        c->timer = nullptr;
        delayed_ping_cleanup(c);
    }, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(ctx.response_received) << "Client should receive delayed ping response";
    EXPECT_FALSE(ctx.timed_out);
    // Allow some scheduling slack (timer granularity + network loopback).
    EXPECT_GE(ctx.elapsed_ms, DELAY_MS - 20)
        << "Reply arrived too early (elapsed=" << ctx.elapsed_ms << "ms)";
    EXPECT_LE(ctx.elapsed_ms, DELAY_MS + 500)
        << "Reply arrived too late (elapsed=" << ctx.elapsed_ms << "ms)";

    uv_loop_close(&loop);
}

TEST(DelayedPing, RejectsDelayExceedingClientMax) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId client_id{};
    client_id.fill(0x33);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    // Default max is 10_000 ms; request 20_000 ms → must be rejected locally.
    uint16_t tid = client.delayed_ping(
        Ipv4Address::from_string("127.0.0.1", 12345),
        20000,
        [](const Response&) {},
        [](uint16_t) {});
    EXPECT_EQ(tid, 0) << "delayed_ping should reject delays above max_ping_delay_ms";

    client.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(DelayedPing, ServerDropsDelayAboveItsMax) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0x44);
    RpcSocket server(&loop, server_id);
    server.bind(0);
    // Server allows up to 50 ms; client will request 500 ms → server drops.
    server.set_max_ping_delay_ms(50);

    RpcHandlers handlers(server);
    handlers.install();

    NodeId client_id{};
    client_id.fill(0x55);
    RpcSocket client(&loop, client_id);
    client.bind(0);
    // Client max is relaxed to 10 s so it will actually send the request.
    client.set_max_ping_delay_ms(10000);

    DelayedPingCtx ctx;
    ctx.server = &server;
    ctx.client = &client;
    ctx.started_at = uv_now(&loop);

    client.delayed_ping(
        Ipv4Address::from_string("127.0.0.1", server.port()),
        500,  // > server's 50 ms cap
        [&ctx](const Response&) {
            ctx.response_received = true;
            delayed_ping_cleanup(&ctx);
        },
        [&ctx](uint16_t) {
            ctx.timed_out = true;
            delayed_ping_cleanup(&ctx);
        });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<DelayedPingCtx*>(t->data);
        c->timer = nullptr;
        delayed_ping_cleanup(c);
    }, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_FALSE(ctx.response_received)
        << "Server must drop the request when delayMs exceeds its max_ping_delay_ms";
    EXPECT_TRUE(ctx.timed_out) << "Client should time out";

    uv_loop_close(&loop);
}

// ============================================================================
// Ping-and-swap eviction — when a routing-table bucket fills, the RpcSocket
// pings the oldest entry; if it times out the old node is evicted and the
// new one swapped in. Matches JS dht-rpc `_onfullrow` / `_repingAndSwap`.
// ============================================================================

// Craft a NodeId that lands in a specific bucket relative to `local`.
// Bucket index = position of the first differing bit (0 = MSB).
// `rank` is a lexicographic tiebreaker so we can inject K different IDs
// into the same bucket.
static NodeId node_id_in_bucket(const NodeId& local, size_t bucket_idx,
                                 uint8_t rank) {
    NodeId id = local;
    size_t byte = bucket_idx / 8;
    size_t bit  = bucket_idx % 8;
    id[byte] ^= static_cast<uint8_t>(0x80 >> bit);  // flip the target bit
    // Overwrite the last byte for uniqueness (doesn't affect bucket index
    // because we only touched one higher bit).
    id[31] = rank;
    return id;
}

// Inject a fake node directly into the routing table for test setup.
static void inject_fake(RpcSocket& sock, size_t bucket_idx, uint8_t rank,
                         uint16_t port, uint32_t added_tick,
                         uint32_t seen_tick) {
    Node n{};
    n.id = node_id_in_bucket(sock.table().id(), bucket_idx, rank);
    n.host = "127.0.0.1";
    n.port = port;
    n.added = added_tick;
    n.seen = seen_tick;
    n.pinged = seen_tick;
    ASSERT_TRUE(sock.table().add(n))
        << "Bucket " << bucket_idx << " should accept node rank=" << (int)rank;
}

TEST(PingAndSwap, EvictsWhenOldestTimesOut) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId local_id{};
    local_id.fill(0x00);
    RpcSocket client(&loop, local_id);
    client.bind(0);
    client.set_bootstrapped(true);  // mirror JS `bootstrapped` gate

    // Fill bucket 8 with K fake entries. Oldest = rank 1 (added tick 1),
    // with the largest rank having the freshest added tick.
    constexpr size_t BKT = 8;
    for (size_t i = 0; i < hyperdht::routing::K; i++) {
        inject_fake(client, BKT,
                    static_cast<uint8_t>(i + 1),
                    /*port=*/static_cast<uint16_t>(1000 + i),
                    /*added_tick=*/static_cast<uint32_t>(i + 1),
                    /*seen_tick=*/static_cast<uint32_t>(i + 1));
    }
    ASSERT_EQ(client.table().size(), hyperdht::routing::K);

    // Advance the tick so "since_pinged" isn't 0 and we can compare against
    // RECENT_NODE_TICKS meaningfully. Put us well past RECENT_NODE.
    client.bump_tick(RECENT_NODE_TICKS + 5);

    // New candidate — a 21st node that belongs in the same bucket.
    // Port 0 doesn't matter; it never has to respond.
    Node new_node{};
    new_node.id = node_id_in_bucket(local_id, BKT, /*rank=*/200);
    new_node.host = "127.0.0.1";
    new_node.port = 9999;
    new_node.added = client.tick();
    new_node.seen  = client.tick();
    new_node.pinged = client.tick();

    // Attempt add — bucket is full → triggers ping-and-swap. The oldest
    // entry points at 127.0.0.1:1000 which has nothing listening, so the
    // PING will time out and we'll swap.
    client.table().add(new_node);

    // Run the loop with a watchdog. Adaptive-default timeout is 1000 ms +
    // retries=0, so swap should complete in ~1 s.
    bool cleanup_done = false;
    uv_timer_t watchdog;
    uv_timer_init(&loop, &watchdog);
    struct WD { RpcSocket* c; bool* done; };
    WD wd{&client, &cleanup_done};
    watchdog.data = &wd;
    uv_timer_start(&watchdog, [](uv_timer_t* t) {
        auto* w = static_cast<WD*>(t->data);
        *w->done = true;
        w->c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 2500, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(cleanup_done);
    // After the swap: oldest (rank 1, port 1000) should be gone, new node
    // (rank 200, port 9999) should be present.
    auto new_id  = node_id_in_bucket(local_id, BKT, 200);
    auto old_id  = node_id_in_bucket(local_id, BKT, 1);
    EXPECT_TRUE(client.table().has(new_id))
        << "New node should have been swapped in after PING timeout";
    EXPECT_FALSE(client.table().has(old_id))
        << "Oldest (timed-out) node should have been evicted";
    EXPECT_EQ(client.table().size(), hyperdht::routing::K);

    uv_loop_close(&loop);
}

TEST(PingAndSwap, KeepsOldestWhenItResponds) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // A real "oldest" node that responds to PING.
    NodeId oldest_id{};
    oldest_id.fill(0x55);
    RpcSocket oldest_sock(&loop, oldest_id);
    oldest_sock.bind(0);
    RpcHandlers oldest_handlers(oldest_sock);
    oldest_handlers.install();

    // The client under test.
    NodeId local_id{};
    local_id.fill(0x00);
    RpcSocket client(&loop, local_id);
    client.bind(0);
    client.set_bootstrapped(true);

    // Find a bucket index that puts the oldest node in the right spot.
    // We'll use the bucket determined by bucket_index(local, oldest_id).
    size_t bkt = hyperdht::routing::bucket_index(local_id, oldest_id);

    // Inject the *real* oldest socket at rank 1 (oldest added).
    Node real_old{};
    real_old.id = oldest_id;
    real_old.host = "127.0.0.1";
    real_old.port = oldest_sock.port();
    real_old.added = 1;
    real_old.seen = 1;
    real_old.pinged = 1;
    ASSERT_TRUE(client.table().add(real_old));

    // Fill the rest of the bucket with K-1 fakes (ranks 2..K), each with a
    // later added tick so the real one is the oldest.
    for (size_t i = 1; i < hyperdht::routing::K; i++) {
        inject_fake(client, bkt,
                    static_cast<uint8_t>(i + 1),
                    /*port=*/static_cast<uint16_t>(1100 + i),
                    /*added_tick=*/static_cast<uint32_t>(i + 1),
                    /*seen_tick=*/static_cast<uint32_t>(i + 1));
    }
    ASSERT_EQ(client.table().size(), hyperdht::routing::K);

    client.bump_tick(RECENT_NODE_TICKS + 5);

    // Candidate new node.
    Node new_node{};
    new_node.id = node_id_in_bucket(local_id, bkt, /*rank=*/201);
    // Avoid collision with the oldest_id's last byte
    if (new_node.id == oldest_id) new_node.id[31] ^= 0x01;
    new_node.host = "127.0.0.1";
    new_node.port = 9999;
    new_node.added = client.tick();
    new_node.seen  = client.tick();
    new_node.pinged = client.tick();

    // Trigger ping-and-swap. The real oldest responds → client keeps it,
    // rejects new_node.
    client.table().add(new_node);

    struct WD2 { RpcSocket* c; RpcSocket* o; bool done; };
    WD2 wd{&client, &oldest_sock, false};
    uv_timer_t watchdog;
    uv_timer_init(&loop, &watchdog);
    watchdog.data = &wd;
    uv_timer_start(&watchdog, [](uv_timer_t* t) {
        auto* w = static_cast<WD2*>(t->data);
        w->done = true;
        w->c->close();
        w->o->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 2500, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    EXPECT_TRUE(wd.done);

    EXPECT_TRUE(client.table().has(oldest_id))
        << "Oldest (responded) should have been kept";
    EXPECT_FALSE(client.table().has(new_node.id))
        << "New node should NOT have been swapped in";

    uv_loop_close(&loop);
}

TEST(PingAndSwap, GatedUntilBootstrapped) {
    // JS parity: `_onfullrow` is a no-op while `!this.bootstrapped`. Fill
    // a bucket, add a 21st node *without* marking the socket bootstrapped,
    // and verify no ping-and-swap was triggered.
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId local_id{};
    local_id.fill(0x00);
    RpcSocket client(&loop, local_id);
    client.bind(0);
    // Deliberately leave bootstrapped = false.
    ASSERT_FALSE(client.is_bootstrapped());

    constexpr size_t BKT = 6;
    for (size_t i = 0; i < hyperdht::routing::K; i++) {
        inject_fake(client, BKT,
                    static_cast<uint8_t>(i + 1),
                    /*port=*/static_cast<uint16_t>(1300 + i),
                    /*added_tick=*/static_cast<uint32_t>(i + 1),
                    /*seen_tick=*/static_cast<uint32_t>(i + 1));
    }

    Node new_node{};
    new_node.id = node_id_in_bucket(local_id, BKT, /*rank=*/200);
    new_node.host = "127.0.0.1";
    new_node.port = 9999;
    client.table().add(new_node);

    // No ping should have been scheduled.
    EXPECT_EQ(client.repinging(), 0) << "ping-and-swap must be gated behind bootstrapped";
    // The bucket still contains only the original K fakes; the new node
    // was silently rejected (as JS does pre-bootstrap).
    EXPECT_FALSE(client.table().has(new_node.id));
    EXPECT_EQ(client.table().size(), hyperdht::routing::K);

    client.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(PingAndSwap, RespectsRepingingCap) {
    // We can't easily drive 3 concurrent ping-and-swap attempts in a unit
    // test without a multi-socket setup, so instead we verify the counter
    // bookkeeping: after a swap completes, repinging() is back to 0.
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId local_id{};
    local_id.fill(0x00);
    RpcSocket client(&loop, local_id);
    client.bind(0);
    client.set_bootstrapped(true);

    constexpr size_t BKT = 4;
    for (size_t i = 0; i < hyperdht::routing::K; i++) {
        inject_fake(client, BKT,
                    static_cast<uint8_t>(i + 1),
                    /*port=*/static_cast<uint16_t>(1200 + i),
                    /*added_tick=*/static_cast<uint32_t>(i + 1),
                    /*seen_tick=*/static_cast<uint32_t>(i + 1));
    }
    client.bump_tick(RECENT_NODE_TICKS + 5);

    Node new_node{};
    new_node.id = node_id_in_bucket(local_id, BKT, 200);
    new_node.host = "127.0.0.1";
    new_node.port = 9999;
    client.table().add(new_node);

    // Before the ping fires, counter should be 1 (we scheduled one swap).
    EXPECT_EQ(client.repinging(), 1);

    uv_timer_t watchdog;
    uv_timer_init(&loop, &watchdog);
    watchdog.data = &client;
    uv_timer_start(&watchdog, [](uv_timer_t* t) {
        auto* c = static_cast<RpcSocket*>(t->data);
        c->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 2500, 0);
    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_EQ(client.repinging(), 0)
        << "repinging counter must return to 0 after swap completes";

    uv_loop_close(&loop);
}

// ============================================================================
// DOWN_HINT — a peer reports another node is down. We look up that node in
// our routing table (id = BLAKE2b-256 of its 6-byte compact ipv4 encoding),
// schedule a PING check, and evict on timeout. Matches JS dht-rpc DOWN_HINT.
// ============================================================================

// Build the 6-byte compact ipv4 encoding used as the DOWN_HINT payload and
// as the input to the id-hash. Matches `peer.ipv4.encode({host,port})` in
// JS `dht-rpc/lib/peer.js`: 4-byte host LE + 2-byte port LE.
static std::vector<uint8_t> encode_addr6(const std::string& host, uint16_t port) {
    std::vector<uint8_t> out(6, 0);
    // Parse host into 4 bytes.
    size_t pos = 0;
    for (int i = 0; i < 4; i++) {
        size_t dot = host.find('.', pos);
        std::string part = host.substr(pos, dot == std::string::npos ? std::string::npos : dot - pos);
        out[i] = static_cast<uint8_t>(std::stoi(part));
        if (dot == std::string::npos) break;
        pos = dot + 1;
    }
    out[4] = static_cast<uint8_t>(port & 0xFF);
    out[5] = static_cast<uint8_t>((port >> 8) & 0xFF);
    return out;
}

// Compute the BLAKE2b-256 id of an address (matches JS `peer.id()`).
static NodeId addr_id(const std::string& host, uint16_t port) {
    auto addr6 = encode_addr6(host, port);
    NodeId id{};
    crypto_generichash(id.data(), id.size(), addr6.data(), addr6.size(),
                       nullptr, 0);
    return id;
}

struct DownHintCtx {
    RpcSocket* server = nullptr;
    RpcSocket* client = nullptr;
    bool down_hint_replied = false;
    bool cleaning_up = false;
    uv_timer_t* timer = nullptr;
};

static void down_hint_cleanup(DownHintCtx* ctx) {
    if (ctx->cleaning_up) return;
    ctx->cleaning_up = true;
    ctx->server->close();
    ctx->client->close();
    if (ctx->timer) {
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer), on_close);
        ctx->timer = nullptr;
    }
}

TEST(DownHint, EvictsTargetWhenItTimesOut) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Server = the node we'll send DOWN_HINT to.
    NodeId server_id{};
    server_id.fill(0xA1);
    RpcSocket server(&loop, server_id);
    server.bind(0);

    RpcHandlers handlers(server);
    handlers.install();

    // Client sends the DOWN_HINT.
    NodeId client_id{};
    client_id.fill(0xA2);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    // The reported-down target: a fake address that nothing listens on.
    // Its id in the server's routing table = BLAKE2b(addr6).
    constexpr const char* TARGET_HOST = "127.0.0.1";
    constexpr uint16_t TARGET_PORT = 1;  // nothing listens
    NodeId target_id = addr_id(TARGET_HOST, TARGET_PORT);

    // Inject the target into the server's routing table.
    Node fake{};
    fake.id = target_id;
    fake.host = TARGET_HOST;
    fake.port = TARGET_PORT;
    fake.added = 1;
    fake.seen = 1;
    fake.pinged = 1;
    ASSERT_TRUE(server.table().add(fake));
    ASSERT_EQ(server.table().size(), 1u);

    // Advance server tick so the "pinged < tick" guard passes.
    server.bump_tick(5);

    // Build and send the DOWN_HINT request from the client.
    DownHintCtx ctx;
    ctx.server = &server;
    ctx.client = &client;

    Request req;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    req.command = CMD_DOWN_HINT;
    req.internal = true;
    req.value = encode_addr6(TARGET_HOST, TARGET_PORT);

    client.request(req,
        [&ctx](const Response&) {
            ctx.down_hint_replied = true;
            // Don't clean up yet — we need the server's check to fire + time out.
        },
        [&ctx](uint16_t) {
            down_hint_cleanup(&ctx);
        });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<DownHintCtx*>(t->data);
        c->timer = nullptr;
        down_hint_cleanup(c);
    }, 2500, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(ctx.down_hint_replied)
        << "DOWN_HINT should always receive an empty ack reply";
    EXPECT_FALSE(server.table().has(target_id))
        << "Target should have been evicted after PING timeout";
    EXPECT_EQ(server.table().size(), 0u);

    uv_loop_close(&loop);
}

TEST(DownHint, IgnoresMalformedValue) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0xB1);
    RpcSocket server(&loop, server_id);
    server.bind(0);

    RpcHandlers handlers(server);
    handlers.install();

    NodeId client_id{};
    client_id.fill(0xB2);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    // Short value (< 6 bytes) → JS drops silently and does NOT reply.
    DownHintCtx ctx;
    ctx.server = &server;
    ctx.client = &client;

    Request req;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    req.command = CMD_DOWN_HINT;
    req.internal = true;
    req.value = std::vector<uint8_t>{1, 2, 3};  // only 3 bytes

    client.request(req,
        [&ctx](const Response&) {
            ctx.down_hint_replied = true;
            down_hint_cleanup(&ctx);
        },
        [&ctx](uint16_t) {
            // Expected — no reply ever comes.
            down_hint_cleanup(&ctx);
        });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<DownHintCtx*>(t->data);
        c->timer = nullptr;
        down_hint_cleanup(c);
    }, 2000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    EXPECT_FALSE(ctx.down_hint_replied)
        << "DOWN_HINT with malformed value must be silently dropped";

    uv_loop_close(&loop);
}

TEST(DownHint, UnknownTargetRepliesButDoesNothing) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0xC1);
    RpcSocket server(&loop, server_id);
    server.bind(0);

    RpcHandlers handlers(server);
    handlers.install();

    NodeId client_id{};
    client_id.fill(0xC2);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    // Server's routing table is empty — DOWN_HINT target is unknown.
    ASSERT_EQ(server.table().size(), 0u);

    DownHintCtx ctx;
    ctx.server = &server;
    ctx.client = &client;

    Request req;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    req.command = CMD_DOWN_HINT;
    req.internal = true;
    req.value = encode_addr6("10.20.30.40", 1234);

    client.request(req,
        [&ctx, &server](const Response&) {
            ctx.down_hint_replied = true;
            // No check should have been scheduled since the target isn't known.
            EXPECT_EQ(server.checks(), 0);
            down_hint_cleanup(&ctx);
        },
        [&ctx](uint16_t) { down_hint_cleanup(&ctx); });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<DownHintCtx*>(t->data);
        c->timer = nullptr;
        down_hint_cleanup(c);
    }, 2000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    EXPECT_TRUE(ctx.down_hint_replied);

    uv_loop_close(&loop);
}

// ============================================================================
// filter_node — users can install a callback that silently rejects observed
// peers before they enter the routing table or query frontier. Matches JS
// dht-rpc `_filterNode`.
// ============================================================================

TEST(FilterNode, RejectsPeerOnAddNodeFromNetwork) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId local_id{};
    local_id.fill(0x00);
    RpcSocket sock(&loop, local_id);
    sock.bind(0);

    // Install a filter that rejects anything on 10.0.0.0/24.
    sock.set_filter_node([](const NodeId&, const Ipv4Address& addr) {
        return !(addr.host[0] == 10 && addr.host[1] == 0 && addr.host[2] == 0);
    });

    NodeId node_id{};
    node_id.fill(0x11);

    // Blocked peer.
    sock.add_node_from_network(node_id, Ipv4Address::from_string("10.0.0.5", 1234));
    EXPECT_FALSE(sock.table().has(node_id)) << "Filtered peer must not enter the table";

    // Allowed peer — different id so we don't collide.
    NodeId allowed_id{};
    allowed_id.fill(0x22);
    sock.add_node_from_network(allowed_id, Ipv4Address::from_string("192.168.1.5", 1234));
    EXPECT_TRUE(sock.table().has(allowed_id)) << "Non-filtered peer must be accepted";

    sock.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(FilterNode, PeerIdIsBlake2bOfAddr) {
    // Confirm that compute_peer_id produces the same hash JS produces:
    // BLAKE2b-256 over the 6-byte ipv4 compact encoding (4 host LE + 2 port LE).
    auto addr = Ipv4Address::from_string("192.168.1.5", 1234);
    auto id = hyperdht::rpc::compute_peer_id(addr);

    // Compute reference hash the same way handle_down_hint does — proving
    // the two paths are consistent (so a DOWN_HINT lookup will find the
    // same peer a filter decision was made on).
    uint8_t buf[6];
    buf[0] = 192; buf[1] = 168; buf[2] = 1; buf[3] = 5;
    buf[4] = 1234 & 0xFF;
    buf[5] = (1234 >> 8) & 0xFF;
    std::array<uint8_t, 32> expect{};
    crypto_generichash(expect.data(), 32, buf, 6, nullptr, 0);

    EXPECT_EQ(id, expect);
}

TEST(DelayedPing, HandlersDestructorCancelsPending) {
    // Verify that destroying RpcHandlers while a DELAYED_PING reply is still
    // pending does not crash / leak. We schedule a 2 s delay and tear down
    // immediately after.
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0x66);
    auto server = std::make_unique<RpcSocket>(&loop, server_id);
    server->bind(0);

    auto handlers = std::make_unique<RpcHandlers>(*server);
    handlers->install();

    NodeId client_id{};
    client_id.fill(0x77);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    client.delayed_ping(
        Ipv4Address::from_string("127.0.0.1", server->port()),
        2000,   // long enough we will NOT wait for it
        [](const Response&) {},
        [](uint16_t) {});

    // Pump the loop once so the server receives the request and schedules
    // the pending reply.
    uv_run(&loop, UV_RUN_NOWAIT);
    // Pump a few more times to make sure the schedule happened.
    for (int i = 0; i < 10; i++) uv_run(&loop, UV_RUN_NOWAIT);

    // Destroy handlers first (this should cancel the pending timer cleanly).
    handlers.reset();
    // Then close and destroy sockets.
    client.close();
    server->close();

    uv_run(&loop, UV_RUN_DEFAULT);  // drain all close callbacks
    uv_loop_close(&loop);
    // If we got here without ASan/UBSan complaints, cleanup worked.
    SUCCEED();
}

// ---------------------------------------------------------------------------
// rpc::Session — JS dht-rpc/lib/session.js. A Session tracks the requests
// issued through it so `destroy()` can cancel them as a batch. Cancellation
// is silent (neither on_response nor on_timeout fires).
// ---------------------------------------------------------------------------

TEST(Session, DestroyCancelsInflightRequests) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Server that never replies — we want the timeout-budget-releasing
    // cancel to fire before any response could race it.
    NodeId server_id{};
    server_id.fill(0x10);
    RpcSocket server(&loop, server_id);
    server.bind(0);

    NodeId client_id{};
    client_id.fill(0x11);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    Session session(client);

    // Two PING requests tracked through the session.
    int responses = 0;
    int timeouts = 0;
    Request ping1;
    ping1.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping1.command = CMD_PING;

    Request ping2;
    ping2.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping2.command = CMD_PING;

    session.request(ping1,
        [&](const Response&) { responses++; },
        [&](uint16_t) { timeouts++; });
    session.request(ping2,
        [&](const Response&) { responses++; },
        [&](uint16_t) { timeouts++; });

    EXPECT_EQ(session.inflight_count(), 2u);
    EXPECT_EQ(client.inflight_count(), 2u);

    // destroy() must cancel both; no callback fires.
    session.destroy();

    EXPECT_EQ(session.inflight_count(), 0u);
    EXPECT_EQ(client.inflight_count(), 0u)
        << "RpcSocket inflight budget must be returned on cancel";
    EXPECT_EQ(responses, 0);
    EXPECT_EQ(timeouts, 0);

    // Pump the loop a little to make sure no callback arrives after the fact.
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    struct Ctx { RpcSocket& c; RpcSocket& s; uv_timer_t& t; };
    Ctx ctx{client, server, timer};
    timer.data = &ctx;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->c.close();
        c->s.close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 200, 0);
    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_EQ(responses, 0);
    EXPECT_EQ(timeouts, 0);

    uv_loop_close(&loop);
}

TEST(Session, DestructorCancelsPending) {
    // Scope guarantee: a Session going out of scope with tracked
    // requests must cancel them — otherwise those requests would
    // leak their congestion budget.
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId server_id{};
    server_id.fill(0x20);
    RpcSocket server(&loop, server_id);
    server.bind(0);

    NodeId client_id{};
    client_id.fill(0x21);
    RpcSocket client(&loop, client_id);
    client.bind(0);

    {
        Session session(client);
        Request ping;
        ping.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
        ping.command = CMD_PING;
        session.request(ping, [](const Response&) {}, [](uint16_t) {});
        EXPECT_EQ(client.inflight_count(), 1u);
    } // ~Session here

    EXPECT_EQ(client.inflight_count(), 0u);

    client.close();
    server.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}
