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
