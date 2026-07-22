// Test server-side PEER_HANDSHAKE — Noise IK responder.
// Verifies that the server can process a client's Noise msg1,
// derive matching keys, and produce a valid Noise msg2.

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/dht_messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/server_connection.hpp"

using namespace hyperdht;
using namespace hyperdht::server_connection;

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
// Helper: simulate client-side Noise msg1
// ---------------------------------------------------------------------------

struct ClientHandshake {
    std::vector<uint8_t> noise_msg1;
    std::shared_ptr<noise::NoiseIK> noise_ik;
};

static ClientHandshake make_client_msg1(
    const noise::Keypair& client_kp,
    const noise::PubKey& server_pk,
    uint32_t client_udx_id) {

    // Same prologue as real HyperDHT
    const auto& prol = dht_messages::ns_peer_handshake();

    auto noise_ik = std::make_shared<noise::NoiseIK>(
        true, client_kp, prol.data(), prol.size(), &server_pk);

    // Build client's NoisePayload
    peer_connect::NoisePayload payload;
    payload.version = 1;
    payload.error = peer_connect::ERROR_NONE;
    payload.firewall = peer_connect::FIREWALL_CONSISTENT;
    payload.udx = peer_connect::UdxInfo{1, false, client_udx_id, 0};
    payload.has_secret_stream = true;

    auto payload_bytes = peer_connect::encode_noise_payload(payload);
    auto msg1 = noise_ik->send(payload_bytes.data(), payload_bytes.size());

    ClientHandshake result;
    result.noise_msg1 = std::move(msg1);
    result.noise_ik = noise_ik;
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(ServerHandshake, BasicHandshake) {
    // Generate keypairs
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    // Client creates Noise msg1
    auto client = make_client_msg1(client_kp, server_kp.public_key, 12345);

    // Server processes it
    auto result = handle_handshake(
        server_kp,
        client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000),
        0,   // holepunch_id
        {},  // our_addresses (empty = not OPEN)
        {},  // relay_infos
        nullptr);  // no firewall

    ASSERT_TRUE(result.has_value());
    auto& conn = *result;

    EXPECT_FALSE(conn.has_error);
    EXPECT_EQ(conn.error_code, peer_connect::ERROR_NONE);
    EXPECT_FALSE(conn.reply_noise.empty());
    EXPECT_GT(conn.local_udx_id, 0u);
    EXPECT_NE(conn.secure, nullptr);

    // Server should have learned the client's public key
    EXPECT_EQ(conn.remote_public_key, client_kp.public_key);

    // Server should have the client's UDX ID
    ASSERT_TRUE(conn.remote_payload.udx.has_value());
    EXPECT_EQ(conn.remote_payload.udx->id, 12345u);

    // Client decrypts Noise msg2
    auto server_payload_bytes = client.noise_ik->recv(
        conn.reply_noise.data(), conn.reply_noise.size());
    ASSERT_TRUE(server_payload_bytes.has_value());
    EXPECT_TRUE(client.noise_ik->is_complete());

    auto server_payload = peer_connect::decode_noise_payload(
        server_payload_bytes->data(), server_payload_bytes->size());
    EXPECT_EQ(server_payload.error, peer_connect::ERROR_NONE);
    EXPECT_EQ(server_payload.version, 1u);
    EXPECT_TRUE(server_payload.has_secret_stream);
    ASSERT_TRUE(server_payload.udx.has_value());
    EXPECT_EQ(server_payload.udx->id, conn.local_udx_id);
}

TEST(ServerHandshake, KeysMatch) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);
    auto result = handle_handshake(server_kp, client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 0, {}, {});
    ASSERT_TRUE(result.has_value());

    // Client processes msg2
    client.noise_ik->recv(result->reply_noise.data(), result->reply_noise.size());

    // Keys should be complementary: client tx = server rx, client rx = server tx
    EXPECT_EQ(client.noise_ik->tx_key(), result->rx_key);
    EXPECT_EQ(client.noise_ik->rx_key(), result->tx_key);

    // Handshake hashes should match
    EXPECT_EQ(client.noise_ik->handshake_hash(), result->handshake_hash);
}

TEST(ServerHandshake, FirewallRejects) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);

    // Firewall rejects all connections
    auto result = handle_handshake(server_kp, client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 0, {}, {},
        [](const auto&, const auto&, const auto&) { return true; });

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->firewalled);
    EXPECT_TRUE(result->has_error);
    EXPECT_EQ(result->error_code, peer_connect::ERROR_ABORTED);
    // server-1 — JS: server.js:258-261 returns null BEFORE handshake.send;
    // router.js:99 then sends nothing. No Noise msg2 may be built for a
    // rejected peer — the client sees silence, not a refusal.
    EXPECT_TRUE(result->reply_noise.empty());
}

// Two-phase split — decode_handshake() followed by finalize_handshake()
// must produce an equivalent ServerConnection (same error code,
// firewall flag, holepunch id, public key). NOT a byte-identical msg2
// check: NoiseIK picks a fresh ephemeral on every recv(), so the two
// responses necessarily differ in the ephemeral field. Byte-identity
// would require pinning ephemerals via `set_ephemeral()`, which we
// don't do here.
TEST(ServerHandshake, DecodeThenFinalizeMatchesSync) {
    noise::Seed server_seed{}; server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);
    noise::Seed client_seed{}; client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);

    auto pending = decode_handshake(server_kp, client.noise_msg1);
    ASSERT_TRUE(pending.has_value());

    // Public key should match the client's static.
    EXPECT_EQ(pending->remote_public_key, client_kp.public_key);

    auto result = finalize_handshake(std::move(*pending), 42, {}, {},
                                      /*firewall_rejected=*/false,
                                      /*has_remote_address=*/false);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->firewalled);
    EXPECT_FALSE(result->has_error);
    EXPECT_EQ(result->id, 42);
}

// Finalizing with rejected=true yields the same outcome as the
// sync-wrapper handle_handshake with a reject-all firewall — both mark
// the session firewalled and build NO reply bytes (server-1 silence).
TEST(ServerHandshake, FinalizeRejectedEqualsSyncReject) {
    noise::Seed server_seed{}; server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);
    noise::Seed client_seed{}; client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);

    auto pending = decode_handshake(server_kp, client.noise_msg1);
    ASSERT_TRUE(pending.has_value());

    auto async_result = finalize_handshake(std::move(*pending), 0, {}, {},
                                            /*firewall_rejected=*/true,
                                            /*has_remote_address=*/false);
    ASSERT_TRUE(async_result.has_value());
    EXPECT_TRUE(async_result->firewalled);
    EXPECT_EQ(async_result->error_code, peer_connect::ERROR_ABORTED);
    EXPECT_TRUE(async_result->reply_noise.empty());  // server-1: silence

    // Fresh decode for the sync call (Noise state is single-use).
    auto client2 = make_client_msg1(client_kp, server_kp.public_key, 1);
    auto sync_result = handle_handshake(server_kp, client2.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 0, {}, {},
        [](const auto&, const auto&, const auto&) { return true; });
    ASSERT_TRUE(sync_result.has_value());
    EXPECT_TRUE(sync_result->firewalled);
    EXPECT_EQ(sync_result->error_code, async_result->error_code);
    EXPECT_TRUE(sync_result->reply_noise.empty());  // server-1: silence
}

TEST(ServerHandshake, HolepunchInfoWhenNotOpen) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);

    // Server has no addresses → not OPEN → should include holepunch info
    peer_connect::RelayInfo relay;
    relay.relay_address = compact::Ipv4Address::from_string("1.2.3.4", 49737);
    relay.peer_address = compact::Ipv4Address::from_string("5.6.7.8", 30000);

    auto result = handle_handshake(server_kp, client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 7,
        {}, {relay});
    ASSERT_TRUE(result.has_value());

    // Decode server's response
    auto resp_bytes = client.noise_ik->recv(
        result->reply_noise.data(), result->reply_noise.size());
    auto resp = peer_connect::decode_noise_payload(
        resp_bytes->data(), resp_bytes->size());

    EXPECT_EQ(resp.firewall, peer_connect::FIREWALL_UNKNOWN);
    ASSERT_TRUE(resp.holepunch.has_value());
    EXPECT_EQ(resp.holepunch->id, 7u);
    ASSERT_EQ(resp.holepunch->relays.size(), 1u);
    EXPECT_EQ(resp.holepunch->relays[0].relay_address.host_string(), "1.2.3.4");
}

TEST(ServerHandshake, ConsistentFirewallWithHolepunch) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);

    // Server has addresses → reports CONSISTENT (not OPEN) to force
    // holepunch path. Direct-connect (OPEN) needs UDX rawStream firewall.
    std::vector<compact::Ipv4Address> addrs = {
        compact::Ipv4Address::from_string("1.2.3.4", 49737)
    };
    peer_connect::RelayInfo relay;
    relay.relay_address = compact::Ipv4Address::from_string("9.8.7.6", 49737);

    auto result = handle_handshake(server_kp, client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 0,
        addrs, {relay});
    ASSERT_TRUE(result.has_value());

    auto resp_bytes = client.noise_ik->recv(
        result->reply_noise.data(), result->reply_noise.size());
    auto resp = peer_connect::decode_noise_payload(
        resp_bytes->data(), resp_bytes->size());

    EXPECT_EQ(resp.firewall, peer_connect::FIREWALL_CONSISTENT);
    ASSERT_TRUE(resp.holepunch.has_value());
    EXPECT_EQ(resp.holepunch->id, 0u);
}

TEST(ServerHandshake, InvalidNoiseFails) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    // Garbage noise data
    std::vector<uint8_t> garbage(100, 0xFF);

    auto result = handle_handshake(server_kp, garbage,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 0, {}, {});

    EXPECT_FALSE(result.has_value());
}

// ===========================================================================
// Client-side PEER_HANDSHAKE reply validation (parity finding connect-8).
//
// Loopback RPC harness: a fake relay answers the client's PEER_HANDSHAKE
// with a real Noise IK msg2, mutated per test. Mirrors JS:
//   router.js:63-71  — mode !== REPLY / wrong source address / empty noise
//                      → BAD_HANDSHAKE_REPLY (per-attempt, NOT terminal)
//   connect.js:425-436 — version !== 1 / error !== NONE / missing udx
//                      → SERVER_INCOMPATIBLE / SERVER_ERROR (TERMINAL)
// ===========================================================================

namespace {

struct ReplyCfg {
    uint32_t mode = peer_connect::MODE_REPLY;
    bool clear_noise = false;          // drop the noise bytes from the reply
    uint32_t version = 1;              // server NoisePayload version
    uint32_t error = peer_connect::ERROR_NONE;
    bool include_udx = true;
    bool reply_from_rogue = false;     // reply from a different socket/port
    bool client_reusable = false;      // connect-3: opts.reusableSocket
};

struct ReplyCtx {
    rpc::RpcSocket* client = nullptr;
    rpc::RpcSocket* relay = nullptr;
    rpc::RpcSocket* rogue = nullptr;
    bool done = false;
    bool cleaning = false;
    uv_timer_t* timer = nullptr;
    peer_connect::HandshakeResult result;
    // connect-3: the client's msg1 payload udx.reusableSocket, as decoded
    // by the fake relay (JS connect.js:406).
    bool client_advertised_reusable = false;
    // connect-6: the client's address as the relay observed it (req.from);
    // echoed back in the wire `to` field → HandshakeResult.client_address.
    compact::Ipv4Address observed_client_addr{};
};

void reply_on_close(uv_handle_t*) {}

void reply_cleanup(ReplyCtx* ctx) {
    if (ctx->cleaning) return;
    ctx->cleaning = true;
    ctx->client->close();
    ctx->relay->close();
    ctx->rogue->close();
    if (ctx->timer) {
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer), reply_on_close);
        ctx->timer = nullptr;
    }
}

// Runs one full client peer_handshake() against a fake relay that replies
// per `cfg`, and returns the HandshakeResult the client callback observed.
// `advertised_reusable` (optional) receives the udx.reusableSocket flag the
// fake relay decoded from the client's msg1 payload (connect-3).
peer_connect::HandshakeResult run_reply_scenario(
        const ReplyCfg& cfg, bool* advertised_reusable = nullptr) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);
    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    routing::NodeId cid{};
    cid.fill(0x01);
    routing::NodeId rid{};
    rid.fill(0x02);
    routing::NodeId gid{};
    gid.fill(0x03);
    rpc::RpcSocket client(&loop, cid);
    rpc::RpcSocket relay(&loop, rid);
    rpc::RpcSocket rogue(&loop, gid);
    client.bind(0);
    relay.bind(0);
    rogue.bind(0);

    ReplyCtx ctx;
    ctx.client = &client;
    ctx.relay = &relay;
    ctx.rogue = &rogue;

    bool reply_sent = false;
    relay.on_request([&](const messages::Request& req) {
        if (!req.value.has_value()) {
            ADD_FAILURE() << "PEER_HANDSHAKE request carried no value";
            reply_cleanup(&ctx);
            return;
        }
        auto hs = peer_connect::decode_handshake_msg(
            req.value->data(), req.value->size());

        // Real Noise IK responder so the reply decrypts and completes.
        const auto& prol = dht_messages::ns_peer_handshake();
        noise::NoiseIK responder(false, server_kp, prol.data(), prol.size());
        auto p1 = responder.recv(hs.noise.data(), hs.noise.size());
        if (!p1.has_value()) {
            ADD_FAILURE() << "responder failed to process msg1";
            reply_cleanup(&ctx);
            return;
        }

        // connect-3 — record the client's advertised udx.reusableSocket
        // (JS connect.js:406: udx.reusableSocket = c.reusableSocket).
        auto client_payload = peer_connect::decode_noise_payload(
            p1->data(), p1->size());
        if (client_payload.udx.has_value()) {
            ctx.client_advertised_reusable =
                client_payload.udx->reusable_socket;
        }
        ctx.observed_client_addr = req.from.addr;

        peer_connect::NoisePayload rp;
        rp.version = cfg.version;
        rp.error = cfg.error;
        rp.firewall = peer_connect::FIREWALL_OPEN;
        if (cfg.include_udx) rp.udx = peer_connect::UdxInfo{1, false, 777, 0};
        rp.has_secret_stream = true;
        auto rp_bytes = peer_connect::encode_noise_payload(rp);
        auto msg2 = responder.send(rp_bytes.data(), rp_bytes.size());

        peer_connect::HandshakeMessage reply_msg;
        reply_msg.mode = cfg.mode;
        if (!cfg.clear_noise) reply_msg.noise = std::move(msg2);

        messages::Response resp;
        resp.tid = req.tid;
        resp.from.addr = req.from.addr;
        resp.value = peer_connect::encode_handshake_msg(reply_msg);

        reply_sent = true;
        if (cfg.reply_from_rogue) {
            // Same tid, valid content — but the UDP source is a different
            // port than the relay we sent the request to.
            rogue.reply(resp, true);
        } else {
            relay.reply(resp, req.from_server);
        }
    });

    auto relay_addr = compact::Ipv4Address::from_string("127.0.0.1", relay.port());
    peer_connect::peer_handshake(
        client, relay_addr, client_kp, server_kp.public_key,
        /*our_udx_id=*/42, /*reusable_socket=*/cfg.client_reusable,
        peer_connect::FIREWALL_UNKNOWN, /*addresses4=*/{},
        /*relay_through=*/std::nullopt,
        [&](const peer_connect::HandshakeResult& r) {
            ctx.result = r;
            ctx.done = true;
            reply_cleanup(&ctx);
        });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &ctx;
    ctx.timer = &timer;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<ReplyCtx*>(t->data);
        c->timer = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(t), reply_on_close);
        reply_cleanup(c);
    }, 8000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    EXPECT_TRUE(reply_sent) << "fake relay never produced a reply";
    EXPECT_TRUE(ctx.done) << "peer_handshake callback never fired";
    if (advertised_reusable) {
        *advertised_reusable = ctx.client_advertised_reusable;
    }
    // connect-6 — clientAddress = res.to (router.js:77): our address exactly
    // as the relay observed it (the ephemeral client socket, not port()).
    if (ctx.result.success) {
        EXPECT_EQ(ctx.result.client_address, ctx.observed_client_addr);
        EXPECT_NE(ctx.result.client_address.port, 0);
    }
    return ctx.result;
}

}  // namespace

TEST(PeerHandshakeReply, WellFormedReplySucceeds) {
    auto r = run_reply_scenario(ReplyCfg{});
    EXPECT_TRUE(r.success);
    EXPECT_FALSE(r.terminal);
    ASSERT_TRUE(r.remote_payload.udx.has_value());
    EXPECT_EQ(r.remote_payload.udx->id, 777u);
}

// connect-3 — JS connect.js:406: the client's noisePayload advertises
// udx.reusableSocket = opts.reusableSocket (previously hardcoded false).
TEST(PeerHandshakeReply, ReusableSocketAdvertised) {
    ReplyCfg cfg;
    cfg.client_reusable = true;
    bool advertised = false;
    auto r = run_reply_scenario(cfg, &advertised);
    EXPECT_TRUE(r.success);
    EXPECT_TRUE(advertised);

    bool advertised_off = true;
    run_reply_scenario(ReplyCfg{}, &advertised_off);
    EXPECT_FALSE(advertised_off);
}

// JS router.js:65 — hs.mode !== REPLY → BAD_HANDSHAKE_REPLY (retryable).
TEST(PeerHandshakeReply, WrongModeRejected) {
    ReplyCfg cfg;
    cfg.mode = peer_connect::MODE_FROM_SERVER;
    auto r = run_reply_scenario(cfg);
    EXPECT_FALSE(r.success);
    EXPECT_FALSE(r.terminal);
}

// JS router.js:66-67 — reply must come from the address the request was
// sent to (the RPC layer matches by tid only). Retryable.
TEST(PeerHandshakeReply, MismatchedSourceRejected) {
    ReplyCfg cfg;
    cfg.reply_from_rogue = true;
    auto r = run_reply_scenario(cfg);
    EXPECT_FALSE(r.success);
    EXPECT_FALSE(r.terminal);
}

// JS router.js:68 — !hs.noise → BAD_HANDSHAKE_REPLY (retryable).
TEST(PeerHandshakeReply, EmptyNoiseRejected) {
    ReplyCfg cfg;
    cfg.clear_noise = true;
    auto r = run_reply_scenario(cfg);
    EXPECT_FALSE(r.success);
    EXPECT_FALSE(r.terminal);
}

// JS connect.js:425-428 — payload.version !== 1 → SERVER_INCOMPATIBLE
// (terminal — the whole connect fails, no relay retry).
TEST(PeerHandshakeReply, VersionMismatchTerminal) {
    ReplyCfg cfg;
    cfg.version = 2;
    auto r = run_reply_scenario(cfg);
    EXPECT_FALSE(r.success);
    EXPECT_TRUE(r.terminal);
}

// JS connect.js:429-432 — payload.error !== NONE → SERVER_ERROR (terminal).
TEST(PeerHandshakeReply, ServerErrorTerminal) {
    ReplyCfg cfg;
    cfg.error = peer_connect::ERROR_TRY_LATER;
    auto r = run_reply_scenario(cfg);
    EXPECT_FALSE(r.success);
    EXPECT_TRUE(r.terminal);
}

// JS connect.js:433-436 — !payload.udx → SERVER_ERROR (terminal).
TEST(PeerHandshakeReply, MissingUdxTerminal) {
    ReplyCfg cfg;
    cfg.include_udx = false;
    auto r = run_reply_scenario(cfg);
    EXPECT_FALSE(r.success);
    EXPECT_TRUE(r.terminal);
}
