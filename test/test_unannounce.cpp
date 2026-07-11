// End-to-end loopback tests for dhttop-1 (client unannounce) and dhttop-6
// (announce with clear). A persistent server + handlers holds the announce
// store; a client drives dht_ops::lookup_and_unannounce / announce(clear).
//
// The UNANNOUNCE request is signed per-reply (target, reply token, replying
// node id). If either the signature or token were wrong the server would
// silently drop the request and the record would NOT be removed — so asserting
// the record disappears proves the signature+token were valid and accepted.

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <string>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"

using namespace hyperdht;
using namespace hyperdht::rpc;
using namespace hyperdht::messages;
using namespace hyperdht::compact;
using namespace hyperdht::routing;

// Transition an RpcSocket to persistent (so it serves LOOKUP/ANNOUNCE/
// UNANNOUNCE). Copied from test_rpc_handlers.cpp's helper.
static void make_persistent(RpcSocket& socket) {
    auto our_addr = Ipv4Address::from_string("127.0.0.1", socket.port());
    for (int i = 1; i <= 3; i++) {
        auto from = Ipv4Address::from_string("10.0.0." + std::to_string(i), 49737);
        socket.nat_sampler().add(our_addr, from);
        socket.ring_sampler().add(our_addr.host_string(), our_addr.port);
    }
    socket.force_check_persistent();
}

// Seed `client`'s routing table with `server` so a query walks to it (and
// never reaches the public bootstrap nodes).
static void add_server_to_table(RpcSocket& client, RpcSocket& server) {
    auto server_addr = Ipv4Address::from_string("127.0.0.1", server.port());
    Node node;
    node.id = compute_peer_id(server_addr);
    node.host = "127.0.0.1";
    node.port = server.port();
    node.added = client.tick();
    node.pinged = client.tick();
    node.seen = client.tick();
    client.table().add(node);
}

// Sign an announce/unannounce value for our key at a target.
static std::vector<uint8_t> signed_announce(
    const noise::Keypair& kp,
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const std::array<uint8_t, 32>& token,
    const std::vector<Ipv4Address>& relays = {}) {
    dht_messages::AnnounceMessage ann;
    dht_messages::PeerRecord peer;
    peer.public_key = kp.public_key;
    peer.relay_addresses = relays;
    ann.peer = peer;
    ann.signature = announce_sig::sign_announce(
        target, node_id, token.data(), token.size(), ann, kp);
    return dht_messages::encode_announce_msg(ann);
}

// Shared harness: PING → get token → announce → run body → drain loop.
struct Harness {
    uv_loop_t loop;
    RpcSocket* server = nullptr;
    RpcSocket* client = nullptr;
    RpcHandlers* handlers = nullptr;
    std::array<uint8_t, 32> token{};
    std::array<uint8_t, 32> server_id{};
    std::array<uint8_t, 32> target{};
    bool cleaned = false;
    uv_timer_t timer{};

    void cleanup() {
        if (cleaned) return;
        cleaned = true;
        server->close();
        client->close();
        uv_close(reinterpret_cast<uv_handle_t*>(&timer), nullptr);
    }
};

TEST(Unannounce, RemovesRecordEndToEnd) {
    Harness h;
    uv_loop_init(&h.loop);

    NodeId sid{}; sid.fill(0x11);
    RpcSocket server(&h.loop, sid);
    server.bind(0);
    make_persistent(server);
    RpcHandlers handlers(server);
    handlers.install();

    NodeId cid{}; cid.fill(0x22);
    RpcSocket client(&h.loop, cid);
    client.bind(0);
    add_server_to_table(client, server);

    h.server = &server; h.client = &client; h.handlers = &handlers;
    h.target.fill(0xA5);

    noise::Seed seed{}; seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    bool announce_stored = false;
    bool unannounce_done = false;
    bool store_empty_after = false;

    // Timeout guard.
    uv_timer_init(&h.loop, &h.timer);
    h.timer.data = &h;
    uv_timer_start(&h.timer, [](uv_timer_t* t) {
        static_cast<Harness*>(t->data)->cleanup();
    }, 3000, 0);

    // Phase 1: PING to obtain a token.
    // Fetch a token via FIND_PEER — PING no longer carries a token (JS parity,
    // dht-rpc index.js:641 sendReply(0,null,false,false)). The server is
    // persistent, so FIND_PEER returns both token and id.
    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping.command = CMD_FIND_PEER;
    ping.internal = false;
    ping.target = h.target;

    announce::TargetKey key{};
    std::copy(h.target.begin(), h.target.end(), key.begin());

    client.request(ping,
        [&](const Response& resp) {
            ASSERT_TRUE(resp.token.has_value());
            ASSERT_TRUE(resp.id.has_value());
            h.token = *resp.token;
            h.server_id = *resp.id;

            // Phase 2: signed ANNOUNCE at the target.
            Request ann;
            ann.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
            ann.command = CMD_ANNOUNCE;
            ann.target = h.target;
            ann.token = h.token;
            ann.value = signed_announce(kp, h.target, h.server_id, h.token);

            client.request(ann,
                [&](const Response&) {
                    announce_stored = (handlers.store().get(key).size() == 1);
                    ASSERT_TRUE(announce_stored) << "record must be stored first";

                    // Phase 3: lookup + unannounce our record.
                    dht_ops::lookup_and_unannounce(
                        client, h.target, kp,
                        /*on_reply=*/nullptr,
                        /*user_commit=*/nullptr,
                        [&](int /*error*/, const std::vector<query::QueryReply>&) {
                            unannounce_done = true;
                            store_empty_after =
                                handlers.store().get(key).empty();
                            h.cleanup();
                        });
                },
                [&](uint16_t) { h.cleanup(); });
        },
        [&](uint16_t) { h.cleanup(); });

    uv_run(&h.loop, UV_RUN_DEFAULT);
    uv_loop_close(&h.loop);

    EXPECT_TRUE(announce_stored) << "announce should store one record";
    EXPECT_TRUE(unannounce_done) << "lookup_and_unannounce should complete";
    EXPECT_TRUE(store_empty_after)
        << "UNANNOUNCE (valid sig+token) should remove the record from the store";
}

TEST(Announce, ClearRoutesThroughUnannounceThenAnnounces) {
    Harness h;
    uv_loop_init(&h.loop);

    NodeId sid{}; sid.fill(0x33);
    RpcSocket server(&h.loop, sid);
    server.bind(0);
    make_persistent(server);
    RpcHandlers handlers(server);
    handlers.install();

    NodeId cid{}; cid.fill(0x44);
    RpcSocket client(&h.loop, cid);
    client.bind(0);
    add_server_to_table(client, server);

    h.server = &server; h.client = &client; h.handlers = &handlers;
    h.target.fill(0x5A);

    noise::Seed seed{}; seed.fill(0x77);
    auto kp = noise::generate_keypair(seed);

    // A distinctive relay address marks the NEW announce so we can tell it
    // apart from the stale record.
    auto new_relay = Ipv4Address::from_string("9.9.9.9", 1234);

    bool stale_stored = false;
    bool clear_done = false;
    bool final_is_new = false;

    uv_timer_init(&h.loop, &h.timer);
    h.timer.data = &h;
    uv_timer_start(&h.timer, [](uv_timer_t* t) {
        static_cast<Harness*>(t->data)->cleanup();
    }, 3000, 0);

    // Fetch a token via FIND_PEER — PING no longer carries a token (JS parity,
    // dht-rpc index.js:641 sendReply(0,null,false,false)). The server is
    // persistent, so FIND_PEER returns both token and id.
    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping.command = CMD_FIND_PEER;
    ping.internal = false;
    ping.target = h.target;

    announce::TargetKey key{};
    std::copy(h.target.begin(), h.target.end(), key.begin());

    client.request(ping,
        [&](const Response& resp) {
            ASSERT_TRUE(resp.token.has_value() && resp.id.has_value());
            h.token = *resp.token;
            h.server_id = *resp.id;

            // Store a STALE record (no relays) for our key.
            Request ann;
            ann.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
            ann.command = CMD_ANNOUNCE;
            ann.target = h.target;
            ann.token = h.token;
            ann.value = signed_announce(kp, h.target, h.server_id, h.token);

            client.request(ann,
                [&](const Response&) {
                    stale_stored = (handlers.store().get(key).size() == 1);
                    ASSERT_TRUE(stale_stored);

                    // announce(clear): removes the stale record, then announces
                    // the NEW record (distinctive relay). The commit now signs a
                    // fresh record PER node over that node's LOOKUP token+id, so
                    // we just hand it the keypair + relay list.
                    dht_ops::announce(
                        client, h.target, kp, {new_relay}, /*bump=*/0,
                        [&](int /*error*/, const std::vector<query::QueryReply>&) {
                            clear_done = true;
                            auto recs = handlers.store().get(key);
                            if (recs.size() == 1) {
                                auto pr = dht_messages::decode_peer_record(
                                    recs[0].value.data(), recs[0].value.size());
                                final_is_new =
                                    pr.relay_addresses.size() == 1 &&
                                    pr.relay_addresses[0].port == new_relay.port;
                            }
                            h.cleanup();
                        },
                        /*clear_keypair=*/&kp);
                },
                [&](uint16_t) { h.cleanup(); });
        },
        [&](uint16_t) { h.cleanup(); });

    uv_run(&h.loop, UV_RUN_DEFAULT);
    uv_loop_close(&h.loop);

    EXPECT_TRUE(stale_stored) << "stale record should be stored first";
    EXPECT_TRUE(clear_done) << "announce(clear) should complete";
    EXPECT_TRUE(final_is_new)
        << "after clear+announce the store should hold exactly the NEW record";
}
