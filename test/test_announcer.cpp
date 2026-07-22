// Announcer unit tests — verify record building, relay tracking, and lifecycle.
// These test the non-network parts. Live network test comes in Step 7 (Server).

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/announcer.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"

using namespace hyperdht;
using namespace hyperdht::announcer;

TEST(Announcer, RecordEncodesPubkey) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);

    Announcer ann(socket, kp, target);

    // Record should contain our public key
    EXPECT_FALSE(ann.record().empty());

    auto peer = dht_messages::decode_peer_record(
        ann.record().data(), ann.record().size());
    EXPECT_EQ(peer.public_key, kp.public_key);
    EXPECT_TRUE(peer.relay_addresses.empty());  // No relays yet

    // No relays before start
    EXPECT_TRUE(ann.relays().empty());

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Announcer, StartStop) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);

    Announcer ann(socket, kp, target);

    EXPECT_FALSE(ann.is_running());
    ann.start();
    EXPECT_TRUE(ann.is_running());

    bool stopped = false;
    ann.stop([&] { stopped = true; });
    EXPECT_TRUE(stopped);
    EXPECT_FALSE(ann.is_running());

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Announcer, DoubleStartNoop) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    target.fill(0x33);

    Announcer ann(socket, kp, target);
    ann.start();
    ann.start();  // Should not crash or double-init
    EXPECT_TRUE(ann.is_running());

    ann.stop();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ============================================================================
// announce-4 — the SIGNED/stored announce record always carries
// relayAddresses: [] (JS announcer.js:241-247). Relay discovery happens via
// the responding DHT node (connect.js:359) + the handshake payload
// (server.js:349-368), never via the record. Regression: a second announce
// cycle (relays_ populated) must NOT embed relay addresses in the record.
// ============================================================================
TEST(Announcer, SignedAnnounceHasEmptyRelayAddresses) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // DHT node: persistent socket + router + handlers (stores announces).
    routing::NodeId sid{};
    sid.fill(0x11);
    rpc::RpcSocket server(&loop, sid);
    server.bind(0);
    {
        auto our_addr = compact::Ipv4Address::from_string("127.0.0.1", server.port());
        for (int i = 1; i <= 3; i++) {
            auto from = compact::Ipv4Address::from_string(
                "10.0.0." + std::to_string(i), 49737);
            server.nat_sampler().add(our_addr, from);
            server.ring_sampler().add(our_addr.host_string(), our_addr.port);
        }
        server.force_check_persistent();
    }
    router::Router router;
    rpc::RpcHandlers handlers(server, &router);
    handlers.install();

    // Announcing client, routing table seeded with the DHT node.
    routing::NodeId cid{};
    cid.fill(0x22);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);
    {
        auto server_addr = compact::Ipv4Address::from_string("127.0.0.1", server.port());
        routing::Node node;
        node.id = rpc::compute_peer_id(server_addr);
        node.host = "127.0.0.1";
        node.port = server.port();
        node.added = client.tick();
        node.pinged = client.tick();
        node.seen = client.tick();
        client.table().add(node);
    }

    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);
    announce::TargetKey key{};
    std::copy(target.begin(), target.end(), key.begin());

    Announcer ann(client, kp, target);
    ann.start();

    struct Ctx {
        Announcer* ann;
        router::Router* router;
        rpc::RpcSocket* server;
        rpc::RpcSocket* client;
        announce::TargetKey key;
        int phase = 0;       // 0: wait record, 1: wait relays, 2: settle
        int settle = 0;
        bool stored = false;
        bool relays_empty = false;
        bool done = false;
        uv_timer_t poll{};
        uv_timer_t guard{};
        void cleanup() {
            if (done) return;
            done = true;
            ann->stop_without_unannounce();
            server->close();
            client->close();
            uv_close(reinterpret_cast<uv_handle_t*>(&poll), nullptr);
            uv_close(reinterpret_cast<uv_handle_t*>(&guard), nullptr);
        }
    } ctx{&ann, &router, &server, &client, key};

    uv_timer_init(&loop, &ctx.poll);
    ctx.poll.data = &ctx;
    uv_timer_start(&ctx.poll, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        if (c->done) return;
        if (c->phase == 0) {
            // First cycle: the record is stored on the DHT node. (In this
            // 1-node loopback build_relays() can race the ANNOUNCE
            // response, so relays() may still be empty — refresh until a
            // cycle builds them.)
            if (c->router->record(c->key) != nullptr) {
                c->phase = 1;
                c->ann->refresh();
            }
            return;
        }
        if (c->phase == 1) {
            // A cycle has built the relay list → run one more cycle, now
            // with relays_ populated (the pre-fix regression path embedded
            // them in the signed record here).
            if (!c->ann->relays().empty()) {
                c->phase = 2;
                c->ann->refresh();
            } else {
                c->ann->refresh();
            }
            return;
        }
        // Give the final cycle a few ticks to land, then assert on the
        // record the DHT node now serves.
        if (++c->settle < 6) return;
        const auto* rec = c->router->record(c->key);
        c->stored = rec != nullptr;
        if (rec) {
            auto peer = dht_messages::decode_peer_record(rec->data(), rec->size());
            c->relays_empty = peer.relay_addresses.empty();
        }
        c->cleanup();
    }, 50, 50);

    uv_timer_init(&loop, &ctx.guard);
    ctx.guard.data = &ctx;
    uv_timer_start(&ctx.guard, [](uv_timer_t* t) {
        static_cast<Ctx*>(t->data)->cleanup();
    }, 5000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    EXPECT_TRUE(ctx.stored) << "announce record must be stored on the DHT node";
    EXPECT_TRUE(ctx.relays_empty)
        << "signed announce record must carry relayAddresses: [] "
           "(JS announcer.js:241-247)";
}
