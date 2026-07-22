// Announcer unit tests — verify record building, relay tracking, and lifecycle.
// These test the non-network parts. Live network test comes in Step 7 (Server).

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include <optional>

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

// ============================================================================
// Fake DHT node for the settle / drift / seed tests below.
//
// A raw RpcSocket with a scripted on_request handler. Replies are encoded
// manually and sent via udp_send so the wire `to` field (Response::from —
// "our address as the responder sees us") can LIE, which RpcSocket::reply
// cannot do (it uses resp.from.addr as the UDP destination). Response
// matching on the requester is by tid only, so egress socket is irrelevant;
// set_firewalled(false) makes udp_send egress the bound port so the reply's
// `id` passes the requester's validateId (compute_peer_id of UDP source).
// ============================================================================
namespace {

struct FakeNode {
    rpc::RpcSocket sock;
    compact::Ipv4Address addr;
    routing::NodeId id;

    int find_peer_count = 0;
    int announce_count = 0;
    int ping_count = 0;

    // Behavior knobs
    std::optional<compact::Ipv4Address> announce_observed;  // lie in ANNOUNCE `to`
    std::optional<compact::Ipv4Address> ping_observed;      // lie in PING pong `to`
    std::vector<compact::Ipv4Address> closer;               // FIND_PEER closerNodes

    FakeNode(uv_loop_t* loop, uint8_t id_fill)
        : sock(loop, make_node_id(id_fill)) {
        sock.bind(0);
        sock.set_firewalled(false);  // udp_send egresses the bound port
        addr = compact::Ipv4Address::from_string("127.0.0.1", sock.port());
        id = rpc::compute_peer_id(addr);
        sock.on_request([this](const messages::Request& req) { handle(req); });
    }

    static routing::NodeId make_node_id(uint8_t fill) {
        routing::NodeId nid{};
        nid.fill(fill);
        return nid;
    }

    void handle(const messages::Request& req) {
        messages::Response resp;
        resp.tid = req.tid;
        resp.from.addr = req.from.addr;  // truthful wire `to` by default
        resp.id = id;

        if (req.internal && req.command == messages::CMD_PING) {
            ping_count++;
            if (ping_observed) resp.from.addr = *ping_observed;
        } else if (!req.internal && req.command == messages::CMD_FIND_PEER) {
            find_peer_count++;
            // Real token from our store so the follow-up ANNOUNCE passes
            // the receive path's central token validation.
            resp.token = sock.token_store().create(req.from.addr.host_string());
            resp.closer_nodes = closer;
        } else if (!req.internal && req.command == messages::CMD_ANNOUNCE) {
            announce_count++;
            if (announce_observed) resp.from.addr = *announce_observed;
        }

        sock.udp_send(messages::encode_response(resp), req.from.addr);
    }
};

// Seed `client`'s routing table with a fake node.
void seed_table(rpc::RpcSocket& client, const FakeNode& fake) {
    routing::Node node;
    node.id = fake.id;
    node.host = fake.addr.host_string();
    node.port = fake.addr.port;
    node.added = client.tick();
    node.pinged = client.tick();
    node.seen = client.tick();
    client.table().add(node);
}

noise::Keypair make_keypair(uint8_t fill) {
    noise::Seed seed{};
    seed.fill(fill);
    return noise::generate_keypair(seed);
}

std::array<uint8_t, 32> make_target(const noise::Keypair& kp) {
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);
    return target;
}

}  // namespace

// ============================================================================
// D1 (publish-after-settle) — relays_ must be published from THIS cycle's
// ANNOUNCE responses, within the FIRST update cycle. The old ordering ran
// build_relays() in the find_peer completion callback, which on any network
// (incl. loopback) fires before the ANNOUNCE responses land — so relays()
// stayed empty until a LATER cycle republished the previous cycle's late
// responses (one-cycle-stale relays; field "Finding A"). JS orders it as
// `await q.finished()` → `await Promise.allSettled(ann)` → publish
// (announcer.js:154-189).
// ============================================================================
TEST(Announcer, PublishesRelaysAfterCommitsSettle) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    FakeNode fake(&loop, 0x11);
    // Distinctive observed address in the ANNOUNCE response: proves the
    // published peer_addr came from THIS cycle's commit responses.
    auto distinctive = compact::Ipv4Address::from_string("9.9.9.9", 4242);
    fake.announce_observed = distinctive;
    fake.ping_observed = distinctive;  // keep keepalive drift-free

    routing::NodeId cid{};
    cid.fill(0x22);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);
    seed_table(client, fake);

    auto kp = make_keypair(0x42);
    auto target = make_target(kp);

    Announcer ann(client, kp, target);

    struct Ctx {
        Announcer* ann;
        FakeNode* fake;
        rpc::RpcSocket* client;
        size_t relay_count = 0;
        compact::Ipv4Address peer_addr{};
        int find_peer_at_publish = -1;
        bool done = false;
        uv_timer_t poll{};
        uv_timer_t guard{};
        void cleanup() {
            if (done) return;
            done = true;
            ann->stop_without_unannounce();
            fake->sock.close();
            client->close();
            uv_close(reinterpret_cast<uv_handle_t*>(&poll), nullptr);
            uv_close(reinterpret_cast<uv_handle_t*>(&guard), nullptr);
        }
    } ctx{&ann, &fake, &client};

    ann.start();

    uv_timer_init(&loop, &ctx.poll);
    ctx.poll.data = &ctx;
    uv_timer_start(&ctx.poll, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        if (c->done) return;
        if (!c->ann->relays().empty()) {
            c->relay_count = c->ann->relays().size();
            c->peer_addr = c->ann->relays()[0].peer_address;
            c->find_peer_at_publish = c->fake->find_peer_count;
            c->cleanup();
        }
    }, 20, 20);

    uv_timer_init(&loop, &ctx.guard);
    ctx.guard.data = &ctx;
    uv_timer_start(&ctx.guard, [](uv_timer_t* t) {
        static_cast<Ctx*>(t->data)->cleanup();
    }, 4000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    EXPECT_EQ(ctx.relay_count, 1u)
        << "relays() must be published within the FIRST update cycle "
           "(publish-after-settle, JS announcer.js:184-189)";
    EXPECT_EQ(ctx.find_peer_at_publish, 1)
        << "publish must not require a second find_peer cycle";
    EXPECT_EQ(ctx.peer_addr, distinctive)
        << "published peer_addr must carry THIS cycle's ANNOUNCE observation";
}

// ============================================================================
// D-C (drift detection, BEYOND-JS) — a keepalive pong whose `to` field
// differs from the relay's announce-time peer_addr proves the relay's
// stored forward state is stale; the announcer must refresh() (re-run the
// find_peer+announce cycle). A second drifted pong inside the 10s rate
// limit must NOT re-trigger. JS discards the pong body (announcer.js:114-121).
// ============================================================================
TEST(Announcer, DriftedPongTriggersRateLimitedRefresh) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    FakeNode fake(&loop, 0x11);
    // Truthful ANNOUNCE observation; the PING pong lies about our address.
    fake.ping_observed = compact::Ipv4Address::from_string("127.0.0.1", 9999);

    routing::NodeId cid{};
    cid.fill(0x22);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);
    seed_table(client, fake);

    auto kp = make_keypair(0x42);
    auto target = make_target(kp);

    Announcer ann(client, kp, target);

    struct Ctx {
        Announcer* ann;
        FakeNode* fake;
        rpc::RpcSocket* client;
        // 0: wait cycle 1 settle → ping (drifted)
        // 1: wait drift refresh (cycle 2) + settle → ping again (in window)
        // 2: give a potential (wrong) 3rd cycle time to start, then assert
        int phase = 0;
        int settle = 0;
        int find_peer_after_drift = 0;
        int find_peer_final = 0;
        bool done = false;
        uv_timer_t poll{};
        uv_timer_t guard{};
        void cleanup() {
            if (done) return;
            done = true;
            ann->stop_without_unannounce();
            fake->sock.close();
            client->close();
            uv_close(reinterpret_cast<uv_handle_t*>(&poll), nullptr);
            uv_close(reinterpret_cast<uv_handle_t*>(&guard), nullptr);
        }
    } ctx{&ann, &fake, &client};

    ann.start();

    uv_timer_init(&loop, &ctx.poll);
    ctx.poll.data = &ctx;
    uv_timer_start(&ctx.poll, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        if (c->done) return;
        switch (c->phase) {
            case 0:
                // Cycle 1 settled (publish-after-settle ⇒ relays() set only
                // once the ANNOUNCE resolved and updating_ dropped).
                if (!c->ann->relays().empty()) {
                    c->phase = 1;
                    c->ann->ping_relays_for_test();  // drifted pong #1
                }
                break;
            case 1:
                // Drift must re-run the full cycle: second find_peer walk +
                // second ANNOUNCE. Wait a few extra ticks so cycle 2 fully
                // settles (updating_ false) — the second pong below must be
                // stopped by the RATE LIMIT, not by the updating_ guard.
                if (c->fake->find_peer_count >= 2 &&
                    c->fake->announce_count >= 2 && ++c->settle >= 5) {
                    c->find_peer_after_drift = c->fake->find_peer_count;
                    c->phase = 2;
                    c->settle = 0;
                    c->ann->ping_relays_for_test();  // drifted pong #2 (<10s)
                }
                break;
            case 2:
                if (++c->settle >= 8) {
                    c->find_peer_final = c->fake->find_peer_count;
                    c->cleanup();
                }
                break;
        }
    }, 20, 20);

    uv_timer_init(&loop, &ctx.guard);
    ctx.guard.data = &ctx;
    uv_timer_start(&ctx.guard, [](uv_timer_t* t) {
        static_cast<Ctx*>(t->data)->cleanup();
    }, 8000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    EXPECT_EQ(ctx.find_peer_after_drift, 2)
        << "drifted pong must trigger exactly one refresh cycle";
    EXPECT_EQ(ctx.find_peer_final, 2)
        << "second drifted pong within 10s must be rate-limited (no 3rd cycle)";
    EXPECT_GE(fake.ping_count, 2);
}

// ============================================================================
// D-B (closestNodes reuse) — the reannounce cycle must seed its find_peer
// walk with the previous cycle's closest nodes (JS announcer.js:156
// `nodes: this._closestNodes`, :187 save) so it re-hits the SAME relays.
// Discriminator: node B is discovered in cycle 1 only via A's closerNodes,
// then A stops referring it and B is removed from the routing table — in
// cycle 2 B is reachable ONLY through the saved-seed path.
// ============================================================================
TEST(Announcer, ReannounceSeedsPreviousClosestNodes) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    FakeNode a(&loop, 0x11);
    FakeNode b(&loop, 0x33);
    a.closer = {b.addr};  // cycle 1: A refers B

    routing::NodeId cid{};
    cid.fill(0x22);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);
    seed_table(client, a);  // table: A only

    auto kp = make_keypair(0x42);
    auto target = make_target(kp);

    Announcer ann(client, kp, target);

    struct Ctx {
        Announcer* ann;
        FakeNode* a;
        FakeNode* b;
        rpc::RpcSocket* client;
        int phase = 0;  // 0: wait cycle 1 settle; 1: wait cycle 2; 2: assert
        int settle = 0;
        int b_count_cycle1 = 0;
        int b_count_final = 0;
        bool done = false;
        uv_timer_t poll{};
        uv_timer_t guard{};
        void cleanup() {
            if (done) return;
            done = true;
            ann->stop_without_unannounce();
            a->sock.close();
            b->sock.close();
            client->close();
            uv_close(reinterpret_cast<uv_handle_t*>(&poll), nullptr);
            uv_close(reinterpret_cast<uv_handle_t*>(&guard), nullptr);
        }
    } ctx{&ann, &a, &b, &client};

    ann.start();

    uv_timer_init(&loop, &ctx.poll);
    ctx.poll.data = &ctx;
    uv_timer_start(&ctx.poll, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        if (c->done) return;
        switch (c->phase) {
            case 0:
                // Cycle 1 settled: relays published, B visited + committed.
                if (!c->ann->relays().empty() && c->b->find_peer_count >= 1 &&
                    c->b->announce_count >= 1) {
                    c->b_count_cycle1 = c->b->find_peer_count;
                    // Cut every path to B except the seeded frontier:
                    c->a->closer.clear();               // A stops referring B
                    c->client->table().remove(c->b->id);  // B out of the table
                    c->phase = 1;
                    c->ann->refresh();
                }
                break;
            case 1:
                // Cycle 2 reached A; give B's (seeded) visit time to land.
                if (c->a->find_peer_count >= 2 && ++c->settle >= 5) {
                    c->b_count_final = c->b->find_peer_count;
                    c->cleanup();
                }
                break;
        }
    }, 20, 20);

    uv_timer_init(&loop, &ctx.guard);
    ctx.guard.data = &ctx;
    uv_timer_start(&ctx.guard, [](uv_timer_t* t) {
        static_cast<Ctx*>(t->data)->cleanup();
    }, 8000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    EXPECT_GE(ctx.b_count_cycle1, 1)
        << "cycle 1 must reach B via A's closerNodes";
    EXPECT_EQ(ctx.b_count_final, ctx.b_count_cycle1 + 1)
        << "cycle 2 must query B via the saved closest-nodes seed "
           "(JS announcer.js:156/187) — without seeding B is unreachable";
}
