// Announcer relay-set tests — the published set and the token gate.
//
// Two structures, deliberately different sets:
//   relays()  — what we advertise RIGHT NOW, rebuilt every announce cycle
//               (JS `this.relays`, announcer.js:172/188).
//   is_relay() — whether a node may still be relaying a client's holepunch,
//               i.e. whether it might still hold a record we published
//               (JS `isRelay` over three rotating _serverRelays generations,
//               announcer.js:35/38-42/270-276).
//
// Keeping these in one vector is what froze the published set for the life of
// the process: the commit path could only refresh an entry it already had, or
// append while under PICK_BEST, so a dead relay was advertised forever and a
// healthier node could never take its place.
//
// Split from test_announcer.cpp, which is already at the file-size guideline.

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "hyperdht/announcer.hpp"
#include "hyperdht/compact.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/routing_table.hpp"
#include "hyperdht/rpc.hpp"

using namespace hyperdht;
using announcer::Announcer;

namespace {

// Run the loop until `done()` or `max_ms` elapsed. Returns done()'s result.
bool run_until(uv_loop_t* loop, const std::function<bool()>& done,
               uint64_t max_ms) {
    uv_update_time(loop);
    uint64_t start = uv_now(loop);
    while (!done()) {
        uv_run(loop, UV_RUN_NOWAIT);
        uv_update_time(loop);
        if (uv_now(loop) - start >= max_ms) return done();
    }
    return true;
}

// A scripted DHT node. Same shape as test_announcer.cpp's FakeNode, plus the
// `reply_error` knob: an error reply is counted against the query's error
// budget and never reaches push_closest (query.cpp:377,403), so flipping it
// drops the node out of pickBest on the NEXT cycle — a deterministic way to
// change the committed set without waiting out RPC retries.
struct FakeNode {
    rpc::RpcSocket sock;
    compact::Ipv4Address addr;
    routing::NodeId id;

    int find_peer_count = 0;
    int announce_count = 0;
    int ping_count = 0;

    bool reply_error = false;   // fail FIND_PEER → node leaves the closest set
    bool silent_ping = false;   // never pong → looks dead to the health check

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
        resp.from.addr = req.from.addr;
        resp.id = id;

        if (req.internal && req.command == messages::CMD_PING) {
            ping_count++;
            if (silent_ping) return;
        } else if (!req.internal && req.command == messages::CMD_FIND_PEER) {
            find_peer_count++;
            if (reply_error) {
                resp.error = 1;
            } else {
                resp.token =
                    sock.token_store().create(req.from.addr.host_string());
            }
        } else if (!req.internal && req.command == messages::CMD_ANNOUNCE) {
            announce_count++;
        }

        sock.udp_send(messages::encode_response(resp), req.from.addr);
    }
};

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

// Loop + fake DHT + announcer, torn down in the right order no matter how the
// test exits. Needed because a failing ASSERT_* returns from the test body
// immediately: with hand-written teardown at the bottom, the first failure
// leaves the loop full of live handles and uv_loop_close() wedges the binary.
struct Fixture {
    uv_loop_t loop{};
    std::vector<std::unique_ptr<FakeNode>> nodes;
    std::unique_ptr<rpc::RpcSocket> client;
    noise::Keypair kp;
    std::unique_ptr<Announcer> ann;

    explicit Fixture(int node_count) {
        uv_loop_init(&loop);
        for (int i = 0; i < node_count; ++i) {
            nodes.push_back(std::make_unique<FakeNode>(
                &loop, static_cast<uint8_t>(0x11 + i)));
        }
        routing::NodeId cid{};
        cid.fill(0x22);
        client = std::make_unique<rpc::RpcSocket>(&loop, cid);
        client->bind(0);
        for (auto& n : nodes) seed_table(*client, *n);
        kp = make_keypair(0x42);
        ann = std::make_unique<Announcer>(*client, kp, make_target(kp));
    }

    ~Fixture() {
        if (ann) ann->stop_without_unannounce();
        for (auto& n : nodes) n->sock.close();
        if (client) client->close();
        uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop);
    }

    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    // A cycle is over when it is no longer updating and the generation counter
    // has reached `gen`. `!relays().empty()` stops discriminating after the
    // first cycle publishes.
    bool settled_at(uint64_t gen, uint64_t max_ms = 5000) {
        return run_until(&loop,
                         [this, gen] {
                             return !ann->is_updating_for_test() &&
                                    ann->cycle_gen_for_test() >= gen;
                         },
                         max_ms);
    }

    // Addresses currently advertised on the wire.
    std::vector<compact::Ipv4Address> published() const {
        std::vector<compact::Ipv4Address> out;
        for (const auto& ri : ann->relays()) out.push_back(ri.relay_address);
        return out;
    }

    // Drop these nodes out of the walk: an errored FIND_PEER never reaches
    // push_closest (query.cpp:377,403), so they leave pickBest next cycle.
    void fail_walk_for(const std::vector<compact::Ipv4Address>& addrs) {
        for (auto& n : nodes) {
            for (const auto& a : addrs) {
                if (n->addr == a) n->reply_error = true;
            }
        }
    }
};

bool contains_addr(const std::vector<peer_connect::RelayInfo>& relays,
                   const compact::Ipv4Address& addr) {
    for (const auto& ri : relays) {
        if (ri.relay_address == addr) return true;
    }
    return false;
}

}  // namespace

// ============================================================================
// The published set must follow this cycle's commits.
//
// It used to be write-once: the commit path could refresh an entry it already
// had, or append while under PICK_BEST, so once three slots were taken the set
// was pinned for the life of the process. A relay that died — or that was
// never reachable from third parties, e.g. behind a symmetric NAT — was
// advertised to every client forever, and no healthier node could replace it.
// Restarting the server was the only cure, which is exactly what the field
// kept observing. JS assigns a freshly built list every cycle
// (announcer.js:172,188).
// ============================================================================
TEST(AnnouncerRelays, PublishedListFollowsCommitSetAcrossCycles) {
    Fixture f(6);

    f.ann->start();
    ASSERT_TRUE(f.settled_at(1));

    const auto gen1 = f.published();
    ASSERT_EQ(gen1.size(), announcer::PICK_BEST);

    f.fail_walk_for(gen1);
    f.ann->refresh();
    ASSERT_TRUE(f.settled_at(2));

    ASSERT_EQ(f.ann->relays().size(), announcer::PICK_BEST)
        << "cycle 2 must publish a full set from the surviving nodes";
    for (const auto& old : gen1) {
        EXPECT_FALSE(contains_addr(f.ann->relays(), old))
            << "a node that dropped out of the walk is still being advertised "
               "— the published set is frozen";
    }
}

// ============================================================================
// THE REGRESSION GUARD for the rebuild above.
//
// Rebuilding the published set is only safe because the token gate is wider
// than it: a client that fetched our record during generation 1 is still
// relaying its holepunch through a generation-1 node, and must still be given
// a token. Point the gate at the published list instead — the obvious "fix" —
// and every rebuild test in this file still passes while this one fails,
// because the rebuild would then have made the gate one generation deep where
// JS unions three (announcer.js:38-42). Verified: with the gate lookup
// disabled, the four rebuild tests stay green and only this and the gate-TTL
// test go red.
// ============================================================================
TEST(AnnouncerRelays, IsRelayStillAcceptsPreviousGenerationAddress) {
    Fixture f(6);

    f.ann->start();
    ASSERT_TRUE(f.settled_at(1));

    const auto gen1 = f.published();
    ASSERT_FALSE(gen1.empty()) << "cycle 1 published nothing";

    f.fail_walk_for(gen1);
    f.ann->refresh();
    ASSERT_TRUE(f.settled_at(2));

    // Generation 1 is off the wire …
    for (const auto& old : gen1) {
        ASSERT_FALSE(contains_addr(f.ann->relays(), old))
            << "precondition: cycle 2 must have replaced the published set";
    }

    // … but a client that fetched our record during generation 1 is still
    // relaying through those nodes, and must still be served a token.
    for (const auto& old : gen1) {
        EXPECT_TRUE(f.ann->is_relay(old))
            << "a previous-generation relay was refused: any client holding a "
               "record from that cycle now fails its holepunch round 1";
    }

    // The gate can never be narrower than what we advertise.
    for (const auto& ri : f.ann->relays()) {
        EXPECT_TRUE(f.ann->is_relay(ri.relay_address))
            << "is_relay rejected a relay we are advertising";
    }

    // An address that never acked anything is still refused.
    EXPECT_FALSE(f.ann->is_relay(
        compact::Ipv4Address::from_string("203.0.113.7", 5555)));
}

// ============================================================================
// A cycle that commits to nobody must NOT publish an empty list.
//
// Deliberate divergence from JS, which assigns `this.relays = relays` freely
// even when the walk found nothing (announcer.js:188). JS survives that; we do
// not. An empty relay list makes the handshake reply carry no holepunch info,
// which sends the client down its "no holepunch info -> direct connect" path
// straight at a NAT'd address, and it makes ping_relays() return early so the
// keepalive, drift detection and health checks all stop. Keeping the previous
// set means we advertise possibly-stale relays during an outage, which is
// strictly better than advertising none — and the client has relay failover.
// ============================================================================
TEST(AnnouncerRelays, AllFailCycleKeepsPublishedList) {
    Fixture f(4);

    f.ann->start();
    ASSERT_TRUE(f.settled_at(1));

    const auto gen1 = f.published();
    ASSERT_FALSE(gen1.empty());

    // Total DHT outage: nobody answers the walk.
    for (auto& n : f.nodes) n->reply_error = true;

    f.ann->refresh();
    ASSERT_TRUE(f.settled_at(2));

    EXPECT_EQ(f.ann->relays().size(), gen1.size())
        << "an all-fail cycle must retain the previous published set";
    for (const auto& old : gen1) {
        EXPECT_TRUE(contains_addr(f.ann->relays(), old));
        EXPECT_TRUE(f.ann->is_relay(old));
    }
}

// ============================================================================
// A relay that leaves the walk must leave the published set — which is what
// stops the relay-health check from re-walking forever.
//
// ping_relays() refreshes when fewer than min(total, MIN_ACTIVE) relays pong.
// With the set frozen at three, a single dead relay pinned `total` at 3 and
// made that condition true on every 5s tick for the rest of the process: a
// permanent re-walk. Once the set rebuilds, the corpse drops out, `total`
// becomes 2, and 2 of 2 responding satisfies min(2, 3). Same arithmetic as JS
// (announcer.js:119-121); no separate eviction rule needed.
// ============================================================================
TEST(AnnouncerRelays, DeadRelayLeavesPublishedSetAndStopsRefreshStorm) {
    Fixture f(3);

    f.ann->start();
    ASSERT_TRUE(f.settled_at(1));
    ASSERT_EQ(f.ann->relays().size(), 3u);

    // One relay dies completely: no pong, and gone from the walk.
    const auto corpse = f.nodes[0]->addr;
    f.nodes[0]->silent_ping = true;
    f.nodes[0]->reply_error = true;

    f.ann->refresh();
    ASSERT_TRUE(f.settled_at(2));

    EXPECT_FALSE(contains_addr(f.ann->relays(), corpse))
        << "a dead relay must not be advertised after the next cycle";
    ASSERT_EQ(f.ann->relays().size(), 2u);

    // With the corpse gone the health check is satisfied by the survivors and
    // must stop triggering walks.
    const uint64_t gen_before = f.ann->cycle_gen_for_test();
    for (int i = 0; i < 3; ++i) {
        f.ann->ping_relays_for_test();
        run_until(&f.loop, [] { return false; }, 60);
    }
    EXPECT_EQ(f.ann->cycle_gen_for_test(), gen_before)
        << "relay health kept re-walking: min(total, MIN_ACTIVE) is still "
           "counting a relay that no longer exists";
}

// ============================================================================
// The gate is bounded in time: a node that stopped holding our record long ago
// must fall out. JS bounds it by rotation (three cycles); we bound it by wall
// clock so a refresh storm cannot collapse the window.
// ============================================================================
TEST(AnnouncerRelays, IsRelayExpiresAfterWindow) {
    Fixture f(1);
    f.ann->set_gate_ttl_ms_for_test(40);

    f.ann->start();
    ASSERT_TRUE(f.settled_at(1));
    ASSERT_GT(f.nodes[0]->announce_count, 0) << "node never acked";
    const auto addr = f.nodes[0]->addr;

    // Still advertised, so part (a) of is_relay answers regardless of age.
    EXPECT_TRUE(f.ann->is_relay(addr));

    // Stop advertising it, then let the window lapse.
    f.ann->stop_without_unannounce();
    EXPECT_TRUE(f.ann->relays().empty());
    EXPECT_TRUE(f.ann->is_relay(addr))
        << "gate must outlive the published list — that is its whole purpose";

    const uint64_t deadline = uv_now(&f.loop) + 200;
    run_until(&f.loop, [&] { return uv_now(&f.loop) > deadline; }, 1000);

    EXPECT_FALSE(f.ann->is_relay(addr))
        << "gate entry must expire once the record it served is long gone";
}

// ============================================================================
// stop() invalidates the async sentinel; start() must re-arm it. Server
// suspend/resume stop and start the SAME announcer, so without the re-arm a
// resumed server never re-announces: every callback returns early, the cycle
// never settles, and only the stuck-cycle watchdog keeps firing.
// ============================================================================
TEST(AnnouncerRelays, RestartReannouncesAfterStop) {
    Fixture f(1);

    f.ann->start();
    ASSERT_TRUE(f.settled_at(1));
    ASSERT_FALSE(f.ann->relays().empty()) << "first run never published";
    const int find_peers_first = f.nodes[0]->find_peer_count;
    const uint64_t gen_after_first = f.ann->cycle_gen_for_test();

    f.ann->stop_without_unannounce();
    EXPECT_TRUE(f.ann->relays().empty());

    f.ann->start();
    ASSERT_TRUE(f.settled_at(gen_after_first + 1))
        << "restarted announcer never completed a cycle";

    EXPECT_GT(f.nodes[0]->find_peer_count, find_peers_first)
        << "restarted announcer must walk again";
    EXPECT_FALSE(f.ann->relays().empty())
        << "restarted announcer must republish — a resumed server that never "
           "re-announces is unreachable until the process restarts";
}
