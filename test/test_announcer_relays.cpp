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

// A cycle is over when it is no longer updating and the generation counter has
// reached `gen`. `!relays().empty()` stops discriminating after cycle 1.
std::function<bool()> settled_at(const Announcer& ann, uint64_t gen) {
    return [&ann, gen] {
        return !ann.is_updating_for_test() && ann.cycle_gen_for_test() >= gen;
    };
}

bool contains_addr(const std::vector<peer_connect::RelayInfo>& relays,
                   const compact::Ipv4Address& addr) {
    for (const auto& ri : relays) {
        if (ri.relay_address == addr) return true;
    }
    return false;
}

}  // namespace

// ============================================================================
// The token gate must accept a node that acked our ANNOUNCE even when it is
// absent from the published list.
//
// This is the leniency JS gets from unioning three _serverRelays generations
// (announcer.js:38-42). Without it a client relaying through a record holder
// from an earlier cycle is refused a holepunch token, and its round 1 comes
// back tokenless — the exact failure the server.cpp gate comment warns about.
// ============================================================================
TEST(AnnouncerRelays, IsRelayAcceptsAckedNodeMissingFromPublishedList) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Group A answers first; group B takes over once A starts erroring.
    std::vector<std::unique_ptr<FakeNode>> nodes;
    for (uint8_t i = 0; i < 6; ++i) {
        nodes.push_back(
            std::make_unique<FakeNode>(&loop, static_cast<uint8_t>(0x11 + i)));
    }

    routing::NodeId cid{};
    cid.fill(0x22);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);
    for (auto& n : nodes) seed_table(client, *n);

    auto kp = make_keypair(0x42);
    auto target = make_target(kp);
    Announcer ann(client, kp, target);

    ann.start();
    ASSERT_TRUE(run_until(&loop, settled_at(ann, 1), 5000))
        << "first announce cycle never settled";

    // Whoever got the record in cycle 1 is what we advertise now.
    std::vector<compact::Ipv4Address> published;
    for (const auto& ri : ann.relays()) published.push_back(ri.relay_address);
    ASSERT_FALSE(published.empty()) << "cycle 1 published nothing";

    // Knock the published set out of the walk; the remaining nodes must take
    // over the commits in cycle 2.
    for (auto& n : nodes) {
        for (const auto& p : published) {
            if (n->addr == p) n->reply_error = true;
        }
    }

    const int announces_before = [&] {
        int t = 0;
        for (auto& n : nodes) t += n->announce_count;
        return t;
    }();

    ann.refresh();
    ASSERT_TRUE(run_until(&loop, settled_at(ann, 2), 5000))
        << "second announce cycle never settled";

    // Someone new acked in cycle 2 …
    std::vector<compact::Ipv4Address> newly_acked;
    for (auto& n : nodes) {
        if (n->reply_error) continue;
        if (n->announce_count > 0) newly_acked.push_back(n->addr);
    }
    int announces_after = 0;
    for (auto& n : nodes) announces_after += n->announce_count;
    ASSERT_GT(announces_after, announces_before)
        << "cycle 2 committed to nobody — the flip did not take";
    ASSERT_FALSE(newly_acked.empty());

    // … and the gate must accept them, whether or not they made the wire list.
    for (const auto& a : newly_acked) {
        EXPECT_TRUE(ann.is_relay(a))
            << "a node that acked our ANNOUNCE is a legitimate relay for any "
               "client holding the record it just stored";
    }

    // Property: the gate can never be narrower than what we advertise.
    for (const auto& ri : ann.relays()) {
        EXPECT_TRUE(ann.is_relay(ri.relay_address))
            << "is_relay rejected a relay we are advertising";
    }

    // An address that never acked anything is still refused.
    EXPECT_FALSE(
        ann.is_relay(compact::Ipv4Address::from_string("203.0.113.7", 5555)));

    ann.stop_without_unannounce();
    for (auto& n : nodes) n->sock.close();
    client.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ============================================================================
// The gate is bounded in time: a node that stopped holding our record long ago
// must fall out. JS bounds it by rotation (three cycles); we bound it by wall
// clock so a refresh storm cannot collapse the window.
// ============================================================================
TEST(AnnouncerRelays, IsRelayExpiresAfterWindow) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    FakeNode node(&loop, 0x11);

    routing::NodeId cid{};
    cid.fill(0x22);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);
    seed_table(client, node);

    auto kp = make_keypair(0x42);
    auto target = make_target(kp);
    Announcer ann(client, kp, target);
    ann.set_gate_ttl_ms_for_test(40);

    ann.start();
    ASSERT_TRUE(run_until(&loop, settled_at(ann, 1), 5000));
    ASSERT_GT(node.announce_count, 0) << "node never acked";

    // Still advertised, so part (a) of is_relay answers regardless of age.
    EXPECT_TRUE(ann.is_relay(node.addr));

    // Stop advertising it, then let the window lapse.
    ann.stop_without_unannounce();
    EXPECT_TRUE(ann.relays().empty());
    EXPECT_TRUE(ann.is_relay(node.addr))
        << "gate must outlive the published list — that is its whole purpose";

    const uint64_t deadline = uv_now(&loop) + 200;
    run_until(&loop, [&] { return uv_now(&loop) > deadline; }, 1000);

    EXPECT_FALSE(ann.is_relay(node.addr))
        << "gate entry must expire once the record it served is long gone";

    node.sock.close();
    client.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ============================================================================
// stop() invalidates the async sentinel; start() must re-arm it. Server
// suspend/resume stop and start the SAME announcer, so without the re-arm a
// resumed server never re-announces: every callback returns early, the cycle
// never settles, and only the stuck-cycle watchdog keeps firing.
// ============================================================================
TEST(AnnouncerRelays, RestartReannouncesAfterStop) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    FakeNode node(&loop, 0x11);

    routing::NodeId cid{};
    cid.fill(0x22);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);
    seed_table(client, node);

    auto kp = make_keypair(0x42);
    auto target = make_target(kp);
    Announcer ann(client, kp, target);

    ann.start();
    ASSERT_TRUE(run_until(&loop, settled_at(ann, 1), 5000));
    ASSERT_FALSE(ann.relays().empty()) << "first run never published";
    const int find_peers_first = node.find_peer_count;
    const uint64_t gen_after_first = ann.cycle_gen_for_test();

    ann.stop_without_unannounce();
    EXPECT_TRUE(ann.relays().empty());

    ann.start();
    ASSERT_TRUE(run_until(&loop, settled_at(ann, gen_after_first + 1), 5000))
        << "restarted announcer never completed a cycle";

    EXPECT_GT(node.find_peer_count, find_peers_first)
        << "restarted announcer must walk again";
    EXPECT_FALSE(ann.relays().empty())
        << "restarted announcer must republish — a resumed server that never "
           "re-announces is unreachable until the process restarts";

    ann.stop_without_unannounce();
    node.sock.close();
    client.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}
