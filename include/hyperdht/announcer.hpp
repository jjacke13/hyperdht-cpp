#pragma once

// Announcer — periodic announcement of a server's presence on the DHT.
//
// Flow:
//   1. find_peer(target) to discover k closest nodes
//   2. For each: ANNOUNCE with signed record
//   3. Track relay addresses (which DHT nodes store our announcement)
//   4. Ping relays every 5s to keep NAT mappings alive
//   5. Re-announce every ~5 minutes
//   6. On stop: UNANNOUNCE from all relay nodes
//
// Lifetime: all async callbacks (find_peer, commit, ping_relays) capture a
// weak_ptr<bool> alive_ sentinel. stop_impl() invalidates the sentinel and
// resets current_query_ so callbacks become no-ops after destruction.

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <uv.h>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/compact.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/query.hpp"
#include "hyperdht/rpc.hpp"

namespace hyperdht {
namespace announcer {

// Minimum active relays before triggering a full refresh (matches JS MIN_ACTIVE)
constexpr int MIN_ACTIVE = 3;

class Announcer {
public:
    Announcer(rpc::RpcSocket& socket, const noise::Keypair& keypair,
              const std::array<uint8_t, 32>& target);
    ~Announcer();

    Announcer(const Announcer&) = delete;
    Announcer& operator=(const Announcer&) = delete;

    void start();
    void stop(std::function<void()> on_done = nullptr);

    // Force-stop: tear down timers and relays WITHOUT emitting
    // UNANNOUNCE to the network. Mirrors the JS `destroy({ force: true })`
    // path where `server.close()` is never awaited — active relays are
    // left to expire on their own. Use for crash/exit paths.
    void stop_without_unannounce();

    void refresh();

    // JS: `this.online.notify()` — wakes the _background loop from an
    // `await this.online.wait()` when the network comes back online.
    //
    // In the C++ timer-based model the announcer isn't blocked on a
    // signal, so `notify_online()` simply triggers an immediate update
    // cycle (idempotent — a no-op while one is already in flight).
    // Called from `Server::notify_online()`, which in turn is called
    // from the DHT layer on a network-state transition.
    void notify_online();

    bool is_running() const { return running_; }

    // Test-only: drive one relay keepalive round without waiting for the
    // 5s ping timer (same pattern as RpcSocket::force_check_persistent).
    void ping_relays_for_test() { ping_relays(); }

    // Current relay info (for NoisePayload holepunch field)
    const std::vector<peer_connect::RelayInfo>& relays() const { return relays_; }

    // Encoded peer record (for Router's FIND_PEER response)
    const std::vector<uint8_t>& record() const { return record_; }

private:
    // Common teardown invoked by stop() and stop_without_unannounce().
    void stop_impl(bool send_unannounce);

    rpc::RpcSocket& socket_;
    noise::Keypair keypair_;
    std::array<uint8_t, 32> target_;

    std::vector<uint8_t> record_;  // Encoded PeerRecord
    std::vector<peer_connect::RelayInfo> relays_;

    // Relay tracking
    struct RelayNode {
        compact::Ipv4Address addr;         // Relay node's address
        compact::Ipv4Address peer_addr;    // Our address as seen by this relay (from `to` field)
        std::array<uint8_t, 32> node_id;
        std::array<uint8_t, 32> token;
    };
    std::vector<RelayNode> active_relays_;

    // Timers
    uv_timer_t* bg_timer_ = nullptr;    // Re-announce (~5 min)
    uv_timer_t* ping_timer_ = nullptr;  // Relay keepalive (~5s)
    bool running_ = false;
    bool updating_ = false;

    // ---- Publish-after-settle cycle state ----
    // One "cycle" = one find_peer walk + its ANNOUNCE commits. relays_ is
    // rebuilt (published) only when the walk has completed AND every commit
    // has settled (response, timeout, or congestion drop). JS orders this
    // with `await q.finished()` → `await Promise.allSettled(ann)` → assign
    // this.relays (announcer.js:154-189). cycle_gen_ invalidates late
    // callbacks from a cycle cancelled by notify_online()/stop().
    uint64_t cycle_gen_ = 0;        // bumped at cycle start and on cancel
    int pending_commits_ = 0;       // in-flight ANNOUNCE commits, this cycle
    int cycle_commits_total_ = 0;   // commits issued this cycle (logging)
    bool query_done_ = false;       // this cycle's find_peer walk completed

    // Closest nodes saved at cycle end; seeds the next cycle's find_peer so
    // reannounce re-hits the SAME relays and keeps refreshing their forward
    // state (JS announcer.js:156 `nodes: this._closestNodes`, :187 save).
    std::vector<dht_ops::SeedNode> closest_nodes_;

    // Drift-detection rate limit: uv_now timestamp (ms) of the last
    // drift-triggered refresh; 0 = never. See ping_relays().
    uint64_t last_drift_refresh_ms_ = 0;

    std::shared_ptr<query::Query> current_query_;

    // C7: sentinel for safe async callback invalidation.
    // Captured as weak_ptr in lambdas — if lock() fails or *alive_ is false,
    // the Announcer has been stopped/destroyed.
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);

    void update();
    void commit(const query::QueryReply& node, uint64_t gen);
    void commit_settled();   // decrement pending_commits_ + maybe_publish
    void maybe_publish();    // query_done_ && pending==0 → build_relays
    void unannounce_node(const RelayNode& relay);
    void build_relays();
    void ping_relays();

    static void on_bg_timer(uv_timer_t* timer);
    static void on_ping_timer(uv_timer_t* timer);
};

}  // namespace announcer
}  // namespace hyperdht
