// Announcer implementation — periodically re-announces a server key.
// Runs an iterative query to the target, then sends ANNOUNCE to the
// k closest nodes. Signs each announcement with the server keypair.
//
// JS: .analysis/js/hyperdht/lib/announcer.js:12-277 (whole Announcer class)
//
// C++ diffs from JS:
//   - JS runs an async `_background()` loop that pings relays every 3s
//     and re-announces every ~5min, awaiting on a `Sleeper`/`Signal`.
//     C++ uses two libuv timers: bg_timer_ (REANNOUNCE_MS = 5 min) and
//     ping_timer_ (RELAY_PING_MS = 5 s).
//   - JS keeps three rotating Maps in `_serverRelays[3]`. C++ keeps a
//     single `active_relays_` vector and replaces entries on commit.
//   - JS picks 3 best replies via `pickBest`. C++ commits to all
//     find_peer replies that have a token (capped by query results).
//   - `notify_online()` clears active relays and kicks an update cycle;
//     JS just notifies the `online` Signal which unblocks `_background`.
//   - JS publishes `this.relays` only after `await q.finished()` AND
//     `await Promise.allSettled(ann)` (announcer.js:154-189). C++ mirrors
//     that with a per-cycle pending-commit counter + query-done flag
//     (see update()/commit_settled()/maybe_publish()).
//   - BEYOND-JS: ping_relays() checks each keepalive pong's `to` field
//     against the relay's announce-time peer_addr to detect NAT-mapping
//     drift and re-announce early (JS discards the pong body,
//     announcer.js:114-121). Deliberate divergence; rate-limited.
//
// Lifetime safety: all async callbacks capture a weak_ptr<bool> alive_
// sentinel. stop_impl() sets *alive_ = false and resets current_query_
// so outstanding RPC responses become no-ops when the Announcer is destroyed.

#include "hyperdht/announcer.hpp"

#include <sodium.h>

#include <cstdio>

#include "hyperdht/debug.hpp"

namespace hyperdht {
namespace announcer {

// Re-announce interval: ~5 minutes
constexpr uint64_t REANNOUNCE_MS = 5 * 60 * 1000;

// Relay ping interval: keep NAT mappings alive.
// JS pings every 3s. We use 5s — still well within CGNAT UDP timeouts (30-60s).
constexpr uint64_t RELAY_PING_MS = 5 * 1000;

// Minimum spacing between drift-triggered refreshes (BEYOND-JS, see
// ping_relays). An oscillating NAT observation must not refresh-storm.
constexpr uint64_t DRIFT_REFRESH_MIN_MS = 10 * 1000;

Announcer::Announcer(rpc::RpcSocket& socket, const noise::Keypair& keypair,
                     const std::array<uint8_t, 32>& target)
    : socket_(socket), keypair_(keypair), target_(target) {

    // Initial peer record: publicKey + empty relay addresses
    dht_messages::PeerRecord peer;
    peer.public_key = keypair.public_key;
    record_ = dht_messages::encode_peer_record(peer);
}

Announcer::~Announcer() {
    if (ping_timer_) {
        uv_timer_stop(ping_timer_);
        ping_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(ping_timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        ping_timer_ = nullptr;
    }
    if (bg_timer_) {
        uv_timer_stop(bg_timer_);
        bg_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(bg_timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        bg_timer_ = nullptr;
    }
}

void Announcer::start() {
    if (running_) return;
    running_ = true;

    update();

    // Re-announce timer (~5 min)
    bg_timer_ = new uv_timer_t;
    uv_timer_init(socket_.loop(), bg_timer_);
    bg_timer_->data = this;
    uv_timer_start(bg_timer_, on_bg_timer, REANNOUNCE_MS, REANNOUNCE_MS);

    // Relay ping timer (5s) — keeps NAT mappings alive
    ping_timer_ = new uv_timer_t;
    uv_timer_init(socket_.loop(), ping_timer_);
    ping_timer_->data = this;
    uv_timer_start(ping_timer_, on_ping_timer, RELAY_PING_MS, RELAY_PING_MS);
}

void Announcer::stop(std::function<void()> on_done) {
    stop_impl(/*send_unannounce=*/true);
    if (on_done) on_done();
}

void Announcer::stop_without_unannounce() {
    stop_impl(/*send_unannounce=*/false);
}

// Shared teardown for stop() and stop_without_unannounce(). Splitting
// the policy flag keeps both entry points aligned on the timer/relay
// cleanup order — only the UNANNOUNCE emission is conditional.
void Announcer::stop_impl(bool send_unannounce) {
    if (!running_) return;
    running_ = false;
    *alive_ = false;                        // C7: invalidate sentinel
    if (current_query_) {                    // M9: cancel live query
        current_query_.reset();
    }
    updating_ = false;
    // Invalidate the in-flight cycle (belt-and-braces: *alive_ = false
    // already makes every cycle callback a no-op).
    ++cycle_gen_;
    pending_commits_ = 0;
    query_done_ = false;
    closest_nodes_.clear();

    if (ping_timer_) {
        uv_timer_stop(ping_timer_);
        ping_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(ping_timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        ping_timer_ = nullptr;
    }
    if (bg_timer_) {
        uv_timer_stop(bg_timer_);
        bg_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(bg_timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        bg_timer_ = nullptr;
    }

    if (send_unannounce) {
        for (const auto& relay : active_relays_) {
            unannounce_node(relay);
        }
    }
    active_relays_.clear();
    relays_.clear();
}

void Announcer::refresh() {
    if (!running_) return;
    update();
}

// JS: `this.online.notify()` — wakes _background's `await this.online.wait()`
// which then falls through into the next `_runUpdate()`. In our timer-based
// model we have no blocked awaiter, so the semantically-equivalent action is
// to kick an update cycle immediately. `update()` is already idempotent, so
// this is safe to call repeatedly.
void Announcer::notify_online() {
    if (!running_) {
        DHT_LOG("  [announcer] notify_online: ignored (not running)\n");
        return;
    }
    DHT_LOG("  [announcer] notify_online: triggering update cycle "
            "(clear active_relays_)\n");
    // Clear stale relay entries so the next cycle rebuilds them with
    // fresh peer_addr from the current active_socket() (e.g. after
    // the persistent transition switches from client to server socket).
    active_relays_.clear();
    relays_.clear();
    // Cancel the in-flight cycle so update() isn't blocked by the
    // updating_ guard. Bump cycle_gen_ FIRST: every late callback from
    // the pre-transition cycle (find_peer on_reply/on_done, ANNOUNCE
    // response/timeout) checks its captured gen and becomes a no-op —
    // it must neither publish stale relays nor decrement the new
    // cycle's settle counter.
    ++cycle_gen_;
    pending_commits_ = 0;
    query_done_ = false;
    if (current_query_) {
        // destroy() (not just reset) stops the old walk's fan-out; its
        // synchronous on_done fires into the stale gen and no-ops.
        auto q = std::move(current_query_);
        q->destroy();
    }
    updating_ = false;
    update();
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------

void Announcer::on_bg_timer(uv_timer_t* timer) {
    auto* self = static_cast<Announcer*>(timer->data);
    if (!self || !self->running_) return;
    self->update();
}

void Announcer::on_ping_timer(uv_timer_t* timer) {
    auto* self = static_cast<Announcer*>(timer->data);
    if (!self || !self->running_) return;
    self->ping_relays();
}

// ---------------------------------------------------------------------------
// Ping relay nodes — keep NAT mappings alive + detect lost relays
//
// JS: .analysis/js/hyperdht/lib/announcer.js:105-141 (_background ping loop)
//     JS pings every 3s, then sleeps. We use a periodic uv_timer at 5s.
//     If fewer than MIN_ACTIVE responses come back we trigger refresh()
//     (matches JS:119-121).
//
// BEYOND-JS (deliberate divergence): drift detection. Each pong's
// `resp.from.addr` (wire `to` field = our external address as this relay
// observes it RIGHT NOW) is compared against the peer_addr captured from
// that relay's ANNOUNCE response. A mismatch proves the relay's stored
// forward state (`relay: req.from` at announce time, persistent.js:131-138)
// is stale — our NAT mapping drifted — so we refresh() immediately instead
// of waiting out the 5-min reannounce. JS discards the pong body and only
// counts responders (announcer.js:114-121). Rate-limited to one refresh
// per DRIFT_REFRESH_MIN_MS so an oscillating observation can't storm.
// ---------------------------------------------------------------------------

void Announcer::ping_relays() {
    if (active_relays_.empty()) return;

    // Track how many relays respond. Shared counter freed when all callbacks complete.
    auto active_count = std::make_shared<int>(0);
    auto total = static_cast<int>(active_relays_.size());
    auto pending = std::make_shared<int>(total);

    auto weak = std::weak_ptr<bool>(alive_);  // C7: sentinel
    for (const auto& relay : active_relays_) {
        messages::Request req;
        req.to.addr = relay.addr;
        req.command = messages::CMD_PING;
        req.internal = true;

        const auto relay_addr = relay.addr;
        const auto announced_peer_addr = relay.peer_addr;

        uint16_t tid = socket_.request(req,
            [weak, this, active_count, pending, total, relay_addr,
             announced_peer_addr](const messages::Response& resp) {
                if (auto a = weak.lock(); !a || !*a) return;
                (*active_count)++;
                (*pending)--;

                // Drift check (see header comment above).
                const auto& observed = resp.from.addr;
                DHT_LOG("  [announcer] keepalive pong from %s:%u — "
                        "observed us at %s:%u (announced %s:%u)\n",
                        relay_addr.host_string().c_str(), relay_addr.port,
                        observed.host_string().c_str(), observed.port,
                        announced_peer_addr.host_string().c_str(),
                        announced_peer_addr.port);
                if (observed.port != 0 && !(observed == announced_peer_addr)) {
                    const uint64_t now = uv_now(socket_.loop());
                    if (last_drift_refresh_ms_ == 0 ||
                        now - last_drift_refresh_ms_ >= DRIFT_REFRESH_MIN_MS) {
                        last_drift_refresh_ms_ = now;
                        DHT_LOG("  [announcer] relay %s:%u forward state DRIFTED "
                                "(%s:%u -> %s:%u) — refreshing announce\n",
                                relay_addr.host_string().c_str(), relay_addr.port,
                                announced_peer_addr.host_string().c_str(),
                                announced_peer_addr.port,
                                observed.host_string().c_str(), observed.port);
                        refresh();
                    } else {
                        DHT_LOG("  [announcer] relay %s:%u drift detected but "
                                "rate-limited (last refresh %llums ago)\n",
                                relay_addr.host_string().c_str(), relay_addr.port,
                                static_cast<unsigned long long>(
                                    now - last_drift_refresh_ms_));
                    }
                }

                if (*pending == 0 && *active_count < std::min(total, MIN_ACTIVE)) {
                    DHT_LOG("  [announcer] relay health: %d/%d active (min=%d), refreshing\n",
                            *active_count, total, MIN_ACTIVE);
                    refresh();
                }
            },
            [weak, this, active_count, pending, total](uint16_t) {
                if (auto a = weak.lock(); !a || !*a) return;
                (*pending)--;
                if (*pending == 0 && *active_count < std::min(total, MIN_ACTIVE)) {
                    DHT_LOG("  [announcer] relay health: %d/%d active (min=%d), refreshing\n",
                            *active_count, total, MIN_ACTIVE);
                    refresh();
                }
            });
        // Dropped by the congestion queue (tid == 0): neither callback fires
        // — settle this relay's slot now so the tick's health check can
        // still evaluate (mirror of the ANNOUNCE commit congestion path).
        if (tid == 0) {
            (*pending)--;
            if (*pending == 0 && *active_count < std::min(total, MIN_ACTIVE)) {
                DHT_LOG("  [announcer] relay health: %d/%d active (min=%d), refreshing\n",
                        *active_count, total, MIN_ACTIVE);
                refresh();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Update: find k closest → announce to each → publish after settle
//
// JS: .analysis/js/hyperdht/lib/announcer.js:143-197 (_runUpdate + _update)
//     .analysis/js/hyperdht/lib/announcer.js:298-301 (pickBest)
//
// JS calls `dht.findPeer(target, { nodes: this._closestNodes })`, awaits
// the iterative query, picks the 3 best closestReplies, signs+commits
// each, awaits Promise.allSettled(ann), and only THEN assigns
// `this.relays` / `this._closestNodes` (announcer.js:154-189). C++
// mirrors the ordering with an explicit per-cycle state machine:
//
//   update()          — starts cycle `gen`: pending_commits_ = 0,
//                       query_done_ = false, updating_ = true.
//   commit(gen)       — per tokened reply: ++pending_commits_ before the
//                       ANNOUNCE request; the response callback, the
//                       timeout callback, and the congestion-drop path
//                       (tid == 0) each settle exactly once.
//   on_done           — query_done_ = true, saves closest_nodes_ for the
//                       next cycle's seed, then maybe_publish().
//   maybe_publish()   — when query_done_ && pending_commits_ == 0:
//                       build_relays() (publish) + updating_ = false.
//
// The zero-commit cycle (no token replies) publishes at on_done since
// pending_commits_ is already 0. A cycle cancelled by notify_online()/
// stop() bumps cycle_gen_, so every late callback (captured gen) no-ops.
// We still diff from JS in committing per-reply during the walk rather
// than to pickBest(3) after it.
// ---------------------------------------------------------------------------

void Announcer::update() {
    if (updating_ || !running_) return;
    updating_ = true;

    const uint64_t gen = ++cycle_gen_;
    pending_commits_ = 0;
    cycle_commits_total_ = 0;
    query_done_ = false;

    auto weak = std::weak_ptr<bool>(alive_);  // C7: sentinel
    current_query_ = dht_ops::find_peer(socket_,
        keypair_.public_key,
        [weak, this, gen](const query::QueryReply& reply) {
            if (auto a = weak.lock(); !a || !*a) return;
            if (gen != cycle_gen_) return;  // cancelled cycle
            commit(reply, gen);
        },
        [weak, this, gen](int /*error*/,
                          const std::vector<query::QueryReply>& closest) {
            if (auto a = weak.lock(); !a || !*a) return;
            if (gen != cycle_gen_) return;  // cancelled cycle
            current_query_.reset();
            // Save the walk's closest nodes to seed the next cycle's
            // find_peer, so reannounce re-hits the SAME relays (JS
            // announcer.js:187 `this._closestNodes = q.closestNodes`).
            closest_nodes_.clear();
            for (const auto& r : closest) {
                closest_nodes_.push_back({r.from_id, r.from_addr});
            }
            query_done_ = true;
            maybe_publish();
        },
        // Seed from the previous cycle (JS announcer.js:156
        // `nodes: this._closestNodes`). Seeds are consumed before
        // start(); the on_done above may safely rewrite the vector.
        &closest_nodes_);
}

// One ANNOUNCE commit settled (response, timeout, or congestion drop).
// Only ever called with a live generation — cancelled cycles return
// before reaching here, and their counter was reset by the next update().
void Announcer::commit_settled() {
    if (pending_commits_ > 0) --pending_commits_;
    maybe_publish();
}

// Publish gate: JS assigns this.relays only after `await q.finished()`
// AND `await Promise.allSettled(ann)` (announcer.js:184-189).
void Announcer::maybe_publish() {
    if (!query_done_ || pending_commits_ != 0) return;
    DHT_LOG("  [announcer] cycle settled (%d commits) — publishing relays\n",
            cycle_commits_total_);
    if (running_) build_relays();
    updating_ = false;
}

// ---------------------------------------------------------------------------
// Commit: sign and send ANNOUNCE to a single node
//
// JS: .analysis/js/hyperdht/lib/announcer.js:240-268 (_commit)
//     C++ also tracks per-relay peer_addr (the `to` field on the
//     ANNOUNCE response) so build_relays() can advertise the address
//     each relay actually saw — important for CGNAT where different
//     relays observe different ports.
// ---------------------------------------------------------------------------

void Announcer::commit(const query::QueryReply& node, uint64_t gen) {
    if (!node.token.has_value()) {
        DHT_LOG("  [announcer] skip %s:%u (no token)\n",
                node.from_addr.host_string().c_str(), node.from_addr.port);
        return;
    }

    DHT_LOG("  [announcer] commit to %s:%u (id=%02x%02x...)\n",
            node.from_addr.host_string().c_str(), node.from_addr.port,
            node.from_id[0], node.from_id[1]);

    // Settle accounting: incremented BEFORE the request goes out; exactly
    // one of {response, timeout, congestion-drop} settles it below.
    ++pending_commits_;
    ++cycle_commits_total_;

    auto node_id = node.from_id;
    auto token = *node.token;

    // JS announcer.js:241-247 — the signed/stored record always carries
    // relayAddresses: []. Clients discover relays from the responding DHT
    // node (connect.js:359) and the handshake payload (server.js:349-368),
    // never from the record.
    dht_messages::AnnounceMessage ann;
    dht_messages::PeerRecord peer;
    peer.public_key = keypair_.public_key;
    ann.peer = peer;

    auto signature = announce_sig::sign_announce(
        target_, node_id, token.data(), token.size(), ann, keypair_);
    ann.signature = signature;

    auto ann_value = dht_messages::encode_announce_msg(ann);

    messages::Request req;
    req.to.addr = node.from_addr;
    req.command = messages::CMD_ANNOUNCE;
    req.target = target_;
    req.token = token;
    req.value = std::move(ann_value);

    auto weak = std::weak_ptr<bool>(alive_);  // C7: sentinel
    uint16_t tid = socket_.request(req,
        [weak, this, node, gen](const messages::Response& resp) {
            if (auto a = weak.lock(); !a || !*a) return;
            // Cancelled cycle: neither track the (stale peer_addr) relay
            // nor touch the new cycle's settle counter.
            if (gen != cycle_gen_) return;
            DHT_LOG("  [announcer] ANNOUNCE accepted by %s:%u — "
                    "relay observed us at %s:%u\n",
                    node.from_addr.host_string().c_str(), node.from_addr.port,
                    resp.from.addr.host_string().c_str(), resp.from.addr.port);

            RelayNode relay;
            relay.addr = node.from_addr;
            relay.node_id = node.from_id;
            if (node.token.has_value()) {
                relay.token = *node.token;
            }
            // peer_addr = resp.from.addr = wire `to` field = our address as
            // seen by this specific relay node. Critical for CGNAT where
            // different relays may see us on different ports.
            relay.peer_addr = resp.from.addr;

            // Check if we already have this relay
            bool updated = false;
            for (auto& existing : active_relays_) {
                if (existing.addr == relay.addr) {
                    existing = relay;  // Update token + peer_addr
                    updated = true;
                    break;
                }
            }
            if (!updated && active_relays_.size() < 3) {
                active_relays_.push_back(relay);
            }

            commit_settled();
        },
        [weak, this, node, gen](uint16_t) {
            if (auto a = weak.lock(); !a || !*a) return;
            DHT_LOG("  [announcer] ANNOUNCE timeout from %s:%u\n",
                    node.from_addr.host_string().c_str(), node.from_addr.port);
            if (gen != cycle_gen_) return;
            commit_settled();
        });
    // Dropped by the congestion queue (tid == 0): neither callback will
    // fire — settle now so the cycle's publish gate can't wedge.
    if (tid == 0) {
        DHT_LOG("  [announcer] ANNOUNCE to %s:%u dropped (congestion)\n",
                node.from_addr.host_string().c_str(), node.from_addr.port);
        commit_settled();
    }
}

// ---------------------------------------------------------------------------
// Unannounce from a single relay node
//
// JS: .analysis/js/hyperdht/lib/announcer.js:205-238 (_unannounce)
//     JS first issues a FIND_PEER to acquire a fresh token from the
//     relay, then sends UNANNOUNCE. C++ reuses the token captured at
//     commit() time, so it skips the extra round-trip.
// ---------------------------------------------------------------------------

void Announcer::unannounce_node(const RelayNode& relay) {
    dht_messages::AnnounceMessage ann;
    dht_messages::PeerRecord peer;
    peer.public_key = keypair_.public_key;
    ann.peer = peer;

    auto signature = announce_sig::sign_unannounce(
        target_, relay.node_id, relay.token.data(), relay.token.size(),
        ann, keypair_);
    ann.signature = signature;

    auto ann_value = dht_messages::encode_announce_msg(ann);

    messages::Request req;
    req.to.addr = relay.addr;
    req.command = messages::CMD_UNANNOUNCE;
    req.target = target_;
    req.token = relay.token;
    req.value = std::move(ann_value);

    socket_.request(req, [](const messages::Response&) {}, [](uint16_t) {});
}

// ---------------------------------------------------------------------------
// Build relay info from active relays
//
// JS: .analysis/js/hyperdht/lib/announcer.js:175-189 (the relays/relayAddresses
//     assembly block at the end of _update — also re-encodes record).
// ---------------------------------------------------------------------------

void Announcer::build_relays() {
    relays_.clear();

    for (const auto& relay : active_relays_) {
        peer_connect::RelayInfo ri;
        ri.relay_address = relay.addr;
        // Use per-relay peer_addr (from ANNOUNCE response `to` field) —
        // our address as seen by THIS specific relay. NOT the NAT sampler
        // average, which may be wrong when CGNAT assigns different ports
        // per destination.
        ri.peer_address = relay.peer_addr;
        relays_.push_back(ri);
    }

    // NOTE: record_ is NOT re-encoded here — JS encodes the record once at
    // construction with relayAddresses: [] and never updates it
    // (announcer.js:21). Relay info reaches clients via relays_ in the
    // handshake payload, not the record.

    DHT_LOG("  [announcer] Built relay list: %zu relays\n", relays_.size());
    for (const auto& ri : relays_) {
        DHT_LOG("    relay: %s:%u (peer: %s:%u)\n",
                ri.relay_address.host_string().c_str(), ri.relay_address.port,
                ri.peer_address.host_string().c_str(), ri.peer_address.port);
    }
}

}  // namespace announcer
}  // namespace hyperdht
