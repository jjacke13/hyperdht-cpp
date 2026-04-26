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
//   - `notify_online()` resets has_reannounced_ so build_relays() runs
//     again after recovery; JS just notifies the `online` Signal which
//     unblocks `_background`.

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
//
// Reset `has_reannounced_` so the relay-address re-announce step in
// build_relays() runs again after recovery. Otherwise, stale relays from
// before the outage would remain advertised to peers.
void Announcer::notify_online() {
    if (!running_) {
        DHT_LOG("  [announcer] notify_online: ignored (not running)\n");
        return;
    }
    DHT_LOG("  [announcer] notify_online: triggering update cycle "
            "(reset has_reannounced_ + clear active_relays_)\n");
    has_reannounced_ = false;
    // Clear stale relay entries so the next cycle rebuilds them with
    // fresh peer_addr from the current active_socket() (e.g. after
    // the persistent transition switches from client to server socket).
    active_relays_.clear();
    relays_.clear();
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
// ---------------------------------------------------------------------------

void Announcer::ping_relays() {
    if (active_relays_.empty()) return;

    // Track how many relays respond. Shared counter freed when all callbacks complete.
    auto active_count = std::make_shared<int>(0);
    auto total = static_cast<int>(active_relays_.size());
    auto pending = std::make_shared<int>(total);

    for (const auto& relay : active_relays_) {
        messages::Request req;
        req.to.addr = relay.addr;
        req.command = messages::CMD_PING;
        req.internal = true;

        socket_.request(req,
            [this, active_count, pending, total](const messages::Response&) {
                if (!running_) return;
                (*active_count)++;
                (*pending)--;
                // All done — check health
                if (*pending == 0 && *active_count < std::min(total, MIN_ACTIVE)) {
                    DHT_LOG("  [announcer] relay health: %d/%d active (min=%d), refreshing\n",
                            *active_count, total, MIN_ACTIVE);
                    refresh();
                }
            },
            [this, active_count, pending, total](uint16_t) {
                if (!running_) return;
                (*pending)--;
                if (*pending == 0 && *active_count < std::min(total, MIN_ACTIVE)) {
                    DHT_LOG("  [announcer] relay health: %d/%d active (min=%d), refreshing\n",
                            *active_count, total, MIN_ACTIVE);
                    refresh();
                }
            });
    }
}

// ---------------------------------------------------------------------------
// Update: find k closest → announce to each
//
// JS: .analysis/js/hyperdht/lib/announcer.js:143-197 (_runUpdate + _update)
//     .analysis/js/hyperdht/lib/announcer.js:298-301 (pickBest)
//
// JS calls `dht.findPeer(target)`, awaits the iterative query, picks
// the 3 best closestReplies, signs+commits each, then unannounces any
// stale relays from the previous cycle (`_serverRelays[1]` slot).
// We don't yet do the unannounce diff — we just commit on each query
// reply that yields a token.
// ---------------------------------------------------------------------------

void Announcer::update() {
    if (updating_ || !running_) return;
    updating_ = true;

    current_query_ = dht_ops::find_peer(socket_,
        keypair_.public_key,
        [this](const query::QueryReply& reply) {
            if (!running_) return;
            commit(reply);
        },
        [this](const std::vector<query::QueryReply>&) {
            updating_ = false;
            current_query_.reset();
            if (running_) build_relays();
        });
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

void Announcer::commit(const query::QueryReply& node) {
    if (!node.token.has_value()) {
        DHT_LOG("  [announcer] skip %s:%u (no token)\n",
                node.from_addr.host_string().c_str(), node.from_addr.port);
        return;
    }

    DHT_LOG("  [announcer] commit to %s:%u (id=%02x%02x...)\n",
            node.from_addr.host_string().c_str(), node.from_addr.port,
            node.from_id[0], node.from_id[1]);

    auto node_id = node.from_id;
    auto token = *node.token;

    dht_messages::AnnounceMessage ann;
    dht_messages::PeerRecord peer;
    peer.public_key = keypair_.public_key;
    for (const auto& ri : relays_) {
        peer.relay_addresses.push_back(ri.relay_address);
    }
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

    socket_.request(req,
        [this, node](const messages::Response& resp) {
            if (!running_) return;
            DHT_LOG("  [announcer] ANNOUNCE accepted by %s:%u\n",
                    node.from_addr.host_string().c_str(), node.from_addr.port);

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
            for (auto& existing : active_relays_) {
                if (existing.addr.host_string() == relay.addr.host_string() &&
                    existing.addr.port == relay.addr.port) {
                    existing = relay;  // Update token + peer_addr
                    return;
                }
            }

            if (active_relays_.size() < 3) {
                active_relays_.push_back(relay);
            }
        },
        [node](uint16_t) {
            DHT_LOG("  [announcer] ANNOUNCE timeout from %s:%u\n",
                    node.from_addr.host_string().c_str(), node.from_addr.port);
        });
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

    // Update peer record with relay addresses
    dht_messages::PeerRecord peer;
    peer.public_key = keypair_.public_key;
    for (const auto& ri : relays_) {
        peer.relay_addresses.push_back(ri.relay_address);
    }
    record_ = dht_messages::encode_peer_record(peer);

    DHT_LOG("  [announcer] Built relay list: %zu relays\n", relays_.size());
    for (const auto& ri : relays_) {
        DHT_LOG("    relay: %s:%u (peer: %s:%u)\n",
                ri.relay_address.host_string().c_str(), ri.relay_address.port,
                ri.peer_address.host_string().c_str(), ri.peer_address.port);
    }

    // Re-announce ONCE with relay addresses
    if (!relays_.empty() && running_ && !has_reannounced_) {
        has_reannounced_ = true;
        DHT_LOG("  [announcer] Re-announcing with %zu relay addresses\n",
                relays_.size());
        update();
    }
}

}  // namespace announcer
}  // namespace hyperdht
