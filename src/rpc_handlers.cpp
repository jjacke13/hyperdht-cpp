// DHT RPC request handler implementations — dispatch PING, PING_NAT,
// FIND_NODE, DOWN_HINT, DELAYED_PING (internal) and FIND_PEER, LOOKUP,
// ANNOUNCE, UNANNOUNCE, MUTABLE/IMMUTABLE_GET/PUT (HyperDHT).
//
// JS: .analysis/js/dht-rpc/index.js:632-687 (_onrequest — internal cmds)
//     .analysis/js/hyperdht/lib/persistent.js:16-257 (Persistent class —
//                                                     all HyperDHT cmds)
//
// Three protocol-parity behaviors implemented here:
//
//   1. ID suppression: responses only include our routing table ID when
//      NOT ephemeral. JS: io.js:488 `ephemeral === false && socket ===
//      serverSocket`. Our single-socket impl simplifies to `!ephemeral`.
//
//   2. Storage command gating: FIND_PEER, LOOKUP, ANNOUNCE, UNANNOUNCE,
//      MUTABLE/IMMUTABLE_GET/PUT are dropped when ephemeral. JS:
//      hyperdht/index.js:404 `if (this._persistent === null) return false`.
//      Connection-layer commands (PEER_HANDSHAKE, PEER_HOLEPUNCH) pass
//      through regardless.
//
//   3. DoS hardening:
//      - FIND_NODE rate-limited to 1/sec/IP (6-8x amplification vector)
//      - DOWN_HINT rate-limited to 1/sec/IP (eclipse attack mitigation)
//      - DELAYED_PING timers capped at 256 concurrent
//      - IMMUTABLE/MUTABLE_PUT values capped at 32KB
//
// C++ diffs from JS:
//   - JS Persistent has separate caches for `bumps`, `refreshes`,
//     `mutables`, `immutables` (record-cache + xache packages).
//     C++ uses simpler `RecordCache` for mutables/immutables and
//     `AnnounceStore` for the record cache. No bump/refresh handling.
//   - Mutable/immutable size split is half-and-half (matches JS,
//     persistent.js constructor).

#include "hyperdht/rpc_handlers.hpp"

#include <cassert>
#include <chrono>
#include <cstring>

#include <sodium.h>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/debug.hpp"
#include "hyperdht/dht_messages.hpp"

namespace hyperdht {
namespace rpc {

// Wall-clock milliseconds — for the bump drift gate, which mirrors JS
// `Date.now()` (the announcer stamps bump with wall-clock time). Must NOT be
// uv_now (monotonic loop time), or the `bump <= now + drift` check misbehaves.
static uint64_t wall_clock_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

RpcHandlers::RpcHandlers(RpcSocket& socket, router::Router* router,
                         StorageCacheConfig cache_config)
    : socket_(socket),
      router_(router),
      storage_ttl_ms_(cache_config.ttl_ms),
      ann_ttl_ms_(cache_config.ann_ttl_ms),
      // JS: index.js:610-615 — mutable/immutable each get maxSize/2 entries.
      // Guard against max_size=0 by using at least 1 entry per cache.
      mutables_(std::max<size_t>(1, cache_config.max_size / 2)),
      immutables_(std::max<size_t>(1, cache_config.max_size / 2)) {
    start_gc_timer();
}

RpcHandlers::~RpcHandlers() {
    if (gc_timer_) {
        uv_timer_stop(gc_timer_);
        gc_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(gc_timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        gc_timer_ = nullptr;
    }

    // Cancel any scheduled DELAYED_PING replies. Orphan each pending struct
    // (owner=nullptr) so if the fire callback somehow races us it bails out,
    // then uv_close the timer — the close callback deletes the struct.
    for (auto* dr : pending_delayed_) {
        dr->owner = nullptr;
        uv_timer_stop(&dr->timer);
        uv_close(reinterpret_cast<uv_handle_t*>(&dr->timer), [](uv_handle_t* h) {
            auto* d = static_cast<DelayedReply*>(h->data);
            delete d;
        });
    }
    pending_delayed_.clear();
}

void RpcHandlers::start_gc_timer() {
    if (!socket_.loop()) return;
    gc_timer_ = new uv_timer_t;
    uv_timer_init(socket_.loop(), gc_timer_);
    gc_timer_->data = this;
    uv_timer_start(gc_timer_, on_gc_tick, GC_INTERVAL_MS, GC_INTERVAL_MS);
    // Unref so the GC timer doesn't keep the event loop alive by itself
    uv_unref(reinterpret_cast<uv_handle_t*>(gc_timer_));
}

void RpcHandlers::on_gc_tick(uv_timer_t* timer) {
    auto* self = static_cast<RpcHandlers*>(timer->data);
    if (!self) return;
    auto now = uv_now(self->socket_.loop());
    self->mutables_.gc(now, self->storage_ttl_ms_);
    self->immutables_.gc(now, self->storage_ttl_ms_);
    self->store_.gc(now);

    // Expire stale bump entries, same TTL as the announce store (JS bumps
    // Cache uses maxAge = opts.maxAge, same as the records cache).
    for (auto it = self->bumps_.begin(); it != self->bumps_.end();) {
        if (now - it->second.created_at > self->ann_ttl_ms_) {
            it = self->bumps_.erase(it);
        } else {
            ++it;
        }
    }
}

void RpcHandlers::install() {
    socket_.on_request([this](const messages::Request& req) {
        handle(req);
    });
}

void RpcHandlers::handle(const messages::Request& req) {
    static uint64_t req_count = 0;  // L3: was int, UB at INT_MAX
    if (++req_count <= 5 || !req.internal) {
        DHT_LOG( "  [handlers] req #%lu: int=%d cmd=%u from %s:%u\n",
                (unsigned long)req_count, req.internal ? 1 : 0, req.command,
                req.from.addr.host_string().c_str(), req.from.addr.port);
    }
    if (req.internal) {
        switch (req.command) {
            case messages::CMD_PING:         handle_ping(req); break;
            case messages::CMD_PING_NAT:     handle_ping_nat(req); break;
            case messages::CMD_FIND_NODE:    handle_find_node(req); break;
            case messages::CMD_DOWN_HINT:    handle_down_hint(req); break;
            case messages::CMD_DELAYED_PING: handle_delayed_ping(req); break;
            // JS index.js:679 — unknown internal command → UNKNOWN_COMMAND reply.
            default: send_unknown_command_reply(req); break;
        }
    } else {
        DHT_LOG( "  [handlers] ext cmd=%u from %s:%u\n",
                req.command, req.from.addr.host_string().c_str(), req.from.addr.port);

        // Connection-layer commands pass through regardless of ephemeral state.
        switch (req.command) {
            case messages::CMD_PEER_HANDSHAKE:
                if (router_) {
                    router_->handle_peer_handshake(req,
                        [this, from_server = req.from_server]
                        (const messages::Response& resp) {
                            socket_.reply(resp, from_server);
                        },
                        [this](const messages::Request& req) {
                            auto buf = messages::encode_request(req);
                            socket_.udp_send(buf, req.to.addr);
                        },
                        // Closer-nodes provider for the no-relay FROM_CLIENT
                        // reply (JS router.js:135). Same table.closest() the
                        // query responses use (make_query_response above).
                        [this](const announce::TargetKey& target)
                            -> std::vector<compact::Ipv4Address> {
                            std::vector<compact::Ipv4Address> out;
                            for (const auto* node : socket_.table().closest(target)) {
                                out.push_back(compact::Ipv4Address::from_string(
                                    node->host, node->port));
                            }
                            return out;
                        });
                }
                return;
            case messages::CMD_PEER_HOLEPUNCH:
                if (router_) {
                    router_->handle_peer_holepunch(req,
                        [this, from_server = req.from_server]
                        (const messages::Response& resp) {
                            socket_.reply(resp, from_server);
                        },
                        [this](const messages::Request& req) {
                            auto buf = messages::encode_request(req);
                            socket_.udp_send(buf, req.to.addr);
                        });
                }
                return;
            default:
                break;
        }

        // Storage commands gated behind persistent state.
        // JS: hyperdht/index.js:404 — `if (this._persistent === null) return false`
        // Announce signatures include our node ID; accepting them while ephemeral
        // (random ID) would produce signatures that become invalid when the ID
        // changes at the persistent transition. dht-rpc turns that `false` into
        // an UNKNOWN_COMMAND reply (index.js:684-685), so an ephemeral node
        // answers storage queries with an error instead of silently timing out.
        if (socket_.is_ephemeral()) {
            send_unknown_command_reply(req);
            return;
        }

        switch (req.command) {
            case messages::CMD_FIND_PEER:     handle_find_peer(req); break;
            case messages::CMD_LOOKUP:        handle_lookup(req); break;
            case messages::CMD_ANNOUNCE:      handle_announce(req); break;
            case messages::CMD_UNANNOUNCE:    handle_unannounce(req); break;
            case messages::CMD_MUTABLE_PUT:   handle_mutable_put(req); break;
            case messages::CMD_MUTABLE_GET:   handle_mutable_get(req); break;
            case messages::CMD_IMMUTABLE_PUT: handle_immutable_put(req); break;
            case messages::CMD_IMMUTABLE_GET: handle_immutable_get(req); break;
            // JS index.js:684-685 — onrequest returned false → UNKNOWN_COMMAND.
            default: send_unknown_command_reply(req); break;
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: build a response with our ID, token, and closer nodes
//
// JS: .analysis/js/dht-rpc/lib/io.js:485-518 (_sendReply — assembles
//     response with id/token/closerNodes/error/value flags)
//
// ID is only included when NOT ephemeral. JS:
//   `const id = this._io.ephemeral === false && socket === this._io.serverSocket`
// Our single-socket implementation simplifies to: `!ephemeral`.
// ---------------------------------------------------------------------------

messages::Response RpcHandlers::make_query_response(const messages::Request& req) {
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    // JS: io.js:488 — includes ID only when `!ephemeral && socket === serverSocket`
    if (!socket_.is_ephemeral() && req.from_server) {
        resp.id = socket_.table().id();
    }
    resp.token = socket_.token_store().create(req.from.addr.host_string());

    if (req.target.has_value()) {
        routing::NodeId target{};
        std::copy(req.target->begin(), req.target->end(), target.begin());

        auto closest = socket_.table().closest(target);
        for (const auto* node : closest) {
            resp.closer_nodes.push_back(
                compact::Ipv4Address::from_string(node->host, node->port));
        }
    }

    return resp;
}

// JS: dht-rpc/index.js:679,685 — `req.sendReply(UNKNOWN_COMMAND, null, false,
// req.target !== null)`. sendReply(error, value, token, hasCloserNodes) →
// _sendReply (io.js:485-518): error=UNKNOWN_COMMAND, value=null, token=false
// (no token bytes), closerNodes only when the request carried a target
// (hasCloserNodes == target !== null), id only when
// `!ephemeral && socket === serverSocket`.
void RpcHandlers::send_unknown_command_reply(const messages::Request& req) {
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    resp.error = messages::ERR_UNKNOWN_COMMAND;
    // id only when persistent AND on the server socket (JS io.js:488).
    if (!socket_.is_ephemeral() && req.from_server) {
        resp.id = socket_.table().id();
    }
    // closerNodes only when the request carried a target (JS io.js:489-490).
    if (req.target.has_value()) {
        routing::NodeId target{};
        std::copy(req.target->begin(), req.target->end(), target.begin());
        for (const auto* node : socket_.table().closest(target)) {
            resp.closer_nodes.push_back(
                compact::Ipv4Address::from_string(node->host, node->port));
        }
    }
    // Note: no token (JS token=false).
    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// PING — reply with our node ID and a token for the sender
//
// JS: .analysis/js/dht-rpc/index.js:640-643 (_onrequest case PING)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_ping(const messages::Request& req) {
    auto resp = make_query_response(req);
    // JS index.js:641 — `req.sendReply(0, null, false, false)`: PING carries
    // neither a token nor closer nodes. make_query_response set both; strip them.
    resp.token.reset();
    resp.closer_nodes.clear();
    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// PING_NAT — reply to the sender's specified port (for NAT detection)
//
// JS: .analysis/js/dht-rpc/index.js:649-655 (_onrequest case PING_NAT)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_ping_nat(const messages::Request& req) {
    if (!req.value.has_value() || req.value->size() < 2) return;

    uint16_t port = static_cast<uint16_t>((*req.value)[0])
                  | (static_cast<uint16_t>((*req.value)[1]) << 8);
    if (port == 0) return;

    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = compact::Ipv4Address::from_string(
        req.from.addr.host_string(), port);

    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// FIND_NODE — return the k closest nodes to the target
//
// JS: .analysis/js/dht-rpc/index.js:658-662 (_onrequest case FIND_NODE)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_find_node(const messages::Request& req) {
    // H21: per-IP rate limit — 1 response/sec/IP to mitigate amplification
    uint32_t ip = 0;
    std::memcpy(&ip, req.from.addr.host.data(), 4);
    auto now = uv_now(socket_.loop());
    auto it = find_node_rate_.find(ip);
    if (it != find_node_rate_.end() && now - it->second < 1000) return;
    find_node_rate_[ip] = now;
    if (find_node_rate_.size() > 8192) find_node_rate_.clear();  // cap map growth

    auto resp = make_query_response(req);
    // JS index.js:660 — `req.sendReply(0, null, false, true)`: FIND_NODE returns
    // closer nodes but NO token. make_query_response set a token; strip it.
    resp.token.reset();
    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// DOWN_HINT — a peer tells us another node is unresponsive. We look up that
// node in our routing table (by BLAKE2b-256 hash of its 6-byte compact ipv4
// encoding, matching JS `peer.id()`) and schedule a PING check. If the check
// times out, the node is evicted. Always reply with an empty response.
// Rate-limited to MAX_CHECKS in-flight checks at once.
//
// JS: .analysis/js/dht-rpc/index.js:664-676 (_onrequest case DOWN_HINT)
//     .analysis/js/dht-rpc/index.js:737-762 (_check — the actual ping)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_down_hint(const messages::Request& req) {
    // Reply first — JS pattern: `req.sendReply(0, null, false, false)` is
    // unconditional after the switch case.
    auto send_empty_reply = [&]() {
        messages::Response resp;
        resp.tid = req.tid;
        resp.from.addr = req.from.addr;
        if (!socket_.is_ephemeral() && req.from_server) {
            resp.id = socket_.table().id();
        }
        socket_.reply(resp, req.from_server);
    };

    if (!req.value.has_value() || req.value->size() < 6) {
        // JS drops silently without replying when value is malformed.
        return;
    }

    // H27: rate-limit DOWN_HINT per source IP (max 1/sec) to mitigate
    // eclipse attacks where attacker floods hints for all known nodes.
    {
        uint32_t ip = 0;
        std::memcpy(&ip, req.from.addr.host.data(), 4);
        auto now = uv_now(socket_.loop());
        auto it = down_hint_rate_.find(ip);
        if (it != down_hint_rate_.end() && now - it->second < 1000) {
            send_empty_reply();
            return;
        }
        down_hint_rate_[ip] = now;
        if (down_hint_rate_.size() > 4096) down_hint_rate_.clear();
    }

    // Respect the rate limit (JS: `if (this._checks < 10)`).
    if (socket_.checks() >= MAX_CHECKS) {
        send_empty_reply();
        return;
    }

    // Compute the target node id: BLAKE2b-256 of the 6-byte ipv4 compact
    // encoding (matches JS `peer.id(host, port)`).
    routing::NodeId target{};
    crypto_generichash(target.data(), target.size(),
                       req.value->data(), 6,
                       nullptr, 0);

    // Look up in our routing table. Only act if the node exists AND we
    // haven't already pinged it this tick (or it has no down hints yet).
    if (auto* node = socket_.table().get_mut(target)) {
        if (node->pinged < socket_.tick() || node->down_hints == 0) {
            node->down_hints++;
            // Snapshot by value — check_node() will reference only
            // id/host/port/seen so a copy is safe.
            routing::Node snapshot = *node;
            socket_.check_node(snapshot);
        }
    }

    send_empty_reply();
}

// ---------------------------------------------------------------------------
// DELAYED_PING — reply with a plain PING after `delay_ms` milliseconds.
// Value is a 4-byte LE uint32. Matches JS dht-rpc `_ondelayedping`:
//   - Drop silently if value < 4 bytes or delay > max_ping_delay.
//   - Schedule a uv_timer; on fire, send empty reply.
//   - Pending timers are cancelled in the destructor.
//
// JS: .analysis/js/dht-rpc/index.js:693-703 (_ondelayedping — uses
//     setTimeout, tracks via `_pendingTimers` Set; we use a vector of
//     uv_timer_t* heap structs cleaned up in the destructor.)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_delayed_ping(const messages::Request& req) {
    if (!req.value.has_value() || req.value->size() < 4) return;
    constexpr size_t MAX_PENDING_DELAYED = 256;  // H22: cap timer accumulation
    if (pending_delayed_.size() >= MAX_PENDING_DELAYED) return;

    const auto& v = *req.value;
    uint32_t delay_ms =
        static_cast<uint32_t>(v[0])
      | (static_cast<uint32_t>(v[1]) << 8)
      | (static_cast<uint32_t>(v[2]) << 16)
      | (static_cast<uint32_t>(v[3]) << 24);

    // Respect our own configured max (mirrors JS: `if (delayMs > this.maxPingDelay) return`)
    if (delay_ms > socket_.max_ping_delay_ms()) return;

    if (!socket_.loop()) return;

    // Schedule the reply
    auto* dr = new DelayedReply{};
    dr->owner = this;
    dr->tid = req.tid;
    dr->from = req.from.addr;
    dr->from_server = req.from_server;

    uv_timer_init(socket_.loop(), &dr->timer);
    dr->timer.data = dr;
    uv_timer_start(&dr->timer, on_delayed_ping_fire,
                   static_cast<uint64_t>(delay_ms), 0);

    pending_delayed_.push_back(dr);
}

void RpcHandlers::on_delayed_ping_fire(uv_timer_t* timer) {
    auto* dr = static_cast<DelayedReply*>(timer->data);
    if (!dr) return;

    if (dr->owner) {
        // Send empty reply (matches JS: req.sendReply(0, null, false, false))
        messages::Response resp;
        resp.tid = dr->tid;
        resp.from.addr = dr->from;
        if (!dr->owner->socket_.is_ephemeral() && dr->from_server) {
            resp.id = dr->owner->socket_.table().id();
        }
        dr->owner->socket_.reply(resp, dr->from_server);

        // Remove from pending list (swap-and-pop)
        auto& vec = dr->owner->pending_delayed_;
        for (size_t i = 0; i < vec.size(); i++) {
            if (vec[i] == dr) {
                vec[i] = vec.back();
                vec.pop_back();
                break;
            }
        }
    }

    // Close the timer and free the struct. Safe to call uv_close from within
    // the timer callback — libuv marks the handle closing and invokes the
    // close callback after the current callback returns.
    uv_close(reinterpret_cast<uv_handle_t*>(&dr->timer), [](uv_handle_t* h) {
        auto* d = static_cast<DelayedReply*>(h->data);
        delete d;
    });
}

// ---------------------------------------------------------------------------
// FIND_PEER — return a single stored peer record for the target
//
// JS: .analysis/js/hyperdht/lib/persistent.js:39-43 (onfindpeer)
//     `req.reply(fwd ? fwd.record : null)` — router ONLY, no announce-store
//     fallback. A findPeer only resolves a self-announced server (the router
//     entry populated by handle_announce's announceSelf branch); relayed
//     announcements live in the records cache and surface via LOOKUP, not
//     FIND_PEER. The prior store fallback diverged from JS and is removed.
// ---------------------------------------------------------------------------

void RpcHandlers::handle_find_peer(const messages::Request& req) {
    if (!req.target.has_value()) return;

    auto resp = make_query_response(req);

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    if (router_) {
        const auto* rec = router_->record(target);
        if (rec) resp.value = *rec;
    }

    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// LOOKUP — return all stored peer records for the target (up to 20)
//
// JS: .analysis/js/hyperdht/lib/persistent.js:26-37 (onlookup)
//     records = this.records.get(k, 20); bump = this.bumps.get(k) || 0;
//     fwd = this.dht._router.get(k); if (fwd && records.length < 20)
//     records.push(fwd.record); reply = records.length
//     ? c.encode(m.lookupRawReply, { peers: records, bump }) : null.
//
//     Each stored record is a bare m.peer (see handle_announce), so the
//     shared encode_lookup_reply concatenates them raw — wire-identical to
//     the JS `rawPeers = c.array(c.raw)` encode path.
// ---------------------------------------------------------------------------

void RpcHandlers::handle_lookup(const messages::Request& req) {
    if (!req.target.has_value()) return;

    auto resp = make_query_response(req);

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    auto peers = store_.get(target);
    if (peers.size() > announce::MAX_PEERS_PER_TARGET) {
        peers.resize(announce::MAX_PEERS_PER_TARGET);
    }

    dht_messages::LookupRawReply reply;
    reply.peers.reserve(peers.size() + 1);
    for (const auto& p : peers) {
        reply.peers.push_back(p.value);  // bare m.peer record
    }

    // JS persistent.js:34 — push the router's forward record (a self-announced
    // server for this target) when we have room under the 20 cap.
    if (router_ && reply.peers.size() < announce::MAX_PEERS_PER_TARGET) {
        if (const auto* rec = router_->record(target)) {
            reply.peers.push_back(*rec);
        }
    }

    reply.bump = bump_for(target);

    // JS persistent.js:36 — reply null when there are no records at all.
    if (!reply.peers.empty()) {
        resp.value = dht_messages::encode_lookup_reply(reply);
    }

    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// ANNOUNCE — validate token and store peer announcement
//
// JS: .analysis/js/hyperdht/lib/persistent.js:100-150 (onannounce)
//     .analysis/js/hyperdht/lib/persistent.js:269-284 (annSignable)
//
// C++ diffs from JS:
//   - No `refresh` cache plumbing (JS:145-147). The refresh-only path
//     replies but doesn't yet hook up `_onrefresh`.
//   - Relay-address cap of 3 matches JS:121-123.
//   - Bump tracking + announceSelf router population + bare-record storage
//     now mirror JS (persistent.js:121-143). See body.
// ---------------------------------------------------------------------------

void RpcHandlers::handle_announce(const messages::Request& req) {
    if (!req.target.has_value()) return;
    if (!req.token.has_value()) return;

    // Validate token: must match what we issued for this sender
    if (!socket_.token_store().validate(
            req.from.addr.host_string(), *req.token)) {
        return;
    }

    // Decode the announce message
    if (!req.value.has_value()) return;
    auto ann = dht_messages::decode_announce_msg(
        req.value->data(), req.value->size());

    // Refresh-only (no peer) — skip signature check (JS: _onrefresh)
    if (!ann.peer.has_value()) {
        if (!ann.refresh.has_value()) return;
        // TODO: implement full refresh token handling (_onrefresh)
        // For now, reply so the client doesn't time out
        messages::Response resp;
        resp.tid = req.tid;
        resp.from.addr = req.from.addr;
        if (!socket_.is_ephemeral() && req.from_server) {
            resp.id = socket_.table().id();
        }
        socket_.reply(resp, req.from_server);
        return;
    }

    // Signature is required when peer is present
    if (!ann.signature.has_value()) return;

    // Verify Ed25519 signature: signable = NS_ANNOUNCE + BLAKE2b(target || nodeId || token || peer || refresh)
    // NOTE: verify against the announce AS SIGNED (untrimmed) — JS computes
    // annSignable at persistent.js:106, BEFORE the relay trim at :121-123.
    // Trimming first would re-encode a different m.peer and reject any
    // legitimate announce carrying >3 relay addresses.
    auto node_id = socket_.table().id();
    bool valid = announce_sig::verify_announce(
        dht_messages::ns_announce(),
        *req.target, node_id,
        req.token->data(), req.token->size(),
        ann, *ann.signature,
        ann.peer->public_key);

    if (!valid) return;  // Silently drop invalid signatures

    // Cap relay addresses at 3 for the stored/served record — AFTER the
    // signature check (JS persistent.js:121-123).
    if (ann.peer->relay_addresses.size() > 3) {
        ann.peer->relay_addresses.resize(3);
    }

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    // The stored record is the BARE re-encoded m.peer (relays already trimmed
    // to <=3 above), NOT the full announce message. JS persistent.js:129
    // `record = encodeUnslab(m.peer, peer)`. This is exactly the byte string
    // that LOOKUP/FIND_PEER hand back (self-delimiting in the raw peers array).
    auto record = dht_messages::encode_peer_record(*ann.peer);

    // announceSelf = BLAKE2b(peer.publicKey) === req.target (a server
    // announcing itself). JS persistent.js:125-128.
    std::array<uint8_t, 32> pk_hash{};
    crypto_generichash(pk_hash.data(), 32,
                       ann.peer->public_key.data(),
                       ann.peer->public_key.size(),
                       nullptr, 0);
    const bool announce_self = (pk_hash == *req.target);

    assert(socket_.loop() != nullptr);

    if (announce_self) {
        // JS persistent.js:131-138 — the record is served via the router
        // (relay = req.from, no connection handlers) and removed from the
        // records cache. handle_find_peer resolves it from here.
        if (router_) {
            auto* existing = router_->get(target);
            if (existing && existing->on_peer_handshake) {
                // A locally-listening Server owns this target — keep its
                // handlers, just refresh the served record + relay hint.
                existing->record = std::move(record);
                existing->relay = req.from.addr;
            } else {
                router::ForwardEntry entry;
                entry.record = std::move(record);
                entry.relay = req.from.addr;
                router_->set(target, std::move(entry));
            }
        }
        store_.remove(target, req.from.addr);
    } else {
        // JS persistent.js:140-142 — bump gate. currentBump defaults 0; a
        // bump only sticks if it's strictly greater AND within the wall-clock
        // drift window (guards against a peer stamping a far-future value).
        const uint64_t current_bump = bump_for(target);
        const uint64_t now_wall = wall_clock_ms();
        if (ann.bump > current_bump &&
            ann.bump <= now_wall + MAX_BUMP_DRIFT_MS) {
            bumps_[target] = {ann.bump, uv_now(socket_.loop())};
        }

        // Store the bare record. `ann_ttl_ms_` is plumbed from
        // `DhtOptions::max_age_ms` via `StorageCacheConfig`, matching the JS
        // `persistent.records: { maxAge: opts.maxAge }` pattern in
        // `hyperdht/index.js:607,599`. Defaults to 20 min when the caller
        // leaves the option at its default value.
        announce::PeerAnnouncement stored;
        stored.from = req.from.addr;
        stored.value = std::move(record);
        stored.created_at = uv_now(socket_.loop());
        stored.ttl = ann_ttl_ms_;
        store_.put(target, stored);
    }

    // Reply (JS: { token: false, closerNodes: false })
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    if (!socket_.is_ephemeral() && req.from_server) {
        resp.id = socket_.table().id();
    }

    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// UNANNOUNCE — validate token and remove peer announcement
//
// JS: .analysis/js/hyperdht/lib/persistent.js:53-70 (onunannounce)
//     .analysis/js/hyperdht/lib/persistent.js:45-51 (unannounce helper)
//
// Mirrors JS: removes the AnnounceStore record for this sender AND, when the
// unannouncing key hashes to the target (a self-announce), the relay-only
// router entry that handle_announce created. A locally-listening Server's
// router entry is left untouched (it owns its lifecycle via Server::close()).
// ---------------------------------------------------------------------------

void RpcHandlers::handle_unannounce(const messages::Request& req) {
    if (!req.target.has_value()) return;
    if (!req.token.has_value()) return;

    // Validate token
    if (!socket_.token_store().validate(
            req.from.addr.host_string(), *req.token)) {
        return;
    }

    // Decode the announce message (UNANNOUNCE uses same codec)
    if (!req.value.has_value()) return;
    auto ann = dht_messages::decode_announce_msg(
        req.value->data(), req.value->size());

    // Both peer and signature required for unannounce
    if (!ann.peer.has_value()) return;
    if (!ann.signature.has_value()) return;

    // Verify signature with NS_UNANNOUNCE namespace
    auto node_id = socket_.table().id();
    bool valid = announce_sig::verify_announce(
        dht_messages::ns_unannounce(),
        *req.target, node_id,
        req.token->data(), req.token->size(),
        ann, *ann.signature,
        ann.peer->public_key);

    if (!valid) return;  // Silently drop

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    // JS persistent.js:45-51 (unannounce helper): if the unannouncing key
    // hashes to the target it was a self-announce — drop the router entry
    // that handle_announce created for it. Guard: never remove a locally
    // listening Server's entry (it owns its own lifecycle via Server::close);
    // only relay-only announce entries (no handlers) are cleared here.
    if (router_) {
        std::array<uint8_t, 32> pk_hash{};
        crypto_generichash(pk_hash.data(), 32,
                           ann.peer->public_key.data(),
                           ann.peer->public_key.size(),
                           nullptr, 0);
        if (pk_hash == *req.target) {
            auto* existing = router_->get(target);
            if (existing && !existing->on_peer_handshake) {
                router_->remove(target);
            }
        }
    }

    // Remove the announcement from this sender
    store_.remove(target, req.from.addr);

    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    if (!socket_.is_ephemeral() && req.from_server) {
        resp.id = socket_.table().id();
    }

    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// MUTABLE_PUT — signed key-value storage with seq ordering
//
// JS: .analysis/js/hyperdht/lib/persistent.js:174-205 (onmutableput)
//     .analysis/js/hyperdht/lib/persistent.js:259-267 (verifyMutable)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_mutable_put(const messages::Request& req) {
    if (!req.target.has_value()) return;
    if (!req.token.has_value()) return;
    if (!req.value.has_value()) return;

    // Validate token
    if (!socket_.token_store().validate(
            req.from.addr.host_string(), *req.token)) {
        return;
    }

    // Decode the mutable put request
    auto put = dht_messages::decode_mutable_put(
        req.value->data(), req.value->size());

    // Verify target = BLAKE2b(publicKey)
    std::array<uint8_t, 32> expected_target{};
    crypto_generichash(expected_target.data(), 32,
                       put.public_key.data(), 32,
                       nullptr, 0);
    if (expected_target != *req.target) return;

    // Verify value is non-empty and not too large
    if (put.value.empty()) return;
    constexpr size_t MAX_MUTABLE_VALUE = 32768;  // C16: cap value size
    if (put.value.size() > MAX_MUTABLE_VALUE) return;

    // Verify Ed25519 signature over NS_MUTABLE_PUT + BLAKE2b(seq || value)
    if (!announce_sig::verify_mutable(
            put.signature, put.seq,
            put.value.data(), put.value.size(),
            put.public_key)) {
        return;
    }

    auto key = to_hex_key(*req.target);

    // Check seq ordering against existing record
    auto* existing_ptr = mutables_.get(key);
    if (existing_ptr) {
        auto existing = dht_messages::decode_mutable_get_resp(
            existing_ptr->data(), existing_ptr->size());

        // Same seq but different value → error
        if (existing.seq == put.seq && existing.value != put.value) {
            messages::Response resp;
            resp.tid = req.tid;
            resp.from.addr = req.from.addr;
            resp.error = messages::ERR_SEQ_REUSED;
            socket_.reply(resp, req.from_server);
            return;
        }

        // New seq is lower → error
        if (put.seq < existing.seq) {
            messages::Response resp;
            resp.tid = req.tid;
            resp.from.addr = req.from.addr;
            resp.error = messages::ERR_SEQ_TOO_LOW;
            socket_.reply(resp, req.from_server);
            return;
        }
    }

    // Store as encoded MutableGetResponse
    dht_messages::MutableGetResponse stored;
    stored.seq = put.seq;
    stored.value = put.value;
    stored.signature = put.signature;
    mutables_.put(key, dht_messages::encode_mutable_get_resp(stored),
                  uv_now(socket_.loop()));

    // Reply with no value (success)
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// MUTABLE_GET — return stored mutable value if seq >= requested
//
// JS: .analysis/js/hyperdht/lib/persistent.js:152-172 (onmutableget)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_mutable_get(const messages::Request& req) {
    if (!req.target.has_value()) return;
    if (!req.value.has_value()) return;  // JS: silently drops if no value field

    // Decode requested seq from value (compact-encoded uint)
    uint64_t requested_seq = 0;
    if (!req.value->empty()) {
        compact::State s = compact::State::for_decode(
            req.value->data(), req.value->size());
        requested_seq = compact::Uint::decode(s);
    }

    auto resp = make_query_response(req);

    auto key = to_hex_key(*req.target);
    auto* stored = mutables_.get(key);
    if (stored) {
        auto local = dht_messages::decode_mutable_get_resp(
            stored->data(), stored->size());
        if (local.seq >= requested_seq) {
            resp.value = *stored;
        }
    }

    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// IMMUTABLE_PUT — content-addressed storage (target = BLAKE2b(value))
//
// JS: .analysis/js/hyperdht/lib/persistent.js:216-227 (onimmutableput)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_immutable_put(const messages::Request& req) {
    if (!req.target.has_value()) return;
    if (!req.token.has_value()) return;
    if (!req.value.has_value() || req.value->empty()) return;
    constexpr size_t MAX_IMMUTABLE_VALUE = 32768;  // C15: cap value size
    if (req.value->size() > MAX_IMMUTABLE_VALUE) return;

    // Validate token
    if (!socket_.token_store().validate(
            req.from.addr.host_string(), *req.token)) {
        return;
    }

    // Verify target = BLAKE2b(value)
    std::array<uint8_t, 32> expected_target{};
    crypto_generichash(expected_target.data(), 32,
                       req.value->data(), req.value->size(),
                       nullptr, 0);
    if (expected_target != *req.target) return;

    auto key = to_hex_key(*req.target);
    immutables_.put(key, *req.value, uv_now(socket_.loop()));

    // Reply with no value (success)
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    socket_.reply(resp, req.from_server);
}

// ---------------------------------------------------------------------------
// IMMUTABLE_GET — return stored value by content hash
//
// JS: .analysis/js/hyperdht/lib/persistent.js:207-214 (onimmutableget)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_immutable_get(const messages::Request& req) {
    if (!req.target.has_value()) return;

    auto resp = make_query_response(req);

    auto key = to_hex_key(*req.target);
    auto* stored = immutables_.get(key);
    if (stored) {
        resp.value = *stored;
    }

    socket_.reply(resp, req.from_server);
}

}  // namespace rpc
}  // namespace hyperdht
