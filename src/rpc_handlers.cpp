// DHT RPC request handler implementations — dispatch PING, PING_NAT,
// FIND_NODE, DOWN_HINT, DELAYED_PING (internal) and FIND_PEER, LOOKUP,
// ANNOUNCE, UNANNOUNCE, MUTABLE/IMMUTABLE_GET/PUT (HyperDHT).
//
// JS: .analysis/js/dht-rpc/index.js:632-687 (_onrequest — internal cmds)
//     .analysis/js/hyperdht/lib/persistent.js:16-257 (Persistent class —
//                                                     all HyperDHT cmds)
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

#include <sodium.h>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/debug.hpp"
#include "hyperdht/dht_messages.hpp"

namespace hyperdht {
namespace rpc {

RpcHandlers::RpcHandlers(RpcSocket& socket, router::Router* router,
                         StorageCacheConfig cache_config)
    : socket_(socket),
      router_(router),
      storage_ttl_ms_(cache_config.ttl_ms),
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
}

void RpcHandlers::install() {
    socket_.on_request([this](const messages::Request& req) {
        handle(req);
    });
}

void RpcHandlers::handle(const messages::Request& req) {
    static int req_count = 0;
    if (++req_count <= 5 || !req.internal) {
        DHT_LOG( "  [handlers] req #%d: int=%d cmd=%u from %s:%u\n",
                req_count, req.internal ? 1 : 0, req.command,
                req.from.addr.host_string().c_str(), req.from.addr.port);
    }
    if (req.internal) {
        switch (req.command) {
            case messages::CMD_PING:         handle_ping(req); break;
            case messages::CMD_PING_NAT:     handle_ping_nat(req); break;
            case messages::CMD_FIND_NODE:    handle_find_node(req); break;
            case messages::CMD_DOWN_HINT:    handle_down_hint(req); break;
            case messages::CMD_DELAYED_PING: handle_delayed_ping(req); break;
            default: break;
        }
    } else {
        DHT_LOG( "  [handlers] ext cmd=%u from %s:%u\n",
                req.command, req.from.addr.host_string().c_str(), req.from.addr.port);
        switch (req.command) {
            case messages::CMD_PEER_HANDSHAKE:
                if (router_) {
                    router_->handle_peer_handshake(req,
                        [this](const messages::Response& resp) { socket_.reply(resp); },
                        [this](const messages::Request& req) {
                            auto buf = messages::encode_request(req);
                            socket_.udp_send(buf, req.to.addr);
                        });
                }
                break;
            case messages::CMD_PEER_HOLEPUNCH:
                if (router_) {
                    router_->handle_peer_holepunch(req,
                        [this](const messages::Response& resp) { socket_.reply(resp); },
                        [this](const messages::Request& req) {
                            auto buf = messages::encode_request(req);
                            socket_.udp_send(buf, req.to.addr);
                        });
                }
                break;
            case messages::CMD_FIND_PEER:     handle_find_peer(req); break;
            case messages::CMD_LOOKUP:        handle_lookup(req); break;
            case messages::CMD_ANNOUNCE:      handle_announce(req); break;
            case messages::CMD_UNANNOUNCE:    handle_unannounce(req); break;
            case messages::CMD_MUTABLE_PUT:   handle_mutable_put(req); break;
            case messages::CMD_MUTABLE_GET:   handle_mutable_get(req); break;
            case messages::CMD_IMMUTABLE_PUT: handle_immutable_put(req); break;
            case messages::CMD_IMMUTABLE_GET: handle_immutable_get(req); break;
            default: break;
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: build a response with our ID, token, and closer nodes
//
// JS: .analysis/js/dht-rpc/lib/io.js:485-518 (_sendReply — assembles
//     response with id/token/closerNodes/error/value flags)
// ---------------------------------------------------------------------------

messages::Response RpcHandlers::make_query_response(const messages::Request& req) {
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    resp.id = socket_.table().id();
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

// ---------------------------------------------------------------------------
// PING — reply with our node ID and a token for the sender
//
// JS: .analysis/js/dht-rpc/index.js:640-643 (_onrequest case PING)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_ping(const messages::Request& req) {
    auto resp = make_query_response(req);
    resp.closer_nodes.clear();  // PING doesn't return closer nodes
    socket_.reply(resp);
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

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// FIND_NODE — return the k closest nodes to the target
//
// JS: .analysis/js/dht-rpc/index.js:658-662 (_onrequest case FIND_NODE)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_find_node(const messages::Request& req) {
    auto resp = make_query_response(req);
    socket_.reply(resp);
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
        resp.id = socket_.table().id();
        socket_.reply(resp);
    };

    if (!req.value.has_value() || req.value->size() < 6) {
        // JS drops silently without replying when value is malformed.
        return;
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
        resp.id = dr->owner->socket_.table().id();
        dr->owner->socket_.reply(resp);

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
//     JS only checks `dht._router.get(target).record`. C++ also falls
//     back to the AnnounceStore so we can return any cached peer record
//     even if no Server is locally listening for `target`.
// ---------------------------------------------------------------------------

void RpcHandlers::handle_find_peer(const messages::Request& req) {
    if (!req.target.has_value()) return;

    auto resp = make_query_response(req);

    // Look up the target in our announce store
    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    // Check Router first (self-announcing servers)
    if (router_) {
        const auto* rec = router_->record(target);
        if (rec) {
            resp.value = *rec;
            socket_.reply(resp);
            return;
        }
    }

    // Fall back to announce store
    auto peers = store_.get(target);
    if (!peers.empty()) {
        resp.value = peers.back().value;
    }

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// LOOKUP — return all stored peer records for the target (up to 20)
//
// JS: .analysis/js/hyperdht/lib/persistent.js:26-37 (onlookup)
//     JS uses `records.get(k, 20)` from the record-cache package and
//     wraps in `lookupRawReply { peers, bump }`. We don't track bumps;
//     value is just a varint count + length-prefixed peer records.
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

    if (!peers.empty()) {
        // Encode all peer values as a length-prefixed array.
        // Format: varint(count) + [varint(len) + value_bytes]...
        compact::State state;
        compact::Uint::preencode(state, static_cast<uint64_t>(peers.size()));
        for (const auto& p : peers) {
            compact::Buffer::preencode(state, p.value.data(), p.value.size());
        }

        std::vector<uint8_t> buf(state.end);
        state.buffer = buf.data();
        state.start = 0;

        compact::Uint::encode(state, static_cast<uint64_t>(peers.size()));
        for (const auto& p : peers) {
            compact::Buffer::encode(state, p.value.data(), p.value.size());
        }

        if (!state.error) {
            resp.value = std::move(buf);
        }
    }

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// ANNOUNCE — validate token and store peer announcement
//
// JS: .analysis/js/hyperdht/lib/persistent.js:100-150 (onannounce)
//     .analysis/js/hyperdht/lib/persistent.js:269-284 (annSignable)
//
// C++ diffs from JS:
//   - No `bumps` cache (JS:140-142). We just store the announcement.
//   - No `refresh` cache plumbing (JS:145-147). The refresh-only path
//     replies but doesn't yet hook up `_onrefresh`.
//   - JS treats announceSelf (TMP == target, persistent.js:128) by
//     populating `_router`; C++ uses the AnnounceStore unconditionally.
//   - Relay-address cap of 3 matches JS:121-123.
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
        resp.id = socket_.table().id();
        socket_.reply(resp);
        return;
    }

    // Cap relay addresses at 3 (matches JS persistent.js)
    if (ann.peer->relay_addresses.size() > 3) {
        ann.peer->relay_addresses.resize(3);
    }

    // Signature is required when peer is present
    if (!ann.signature.has_value()) return;

    // Verify Ed25519 signature: signable = NS_ANNOUNCE + BLAKE2b(target || nodeId || token || peer || refresh)
    auto node_id = socket_.table().id();
    bool valid = announce_sig::verify_announce(
        dht_messages::ns_announce(),
        *req.target, node_id,
        req.token->data(), req.token->size(),
        ann, *ann.signature,
        ann.peer->public_key);

    if (!valid) return;  // Silently drop invalid signatures

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    // Store the announcement
    assert(socket_.loop() != nullptr);
    announce::PeerAnnouncement stored;
    stored.from = req.from.addr;
    stored.value = *req.value;
    stored.created_at = uv_now(socket_.loop());
    stored.ttl = announce::DEFAULT_TTL_MS;

    store_.put(target, stored);

    // Reply (JS: { token: false, closerNodes: false })
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    resp.id = socket_.table().id();

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// UNANNOUNCE — validate token and remove peer announcement
//
// JS: .analysis/js/hyperdht/lib/persistent.js:53-70 (onunannounce)
//     .analysis/js/hyperdht/lib/persistent.js:45-51 (unannounce helper)
//
// C++ diffs from JS:
//   - JS removes from `dht._router` if the announcer is the publisher
//     (TMP equals target). C++ only removes from AnnounceStore — the
//     Router entry is removed by Server::close().
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

    // Remove the announcement from this sender
    store_.remove(target, req.from.addr);

    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    resp.id = socket_.table().id();

    socket_.reply(resp);
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

    // Verify value is non-empty
    if (put.value.empty()) return;

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
            socket_.reply(resp);
            return;
        }

        // New seq is lower → error
        if (put.seq < existing.seq) {
            messages::Response resp;
            resp.tid = req.tid;
            resp.from.addr = req.from.addr;
            resp.error = messages::ERR_SEQ_TOO_LOW;
            socket_.reply(resp);
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
    socket_.reply(resp);
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

    socket_.reply(resp);
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
    socket_.reply(resp);
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

    socket_.reply(resp);
}

}  // namespace rpc
}  // namespace hyperdht
