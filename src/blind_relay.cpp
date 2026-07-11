// Blind Relay — fallback relay path for connections that can't holepunch.
//
// Implements the "blind-relay" Protomux protocol: message encoding/decoding,
// BlindRelayClient (endpoint side), and BlindRelayServer/Session (relay node).
//
// JS reference: blind-relay/index.js
// See blind_relay.hpp for architecture overview.
//
// Resource limits: pairings_ map capped at 1024 entries (on_pair).
// Session destructor guards channel_ dereference against Mux teardown.

#include "hyperdht/blind_relay.hpp"

#include <sodium.h>

#include <algorithm>
#include <cassert>
#include <cstring>

#include "hyperdht/debug.hpp"

namespace hyperdht {
namespace blind_relay {

// ---------------------------------------------------------------------------
// Encoding helpers — match compact-encoding used by JS blind-relay
// ---------------------------------------------------------------------------

// Varint encode/decode (reuse protomux helpers)
static size_t varint_encode(uint8_t* buf, uint64_t value) {
    return protomux::varint_encode(buf, value);
}
static uint64_t varint_decode(const uint8_t*& ptr, const uint8_t* end) {
    return protomux::varint_decode(ptr, end);
}
static size_t varint_size(uint64_t value) {
    return protomux::varint_size(value);
}

// ---------------------------------------------------------------------------
// Token utilities
// ---------------------------------------------------------------------------

Token generate_token() {
    Token t{};
    randombytes_buf(t.data(), t.size());
    return t;
}

std::string token_hex(const Token& t) {
    std::string hex;
    hex.reserve(64);
    static const char digits[] = "0123456789abcdef";
    for (uint8_t b : t) {
        hex.push_back(digits[b >> 4]);
        hex.push_back(digits[b & 0x0f]);
    }
    return hex;
}

// ---------------------------------------------------------------------------
// Pair message encoding/decoding
// ---------------------------------------------------------------------------
// Wire format:
//   [flags:bitfield(7)] [token:fixed32] [id:uint] [seq:uint]
//
// bitfield(7) = 1 byte, bit 0 = isInitiator
// fixed32 = exactly 32 bytes (no length prefix)
// uint = compact-encoding varint

std::vector<uint8_t> encode_pair(const PairMessage& m) {
    // Calculate size
    size_t size = 1;  // flags byte (bitfield(7) = 1 byte)
    size += 32;       // token (fixed32)
    size += varint_size(m.id);
    size += varint_size(m.seq);

    std::vector<uint8_t> buf(size);
    size_t offset = 0;

    // Flags: bit 0 = isInitiator
    buf[offset++] = m.is_initiator ? 1 : 0;

    // Token: fixed 32 bytes
    std::memcpy(buf.data() + offset, m.token.data(), 32);
    offset += 32;

    // ID: varint
    offset += varint_encode(buf.data() + offset, m.id);

    // Seq: varint
    offset += varint_encode(buf.data() + offset, m.seq);

    buf.resize(offset);
    return buf;
}

// Returns std::nullopt on truncation. JS m.pair.decode reads flags + fixed32
// token + uint id + uint seq; compact-encoding throws (→ protomux teardown) if
// any field underflows. We require all four to be present.
std::optional<PairMessage> decode_pair(const uint8_t* data, size_t len) {
    PairMessage m;
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    // Flags
    if (ptr >= end) return std::nullopt;
    uint8_t flags = *ptr++;
    m.is_initiator = (flags & 1) != 0;

    // Token (fixed 32 bytes)
    if (end - ptr < 32) return std::nullopt;
    std::memcpy(m.token.data(), ptr, 32);
    ptr += 32;

    // ID (varint must be present)
    if (ptr >= end) return std::nullopt;
    m.id = static_cast<uint32_t>(varint_decode(ptr, end));

    // Seq (varint must be present)
    if (ptr >= end) return std::nullopt;
    m.seq = static_cast<uint32_t>(varint_decode(ptr, end));

    return m;
}

// ---------------------------------------------------------------------------
// Unpair message encoding/decoding
// ---------------------------------------------------------------------------
// Wire format:
//   [flags:bitfield(0)] [token:fixed32]
//
// bitfield(0) = 1 byte (empty flags, reserved)

std::vector<uint8_t> encode_unpair(const UnpairMessage& m) {
    std::vector<uint8_t> buf(1 + 32);
    buf[0] = 0;  // empty flags
    std::memcpy(buf.data() + 1, m.token.data(), 32);
    return buf;
}

// Returns std::nullopt on truncation. JS m.unpair.decode reads flags + fixed32
// token; a short buffer throws (→ protomux teardown).
std::optional<UnpairMessage> decode_unpair(const uint8_t* data, size_t len) {
    UnpairMessage m;
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    // Flags
    if (ptr >= end) return std::nullopt;
    ptr++;

    // Token (fixed 32 bytes)
    if (end - ptr < 32) return std::nullopt;
    std::memcpy(m.token.data(), ptr, 32);

    return m;
}

// ---------------------------------------------------------------------------
// BlindRelayClient
// ---------------------------------------------------------------------------

BlindRelayClient::BlindRelayClient(protomux::Channel* channel)
    : channel_(channel), alive_(std::make_shared<bool>(true)) {
    assert(channel_);

    // Register message handlers: type 0 = Pair, type 1 = Unpair
    // JS: this._pair = this._channel.addMessage({ ... onmessage: this._onpair })
    // Use weak_ptr sentinel so callbacks become no-ops after destruction.
    std::weak_ptr<bool> weak_alive = alive_;

    pair_msg_type_ = channel_->add_message({
        [this, weak_alive](const uint8_t* data, size_t len) {
            if (weak_alive.expired()) return;
            on_pair_response(data, len);
        }
    });

    // JS index.js:319-321 — the client registers the unpair message with NO
    // onmessage: inbound unpair is ignored (the type exists only for sending).
    // We register an empty handler to keep the wire message index (1) stable;
    // Channel::dispatch skips handlers whose on_message is empty.
    unpair_msg_type_ = channel_->add_message({});

    // Set up channel lifecycle callbacks
    channel_->on_close = [this, weak_alive]() {
        if (weak_alive.expired()) return;
        closed_ = true;
        // Fail all pending requests
        for (auto& [key, req] : requests_) {
            if (req.on_error) req.on_error(RelayError::CHANNEL_CLOSED);
        }
        requests_.clear();
    };

    channel_->on_destroy = [this, weak_alive]() {
        if (weak_alive.expired()) return;
        destroyed_ = true;
    };
}

BlindRelayClient::~BlindRelayClient() {
    // Invalidate sentinel so any pending callbacks become no-ops
    alive_.reset();
    // Clear channel callbacks to break ref cycles — but only if the
    // channel hasn't already been destroyed by the Mux teardown.
    if (!destroyed_ && channel_) {
        channel_->on_close = nullptr;
        channel_->on_destroy = nullptr;
    }
}

void BlindRelayClient::open(const uint8_t* handshake, size_t handshake_len) {
    if (closed_ || destroyed_) return;
    channel_->open(handshake, handshake_len);
}

void BlindRelayClient::pair(bool is_initiator, const Token& token,
                             uint32_t local_stream_id,
                             OnPairedCb on_paired, OnErrorCb on_error) {
    if (destroyed_) {
        if (on_error) on_error(RelayError::CHANNEL_DESTROYED);
        return;
    }

    auto key = token_hex(token);
    if (requests_.count(key)) {
        // JS: throw ALREADY_PAIRING
        if (on_error) on_error(RelayError::ALREADY_PAIRING);
        return;
    }

    requests_[key] = PairRequest{is_initiator, token, local_stream_id,
                                  std::move(on_paired), std::move(on_error)};

    // Send Pair message
    // JS: client._pair.send({ isInitiator, token, id: stream.id, seq: 0 })
    PairMessage msg;
    msg.is_initiator = is_initiator;
    msg.token = token;
    msg.id = local_stream_id;
    msg.seq = 0;

    auto encoded = encode_pair(msg);
    channel_->send(pair_msg_type_, encoded.data(), encoded.size());

    DHT_LOG("  [blind-relay-client] Sent pair: initiator=%d, token=%s, id=%u\n",
            is_initiator, key.substr(0, 8).c_str(), local_stream_id);
}

void BlindRelayClient::unpair(const Token& token) {
    auto key = token_hex(token);
    auto it = requests_.find(key);
    if (it != requests_.end()) {
        auto req = std::move(it->second);
        requests_.erase(it);
        if (req.on_error) req.on_error(RelayError::PAIRING_CANCELLED);  // PAIRING_CANCELLED
    }

    if (!destroyed_) {
        UnpairMessage msg;
        msg.token = token;
        auto encoded = encode_unpair(msg);
        channel_->send(unpair_msg_type_, encoded.data(), encoded.size());
    }
}

void BlindRelayClient::close() {
    if (closed_) return;
    closed_ = true;
    channel_->close();
}

void BlindRelayClient::destroy() {
    if (destroyed_) return;
    destroyed_ = true;
    // Fail all pending requests
    for (auto& [key, req] : requests_) {
        if (req.on_error) req.on_error(RelayError::DESTROYED);
    }
    requests_.clear();
    channel_->close();
}

// JS: client._onpair(msg) — relay responds with our assigned stream ID
void BlindRelayClient::on_pair_response(const uint8_t* data, size_t len) {
    auto decoded = decode_pair(data, len);
    if (!decoded) {
        // Malformed message. JS: the decode throw tears the connection down.
        channel_->close();
        return;
    }
    const auto& msg = *decoded;
    auto key = token_hex(msg.token);

    auto it = requests_.find(key);
    if (it == requests_.end()) return;

    auto& req = it->second;

    // Validate initiator matches
    if (msg.is_initiator != req.is_initiator) return;

    DHT_LOG("  [blind-relay-client] Pair response: initiator=%d, remote_id=%u\n",
            msg.is_initiator, msg.id);

    // Extract callback before erasing (avoid use-after-move)
    auto on_paired = std::move(req.on_paired);
    requests_.erase(it);

    // msg.id is the relay's stream ID assigned to us
    if (on_paired) on_paired(msg.id);
}

// ---------------------------------------------------------------------------
// BlindRelayServer
// ---------------------------------------------------------------------------

BlindRelayServer::BlindRelayServer(CreateStreamFn create_stream)
    : create_stream_fn(std::move(create_stream)) {}

BlindRelayServer::~BlindRelayServer() {
    // Hard destroy: drop every session immediately. ~BlindRelaySession resets
    // its alive_ sentinel first, so relay stream close callbacks become no-ops
    // and cannot re-enter a half-destroyed session or the server.
    sessions_.clear();
    zombies_.clear();
    pairings_.clear();
}

BlindRelaySession* BlindRelayServer::accept(protomux::Mux* mux,
                                             const std::vector<uint8_t>& channel_id) {
    reap_zombies();  // safe point — no session method on the stack

    auto* channel = mux->create_channel(PROTOCOL_NAME, channel_id, false);
    if (!channel) return nullptr;

    auto session = std::make_unique<BlindRelaySession>(*this, channel);
    auto* ptr = session.get();
    sessions_.push_back(std::move(session));
    ptr->open();
    return ptr;
}

// JS index.js:36-46 — graceful: end() every session and let each drain via its
// pending_close_/endMaybe machinery; clear pairings once they're all gone.
void BlindRelayServer::close() {
    reap_zombies();
    closing_ = true;

    if (sessions_.empty()) {
        pairings_.clear();
        auto cb = on_closed;
        if (cb) cb();
        return;
    }

    // Snapshot raw pointers: a synchronously-draining session self-removes via
    // notify_session_closed (mutating sessions_), so we cannot iterate it live.
    std::vector<BlindRelaySession*> snapshot;
    snapshot.reserve(sessions_.size());
    for (auto& s : sessions_) snapshot.push_back(s.get());
    for (auto* s : snapshot) s->close();

    // Sessions with no in-flight pairing have drained and removed themselves;
    // any left have in-flight pairings and drain later. When the last one goes,
    // notify_session_closed() clears pairings_ and fires on_closed.
}

void BlindRelayServer::notify_session_closed(BlindRelaySession* session) {
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it->get() == session) {
            // Move (do not free) the owning unique_ptr aside — the session is
            // often still on the call stack here. reap_zombies() frees it at a
            // later safe point.
            zombies_.push_back(std::move(*it));
            sessions_.erase(it);
            break;
        }
    }

    if (closing_ && sessions_.empty()) {
        pairings_.clear();
        auto cb = on_closed;
        if (cb) cb();
    }
}

BlindRelayServer::RelayPair& BlindRelayServer::get_or_create_pair(const Token& token) {
    // H25: evict stale unpaired entries (>30s) on each new pair attempt
    constexpr auto PAIRING_TTL = std::chrono::seconds(30);
    auto now = std::chrono::steady_clock::now();
    for (auto it = pairings_.begin(); it != pairings_.end(); ) {
        if (!it->second.paired() && (now - it->second.created_at) > PAIRING_TTL) {
            it = pairings_.erase(it);
        } else {
            ++it;
        }
    }

    auto key = token_hex(token);
    auto it = pairings_.find(key);
    if (it != pairings_.end()) return it->second;

    auto& pair = pairings_[key];
    pair.token = token;
    return pair;
}

void BlindRelayServer::remove_pair(const Token& token) {
    pairings_.erase(token_hex(token));
}

void BlindRelayServer::remove_pair_by_key(const std::string& hex_key) {
    pairings_.erase(hex_key);
}

// ---------------------------------------------------------------------------
// BlindRelaySession
// ---------------------------------------------------------------------------

BlindRelaySession::BlindRelaySession(BlindRelayServer& server,
                                       protomux::Channel* channel)
    : server_(server), channel_(channel), alive_(std::make_shared<bool>(true)) {
    assert(channel_);

    // Register message handlers with weak sentinel for lifetime safety
    std::weak_ptr<bool> weak_alive = alive_;

    pair_msg_type_ = channel_->add_message({
        [this, weak_alive](const uint8_t* data, size_t len) {
            if (weak_alive.expired()) return;
            on_pair(data, len);
        }
    });

    unpair_msg_type_ = channel_->add_message({
        [this, weak_alive](const uint8_t* data, size_t len) {
            if (weak_alive.expired()) return;
            on_unpair(data, len);
        }
    });

    channel_->on_close = [this, weak_alive]() {
        if (weak_alive.expired()) return;
        closed_ = true;
        // Clean up all pairings owned by this session — erase by hex key
        for (const auto& key : pairing_tokens_) {
            server_.remove_pair_by_key(key);
        }
        pairing_tokens_.clear();
        // Destroy all active relay streams. Move the map aside first: a destroy
        // can synchronously fire relay_stream_close_cb → on_stream_closed(key),
        // which erases from streams_ — mutating a map we'd otherwise iterate.
        auto streams = std::move(streams_);
        streams_.clear();
        for (auto& [key, stream] : streams) {
            if (stream) {
                udx_stream_destroy(stream);
            }
        }
        // The channel is closing — it must never be touched again (the Mux
        // frees it after this returns). Null it BEFORE notify_session_closed
        // so neither the zombie-reap path nor ~BlindRelaySession dereferences
        // a dangling Channel* (ASAN heap-UAF, found 2026-07-11).
        channel_ = nullptr;
        // Remove ourselves from the server (JS _onclose: _sessions.delete(this)).
        server_.notify_session_closed(this);
    };

    // Destroy-without-close path (Mux teardown): same dangling-pointer
    // protection as the client session's on_destroy (see ctor above).
    channel_->on_destroy = [this, weak_alive]() {
        if (weak_alive.expired()) return;
        destroyed_ = true;
        channel_ = nullptr;
    };
}

BlindRelaySession::~BlindRelaySession() {
    // Invalidate sentinel so pending callbacks become no-ops
    alive_.reset();
    // H7: guard against dangling channel_ (may have been destroyed by Mux teardown)
    if (!destroyed_ && channel_) {
        channel_->on_close = nullptr;
        channel_->on_destroy = nullptr;
    }
    // Clean up relay streams if not closed via channel close
    for (auto& [key, stream] : streams_) {
        if (stream) {
            udx_stream_destroy(stream);
        }
    }
    streams_.clear();
}

void BlindRelaySession::open() {
    channel_->open();
}

void BlindRelaySession::close() {
    if (closed_) return;
    // JS: end() waits for in-flight pairings. Set pending flag so
    // on_pair can close the channel when the last pairing completes.
    if (pairing_tokens_.empty()) {
        channel_->close();
    } else {
        pending_close_ = true;
    }
}

void BlindRelaySession::destroy() {
    if (destroyed_) return;
    destroyed_ = true;
    channel_->close();
}

// JS: session._onpair(msg) — core matching logic
void BlindRelaySession::on_pair(const uint8_t* data, size_t len) {
    if (closed_) return;

    auto decoded = decode_pair(data, len);
    if (!decoded) {
        // Malformed message. JS: the compact-encoding decode throws, which
        // propagates through protomux and tears the connection down. Mirror it.
        channel_->close();
        return;
    }
    const auto& msg = *decoded;
    auto key = token_hex(msg.token);

    DHT_LOG("  [blind-relay-session] Pair request: initiator=%d, token=%s, id=%u\n",
            msg.is_initiator, key.substr(0, 8).c_str(), msg.id);

    // H25: anti-DoS cap on unpaired entries (JS blind-relay has no cap).
    constexpr size_t MAX_PAIRINGS = 1024;
    if (server_.pairing_count() >= MAX_PAIRINGS) {
        if (!server_.has_pair(key)) return;
    }
    auto& pair = server_.get_or_create_pair(msg.token);

    // Check if this initiator slot is already taken
    // JS index.js:145 — `else if (pair.links[+isInitiator]) return`
    if (pair.has(msg.is_initiator)) {
        DHT_LOG("  [blind-relay-session] Duplicate initiator=%d for token, ignoring\n",
                msg.is_initiator);
        return;
    }

    // Fill in the link
    int idx = msg.is_initiator ? 1 : 0;
    pair.links[idx].session = this;
    pair.links[idx].is_initiator = msg.is_initiator;
    pair.links[idx].remote_id = msg.id;

    pairing_tokens_.insert(key);

    // Check if both sides have arrived
    if (!pair.paired()) {
        DHT_LOG("  [blind-relay-session] Waiting for other side\n");
        return;
    }

    DHT_LOG("  [blind-relay-session] Both sides arrived, setting up relay\n");

    // Remove from server pairings (no longer needed for matching).
    // Copy BEFORE remove — remove_pair invalidates the `pair` reference.
    auto pair_copy = pair;
    server_.remove_pair(pair_copy.token);

    // Pass 1 (JS index.js:155-158 + BlindRelayLink.createStream/_onfirewall):
    // create the relay stream for each link and install the firewall so the
    // relay learns each peer's UDP source on the first inbound packet.
    for (auto& link : pair_copy.links) {
        if (!link.session || !server_.create_stream_fn) {
            for (auto& l : pair_copy.links) {
                if (l.stream) udx_stream_destroy(l.stream);
            }
            DHT_LOG("  [blind-relay-session] No session/create_stream_fn!\n");
            return;
        }
        auto* ctx = new RelayStreamCtx{link.session->alive_, link.session,
                                       key, link.remote_id};
        link.stream = server_.create_stream_fn(&relay_stream_close_cb, ctx);
        if (!link.stream) {
            delete ctx;  // factory failed before taking ownership of ctx
            for (auto& l : pair_copy.links) {
                if (l.stream) udx_stream_destroy(l.stream);
            }
            DHT_LOG("  [blind-relay-session] Failed to create relay stream\n");
            return;
        }
        udx_stream_firewall(link.stream, &relay_firewall_cb);
    }

    // Pass 2 (JS index.js:160-171): wire bidirectional relay and move each link
    // from pending-pairing to active-streams. (Close/error handlers were wired
    // at stream creation via the udx close callback — see finding blind-relay-4.)
    auto* stream_a = pair_copy.links[0].stream;
    auto* stream_b = pair_copy.links[1].stream;

    int err_a = udx_stream_relay_to(stream_a, stream_b);
    int err_b = udx_stream_relay_to(stream_b, stream_a);

    if (err_a < 0 || err_b < 0) {
        DHT_LOG("  [blind-relay-session] udx_stream_relay_to failed: %d, %d\n",
                err_a, err_b);
        udx_stream_destroy(stream_a);
        udx_stream_destroy(stream_b);
        return;
    }

    for (auto& link : pair_copy.links) {
        if (!link.session) continue;
        link.session->pairing_tokens_.erase(key);
        link.session->streams_[key] = link.stream;
    }

    // Pass 3 (JS index.js:173-185): per link — SEND the confirmation, THEN
    // end-maybe (close the channel if end() was requested), THEN emit. The send
    // must precede the close or the confirmation is dropped on a closed channel
    // (finding blind-relay-2). The closed_ guard covers the degenerate case
    // where both links belong to the same session (a sibling may have closed
    // it, freeing channel_).
    for (auto& link : pair_copy.links) {
        if (!link.session || !link.stream || link.session->closed_) continue;

        PairMessage response;
        response.is_initiator = link.is_initiator;
        response.token = pair_copy.token;
        response.id = link.stream->local_id;  // Relay's stream ID for this peer
        response.seq = 0;

        auto encoded = encode_pair(response);
        link.session->channel_->send(
            link.session->pair_msg_type_, encoded.data(), encoded.size());

        DHT_LOG("  [blind-relay-session] Sent pair confirmation: "
                "initiator=%d, relay_stream_id=%u, peer_id=%u\n",
                link.is_initiator, link.stream->local_id, link.remote_id);

        // JS session._endMaybe(): now that this session's pairing completed,
        // close its channel if end() was requested. AFTER the send above.
        if (link.session->pending_close_ && link.session->pairing_tokens_.empty()) {
            link.session->channel_->close();  // may free channel_; don't touch it below
        }

        // Emit pair event (JS emits after endMaybe).
        if (link.session->on_pair_event) {
            link.session->on_pair_event(
                link.is_initiator, pair_copy.token,
                link.stream, link.remote_id);
        }
    }
}

// JS: session._onunpair(msg) — index.js:188-211
void BlindRelaySession::on_unpair(const uint8_t* data, size_t len) {
    auto decoded = decode_unpair(data, len);
    if (!decoded) {
        // Malformed — mirror the JS decode-throw teardown.
        channel_->close();
        return;
    }
    const auto& msg = *decoded;
    auto key = token_hex(msg.token);

    // Cancel a still-pending pairing (JS index.js:191-199) and return, matching
    // JS. Returning also avoids touching channel_ after a possible close().
    if (pairing_tokens_.count(key)) {
        pairing_tokens_.erase(key);
        server_.remove_pair(msg.token);
        // JS: session._endMaybe()
        if (pending_close_ && pairing_tokens_.empty()) {
            channel_->close();
        }
        DHT_LOG("  [blind-relay-session] Unpair (pending): token=%s\n",
                key.substr(0, 8).c_str());
        return;
    }

    // Destroy an active relay stream (JS index.js:201-210). Erase from streams_
    // BEFORE destroy: destroy can synchronously fire relay_stream_close_cb →
    // on_stream_closed(key), which would invalidate an iterator we still hold.
    auto it = streams_.find(key);
    if (it != streams_.end()) {
        auto* stream = it->second;
        streams_.erase(it);
        if (stream) {
            udx_stream_destroy(stream);
        }
    }

    DHT_LOG("  [blind-relay-session] Unpair: token=%s\n", key.substr(0, 8).c_str());
}

// JS: stream.on('close', () => session._streams.delete(keyString)) (index.js:166)
void BlindRelaySession::on_stream_closed(const std::string& key) {
    streams_.erase(key);
}

// ---------------------------------------------------------------------------
// Relay stream udx callbacks (JS BlindRelayLink._onfirewall + stream handlers)
// ---------------------------------------------------------------------------

// JS BlindRelayLink._onfirewall (index.js:276-280): on the first inbound packet
// from an unknown remote, connect the relay stream to that source using the
// peer's stream id, then accept the packet so it is relayed.
int relay_firewall_cb(udx_stream_t* stream, udx_socket_t* socket,
                      const struct sockaddr* from) {
    auto* ctx = static_cast<RelayStreamCtx*>(stream->data);
    if (ctx) {
        udx_stream_connect(stream, socket, ctx->remote_id, from);
    }
    // libudx: non-zero return DROPS the packet, zero ACCEPTS it (relays it).
    // JS returns false → accept. Return 0.
    return 0;
}

// JS stream 'close'/'error' handlers (index.js:164-167). udx folds errors into
// close(status), so this single callback covers both. Drops the stream from its
// session's map and frees the per-stream context.
void relay_stream_close_cb(udx_stream_t* stream, int /*status*/) {
    auto* ctx = static_cast<RelayStreamCtx*>(stream->data);
    if (!ctx) return;
    if (!ctx->session_alive.expired() && ctx->session) {
        ctx->session->on_stream_closed(ctx->key);
    }
    stream->data = nullptr;
    delete ctx;
}

}  // namespace blind_relay
}  // namespace hyperdht
