// Blind Relay — fallback relay path for connections that can't holepunch.
//
// Implements the "blind-relay" Protomux protocol: message encoding/decoding,
// BlindRelayClient (endpoint side), and BlindRelayServer/Session (relay node).
//
// JS reference: blind-relay/index.js
// See blind_relay.hpp for architecture overview.

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

PairMessage decode_pair(const uint8_t* data, size_t len) {
    PairMessage m;
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    if (ptr >= end) return m;

    // Flags
    uint8_t flags = *ptr++;
    m.is_initiator = (flags & 1) != 0;

    // Token
    if (ptr + 32 > end) return m;
    std::memcpy(m.token.data(), ptr, 32);
    ptr += 32;

    // ID
    if (ptr < end) m.id = static_cast<uint32_t>(varint_decode(ptr, end));

    // Seq
    if (ptr < end) m.seq = static_cast<uint32_t>(varint_decode(ptr, end));

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

UnpairMessage decode_unpair(const uint8_t* data, size_t len) {
    UnpairMessage m;
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    if (ptr >= end) return m;

    // Skip flags
    ptr++;

    // Token
    if (ptr + 32 <= end) {
        std::memcpy(m.token.data(), ptr, 32);
    }

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

    unpair_msg_type_ = channel_->add_message({
        [this, weak_alive](const uint8_t* data, size_t len) {
            if (weak_alive.expired()) return;
            on_unpair_response(data, len);
        }
    });

    // Set up channel lifecycle callbacks
    channel_->on_close = [this, weak_alive]() {
        if (weak_alive.expired()) return;
        closed_ = true;
        // Fail all pending requests
        for (auto& [key, req] : requests_) {
            if (req.on_error) req.on_error(-1);
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
    // Clear channel callbacks to break ref cycles
    channel_->on_close = nullptr;
    channel_->on_destroy = nullptr;
}

void BlindRelayClient::open(const uint8_t* handshake, size_t handshake_len) {
    if (closed_ || destroyed_) return;
    channel_->open(handshake, handshake_len);
}

void BlindRelayClient::pair(bool is_initiator, const Token& token,
                             uint32_t local_stream_id,
                             OnPairedCb on_paired, OnErrorCb on_error) {
    if (destroyed_) {
        if (on_error) on_error(-2);
        return;
    }

    auto key = token_hex(token);
    if (requests_.count(key)) {
        // JS: throw ALREADY_PAIRING
        if (on_error) on_error(-3);
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
        if (req.on_error) req.on_error(-4);  // PAIRING_CANCELLED
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
        if (req.on_error) req.on_error(-5);
    }
    requests_.clear();
    channel_->close();
}

// JS: client._onpair(msg) — relay responds with our assigned stream ID
void BlindRelayClient::on_pair_response(const uint8_t* data, size_t len) {
    auto msg = decode_pair(data, len);
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

// JS: client._onunpair(msg)
void BlindRelayClient::on_unpair_response(const uint8_t* data, size_t len) {
    auto msg = decode_unpair(data, len);
    auto key = token_hex(msg.token);

    auto it = requests_.find(key);
    if (it == requests_.end()) return;

    auto req = std::move(it->second);
    requests_.erase(it);

    if (req.on_error) req.on_error(-4);  // PAIRING_CANCELLED
}

// ---------------------------------------------------------------------------
// BlindRelayServer
// ---------------------------------------------------------------------------

BlindRelayServer::BlindRelayServer(CreateStreamFn create_stream)
    : create_stream_fn(std::move(create_stream)) {}

BlindRelayServer::~BlindRelayServer() {
    close();
}

BlindRelaySession* BlindRelayServer::accept(protomux::Mux* mux,
                                             const std::vector<uint8_t>& channel_id) {
    auto* channel = mux->create_channel(PROTOCOL_NAME, channel_id, false);
    if (!channel) return nullptr;

    auto session = std::make_unique<BlindRelaySession>(*this, channel);
    auto* ptr = session.get();
    sessions_.push_back(std::move(session));
    ptr->open();
    return ptr;
}

void BlindRelayServer::close() {
    for (auto& session : sessions_) {
        session->close();
    }
    sessions_.clear();
    pairings_.clear();
}

BlindRelayServer::RelayPair& BlindRelayServer::get_or_create_pair(const Token& token) {
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
        // Destroy all active streams
        for (auto& [key, stream] : streams_) {
            if (stream) {
                udx_stream_destroy(stream);
            }
        }
        pairing_tokens_.clear();
        streams_.clear();
    };
}

BlindRelaySession::~BlindRelaySession() {
    // Invalidate sentinel so pending callbacks become no-ops
    alive_.reset();
    // Clear channel callbacks to break ref cycles
    channel_->on_close = nullptr;
    channel_->on_destroy = nullptr;
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

    auto msg = decode_pair(data, len);
    auto key = token_hex(msg.token);

    DHT_LOG("  [blind-relay-session] Pair request: initiator=%d, token=%s, id=%u\n",
            msg.is_initiator, key.substr(0, 8).c_str(), msg.id);

    auto& pair = server_.get_or_create_pair(msg.token);

    // Check if this initiator slot is already taken
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

    // Remove from server pairings (no longer needed for matching)
    // We take a copy since remove_pair invalidates the reference
    auto pair_copy = pair;
    server_.remove_pair(pair_copy.token);

    // Pass 1: Create relay streams
    // JS: blind-relay/index.js:155-158
    for (auto& link : pair_copy.links) {
        if (!server_.create_stream_fn) {
            DHT_LOG("  [blind-relay-session] No create_stream_fn!\n");
            return;
        }
        link.stream = server_.create_stream_fn();
        if (!link.stream) {
            DHT_LOG("  [blind-relay-session] Failed to create relay stream\n");
            return;
        }
    }

    // Pass 2: Wire bidirectional relay via udx_stream_relay_to()
    // JS: blind-relay/index.js:160-171 — stream.relayTo(remote.stream)
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

    // Track streams in both sessions and check for deferred close
    for (auto& link : pair_copy.links) {
        if (link.session) {
            link.session->pairing_tokens_.erase(key);
            link.session->streams_[key] = link.stream;
            // JS: session._endMaybe() — close channel when all pairings complete
            if (link.session->pending_close_ && link.session->pairing_tokens_.empty()) {
                link.session->channel_->close();
            }
        }
    }

    // Pass 3: Send pair confirmations back to both peers
    // JS: blind-relay/index.js:173-185
    for (auto& link : pair_copy.links) {
        if (!link.session || !link.stream) continue;

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

        // Emit pair event
        if (link.session->on_pair_event) {
            link.session->on_pair_event(
                link.is_initiator, pair_copy.token,
                link.stream, link.remote_id);
        }
    }
}

// JS: session._onunpair(msg)
void BlindRelaySession::on_unpair(const uint8_t* data, size_t len) {
    auto msg = decode_unpair(data, len);
    auto key = token_hex(msg.token);

    // Remove from pairing (if still pending)
    if (pairing_tokens_.count(key)) {
        pairing_tokens_.erase(key);
        server_.remove_pair(msg.token);
        // JS: session._endMaybe()
        if (pending_close_ && pairing_tokens_.empty()) {
            channel_->close();
        }
    }

    // Destroy active stream (if already paired)
    auto it = streams_.find(key);
    if (it != streams_.end()) {
        if (it->second) {
            udx_stream_destroy(it->second);
        }
        streams_.erase(it);
    }

    DHT_LOG("  [blind-relay-session] Unpair: token=%s\n", key.substr(0, 8).c_str());
}

}  // namespace blind_relay
}  // namespace hyperdht
