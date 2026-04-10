// HyperDHT message codecs — encode/decode for announce records,
// peer records, and mutable/immutable storage values. Wire-compatible
// with hyperdht/lib/messages.js.

#include "hyperdht/dht_messages.hpp"

#include <sodium.h>

#include <cstring>

namespace hyperdht {
namespace dht_messages {

using compact::State;
using compact::Uint;
using compact::Buffer;
using compact::Fixed32;
using compact::Fixed64;
using compact::Ipv4Addr;
using compact::Ipv4Address;
using compact::Array;

// ---------------------------------------------------------------------------
// Namespace hashes — BLAKE2b-256(BLAKE2b-256("hyperswarm/dht") || cmd_byte)
// ---------------------------------------------------------------------------

static std::array<uint8_t, 32> compute_ns(uint8_t cmd_byte) {
    // Step 1: BLAKE2b-256("hyperswarm/dht")
    uint8_t ns_hash[32];
    const char* name = "hyperswarm/dht";
    crypto_generichash(ns_hash, 32,
                       reinterpret_cast<const uint8_t*>(name), std::strlen(name),
                       nullptr, 0);

    // Step 2: BLAKE2b-256(ns_hash || cmd_byte)
    uint8_t ns_input[33];
    std::memcpy(ns_input, ns_hash, 32);
    ns_input[32] = cmd_byte;

    std::array<uint8_t, 32> result{};
    crypto_generichash(result.data(), 32, ns_input, 33, nullptr, 0);
    return result;
}

// Lazy-initialized static instances
const std::array<uint8_t, 32>& ns_announce() {
    static auto ns = compute_ns(4);  // CMD_ANNOUNCE
    return ns;
}

const std::array<uint8_t, 32>& ns_unannounce() {
    static auto ns = compute_ns(5);  // CMD_UNANNOUNCE
    return ns;
}

const std::array<uint8_t, 32>& ns_mutable_put() {
    static auto ns = compute_ns(6);  // CMD_MUTABLE_PUT
    return ns;
}

const std::array<uint8_t, 32>& ns_peer_handshake() {
    static auto ns = compute_ns(0);  // CMD_PEER_HANDSHAKE
    return ns;
}

const std::array<uint8_t, 32>& ns_peer_holepunch() {
    static auto ns = compute_ns(1);  // CMD_PEER_HOLEPUNCH
    return ns;
}

// ---------------------------------------------------------------------------
// PeerRecord
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_peer_record(const PeerRecord& p) {
    State state;
    Fixed32::preencode(state, p.public_key);
    Array<Ipv4Addr, Ipv4Address>::preencode(state, p.relay_addresses);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Fixed32::encode(state, p.public_key);
    Array<Ipv4Addr, Ipv4Address>::encode(state, p.relay_addresses);
    return buf;
}

PeerRecord decode_peer_record(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    PeerRecord p;

    p.public_key = Fixed32::decode(state);
    if (state.error) return p;
    p.relay_addresses = Array<Ipv4Addr, Ipv4Address>::decode(state);
    return p;
}

// ---------------------------------------------------------------------------
// AnnounceMessage
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_announce_msg(const AnnounceMessage& m) {
    uint8_t flags = 0;
    if (m.peer.has_value()) flags |= 1;
    if (m.refresh.has_value()) flags |= 2;
    if (m.signature.has_value()) flags |= 4;
    if (m.bump > 0) flags |= 8;

    State state;
    Uint::preencode(state, flags);
    if (m.peer.has_value()) {
        Fixed32::preencode(state, m.peer->public_key);
        Array<Ipv4Addr, Ipv4Address>::preencode(state, m.peer->relay_addresses);
    }
    if (m.refresh.has_value()) Fixed32::preencode(state, *m.refresh);
    if (m.signature.has_value()) Fixed64::preencode(state, *m.signature);
    if (m.bump > 0) Uint::preencode(state, m.bump);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, flags);
    if (m.peer.has_value()) {
        Fixed32::encode(state, m.peer->public_key);
        Array<Ipv4Addr, Ipv4Address>::encode(state, m.peer->relay_addresses);
    }
    if (m.refresh.has_value()) Fixed32::encode(state, *m.refresh);
    if (m.signature.has_value()) Fixed64::encode(state,*m.signature);
    if (m.bump > 0) Uint::encode(state, m.bump);

    return buf;
}

AnnounceMessage decode_announce_msg(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    AnnounceMessage m;

    uint8_t flags = static_cast<uint8_t>(Uint::decode(state));
    if (state.error) return m;

    if (flags & 1) {
        PeerRecord peer;
        peer.public_key = Fixed32::decode(state);
        if (state.error) return m;
        peer.relay_addresses = Array<Ipv4Addr, Ipv4Address>::decode(state);
        if (state.error) return m;
        m.peer = std::move(peer);
    }
    if (flags & 2) {
        m.refresh = Fixed32::decode(state);
        if (state.error) return m;
    }
    if (flags & 4) {
        m.signature = Fixed64::decode(state);
        if (state.error) return m;
    }
    if (flags & 8) {
        m.bump = Uint::decode(state);
        if (state.error) return m;
    }

    return m;
}

// ---------------------------------------------------------------------------
// MutablePutRequest
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_mutable_put(const MutablePutRequest& m) {
    State state;
    Fixed32::preencode(state, m.public_key);
    Uint::preencode(state, m.seq);
    Buffer::preencode(state, m.value.data(), m.value.size());
    Fixed64::preencode(state, m.signature);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Fixed32::encode(state, m.public_key);
    Uint::encode(state, m.seq);
    Buffer::encode(state, m.value.data(), m.value.size());
    Fixed64::encode(state,m.signature);

    return buf;
}

MutablePutRequest decode_mutable_put(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    MutablePutRequest m;

    m.public_key = Fixed32::decode(state);
    if (state.error) return m;
    m.seq = Uint::decode(state);
    if (state.error) return m;

    auto val = Buffer::decode(state);
    if (state.error) return m;
    if (!val.is_null()) {
        m.value.assign(val.data, val.data + val.len);
    }

    m.signature = Fixed64::decode(state);
    if (state.error) return m;
    return m;
}

// ---------------------------------------------------------------------------
// MutableGetResponse
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_mutable_get_resp(const MutableGetResponse& m) {
    State state;
    Uint::preencode(state, m.seq);
    Buffer::preencode(state, m.value.data(), m.value.size());
    Fixed64::preencode(state, m.signature);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, m.seq);
    Buffer::encode(state, m.value.data(), m.value.size());
    Fixed64::encode(state,m.signature);

    return buf;
}

MutableGetResponse decode_mutable_get_resp(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    MutableGetResponse m;

    m.seq = Uint::decode(state);
    if (state.error) return m;

    auto val = Buffer::decode(state);
    if (state.error) return m;
    if (!val.is_null()) {
        m.value.assign(val.data, val.data + val.len);
    }

    m.signature = Fixed64::decode(state);
    if (state.error) return m;
    return m;
}

// ---------------------------------------------------------------------------
// MutableSignable — the data that gets hashed then signed
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_mutable_signable(uint64_t seq, const uint8_t* value, size_t len) {
    State state;
    Uint::preencode(state, seq);
    Buffer::preencode(state, value, len);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, seq);
    Buffer::encode(state, value, len);

    return buf;
}

// ---------------------------------------------------------------------------
// LookupRawReply
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_lookup_reply(const LookupRawReply& r) {
    State state;

    // Array of raw buffers: varint(count) + [buffer, buffer, ...]
    Uint::preencode(state, static_cast<uint64_t>(r.peers.size()));
    for (const auto& peer : r.peers) {
        Buffer::preencode(state, peer.data(), peer.size());
    }
    Uint::preencode(state, r.bump);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, static_cast<uint64_t>(r.peers.size()));
    for (const auto& peer : r.peers) {
        Buffer::encode(state, peer.data(), peer.size());
    }
    Uint::encode(state, r.bump);

    return buf;
}

LookupRawReply decode_lookup_reply(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    LookupRawReply r;

    uint64_t count = Uint::decode(state);
    if (state.error || count > 1024) return r;  // Cap at 1024 (20 per target * safety margin)
    r.peers.reserve(static_cast<size_t>(count));

    for (uint64_t i = 0; i < count && !state.error; i++) {
        auto buf = Buffer::decode(state);
        if (state.error) return r;
        if (!buf.is_null()) {
            r.peers.emplace_back(buf.data, buf.data + buf.len);
        }
    }

    // bump is optional — 0 if past end
    if (state.start < state.end) {
        r.bump = Uint::decode(state);
    }

    return r;
}

}  // namespace dht_messages
}  // namespace hyperdht
