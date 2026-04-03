#pragma once

// HyperDHT message codecs — announce, peer record, mutable/immutable storage.
//
// Wire formats (from hyperdht/lib/messages.js):
//
// PeerRecord:     fixed32(publicKey) + ipv4Array(relayAddresses)
//
// AnnounceMessage: uint(flags) + [peer] + [fixed32(refresh)] + [fixed64(signature)] + [uint(bump)]
//   flags: bit0=peer, bit1=refresh, bit2=signature, bit3=bump
//
// MutablePutRequest:  fixed32(publicKey) + uint(seq) + buffer(value) + fixed64(signature)
// MutableGetResponse: uint(seq) + buffer(value) + fixed64(signature)
// MutableSignable:    uint(seq) + buffer(value)
//
// LookupRawReply:     array(raw)(peers) + uint(bump)

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "hyperdht/compact.hpp"

namespace hyperdht {
namespace dht_messages {

// ---------------------------------------------------------------------------
// Namespace hashes — BLAKE2b-256(BLAKE2b-256("hyperswarm/dht") || cmd_byte)
// Precomputed at startup.
// ---------------------------------------------------------------------------

const std::array<uint8_t, 32>& ns_announce();
const std::array<uint8_t, 32>& ns_unannounce();
const std::array<uint8_t, 32>& ns_mutable_put();
const std::array<uint8_t, 32>& ns_peer_handshake();
const std::array<uint8_t, 32>& ns_peer_holepunch();

// ---------------------------------------------------------------------------
// PeerRecord — publicKey + relayAddresses
// ---------------------------------------------------------------------------

struct PeerRecord {
    std::array<uint8_t, 32> public_key{};
    std::vector<compact::Ipv4Address> relay_addresses;
};

std::vector<uint8_t> encode_peer_record(const PeerRecord& p);
PeerRecord decode_peer_record(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// AnnounceMessage — the value field of ANNOUNCE/UNANNOUNCE requests
// ---------------------------------------------------------------------------

struct AnnounceMessage {
    std::optional<PeerRecord> peer;
    std::optional<std::array<uint8_t, 32>> refresh;    // 32-byte refresh token
    std::optional<std::array<uint8_t, 64>> signature;  // 64-byte Ed25519 signature
    uint64_t bump = 0;                                  // 0 = not set
};

std::vector<uint8_t> encode_announce_msg(const AnnounceMessage& m);
AnnounceMessage decode_announce_msg(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// MutablePutRequest — value field of MUTABLE_PUT
// ---------------------------------------------------------------------------

struct MutablePutRequest {
    std::array<uint8_t, 32> public_key{};
    uint64_t seq = 0;
    std::vector<uint8_t> value;
    std::array<uint8_t, 64> signature{};
};

std::vector<uint8_t> encode_mutable_put(const MutablePutRequest& m);
MutablePutRequest decode_mutable_put(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// MutableGetResponse — value field of MUTABLE_GET response
// ---------------------------------------------------------------------------

struct MutableGetResponse {
    uint64_t seq = 0;
    std::vector<uint8_t> value;
    std::array<uint8_t, 64> signature{};
};

std::vector<uint8_t> encode_mutable_get_resp(const MutableGetResponse& m);
MutableGetResponse decode_mutable_get_resp(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// MutableSignable — the data that gets signed for mutable storage
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_mutable_signable(uint64_t seq, const uint8_t* value, size_t len);

// ---------------------------------------------------------------------------
// LookupRawReply — value field of LOOKUP response (array of raw peer records)
// ---------------------------------------------------------------------------

struct LookupRawReply {
    std::vector<std::vector<uint8_t>> peers;  // Raw encoded PeerRecord bytes
    uint64_t bump = 0;
};

std::vector<uint8_t> encode_lookup_reply(const LookupRawReply& r);
LookupRawReply decode_lookup_reply(const uint8_t* data, size_t len);

}  // namespace dht_messages
}  // namespace hyperdht
