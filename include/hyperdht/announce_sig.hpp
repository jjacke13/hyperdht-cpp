#pragma once

// Announce signature scheme — sign and verify ANNOUNCE/UNANNOUNCE/MUTABLE_PUT.
//
// Signable format (64 bytes):
//   bytes 0-31:  namespace hash (NS_ANNOUNCE, NS_UNANNOUNCE, or NS_MUTABLE_PUT)
//   bytes 32-63: BLAKE2b-256(target || nodeId || token || encoded_peer || refresh)
//
// Signature: Ed25519 detached signature (64 bytes) over the 64-byte signable.

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "hyperdht/dht_messages.hpp"
#include "hyperdht/noise_wrap.hpp"

namespace hyperdht {
namespace announce_sig {

// ---------------------------------------------------------------------------
// Announce/Unannounce signatures
// ---------------------------------------------------------------------------

// Build the 64-byte signable for announce/unannounce verification.
// ns: 32-byte namespace (ns_announce() or ns_unannounce())
// target: 32-byte lookup target
// node_id: 32-byte DHT node routing table ID
// token: token from the DHT response (variable length)
// encoded_peer: the announce's peer field encoded with encode_peer_record()
// refresh: 32-byte refresh token (empty if not present)
std::array<uint8_t, 64> ann_signable(
    const std::array<uint8_t, 32>& ns,
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const uint8_t* token, size_t token_len,
    const uint8_t* encoded_peer, size_t peer_len,
    const uint8_t* refresh, size_t refresh_len);

// Sign an announcement. Returns 64-byte Ed25519 signature.
std::array<uint8_t, 64> sign_announce(
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const uint8_t* token, size_t token_len,
    const dht_messages::AnnounceMessage& ann,
    const noise::Keypair& keypair);

// Sign an unannouncement.
std::array<uint8_t, 64> sign_unannounce(
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const uint8_t* token, size_t token_len,
    const dht_messages::AnnounceMessage& ann,
    const noise::Keypair& keypair);

// Verify an announce/unannounce signature.
bool verify_announce(
    const std::array<uint8_t, 32>& ns,
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const uint8_t* token, size_t token_len,
    const dht_messages::AnnounceMessage& ann,
    const std::array<uint8_t, 64>& signature,
    const std::array<uint8_t, 32>& public_key);

// ---------------------------------------------------------------------------
// Mutable storage signatures
// ---------------------------------------------------------------------------

// Sign a mutable value. Returns 64-byte Ed25519 signature.
std::array<uint8_t, 64> sign_mutable(
    uint64_t seq, const uint8_t* value, size_t value_len,
    const noise::Keypair& keypair);

// Verify a mutable value signature.
bool verify_mutable(
    const std::array<uint8_t, 64>& signature,
    uint64_t seq, const uint8_t* value, size_t value_len,
    const std::array<uint8_t, 32>& public_key);

}  // namespace announce_sig
}  // namespace hyperdht
