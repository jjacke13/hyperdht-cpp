// Announce signature implementation — Ed25519 sign/verify over the
// 64-byte signable blob used by ANNOUNCE, UNANNOUNCE and MUTABLE_PUT.
//
// JS: .analysis/js/hyperdht/lib/persistent.js:236-256 (static signMutable
//                                                       / signAnnounce /
//                                                       signUnannounce)
//     .analysis/js/hyperdht/lib/persistent.js:259-267 (verifyMutable)
//     .analysis/js/hyperdht/lib/persistent.js:269-284 (annSignable)
//     .analysis/js/hyperdht/lib/persistent.js:286-294 (sign helper)
//
// C++ diffs from JS:
//   - JS calls `crypto_generichash_batch` over the array
//     [target, id, token, encode(peer), refresh||EMPTY]. C++ uses
//     incremental BLAKE2b via crypto_generichash_init/update/final;
//     equivalent output. Empty refresh is handled by skipping the
//     update call (no-op for hash).

#include "hyperdht/announce_sig.hpp"

#include <sodium.h>

#include <cstring>

namespace hyperdht {
namespace announce_sig {

// ---------------------------------------------------------------------------
// ann_signable — build the 64-byte signable buffer
//
// JS: .analysis/js/hyperdht/lib/persistent.js:269-284 (annSignable)
//
// Layout: [0..32) = namespace, [32..64) = BLAKE2b-256(target || id ||
// token || encoded_peer || refresh).
// ---------------------------------------------------------------------------

std::array<uint8_t, 64> ann_signable(
    const std::array<uint8_t, 32>& ns,
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const uint8_t* token, size_t token_len,
    const uint8_t* encoded_peer, size_t peer_len,
    const uint8_t* refresh, size_t refresh_len) {

    std::array<uint8_t, 64> signable{};

    // Bytes 0-31: namespace
    std::memcpy(signable.data(), ns.data(), 32);

    // Bytes 32-63: BLAKE2b-256(target || node_id || token || encoded_peer || refresh)
    // Use incremental hashing (equivalent to JS crypto_generichash_batch)
    crypto_generichash_state hash_state;
    crypto_generichash_init(&hash_state, nullptr, 0, 32);
    crypto_generichash_update(&hash_state, target.data(), 32);
    crypto_generichash_update(&hash_state, node_id.data(), 32);
    if (token && token_len > 0) {
        crypto_generichash_update(&hash_state, token, token_len);
    }
    if (encoded_peer && peer_len > 0) {
        crypto_generichash_update(&hash_state, encoded_peer, peer_len);
    }
    if (refresh && refresh_len > 0) {
        crypto_generichash_update(&hash_state, refresh, refresh_len);
    }
    // If no refresh: JS passes EMPTY (0-length buffer) which is a no-op for the hash
    crypto_generichash_final(&hash_state, signable.data() + 32, 32);
    sodium_memzero(&hash_state, sizeof(hash_state));  // M4: zero intermediate state

    return signable;
}

// ---------------------------------------------------------------------------
// Helper: build signable from an AnnounceMessage
// ---------------------------------------------------------------------------

static std::array<uint8_t, 64> build_ann_signable(
    const std::array<uint8_t, 32>& ns,
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const uint8_t* token, size_t token_len,
    const dht_messages::AnnounceMessage& ann) {

    // Encode the peer field
    std::vector<uint8_t> encoded_peer;
    if (ann.peer.has_value()) {
        encoded_peer = dht_messages::encode_peer_record(*ann.peer);
    }

    // Refresh field
    const uint8_t* refresh = nullptr;
    size_t refresh_len = 0;
    if (ann.refresh.has_value()) {
        refresh = ann.refresh->data();
        refresh_len = 32;
    }

    return ann_signable(ns, target, node_id,
                        token, token_len,
                        encoded_peer.data(), encoded_peer.size(),
                        refresh, refresh_len);
}

// ---------------------------------------------------------------------------
// Sign announce / unannounce
//
// JS: .analysis/js/hyperdht/lib/persistent.js:250-256 (static
//     signAnnounce / signUnannounce — both call sign(annSignable(...)))
// ---------------------------------------------------------------------------

std::array<uint8_t, 64> sign_announce(
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const uint8_t* token, size_t token_len,
    const dht_messages::AnnounceMessage& ann,
    const noise::Keypair& keypair) {

    auto signable = build_ann_signable(
        dht_messages::ns_announce(), target, node_id, token, token_len, ann);

    std::array<uint8_t, 64> signature{};
    crypto_sign_detached(signature.data(), nullptr,
                         signable.data(), 64,
                         keypair.secret_key.data());
    return signature;
}

std::array<uint8_t, 64> sign_unannounce(
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const uint8_t* token, size_t token_len,
    const dht_messages::AnnounceMessage& ann,
    const noise::Keypair& keypair) {

    auto signable = build_ann_signable(
        dht_messages::ns_unannounce(), target, node_id, token, token_len, ann);

    std::array<uint8_t, 64> signature{};
    crypto_sign_detached(signature.data(), nullptr,
                         signable.data(), 64,
                         keypair.secret_key.data());
    return signature;
}

// ---------------------------------------------------------------------------
// Verify announce / unannounce
//
// JS: .analysis/js/hyperdht/lib/persistent.js:64 (onunannounce verify)
//     .analysis/js/hyperdht/lib/persistent.js:115 (onannounce verify)
//     Both use `crypto_sign_verify_detached(signature, signable, peer.publicKey)`.
// ---------------------------------------------------------------------------

bool verify_announce(
    const std::array<uint8_t, 32>& ns,
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const uint8_t* token, size_t token_len,
    const dht_messages::AnnounceMessage& ann,
    const std::array<uint8_t, 64>& signature,
    const std::array<uint8_t, 32>& public_key) {

    auto signable = build_ann_signable(ns, target, node_id, token, token_len, ann);

    return crypto_sign_verify_detached(
        signature.data(), signable.data(), 64, public_key.data()) == 0;
}

// ---------------------------------------------------------------------------
// Mutable storage signatures
//
// JS: .analysis/js/hyperdht/lib/persistent.js:236-244 (static signMutable)
//     .analysis/js/hyperdht/lib/persistent.js:259-267 (verifyMutable)
//
// Layout: [0..32) = NS_MUTABLE_PUT, [32..64) = BLAKE2b-256(encode(
// mutableSignable, {seq, value})).
// ---------------------------------------------------------------------------

static std::array<uint8_t, 64> mutable_signable(
    uint64_t seq, const uint8_t* value, size_t value_len) {

    std::array<uint8_t, 64> signable{};

    // Bytes 0-31: NS_MUTABLE_PUT
    std::memcpy(signable.data(), dht_messages::ns_mutable_put().data(), 32);

    // Bytes 32-63: BLAKE2b-256(encode(mutableSignable, {seq, value}))
    auto encoded = dht_messages::encode_mutable_signable(seq, value, value_len);
    crypto_generichash(signable.data() + 32, 32,
                       encoded.data(), encoded.size(),
                       nullptr, 0);

    return signable;
}

std::array<uint8_t, 64> sign_mutable(
    uint64_t seq, const uint8_t* value, size_t value_len,
    const noise::Keypair& keypair) {

    auto signable = mutable_signable(seq, value, value_len);

    std::array<uint8_t, 64> signature{};
    crypto_sign_detached(signature.data(), nullptr,
                         signable.data(), 64,
                         keypair.secret_key.data());
    return signature;
}

bool verify_mutable(
    const std::array<uint8_t, 64>& signature,
    uint64_t seq, const uint8_t* value, size_t value_len,
    const std::array<uint8_t, 32>& public_key) {

    auto signable = mutable_signable(seq, value, value_len);

    return crypto_sign_verify_detached(
        signature.data(), signable.data(), 64, public_key.data()) == 0;
}

}  // namespace announce_sig
}  // namespace hyperdht
