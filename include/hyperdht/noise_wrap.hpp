#pragma once

// Phase 4: Noise IK handshake — Noise_IK_Ed25519_ChaChaPoly_BLAKE2b
// Uses libsodium for all crypto. Ed25519 DH via SHA512 scalar extraction
// + crypto_scalarmult_ed25519_noclamp (NOT standard X25519).

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace hyperdht {
namespace noise {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr size_t HASHLEN = 64;       // BLAKE2b-512 output
constexpr size_t BLOCKLEN = 128;     // BLAKE2b block size (for HMAC)
constexpr size_t DHLEN = 32;         // Ed25519 point size
constexpr size_t PKLEN = 32;         // Public key size
constexpr size_t SKLEN = 64;         // Ed25519 signing secret key (seed || pubkey)
constexpr size_t SEEDLEN = 32;       // Keypair seed size
constexpr size_t KEYLEN = 32;        // Cipher key size
constexpr size_t MACLEN = 16;        // Poly1305 tag size
constexpr size_t NONCELEN = 12;      // ChaCha20-Poly1305 IETF nonce

using Hash = std::array<uint8_t, HASHLEN>;
using Key = std::array<uint8_t, KEYLEN>;
using PubKey = std::array<uint8_t, PKLEN>;
using SecKey = std::array<uint8_t, SKLEN>;
using Seed = std::array<uint8_t, SEEDLEN>;

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

struct Keypair {
    PubKey public_key;
    SecKey secret_key;
};

// Generate Ed25519 signing keypair from seed (deterministic)
Keypair generate_keypair(const Seed& seed);

// Generate Ed25519 signing keypair (random)
Keypair generate_keypair();

// ---------------------------------------------------------------------------
// Low-level crypto primitives (tested individually against JS vectors)
// ---------------------------------------------------------------------------

// BLAKE2b-512(input) → 64-byte hash
Hash blake2b_512(const uint8_t* data, size_t len);

// HMAC-BLAKE2b(key, messages...) — 128-byte block HMAC
// Matches JS: hmac(out, [msg1, msg2, ...], key)
Hash hmac_blake2b(const uint8_t* key, size_t key_len,
                  const uint8_t* const* msgs, const size_t* msg_lens,
                  size_t msg_count);

// Convenience: HMAC with a single message
Hash hmac_blake2b(const uint8_t* key, size_t key_len,
                  const uint8_t* msg, size_t msg_len);

// HKDF Extract-and-Expand → 2 output keys (each HASHLEN bytes)
struct HkdfPair {
    Hash first;   // chaining key
    Hash second;  // derived key
};
HkdfPair hkdf(const uint8_t* salt, size_t salt_len,
              const uint8_t* ikm, size_t ikm_len);

// Ed25519 DH: SHA512(seed) → clamp → scalarmult_ed25519_noclamp
std::array<uint8_t, DHLEN> dh(const Keypair& local, const PubKey& remote);

// ChaCha20-Poly1305 IETF encrypt
// Nonce: 4 zero bytes + LE uint32 counter + 4 zero bytes
std::vector<uint8_t> encrypt(const Key& key, uint64_t counter,
                             const uint8_t* ad, size_t ad_len,
                             const uint8_t* plaintext, size_t pt_len);

// ChaCha20-Poly1305 IETF decrypt
std::optional<std::vector<uint8_t>> decrypt(const Key& key, uint64_t counter,
                                            const uint8_t* ad, size_t ad_len,
                                            const uint8_t* ciphertext, size_t ct_len);

// ---------------------------------------------------------------------------
// CipherState — holds key + nonce counter
// ---------------------------------------------------------------------------

class CipherState {
public:
    CipherState();
    explicit CipherState(const Key& key);

    void initialise_key(const Key& key);
    bool has_key() const;

    // Encrypt with associated data, increments nonce
    std::vector<uint8_t> encrypt_with_ad(const uint8_t* ad, size_t ad_len,
                                         const uint8_t* pt, size_t pt_len);

    // Decrypt with associated data, increments nonce
    std::optional<std::vector<uint8_t>> decrypt_with_ad(const uint8_t* ad, size_t ad_len,
                                                        const uint8_t* ct, size_t ct_len);

private:
    std::optional<Key> key_;
    uint64_t nonce_ = 0;
};

// ---------------------------------------------------------------------------
// SymmetricState — chaining key + digest + cipher
// ---------------------------------------------------------------------------

class SymmetricState {
public:
    SymmetricState();

    void mix_hash(const uint8_t* data, size_t len);
    void mix_key(const PubKey& remote_key, const Keypair& local_key);

    // Encrypt plaintext, update digest with ciphertext
    std::vector<uint8_t> encrypt_and_hash(const uint8_t* pt, size_t pt_len);

    // Decrypt ciphertext, update digest with ciphertext
    std::optional<std::vector<uint8_t>> decrypt_and_hash(const uint8_t* ct, size_t ct_len);

    // Derive final transport keys
    struct SplitKeys {
        Key key1;
        Key key2;
    };
    SplitKeys split() const;

    // Access handshake hash
    Hash get_handshake_hash() const;

    // Direct access for handshake state machine
    Hash digest;
    Hash chaining_key;

private:
    CipherState cipher_;
};

// ---------------------------------------------------------------------------
// NoiseIK — full IK handshake state machine
// ---------------------------------------------------------------------------

class NoiseIK {
public:
    // Construct handshake state
    // initiator: true if we initiate (send msg1)
    // static_kp: our long-term Ed25519 keypair
    // remote_static: their known public key (IK pattern: known before handshake)
    //   - For initiator: required (responder's pubkey)
    //   - For responder: empty (learned from msg1)
    NoiseIK(bool initiator, const Keypair& static_kp,
            const uint8_t* prologue, size_t prologue_len,
            const PubKey* remote_static = nullptr);

    // Write the next handshake message (with optional payload)
    std::vector<uint8_t> send(const uint8_t* payload = nullptr, size_t payload_len = 0);

    // Read and process incoming handshake message, returns payload
    std::optional<std::vector<uint8_t>> recv(const uint8_t* msg, size_t msg_len);

    bool is_complete() const;

    // After handshake completes: transport keys and hash
    Key tx_key() const;
    Key rx_key() const;
    Hash handshake_hash() const;

    // Test-only: inject a fixed ephemeral keypair for deterministic vectors
    void set_ephemeral(const Keypair& ephemeral);

    // Exposed for intermediate state verification in tests
    const SymmetricState& symmetric() const { return symmetric_; }

private:
    bool initiator_;
    bool complete_ = false;
    int message_index_ = 0;  // 0 = msg1, 1 = msg2

    Keypair s_;              // our static keypair
    Keypair e_;              // our ephemeral keypair (generated on first send/recv)
    bool e_generated_ = false;

    PubKey rs_;              // remote static (known for IK initiator, learned for responder)
    PubKey re_;              // remote ephemeral (learned from messages)
    bool rs_known_ = false;

    SymmetricState symmetric_;

    Key tx_;
    Key rx_;
    Hash hash_;
};

}  // namespace noise
}  // namespace hyperdht
