// Noise IK handshake implementation — initiator/responder state machines
// for Noise_IK_Ed25519_ChaChaPoly_BLAKE2b. All crypto via libsodium;
// Ed25519 DH uses SHA512 scalar extraction + crypto_scalarmult_ed25519_noclamp.

#include "hyperdht/noise_wrap.hpp"

#include <sodium.h>

#include <algorithm>
#include <cassert>
#include <cstring>

namespace hyperdht {
namespace noise {

// Protocol name determines initial hash — must match JS exactly
static constexpr const char* PROTOCOL_NAME = "Noise_IK_Ed25519_ChaChaPoly_BLAKE2b";

// ---------------------------------------------------------------------------
// Keypair generation
// ---------------------------------------------------------------------------

Keypair generate_keypair(const Seed& seed) {
    Keypair kp;
    crypto_sign_seed_keypair(kp.public_key.data(), kp.secret_key.data(), seed.data());
    return kp;
}

Keypair generate_keypair() {
    Keypair kp;
    crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data());
    return kp;
}

// ---------------------------------------------------------------------------
// BLAKE2b-512
// ---------------------------------------------------------------------------

Hash blake2b_512(const uint8_t* data, size_t len) {
    Hash out{};
    crypto_generichash(out.data(), HASHLEN, data, len, nullptr, 0);
    return out;
}

// ---------------------------------------------------------------------------
// HMAC-BLAKE2b (128-byte block)
// Matches JS: crypto_generichash_batch(out, [InnerKeyPad, ...msgs])
//             crypto_generichash_batch(out, [OuterKeyPad, out])
// ---------------------------------------------------------------------------

Hash hmac_blake2b(const uint8_t* key, size_t key_len,
                  const uint8_t* const* msgs, const size_t* msg_lens,
                  size_t msg_count) {
    // Prepare HMAC key (pad or hash to BLOCKLEN)
    uint8_t hmac_key[BLOCKLEN] = {};
    if (key_len > BLOCKLEN) {
        crypto_generichash(hmac_key, HASHLEN, key, key_len, nullptr, 0);
    } else {
        std::memcpy(hmac_key, key, key_len);
    }

    uint8_t inner_pad[BLOCKLEN];
    uint8_t outer_pad[BLOCKLEN];
    for (size_t i = 0; i < BLOCKLEN; i++) {
        inner_pad[i] = 0x36 ^ hmac_key[i];
        outer_pad[i] = 0x5c ^ hmac_key[i];
    }
    sodium_memzero(hmac_key, BLOCKLEN);

    // Inner hash: BLAKE2b(InnerKeyPad || msg1 || msg2 || ...)
    Hash inner_hash{};
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, HASHLEN);
    crypto_generichash_update(&state, inner_pad, BLOCKLEN);
    for (size_t i = 0; i < msg_count; i++) {
        crypto_generichash_update(&state, msgs[i], msg_lens[i]);
    }
    crypto_generichash_final(&state, inner_hash.data(), HASHLEN);
    sodium_memzero(&state, sizeof(state));
    sodium_memzero(inner_pad, BLOCKLEN);

    // Outer hash: BLAKE2b(OuterKeyPad || inner_hash)
    Hash out{};
    crypto_generichash_init(&state, nullptr, 0, HASHLEN);
    crypto_generichash_update(&state, outer_pad, BLOCKLEN);
    crypto_generichash_update(&state, inner_hash.data(), HASHLEN);
    crypto_generichash_final(&state, out.data(), HASHLEN);
    sodium_memzero(&state, sizeof(state));
    sodium_memzero(outer_pad, BLOCKLEN);

    return out;
}

Hash hmac_blake2b(const uint8_t* key, size_t key_len,
                  const uint8_t* msg, size_t msg_len) {
    const uint8_t* msgs[] = {msg};
    size_t lens[] = {msg_len};
    return hmac_blake2b(key, key_len, msgs, lens, 1);
}

// ---------------------------------------------------------------------------
// HKDF Extract-and-Expand
// ---------------------------------------------------------------------------

HkdfPair hkdf(const uint8_t* salt, size_t salt_len,
              const uint8_t* ikm, size_t ikm_len) {
    // Extract: PRK = HMAC(salt, ikm)
    auto prk = hmac_blake2b(salt, salt_len, ikm, ikm_len);

    // Expand iteration 1: T1 = HMAC(PRK, 0x01)
    // JS: prev = empty_info, then HMAC(key, [prev, info, counter])
    // With empty info: HMAC(PRK, [empty, empty, 0x01]) = HMAC(PRK, 0x01)
    uint8_t counter1[] = {0x01};
    uint8_t empty[] = {};
    const uint8_t* msgs1[] = {empty, empty, counter1};
    size_t lens1[] = {0, 0, 1};
    auto t1 = hmac_blake2b(prk.data(), HASHLEN, msgs1, lens1, 3);

    // Expand iteration 2: T2 = HMAC(PRK, T1 || 0x02)
    uint8_t counter2[] = {0x02};
    const uint8_t* msgs2[] = {t1.data(), empty, counter2};
    size_t lens2[] = {HASHLEN, 0, 1};
    auto t2 = hmac_blake2b(prk.data(), HASHLEN, msgs2, lens2, 3);

    return {t1, t2};
}

// ---------------------------------------------------------------------------
// Ed25519 DH
// ---------------------------------------------------------------------------

std::array<uint8_t, DHLEN> dh(const Keypair& local, const PubKey& remote) {
    // Extract scalar: SHA512(seed) → take lower 32 bytes → clamp
    uint8_t sk_full[64];
    crypto_hash_sha512(sk_full, local.secret_key.data(), SEEDLEN);

    // Only the lower 32 bytes are the scalar (Ed25519 convention)
    uint8_t scalar[32];
    std::memcpy(scalar, sk_full, 32);
    sodium_memzero(sk_full, sizeof(sk_full));

    // Clamp (same as JS noise-curve-ed)
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    std::array<uint8_t, DHLEN> out{};
    if (crypto_scalarmult_ed25519_noclamp(out.data(), scalar, remote.data()) != 0) {
        // Low-order point attack — DH result would be zero
        sodium_memzero(scalar, sizeof(scalar));
        sodium_memzero(out.data(), DHLEN);
        return out;  // Return zeroed output; callers must check
    }

    sodium_memzero(scalar, sizeof(scalar));
    return out;
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 IETF
// ---------------------------------------------------------------------------

static void build_nonce(uint8_t nonce[NONCELEN], uint64_t counter) {
    // JS: 12 bytes all zero, then setUint32(4, counter, true)
    // Layout: [0,0,0,0, counter_LE32, 0,0,0,0]
    std::memset(nonce, 0, NONCELEN);
    auto c = static_cast<uint32_t>(counter);
    nonce[4] = static_cast<uint8_t>(c);
    nonce[5] = static_cast<uint8_t>(c >> 8);
    nonce[6] = static_cast<uint8_t>(c >> 16);
    nonce[7] = static_cast<uint8_t>(c >> 24);
}

std::vector<uint8_t> encrypt(const Key& key, uint64_t counter,
                             const uint8_t* ad, size_t ad_len,
                             const uint8_t* plaintext, size_t pt_len) {
    uint8_t nonce[NONCELEN];
    build_nonce(nonce, counter);

    std::vector<uint8_t> ct(pt_len + MACLEN);
    unsigned long long ct_len = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ct.data(), &ct_len,
        plaintext, pt_len,
        ad, ad_len,
        nullptr, nonce, key.data());
    ct.resize(static_cast<size_t>(ct_len));
    return ct;
}

std::optional<std::vector<uint8_t>> decrypt(const Key& key, uint64_t counter,
                                            const uint8_t* ad, size_t ad_len,
                                            const uint8_t* ciphertext, size_t ct_len) {
    if (ct_len < MACLEN) return std::nullopt;

    uint8_t nonce[NONCELEN];
    build_nonce(nonce, counter);

    std::vector<uint8_t> pt(ct_len - MACLEN);
    unsigned long long pt_len = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        pt.data(), &pt_len,
        nullptr,
        ciphertext, ct_len,
        ad, ad_len,
        nonce, key.data());
    if (rc != 0) return std::nullopt;
    pt.resize(static_cast<size_t>(pt_len));
    return pt;
}

// ---------------------------------------------------------------------------
// CipherState
// ---------------------------------------------------------------------------

CipherState::CipherState() = default;

CipherState::CipherState(const Key& key) : key_(key), nonce_(0) {}

void CipherState::initialise_key(const Key& key) {
    key_ = key;
    nonce_ = 0;
}

bool CipherState::has_key() const { return key_.has_value(); }

std::vector<uint8_t> CipherState::encrypt_with_ad(const uint8_t* ad, size_t ad_len,
                                                   const uint8_t* pt, size_t pt_len) {
    if (!has_key()) {
        return std::vector<uint8_t>(pt, pt + pt_len);
    }
    auto ct = noise::encrypt(*key_, nonce_, ad, ad_len, pt, pt_len);
    nonce_++;
    return ct;
}

std::optional<std::vector<uint8_t>> CipherState::decrypt_with_ad(const uint8_t* ad, size_t ad_len,
                                                                  const uint8_t* ct, size_t ct_len) {
    if (!has_key()) {
        return std::vector<uint8_t>(ct, ct + ct_len);
    }
    auto pt = noise::decrypt(*key_, nonce_, ad, ad_len, ct, ct_len);
    if (pt) nonce_++;  // Only advance on successful decryption
    return pt;
}

// ---------------------------------------------------------------------------
// SymmetricState
// ---------------------------------------------------------------------------

SymmetricState::SymmetricState() {
    digest.fill(0);
    chaining_key.fill(0);
}

void SymmetricState::mix_hash(const uint8_t* data, size_t len) {
    // h = BLAKE2b(h || data)
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, HASHLEN);
    crypto_generichash_update(&state, digest.data(), HASHLEN);
    crypto_generichash_update(&state, data, len);
    crypto_generichash_final(&state, digest.data(), HASHLEN);
    sodium_memzero(&state, sizeof(state));
}

void SymmetricState::mix_key(const PubKey& remote_key, const Keypair& local_key) {
    auto dh_result = dh(local_key, remote_key);
    auto [ck, temp_k] = hkdf(chaining_key.data(), HASHLEN,
                              dh_result.data(), DHLEN);
    chaining_key = ck;
    Key cipher_key;
    std::copy_n(temp_k.data(), KEYLEN, cipher_key.data());
    cipher_.initialise_key(cipher_key);
}

std::vector<uint8_t> SymmetricState::encrypt_and_hash(const uint8_t* pt, size_t pt_len) {
    auto ct = cipher_.encrypt_with_ad(digest.data(), HASHLEN, pt, pt_len);
    mix_hash(ct.data(), ct.size());
    return ct;
}

std::optional<std::vector<uint8_t>> SymmetricState::decrypt_and_hash(const uint8_t* ct, size_t ct_len) {
    auto pt = cipher_.decrypt_with_ad(digest.data(), HASHLEN, ct, ct_len);
    // Per Noise spec: always mix ciphertext into h, even on auth failure
    mix_hash(ct, ct_len);
    return pt;
}

SymmetricState::SplitKeys SymmetricState::split() const {
    uint8_t empty[] = {};
    auto [h1, h2] = hkdf(chaining_key.data(), HASHLEN, empty, 0);
    SplitKeys keys;
    std::copy_n(h1.data(), KEYLEN, keys.key1.data());
    std::copy_n(h2.data(), KEYLEN, keys.key2.data());
    return keys;
}

Hash SymmetricState::get_handshake_hash() const {
    return digest;
}

// ---------------------------------------------------------------------------
// NoiseIK — IK pattern:
//   pre-message: ← s
//   msg1 (→): e, es, s, ss
//   msg2 (←): e, ee, se
// ---------------------------------------------------------------------------

NoiseIK::NoiseIK(bool initiator, const Keypair& static_kp,
                 const uint8_t* prologue, size_t prologue_len,
                 const PubKey* remote_static)
    : initiator_(initiator), s_(static_kp) {

    // Initialize symmetric state with protocol name
    size_t pn_len = std::strlen(PROTOCOL_NAME);
    // Protocol name fits in HASHLEN (35 < 64), so pad with zeros
    symmetric_.digest.fill(0);
    std::memcpy(symmetric_.digest.data(), PROTOCOL_NAME, pn_len);
    symmetric_.chaining_key = symmetric_.digest;

    // MixHash(prologue)
    symmetric_.mix_hash(prologue, prologue_len);

    // IK pre-message: responder's static key is pre-shared
    // Both sides MixHash the responder's public key
    if (initiator_) {
        // Initiator knows remote static (responder's pubkey)
        assert(remote_static != nullptr);
        rs_ = *remote_static;
        rs_known_ = true;
        symmetric_.mix_hash(rs_.data(), PKLEN);
    } else {
        // Responder MixHash-es its own static pubkey
        symmetric_.mix_hash(s_.public_key.data(), PKLEN);
        // rs_ will be learned from msg1
    }
}

std::vector<uint8_t> NoiseIK::send(const uint8_t* payload, size_t payload_len) {
    if (complete_ || corrupt_) return {};  // Handshake done or corrupted
    // Validate send order: initiator sends msg0, responder sends msg1
    if (message_index_ == 0 && !initiator_) return {};
    if (message_index_ == 1 && initiator_) return {};

    std::vector<uint8_t> out;

    if (message_index_ == 0 && initiator_) {
        // Message 1 (initiator → responder): e, es, s, ss

        // e: generate ephemeral, MixHash, send pubkey
        if (!e_generated_) {
            e_ = generate_keypair();
            e_generated_ = true;
        }
        symmetric_.mix_hash(e_.public_key.data(), PKLEN);
        out.insert(out.end(), e_.public_key.begin(), e_.public_key.end());

        // es: DH(e, rs) → MixKey
        symmetric_.mix_key(rs_, e_);

        // s: encrypt our static pubkey and send
        auto enc_s = symmetric_.encrypt_and_hash(
            s_.public_key.data(), PKLEN);
        out.insert(out.end(), enc_s.begin(), enc_s.end());

        // ss: DH(s, rs) → MixKey
        symmetric_.mix_key(rs_, s_);

    } else if (message_index_ == 1 && !initiator_) {
        // Message 2 (responder → initiator): e, ee, se

        // e: generate ephemeral, MixHash, send pubkey
        if (!e_generated_) {
            e_ = generate_keypair();
            e_generated_ = true;
        }
        symmetric_.mix_hash(e_.public_key.data(), PKLEN);
        out.insert(out.end(), e_.public_key.begin(), e_.public_key.end());

        // ee: DH(e, re) → MixKey
        symmetric_.mix_key(re_, e_);

        // se: DH(e, rs) → MixKey
        // SE = DH(initiator_static, responder_ephemeral)
        // Responder computes: scalarmult(responder_e_scalar, initiator_s_pubkey)
        symmetric_.mix_key(rs_, e_);
    }

    // Encrypt payload
    auto enc_payload = symmetric_.encrypt_and_hash(
        payload ? payload : nullptr,
        payload ? payload_len : 0);
    out.insert(out.end(), enc_payload.begin(), enc_payload.end());

    message_index_++;

    // Check if handshake is done
    if (message_index_ >= 2) {
        auto [k1, k2] = symmetric_.split();
        tx_ = initiator_ ? k1 : k2;
        rx_ = initiator_ ? k2 : k1;
        hash_ = symmetric_.get_handshake_hash();
        complete_ = true;
    }

    return out;
}

std::optional<std::vector<uint8_t>> NoiseIK::recv(const uint8_t* msg, size_t msg_len) {
    if (complete_ || corrupt_) return std::nullopt;  // Handshake done or corrupted
    // Validate recv order: responder receives msg0, initiator receives msg1
    if (message_index_ == 0 && initiator_) return std::nullopt;
    if (message_index_ == 1 && !initiator_) return std::nullopt;

    size_t offset = 0;

    auto shift = [&](size_t n) -> const uint8_t* {
        if (offset + n > msg_len) return nullptr;
        const uint8_t* ptr = msg + offset;
        offset += n;
        return ptr;
    };

    if (message_index_ == 0 && !initiator_) {
        // Receive Message 1 (responder side): e, es, s, ss

        // e: read ephemeral pubkey
        auto e_data = shift(PKLEN);
        if (!e_data) return std::nullopt;
        std::copy_n(e_data, PKLEN, re_.data());
        symmetric_.mix_hash(re_.data(), PKLEN);

        // es: DH(s, re) — responder uses static key with remote ephemeral
        symmetric_.mix_key(re_, s_);

        // s: decrypt remote static pubkey
        size_t enc_s_len = PKLEN + MACLEN;  // 32 + 16 = 48
        auto enc_s_data = shift(enc_s_len);
        if (!enc_s_data) return std::nullopt;
        auto dec_s = symmetric_.decrypt_and_hash(enc_s_data, enc_s_len);
        if (!dec_s) return std::nullopt;
        std::copy_n(dec_s->data(), PKLEN, rs_.data());
        rs_known_ = true;

        // ss: DH(s, rs) — both static keys
        symmetric_.mix_key(rs_, s_);

    } else if (message_index_ == 1 && initiator_) {
        // Receive Message 2 (initiator side): e, ee, se

        // e: read ephemeral pubkey
        auto e_data = shift(PKLEN);
        if (!e_data) return std::nullopt;
        std::copy_n(e_data, PKLEN, re_.data());
        symmetric_.mix_hash(re_.data(), PKLEN);

        // ee: DH(e, re) — both ephemeral
        symmetric_.mix_key(re_, e_);

        // se: DH(s, re) — our static, their ephemeral
        // Wait — from initiator's perspective, se means: local=static, remote=ephemeral
        // JS keyPattern: SE with initiator=true → local=static, remote=ephemeral
        symmetric_.mix_key(re_, s_);
    }

    // Decrypt payload (remaining bytes)
    size_t remaining = msg_len - offset;
    auto payload = symmetric_.decrypt_and_hash(msg + offset, remaining);
    if (!payload) {
        corrupt_ = true;  // digest was modified by mix_hash; state is now inconsistent
        return std::nullopt;
    }

    message_index_++;

    // Check if handshake is done
    if (message_index_ >= 2) {
        auto [k1, k2] = symmetric_.split();
        tx_ = initiator_ ? k1 : k2;
        rx_ = initiator_ ? k2 : k1;
        hash_ = symmetric_.get_handshake_hash();
        complete_ = true;
    }

    return payload;
}

void NoiseIK::set_ephemeral(const Keypair& ephemeral) {
    e_ = ephemeral;
    e_generated_ = true;
}

bool NoiseIK::is_complete() const { return complete_; }

Key NoiseIK::tx_key() const { return tx_; }
Key NoiseIK::rx_key() const { return rx_; }
Hash NoiseIK::handshake_hash() const { return hash_; }

}  // namespace noise
}  // namespace hyperdht
