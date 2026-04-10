// DHT token implementation — dual BLAKE2b secrets rotated every 7.5s.
// Generates tokens for a given host; accepts tokens matching either
// the current or previous secret during the overlap window.

#include "hyperdht/tokens.hpp"

#include <sodium.h>

#include <cstring>

namespace hyperdht {
namespace tokens {

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

Token generate_token(const std::string& host, const Secret& secret) {
    Token token{};
    // BLAKE2b-256 with secret as key, host as message
    crypto_generichash(token.data(), TOKEN_LEN,
                       reinterpret_cast<const uint8_t*>(host.data()), host.size(),
                       secret.data(), SECRET_LEN);
    return token;
}

// ---------------------------------------------------------------------------
// TokenStore
// ---------------------------------------------------------------------------

TokenStore::TokenStore() {
    randombytes_buf(current_.data(), SECRET_LEN);
    randombytes_buf(previous_.data(), SECRET_LEN);
}

void TokenStore::rotate() {
    // JS: swap secrets, then hash the old one to create new current
    std::swap(current_, previous_);
    // Hash into temp buffer to avoid in-place aliasing
    Secret temp{};
    crypto_generichash(temp.data(), SECRET_LEN,
                       current_.data(), SECRET_LEN,
                       nullptr, 0);
    current_ = temp;
    sodium_memzero(temp.data(), SECRET_LEN);
}

Token TokenStore::create(const std::string& host) const {
    return generate_token(host, current_);
}

bool TokenStore::validate(const std::string& host, const Token& token) const {
    // Check against current secret
    auto expected_current = generate_token(host, current_);
    if (sodium_memcmp(token.data(), expected_current.data(), TOKEN_LEN) == 0) {
        return true;
    }

    // Check against previous secret
    auto expected_previous = generate_token(host, previous_);
    return sodium_memcmp(token.data(), expected_previous.data(), TOKEN_LEN) == 0;
}

}  // namespace tokens
}  // namespace hyperdht
