#pragma once

// DHT token system — dual BLAKE2b secrets with rotation.
// token = BLAKE2b-256(host_string, secret)
// Both current and previous secrets are valid for verification.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace hyperdht {
namespace tokens {

constexpr size_t TOKEN_LEN = 32;   // BLAKE2b-256 output
constexpr size_t SECRET_LEN = 32;  // Random secret size

using Token = std::array<uint8_t, TOKEN_LEN>;
using Secret = std::array<uint8_t, SECRET_LEN>;

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

// Generate a token: BLAKE2b-256(host_string, secret)
// The secret is used as the BLAKE2b key, host_string as the message.
Token generate_token(const std::string& host, const Secret& secret);

// ---------------------------------------------------------------------------
// TokenStore — manages dual secrets with rotation
// ---------------------------------------------------------------------------

class TokenStore {
public:
    TokenStore();

    // Rotate secrets: previous = current, current = new random
    void rotate();

    // Generate a token for a host using the CURRENT secret
    Token create(const std::string& host) const;

    // Validate a token against BOTH current and previous secrets
    bool validate(const std::string& host, const Token& token) const;

    // Access secrets (for testing)
    const Secret& current_secret() const { return current_; }
    const Secret& previous_secret() const { return previous_; }

private:
    Secret current_;
    Secret previous_;
};

}  // namespace tokens
}  // namespace hyperdht
