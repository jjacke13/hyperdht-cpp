#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include <sodium.h>

#include "hyperdht/tokens.hpp"

using namespace hyperdht::tokens;

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

TEST(Tokens, GenerateDeterministic) {
    Secret secret{};
    secret.fill(0x42);
    std::string host = "127.0.0.1";

    auto t1 = generate_token(host, secret);
    auto t2 = generate_token(host, secret);
    EXPECT_EQ(t1, t2) << "Same inputs → same token";
}

TEST(Tokens, DifferentHostDifferentToken) {
    Secret secret{};
    secret.fill(0x42);

    auto t1 = generate_token("127.0.0.1", secret);
    auto t2 = generate_token("192.168.1.1", secret);
    EXPECT_NE(t1, t2);
}

TEST(Tokens, DifferentSecretDifferentToken) {
    Secret s1{};
    s1.fill(0x42);
    Secret s2{};
    s2.fill(0x43);

    auto t1 = generate_token("127.0.0.1", s1);
    auto t2 = generate_token("127.0.0.1", s2);
    EXPECT_NE(t1, t2);
}

// ---------------------------------------------------------------------------
// TokenStore
// ---------------------------------------------------------------------------

TEST(TokenStore, CreateAndValidate) {
    TokenStore store;
    std::string host = "10.0.0.1";

    auto token = store.create(host);
    EXPECT_TRUE(store.validate(host, token));
}

TEST(TokenStore, WrongHostFails) {
    TokenStore store;

    auto token = store.create("10.0.0.1");
    EXPECT_FALSE(store.validate("10.0.0.2", token));
}

TEST(TokenStore, ValidAfterOneRotation) {
    TokenStore store;
    std::string host = "10.0.0.1";

    auto token = store.create(host);
    store.rotate();  // Token was created with now-previous secret
    EXPECT_TRUE(store.validate(host, token))
        << "Token from previous secret should still be valid";
}

TEST(TokenStore, InvalidAfterTwoRotations) {
    TokenStore store;
    std::string host = "10.0.0.1";

    auto token = store.create(host);
    store.rotate();  // Previous = old current
    store.rotate();  // Previous = rotated, old current is gone
    EXPECT_FALSE(store.validate(host, token))
        << "Token should expire after two rotations";
}

TEST(TokenStore, NewTokenValidAfterRotation) {
    TokenStore store;
    std::string host = "10.0.0.1";

    store.rotate();
    auto token = store.create(host);  // Created with new current
    EXPECT_TRUE(store.validate(host, token));
}

TEST(TokenStore, FakeTokenFails) {
    TokenStore store;
    Token fake{};
    fake.fill(0xFF);
    EXPECT_FALSE(store.validate("10.0.0.1", fake));
}
