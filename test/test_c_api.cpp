// C API tests — verify the extern "C" interface works correctly.
// These tests use ONLY the C API (hyperdht.h), not the C++ headers,
// to prove FFI consumers can use the library.

// Include only the C header
#include "hyperdht/hyperdht.h"

#include <gtest/gtest.h>

#include <uv.h>

#include <cstring>

// ============================================================================
// Keypair tests
// ============================================================================

TEST(CAPI, KeypairGenerate) {
    hyperdht_keypair_t kp;
    hyperdht_keypair_generate(&kp);

    // Public key should be non-zero
    uint8_t zero[32] = {};
    EXPECT_NE(memcmp(kp.public_key, zero, 32), 0)
        << "Generated public key should not be all zeros";
}

TEST(CAPI, KeypairFromSeed) {
    uint8_t seed[32];
    memset(seed, 0x42, 32);

    hyperdht_keypair_t kp1, kp2;
    hyperdht_keypair_from_seed(&kp1, seed);
    hyperdht_keypair_from_seed(&kp2, seed);

    // Same seed → same keypair
    EXPECT_EQ(memcmp(kp1.public_key, kp2.public_key, 32), 0);
    EXPECT_EQ(memcmp(kp1.secret_key, kp2.secret_key, 64), 0);
}

TEST(CAPI, KeypairDifferentSeeds) {
    uint8_t seed1[32], seed2[32];
    memset(seed1, 0x01, 32);
    memset(seed2, 0x02, 32);

    hyperdht_keypair_t kp1, kp2;
    hyperdht_keypair_from_seed(&kp1, seed1);
    hyperdht_keypair_from_seed(&kp2, seed2);

    // Different seeds → different keys
    EXPECT_NE(memcmp(kp1.public_key, kp2.public_key, 32), 0);
}

// ============================================================================
// Lifecycle tests
// ============================================================================

TEST(CAPI, CreateAndDestroy) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);

    EXPECT_EQ(hyperdht_is_destroyed(dht), 0);

    int rc = hyperdht_bind(dht, 0);
    EXPECT_EQ(rc, 0);
    EXPECT_GT(hyperdht_port(dht), 0);

    bool destroyed = false;
    hyperdht_destroy(dht, [](void* ud) {
        *static_cast<bool*>(ud) = true;
    }, &destroyed);
    EXPECT_TRUE(destroyed);

    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, CreateWithOptions) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_opts_t opts;
    opts.port = 0;
    opts.ephemeral = 1;

    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    ASSERT_NE(dht, nullptr);

    hyperdht_bind(dht, 0);
    EXPECT_GT(hyperdht_port(dht), 0);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, DefaultKeypair) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);

    hyperdht_keypair_t kp;
    hyperdht_default_keypair(dht, &kp);

    // Should be non-zero (auto-generated)
    uint8_t zero[32] = {};
    EXPECT_NE(memcmp(kp.public_key, zero, 32), 0);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, NullInputsSafe) {
    // All functions should handle NULL gracefully
    EXPECT_EQ(hyperdht_create(NULL, NULL), nullptr);
    EXPECT_EQ(hyperdht_bind(NULL, 0), -1);
    EXPECT_EQ(hyperdht_port(NULL), 0);
    EXPECT_EQ(hyperdht_is_destroyed(NULL), 1);
    EXPECT_EQ(hyperdht_connect(NULL, NULL, NULL, NULL), -1);
    EXPECT_EQ(hyperdht_server_create(NULL), nullptr);
    EXPECT_EQ(hyperdht_immutable_put(NULL, NULL, 0, NULL, NULL), -1);
    EXPECT_EQ(hyperdht_immutable_get(NULL, NULL, NULL, NULL, NULL), -1);
    EXPECT_EQ(hyperdht_mutable_put(NULL, NULL, NULL, 0, 0, NULL, NULL), -1);
    EXPECT_EQ(hyperdht_mutable_get(NULL, NULL, 0, NULL, NULL, NULL), -1);

    // Destroy with NULL should not crash
    hyperdht_destroy(NULL, NULL, NULL);
    hyperdht_server_close(NULL, NULL, NULL);
    hyperdht_server_refresh(NULL);
}

// ============================================================================
// Server tests
// ============================================================================

TEST(CAPI, ServerCreateAndClose) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    hyperdht_bind(dht, 0);

    hyperdht_server_t* srv = hyperdht_server_create(dht);
    ASSERT_NE(srv, nullptr);

    bool closed = false;
    hyperdht_server_close(srv, [](void* ud) {
        *static_cast<bool*>(ud) = true;
    }, &closed);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);

    EXPECT_TRUE(closed);
}

TEST(CAPI, ServerListen) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    hyperdht_bind(dht, 0);

    hyperdht_server_t* srv = hyperdht_server_create(dht);
    ASSERT_NE(srv, nullptr);

    hyperdht_keypair_t kp;
    hyperdht_keypair_generate(&kp);

    int rc = hyperdht_server_listen(srv, &kp,
        [](const hyperdht_connection_t*, void*) {},
        NULL);
    EXPECT_EQ(rc, 0);

    hyperdht_server_close(srv, NULL, NULL);
    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}
