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
    hyperdht_opts_default(&opts);
    opts.port = 0;
    opts.ephemeral = 1;

    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    ASSERT_NE(dht, nullptr);

    hyperdht_bind(dht, 0);
    EXPECT_GT(hyperdht_port(dht), 0);

    // Defaults init leaves keep-alive at its sentinel → C++ default (5000 ms).
    EXPECT_EQ(hyperdht_connection_keep_alive(dht), 5000u);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, OptsDefaultSetsSafeValues) {
    // Verify the init helper zero-initialises other fields and sets the
    // keep-alive sentinel (so the library uses its own default).
    hyperdht_opts_t opts;
    memset(&opts, 0xEE, sizeof(opts));  // poison to catch missing fields
    hyperdht_opts_default(&opts);

    EXPECT_EQ(opts.port, 0u);
    EXPECT_EQ(opts.ephemeral, 1);
    EXPECT_EQ(opts.use_public_bootstrap, 0);
    EXPECT_EQ(opts.connection_keep_alive, UINT64_MAX);
}

TEST(CAPI, ConnectionKeepAliveCustomValue) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_opts_t opts;
    hyperdht_opts_default(&opts);
    opts.connection_keep_alive = 1234;

    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    ASSERT_NE(dht, nullptr);
    EXPECT_EQ(hyperdht_connection_keep_alive(dht), 1234u);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, ConnectionKeepAliveDisabled) {
    // 0 = disabled (matches JS `connectionKeepAlive: false`).
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_opts_t opts;
    hyperdht_opts_default(&opts);
    opts.connection_keep_alive = 0;

    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    ASSERT_NE(dht, nullptr);
    EXPECT_EQ(hyperdht_connection_keep_alive(dht), 0u);

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

// ============================================================================
// Extended API (2026-04-17) — coverage for the new FFI surface
// ============================================================================

TEST(CAPI, OptsFromSeedDerivesDeterministicKeypair) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    uint8_t seed[32];
    memset(seed, 0x37, 32);

    hyperdht_opts_t opts;
    hyperdht_opts_default(&opts);
    memcpy(opts.seed, seed, 32);
    opts.seed_is_set = 1;

    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    ASSERT_NE(dht, nullptr);

    hyperdht_keypair_t derived_from_seed;
    hyperdht_keypair_from_seed(&derived_from_seed, seed);

    hyperdht_keypair_t dht_default;
    hyperdht_default_keypair(dht, &dht_default);

    // Same seed → same public key via both code paths.
    EXPECT_EQ(memcmp(derived_from_seed.public_key, dht_default.public_key, 32), 0);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, ConnectOptsDefaultHasSensibleValues) {
    hyperdht_connect_opts_t opts;
    hyperdht_connect_opts_default(&opts);
    EXPECT_EQ(opts.keypair, nullptr);
    EXPECT_EQ(opts.relay_through, nullptr);
    EXPECT_EQ(opts.relay_keep_alive_ms, 0u);  // 0 = library default
    EXPECT_EQ(opts.fast_open, 1);
    EXPECT_EQ(opts.local_connection, 1);
}

TEST(CAPI, AddNodeRejectsInvalidHost) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);
    hyperdht_bind(dht, 0);

    EXPECT_LT(hyperdht_add_node(dht, "not.a.valid.ip", 49737), 0);
    EXPECT_LT(hyperdht_add_node(dht, nullptr, 49737), 0);
    EXPECT_EQ(hyperdht_add_node(dht, "1.2.3.4", 49737), 0);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, ToArraySnapshotsRoutingTable) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);
    hyperdht_bind(dht, 0);

    hyperdht_add_node(dht, "1.2.3.4", 49737);
    hyperdht_add_node(dht, "5.6.7.8", 12345);

    // Flat buffer — stride HYPERDHT_HOST_STRIDE per entry.
    char hosts[16 * HYPERDHT_HOST_STRIDE];
    uint16_t ports[16];
    size_t n = hyperdht_to_array(dht, hosts, ports, 16);
    EXPECT_GE(n, 2u);

    // Entries are null-terminated IPv4 strings inside the flat buffer.
    for (size_t i = 0; i < n; ++i) {
        const char* host_i = hosts + i * HYPERDHT_HOST_STRIDE;
        EXPECT_GT(std::strlen(host_i), 0u);
        EXPECT_GT(ports[i], 0);
    }

    // cap = 0 → 0 entries written (matches JS {limit: 0})
    EXPECT_EQ(hyperdht_to_array(dht, hosts, ports, 0), 0u);

    // Oversized cap: write available, not more
    char big_hosts[256 * HYPERDHT_HOST_STRIDE];
    uint16_t big_ports[256];
    size_t m = hyperdht_to_array(dht, big_hosts, big_ports, 256);
    EXPECT_EQ(m, n) << "oversized cap must write only what's available";

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, RemoteAddressNullWhenFirewalled) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);
    hyperdht_bind(dht, 0);

    char host[46];
    uint16_t port;
    EXPECT_LT(hyperdht_remote_address(dht, host, &port), 0);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, SuspendResumeLoggedFiresCallbacks) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);
    hyperdht_bind(dht, 0);

    struct Ctx { int count = 0; } ctx;
    auto cb = +[](const char*, void* ud) {
        static_cast<Ctx*>(ud)->count++;
    };

    hyperdht_suspend_logged(dht, cb, &ctx);
    EXPECT_GE(ctx.count, 3);  // at least 3 phase breadcrumbs

    int before = ctx.count;
    hyperdht_resume_logged(dht, cb, &ctx);
    EXPECT_GT(ctx.count, before);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, DestroyForceTearsDownWithoutHanging) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);
    hyperdht_bind(dht, 0);

    hyperdht_destroy_force(dht, NULL, NULL);
    EXPECT_EQ(hyperdht_is_destroyed(dht), 1);

    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, PunchStatsAccessorsReturnZeroOnFreshDHT) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);

    EXPECT_EQ(hyperdht_punch_stats_consistent(dht), 0);
    EXPECT_EQ(hyperdht_punch_stats_random(dht), 0);
    EXPECT_EQ(hyperdht_punch_stats_open(dht), 0);
    EXPECT_EQ(hyperdht_relay_stats_attempts(dht), 0);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

TEST(CAPI, QueryCancelStopsLookupCleanly) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);
    hyperdht_bind(dht, 0);

    struct Ctx { int done_err = 999; } ctx;
    uint8_t target[32] = {0};
    target[0] = 0xAA;

    auto on_reply = +[](const uint8_t*, size_t, const char*, uint16_t, void*) {};
    auto on_done = +[](int err, void* ud) {
        static_cast<Ctx*>(ud)->done_err = err;
    };

    hyperdht_query_t* q = hyperdht_lookup_ex(dht, target, on_reply, on_done, &ctx);
    ASSERT_NE(q, nullptr);

    hyperdht_query_cancel(q);
    // cancel triggers done synchronously via Query::destroy()
    EXPECT_EQ(ctx.done_err, HYPERDHT_ERR_CANCELLED);

    hyperdht_query_free(q);  // user owns the handle, must free

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

// C2 safety: double-cancel is idempotent — second call is a no-op.
TEST(CAPI, QueryDoubleCancelIsNoop) {
    uv_loop_t loop;
    uv_loop_init(&loop);
    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);
    hyperdht_bind(dht, 0);

    struct Ctx { int done_calls = 0; int last_err = 0; } ctx;
    uint8_t target[32] = {0x33};

    auto on_done = +[](int err, void* ud) {
        auto* c = static_cast<Ctx*>(ud);
        c->done_calls++;
        c->last_err = err;
    };

    hyperdht_query_t* q = hyperdht_lookup_ex(dht, target, nullptr, on_done, &ctx);
    ASSERT_NE(q, nullptr);

    hyperdht_query_cancel(q);
    EXPECT_EQ(ctx.done_calls, 1);
    EXPECT_EQ(ctx.last_err, HYPERDHT_ERR_CANCELLED);

    // Second cancel: no additional done fire, no crash.
    hyperdht_query_cancel(q);
    EXPECT_EQ(ctx.done_calls, 1);

    hyperdht_query_free(q);
    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

// C2 safety: cancel after the query finished naturally is a no-op.
// Simulate by calling free, then cancel — free detaches the callback,
// and cancel then sees done_cb is null (we reuse the `done` flag but
// the check order is: done → skip; so we drive done through cancel).
TEST(CAPI, QueryFreeDetachesCallbackOnLateDone) {
    uv_loop_t loop;
    uv_loop_init(&loop);
    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    ASSERT_NE(dht, nullptr);
    hyperdht_bind(dht, 0);

    struct Ctx { int done_calls = 0; } ctx;
    uint8_t target[32] = {0x77};
    auto on_done = +[](int, void* ud) {
        static_cast<Ctx*>(ud)->done_calls++;
    };

    hyperdht_query_t* q = hyperdht_lookup_ex(dht, target, nullptr, on_done, &ctx);
    ASSERT_NE(q, nullptr);

    // User abandons the query before it completes.
    hyperdht_query_free(q);

    // Pump the loop briefly so any pending completion callbacks get a
    // chance to fire. Since the handle is freed and the callback
    // detached, none should reach the user's done_cb.
    for (int i = 0; i < 5; ++i) uv_run(&loop, UV_RUN_NOWAIT);

    EXPECT_EQ(ctx.done_calls, 0);  // silent — callback was detached

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
}

// C2 safety: null-this on all new query handle functions.
TEST(CAPI, QueryCancelAndFreeTolerateNull) {
    hyperdht_query_cancel(nullptr);  // no crash
    hyperdht_query_free(nullptr);    // no crash
    SUCCEED();
}

// C1 safety: double-call of hyperdht_firewall_done is a no-op.
// Wraps a stand-alone test — we don't need a real server, just
// exercise the handle-close flow.
TEST(CAPI, FirewallDoneTolleratesNull) {
    hyperdht_firewall_done(nullptr, 0);  // no crash
    hyperdht_firewall_done(nullptr, 1);  // no crash
    SUCCEED();
}

// Null-this tolerance on the new server-level and DHT-level FFI adds.
TEST(CAPI, NewFunctionsTolerateNullThis) {
    // Server accessors
    uint8_t pk[32];
    char host[46]; uint16_t port;
    EXPECT_LT(hyperdht_server_address(nullptr, host, &port), 0);
    EXPECT_LT(hyperdht_server_public_key(nullptr, pk), 0);

    // on_listening registration
    hyperdht_server_on_listening(nullptr, nullptr, nullptr);  // no crash

    // DHT accessors
    EXPECT_EQ(hyperdht_punch_stats_consistent(nullptr), 0);
    EXPECT_EQ(hyperdht_punch_stats_random(nullptr), 0);
    EXPECT_EQ(hyperdht_punch_stats_open(nullptr), 0);
    EXPECT_LT(hyperdht_add_node(nullptr, "1.2.3.4", 49737), 0);
    EXPECT_LT(hyperdht_remote_address(nullptr, host, &port), 0);
    EXPECT_EQ(hyperdht_to_array(nullptr, host, &port, 1), 0u);

    // Lifecycle
    hyperdht_suspend_logged(nullptr, nullptr, nullptr);  // no crash
    hyperdht_resume_logged(nullptr, nullptr, nullptr);   // no crash
    hyperdht_destroy_force(nullptr, nullptr, nullptr);   // no crash
    hyperdht_server_close_force(nullptr, nullptr, nullptr);
    hyperdht_server_suspend_logged(nullptr, nullptr, nullptr);

    // _ex queries with null dht
    EXPECT_EQ(hyperdht_find_peer_ex(nullptr, pk, nullptr, nullptr, nullptr), nullptr);
    EXPECT_EQ(hyperdht_lookup_ex(nullptr, pk, nullptr, nullptr, nullptr), nullptr);
    EXPECT_EQ(hyperdht_immutable_get_ex(nullptr, pk, nullptr, nullptr, nullptr), nullptr);
    EXPECT_EQ(hyperdht_mutable_get_ex(nullptr, pk, 0, nullptr, nullptr, nullptr), nullptr);

    SUCCEED();
}
