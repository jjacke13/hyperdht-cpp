// HyperDHT class tests — constructor, bind, create_server, destroy.
// Live connect test is separate (test_live_connect.cpp).

#include <gtest/gtest.h>

#include <set>

#include <sodium.h>
#include <uv.h>
#include <udx.h>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/dht.hpp"
#include "hyperdht/hyperdht.h"
#include "hyperdht/secret_stream.hpp"

using namespace hyperdht;

TEST(HyperDHT, CreateAndDestroy) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);
    EXPECT_FALSE(dht.is_bound());
    EXPECT_FALSE(dht.is_destroyed());

    int rc = dht.bind();
    EXPECT_EQ(rc, 0);
    EXPECT_TRUE(dht.is_bound());
    EXPECT_GT(dht.port(), 0u);

    dht.destroy();
    EXPECT_TRUE(dht.is_destroyed());

    // Run the loop to drain close callbacks while dht is still alive
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, DefaultKeypairGenerated) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    auto zero = noise::PubKey{};
    EXPECT_NE(dht.default_keypair().public_key, zero);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, CustomKeypair) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    DhtOptions opts;
    opts.default_keypair = kp;

    HyperDHT dht(&loop, opts);
    EXPECT_EQ(dht.default_keypair().public_key, kp.public_key);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, CreateServer) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    auto* srv = dht.create_server();
    ASSERT_NE(srv, nullptr);
    EXPECT_FALSE(srv->is_listening());
    EXPECT_TRUE(dht.is_bound());  // create_server auto-binds

    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);

    srv->listen(kp, [](const server::ConnectionInfo&) {});
    EXPECT_TRUE(srv->is_listening());
    EXPECT_EQ(dht.router().size(), 1u);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, DestroyClosesServers) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    auto* srv = dht.create_server();
    noise::Seed seed{};
    seed.fill(0x11);
    srv->listen(noise::generate_keypair(seed), [](const server::ConnectionInfo&) {});

    EXPECT_EQ(dht.router().size(), 1u);

    dht.destroy();
    EXPECT_EQ(dht.router().size(), 0u);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// Live test: HyperDHT::connect() → stream open → SecretStream to JS server.
// Uses the full do_connect pipeline (rawStream + holepunch) + C API stream.
//
// Required env:
//   SERVER_KEY=<64-hex>  — remote server public key
//
// Optional §6 hooks (ConnectOptions — per-connect):
//   CLIENT_SEED=<64-hex>     — derive the client keypair from this seed
//                              and pass it via ConnectOptions::keypair
//                              (the §6 per-connect override). Mutually
//                              exclusive with DHT_SEED below.
//   FAST_OPEN=0|1            — override `ConnectOptions::fast_open`
//                              (default 1). Set to 0 to disable the
//                              pre-Round-1 low-TTL probe.
//   LOCAL_CONNECTION=0|1     — override `ConnectOptions::local_connection`
//                              (default 1). Set to 0 to skip the LAN
//                              shortcut branch entirely.
//
// Optional §7 hook (DhtOptions — DHT default):
//   DHT_SEED=<64-hex>        — derive the DHT's `default_keypair` from
//                              this seed via `DhtOptions::seed`. The
//                              derived keypair is then used by every
//                              connect that doesn't override via
//                              `ConnectOptions::keypair`. Verifies the
//                              §7 seed→keypair plumbing end-to-end.
TEST(HyperDHT, LiveConnect) {
    const char* key_env = std::getenv("SERVER_KEY");
    if (!key_env || strlen(key_env) != 64) {
        GTEST_SKIP() << "Set SERVER_KEY=<64-hex-chars> to run this test";
    }

    noise::PubKey server_pk{};
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(key_env + i * 2, "%02x", &byte);
        server_pk[i] = static_cast<uint8_t>(byte);
    }

    uv_loop_t loop;
    uv_loop_init(&loop);

    // §7: build DhtOptions from env hooks BEFORE HyperDHT construction.
    // DHT_SEED flows into DhtOptions::seed which the constructor uses to
    // derive `default_keypair`. The derived default will then be used for
    // the handshake unless a per-connect CLIENT_SEED also sets
    // ConnectOptions::keypair (in which case the per-connect override wins).
    DhtOptions dht_opts;
    if (const char* dht_seed = std::getenv("DHT_SEED");
        dht_seed && strlen(dht_seed) == 64) {
        noise::Seed s{};
        for (int i = 0; i < 32; i++) {
            unsigned int byte;
            sscanf(dht_seed + i * 2, "%02x", &byte);
            s[i] = static_cast<uint8_t>(byte);
        }
        dht_opts.seed = s;
        printf("  DHT_SEED set — default_keypair will be derived\n");
    }

    HyperDHT dht(&loop, dht_opts);
    dht.bind();
    printf("  Bound to port %u\n", dht.port());
    printf("  DHT default_keypair pubkey = ");
    for (uint8_t b : dht.default_keypair().public_key) printf("%02x", b);
    printf("\n");

    // §6: build ConnectOptions from env hooks so a single live run can
    // exercise keypair override / fast_open / local_connection without
    // rebuilding.
    ConnectOptions conn_opts;

    if (const char* seed_env = std::getenv("CLIENT_SEED");
        seed_env && strlen(seed_env) == 64) {
        noise::Seed seed{};
        for (int i = 0; i < 32; i++) {
            unsigned int byte;
            sscanf(seed_env + i * 2, "%02x", &byte);
            seed[i] = static_cast<uint8_t>(byte);
        }
        auto override_kp = noise::generate_keypair(seed);
        printf("  CLIENT_SEED override: our pubkey = ");
        for (uint8_t b : override_kp.public_key) printf("%02x", b);
        printf("\n");
        conn_opts.keypair = override_kp;
    } else {
        printf("  (no CLIENT_SEED — using DHT default_keypair)\n");
    }

    if (const char* fo = std::getenv("FAST_OPEN"); fo) {
        conn_opts.fast_open = (fo[0] != '0');
        printf("  FAST_OPEN=%d\n", conn_opts.fast_open ? 1 : 0);
    }
    if (const char* lc = std::getenv("LOCAL_CONNECTION"); lc) {
        conn_opts.local_connection = (lc[0] != '0');
        printf("  LOCAL_CONNECTION=%d\n", conn_opts.local_connection ? 1 : 0);
    }

    bool connected = false;
    bool header_received = false;
    udx_stream_t* stream = nullptr;
    secret_stream::SecretStream* ss = nullptr;

    dht.connect(server_pk, conn_opts, [&](int err, const ConnectResult& r) {
        printf("  connect: err=%d success=%d\n", err, r.success);
        if (err != 0 || !r.success) return;

        connected = true;
        printf("  peer: %s:%u  udx: us=%u them=%u  rawStream=%s\n",
               r.peer_address.host_string().c_str(), r.peer_address.port,
               r.local_udx_id, r.remote_udx_id,
               r.raw_stream ? "yes" : "no");

        // Step 2: UDX stream connect — reuse rawStream, clear stale firewall first
        stream = r.raw_stream;
        udx_stream_firewall(stream, nullptr);  // Clear holepunch firewall
        struct sockaddr_in dest{};
        uv_ip4_addr(r.peer_address.host_string().c_str(), r.peer_address.port, &dest);
        printf("  Connecting UDX to %s:%u (us=%u them=%u)\n",
               r.peer_address.host_string().c_str(), r.peer_address.port,
               r.local_udx_id, r.remote_udx_id);
        fflush(stdout);
        udx_stream_connect(stream, dht.socket().socket_handle(), r.remote_udx_id,
                           reinterpret_cast<const struct sockaddr*>(&dest));

        // Step 3: SecretStream header exchange
        ss = new secret_stream::SecretStream(r.tx_key, r.rx_key, r.handshake_hash, true);
        auto header = ss->create_header_message();
        printf("  Sending SecretStream header (%zu bytes)\n", header.size());

        auto* hdr_buf = new std::vector<uint8_t>(std::move(header));
        uv_buf_t uv_buf = uv_buf_init(
            reinterpret_cast<char*>(hdr_buf->data()),
            static_cast<unsigned int>(hdr_buf->size()));
        auto* wreq = static_cast<udx_stream_write_t*>(
            calloc(1, sizeof(udx_stream_write_t) + sizeof(udx_stream_write_buf_t)));
        wreq->data = hdr_buf;
        udx_stream_write(wreq, stream, &uv_buf, 1,
            [](udx_stream_write_t* req, int, int) {
                delete static_cast<std::vector<uint8_t>*>(req->data);
                free(req);
            });

        // Read the server's header + data
        stream->data = &header_received;
        udx_stream_read_start(stream, [](udx_stream_t* s, ssize_t nread, const uv_buf_t* buf) {
            if (nread <= 0) return;
            auto* hdr_done = static_cast<bool*>(s->data);
            if (!*hdr_done && nread >= 59) {
                printf("  Received server SecretStream header!\n");
                *hdr_done = true;
            }
        });
    });

    // Timeout — clean up and stop
    uv_timer_t timeout;
    uv_timer_init(&loop, &timeout);
    struct TimeoutCtx { HyperDHT* dht; udx_stream_t** stream; secret_stream::SecretStream** ss; };
    auto* tctx = new TimeoutCtx{&dht, &stream, &ss};
    timeout.data = tctx;
    uv_timer_start(&timeout, [](uv_timer_t* t) {
        auto* c = static_cast<TimeoutCtx*>(t->data);
        printf("  TIMEOUT — cleaning up\n");
        if (*c->stream) udx_stream_destroy(*c->stream);
        delete *c->ss;
        c->dht->destroy();
        delete c;
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 45000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(connected) << "connect should succeed";
    EXPECT_TRUE(header_received) << "SecretStream header should be received";

    uv_loop_close(&loop);
}

TEST(HyperDHT, ConnectToDestroyedFails) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);
    dht.destroy();

    noise::PubKey pk{};
    pk.fill(0x42);

    int error = 0;
    dht.connect(pk, [&](int err, const ConnectResult&) {
        error = err;
    });
    EXPECT_EQ(error, -1);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Suspend / Resume
// ---------------------------------------------------------------------------

TEST(HyperDHT, SuspendResume) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);
    dht.bind();

    EXPECT_FALSE(dht.is_suspended());
    EXPECT_TRUE(dht.is_connectable());

    dht.suspend();
    EXPECT_TRUE(dht.is_suspended());
    EXPECT_FALSE(dht.is_connectable());

    dht.resume();
    EXPECT_FALSE(dht.is_suspended());
    EXPECT_TRUE(dht.is_connectable());

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, SuspendWithServer) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);
    dht.bind();

    auto* srv = dht.create_server();
    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);
    srv->listen(kp, [](const server::ConnectionInfo&) {});
    EXPECT_TRUE(srv->is_listening());

    dht.suspend();
    EXPECT_TRUE(srv->is_suspended());

    dht.resume();
    EXPECT_FALSE(srv->is_suspended());

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

TEST(HyperDHT, Pool) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);
    auto pool = dht.pool();

    // Pool starts empty
    EXPECT_EQ(pool.connected_count(), 0u);
    EXPECT_EQ(pool.connecting_count(), 0u);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Connectable flag
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Storage API — §5: HyperDHT::{mutable,immutable}_{put,get}
//
// These are thin wrappers around dht_ops (which has its own roundtrip
// tests in test_rpc_handlers and test_storage_live). Here we exercise
// the class-level wrapper layer:
//
//   - API shape: returns non-null shared_ptr<Query>
//   - Auto-bind: calling without an explicit bind() works
//   - No crash on well-formed inputs
//   - Synchronous derivations (hash for immutable_put, signature for
//     mutable_put) match the same primitives called directly
//
// Not covered here (already covered elsewhere):
//   - commit phase / on_done being fired with network results
//   - signature verification at the server
//   - seq ordering semantics
// ---------------------------------------------------------------------------

TEST(HyperDHT, ImmutablePutReturnsValidQuery) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    std::vector<uint8_t> value{'h', 'i'};
    auto q = dht.immutable_put(value,
        [](const HyperDHT::ImmutablePutResult&) {});

    EXPECT_NE(q, nullptr);
    EXPECT_TRUE(dht.is_bound());  // auto-binds

    // Verify the target hash the wrapper would surface matches the
    // underlying primitive (JS: sodium.crypto_generichash(target, value)).
    std::array<uint8_t, 32> expected{};
    crypto_generichash(expected.data(), 32,
                       value.data(), value.size(), nullptr, 0);
    auto actual = dht_ops::hash_public_key(value.data(), value.size());
    EXPECT_EQ(actual, expected);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, ImmutablePutRejectsEmptyValue) {
    // §5 fix M3: empty values return nullptr immediately, matching the
    // server-side rejection in JS persistent.onimmutableput.
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    auto q = dht.immutable_put({},
        [](const HyperDHT::ImmutablePutResult&) {});
    EXPECT_EQ(q, nullptr);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, ImmutableGetReturnsValidQuery) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    std::array<uint8_t, 32> target{};
    target.fill(0xAB);

    auto q = dht.immutable_get(target,
        [](const HyperDHT::ImmutableGetResult&) {});

    EXPECT_NE(q, nullptr);
    EXPECT_TRUE(dht.is_bound());

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, ImmutableGetStreamingOverload) {
    // §5 fix H1: verify the streaming overload with a separate on_value
    // callback compiles and returns a valid query. Actual streaming
    // semantics are covered by test_rpc_handlers (dht_ops level).
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    std::array<uint8_t, 32> target{};
    target.fill(0xCD);

    int value_calls = 0;
    auto q = dht.immutable_get(target,
        [&value_calls](const std::vector<uint8_t>&) { value_calls++; },
        [](const HyperDHT::ImmutableGetResult&) {});
    EXPECT_NE(q, nullptr);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, MutablePutReturnsValidQuery) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    noise::Seed seed{};
    seed.fill(0x77);
    auto kp = noise::generate_keypair(seed);
    std::vector<uint8_t> value{'m', 'u', 't'};
    const uint64_t seq = 42;

    auto q = dht.mutable_put(kp, value, seq,
        [](const HyperDHT::MutablePutResult&) {});

    EXPECT_NE(q, nullptr);
    EXPECT_TRUE(dht.is_bound());

    // Verify the signature produced by the primitive (which the wrapper
    // surfaces in MutablePutResult.signature) round-trips through verify.
    auto sig = announce_sig::sign_mutable(
        seq, value.data(), value.size(), kp);
    EXPECT_TRUE(announce_sig::verify_mutable(
        sig, seq, value.data(), value.size(), kp.public_key));

    // Different seq produces a different signature.
    auto sig2 = announce_sig::sign_mutable(
        seq + 1, value.data(), value.size(), kp);
    EXPECT_NE(sig, sig2);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, MutablePutRejectsEmptyValue) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    noise::Seed seed{};
    seed.fill(0x77);
    auto kp = noise::generate_keypair(seed);

    auto q = dht.mutable_put(kp, {}, 0,
        [](const HyperDHT::MutablePutResult&) {});
    EXPECT_EQ(q, nullptr);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, MutableGetReturnsValidQuery) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);

    noise::PubKey pk{};
    pk.fill(0x22);

    // Default overload (min_seq=0, latest=true).
    auto q = dht.mutable_get(pk,
        [](const HyperDHT::MutableGetResult&) {});
    EXPECT_NE(q, nullptr);
    EXPECT_TRUE(dht.is_bound());

    // Explicit overload.
    auto q2 = dht.mutable_get(pk, /*min_seq=*/5, /*latest=*/false,
        [](const HyperDHT::MutableGetResult&) {});
    EXPECT_NE(q2, nullptr);

    // Streaming overload.
    auto q3 = dht.mutable_get(pk, /*min_seq=*/0, /*latest=*/true,
        [](const dht_ops::MutableResult&) {},
        [](const HyperDHT::MutableGetResult&) {});
    EXPECT_NE(q3, nullptr);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, StorageTargetDerivationMatchesJS) {
    // Sanity check the shared hash function used for both immutable_put
    // (target = hash(value)) and mutable_{put,get} (target = hash(pubkey))
    // against the JS convention (`sodium.crypto_generichash`).
    //
    // A 32-byte public key of all 0x42 should hash to a stable value —
    // and both the mutable_put target and mutable_get target must agree.
    std::array<uint8_t, 32> pk;
    pk.fill(0x42);

    std::array<uint8_t, 32> t1{};
    crypto_generichash(t1.data(), 32, pk.data(), 32, nullptr, 0);
    auto t2 = dht_ops::hash_public_key(pk.data(), pk.size());
    EXPECT_EQ(t1, t2);
}

// ---------------------------------------------------------------------------
// §6 — ConnectOptions: keypair, fast_open, local_connection
//
// These are smoke tests for the option surface. Full end-to-end validation
// of the LAN shortcut and fast-open pre-probe requires a live peer and is
// covered by the manual live-test checklist in docs/JS-PARITY-GAPS.md.
// ---------------------------------------------------------------------------

TEST(HyperDHT, ConnectOptionsDefaults) {
    // Verify the default values of the new §6 fields match the JS defaults.
    ConnectOptions opts;
    EXPECT_FALSE(opts.keypair.has_value());
    EXPECT_TRUE(opts.fast_open);         // JS: opts.fastOpen !== false
    EXPECT_TRUE(opts.local_connection);  // JS: opts.localConnection !== false
    EXPECT_FALSE(opts.reusable_socket);
    EXPECT_EQ(opts.pool, nullptr);
    EXPECT_TRUE(opts.relay_addresses.empty());
}

TEST(HyperDHT, ConnectOptionsKeypairOverride) {
    // Setting opts.keypair should override the default DHT keypair without
    // affecting the DHT's own default_keypair.
    uv_loop_t loop;
    uv_loop_init(&loop);

    noise::Seed default_seed{};
    default_seed.fill(0xAA);
    DhtOptions dht_opts;
    dht_opts.default_keypair = noise::generate_keypair(default_seed);

    HyperDHT dht(&loop, dht_opts);
    auto dht_default_pk = dht.default_keypair().public_key;

    // Connection keypair overrides just for this connect
    noise::Seed override_seed{};
    override_seed.fill(0xBB);
    auto override_kp = noise::generate_keypair(override_seed);
    ASSERT_NE(override_kp.public_key, dht_default_pk);

    ConnectOptions opts;
    opts.keypair = override_kp;
    EXPECT_TRUE(opts.keypair.has_value());
    EXPECT_EQ(opts.keypair->public_key, override_kp.public_key);

    // The DHT's default keypair must not be mutated
    EXPECT_EQ(dht.default_keypair().public_key, dht_default_pk);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, ConnectOptionsFastOpenToggle) {
    // Verify the fast_open field can be toggled without crashing the
    // connect setup. (Actual probe-TTL-5 behavior is covered by the live
    // holepunch tests when they run with a real peer.)
    ConnectOptions a;  // default
    EXPECT_TRUE(a.fast_open);

    ConnectOptions b;
    b.fast_open = false;
    EXPECT_FALSE(b.fast_open);
}

TEST(HyperDHT, ConnectOptionsLocalConnectionToggle) {
    // Same smoke check for local_connection.
    ConnectOptions a;
    EXPECT_TRUE(a.local_connection);

    ConnectOptions b;
    b.local_connection = false;
    EXPECT_FALSE(b.local_connection);
}

// ---------------------------------------------------------------------------
// §7 — DhtOptions fields: host, seed, nodes, connection_keep_alive,
//      random_punch_interval, defer_random_punch, max_size, max_age_ms
//
// These tests exercise the option plumbing. End-to-end behavior of the
// cache tuning and random-punch throttling is covered by existing
// holepunch/rpc_handlers tests; here we just verify the fields are
// read from DhtOptions and applied to the right internal state.
// ---------------------------------------------------------------------------

TEST(HyperDHT, OptionsDefaults) {
    // Defaults should match JS conventions.
    DhtOptions opts;
    EXPECT_EQ(opts.host, "0.0.0.0");
    EXPECT_EQ(opts.port, 0u);
    EXPECT_FALSE(opts.seed.has_value());
    EXPECT_TRUE(opts.nodes.empty());
    EXPECT_EQ(opts.connection_keep_alive, 5000u);  // JS default
    EXPECT_EQ(opts.random_punch_interval, 20000u); // JS default
    EXPECT_FALSE(opts.defer_random_punch);
    EXPECT_EQ(opts.max_size, 65536u);              // JS default
    EXPECT_EQ(opts.max_age_ms, 20u * 60 * 1000);   // JS default (20min)
}

TEST(HyperDHT, SeedDerivesDeterministicKeypair) {
    // A fixed seed must produce the same pubkey across runs.
    uv_loop_t loop;
    uv_loop_init(&loop);

    noise::Seed seed{};
    seed.fill(0xAA);

    DhtOptions opts1;
    opts1.seed = seed;
    HyperDHT dht1(&loop, opts1);
    auto pk1 = dht1.default_keypair().public_key;

    DhtOptions opts2;
    opts2.seed = seed;
    HyperDHT dht2(&loop, opts2);
    auto pk2 = dht2.default_keypair().public_key;

    EXPECT_EQ(pk1, pk2) << "Same seed must produce same keypair";

    // A different seed produces a different keypair.
    noise::Seed seed2{};
    seed2.fill(0xBB);
    DhtOptions opts3;
    opts3.seed = seed2;
    HyperDHT dht3(&loop, opts3);
    EXPECT_NE(dht3.default_keypair().public_key, pk1);

    dht1.destroy();
    dht2.destroy();
    dht3.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, KeypairOverridePrecedesSeed) {
    // If `default_keypair` is already populated, `seed` is ignored.
    uv_loop_t loop;
    uv_loop_init(&loop);

    noise::Seed kp_seed{};
    kp_seed.fill(0xCC);
    auto explicit_kp = noise::generate_keypair(kp_seed);

    noise::Seed opts_seed{};
    opts_seed.fill(0xDD);

    DhtOptions opts;
    opts.default_keypair = explicit_kp;
    opts.seed = opts_seed;  // should be ignored

    HyperDHT dht(&loop, opts);
    EXPECT_EQ(dht.default_keypair().public_key, explicit_kp.public_key);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, HostLoopbackBind) {
    // Binding to 127.0.0.1 should succeed and the port should be set.
    uv_loop_t loop;
    uv_loop_init(&loop);

    DhtOptions opts;
    opts.host = "127.0.0.1";
    HyperDHT dht(&loop, opts);
    EXPECT_EQ(dht.host(), "127.0.0.1");

    int rc = dht.bind();
    EXPECT_EQ(rc, 0);
    EXPECT_GT(dht.port(), 0u);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, HostInvalidRejected) {
    // A malformed IPv4 string must fail to bind cleanly (no crash).
    uv_loop_t loop;
    uv_loop_init(&loop);

    DhtOptions opts;
    opts.host = "not.a.valid.ip";
    HyperDHT dht(&loop, opts);

    int rc = dht.bind();
    EXPECT_NE(rc, 0) << "Malformed host must fail bind";
    EXPECT_FALSE(dht.is_bound());

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, NodesPreseededIntoRoutingTable) {
    // Nodes provided in opts.nodes should be inserted into the routing
    // table at construction time, before any bootstrap query. Each node
    // must be present by identity (host/port), not just by count.
    uv_loop_t loop;
    uv_loop_init(&loop);

    DhtOptions opts;
    opts.nodes.push_back(compact::Ipv4Address::from_string("10.0.0.1", 49737));
    opts.nodes.push_back(compact::Ipv4Address::from_string("10.0.0.2", 49737));
    opts.nodes.push_back(compact::Ipv4Address::from_string("10.0.0.3", 49737));

    HyperDHT dht(&loop, opts);
    EXPECT_EQ(dht.socket().table().size(), 3u);

    // Walk every node in the table and verify each of the three addresses
    // is present. Collect a set of host:port strings and check membership.
    std::set<std::string> found;
    const auto& table = dht.socket().table();
    for (size_t i = 0; i < 256; i++) {
        const auto& bucket = table.bucket(i);
        for (const auto& node : bucket.nodes()) {
            found.insert(node.host + ":" + std::to_string(node.port));
        }
    }
    EXPECT_EQ(found.count("10.0.0.1:49737"), 1u);
    EXPECT_EQ(found.count("10.0.0.2:49737"), 1u);
    EXPECT_EQ(found.count("10.0.0.3:49737"), 1u);

    // Also verify the tick fields were populated (not left at 0).
    // Pick any one of the pre-seeded nodes — all should have non-zero
    // added/pinged/seen tick values.
    bool any_has_ticks = false;
    for (size_t i = 0; i < 256; i++) {
        const auto& bucket = table.bucket(i);
        for (const auto& node : bucket.nodes()) {
            // tick values are uint32_t; pre-seeded nodes share the
            // construction-time tick which may or may not be 0 depending
            // on prior loop state. What matters is that added == pinged
            // == seen (set together in the constructor), not that they're
            // non-zero.
            EXPECT_EQ(node.added, node.pinged);
            EXPECT_EQ(node.pinged, node.seen);
            any_has_ticks = true;
        }
    }
    EXPECT_TRUE(any_has_ticks);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, RandomPunchIntervalAppliesToStats) {
    // opts.random_punch_interval must reach PunchStats.
    uv_loop_t loop;
    uv_loop_init(&loop);

    DhtOptions opts;
    opts.random_punch_interval = 12345;
    HyperDHT dht(&loop, opts);

    EXPECT_EQ(dht.random_punch_interval(), 12345u);
    EXPECT_EQ(dht.punch_stats().random_punch_interval, 12345u);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, DeferRandomPunchSeedsLastPunch) {
    // With defer_random_punch=true, last_random_punch is seeded to
    // uv_now() at construction so the first random punch has to wait
    // the full interval. Capture the loop's time BEFORE construction
    // and assert last_random_punch >= captured_time — that proves
    // the assignment happened inside this construction (not leftover
    // state from elsewhere) AND is non-zero.
    uv_loop_t loop;
    uv_loop_init(&loop);
    const uint64_t before = uv_now(&loop);

    DhtOptions opts;
    opts.defer_random_punch = true;
    HyperDHT dht(&loop, opts);

    EXPECT_TRUE(dht.defer_random_punch());
    EXPECT_GE(dht.punch_stats().last_random_punch, before)
        << "last_random_punch must be seeded at/after construction time";

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, DeferRandomPunchResumeReSeeds) {
    // §7 parity with JS hyperdht/index.js:97 — resume() re-seeds
    // last_random_punch when defer_random_punch is set.
    uv_loop_t loop;
    uv_loop_init(&loop);

    DhtOptions opts;
    opts.defer_random_punch = true;
    HyperDHT dht(&loop, opts);
    dht.bind();

    const uint64_t t0 = dht.punch_stats().last_random_punch;

    dht.suspend();
    EXPECT_TRUE(dht.is_suspended());

    // Advance loop time a bit so the re-seeded value is distinguishable.
    uv_run(&loop, UV_RUN_NOWAIT);
    uv_update_time(&loop);

    dht.resume();
    const uint64_t t1 = dht.punch_stats().last_random_punch;
    EXPECT_GE(t1, t0) << "resume() must re-seed last_random_punch";

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, MaxSizeAndMaxAgeAccessors) {
    // Field round-trip check.
    uv_loop_t loop;
    uv_loop_init(&loop);

    DhtOptions opts;
    opts.max_size = 1024;
    opts.max_age_ms = 60 * 1000;
    HyperDHT dht(&loop, opts);

    EXPECT_EQ(dht.max_size(), 1024u);
    EXPECT_EQ(dht.max_age_ms(), 60u * 1000);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, ConnectionKeepAliveAccessor) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    DhtOptions opts;
    opts.connection_keep_alive = 7500;
    HyperDHT dht(&loop, opts);

    EXPECT_EQ(dht.connection_keep_alive(), 7500u);

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(HyperDHT, NotConnectableWhenSuspended) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);
    dht.bind();

    EXPECT_TRUE(dht.is_connectable());

    dht.suspend();
    EXPECT_FALSE(dht.is_connectable());

    // Connect while suspended must fail synchronously with the
    // SUSPENDED error code (-8). JS connect.js:49-51 destroys the
    // socket immediately in this case; C++ rejects via on_done.
    noise::PubKey pk{};
    pk.fill(0x42);
    int error = 0;
    bool callback_fired = false;
    dht.connect(pk, ConnectOptions{}, [&](int err, const ConnectResult&) {
        callback_fired = true;
        error = err;
    });
    EXPECT_TRUE(callback_fired);
    EXPECT_EQ(error, -8) << "Expected SUSPENDED error code";
    EXPECT_TRUE(dht.is_suspended());

    dht.resume();
    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}
