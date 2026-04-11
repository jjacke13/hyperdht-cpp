// HyperDHT class tests — constructor, bind, create_server, destroy.
// Live connect test is separate (test_live_connect.cpp).

#include <gtest/gtest.h>

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
// Optional §6 hooks:
//   CLIENT_SEED=<64-hex>     — derive the client keypair from this seed
//                              (otherwise a random one is used). Used to
//                              verify `ConnectOptions::keypair` override.
//   FAST_OPEN=0|1            — override `ConnectOptions::fast_open`
//                              (default 1). Set to 0 to disable the
//                              pre-Round-1 low-TTL probe.
//   LOCAL_CONNECTION=0|1     — override `ConnectOptions::local_connection`
//                              (default 1). Set to 0 to skip the LAN
//                              shortcut branch entirely.
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

    HyperDHT dht(&loop);
    dht.bind();
    printf("  Bound to port %u\n", dht.port());

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
        printf("  (random client keypair)\n");
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
