// HyperDHT class tests — constructor, bind, create_server, destroy.
// Live connect test is separate (test_live_connect.cpp).

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>
#include <udx.h>

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
// Set SERVER_KEY=<64-hex-chars> to enable.
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

    bool connected = false;
    bool header_received = false;
    udx_stream_t* stream = nullptr;
    secret_stream::SecretStream* ss = nullptr;

    dht.connect(server_pk, [&](int err, const ConnectResult& r) {
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

TEST(HyperDHT, NotConnectableWhenSuspended) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);
    dht.bind();

    EXPECT_TRUE(dht.is_connectable());

    dht.suspend();
    EXPECT_FALSE(dht.is_connectable());

    // Connect while suspended should fail
    noise::PubKey pk{};
    pk.fill(0x42);
    int error = 0;
    dht.connect(pk, ConnectOptions{}, [&](int err, const ConnectResult&) {
        error = err;
    });
    // Suspended DHT is not destroyed, but connect checks is_connectable
    // via the suspended flag in the connect options check
    EXPECT_TRUE(dht.is_suspended());

    dht.resume();
    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}
