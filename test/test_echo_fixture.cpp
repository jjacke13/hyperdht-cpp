// Quick echo test against the permanent JS test fixture.
// Uses the C FFI (hyperdht.h) end-to-end — same path Python uses.
//
// Usage:
//   SERVER_KEY=c4353145d7bf7d7bff95ed7e59cd4c5c602da58af8fae06e2ce150560e04d56c \
//     ./test_echo_fixture
//
// Requires the JS fixture running on a reachable machine.

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <uv.h>

#include "hyperdht/hyperdht.h"

TEST(Fixture, EchoRoundTrip) {
    const char* key_env = std::getenv("SERVER_KEY");
    if (!key_env || strlen(key_env) != 64) {
        GTEST_SKIP() << "Set SERVER_KEY=<64-hex-chars> to run";
    }

    uint8_t server_pk[32];
    for (int i = 0; i < 32; i++) {
        unsigned int b;
        sscanf(key_env + i * 2, "%02x", &b);
        server_pk[i] = static_cast<uint8_t>(b);
    }

    uv_loop_t loop;
    uv_loop_init(&loop);

    // Create DHT with public bootstrap enabled
    hyperdht_opts_t opts{};
    opts.use_public_bootstrap = 1;
    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    ASSERT_NE(dht, nullptr);
    ASSERT_EQ(hyperdht_bind(dht, 0), 0);
    printf("  Bound to port %u\n", hyperdht_port(dht));

    // State shared across callbacks
    struct State {
        hyperdht_t* dht;
        hyperdht_stream_t* stream = nullptr;
        bool connected = false;
        bool echo_received = false;
        std::string echo_data;
        bool closed = false;
        uv_timer_t* timeout = nullptr;
    };
    State state{dht};

    const std::string test_msg = "hello from C++ via hyperdht-cpp echo test";

    // Connect
    printf("  Connecting to fixture...\n");
    int rc = hyperdht_connect(dht, server_pk,
        [](int error, const hyperdht_connection_t* conn, void* ud) {
            auto* s = static_cast<State*>(ud);
            printf("  connect: error=%d\n", error);
            if (error != 0 || !conn) {
                printf("  CONNECT FAILED\n");
                return;
            }
            s->connected = true;
            printf("  Connected! peer=%s:%u udx=(us=%u them=%u) raw=%s\n",
                   conn->peer_host, conn->peer_port,
                   conn->local_udx_id, conn->remote_udx_id,
                   conn->raw_stream ? "yes" : "no");

            // Open encrypted stream (uses SecretStreamDuplex internally)
            s->stream = hyperdht_stream_open(s->dht, conn,
                // on_open
                [](void* ud2) {
                    auto* s2 = static_cast<State*>(ud2);
                    printf("  Stream OPEN — encrypted channel ready\n");

                    // Send the test message
                    const char* msg = "hello from C++ via hyperdht-cpp echo test";
                    int wrc = hyperdht_stream_write(s2->stream,
                        reinterpret_cast<const uint8_t*>(msg), strlen(msg));
                    printf("  Sent %zu bytes (rc=%d): \"%s\"\n", strlen(msg), wrc, msg);
                },
                // on_data
                [](const uint8_t* data, size_t len, void* ud2) {
                    auto* s2 = static_cast<State*>(ud2);
                    s2->echo_data.assign(reinterpret_cast<const char*>(data), len);
                    s2->echo_received = true;
                    printf("  ECHO RECEIVED (%zu bytes): \"%s\"\n", len, s2->echo_data.c_str());

                    // Success! Close the stream gracefully.
                    hyperdht_stream_close(s2->stream);
                },
                // on_close
                [](void* ud2) {
                    auto* s2 = static_cast<State*>(ud2);
                    s2->closed = true;
                    printf("  Stream CLOSED\n");

                    // Tear down
                    if (s2->timeout) {
                        uv_timer_stop(s2->timeout);
                        uv_close(reinterpret_cast<uv_handle_t*>(s2->timeout),
                                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
                        s2->timeout = nullptr;
                    }
                    hyperdht_destroy(s2->dht, nullptr, nullptr);
                },
                ud);  // pass the same userdata through

            if (!s->stream) {
                printf("  hyperdht_stream_open FAILED\n");
            }
        },
        &state);

    ASSERT_EQ(rc, 0) << "hyperdht_connect failed synchronously";

    // Safety timeout
    state.timeout = new uv_timer_t;
    uv_timer_init(&loop, state.timeout);
    state.timeout->data = &state;
    uv_timer_start(state.timeout, [](uv_timer_t* t) {
        auto* s = static_cast<State*>(t->data);
        printf("  TIMEOUT — tearing down\n");
        if (s->stream) hyperdht_stream_close(s->stream);
        else {
            uv_timer_stop(t);
            uv_close(reinterpret_cast<uv_handle_t*>(t),
                     [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
            s->timeout = nullptr;
            hyperdht_destroy(s->dht, nullptr, nullptr);
        }
    }, 30000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(state.connected) << "should have connected to the fixture";
    EXPECT_TRUE(state.echo_received) << "should have received the echo";
    EXPECT_EQ(state.echo_data, test_msg)
        << "echo should match exactly what we sent";

    hyperdht_free(dht);
    uv_loop_close(&loop);
}
