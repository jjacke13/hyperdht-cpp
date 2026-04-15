// Live server test — listens for an incoming connection from a JS client.
// Generates a random keypair each run. Prints the pubkey for the JS client.
// Exits after first connection or 120s timeout.

#include <gtest/gtest.h>

#include <cstdio>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/dht.hpp"

using namespace hyperdht;

TEST(LiveServer, WaitForConnection) {
    auto kp = noise::generate_keypair();  // Random keypair for each run

    printf("  Server public key: ");
    for (int i = 0; i < 32; i++) printf("%02x", kp.public_key[i]);
    printf("\n");

    uv_loop_t loop;
    uv_loop_init(&loop);

    DhtOptions opts;
    opts.bootstrap = HyperDHT::default_bootstrap_nodes();
    HyperDHT dht(&loop, opts);
    dht.bind();
    printf("  Bound to port %u\n", dht.port());

    auto* srv = dht.create_server();

    bool got_connection = false;
    server::ConnectionInfo conn_info;

    srv->listen(kp, [&](const server::ConnectionInfo& info) {
        printf("  CONNECTION RECEIVED!\n");
        printf("    Remote pubkey: ");
        for (int i = 0; i < 8; i++) printf("%02x", info.remote_public_key[i]);
        printf("...\n");
        printf("    Peer address: %s:%u\n",
               info.peer_address.host_string().c_str(), info.peer_address.port);
        printf("    UDX IDs: local=%u remote=%u\n",
               info.local_udx_id, info.remote_udx_id);

        got_connection = true;
        conn_info = info;

        // Stop after first connection
        dht.destroy();
    });

    printf("  Listening... (waiting up to 120s for JS client)\n");
    printf("  Run the JS client now!\n");
    fflush(stdout);

    // Overall timeout
    uv_timer_t timeout;
    uv_timer_init(&loop, &timeout);
    timeout.data = &dht;
    uv_timer_start(&timeout, [](uv_timer_t* t) {
        printf("  TIMEOUT — no connection received\n");
        auto* d = static_cast<HyperDHT*>(t->data);
        d->destroy();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 300000, 0);  // 5 minutes

    uv_run(&loop, UV_RUN_DEFAULT);

    if (got_connection) {
        printf("  SUCCESS — JS client connected to C++ server!\n");
    }

    EXPECT_TRUE(got_connection) << "No connection received within 120s";

    uv_loop_close(&loop);
}
