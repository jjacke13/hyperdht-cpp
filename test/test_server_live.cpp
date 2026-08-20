// Live server test — listens for an incoming connection from a JS client.
// Generates a random keypair each run. Prints the pubkey for the JS client.
// Exits after first connection or 120s timeout.

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/dht.hpp"
#include "hyperdht/udx.hpp"

using namespace hyperdht;

TEST(LiveServer, WaitForConnection) {
    // HYPERDHT_LIVE_SEED=<64 hex chars> — derive the keypair deterministically
    // instead of generating a fresh one per run. A random key means the remote
    // side has to be handed a new key every restart, which makes a two-machine
    // test impossible to coordinate; with a fixed seed the public key is stable
    // and the remote client can be pointed at it once and re-run at will.
    noise::Keypair kp;
    const char* seed_hex = std::getenv("HYPERDHT_LIVE_SEED");
    if (seed_hex && std::strlen(seed_hex) == 64) {
        noise::Seed seed{};
        for (int i = 0; i < 32; i++) {
            seed[i] = static_cast<uint8_t>(
                std::stoul(std::string(seed_hex + i * 2, 2), nullptr, 16));
        }
        kp = noise::generate_keypair(seed);
        printf("  Keypair from HYPERDHT_LIVE_SEED (deterministic)\n");
    } else {
        kp = noise::generate_keypair();  // Random keypair for each run
    }

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

    // HYPERDHT_LIVE_WAN_ONLY=1 — stop advertising our LAN addresses, so a
    // client on the same subnet cannot take the LAN shortcut and has to
    // holepunch to our public address like a real remote peer. Without this,
    // a same-machine or same-LAN cross-test connects in ~1s over 192.168.x
    // and never exercises the punch path at all (JS `dht.stats.punches` stays
    // all-zero, which is the tell).
    if (const char* wan = std::getenv("HYPERDHT_LIVE_WAN_ONLY")) {
        if (wan[0] == '1') {
            for (const auto& a : dht.local_addresses_now()) {
                printf("  WAN-ONLY: excluding local address %s\n",
                       a.host_string().c_str());
                dht.exclude_local_address(a.host_string());
            }
        }
    }

    auto* srv = dht.create_server();

    // HYPERDHT_LIVE_NO_FAST_PING=1 — suppress the fast-mode ping so the
    // connection has to complete through the slow probe loop. Combined with
    // WAN_ONLY above this reproduces the field-failing shape deliberately:
    // the reports were "it only connects when fast-mode fires", which is
    // exactly what you cannot reproduce while fast mode is allowed to fire.
    if (const char* nf = std::getenv("HYPERDHT_LIVE_NO_FAST_PING")) {
        if (nf[0] == '1') {
            srv->disable_fast_mode_ping = true;
            printf("  NO-FAST-PING: fast-mode ping suppressed; "
                   "the punch must come from the probe loop\n");
        }
    }

    bool got_connection = false;
    server::ConnectionInfo conn_info;

    // HYPERDHT_LIVE_STAY=1 — keep serving after the first connection instead
    // of tearing the DHT down. A two-machine test wants several attempts
    // against ONE announced server (the announce itself takes seconds to
    // propagate, so restarting per attempt tests the announcer more than the
    // punch).
    const char* stay_env = std::getenv("HYPERDHT_LIVE_STAY");
    const bool stay = stay_env && stay_env[0] == '1';
    int connections = 0;

    srv->listen(kp, [&](const server::ConnectionInfo& info) {
        printf("  CONNECTION RECEIVED! (#%d)\n", ++connections);
        printf("    Remote pubkey: ");
        for (int i = 0; i < 8; i++) printf("%02x", info.remote_public_key[i]);
        printf("...\n");
        printf("    Peer address: %s:%u\n",
               info.peer_address.host_string().c_str(), info.peer_address.port);
        printf("    UDX IDs: local=%u remote=%u\n",
               info.local_udx_id, info.remote_udx_id);
        const auto& s = dht.stats();
        printf("    punches so far: consistent=%d random=%d open=%d\n",
               s.punches.consistent, s.punches.random, s.punches.open);
        fflush(stdout);

        got_connection = true;
        conn_info = info;

        if (!stay) dht.destroy();  // Stop after first connection
    });

    // HYPERDHT_LIVE_TIMEOUT_S — how long to stay up (default 300).
    uint64_t timeout_s = 300;
    if (const char* t = std::getenv("HYPERDHT_LIVE_TIMEOUT_S")) {
        timeout_s = std::strtoull(t, nullptr, 10);
        if (timeout_s == 0) timeout_s = 300;
    }

    printf("  Listening... (up to %llus, stay=%d)\n",
           static_cast<unsigned long long>(timeout_s), stay ? 1 : 0);
    printf("  Run the JS client now!\n");
    fflush(stdout);

    // Overall timeout
    uv_timer_t timeout;
    uv_timer_init(&loop, &timeout);
    timeout.data = &dht;
    uv_timer_start(&timeout, [](uv_timer_t* t) {
        printf("  Time is up — shutting down\n");
        auto* d = static_cast<HyperDHT*>(t->data);
        d->destroy();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, timeout_s * 1000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    if (got_connection) {
        printf("  SUCCESS — JS client connected to C++ server!\n");
    }

    // Which strategy actually ran. All-zero with a connection means the peer
    // took a shortcut (LAN, or already-open) and the punch path was never
    // exercised — re-run with HYPERDHT_LIVE_WAN_ONLY=1 to force it.
    const auto& st = dht.stats();
    printf("  punches: consistent=%d random=%d open=%d\n",
           st.punches.consistent, st.punches.random, st.punches.open);
    // Must be 0. Anything else means a socket close was refused because a
    // stream was still attached, i.e. someone dropped a socket keepalive
    // early (see hyperdht_stream_open's contract).
    printf("  busy_close_count: %llu\n",
           static_cast<unsigned long long>(udx::busy_close_count()));

    EXPECT_TRUE(got_connection) << "No connection received within 120s";

    uv_loop_close(&loop);
}
