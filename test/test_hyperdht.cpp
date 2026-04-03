// HyperDHT class tests — constructor, bind, create_server, destroy.
// Live connect test is separate (test_live_connect.cpp).

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/dht.hpp"

using namespace hyperdht;

TEST(HyperDHT, CreateAndDestroy) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    {
        HyperDHT dht(&loop);
        EXPECT_FALSE(dht.is_bound());
        EXPECT_FALSE(dht.is_destroyed());

        int rc = dht.bind();
        EXPECT_EQ(rc, 0);
        EXPECT_TRUE(dht.is_bound());
        EXPECT_GT(dht.port(), 0u);

        dht.destroy();
        EXPECT_TRUE(dht.is_destroyed());
    }

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
