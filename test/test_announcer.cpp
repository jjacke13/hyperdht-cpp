// Announcer unit tests — verify record building, relay tracking, and lifecycle.
// These test the non-network parts. Live network test comes in Step 7 (Server).

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/announcer.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/rpc.hpp"

using namespace hyperdht;
using namespace hyperdht::announcer;

TEST(Announcer, RecordEncodesPubkey) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);

    Announcer ann(socket, kp, target);

    // Record should contain our public key
    EXPECT_FALSE(ann.record().empty());

    auto peer = dht_messages::decode_peer_record(
        ann.record().data(), ann.record().size());
    EXPECT_EQ(peer.public_key, kp.public_key);
    EXPECT_TRUE(peer.relay_addresses.empty());  // No relays yet

    // No relays before start
    EXPECT_TRUE(ann.relays().empty());

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Announcer, StartStop) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);

    Announcer ann(socket, kp, target);

    EXPECT_FALSE(ann.is_running());
    ann.start();
    EXPECT_TRUE(ann.is_running());

    bool stopped = false;
    ann.stop([&] { stopped = true; });
    EXPECT_TRUE(stopped);
    EXPECT_FALSE(ann.is_running());

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Announcer, DoubleStartNoop) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    target.fill(0x33);

    Announcer ann(socket, kp, target);
    ann.start();
    ann.start();  // Should not crash or double-init
    EXPECT_TRUE(ann.is_running());

    ann.stop();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}
