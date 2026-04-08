// Server class tests — listen, close, handshake dispatch through Router.

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/server.hpp"

using namespace hyperdht;
using namespace hyperdht::server;

TEST(Server, ListenAndClose) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;

    Server srv(socket, router);

    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);

    EXPECT_FALSE(srv.is_listening());

    srv.listen(kp, [](const ConnectionInfo&) {});

    EXPECT_TRUE(srv.is_listening());
    EXPECT_EQ(router.size(), 1u);  // Registered in router

    bool closed = false;
    srv.close([&] { closed = true; });
    EXPECT_TRUE(closed);
    EXPECT_TRUE(srv.is_closed());
    EXPECT_EQ(router.size(), 0u);  // Removed from router

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Server, HandshakeViaRouter) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    bool connection_received = false;
    ConnectionInfo received_info;

    srv.listen(server_kp, [&](const ConnectionInfo& info) {
        connection_received = true;
        received_info = info;
    });

    // Simulate a client handshake through the Router
    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    // Build client Noise msg1
    const auto& prol = dht_messages::ns_peer_handshake();
    noise::NoiseIK client_noise(true, client_kp, prol.data(), prol.size(),
                                 &server_kp.public_key);

    peer_connect::NoisePayload client_payload;
    client_payload.version = 1;
    client_payload.firewall = peer_connect::FIREWALL_OPEN;  // OPEN = direct connect
    client_payload.udx = peer_connect::UdxInfo{1, false, 12345, 0};
    client_payload.has_secret_stream = true;
    client_payload.addresses4.push_back(
        compact::Ipv4Address::from_string("10.0.0.1", 5000));

    auto payload_bytes = peer_connect::encode_noise_payload(client_payload);
    auto msg1 = client_noise.send(payload_bytes.data(), payload_bytes.size());

    // Build HandshakeMessage
    peer_connect::HandshakeMessage hs_msg;
    hs_msg.mode = peer_connect::MODE_FROM_CLIENT;
    hs_msg.noise = msg1;
    auto hs_value = peer_connect::encode_handshake_msg(hs_msg);

    // Build a fake PEER_HANDSHAKE request
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32,
                       server_kp.public_key.data(), 32, nullptr, 0);

    messages::Request req;
    req.target = target;
    req.value = hs_value;
    req.from.addr = compact::Ipv4Address::from_string("10.0.0.1", 5000);
    req.tid = 99;

    // Dispatch through router
    bool handled = router.handle_peer_handshake(req,
        [&](const messages::Response& resp) {
            // Server responded — client can process msg2
            if (resp.value.has_value() && !resp.value->empty()) {
                auto resp_hs = peer_connect::decode_handshake_msg(
                    resp.value->data(), resp.value->size());
                auto decrypted = client_noise.recv(
                    resp_hs.noise.data(), resp_hs.noise.size());
                EXPECT_TRUE(decrypted.has_value());
                EXPECT_TRUE(client_noise.is_complete());
            }
        },
        [](const messages::Request&) {});

    EXPECT_TRUE(handled);

    // Since client is OPEN, server should call on_connection directly
    EXPECT_TRUE(connection_received);
    EXPECT_EQ(received_info.remote_public_key, client_kp.public_key);
    EXPECT_EQ(received_info.remote_udx_id, 12345u);
    EXPECT_FALSE(received_info.is_initiator);

    // Keys should be complementary
    EXPECT_EQ(client_noise.tx_key(), received_info.rx_key);
    EXPECT_EQ(client_noise.rx_key(), received_info.tx_key);

    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Server, FirewallRejectsConnection) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    bool connection_received = false;
    srv.listen(server_kp, [&](const ConnectionInfo&) {
        connection_received = true;
    });

    // Set firewall to reject all
    srv.set_firewall([](const auto&, const auto&, const auto&) { return true; });

    // Build client handshake
    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    const auto& prol = dht_messages::ns_peer_handshake();
    noise::NoiseIK client_noise(true, client_kp, prol.data(), prol.size(),
                                 &server_kp.public_key);

    peer_connect::NoisePayload client_payload;
    client_payload.version = 1;
    client_payload.firewall = peer_connect::FIREWALL_OPEN;
    client_payload.udx = peer_connect::UdxInfo{1, false, 1, 0};
    client_payload.has_secret_stream = true;
    client_payload.addresses4.push_back(
        compact::Ipv4Address::from_string("10.0.0.1", 5000));

    auto payload_bytes = peer_connect::encode_noise_payload(client_payload);
    auto msg1 = client_noise.send(payload_bytes.data(), payload_bytes.size());

    peer_connect::HandshakeMessage hs_msg;
    hs_msg.mode = peer_connect::MODE_FROM_CLIENT;
    hs_msg.noise = msg1;

    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32,
                       server_kp.public_key.data(), 32, nullptr, 0);

    messages::Request req;
    req.target = target;
    req.value = peer_connect::encode_handshake_msg(hs_msg);
    req.from.addr = compact::Ipv4Address::from_string("10.0.0.1", 5000);
    req.tid = 1;

    router.handle_peer_handshake(req, [](const messages::Response&) {},
                                     [](const messages::Request&) {});

    // Firewall rejected — no connection
    EXPECT_FALSE(connection_received);

    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Server, DoubleListenNoop) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    noise::Seed seed{};
    seed.fill(0x11);
    auto kp = noise::generate_keypair(seed);

    srv.listen(kp, [](const ConnectionInfo&) {});
    srv.listen(kp, [](const ConnectionInfo&) {});  // Should not crash

    EXPECT_TRUE(srv.is_listening());
    EXPECT_EQ(router.size(), 1u);

    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Suspend / Resume
// ---------------------------------------------------------------------------

TEST(Server, SuspendResume) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    noise::Seed seed{};
    seed.fill(0x22);
    auto kp = noise::generate_keypair(seed);

    srv.listen(kp, [](const ConnectionInfo&) {});
    EXPECT_TRUE(srv.is_listening());
    EXPECT_FALSE(srv.is_suspended());

    srv.suspend();
    EXPECT_TRUE(srv.is_suspended());
    EXPECT_TRUE(srv.is_listening());  // Still listening, just suspended

    srv.resume();
    EXPECT_FALSE(srv.is_suspended());

    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

TEST(Server, Address) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    noise::Seed seed{};
    seed.fill(0x33);
    auto kp = noise::generate_keypair(seed);

    srv.listen(kp, [](const ConnectionInfo&) {});

    auto addr = srv.address();
    EXPECT_EQ(addr.public_key, kp.public_key);
    EXPECT_GT(addr.port, 0u);

    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

TEST(Server, ShareLocalAddressDefault) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    EXPECT_TRUE(srv.share_local_address);  // Default: true
    EXPECT_EQ(srv.handshake_clear_wait, 10000u);  // Default: 10s

    srv.share_local_address = false;
    EXPECT_FALSE(srv.share_local_address);

    srv.handshake_clear_wait = 5000;
    EXPECT_EQ(srv.handshake_clear_wait, 5000u);

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}
