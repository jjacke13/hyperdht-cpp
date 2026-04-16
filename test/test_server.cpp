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

// JS: server.js:251 `await this.firewall(...)` — the async firewall
// callback receives a completion handler and the handshake response
// is deferred until the callback fires.
TEST(Server, AsyncFirewallDeferredAccept) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);
    router::Router router;
    Server srv(socket, router);

    noise::Seed server_seed{}; server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    srv.listen(server_kp, [](const ConnectionInfo&) {});

    // Capture the `done` completion handler — invoke it LATER.
    Server::FirewallDoneCb deferred_done;
    std::array<uint8_t, 32> captured_pk{};
    int fw_calls = 0;

    srv.set_firewall_async(
        [&](const std::array<uint8_t, 32>& pk, const peer_connect::NoisePayload&,
            const compact::Ipv4Address&, Server::FirewallDoneCb done) {
            fw_calls++;
            captured_pk = pk;
            deferred_done = std::move(done);
        });

    // Build + send a client handshake via the router.
    noise::Seed client_seed{}; client_seed.fill(0x22);
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

    bool reply_sent = false;
    router.handle_peer_handshake(
        req,
        [&reply_sent](const messages::Response&) { reply_sent = true; },
        [](const messages::Request&) {});

    // Firewall was invoked exactly once, but the reply is still
    // pending — `done` wasn't called yet.
    EXPECT_EQ(fw_calls, 1);
    EXPECT_EQ(captured_pk, client_kp.public_key);
    EXPECT_FALSE(reply_sent);
    ASSERT_TRUE(deferred_done);

    // User accepts asynchronously → reply flows now.
    deferred_done(/*reject=*/false);
    EXPECT_TRUE(reply_sent);

    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// Calling `done` twice is a silent no-op on the second call. Previous
// implementation would have moved-from an already-moved
// PendingHandshake and produced a garbage second ServerConnection
// that leaks a udx_stream_t.
TEST(Server, AsyncFirewallDoneCalledTwiceIsNoop) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);
    router::Router router;
    Server srv(socket, router);

    noise::Seed server_seed{}; server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);
    srv.listen(server_kp, [](const ConnectionInfo&) {});

    Server::FirewallDoneCb deferred_done;
    srv.set_firewall_async(
        [&](const auto&, const auto&, const auto&,
            Server::FirewallDoneCb done) { deferred_done = std::move(done); });

    // Build + dispatch handshake
    noise::Seed client_seed{}; client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);
    const auto& prol = dht_messages::ns_peer_handshake();
    noise::NoiseIK client_noise(true, client_kp, prol.data(), prol.size(),
                                 &server_kp.public_key);
    peer_connect::NoisePayload cp;
    cp.version = 1;
    cp.firewall = peer_connect::FIREWALL_OPEN;
    cp.udx = peer_connect::UdxInfo{1, false, 1, 0};
    cp.has_secret_stream = true;
    cp.addresses4.push_back(
        compact::Ipv4Address::from_string("10.0.0.1", 5000));
    auto cpb = peer_connect::encode_noise_payload(cp);
    auto msg1 = client_noise.send(cpb.data(), cpb.size());

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

    int reply_count = 0;
    router.handle_peer_handshake(req,
        [&reply_count](const messages::Response&) { reply_count++; },
        [](const messages::Request&) {});

    ASSERT_TRUE(deferred_done);
    deferred_done(/*reject=*/false);
    EXPECT_EQ(reply_count, 1);

    // Second call must be a silent no-op.
    deferred_done(/*reject=*/true);
    EXPECT_EQ(reply_count, 1) << "second done() must not produce another reply";

    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// If the Server is closed BEFORE the async firewall completes,
// invoking `done` must be a silent no-op (no dispatch, no UAF).
TEST(Server, AsyncFirewallAfterServerCloseIsNoop) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);
    router::Router router;
    Server srv(socket, router);

    noise::Seed server_seed{}; server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);
    srv.listen(server_kp, [](const ConnectionInfo&) {});

    Server::FirewallDoneCb deferred_done;
    srv.set_firewall_async(
        [&](const auto&, const auto&, const auto&,
            Server::FirewallDoneCb done) { deferred_done = std::move(done); });

    noise::Seed client_seed{}; client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);
    const auto& prol = dht_messages::ns_peer_handshake();
    noise::NoiseIK client_noise(true, client_kp, prol.data(), prol.size(),
                                 &server_kp.public_key);
    peer_connect::NoisePayload cp;
    cp.version = 1;
    cp.firewall = peer_connect::FIREWALL_OPEN;
    cp.udx = peer_connect::UdxInfo{1, false, 1, 0};
    cp.has_secret_stream = true;
    cp.addresses4.push_back(
        compact::Ipv4Address::from_string("10.0.0.1", 5000));
    auto cpb = peer_connect::encode_noise_payload(cp);
    auto msg1 = client_noise.send(cpb.data(), cpb.size());
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

    int reply_count = 0;
    router.handle_peer_handshake(req,
        [&reply_count](const messages::Response&) { reply_count++; },
        [](const messages::Request&) {});
    ASSERT_TRUE(deferred_done);

    // Tear down the server BEFORE the user completes the firewall.
    srv.close();

    // done() must not touch `this` (UAF guard via weak_ptr alive_).
    // Can't actually delete the Server here — its stack scope covers
    // the entire test — but close() flips *alive_=false, which the
    // weak_ptr guard treats as "expired".
    deferred_done(/*reject=*/false);
    EXPECT_EQ(reply_count, 0) << "post-close done() must not produce a reply";

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// async firewall that rejects: handshake completes, reply is sent
// with ERROR_ABORTED, session not registered.
TEST(Server, AsyncFirewallDeferredReject) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);
    router::Router router;
    Server srv(socket, router);

    noise::Seed server_seed{}; server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);
    srv.listen(server_kp, [](const ConnectionInfo&) {});

    Server::FirewallDoneCb deferred_done;
    srv.set_firewall_async(
        [&](const auto&, const auto&, const auto&,
            Server::FirewallDoneCb done) { deferred_done = std::move(done); });

    // Build handshake msg1
    noise::Seed client_seed{}; client_seed.fill(0x22);
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

    bool reply_sent = false;
    router.handle_peer_handshake(req,
        [&reply_sent](const messages::Response&) { reply_sent = true; },
        [](const messages::Request&) {});

    ASSERT_TRUE(deferred_done);
    deferred_done(/*reject=*/true);
    // Reply still goes out — but with ERROR_ABORTED inside the Noise
    // payload. Client sees a clean refusal instead of a hang.
    EXPECT_TRUE(reply_sent);

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
// Address — §14: returns NAT-sampled host/port, not bound socket port.
// ---------------------------------------------------------------------------

TEST(Server, AddressEmptyBeforeListen) {
    // JS: `if (!this._keyPair) return null` — in C++ we return a
    // default-constructed AddressInfo (zero public_key + empty host).
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    auto addr = srv.address();
    EXPECT_TRUE(addr.host.empty());
    EXPECT_EQ(addr.port, 0u);
    // public_key is zero-initialized
    std::array<uint8_t, 32> zero{};
    EXPECT_EQ(addr.public_key, zero);

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Server, AddressBeforeNatSample) {
    // Without any NAT samples, host="" and port=0 — the NAT sampler has
    // not classified us yet. The bound socket port is intentionally NOT
    // reported (it's local, not public).
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
    EXPECT_TRUE(addr.host.empty());
    EXPECT_EQ(addr.port, 0u);

    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Server, AddressReflectsNatSampler) {
    // After feeding a sample into the NAT sampler, the server's address
    // reflects the NAT-detected (public) host/port — matching JS
    // `server.address() → { host: dht.host, port: dht.port }`.
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

    // Inject a single NAT sample: seen-by node 203.0.113.1 reports us at
    // 198.51.100.7:55555. One sample populates host_/port_ (classification
    // still waits for ≥3 samples, but the "current best" updates immediately).
    auto seen_by = compact::Ipv4Address::from_string("203.0.113.1", 49737);
    auto our_pub = compact::Ipv4Address::from_string("198.51.100.7", 55555);
    ASSERT_TRUE(socket.nat_sampler().add(our_pub, seen_by));

    auto addr = srv.address();
    EXPECT_EQ(addr.public_key, kp.public_key);
    EXPECT_EQ(addr.host, "198.51.100.7");
    EXPECT_EQ(addr.port, 55555u);

    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// NotifyOnline — §8: wakes the announcer's update cycle.
// ---------------------------------------------------------------------------

TEST(Server, NotifyOnlineBeforeListenNoOp) {
    // Must not crash when called before listen() (no announcer yet).
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    srv.notify_online();  // no-op; must not crash
    EXPECT_FALSE(srv.is_listening());

    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Server, NotifyOnlineWhileSuspendedNoOp) {
    // JS semantics: notifyOnline is a no-op if the server is suspended,
    // because the announcer is stopped during suspend.
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    noise::Seed seed{};
    seed.fill(0x77);
    auto kp = noise::generate_keypair(seed);
    srv.listen(kp, [](const ConnectionInfo&) {});

    srv.suspend();
    EXPECT_TRUE(srv.is_suspended());

    srv.notify_online();  // no-op while suspended; must not crash

    srv.resume();
    srv.close();
    socket.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Server, NotifyOnlineIdempotentWhileListening) {
    // Repeated calls while an update is already in flight must be safe.
    // `Announcer::update()` is guarded by `updating_`, so a second call
    // during the same cycle is a no-op.
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    socket.bind(0);

    router::Router router;
    Server srv(socket, router);

    noise::Seed seed{};
    seed.fill(0x55);
    auto kp = noise::generate_keypair(seed);
    srv.listen(kp, [](const ConnectionInfo&) {});

    srv.notify_online();
    srv.notify_online();
    srv.notify_online();
    EXPECT_TRUE(srv.is_listening());

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
