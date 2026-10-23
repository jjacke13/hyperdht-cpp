#include <gtest/gtest.h>
#include <sodium.h>
#include <cstring>
#include "hyperdht/announce_sig.hpp"
#include "hyperdht/rpc_handlers.hpp"
#include "hyperdht/server.hpp"
#include "hyperdht/udx.hpp"

using namespace hyperdht;

static void pump(uv_loop_t& loop, unsigned ms = 30) {
    for (unsigned i = 0; i < ms; ++i) {
        uv_run(&loop, UV_RUN_NOWAIT);
        uv_sleep(1);
    }
}
static compact::Ipv4Address local(uint16_t port) {
    return compact::Ipv4Address::from_string("127.0.0.1", port);
}
static announce::TargetKey key(uint8_t byte) {
    announce::TargetKey k{}; k[0] = byte; return k;
}

TEST(Security, RelayCacheBoundsRefreshesAndProtectsListeners) {
    router::Router r(2);
    router::ForwardEntry listener;
    listener.on_peer_handshake = [](const auto&, const auto&, const auto&, bool, auto) {};
    r.set(key(0), std::move(listener));
    r.set(key(1), {}); r.set(key(2), {});
    EXPECT_NE(r.get(key(1)), nullptr); // promote 1 so 2 is evicted
    r.set(key(3), {});
    EXPECT_EQ(r.size(), 3u);
    EXPECT_FALSE(r.has(key(2)));
    EXPECT_TRUE(r.has(key(0)));
    r.set(key(0), {}); // a remote record cannot replace a listener
    EXPECT_TRUE(r.get(key(0))->on_peer_handshake);
    r.gc(uv_hrtime() / 1000000 + announce::DEFAULT_TTL_MS + 1);
    EXPECT_EQ(r.size(), 1u);
    EXPECT_TRUE(r.has(key(0)));
    r.clear(); EXPECT_EQ(r.size(), 0u);
    r.set(key(4), {}); EXPECT_TRUE(r.has(key(4)));
}

TEST(Security, RelayExpiryAndRefreshApplyOnRead) {
    router::Router r(2, 10);
    router::ForwardEntry entry; entry.record = {1};
    r.set(key(1), entry);
    uv_sleep(15);
    EXPECT_EQ(r.record(key(1)), nullptr);
    EXPECT_FALSE(r.has(key(1)));
    r.set(key(1), entry);
    uv_sleep(5);
    r.set(key(1), entry);
    uv_sleep(7);
    EXPECT_NE(r.record(key(1)), nullptr);
}

TEST(Security, SignedAnnouncementAndRefreshRespectRelayLimit) {
    uv_loop_t loop; ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        rpc::RpcSocket sock(&loop, {}); ASSERT_EQ(sock.bind(0, "127.0.0.1"), 0);
        sock.force_check_persistent();
        router::Router r(2);
        {
            rpc::RpcHandlers handlers(sock, &r);
            std::array<uint8_t, 32> preimage{}; preimage[0] = 42;
            for (int i = 0; i < 4; ++i) {
                noise::Seed seed{}; seed[0] = i;
                auto kp = noise::generate_keypair(seed);
                std::array<uint8_t, 32> target{};
                crypto_generichash(target.data(), 32, kp.public_key.data(), 32, nullptr, 0);
                messages::Request req;
                req.command = messages::CMD_ANNOUNCE; req.target = target;
                req.from.addr = local(sock.port()); req.token = sock.token_store().create("127.0.0.1");
                dht_messages::AnnounceMessage ann;
                dht_messages::PeerRecord peer; peer.public_key = kp.public_key; ann.peer = peer;
                if (i == 0) {
                    std::array<uint8_t, 32> hash{};
                    crypto_generichash(hash.data(), 32, preimage.data(), 32, nullptr, 0);
                    ann.refresh = hash;
                }
                ann.signature = announce_sig::sign_announce(target, sock.table().id(),
                    req.token->data(), req.token->size(), ann, kp);
                req.value = dht_messages::encode_announce_msg(ann); handlers.handle(req);
                EXPECT_LE(r.size(), 2u);
            }
            messages::Request req; req.command = messages::CMD_ANNOUNCE;
            req.target = key(0); req.from.addr = local(sock.port());
            req.token = sock.token_store().create("127.0.0.1");
            dht_messages::AnnounceMessage refresh; refresh.refresh = preimage;
            req.value = dht_messages::encode_announce_msg(refresh); handlers.handle(req);
            EXPECT_EQ(r.size(), 2u);
        }
        sock.close(); uv_run(&loop, UV_RUN_DEFAULT);
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

TEST(Security, RpcRejectsForeignUnsolicitedAndWrongSocketReplies) {
    uv_loop_t loop; ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        rpc::RpcSocket victim(&loop, {}), peer(&loop, {}), other(&loop, {});
        for (auto* s : {&victim, &peer, &other}) ASSERT_EQ(s->bind(0, "127.0.0.1"), 0);
        messages::Request req; req.internal = true; req.command = messages::CMD_PING;
        req.to.addr = local(peer.port());
        int replies = 0;
        auto tid = victim.request(req, [&](const auto&) { ++replies; }); ASSERT_NE(tid, 0);
        sockaddr_in address{}; int len = sizeof(address);
        ASSERT_EQ(udx_socket_getsockname(victim.client_socket_handle(),
            reinterpret_cast<sockaddr*>(&address), &len), 0);
        auto client = local(ntohs(address.sin_port));
        messages::Response forged; forged.tid = tid; forged.from.addr = local(4444);
        auto bytes = messages::encode_response(forged);
        other.udp_send(bytes, client); pump(loop);
        peer.udp_send(bytes, local(victim.port()), peer.socket_handle()); pump(loop);
        EXPECT_EQ(replies, 0); EXPECT_EQ(victim.nat_sampler().sampled(), 0);
        forged.tid = 0; bytes = messages::encode_response(forged);
        peer.udp_send(bytes, client, peer.socket_handle()); pump(loop);
        EXPECT_EQ(victim.nat_sampler().sampled(), 0);
        forged.tid = tid; bytes = messages::encode_response(forged);
        peer.udp_send(bytes, client, peer.socket_handle()); pump(loop);
        EXPECT_EQ(replies, 1); EXPECT_EQ(victim.nat_sampler().sampled(), 1);
        for (auto* s : {&victim, &peer, &other}) s->close();
        uv_run(&loop, UV_RUN_DEFAULT);
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

TEST(Security, QuickFirewallCrossSocketReplyStillWorks) {
    uv_loop_t loop; ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        rpc::RpcSocket client(&loop, {}), peer(&loop, {});
        ASSERT_EQ(client.bind(0, "127.0.0.1"), 0); ASSERT_EQ(peer.bind(0, "127.0.0.1"), 0);
        {
            rpc::RpcHandlers handlers(peer); handlers.install();
            EXPECT_TRUE(client.is_firewalled());
            client.quick_firewall_ping(local(peer.port())); pump(loop);
            EXPECT_FALSE(client.is_firewalled());
            EXPECT_TRUE(client.is_ephemeral());
        }
        client.close(); peer.close(); uv_run(&loop, UV_RUN_DEFAULT);
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

TEST(Security, UdxRejectsForeignResetButAcceptsPeerReset) {
    uv_loop_t loop; ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        udx::Udx u(&loop); udx::UdxSocket victim(u), peer(u), other(u);
        sockaddr_in bind{}; uv_ip4_addr("127.0.0.1", 0, &bind);
        for (auto* s : {&victim, &peer, &other}) ASSERT_EQ(s->bind(reinterpret_cast<sockaddr*>(&bind)), 0);
        sockaddr_in peer_addr{}, victim_addr{}; int n = sizeof(peer_addr);
        peer.getsockname(reinterpret_cast<sockaddr*>(&peer_addr), &n);
        n = sizeof(victim_addr); victim.getsockname(reinterpret_cast<sockaddr*>(&victim_addr), &n);
        int status = 0;
        udx::UdxStream stream(u, 1234, [](udx_stream_t* s, int err) {
            *static_cast<int*>(s->data) = err;
        }, nullptr);
        stream.handle()->data = &status;
        ASSERT_EQ(stream.connect(victim, 99, reinterpret_cast<sockaddr*>(&peer_addr)), 0);
        stream.firewall([](udx_stream_t* s, udx_socket_t*, const sockaddr*) {
            *static_cast<int*>(s->data) = 123; // a reset must never trigger migration
            return 1;
        });
        uint8_t packet[20] = {UDX_MAGIC_BYTE, UDX_VERSION, UDX_HEADER_DESTROY, 0};
        packet[4] = 0xd2; packet[5] = 0x04; // LE 1234
        uv_buf_t buf = uv_buf_init(reinterpret_cast<char*>(packet), sizeof(packet));
        udx_socket_send_t first{}, second{}, wrong_socket{};
        ASSERT_EQ(other.send(&first, &buf, 1, reinterpret_cast<sockaddr*>(&victim_addr), [](auto*, int) {}), 0);
        pump(loop); EXPECT_EQ(status, 0);
        sockaddr_in other_addr{}; n = sizeof(other_addr);
        other.getsockname(reinterpret_cast<sockaddr*>(&other_addr), &n);
        ASSERT_EQ(peer.send(&wrong_socket, &buf, 1, reinterpret_cast<sockaddr*>(&other_addr), [](auto*, int) {}), 0);
        pump(loop); EXPECT_EQ(status, 0);
        ASSERT_EQ(peer.send(&second, &buf, 1, reinterpret_cast<sockaddr*>(&victim_addr), [](auto*, int) {}), 0);
        pump(loop); EXPECT_EQ(status, UV_ECONNRESET);
        victim.close(); peer.close(); other.close(); uv_run(&loop, UV_RUN_DEFAULT);
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

TEST(Security, FullFirewallProbeRequiresExpectedSourceAndServerSocket) {
    uv_loop_t loop; ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        rpc::RpcSocket client(&loop, {}), peer(&loop, {}), other(&loop, {});
        for (auto* s : {&client, &peer, &other}) ASSERT_EQ(s->bind(0, "127.0.0.1"), 0);
        auto advertised = local(client.port());
        for (int i = 0; i < 3; ++i) {
            client.nat_sampler().add(advertised, compact::Ipv4Address::from_string("127.0.0." + std::to_string(i + 2), 49737));
            client.ring_sampler().add(advertised.host_string(), advertised.port);
        }
        routing::Node node; node.id = rpc::compute_peer_id(local(peer.port()));
        node.host = "127.0.0.1"; node.port = peer.port(); client.table().add(node);
        client.set_bootstrapped(true);
        uint16_t probe_tid = 0;
        peer.on_request([&](const auto& req) {
            if (req.command == messages::CMD_PING_NAT) probe_tid = req.tid;
        });
        for (int i = 0; i < rpc::STABLE_TICKS_INIT; ++i) client.background_tick();
        pump(loop); ASSERT_NE(probe_tid, 0);
        messages::Response resp; resp.tid = probe_tid; resp.from.addr = advertised;
        auto bytes = messages::encode_response(resp);
        other.udp_send(bytes, advertised, other.socket_handle()); pump(loop);
        EXPECT_TRUE(client.is_ephemeral()); EXPECT_TRUE(client.is_firewalled());
        sockaddr_in a{}; int len = sizeof(a);
        udx_socket_getsockname(client.client_socket_handle(), reinterpret_cast<sockaddr*>(&a), &len);
        peer.udp_send(bytes, local(ntohs(a.sin_port)), peer.socket_handle()); pump(loop);
        EXPECT_TRUE(client.is_ephemeral());
        peer.udp_send(bytes, advertised, peer.socket_handle()); pump(loop);
        EXPECT_FALSE(client.is_ephemeral()); EXPECT_FALSE(client.is_firewalled());
        for (auto* s : {&client, &peer, &other}) s->close();
        uv_run(&loop, UV_RUN_DEFAULT);
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

class UdxResetIPv6 : public testing::TestWithParam<bool> {};
TEST_P(UdxResetIPv6, SourceGuard) {
    const bool mapped = GetParam();
    {
        uv_loop_t loop; ASSERT_EQ(uv_loop_init(&loop), 0);
        {
            udx::Udx u(&loop); udx::UdxSocket victim(u), peer(u), other(u);
            sockaddr_in6 bind6{}; uv_ip6_addr(mapped ? "::" : "::1", 0, &bind6);
            int rc = victim.bind(reinterpret_cast<sockaddr*>(&bind6));
            if (rc == UV_EADDRNOTAVAIL || rc == UV_EAFNOSUPPORT) {
                victim.close(); peer.close(); other.close();
                uv_run(&loop, UV_RUN_DEFAULT);
                EXPECT_EQ(uv_loop_close(&loop), 0);
                GTEST_SKIP() << "IPv6 unavailable: " << uv_strerror(rc);
            }
            ASSERT_EQ(rc, 0);
            sockaddr_storage bind_peer{};
            if (mapped) uv_ip4_addr("127.0.0.1", 0, reinterpret_cast<sockaddr_in*>(&bind_peer));
            else uv_ip6_addr("::1", 0, reinterpret_cast<sockaddr_in6*>(&bind_peer));
            ASSERT_EQ(peer.bind(reinterpret_cast<sockaddr*>(&bind_peer)), 0);
            ASSERT_EQ(other.bind(reinterpret_cast<sockaddr*>(&bind_peer)), 0);
            sockaddr_storage peer_addr{}, destination{}; int n = sizeof(peer_addr);
            peer.getsockname(reinterpret_cast<sockaddr*>(&peer_addr), &n);
            sockaddr_in6 bound6{}; n = sizeof(bound6);
            victim.getsockname(reinterpret_cast<sockaddr*>(&bound6), &n);
            if (mapped) uv_ip4_addr("127.0.0.1", ntohs(bound6.sin6_port), reinterpret_cast<sockaddr_in*>(&destination));
            else uv_ip6_addr("::1", ntohs(bound6.sin6_port), reinterpret_cast<sockaddr_in6*>(&destination));
            int status = 0;
            udx::UdxStream stream(u, 1234, [](udx_stream_t* s, int err) {
                *static_cast<int*>(s->data) = err;
            }, nullptr);
            stream.handle()->data = &status;
            ASSERT_EQ(stream.connect(victim, 99, reinterpret_cast<sockaddr*>(&peer_addr)), 0);
            uint8_t packet[20] = {UDX_MAGIC_BYTE, UDX_VERSION, UDX_HEADER_DESTROY, 0};
            packet[4] = 0xd2; packet[5] = 0x04;
            uv_buf_t buf = uv_buf_init(reinterpret_cast<char*>(packet), sizeof(packet));
            udx_socket_send_t first{}, second{};
            ASSERT_EQ(other.send(&first, &buf, 1, reinterpret_cast<sockaddr*>(&destination), [](auto*, int) {}), 0);
            pump(loop); EXPECT_EQ(status, 0);
            ASSERT_EQ(peer.send(&second, &buf, 1, reinterpret_cast<sockaddr*>(&destination), [](auto*, int) {}), 0);
            pump(loop); EXPECT_EQ(status, UV_ECONNRESET);
            victim.close(); peer.close(); other.close(); uv_run(&loop, UV_RUN_DEFAULT);
        }
        EXPECT_EQ(uv_loop_close(&loop), 0);
    }
}

INSTANTIATE_TEST_SUITE_P(Security, UdxResetIPv6, testing::Bool());

TEST(Security, PersistentPingNatCanReplyOnClientSocket) {
    uv_loop_t loop; ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        rpc::RpcSocket client(&loop, {}), peer(&loop, {});
        ASSERT_EQ(client.bind(0, "127.0.0.1"), 0); ASSERT_EQ(peer.bind(0, "127.0.0.1"), 0);
        client.force_check_persistent();
        {
            rpc::RpcHandlers handlers(peer); handlers.install();
            sockaddr_in addr{}; int len = sizeof(addr);
            udx_socket_getsockname(client.client_socket_handle(), reinterpret_cast<sockaddr*>(&addr), &len);
            uint16_t port = ntohs(addr.sin_port);
            messages::Request req; req.internal = true; req.command = messages::CMD_PING_NAT;
            req.to.addr = local(peer.port());
            req.value = std::vector<uint8_t>{static_cast<uint8_t>(port), static_cast<uint8_t>(port >> 8)};
            bool replied = false;
            ASSERT_NE(client.request(req, [&](const auto&) { replied = true; }), 0);
            pump(loop); EXPECT_TRUE(replied);
        }
        client.close(); peer.close(); uv_run(&loop, UV_RUN_DEFAULT);
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}
