// Server per-session punch socket — JS parity for hyperdht/lib/server.js.
//
// JS acquires a pool socket per session (server.js:436 `new Holepuncher(...)`
// → holepuncher.js:14 `dht._socketPool.acquire()`), answers the handshake
// from it (server.js:481 `{ socket: h.puncher.socket, noise: h.reply }`),
// receives the PEER_HOLEPUNCH rounds on it (server.js:508-511
// `req.socket === p.socket`), answers those from it (router.js:233
// `{ socket: reply.socket }`), and holds every round until the socket's NAT
// sampling concludes (server.js:519 `await p.analyze(false)`).
//
// The harness is deliberately wire-level: a handful of plain udx sockets
// stand in for the relaying DHT nodes so every assertion is about the UDP
// source port an assertion actually observed, not about an internal call.

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include <functional>
#include <memory>
#include <vector>

#include "hyperdht/compact.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/server.hpp"
#include "hyperdht/udx.hpp"

using namespace hyperdht;
using namespace hyperdht::server;
using compact::Ipv4Address;

namespace {

uint16_t port_of(udx_socket_t* s) {
    struct sockaddr_in a{};
    int len = sizeof(a);
    udx_socket_getsockname(s, reinterpret_cast<struct sockaddr*>(&a), &len);
    return ntohs(a.sin_port);
}

// A stand-in DHT node: answers the punch socket's NAT-discovery PINGs (on
// demand, so a test can hold sampling open) and records everything else it
// receives together with the UDP source port it arrived from.
struct FakeNode {
    explicit FakeNode(udx::Udx& u) : sock(u) {}

    udx::UdxSocket sock;
    uint16_t port = 0;
    Ipv4Address observed{};      // what this node claims our address is
    bool auto_answer_ping = false;

    std::vector<std::pair<uint16_t, Ipv4Address>> queued_pings;  // tid, src
    int probes = 0;
    uint16_t first_probe_src = 0;
    std::vector<std::pair<std::vector<uint8_t>, uint16_t>> handshakes;
    std::vector<std::pair<std::vector<uint8_t>, uint16_t>> rounds;

    Ipv4Address addr() const {
        return Ipv4Address::from_string("127.0.0.1", port);
    }

    void answer_pings() {
        for (const auto& [tid, dest] : queued_pings) {
            messages::Response resp;
            resp.tid = tid;
            // Wire `to` — how this node sees the socket that pinged it.
            resp.from.addr = observed;
            send(messages::encode_response(resp), dest);
        }
        queued_pings.clear();
    }

    void send(const std::vector<uint8_t>& data, const Ipv4Address& to) {
        struct SendCtx {
            udx_socket_send_t req{};
            std::vector<uint8_t> buf;
        };
        auto* ctx = new SendCtx;
        ctx->buf = data;
        ctx->req.data = ctx;
        uv_buf_t b = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                 static_cast<unsigned int>(ctx->buf.size()));
        struct sockaddr_in dest{};
        uv_ip4_addr(to.host_string().c_str(), to.port, &dest);
        sock.send(&ctx->req, &b, 1,
                  reinterpret_cast<const struct sockaddr*>(&dest),
                  [](udx_socket_send_t* r, int) {
                      delete static_cast<SendCtx*>(r->data);
                  });
    }

    static void on_recv(udx_socket_t* s, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr) {
        auto* self = static_cast<FakeNode*>(s->data);
        if (!self || nread <= 0 || !addr) return;
        const auto* in = reinterpret_cast<const struct sockaddr_in*>(addr);
        char host[INET_ADDRSTRLEN];
        uv_ip4_name(in, host, sizeof(host));
        uint16_t src = ntohs(in->sin_port);
        const auto* data = reinterpret_cast<const uint8_t*>(buf->base);
        auto len = static_cast<size_t>(nread);

        if (len == 1 && data[0] == 0x00) {
            if (self->probes++ == 0) self->first_probe_src = src;
            return;
        }
        messages::Request req;
        messages::Response resp;
        if (messages::decode_message(data, len, req, resp) !=
            messages::REQUEST_ID) {
            return;
        }
        if (req.command == messages::CMD_PING && req.internal) {
            self->queued_pings.push_back(
                {req.tid, Ipv4Address::from_string(host, src)});
            if (self->auto_answer_ping) self->answer_pings();
            return;
        }
        if (!req.value.has_value()) return;
        if (req.command == messages::CMD_PEER_HANDSHAKE) {
            self->handshakes.push_back({*req.value, src});
        } else if (req.command == messages::CMD_PEER_HOLEPUNCH) {
            self->rounds.push_back({*req.value, src});
        }
    }
};

}  // namespace

class ServerPunchSocket : public ::testing::Test {
  protected:
    static constexpr size_t NODE_COUNT = 6;  // >= discover's MIN_SAMPLES (4)

    uv_loop_t loop_{};
    std::unique_ptr<rpc::RpcSocket> socket_;
    router::Router router_;
    std::unique_ptr<Server> srv_;
    std::unique_ptr<udx::Udx> fake_udx_;
    std::vector<std::unique_ptr<FakeNode>> nodes_;
    noise::Keypair server_kp_;
    // What the fake nodes report as our punch socket's public address.
    Ipv4Address our_public_ = Ipv4Address::from_string("198.51.100.7", 55555);

    // Client handshake state, filled by do_handshake().
    std::shared_ptr<noise::NoiseIK> client_noise_;
    std::shared_ptr<holepunch::SecurePayload> client_secure_;
    uint32_t hp_id_ = 0;
    std::array<uint8_t, 32> target_{};

    void SetUp() override {
        uv_loop_init(&loop_);

        routing::NodeId our_id{};
        our_id.fill(0x42);
        socket_ = std::make_unique<rpc::RpcSocket>(&loop_, our_id);
        ASSERT_EQ(socket_->bind(0), 0);

        fake_udx_ = std::make_unique<udx::Udx>(&loop_);
        for (size_t i = 0; i < NODE_COUNT; i++) {
            auto node = std::make_unique<FakeNode>(*fake_udx_);
            struct sockaddr_in any{};
            uv_ip4_addr("127.0.0.1", 0, &any);
            ASSERT_EQ(node->sock.bind(
                          reinterpret_cast<const struct sockaddr*>(&any)), 0);
            node->port = port_of(node->sock.handle());
            node->observed = our_public_;
            node->sock.handle()->data = node.get();
            ASSERT_EQ(node->sock.recv_start(FakeNode::on_recv), 0);

            // Seed the routing table so discover_pool_addresses targets these
            // loopback nodes instead of the public bootstrap servers.
            routing::Node entry;
            entry.id.fill(static_cast<uint8_t>(i + 1));
            entry.host = "127.0.0.1";
            entry.port = node->port;
            socket_->table().add(entry);

            nodes_.push_back(std::move(node));
        }

        noise::Seed seed{};
        seed.fill(0x11);
        server_kp_ = noise::generate_keypair(seed);
        crypto_generichash(target_.data(), 32,
                           server_kp_.public_key.data(), 32, nullptr, 0);

        srv_ = std::make_unique<Server>(*socket_, router_);
        srv_->listen(server_kp_, [](const ConnectionInfo&) {});
    }

    void TearDown() override {
        if (srv_) srv_->close();
        if (socket_) socket_->close();
        for (auto& n : nodes_) n->sock.close();
        uv_run(&loop_, UV_RUN_DEFAULT);
        srv_.reset();
        socket_.reset();
        nodes_.clear();
        fake_udx_.reset();
        uv_loop_close(&loop_);
    }

    FakeNode& relay() { return *nodes_[0]; }
    FakeNode& client_node() { return *nodes_[1]; }

    uint16_t main_port() { return port_of(socket_->active_socket()); }

    server_connection::ServerConnection* conn() { return srv_->session(hp_id_); }

    uint16_t punch_port() {
        auto* c = conn();
        if (!c || !c->punch_socket) return 0;
        return port_of(c->punch_socket->socket_handle());
    }

    bool run_loop_until(const std::function<bool()>& pred,
                        uint64_t timeout_ms = 2000) {
        uv_timer_t tick{};
        uv_timer_init(&loop_, &tick);
        uv_timer_start(&tick, [](uv_timer_t*) {}, 1, 1);
        uv_update_time(&loop_);
        uint64_t deadline = uv_now(&loop_) + timeout_ms;
        while (!pred() && uv_now(&loop_) < deadline) {
            uv_run(&loop_, UV_RUN_ONCE);
        }
        uv_timer_stop(&tick);
        uv_close(reinterpret_cast<uv_handle_t*>(&tick), nullptr);
        uv_run(&loop_, UV_RUN_NOWAIT);
        return pred();
    }

    void pump_ms(uint64_t ms) { run_loop_until([] { return false; }, ms); }

    // Drive a PEER_HANDSHAKE through the Router exactly as rpc_handlers does,
    // with a REAL relay egress so the fake relay observes the source port.
    // `relayed` picks JS's `direct` split: FROM_RELAY carries a peerAddress,
    // FROM_CLIENT does not.
    void do_handshake(bool relayed,
                      uint32_t client_fw = peer_connect::FIREWALL_CONSISTENT) {
        noise::Seed client_seed{};
        client_seed.fill(0x22);
        auto client_kp = noise::generate_keypair(client_seed);

        const auto& prol = dht_messages::ns_peer_handshake();
        client_noise_ = std::make_shared<noise::NoiseIK>(
            true, client_kp, prol.data(), prol.size(), &server_kp_.public_key);

        peer_connect::NoisePayload cp;
        cp.version = 1;
        cp.firewall = client_fw;
        cp.udx = peer_connect::UdxInfo{1, false, 12345, 0};
        cp.has_secret_stream = true;
        cp.addresses4.push_back(Ipv4Address::from_string("10.0.0.1", 5000));
        auto cpb = peer_connect::encode_noise_payload(cp);

        peer_connect::HandshakeMessage hs_msg;
        hs_msg.noise = client_noise_->send(cpb.data(), cpb.size());
        if (relayed) {
            hs_msg.mode = peer_connect::MODE_FROM_RELAY;
            hs_msg.peer_address = client_node().addr();
        } else {
            hs_msg.mode = peer_connect::MODE_FROM_CLIENT;
        }

        messages::Request req;
        req.target = target_;
        req.value = peer_connect::encode_handshake_msg(hs_msg);
        req.command = messages::CMD_PEER_HANDSHAKE;
        req.from.addr = relayed ? relay().addr() : client_node().addr();
        req.tid = 1;

        auto absorb = [&](const std::vector<uint8_t>& value) {
            auto resp_hs = peer_connect::decode_handshake_msg(value.data(),
                                                              value.size());
            auto plain = client_noise_->recv(resp_hs.noise.data(),
                                             resp_hs.noise.size());
            ASSERT_TRUE(plain.has_value());
            auto sp = peer_connect::decode_noise_payload(plain->data(),
                                                         plain->size());
            ASSERT_TRUE(sp.holepunch.has_value());
            hp_id_ = sp.holepunch->id;

            const auto& ns_hp = dht_messages::ns_peer_holepunch();
            std::array<uint8_t, 32> secret{};
            crypto_generichash(secret.data(), 32, ns_hp.data(), 32,
                               client_noise_->handshake_hash().data(), 64);
            client_secure_ = std::make_shared<holepunch::SecurePayload>(secret);
        };

        ASSERT_TRUE(router_.handle_peer_handshake(
            req,
            [&](const messages::Response& resp) {
                ASSERT_TRUE(resp.value.has_value());
                absorb(*resp.value);
            },
            [&](const messages::Request& relay_req, udx_socket_t* via) {
                ASSERT_TRUE(relay_req.value.has_value());
                auto hs = peer_connect::decode_handshake_msg(
                    relay_req.value->data(), relay_req.value->size());
                peer_connect::HandshakeMessage inner;
                inner.mode = peer_connect::MODE_REPLY;
                inner.noise = hs.noise;
                absorb(peer_connect::encode_handshake_msg(inner));
                // Real egress: this is what puts the punch socket's port on
                // the wire for the relay (and the assertions) to see.
                socket_->udp_send(messages::encode_request(relay_req),
                                  relay_req.to.addr, via);
            }));
    }

    // A round-1 PEER_HOLEPUNCH FROM_RELAY, delivered as a real datagram from
    // the relay node to the session's punch socket.
    std::vector<uint8_t> encode_round(
        uint32_t round, bool punching,
        std::optional<Ipv4Address> remote_address = std::nullopt) {
        holepunch::HolepunchPayload p;
        p.firewall = peer_connect::FIREWALL_CONSISTENT;
        p.round = round;
        p.punching = punching;
        p.addresses.push_back(client_node().addr());
        p.remote_address = remote_address;
        auto bytes = holepunch::encode_holepunch_payload(p);

        holepunch::HolepunchMessage msg;
        msg.mode = peer_connect::MODE_FROM_RELAY;
        msg.id = hp_id_;
        msg.payload = client_secure_->encrypt(bytes.data(), bytes.size());
        msg.peer_address = client_node().addr();
        return holepunch::encode_holepunch_msg(msg);
    }

    // The PEER_HOLEPUNCH request a relay forwards to us, on the wire.
    std::vector<uint8_t> wrap_round(std::vector<uint8_t> value) {
        messages::Request req;
        req.tid = 2;
        req.command = messages::CMD_PEER_HOLEPUNCH;
        req.internal = false;
        req.target = target_;
        req.to.addr = our_public_;  // wire `to` = how the client sees us
        req.value = std::move(value);
        return messages::encode_request(req);
    }

    void send_round_to_punch_socket(std::vector<uint8_t> value) {
        relay().send(wrap_round(std::move(value)),
                     Ipv4Address::from_string("127.0.0.1", punch_port()));
    }

    void complete_pool_sampling() {
        for (auto& n : nodes_) {
            n->auto_answer_ping = true;
            n->answer_pings();
        }
    }

    holepunch::HolepunchPayload decrypt_round_reply(
        const std::vector<uint8_t>& value) {
        auto msg = holepunch::decode_holepunch_msg(value.data(), value.size());
        auto plain = client_secure_->decrypt(msg.payload.data(),
                                             msg.payload.size());
        EXPECT_TRUE(plain.has_value());
        if (!plain) return {};
        return holepunch::decode_holepunch_payload(plain->data(), plain->size());
    }
};

// (a) A relayed (firewalled) handshake acquires a punch socket and the Noise
//     msg2 leaves THAT socket — JS server.js:481.
TEST_F(ServerPunchSocket, HandshakeReplyEgressesFromPunchSocket) {
    do_handshake(/*relayed=*/true);

    auto* c = conn();
    ASSERT_NE(c, nullptr);
    ASSERT_TRUE(c->punch_socket) << "firewalled relayed session must punch";

    ASSERT_TRUE(run_loop_until([&] { return !relay().handshakes.empty(); }));
    uint16_t src = relay().handshakes[0].second;
    EXPECT_NE(src, main_port()) << "reply still came from the main socket";
    EXPECT_EQ(src, punch_port());
}

// (b) A round that lands before NAT sampling concludes is parked, answered
//     once it does, and the answer carries the PUNCH socket's classification
//     — JS server.js:519 `await p.analyze(false)`.
TEST_F(ServerPunchSocket, RoundDeferredUntilPoolSamplingSettles) {
    do_handshake(/*relayed=*/true);
    ASSERT_TRUE(conn() && conn()->punch_socket);

    send_round_to_punch_socket(encode_round(1, /*punching=*/true));
    ASSERT_TRUE(run_loop_until([&] { return !conn()->parked_rounds.empty(); }));
    EXPECT_TRUE(relay().rounds.empty()) << "answered before sampling settled";
    EXPECT_EQ(conn()->punch_socket->nat_sampler().firewall(),
              peer_connect::FIREWALL_UNKNOWN);
    // A round that DID decrypt feeds the session sampler, parked or not
    // (JS server.js:508-511 runs before the analyzer await).
    EXPECT_GE(conn()->punch_socket->nat_sampler().sampled(), 1);

    complete_pool_sampling();
    ASSERT_TRUE(run_loop_until([&] { return !relay().rounds.empty(); }));

    auto* c = conn();
    ASSERT_NE(c, nullptr);
    auto payload = decrypt_round_reply(relay().rounds[0].first);
    EXPECT_EQ(payload.error, peer_connect::ERROR_NONE);
    EXPECT_EQ(payload.firewall, c->punch_socket->nat_sampler().firewall());
    EXPECT_EQ(payload.firewall, peer_connect::FIREWALL_CONSISTENT)
        << "six agreeing samples must classify as CONSISTENT";
    // The answer rides the punch socket too (JS router.js:233).
    EXPECT_EQ(relay().rounds[0].second, punch_port());
}

// (c) The fast-mode ping leaves the punch socket, not the main one —
//     JS server.js:530-537 `p.ping(peerAddress)` → holepuncher.js:77.
TEST_F(ServerPunchSocket, FastModePingEgressesFromPunchSocket) {
    do_handshake(/*relayed=*/true);
    ASSERT_TRUE(conn() && conn()->punch_socket);
    complete_pool_sampling();

    // remoteAddress echoes the address our samplers agree on → fast mode.
    send_round_to_punch_socket(encode_round(1, /*punching=*/true, our_public_));

    ASSERT_TRUE(run_loop_until([&] { return client_node().probes > 0; }));
    EXPECT_EQ(client_node().first_probe_src, punch_port());
    EXPECT_NE(client_node().first_probe_src, main_port());
}

// (d) A direct (FROM_CLIENT) handshake is JS's `direct` case: no puncher, no
//     punch socket, the pre-existing main-socket path untouched
//     (server.js:390-394 returns before :436).
TEST_F(ServerPunchSocket, DirectHandshakeCreatesNoPunchSocket) {
    do_handshake(/*relayed=*/false);

    auto* c = conn();
    ASSERT_NE(c, nullptr);
    EXPECT_FALSE(c->punch_socket);
    EXPECT_TRUE(c->parked_rounds.empty());
}

// A well-formed round whose payload does not decrypt changes NO session state
// — not the NAT sampler, not the freeze, not the park queue. JS drops it at
// server.js:491-493, ahead of `nat.add` and the analyzer. Sampling it would
// let three spoofed sources carrying a chosen `to` pin the address and
// firewall this session advertises.
TEST_F(ServerPunchSocket, UndecryptableRoundChangesNoState) {
    do_handshake(/*relayed=*/true);
    ASSERT_TRUE(conn() && conn()->punch_socket);

    for (int i = 0; i < 3; i++) {  // 3 = NatSampler's CONSISTENT threshold
        holepunch::HolepunchMessage msg;
        msg.mode = peer_connect::MODE_FROM_RELAY;
        msg.id = hp_id_;
        msg.payload = std::vector<uint8_t>(64, 0xAB);  // not our ciphertext
        msg.peer_address = client_node().addr();
        // Distinct spoofed sources: NatSampler dedups by source only.
        nodes_[i]->send(
            wrap_round(holepunch::encode_holepunch_msg(msg)),
            Ipv4Address::from_string("127.0.0.1", punch_port()));
    }
    pump_ms(100);

    auto* c = conn();
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(c->punch_socket->nat_sampler().sampled(), 0)
        << "unauthenticated rounds must not reach the session NAT sampler";
    EXPECT_EQ(c->punch_socket->nat_sampler().firewall(),
              peer_connect::FIREWALL_UNKNOWN);
    EXPECT_FALSE(c->punch_socket->nat_sampler().is_frozen());
    EXPECT_TRUE(c->parked_rounds.empty());
    EXPECT_TRUE(relay().rounds.empty());
}

// The park queue is bounded (drop-oldest): a client that floods rounds while
// sampling runs cannot grow the session without limit.
TEST_F(ServerPunchSocket, ParkedRoundsAreBounded) {
    do_handshake(/*relayed=*/true);
    ASSERT_TRUE(conn() && conn()->punch_socket);

    for (uint32_t i = 0; i < 12; i++) {
        send_round_to_punch_socket(encode_round(1, /*punching=*/true));
    }
    ASSERT_TRUE(run_loop_until([&] {
        return conn() && conn()->parked_rounds.size() >= 8;
    }));
    pump_ms(50);
    EXPECT_EQ(conn()->parked_rounds.size(), 8u);
}
