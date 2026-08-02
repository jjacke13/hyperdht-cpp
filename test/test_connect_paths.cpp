// Integration tests for the client connect pipeline paths:
//   connect-6 — LAN same-NAT shortcut is EXCLUSIVE of holepunch
//               (JS connect.js:234-251)
//   connect-7 — opts.holepunch client veto (JS connect.js:296-307)
//
// Harness: a fake relay RpcSocket on loopback. For the LAN tests it
// completes a REAL Noise IK handshake as the "server" and crafts the
// server's NoisePayload. For the veto tests it answers PEER_HOLEPUNCH
// rounds with payloads encrypted under the shared holepunch secret.
// Fake loopback DHT nodes answer PINGs so pool NAT sampling classifies
// CONSISTENT.

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "hyperdht/compact.hpp"
#include "hyperdht/dht.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/rpc.hpp"

using namespace hyperdht;
using Ipv4Address = compact::Ipv4Address;

namespace {

// Run the loop until `done()` or `max_ms` elapsed.
void run_until(uv_loop_t* loop, const std::function<bool()>& done,
               uint64_t max_ms) {
    uv_update_time(loop);
    uint64_t start = uv_now(loop);
    while (!done()) {
        uv_run(loop, UV_RUN_ONCE);
        uv_update_time(loop);
        if (uv_now(loop) - start >= max_ms) break;
    }
}

// Minimal PING responder — replies with the requester's observed address in
// the wire `to` field (feeds the requester's NAT sampler).
void answer_ping(rpc::RpcSocket& sock, const messages::Request& req) {
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    sock.reply(resp, req.from_server);
}

// ===========================================================================
// connect-6 — LAN same-NAT shortcut (EXCLUSIVE of holepunch)
// ===========================================================================

struct LanScenarioResult {
    bool connect_done = false;
    int connect_err = 0;
    ConnectResult connect_result;
    int holepunch_reqs = 0;  // PEER_HOLEPUNCH requests seen by the relay
};

// Drives HyperDHT::connect() against a fake relay whose crafted server
// payload advertises `lan_port` on 127.0.0.1 as the server's only address.
// The relay's reply peer_address (→ hs.server_address, JS serverAddress)
// shares the client's host (127.0.0.1) so the JS LAN trigger
// `clientAddress.host === serverAddress.host` fires.
LanScenarioResult run_lan_scenario(uint16_t lan_port, bool lan_peer_alive) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    LanScenarioResult out;

    noise::Seed server_seed{};
    server_seed.fill(0x31);
    auto server_kp = noise::generate_keypair(server_seed);

    routing::NodeId rid{};
    rid.fill(0x02);
    rpc::RpcSocket relay(&loop, rid);
    relay.bind(0);
    auto relay_addr = Ipv4Address::from_string("127.0.0.1", relay.port());

    // The "LAN peer" the server payload points at (answers dht.ping).
    routing::NodeId lid{};
    lid.fill(0x03);
    rpc::RpcSocket lan_peer(&loop, lid);
    if (lan_peer_alive) {
        lan_peer.bind(0);
        lan_port = lan_peer.port();
        lan_peer.on_request([&](const messages::Request& req) {
            if (req.internal && req.command == messages::CMD_PING) {
                answer_ping(lan_peer, req);
            }
        });
    }
    const uint16_t lan_port_used = lan_port;

    relay.on_request([&](const messages::Request& req) {
        if (req.internal && req.command == messages::CMD_PING) {
            answer_ping(relay, req);
            return;
        }
        if (req.command == messages::CMD_PEER_HOLEPUNCH) {
            out.holepunch_reqs++;
            return;  // never answered — the test only counts
        }
        if (req.command != messages::CMD_PEER_HANDSHAKE || !req.value) return;

        auto hs = peer_connect::decode_handshake_msg(
            req.value->data(), req.value->size());

        const auto& prol = dht_messages::ns_peer_handshake();
        noise::NoiseIK responder(false, server_kp, prol.data(), prol.size());
        auto p1 = responder.recv(hs.noise.data(), hs.noise.size());
        if (!p1.has_value()) {
            ADD_FAILURE() << "responder failed to process msg1";
            return;
        }

        // Server payload: CONSISTENT firewall + one LAN address +
        // holepunch info (so the pipeline reaches the LAN block).
        peer_connect::NoisePayload rp;
        rp.version = 1;
        rp.error = peer_connect::ERROR_NONE;
        rp.firewall = peer_connect::FIREWALL_CONSISTENT;
        rp.addresses4.push_back(
            Ipv4Address::from_string("127.0.0.1", lan_port_used));
        rp.udx = peer_connect::UdxInfo{1, false, 777, 0};
        rp.has_secret_stream = true;
        peer_connect::HolepunchInfo hp;
        hp.id = 7;
        peer_connect::RelayInfo ri;
        ri.relay_address = relay_addr;
        ri.peer_address = Ipv4Address::from_string("127.0.0.1", 9998);
        hp.relays.push_back(ri);
        rp.holepunch = hp;

        auto rp_bytes = peer_connect::encode_noise_payload(rp);
        auto msg2 = responder.send(rp_bytes.data(), rp_bytes.size());

        peer_connect::HandshakeMessage reply_msg;
        reply_msg.mode = peer_connect::MODE_REPLY;
        reply_msg.noise = std::move(msg2);
        // → hs.server_address (JS serverAddress = hs.peerAddress || to).
        // Same host as the client (127.0.0.1), different addr than the
        // relay → `relayed` is true and the LAN trigger host check fires.
        reply_msg.peer_address = Ipv4Address::from_string("127.0.0.1", 9998);

        messages::Response resp;
        resp.tid = req.tid;
        resp.from.addr = req.from.addr;  // → hs.client_address (JS res.to)
        resp.value = peer_connect::encode_handshake_msg(reply_msg);
        relay.reply(resp, req.from_server);
    });

    HyperDHT dht(&loop);  // empty bootstrap — offline
    dht.bind();
    dht.cache_relay_addresses(server_kp.public_key, {relay_addr});

    dht.connect(server_kp.public_key,
        [&](int err, const ConnectResult& result) {
            out.connect_done = true;
            out.connect_err = err;
            out.connect_result = result;
        });

    run_until(&loop, [&] { return out.connect_done; }, 15000);
    EXPECT_TRUE(out.connect_done) << "connect callback never fired";

    // Grace period: old (buggy) behavior launched the holepunch engine in
    // parallel with the LAN ping — give any stray Round 1 time to land.
    run_until(&loop, [] { return false; }, 700);

    if (out.connect_result.raw_stream) {
        udx_stream_destroy(out.connect_result.raw_stream);
    }
    dht.destroy();
    relay.close();
    if (lan_peer_alive) lan_peer.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    return out;
}

}  // namespace

// JS connect.js:234-251 — when the LAN trigger fires and the LAN ping
// succeeds, the connection completes over the LAN address and the
// holepunch engine is NEVER started.
TEST(ConnectLan, LanShortcutIsExclusiveOfHolepunch) {
    auto out = run_lan_scenario(0, /*lan_peer_alive=*/true);

    EXPECT_EQ(out.connect_err, 0);
    EXPECT_TRUE(out.connect_result.success);
    EXPECT_EQ(out.connect_result.peer_address.host_string(), "127.0.0.1");
    EXPECT_EQ(out.holepunch_reqs, 0)
        << "holepunch engine ran despite exclusive LAN path";
}

// JS connect.js:244-247 — LAN ping failure aborts the connect
// (HOLEPUNCH_ABORTED); it does NOT fall back to holepunch.
TEST(ConnectLan, LanPingFailureAbortsWithoutHolepunch) {
    // Port 1 on loopback — nothing listens, ping times out.
    auto out = run_lan_scenario(1, /*lan_peer_alive=*/false);

    EXPECT_EQ(out.connect_err, ConnectError::HOLEPUNCH_TIMEOUT);
    EXPECT_FALSE(out.connect_result.success);
    EXPECT_EQ(out.holepunch_reqs, 0)
        << "holepunch engine ran despite exclusive LAN path";
}

// ===========================================================================
// connect-7 — opts.holepunch client veto
// ===========================================================================

namespace {

struct VetoScenarioResult {
    bool done = false;
    holepunch::HolepunchResult result;
    bool veto_called = false;
    uint32_t veto_remote_fw = 0;
    uint32_t veto_local_fw = 0;
    std::vector<Ipv4Address> veto_remote_addrs;
    bool relay_saw_punching = false;  // a round with punching=true arrived
};

// Drives holepunch_connect() directly against a fake relay. The relay
// answers Round 1 with a CONSISTENT-firewall server payload (+ token) and
// answers a punching round with ERROR_ABORTED (to terminate quickly).
// Six loopback DHT nodes answer the pool socket's sampling PINGs.
VetoScenarioResult run_veto_scenario(bool veto_allows) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    VetoScenarioResult out;

    routing::NodeId cid{};
    cid.fill(0x01);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);

    routing::NodeId rid{};
    rid.fill(0x02);
    rpc::RpcSocket relay(&loop, rid);
    relay.bind(0);
    auto relay_addr = Ipv4Address::from_string("127.0.0.1", relay.port());

    // Fake DHT nodes so discover_pool_addresses gets >= 4 samples and the
    // pool NAT classifies CONSISTENT (6 nodes + relay = 7 targets, which
    // is exactly MAX_TARGETS — no public-bootstrap fallback pings).
    std::vector<std::unique_ptr<rpc::RpcSocket>> nodes;
    for (int i = 0; i < 6; i++) {
        routing::NodeId nid{};
        nid.fill(static_cast<uint8_t>(0x10 + i));
        auto n = std::make_unique<rpc::RpcSocket>(&loop, nid);
        n->bind(0);
        auto* np = n.get();
        np->on_request([np](const messages::Request& req) {
            if (req.internal && req.command == messages::CMD_PING) {
                answer_ping(*np, req);
            }
        });
        routing::Node node;
        node.id = nid;
        node.host = "127.0.0.1";
        node.port = np->port();
        client.table().add(node);
        nodes.push_back(std::move(n));
    }

    // Crafted handshake result — both sides derive the holepunch secret
    // from the same (arbitrary) handshake hash.
    peer_connect::HandshakeResult hs;
    hs.success = true;
    hs.handshake_hash.fill(0x77);
    hs.remote_public_key.fill(0x55);

    const auto& ns_hp = dht_messages::ns_peer_holepunch();
    std::array<uint8_t, 32> hp_secret{};
    crypto_generichash(hp_secret.data(), 32, ns_hp.data(), 32,
                       hs.handshake_hash.data(), 64);
    auto relay_secure = std::make_shared<holepunch::SecurePayload>(hp_secret);

    relay.on_request([&](const messages::Request& req) {
        if (req.internal && req.command == messages::CMD_PING) {
            answer_ping(relay, req);
            return;
        }
        if (req.command != messages::CMD_PEER_HOLEPUNCH || !req.value) return;

        auto msg = holepunch::decode_holepunch_msg(
            req.value->data(), req.value->size());
        auto dec = relay_secure->decrypt(msg.payload.data(),
                                         msg.payload.size());
        if (!dec) {
            ADD_FAILURE() << "relay could not decrypt holepunch payload";
            return;
        }
        auto payload = holepunch::decode_holepunch_payload(
            dec->data(), dec->size());

        holepunch::HolepunchPayload reply;
        reply.error = peer_connect::ERROR_NONE;
        reply.firewall = peer_connect::FIREWALL_CONSISTENT;
        reply.round = payload.round;
        if (payload.punching) {
            out.relay_saw_punching = true;
            // Terminate the punch quickly — the client treats any non-NONE,
            // non-TRY_LATER error as fatal for the round.
            reply.error = peer_connect::ERROR_ABORTED;
        } else {
            reply.addresses.push_back(
                Ipv4Address::from_string("10.0.0.1", 9999));
            std::array<uint8_t, 32> token{};
            token.fill(0xAB);
            reply.token = token;
        }

        auto reply_bytes = holepunch::encode_holepunch_payload(reply);
        holepunch::HolepunchMessage reply_msg;
        reply_msg.mode = peer_connect::MODE_REPLY;
        reply_msg.id = msg.id;
        reply_msg.payload = relay_secure->encrypt(reply_bytes.data(),
                                                  reply_bytes.size());

        messages::Response resp;
        resp.tid = req.tid;
        resp.from.addr = req.from.addr;
        resp.value = holepunch::encode_holepunch_msg(reply_msg);
        relay.reply(resp, req.from_server);
    });

    holepunch::holepunch_connect(
        client, hs, relay_addr,
        /*peer_addr=*/Ipv4Address::from_string("10.0.0.2", 9998),
        /*holepunch_id=*/7,
        peer_connect::FIREWALL_UNKNOWN, {},
        [&](const holepunch::HolepunchResult& r) {
            out.done = true;
            out.result = r;
        },
        /*fast_open=*/false,
        nullptr, nullptr, nullptr, nullptr,
        // connect-7 — the veto under test.
        [&](uint32_t remote_fw, uint32_t local_fw,
            const std::vector<Ipv4Address>& remote_addrs,
            const std::vector<Ipv4Address>& /*local_addrs*/) {
            out.veto_called = true;
            out.veto_remote_fw = remote_fw;
            out.veto_local_fw = local_fw;
            out.veto_remote_addrs = remote_addrs;
            return veto_allows;
        });

    run_until(&loop, [&] { return out.done; }, 20000);
    EXPECT_TRUE(out.done) << "holepunch_connect callback never fired";

    client.close();
    relay.close();
    for (auto& n : nodes) n->close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    return out;
}

}  // namespace

// JS connect.js:296-307 — opts.holepunch returning false aborts the punch
// BEFORE any punching round is sent (HOLEPUNCH_ABORTED semantics).
TEST(ConnectVeto, VetoFalseAbortsBeforePunchingRound) {
    auto out = run_veto_scenario(/*veto_allows=*/false);

    EXPECT_TRUE(out.veto_called);
    EXPECT_FALSE(out.result.success);
    EXPECT_TRUE(out.result.aborted);
    EXPECT_FALSE(out.relay_saw_punching)
        << "punching round was sent despite the veto";
    // Args mirror JS: (puncher.remoteFirewall, nat.firewall, ...)
    EXPECT_EQ(out.veto_remote_fw, peer_connect::FIREWALL_CONSISTENT);
    EXPECT_EQ(out.veto_local_fw, peer_connect::FIREWALL_CONSISTENT);
    ASSERT_FALSE(out.veto_remote_addrs.empty());
    EXPECT_EQ(out.veto_remote_addrs[0].host_string(), "10.0.0.1");
}

// Control: a veto returning true lets the punch proceed to the punching
// round (the relay then aborts it, which is NOT a veto abort).
TEST(ConnectVeto, VetoTrueProceedsToPunchingRound) {
    auto out = run_veto_scenario(/*veto_allows=*/true);

    EXPECT_TRUE(out.veto_called);
    EXPECT_TRUE(out.relay_saw_punching)
        << "punching round never reached the relay";
    EXPECT_FALSE(out.result.success);   // relay replied ERROR_ABORTED
    EXPECT_FALSE(out.result.aborted);   // remote abort, not a client veto
}

// ===========================================================================
// Finding M — Round-1 relay failover
//   JS connect.js:271 — "TODO: we should retry here with some of the other
//   relays, bail for now". Field: one relay unreachable from the client but
//   healthy from the server = permanent -5 with no failover.
// ===========================================================================

namespace {

struct FailoverScenarioResult {
    bool done = false;
    holepunch::HolepunchResult result;
    int dead_relay_hp_reqs = 0;
    bool live_relay_saw_round1 = false;
    bool live_relay_saw_punching = false;
    // Round 1 as the LIVE relay saw it — the message's peerAddress is the
    // forward destination (router.js:214), the payload's remoteAddress is
    // what the server matches against its own NAT samples (server.js:530).
    std::optional<Ipv4Address> live_msg_peer_address;
    std::optional<Ipv4Address> live_payload_remote_address;
    std::vector<Ipv4Address> punch_addresses;
};

// Two relays: the first swallows every PEER_HOLEPUNCH (the field's
// symmetric-NAT relay — reachable for PINGs, silent for the punch), the
// second answers Round 1 with a CONSISTENT server payload + token and
// aborts the punching round so the scenario terminates quickly.
// `with_fallback=false` is the control: no fallback list, no failover.
FailoverScenarioResult run_failover_scenario(bool with_fallback) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    FailoverScenarioResult out;

    routing::NodeId cid{};
    cid.fill(0x01);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);

    routing::NodeId dead_id{};
    dead_id.fill(0x02);
    rpc::RpcSocket dead_relay(&loop, dead_id);
    dead_relay.bind(0);
    auto dead_addr = Ipv4Address::from_string("127.0.0.1", dead_relay.port());

    routing::NodeId live_id{};
    live_id.fill(0x03);
    rpc::RpcSocket live_relay(&loop, live_id);
    live_relay.bind(0);
    // udp_send (used below to lie in the wire `to` field) must egress the
    // bound port so the reply's id passes the client's validateId.
    live_relay.set_firewalled(false);
    auto live_addr = Ipv4Address::from_string("127.0.0.1", live_relay.port());

    // What the FAILOVER relay claims to see our pool socket as. Distinct from
    // everyone else's observation, and this relay is never a
    // discover_pool_addresses target (only relays[0] is), so JS's
    // `nat.add(reply.to, reply.from)` (connect.js:578) is the ONLY path by
    // which it can reach our NAT sampler.
    const auto live_observed =
        Ipv4Address::from_string("198.51.100.9", 4444);

    // Fake DHT nodes so pool NAT sampling reaches >= 4 samples.
    std::vector<std::unique_ptr<rpc::RpcSocket>> nodes;
    for (int i = 0; i < 6; i++) {
        routing::NodeId nid{};
        nid.fill(static_cast<uint8_t>(0x10 + i));
        auto n = std::make_unique<rpc::RpcSocket>(&loop, nid);
        n->bind(0);
        auto* np = n.get();
        np->on_request([np](const messages::Request& req) {
            if (req.internal && req.command == messages::CMD_PING) {
                answer_ping(*np, req);
            }
        });
        routing::Node node;
        node.id = nid;
        node.host = "127.0.0.1";
        node.port = np->port();
        client.table().add(node);
        nodes.push_back(std::move(n));
    }

    peer_connect::HandshakeResult hs;
    hs.success = true;
    hs.handshake_hash.fill(0x77);
    hs.remote_public_key.fill(0x55);

    const auto& ns_hp = dht_messages::ns_peer_holepunch();
    std::array<uint8_t, 32> hp_secret{};
    crypto_generichash(hp_secret.data(), 32, ns_hp.data(), 32,
                       hs.handshake_hash.data(), 64);
    auto secure = std::make_shared<holepunch::SecurePayload>(hp_secret);

    // The dead relay answers PINGs (so it still looks alive to the routing
    // table and to pool sampling) but never answers a holepunch round.
    dead_relay.on_request([&](const messages::Request& req) {
        if (req.internal && req.command == messages::CMD_PING) {
            answer_ping(dead_relay, req);
            return;
        }
        if (req.command == messages::CMD_PEER_HOLEPUNCH) {
            out.dead_relay_hp_reqs++;
        }
    });

    live_relay.on_request([&](const messages::Request& req) {
        if (req.internal && req.command == messages::CMD_PING) {
            answer_ping(live_relay, req);
            return;
        }
        if (req.command != messages::CMD_PEER_HOLEPUNCH || !req.value) return;

        auto msg = holepunch::decode_holepunch_msg(
            req.value->data(), req.value->size());
        auto dec = secure->decrypt(msg.payload.data(), msg.payload.size());
        if (!dec) {
            ADD_FAILURE() << "live relay could not decrypt holepunch payload";
            return;
        }
        auto payload = holepunch::decode_holepunch_payload(
            dec->data(), dec->size());

        holepunch::HolepunchPayload reply;
        reply.error = peer_connect::ERROR_NONE;
        reply.firewall = peer_connect::FIREWALL_CONSISTENT;
        reply.round = payload.round;
        if (payload.punching) {
            out.live_relay_saw_punching = true;
            out.punch_addresses = payload.addresses;
            reply.error = peer_connect::ERROR_ABORTED;
        } else {
            if (!out.live_relay_saw_round1) {
                out.live_relay_saw_round1 = true;
                out.live_msg_peer_address = msg.peer_address;
                out.live_payload_remote_address = payload.remote_address;
            }
            reply.addresses.push_back(
                Ipv4Address::from_string("10.0.0.1", 9999));
            std::array<uint8_t, 32> token{};
            token.fill(0xAB);
            reply.token = token;
        }

        auto reply_bytes = holepunch::encode_holepunch_payload(reply);
        holepunch::HolepunchMessage reply_msg;
        reply_msg.mode = peer_connect::MODE_REPLY;
        reply_msg.id = msg.id;
        reply_msg.payload = secure->encrypt(reply_bytes.data(),
                                            reply_bytes.size());

        messages::Response resp;
        resp.tid = req.tid;
        // Lie about where we see the client: this becomes the client's
        // `our_addr` for this leg. Sent via udp_send because
        // RpcSocket::reply() uses resp.from.addr as the UDP destination and
        // so cannot carry a `to` field that differs from the real source.
        resp.from.addr = live_observed;
        resp.id = rpc::compute_peer_id(live_addr);
        resp.value = holepunch::encode_holepunch_msg(reply_msg);
        live_relay.udp_send(messages::encode_response(resp), req.from.addr);
    });

    // The live relay's OWN view of the server — distinct from the fresh
    // observation the handshake relay gave us, exactly as in the field.
    std::vector<peer_connect::RelayInfo> fallbacks;
    if (with_fallback) {
        peer_connect::RelayInfo r;
        r.relay_address = live_addr;
        r.peer_address = Ipv4Address::from_string("10.0.0.3", 9997);
        fallbacks.push_back(r);
    }

    holepunch::holepunch_connect(
        client, hs, dead_addr,
        /*peer_addr=*/Ipv4Address::from_string("10.0.0.2", 9998),
        /*holepunch_id=*/7,
        peer_connect::FIREWALL_UNKNOWN, {},
        [&](const holepunch::HolepunchResult& r) {
            out.done = true;
            out.result = r;
        },
        /*fast_open=*/false,
        nullptr, nullptr, nullptr, nullptr, nullptr,
        fallbacks);

    run_until(&loop, [&] { return out.done; }, 30000);
    EXPECT_TRUE(out.done) << "holepunch_connect callback never fired";

    client.close();
    dead_relay.close();
    live_relay.close();
    for (auto& n : nodes) n->close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    return out;
}

}  // namespace

// A silent relay must not be terminal: Round 1 retries through the next
// relay in the announce record and the punch continues from there.
TEST(ConnectRelayFailover, DeadRelayFallsOverToTheNextRelay) {
    auto out = run_failover_scenario(/*with_fallback=*/true);

    EXPECT_GE(out.dead_relay_hp_reqs, 1) << "Round 1 never reached relay 1";
    EXPECT_TRUE(out.live_relay_saw_round1) << "no failover to relay 2";
    EXPECT_TRUE(out.live_relay_saw_punching)
        << "failover stopped short of the punching round";

    // The forward destination is the FAILOVER relay's own peer_address
    // (router.js:214 relays to it verbatim) — not the handshake relay's
    // observation, which names a mapping this relay has no session on.
    ASSERT_TRUE(out.live_msg_peer_address.has_value());
    EXPECT_EQ(out.live_msg_peer_address->host_string(), "10.0.0.3");
    EXPECT_EQ(out.live_msg_peer_address->port, 9997);

    // The payload's remoteAddress stays the fresh observation — it is what
    // the server matches against its NAT samples for the fast-mode punch.
    ASSERT_TRUE(out.live_payload_remote_address.has_value());
    EXPECT_EQ(out.live_payload_remote_address->host_string(), "10.0.0.2");
    EXPECT_EQ(out.live_payload_remote_address->port, 9998);

    // JS connect.js:578 `nat.add(reply.to, reply.from)` — in C++ this happens
    // one layer down, in PoolSocket::handle_message, for every response that
    // arrives on the pool socket. The failover relay is never a pool-sampling
    // target, so its round-1 reply is the only way its view of us enters the
    // sampler; pinning that here keeps the punching round advertising a
    // mapping that only this relay can see.
    bool saw_failover_observation = false;
    for (const auto& a : out.punch_addresses) {
        if (a.host_string() == "198.51.100.9" && a.port == 4444) {
            saw_failover_observation = true;
        }
    }
    EXPECT_TRUE(saw_failover_observation)
        << "the failover relay's view of our pool socket never reached the "
           "NAT sampler, so the punching round could not advertise it";
    EXPECT_GE(out.punch_addresses.size(), 2u);
}

// Control: with no fallback relays the behavior is unchanged — one relay,
// one attempt, terminal failure.
TEST(ConnectRelayFailover, NoFallbackRelaysStaysSingleAttempt) {
    auto out = run_failover_scenario(/*with_fallback=*/false);

    EXPECT_GE(out.dead_relay_hp_reqs, 1);
    EXPECT_FALSE(out.live_relay_saw_round1);
    EXPECT_FALSE(out.result.success);
}

// The failover list is capped below the wire limit (128 relay entries,
// peer_connect.cpp:175): each entry costs a multi-second RPC, and the
// handshake reply it comes from is authored by the peer we are dialing.
TEST(ConnectRelayFailover, FallbackListSkipsTheChosenRelayAndIsCapped) {
    std::vector<peer_connect::RelayInfo> relays;
    for (int i = 0; i < 10; i++) {
        peer_connect::RelayInfo r;
        r.relay_address =
            Ipv4Address::from_string("10.9.0." + std::to_string(i), 100 + i);
        r.peer_address =
            Ipv4Address::from_string("10.8.0." + std::to_string(i), 200 + i);
        relays.push_back(r);
    }

    // Chosen = relays[1]; it must not appear in its own fallback list.
    auto out = holepunch::pick_fallback_relays(relays, relays[1].relay_address);

    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0].relay_address.host_string(), "10.9.0.0");
    EXPECT_EQ(out[1].relay_address.host_string(), "10.9.0.2");
    // Each entry keeps its own peer_address — the relay-specific session.
    EXPECT_EQ(out[0].peer_address.host_string(), "10.8.0.0");
    EXPECT_EQ(out[1].peer_address.port, 202);

    // A relay set that is entirely the chosen one yields no failover legs.
    EXPECT_TRUE(holepunch::pick_fallback_relays({relays[1]},
                                                relays[1].relay_address)
                    .empty());
}

// ===========================================================================
// B2 — the punching round must gossip the FULL sampled address set
//   JS connect.js:654,684 `addresses: c.puncher.nat.addresses` — the same
//   set round 1 sends (:567). C++ sent only the relay's single observation of
//   our pool socket, so a server whose probes could not reach that one mapping
//   had no alternative to try, and the two rounds disagreed about who we are.
//   Also covers JS connect.js:578 `nat.add(reply.to, reply.from)`: the relay's
//   observation must enter the sampler, not just be used locally.
// ===========================================================================

namespace {

struct PunchAddrResult {
    bool done = false;
    size_t round1_addrs = 0;
    size_t punch_addrs = 0;
    bool saw_round1 = false;
    bool saw_punch = false;
    std::vector<Ipv4Address> punch_list;
};

// Half the sampling nodes report one observed address for our pool socket and
// half report another, so the pool NAT sampler ends up holding TWO addresses
// with >=2 hits each — CONSISTENT, and a set the punching round can be seen
// to carry (or drop).
PunchAddrResult run_punch_addresses_scenario() {
    uv_loop_t loop;
    uv_loop_init(&loop);

    PunchAddrResult out;

    routing::NodeId cid{};
    cid.fill(0x01);
    rpc::RpcSocket client(&loop, cid);
    client.bind(0);

    routing::NodeId rid{};
    rid.fill(0x02);
    rpc::RpcSocket relay(&loop, rid);
    relay.bind(0);
    auto relay_addr = Ipv4Address::from_string("127.0.0.1", relay.port());

    // Two distinct "observed" mappings, neither of them the truthful one, so
    // the sampled set is unambiguous in the assertions below.
    const auto obs_a = Ipv4Address::from_string("198.51.100.7", 1111);
    const auto obs_b = Ipv4Address::from_string("198.51.100.7", 2222);

    std::vector<std::unique_ptr<rpc::RpcSocket>> nodes;
    for (int i = 0; i < 6; i++) {
        routing::NodeId nid{};
        nid.fill(static_cast<uint8_t>(0x10 + i));
        auto n = std::make_unique<rpc::RpcSocket>(&loop, nid);
        n->bind(0);
        n->set_firewalled(false);
        auto* np = n.get();
        const auto observed = (i < 3) ? obs_a : obs_b;
        np->on_request([np, observed](const messages::Request& req) {
            if (!(req.internal && req.command == messages::CMD_PING)) return;
            messages::Response resp;
            resp.tid = req.tid;
            resp.from.addr = observed;  // lie about where we see them
            np->udp_send(messages::encode_response(resp), req.from.addr);
        });
        routing::Node node;
        node.id = nid;
        node.host = "127.0.0.1";
        node.port = np->port();
        client.table().add(node);
        nodes.push_back(std::move(n));
    }

    peer_connect::HandshakeResult hs;
    hs.success = true;
    hs.handshake_hash.fill(0x77);
    hs.remote_public_key.fill(0x55);

    const auto& ns_hp = dht_messages::ns_peer_holepunch();
    std::array<uint8_t, 32> hp_secret{};
    crypto_generichash(hp_secret.data(), 32, ns_hp.data(), 32,
                       hs.handshake_hash.data(), 64);
    auto relay_secure = std::make_shared<holepunch::SecurePayload>(hp_secret);

    relay.on_request([&](const messages::Request& req) {
        if (req.internal && req.command == messages::CMD_PING) {
            answer_ping(relay, req);
            return;
        }
        if (req.command != messages::CMD_PEER_HOLEPUNCH || !req.value) return;

        auto msg = holepunch::decode_holepunch_msg(
            req.value->data(), req.value->size());
        auto dec = relay_secure->decrypt(msg.payload.data(),
                                         msg.payload.size());
        if (!dec) {
            ADD_FAILURE() << "relay could not decrypt holepunch payload";
            return;
        }
        auto payload = holepunch::decode_holepunch_payload(
            dec->data(), dec->size());

        holepunch::HolepunchPayload reply;
        reply.error = peer_connect::ERROR_NONE;
        reply.firewall = peer_connect::FIREWALL_CONSISTENT;
        reply.round = payload.round;
        if (payload.punching) {
            out.saw_punch = true;
            out.punch_addrs = payload.addresses.size();
            out.punch_list = payload.addresses;
            reply.error = peer_connect::ERROR_ABORTED;  // terminate fast
        } else {
            if (!out.saw_round1) {
                out.saw_round1 = true;
                out.round1_addrs = payload.addresses.size();
            }
            reply.addresses.push_back(
                Ipv4Address::from_string("10.0.0.1", 9999));
            std::array<uint8_t, 32> token{};
            token.fill(0xAB);
            reply.token = token;
        }

        auto reply_bytes = holepunch::encode_holepunch_payload(reply);
        holepunch::HolepunchMessage reply_msg;
        reply_msg.mode = peer_connect::MODE_REPLY;
        reply_msg.id = msg.id;
        reply_msg.payload = relay_secure->encrypt(reply_bytes.data(),
                                                  reply_bytes.size());

        messages::Response resp;
        resp.tid = req.tid;
        resp.from.addr = req.from.addr;
        resp.value = holepunch::encode_holepunch_msg(reply_msg);
        relay.reply(resp, req.from_server);
    });

    holepunch::holepunch_connect(
        client, hs, relay_addr,
        /*peer_addr=*/Ipv4Address::from_string("10.0.0.2", 9998),
        /*holepunch_id=*/7,
        peer_connect::FIREWALL_UNKNOWN, {},
        [&](const holepunch::HolepunchResult&) { out.done = true; },
        /*fast_open=*/false,
        nullptr, nullptr, nullptr, nullptr, nullptr, {});

    run_until(&loop, [&] { return out.done; }, 20000);

    client.close();
    relay.close();
    for (auto& n : nodes) n->close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    return out;
}

}  // namespace

TEST(ConnectPunchAddresses, PunchingRoundGossipsFullSampledSet) {
    auto out = run_punch_addresses_scenario();

    ASSERT_TRUE(out.saw_round1) << "relay never saw round 1";
    ASSERT_TRUE(out.saw_punch) << "relay never saw the punching round";

    // Round 1 carrying nothing is correct, not a harness failure: it fires
    // immediately after the handshake reply, before pool NAT sampling has
    // settled, so the classification is still UNKNOWN and nat.addresses() is
    // empty (JS holepuncher.js:19-20 / connect.js:567 behave the same). The
    // punching round is the one that runs post-sampling, and it is where the
    // full set has to appear.
    EXPECT_EQ(out.round1_addrs, 0u)
        << "round 1 unexpectedly had a settled sample set; if this changes, "
           "the punching round must still match it";

    ASSERT_EQ(out.punch_addrs, 2u)
        << "the punching round advertised " << out.punch_addrs
        << " address(es); the sampler held two distinct mappings and the "
           "server needs both — with one it has a single candidate to probe "
           "and nothing to fall back on";

    // Exactly the two mappings the sampling nodes reported, proving the set
    // came from the NAT sampler and not from the relay's lone observation.
    std::vector<uint16_t> ports;
    for (const auto& a : out.punch_list) {
        EXPECT_EQ(a.host_string(), "198.51.100.7");
        ports.push_back(a.port);
    }
    std::sort(ports.begin(), ports.end());
    EXPECT_EQ(ports, (std::vector<uint16_t>{1111, 2222}));
}
