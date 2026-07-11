#include <gtest/gtest.h>

#include "hyperdht/holepunch.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/router.hpp"

using namespace hyperdht;
using namespace hyperdht::router;
using Ipv4Address = compact::Ipv4Address;

static announce::TargetKey make_target(uint8_t fill) {
    announce::TargetKey t{};
    t.fill(fill);
    return t;
}

// No-op callbacks for tests that don't care about them
static auto noop_reply = [](const messages::Response&) {};
static auto noop_relay = [](const messages::Request&) {};

// Helper: register a handshake handler that echoes back {0xDE, 0xAD}
static ForwardEntry make_echo_entry() {
    ForwardEntry entry;
    entry.on_peer_handshake = [](const std::vector<uint8_t>&,
                                  const Ipv4Address&,
                                  std::function<void(std::vector<uint8_t>)> reply_fn) {
        reply_fn({0xDE, 0xAD});
    };
    return entry;
}

// Helper: build a PEER_HANDSHAKE request with given mode
static messages::Request make_hs_request(const announce::TargetKey& target,
                                          uint32_t mode,
                                          Ipv4Address from = Ipv4Address::from_string("10.0.0.1", 5000),
                                          uint16_t tid = 42) {
    peer_connect::HandshakeMessage hs_msg;
    hs_msg.mode = mode;
    hs_msg.noise = {0x01, 0x02, 0x03};
    if (mode == peer_connect::MODE_FROM_RELAY || mode == peer_connect::MODE_FROM_SECOND_RELAY) {
        // FROM_RELAY includes the original client's address in peerAddress
        hs_msg.peer_address = Ipv4Address::from_string("192.168.1.100", 9999);
    }

    messages::Request req;
    req.target = *reinterpret_cast<const std::array<uint8_t, 32>*>(target.data());
    req.value = peer_connect::encode_handshake_msg(hs_msg);
    req.from.addr = from;
    req.to.addr = Ipv4Address::from_string("10.0.0.2", 5001);
    req.tid = tid;
    req.command = messages::CMD_PEER_HANDSHAKE;
    req.internal = false;
    return req;
}

// ============================================================================
// Basic tests (updated for new API)
// ============================================================================

TEST(Router, SetGetRemove) {
    Router r;
    auto target = make_target(0x11);

    ForwardEntry entry;
    entry.record = {1, 2, 3};
    r.set(target, entry);

    EXPECT_TRUE(r.has(target));
    EXPECT_EQ(r.size(), 1u);

    auto* e = r.get(target);
    ASSERT_NE(e, nullptr);
    EXPECT_EQ(e->record, std::vector<uint8_t>({1, 2, 3}));

    r.remove(target);
    EXPECT_FALSE(r.has(target));
    EXPECT_EQ(r.size(), 0u);
}

TEST(Router, RecordLookup) {
    Router r;
    auto target = make_target(0x22);

    ForwardEntry entry;
    entry.record = {0xAA, 0xBB};
    r.set(target, entry);

    auto* rec = r.record(target);
    ASSERT_NE(rec, nullptr);
    EXPECT_EQ((*rec)[0], 0xAA);

    auto missing = make_target(0xFF);
    EXPECT_EQ(r.record(missing), nullptr);
}

TEST(Router, HandshakeDispatch) {
    Router r;
    auto target = make_target(0x33);

    bool handler_called = false;
    std::vector<uint8_t> received_noise;

    ForwardEntry entry;
    entry.on_peer_handshake = [&](const std::vector<uint8_t>& noise,
                                   const Ipv4Address&,
                                   std::function<void(std::vector<uint8_t>)> reply_fn) {
        handler_called = true;
        received_noise = noise;
        reply_fn({0xDE, 0xAD});
    };
    r.set(target, entry);

    auto req = make_hs_request(target, peer_connect::MODE_FROM_CLIENT);

    bool reply_sent = false;
    r.handle_peer_handshake(req,
        [&](const messages::Response& resp) {
            reply_sent = true;
            EXPECT_EQ(resp.tid, 42u);
            EXPECT_TRUE(resp.value.has_value());
        },
        noop_relay);

    EXPECT_TRUE(handler_called);
    EXPECT_EQ(received_noise, std::vector<uint8_t>({0x01, 0x02, 0x03}));
    EXPECT_TRUE(reply_sent);
}

TEST(Router, UnknownTargetReturnsFalse) {
    Router r;

    messages::Request req;
    auto target = make_target(0xFF);
    req.target = *reinterpret_cast<const std::array<uint8_t, 32>*>(target.data());
    req.value = std::vector<uint8_t>{0x00};
    req.from.addr = Ipv4Address::from_string("10.0.0.1", 5000);

    bool handled = r.handle_peer_handshake(req, noop_reply, noop_relay);
    EXPECT_FALSE(handled);
}

TEST(Router, Clear) {
    Router r;
    r.set(make_target(0x11), ForwardEntry{});
    r.set(make_target(0x22), ForwardEntry{});
    EXPECT_EQ(r.size(), 2u);

    r.clear();
    EXPECT_EQ(r.size(), 0u);
}

// ============================================================================
// Relay reply mechanism tests (the bug fix)
// ============================================================================

// Test 1: FROM_CLIENT → RESPONSE (direct reply)
TEST(Router, DirectReplyIsResponse) {
    Router r;
    auto target = make_target(0x44);
    r.set(target, make_echo_entry());

    auto req = make_hs_request(target, peer_connect::MODE_FROM_CLIENT);

    bool reply_called = false;
    bool relay_called = false;

    r.handle_peer_handshake(req,
        [&](const messages::Response& resp) {
            reply_called = true;
            // Decode the value — should be mode=REPLY (4)
            auto hs = peer_connect::decode_handshake_msg(
                resp.value->data(), resp.value->size());
            EXPECT_EQ(hs.mode, peer_connect::MODE_REPLY);
            EXPECT_EQ(resp.tid, 42u);
        },
        [&](const messages::Request&) { relay_called = true; });

    EXPECT_TRUE(reply_called) << "FROM_CLIENT must use reply (RESPONSE), not relay";
    EXPECT_FALSE(relay_called);
}

// Test 2: FROM_RELAY → REQUEST (relay back to relay node)
TEST(Router, RelayReplyIsRequest) {
    Router r;
    auto target = make_target(0x55);
    r.set(target, make_echo_entry());

    auto relay_addr = Ipv4Address::from_string("157.90.213.229", 49738);
    auto req = make_hs_request(target, peer_connect::MODE_FROM_RELAY, relay_addr);

    bool reply_called = false;
    bool relay_called = false;

    r.handle_peer_handshake(req,
        [&](const messages::Response&) { reply_called = true; },
        [&](const messages::Request& relay_req) {
            relay_called = true;

            // Verify it's a REQUEST that goes back to the relay
            EXPECT_EQ(relay_req.to.addr.host_string(), "157.90.213.229");
            EXPECT_EQ(relay_req.to.addr.port, 49738);

            // Encode it and check the first byte is REQUEST_ID (0x03)
            auto buf = messages::encode_request(relay_req);
            EXPECT_EQ(buf[0], messages::REQUEST_ID)
                << "FROM_RELAY must send a REQUEST (0x03), not a RESPONSE (0x13)";
        });

    EXPECT_FALSE(reply_called) << "FROM_RELAY must NOT use reply (RESPONSE)";
    EXPECT_TRUE(relay_called) << "FROM_RELAY must use relay (REQUEST)";
}

// Test 3: Relay reply preserves TID
TEST(Router, RelayReplyPreservesTid) {
    Router r;
    auto target = make_target(0x66);
    r.set(target, make_echo_entry());

    auto req = make_hs_request(target, peer_connect::MODE_FROM_RELAY,
                                Ipv4Address::from_string("10.0.0.1", 5000),
                                /*tid=*/12345);

    r.handle_peer_handshake(req,
        noop_reply,
        [&](const messages::Request& relay_req) {
            EXPECT_EQ(relay_req.tid, 12345)
                << "Relay REQUEST must preserve the original TID";
        });
}

// Test 4: Relay reply has mode=FROM_SERVER
TEST(Router, RelayReplyModeIsFromServer) {
    Router r;
    auto target = make_target(0x77);
    r.set(target, make_echo_entry());

    auto req = make_hs_request(target, peer_connect::MODE_FROM_RELAY);

    r.handle_peer_handshake(req,
        noop_reply,
        [&](const messages::Request& relay_req) {
            ASSERT_TRUE(relay_req.value.has_value());
            auto hs = peer_connect::decode_handshake_msg(
                relay_req.value->data(), relay_req.value->size());
            EXPECT_EQ(hs.mode, peer_connect::MODE_FROM_SERVER)
                << "Relay REQUEST must have mode=FROM_SERVER (1)";
        });
}

// Test 5: Relay reply preserves target
TEST(Router, RelayReplyTargetPreserved) {
    Router r;
    auto target = make_target(0x88);
    r.set(target, make_echo_entry());

    auto req = make_hs_request(target, peer_connect::MODE_FROM_RELAY);

    r.handle_peer_handshake(req,
        noop_reply,
        [&](const messages::Request& relay_req) {
            ASSERT_TRUE(relay_req.target.has_value());
            std::array<uint8_t, 32> expected{};
            expected.fill(0x88);
            EXPECT_EQ(*relay_req.target, expected)
                << "Relay REQUEST must preserve the original target";
        });
}

// Test 6: Relay reply includes peerAddress (original client's address)
TEST(Router, RelayReplyIncludesPeerAddress) {
    Router r;
    auto target = make_target(0x99);
    r.set(target, make_echo_entry());

    auto req = make_hs_request(target, peer_connect::MODE_FROM_RELAY);

    r.handle_peer_handshake(req,
        noop_reply,
        [&](const messages::Request& relay_req) {
            auto hs = peer_connect::decode_handshake_msg(
                relay_req.value->data(), relay_req.value->size());
            ASSERT_TRUE(hs.peer_address.has_value())
                << "Relay REQUEST must include peerAddress (client's address)";
            // The peerAddress should be the client's address (set in make_hs_request)
            EXPECT_EQ(hs.peer_address->host_string(), "192.168.1.100");
            EXPECT_EQ(hs.peer_address->port, 9999);
        });
}

// Test 7: PEER_HOLEPUNCH FROM_RELAY also sends REQUEST
TEST(Router, HolepunchRelayIsRequest) {
    Router r;
    auto target = make_target(0xAA);

    ForwardEntry entry;
    entry.on_peer_holepunch = [](const std::vector<uint8_t>& value,
                                  const Ipv4Address& peer_addr,
                                  const Ipv4Address& from_addr,
                                  const Ipv4Address& to_addr,
                                  std::function<void(std::vector<uint8_t>)> reply_fn) {
        // peer_address = client's address from the message (JS peerAddress)
        EXPECT_EQ(peer_addr.host_string(), "192.168.1.50");
        EXPECT_EQ(peer_addr.port, 8888);
        // from_address = UDP source = the relaying DHT node (JS req.from)
        EXPECT_EQ(from_addr.host_string(), "10.0.0.5");
        EXPECT_EQ(from_addr.port, 6000);
        // to_address = the address the request targeted us at (JS req.to)
        EXPECT_EQ(to_addr.host_string(), "10.0.0.2");
        EXPECT_EQ(to_addr.port, 5001);
        // Build a reply holepunch message
        holepunch::HolepunchMessage reply_hp;
        reply_hp.mode = peer_connect::MODE_FROM_SERVER;
        reply_hp.id = 0;
        reply_hp.payload = {0xBE, 0xEF};
        reply_fn(holepunch::encode_holepunch_msg(reply_hp));
    };
    r.set(target, entry);

    // Build a FROM_RELAY holepunch request
    holepunch::HolepunchMessage hp_msg;
    hp_msg.mode = peer_connect::MODE_FROM_RELAY;
    hp_msg.id = 7;
    hp_msg.payload = {0xCA, 0xFE};
    hp_msg.peer_address = Ipv4Address::from_string("192.168.1.50", 8888);

    messages::Request req;
    req.target = *reinterpret_cast<const std::array<uint8_t, 32>*>(target.data());
    req.value = holepunch::encode_holepunch_msg(hp_msg);
    req.from.addr = Ipv4Address::from_string("10.0.0.5", 6000);
    req.to.addr = Ipv4Address::from_string("10.0.0.2", 5001);
    req.tid = 777;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.internal = false;

    bool reply_called = false;
    bool relay_called = false;

    r.handle_peer_holepunch(req,
        [&](const messages::Response&) { reply_called = true; },
        [&](const messages::Request& relay_req) {
            relay_called = true;

            // Verify it's a REQUEST
            auto buf = messages::encode_request(relay_req);
            EXPECT_EQ(buf[0], messages::REQUEST_ID);

            // TID preserved
            EXPECT_EQ(relay_req.tid, 777);

            // Mode is FROM_SERVER in the holepunch value
            auto hp = holepunch::decode_holepunch_msg(
                relay_req.value->data(), relay_req.value->size());
            EXPECT_EQ(hp.mode, peer_connect::MODE_FROM_SERVER);

            // peerAddress is the original client's address
            ASSERT_TRUE(hp.peer_address.has_value());
            EXPECT_EQ(hp.peer_address->host_string(), "192.168.1.50");
        });

    EXPECT_FALSE(reply_called);
    EXPECT_TRUE(relay_called) << "PEER_HOLEPUNCH FROM_RELAY must use relay (REQUEST)";
}

// Test 8: Full relay round-trip — verify wire bytes
TEST(Router, FullRelayRoundTrip) {
    Router r;
    auto target = make_target(0xBB);
    r.set(target, make_echo_entry());

    auto relay_addr = Ipv4Address::from_string("88.99.3.86", 49737);
    auto req = make_hs_request(target, peer_connect::MODE_FROM_RELAY, relay_addr, /*tid=*/1000);

    r.handle_peer_handshake(req,
        noop_reply,
        [&](const messages::Request& relay_req) {
            // Encode to wire bytes — this is what goes on the network
            auto wire = messages::encode_request(relay_req);

            // First byte: REQUEST_ID (0x03)
            EXPECT_EQ(wire[0], 0x03);

            // Decode it back and verify all fields survived
            messages::Request decoded;
            messages::Response unused;
            auto type = messages::decode_message(wire.data(), wire.size(), decoded, unused);
            EXPECT_EQ(type, messages::REQUEST_ID);
            EXPECT_EQ(decoded.tid, 1000);
            EXPECT_EQ(decoded.command, messages::CMD_PEER_HANDSHAKE);
            EXPECT_FALSE(decoded.internal);
            ASSERT_TRUE(decoded.target.has_value());
            ASSERT_TRUE(decoded.value.has_value());

            // Decode the HandshakeMessage from the value
            auto hs = peer_connect::decode_handshake_msg(
                decoded.value->data(), decoded.value->size());
            EXPECT_EQ(hs.mode, peer_connect::MODE_FROM_SERVER);
            EXPECT_FALSE(hs.noise.empty());
            ASSERT_TRUE(hs.peer_address.has_value());
        });
}

// ============================================================================
// Relay-forward (else half) tests — a DHT node that is NOT the server host
// but holds an announce-populated ForwardEntry.relay for the target.
// JS: .analysis/js/hyperdht/lib/router.js:128-171 (onpeerhandshake else),
//     :212-247 (onpeerholepunch FROM_CLIENT / FROM_SERVER).
// ============================================================================

// Helper: a relay-only entry (announce populated relay = announcer's addr,
// no connection handlers) — what handle_announce's announceSelf branch sets.
static ForwardEntry make_relay_entry(Ipv4Address relay_addr) {
    ForwardEntry entry;
    entry.record = {0x01};  // a stored peer record (unused by relay forwarding)
    entry.relay = relay_addr;
    return entry;
}

// FROM_CLIENT on a relay node → FROM_RELAY forwarded toward the entry's relay,
// peerAddress rewritten to the client's UDP source, tid/command/target intact,
// token absent.
TEST(Router, RelayNodeForwardsHandshakeFromClient) {
    Router r;
    auto target = make_target(0xC1);
    auto server_addr = Ipv4Address::from_string("203.0.113.9", 49737);
    r.set(target, make_relay_entry(server_addr));

    auto client_addr = Ipv4Address::from_string("198.51.100.7", 5000);
    auto req = make_hs_request(target, peer_connect::MODE_FROM_CLIENT,
                               client_addr, /*tid=*/321);

    bool reply_called = false;
    bool relay_called = false;
    r.handle_peer_handshake(req,
        [&](const messages::Response&) { reply_called = true; },
        [&](const messages::Request& relay_req) {
            relay_called = true;
            // Forwarded toward the entry's relay (the server)
            EXPECT_EQ(relay_req.to.addr.host_string(), "203.0.113.9");
            EXPECT_EQ(relay_req.to.addr.port, 49737);
            // Same tid / command / target
            EXPECT_EQ(relay_req.tid, 321);
            EXPECT_EQ(relay_req.command, messages::CMD_PEER_HANDSHAKE);
            ASSERT_TRUE(relay_req.target.has_value());
            std::array<uint8_t, 32> exp{};
            exp.fill(0xC1);
            EXPECT_EQ(*relay_req.target, exp);
            // Relayed request carries no token
            EXPECT_FALSE(relay_req.token.has_value());
            // Wire byte is a REQUEST
            auto buf = messages::encode_request(relay_req);
            EXPECT_EQ(buf[0], messages::REQUEST_ID);
            // mode=FROM_RELAY, peerAddress=client addr
            auto hs = peer_connect::decode_handshake_msg(
                relay_req.value->data(), relay_req.value->size());
            EXPECT_EQ(hs.mode, peer_connect::MODE_FROM_RELAY);
            ASSERT_TRUE(hs.peer_address.has_value());
            EXPECT_EQ(hs.peer_address->host_string(), "198.51.100.7");
            EXPECT_EQ(hs.peer_address->port, 5000);
        });

    EXPECT_FALSE(reply_called);
    EXPECT_TRUE(relay_called) << "relay node must forward FROM_CLIENT as FROM_RELAY";
}

// FROM_CLIENT with no relay known → reply to the client with closerNodes so it
// can route toward the target (JS router.js:135). No relay, no handler dispatch.
TEST(Router, RelayNodeNoRelayRepliesWithCloserNodes) {
    Router r;  // no entry at all for this target
    auto target = make_target(0xC2);

    auto client_addr = Ipv4Address::from_string("198.51.100.8", 5001);
    auto req = make_hs_request(target, peer_connect::MODE_FROM_CLIENT,
                               client_addr, /*tid=*/654);

    auto fake_node = Ipv4Address::from_string("192.0.2.55", 49737);
    bool reply_called = false;
    bool relay_called = false;
    r.handle_peer_handshake(req,
        [&](const messages::Response& resp) {
            reply_called = true;
            EXPECT_EQ(resp.tid, 654);
            // Reply travels back to the client
            EXPECT_EQ(resp.from.addr.host_string(), "198.51.100.8");
            // No value, no token; closer nodes present
            EXPECT_FALSE(resp.value.has_value());
            EXPECT_FALSE(resp.token.has_value());
            ASSERT_EQ(resp.closer_nodes.size(), 1u);
            EXPECT_EQ(resp.closer_nodes[0].host_string(), "192.0.2.55");
        },
        [&](const messages::Request&) { relay_called = true; },
        [&](const announce::TargetKey&) {
            return std::vector<Ipv4Address>{fake_node};
        });

    EXPECT_TRUE(reply_called) << "no relay known → reply with closerNodes";
    EXPECT_FALSE(relay_called);
}

// FROM_SERVER on a relay node → bounce a REPLY to the client (peerAddress),
// NOT back to the server (req.from). This is the hop that completes the relay
// round-trip; without it a C++ DHT node is a black hole (the bug being fixed).
TEST(Router, RelayNodeBouncesHandshakeFromServerToClient) {
    Router r;
    auto target = make_target(0xC4);
    auto server_addr = Ipv4Address::from_string("203.0.113.11", 49737);
    r.set(target, make_relay_entry(server_addr));

    auto client_addr = Ipv4Address::from_string("198.51.100.10", 5003);
    peer_connect::HandshakeMessage hs;
    hs.mode = peer_connect::MODE_FROM_SERVER;
    hs.noise = {0x07, 0x08};
    hs.peer_address = client_addr;  // the server tells us where the client is

    messages::Request req;
    req.target = target;
    req.value = peer_connect::encode_handshake_msg(hs);
    req.from.addr = server_addr;  // arrived FROM the server
    req.to.addr = Ipv4Address::from_string("10.0.0.2", 5001);
    req.tid = 999;
    req.command = messages::CMD_PEER_HANDSHAKE;
    req.internal = false;

    bool reply_called = false;
    bool relay_called = false;
    r.handle_peer_handshake(req,
        [&](const messages::Response& resp) {
            reply_called = true;
            // Bounced to the CLIENT (peerAddress), not the server (req.from)
            EXPECT_EQ(resp.from.addr.host_string(), "198.51.100.10");
            EXPECT_EQ(resp.from.addr.port, 5003);
            EXPECT_EQ(resp.tid, 999);
            auto out = peer_connect::decode_handshake_msg(
                resp.value->data(), resp.value->size());
            EXPECT_EQ(out.mode, peer_connect::MODE_REPLY);
            // Reply's peerAddress = the server's address (req.from)
            ASSERT_TRUE(out.peer_address.has_value());
            EXPECT_EQ(out.peer_address->host_string(), "203.0.113.11");
        },
        [&](const messages::Request&) { relay_called = true; });

    EXPECT_TRUE(reply_called) << "FROM_SERVER must bounce a REPLY to the client";
    EXPECT_FALSE(relay_called);
}

// Holepunch FROM_CLIENT on a relay node → FROM_RELAY forwarded toward
// peerAddress (the server, when the client embeds one), peerAddress rewritten
// to the client's UDP source. JS router.js:213-219.
TEST(Router, RelayNodeForwardsHolepunchFromClient) {
    Router r;
    auto target = make_target(0xC3);
    auto server_addr = Ipv4Address::from_string("203.0.113.10", 49737);
    r.set(target, make_relay_entry(server_addr));  // relay-only, no handler

    holepunch::HolepunchMessage hp;
    hp.mode = peer_connect::MODE_FROM_CLIENT;
    hp.id = 9;
    hp.payload = {0xAA, 0xBB};
    hp.peer_address = server_addr;  // client targets the server directly

    auto client_addr = Ipv4Address::from_string("198.51.100.9", 5002);
    messages::Request req;
    req.target = target;
    req.value = holepunch::encode_holepunch_msg(hp);
    req.from.addr = client_addr;
    req.to.addr = Ipv4Address::from_string("10.0.0.2", 5001);
    req.tid = 888;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.internal = false;

    bool reply_called = false;
    bool relay_called = false;
    r.handle_peer_holepunch(req,
        [&](const messages::Response&) { reply_called = true; },
        [&](const messages::Request& relay_req) {
            relay_called = true;
            // peerAddress set → forward toward it (the server)
            EXPECT_EQ(relay_req.to.addr.host_string(), "203.0.113.10");
            EXPECT_EQ(relay_req.tid, 888);
            EXPECT_EQ(relay_req.command, messages::CMD_PEER_HOLEPUNCH);
            EXPECT_FALSE(relay_req.token.has_value());
            auto buf = messages::encode_request(relay_req);
            EXPECT_EQ(buf[0], messages::REQUEST_ID);
            auto out = holepunch::decode_holepunch_msg(
                relay_req.value->data(), relay_req.value->size());
            EXPECT_EQ(out.mode, peer_connect::MODE_FROM_RELAY);
            EXPECT_EQ(out.id, 9u);
            // peerAddress rewritten to the client's UDP source
            ASSERT_TRUE(out.peer_address.has_value());
            EXPECT_EQ(out.peer_address->host_string(), "198.51.100.9");
            EXPECT_EQ(out.peer_address->port, 5002);
        });

    EXPECT_FALSE(reply_called);
    EXPECT_TRUE(relay_called) << "relay node must forward holepunch FROM_CLIENT";
}
