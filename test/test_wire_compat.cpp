// Wire compatibility tests — verify encode/decode round-trip for all
// HyperDHT message types, and cross-verify against JS-generated vectors.
//
// Round-trip: encode → decode → compare fields (tests our own symmetry)
// Cross-test: decode JS-generated hex → verify fields (tests JS compat)
//
// To regenerate JS vectors: node test/js/generate_wire_vectors.js

#include <gtest/gtest.h>

#include <sodium.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "hyperdht/compact.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/peer_connect.hpp"

using namespace hyperdht;

// Helper: hex string to bytes
static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int byte;
        sscanf(hex.c_str() + i, "%2x", &byte);
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

static std::string to_hex(const std::vector<uint8_t>& data) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    for (auto b : data) {
        out.push_back(h[b >> 4]);
        out.push_back(h[b & 0x0F]);
    }
    return out;
}

// ============================================================================
// Round-trip tests (encode → decode → compare)
// ============================================================================

TEST(WireCompat, HandshakeMessageRoundTrip) {
    peer_connect::HandshakeMessage msg;
    msg.mode = peer_connect::MODE_FROM_CLIENT;
    msg.noise = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    msg.peer_address = compact::Ipv4Address::from_string("192.168.1.100", 9999);

    auto encoded = peer_connect::encode_handshake_msg(msg);
    auto decoded = peer_connect::decode_handshake_msg(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.mode, peer_connect::MODE_FROM_CLIENT);
    EXPECT_EQ(decoded.noise, msg.noise);
    ASSERT_TRUE(decoded.peer_address.has_value());
    EXPECT_EQ(decoded.peer_address->host_string(), "192.168.1.100");
    EXPECT_EQ(decoded.peer_address->port, 9999);
}

TEST(WireCompat, HandshakeMessageReplyRoundTrip) {
    peer_connect::HandshakeMessage msg;
    msg.mode = peer_connect::MODE_REPLY;
    msg.noise = {0x11, 0x22, 0x33, 0x44, 0x55};
    // No peerAddress for REPLY

    auto encoded = peer_connect::encode_handshake_msg(msg);
    auto decoded = peer_connect::decode_handshake_msg(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.mode, peer_connect::MODE_REPLY);
    EXPECT_EQ(decoded.noise, msg.noise);
    EXPECT_FALSE(decoded.peer_address.has_value());
}

TEST(WireCompat, HolepunchMessageRoundTrip) {
    holepunch::HolepunchMessage msg;
    msg.mode = peer_connect::MODE_FROM_RELAY;
    msg.id = 42;
    msg.payload = {0xCA, 0xFE, 0xBA, 0xBE};
    msg.peer_address = compact::Ipv4Address::from_string("172.16.0.1", 8080);

    auto encoded = holepunch::encode_holepunch_msg(msg);
    auto decoded = holepunch::decode_holepunch_msg(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.mode, peer_connect::MODE_FROM_RELAY);
    EXPECT_EQ(decoded.id, 42u);
    EXPECT_EQ(decoded.payload, msg.payload);
    ASSERT_TRUE(decoded.peer_address.has_value());
    EXPECT_EQ(decoded.peer_address->host_string(), "172.16.0.1");
    EXPECT_EQ(decoded.peer_address->port, 8080);
}

TEST(WireCompat, AnnounceMessageRoundTrip) {
    dht_messages::AnnounceMessage msg;
    dht_messages::PeerRecord peer;
    peer.public_key.fill(0x42);
    peer.relay_addresses.push_back(
        compact::Ipv4Address::from_string("1.2.3.4", 5000));
    peer.relay_addresses.push_back(
        compact::Ipv4Address::from_string("5.6.7.8", 6000));
    msg.peer = peer;
    msg.signature = std::array<uint8_t, 64>{};
    msg.signature->fill(0xAA);

    auto encoded = dht_messages::encode_announce_msg(msg);
    auto decoded = dht_messages::decode_announce_msg(encoded.data(), encoded.size());

    ASSERT_TRUE(decoded.peer.has_value());
    EXPECT_EQ(decoded.peer->public_key, peer.public_key);
    EXPECT_EQ(decoded.peer->relay_addresses.size(), 2u);
    EXPECT_EQ(decoded.peer->relay_addresses[0].host_string(), "1.2.3.4");
    EXPECT_EQ(decoded.peer->relay_addresses[0].port, 5000);
    ASSERT_TRUE(decoded.signature.has_value());
    std::array<uint8_t, 64> expected_sig{};
    expected_sig.fill(0xAA);
    EXPECT_EQ(*decoded.signature, expected_sig);
}

TEST(WireCompat, AnnounceRefreshOnlyRoundTrip) {
    dht_messages::AnnounceMessage msg;
    msg.refresh = std::array<uint8_t, 32>{};
    msg.refresh->fill(0xBB);
    // No peer, no signature

    auto encoded = dht_messages::encode_announce_msg(msg);
    auto decoded = dht_messages::decode_announce_msg(encoded.data(), encoded.size());

    EXPECT_FALSE(decoded.peer.has_value());
    ASSERT_TRUE(decoded.refresh.has_value());
    std::array<uint8_t, 32> expected{};
    expected.fill(0xBB);
    EXPECT_EQ(*decoded.refresh, expected);
}

TEST(WireCompat, PeerRecordRoundTrip) {
    dht_messages::PeerRecord rec;
    rec.public_key.fill(0x11);
    rec.relay_addresses.push_back(
        compact::Ipv4Address::from_string("88.99.3.86", 49737));

    auto encoded = dht_messages::encode_peer_record(rec);
    auto decoded = dht_messages::decode_peer_record(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.public_key, rec.public_key);
    ASSERT_EQ(decoded.relay_addresses.size(), 1u);
    EXPECT_EQ(decoded.relay_addresses[0].host_string(), "88.99.3.86");
    EXPECT_EQ(decoded.relay_addresses[0].port, 49737);
}

TEST(WireCompat, MutablePutRequestRoundTrip) {
    dht_messages::MutablePutRequest msg;
    msg.public_key.fill(0x55);
    msg.seq = 7;
    msg.value = {'h', 'e', 'l', 'l', 'o', ' ', 'm', 'u', 't', 'a', 'b', 'l', 'e'};
    msg.signature.fill(0xCC);

    auto encoded = dht_messages::encode_mutable_put(msg);
    auto decoded = dht_messages::decode_mutable_put(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.public_key, msg.public_key);
    EXPECT_EQ(decoded.seq, 7u);
    EXPECT_EQ(decoded.value, msg.value);
    EXPECT_EQ(decoded.signature, msg.signature);
}

TEST(WireCompat, MutableGetResponseRoundTrip) {
    dht_messages::MutableGetResponse msg;
    msg.seq = 3;
    msg.value = {'s', 't', 'o', 'r', 'e', 'd', ' ', 'v', 'a', 'l', 'u', 'e'};
    msg.signature.fill(0xDD);

    auto encoded = dht_messages::encode_mutable_get_resp(msg);
    auto decoded = dht_messages::decode_mutable_get_resp(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.seq, 3u);
    EXPECT_EQ(decoded.value, msg.value);
    EXPECT_EQ(decoded.signature, msg.signature);
}

TEST(WireCompat, MutableSignableRoundTrip) {
    auto encoded = dht_messages::encode_mutable_signable(
        5, reinterpret_cast<const uint8_t*>("sign this"), 9);

    // Decode manually: seq(uint) + value(buffer)
    compact::State s = compact::State::for_decode(encoded.data(), encoded.size());
    auto seq = compact::Uint::decode(s);
    auto [ptr, len] = compact::Buffer::decode(s);

    EXPECT_EQ(seq, 5u);
    ASSERT_NE(ptr, nullptr);
    EXPECT_EQ(len, 9u);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(ptr), len), "sign this");
}

TEST(WireCompat, NoisePayloadRoundTrip) {
    peer_connect::NoisePayload payload;
    payload.version = 1;
    payload.error = peer_connect::ERROR_NONE;
    payload.firewall = peer_connect::FIREWALL_CONSISTENT;
    payload.addresses4.push_back(
        compact::Ipv4Address::from_string("91.220.171.23", 36036));

    peer_connect::UdxInfo udx;
    udx.version = 1;
    udx.reusable_socket = false;
    udx.id = 12345;
    udx.seq = 0;
    payload.udx = udx;

    auto encoded = peer_connect::encode_noise_payload(payload);
    auto decoded = peer_connect::decode_noise_payload(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.version, 1u);
    EXPECT_EQ(decoded.error, peer_connect::ERROR_NONE);
    EXPECT_EQ(decoded.firewall, peer_connect::FIREWALL_CONSISTENT);
    ASSERT_EQ(decoded.addresses4.size(), 1u);
    EXPECT_EQ(decoded.addresses4[0].host_string(), "91.220.171.23");
    EXPECT_EQ(decoded.addresses4[0].port, 36036);
    ASSERT_TRUE(decoded.udx.has_value());
    EXPECT_EQ(decoded.udx->id, 12345u);
}

TEST(WireCompat, DhtRequestRoundTrip) {
    messages::Request req;
    req.tid = 1234;
    req.to.addr = compact::Ipv4Address::from_string("10.0.0.1", 5000);
    req.command = messages::CMD_ANNOUNCE;
    req.internal = false;
    std::array<uint8_t, 32> target{};
    target.fill(0x77);
    req.target = target;
    req.value = std::vector<uint8_t>{'t', 'e', 's', 't'};

    auto buf = messages::encode_request(req);
    EXPECT_EQ(buf[0], messages::REQUEST_ID);

    messages::Request decoded;
    messages::Response unused;
    auto type = messages::decode_message(buf.data(), buf.size(), decoded, unused);

    EXPECT_EQ(type, messages::REQUEST_ID);
    EXPECT_EQ(decoded.tid, 1234);
    EXPECT_EQ(decoded.command, messages::CMD_ANNOUNCE);
    EXPECT_FALSE(decoded.internal);
    ASSERT_TRUE(decoded.target.has_value());
    EXPECT_EQ(*decoded.target, target);
    ASSERT_TRUE(decoded.value.has_value());
    EXPECT_EQ(*decoded.value, std::vector<uint8_t>({'t', 'e', 's', 't'}));
}

TEST(WireCompat, DhtResponseRoundTrip) {
    messages::Response resp;
    resp.tid = 5678;
    resp.from.addr = compact::Ipv4Address::from_string("10.0.0.2", 6000);
    std::array<uint8_t, 32> id{};
    id.fill(0x33);
    resp.id = id;
    resp.value = std::vector<uint8_t>{'o', 'k'};

    auto buf = messages::encode_response(resp);
    EXPECT_EQ(buf[0], messages::RESPONSE_ID);

    messages::Request unused;
    messages::Response decoded;
    auto type = messages::decode_message(buf.data(), buf.size(), unused, decoded);

    EXPECT_EQ(type, messages::RESPONSE_ID);
    EXPECT_EQ(decoded.tid, 5678);
    ASSERT_TRUE(decoded.id.has_value());
    EXPECT_EQ(*decoded.id, id);
    ASSERT_TRUE(decoded.value.has_value());
    EXPECT_EQ(*decoded.value, std::vector<uint8_t>({'o', 'k'}));
}

TEST(WireCompat, NoisePayloadWithIpv6RoundTrip) {
    peer_connect::NoisePayload payload;
    payload.version = 1;
    payload.error = peer_connect::ERROR_NONE;
    payload.firewall = peer_connect::FIREWALL_CONSISTENT;
    payload.addresses4.push_back(
        compact::Ipv4Address::from_string("10.0.0.1", 8080));
    payload.addresses6.push_back(
        compact::Ipv6Address::from_string("2001:db8::1", 443));
    payload.addresses6.push_back(
        compact::Ipv6Address::from_string("fe80::abcd", 9999));

    peer_connect::UdxInfo udx;
    udx.version = 1;
    udx.id = 42;
    udx.seq = 0;
    payload.udx = udx;
    payload.has_secret_stream = true;

    auto encoded = peer_connect::encode_noise_payload(payload);
    auto decoded = peer_connect::decode_noise_payload(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.version, 1u);
    EXPECT_EQ(decoded.firewall, peer_connect::FIREWALL_CONSISTENT);
    ASSERT_EQ(decoded.addresses4.size(), 1u);
    EXPECT_EQ(decoded.addresses4[0].host_string(), "10.0.0.1");
    ASSERT_EQ(decoded.addresses6.size(), 2u);
    EXPECT_EQ(decoded.addresses6[0].host_string(), "2001:db8:0:0:0:0:0:1");
    EXPECT_EQ(decoded.addresses6[0].port, 443);
    EXPECT_EQ(decoded.addresses6[1].host_string(), "fe80:0:0:0:0:0:0:abcd");
    EXPECT_EQ(decoded.addresses6[1].port, 9999);
    ASSERT_TRUE(decoded.udx.has_value());
    EXPECT_EQ(decoded.udx->id, 42u);
    EXPECT_TRUE(decoded.has_secret_stream);
}

TEST(WireCompat, NoisePayloadWithRelayThroughRoundTrip) {
    peer_connect::NoisePayload payload;
    payload.version = 1;
    payload.error = peer_connect::ERROR_NONE;
    payload.firewall = peer_connect::FIREWALL_UNKNOWN;

    peer_connect::RelayThroughInfo rt;
    rt.version = 1;
    rt.public_key.fill(0xAA);
    rt.token.fill(0xBB);
    payload.relay_through = rt;

    payload.relay_addresses.push_back(
        compact::Ipv4Address::from_string("1.2.3.4", 5555));

    auto encoded = peer_connect::encode_noise_payload(payload);
    auto decoded = peer_connect::decode_noise_payload(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.version, 1u);
    ASSERT_TRUE(decoded.relay_through.has_value());
    EXPECT_EQ(decoded.relay_through->version, 1u);
    EXPECT_EQ(decoded.relay_through->public_key, rt.public_key);
    EXPECT_EQ(decoded.relay_through->token, rt.token);
    ASSERT_EQ(decoded.relay_addresses.size(), 1u);
    EXPECT_EQ(decoded.relay_addresses[0].host_string(), "1.2.3.4");
    EXPECT_EQ(decoded.relay_addresses[0].port, 5555);
}

TEST(WireCompat, NoisePayloadAllFieldsRoundTrip) {
    // Test with every optional field populated
    peer_connect::NoisePayload payload;
    payload.version = 1;
    payload.error = peer_connect::ERROR_NONE;
    payload.firewall = peer_connect::FIREWALL_OPEN;

    peer_connect::HolepunchInfo hp;
    hp.id = 99;
    peer_connect::RelayInfo ri;
    ri.relay_address = compact::Ipv4Address::from_string("1.1.1.1", 1111);
    ri.peer_address = compact::Ipv4Address::from_string("2.2.2.2", 2222);
    hp.relays.push_back(ri);
    payload.holepunch = hp;

    payload.addresses4.push_back(
        compact::Ipv4Address::from_string("10.0.0.1", 8080));
    payload.addresses6.push_back(
        compact::Ipv6Address::from_string("::1", 443));

    peer_connect::UdxInfo udx;
    udx.version = 1;
    udx.reusable_socket = true;
    udx.id = 777;
    udx.seq = 3;
    payload.udx = udx;
    payload.has_secret_stream = true;

    peer_connect::RelayThroughInfo rt;
    rt.version = 1;
    rt.public_key.fill(0x11);
    rt.token.fill(0x22);
    payload.relay_through = rt;

    payload.relay_addresses.push_back(
        compact::Ipv4Address::from_string("5.5.5.5", 5000));

    auto encoded = peer_connect::encode_noise_payload(payload);
    auto decoded = peer_connect::decode_noise_payload(encoded.data(), encoded.size());

    // Verify all 7 flag fields
    EXPECT_EQ(decoded.version, 1u);
    EXPECT_EQ(decoded.firewall, peer_connect::FIREWALL_OPEN);

    ASSERT_TRUE(decoded.holepunch.has_value());
    EXPECT_EQ(decoded.holepunch->id, 99u);
    ASSERT_EQ(decoded.holepunch->relays.size(), 1u);

    ASSERT_EQ(decoded.addresses4.size(), 1u);
    EXPECT_EQ(decoded.addresses4[0].host_string(), "10.0.0.1");

    ASSERT_EQ(decoded.addresses6.size(), 1u);
    EXPECT_EQ(decoded.addresses6[0].host_string(), "0:0:0:0:0:0:0:1");
    EXPECT_EQ(decoded.addresses6[0].port, 443);

    ASSERT_TRUE(decoded.udx.has_value());
    EXPECT_TRUE(decoded.udx->reusable_socket);
    EXPECT_EQ(decoded.udx->id, 777u);

    EXPECT_TRUE(decoded.has_secret_stream);

    ASSERT_TRUE(decoded.relay_through.has_value());
    EXPECT_EQ(decoded.relay_through->public_key, rt.public_key);
    EXPECT_EQ(decoded.relay_through->token, rt.token);

    ASSERT_EQ(decoded.relay_addresses.size(), 1u);
    EXPECT_EQ(decoded.relay_addresses[0].host_string(), "5.5.5.5");
}

// ============================================================================
// JS cross-verification (decode JS-generated hex vectors)
// Generate with: node test/js/generate_wire_vectors.js
// Then paste the hex values here.
// ============================================================================

// JS-generated NoisePayload with ALL 7 optional fields
// Generated by: node -e "require('hyperdht/lib/messages').noisePayload.encode(...)"
TEST(WireCompat, NoisePayloadDecodeFromJS) {
    // This hex was generated by the JS HyperDHT messages.noisePayload encoder
    // with: version=1, error=0, firewall=CONSISTENT(2), holepunch(id=42),
    // addresses4=[10.0.0.1:8080], addresses6=[2001:db8::1:443],
    // udx(id=777,reusable=true,seq=3), secretStream, relayThrough(pk=0x11..,token=0x22..),
    // relayAddresses=[5.5.5.5:5000]
    // Single continuous hex string from JS (124 bytes)
    const std::string hex = "017f00022a0101010101570402020202ae08010a000001901f0120010db8000000000000000000000001bb010101fd0903030101001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222201050505058813";

    auto bytes = hex_to_bytes(hex);
    ASSERT_EQ(bytes.size(), 124u);

    auto decoded = peer_connect::decode_noise_payload(bytes.data(), bytes.size());

    EXPECT_EQ(decoded.version, 1u);
    EXPECT_EQ(decoded.error, 0u);
    EXPECT_EQ(decoded.firewall, peer_connect::FIREWALL_CONSISTENT);

    // Holepunch info
    ASSERT_TRUE(decoded.holepunch.has_value());
    EXPECT_EQ(decoded.holepunch->id, 42u);
    ASSERT_EQ(decoded.holepunch->relays.size(), 1u);
    EXPECT_EQ(decoded.holepunch->relays[0].relay_address.host_string(), "1.1.1.1");
    EXPECT_EQ(decoded.holepunch->relays[0].relay_address.port, 1111);
    EXPECT_EQ(decoded.holepunch->relays[0].peer_address.host_string(), "2.2.2.2");
    EXPECT_EQ(decoded.holepunch->relays[0].peer_address.port, 2222);

    // IPv4 addresses
    ASSERT_EQ(decoded.addresses4.size(), 1u);
    EXPECT_EQ(decoded.addresses4[0].host_string(), "10.0.0.1");
    EXPECT_EQ(decoded.addresses4[0].port, 8080);

    // IPv6 addresses
    ASSERT_EQ(decoded.addresses6.size(), 1u);
    EXPECT_EQ(decoded.addresses6[0].host_string(), "2001:db8:0:0:0:0:0:1");
    EXPECT_EQ(decoded.addresses6[0].port, 443);

    // UDX info
    ASSERT_TRUE(decoded.udx.has_value());
    EXPECT_EQ(decoded.udx->version, 1u);
    EXPECT_TRUE(decoded.udx->reusable_socket);
    EXPECT_EQ(decoded.udx->id, 777u);
    EXPECT_EQ(decoded.udx->seq, 3u);

    // SecretStream
    EXPECT_TRUE(decoded.has_secret_stream);

    // RelayThrough
    ASSERT_TRUE(decoded.relay_through.has_value());
    EXPECT_EQ(decoded.relay_through->version, 1u);
    std::array<uint8_t, 32> expected_pk{};
    expected_pk.fill(0x11);
    EXPECT_EQ(decoded.relay_through->public_key, expected_pk);
    std::array<uint8_t, 32> expected_token{};
    expected_token.fill(0x22);
    EXPECT_EQ(decoded.relay_through->token, expected_token);

    // Relay addresses
    ASSERT_EQ(decoded.relay_addresses.size(), 1u);
    EXPECT_EQ(decoded.relay_addresses[0].host_string(), "5.5.5.5");
    EXPECT_EQ(decoded.relay_addresses[0].port, 5000);
}

// Also verify C++ encode of the same payload produces identical bytes to JS
TEST(WireCompat, NoisePayloadEncodeMatchesJS) {
    peer_connect::NoisePayload payload;
    payload.version = 1;
    payload.error = 0;
    payload.firewall = peer_connect::FIREWALL_CONSISTENT;

    peer_connect::HolepunchInfo hp;
    hp.id = 42;
    peer_connect::RelayInfo ri;
    ri.relay_address = compact::Ipv4Address::from_string("1.1.1.1", 1111);
    ri.peer_address = compact::Ipv4Address::from_string("2.2.2.2", 2222);
    hp.relays.push_back(ri);
    payload.holepunch = hp;

    payload.addresses4.push_back(compact::Ipv4Address::from_string("10.0.0.1", 8080));
    payload.addresses6.push_back(compact::Ipv6Address::from_string("2001:db8::1", 443));

    peer_connect::UdxInfo udx;
    udx.version = 1;
    udx.reusable_socket = true;
    udx.id = 777;
    udx.seq = 3;
    payload.udx = udx;
    payload.has_secret_stream = true;

    peer_connect::RelayThroughInfo rt;
    rt.version = 1;
    rt.public_key.fill(0x11);
    rt.token.fill(0x22);
    payload.relay_through = rt;

    payload.relay_addresses.push_back(compact::Ipv4Address::from_string("5.5.5.5", 5000));

    auto encoded = peer_connect::encode_noise_payload(payload);

    const std::string expected_hex = "017f00022a0101010101570402020202ae08010a000001901f0120010db8000000000000000000000001bb010101fd0903030101001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222201050505058813";

    EXPECT_EQ(to_hex(encoded), expected_hex)
        << "C++ NoisePayload encode must match JS byte-for-byte";
}

TEST(WireCompat, EncodingIsDeterministic) {
    // HandshakeMessage
    {
        peer_connect::HandshakeMessage msg;
        msg.mode = peer_connect::MODE_FROM_CLIENT;
        msg.noise = {0x01, 0x02, 0x03};
        auto a = peer_connect::encode_handshake_msg(msg);
        auto b = peer_connect::encode_handshake_msg(msg);
        EXPECT_EQ(a, b) << "HandshakeMessage encoding not deterministic";
    }
    // AnnounceMessage
    {
        dht_messages::AnnounceMessage msg;
        dht_messages::PeerRecord peer;
        peer.public_key.fill(0x42);
        msg.peer = peer;
        auto a = dht_messages::encode_announce_msg(msg);
        auto b = dht_messages::encode_announce_msg(msg);
        EXPECT_EQ(a, b) << "AnnounceMessage encoding not deterministic";
    }
    // MutablePutRequest
    {
        dht_messages::MutablePutRequest msg;
        msg.public_key.fill(0x55);
        msg.seq = 1;
        msg.value = {'x'};
        msg.signature.fill(0xCC);
        auto a = dht_messages::encode_mutable_put(msg);
        auto b = dht_messages::encode_mutable_put(msg);
        EXPECT_EQ(a, b) << "MutablePutRequest encoding not deterministic";
    }
}
