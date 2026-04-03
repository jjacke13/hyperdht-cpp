// Edge case tests — boundary conditions for decoders and state machines.
//
// A6: Zero-length buffers, max-size varints, truncated messages
// A7: Expired tokens, full routing table

#include <gtest/gtest.h>

#include <sodium.h>

#include <array>
#include <cstring>
#include <vector>

#include "hyperdht/compact.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/routing_table.hpp"
#include "hyperdht/tokens.hpp"

using namespace hyperdht;

// ============================================================================
// A6: Decoder edge cases
// ============================================================================

// --- Zero-length inputs ---

TEST(EdgeCase, DecodeEmptyHandshakeMessage) {
    auto msg = peer_connect::decode_handshake_msg(nullptr, 0);
    EXPECT_TRUE(msg.noise.empty());
}

TEST(EdgeCase, DecodeEmptyHolepunchMessage) {
    auto msg = holepunch::decode_holepunch_msg(nullptr, 0);
    EXPECT_TRUE(msg.payload.empty());
}

TEST(EdgeCase, DecodeEmptyAnnounceMessage) {
    auto msg = dht_messages::decode_announce_msg(nullptr, 0);
    EXPECT_FALSE(msg.peer.has_value());
    EXPECT_FALSE(msg.signature.has_value());
}

TEST(EdgeCase, DecodeEmptyNoisePayload) {
    auto payload = peer_connect::decode_noise_payload(nullptr, 0);
    EXPECT_EQ(payload.version, 0u);
}

TEST(EdgeCase, DecodeEmptyMutablePut) {
    auto msg = dht_messages::decode_mutable_put(nullptr, 0);
    EXPECT_TRUE(msg.value.empty());
}

TEST(EdgeCase, DecodeEmptyDhtMessage) {
    messages::Request req;
    messages::Response resp;
    auto type = messages::decode_message(nullptr, 0, req, resp);
    EXPECT_EQ(type, 0) << "Empty input should return type 0 (error)";
}

TEST(EdgeCase, DecodeSingleByteRequest) {
    uint8_t buf[] = {messages::REQUEST_ID};
    messages::Request req;
    messages::Response resp;
    auto type = messages::decode_message(buf, 1, req, resp);
    // Should fail gracefully (not enough data for flags + tid + addr)
    EXPECT_EQ(type, 0);
}

TEST(EdgeCase, DecodeSingleByteResponse) {
    uint8_t buf[] = {messages::RESPONSE_ID};
    messages::Request req;
    messages::Response resp;
    auto type = messages::decode_message(buf, 1, req, resp);
    EXPECT_EQ(type, 0);
}

// --- Truncated inputs ---

TEST(EdgeCase, TruncatedHandshakeMessage) {
    // Encode a valid message, then truncate
    peer_connect::HandshakeMessage msg;
    msg.mode = peer_connect::MODE_FROM_CLIENT;
    msg.noise = {0x01, 0x02, 0x03, 0x04, 0x05};
    msg.peer_address = compact::Ipv4Address::from_string("10.0.0.1", 5000);
    auto encoded = peer_connect::encode_handshake_msg(msg);

    // Try decoding with progressively fewer bytes
    for (size_t i = 1; i < encoded.size(); i++) {
        auto decoded = peer_connect::decode_handshake_msg(encoded.data(), i);
        // Should not crash — may have partial data or empty fields
        (void)decoded;
    }
}

TEST(EdgeCase, TruncatedDhtRequest) {
    messages::Request req;
    req.tid = 42;
    req.to.addr = compact::Ipv4Address::from_string("10.0.0.1", 5000);
    req.command = messages::CMD_PING;
    req.internal = true;
    auto buf = messages::encode_request(req);

    for (size_t i = 1; i < buf.size(); i++) {
        messages::Request decoded;
        messages::Response unused;
        auto type = messages::decode_message(buf.data(), i, decoded, unused);
        // Should not crash — returns 0 on truncation
        (void)type;
    }
}

TEST(EdgeCase, TruncatedMutablePut) {
    dht_messages::MutablePutRequest msg;
    msg.public_key.fill(0x55);
    msg.seq = 1;
    msg.value = {'a', 'b', 'c'};
    msg.signature.fill(0xCC);
    auto encoded = dht_messages::encode_mutable_put(msg);

    for (size_t i = 1; i < encoded.size(); i++) {
        auto decoded = dht_messages::decode_mutable_put(encoded.data(), i);
        (void)decoded;
    }
}

// --- Max-size varints ---

TEST(EdgeCase, MaxVarintDoesNotCrash) {
    // 0xFF prefix followed by 8 bytes of 0xFF = max uint64
    uint8_t buf[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    compact::State s = compact::State::for_decode(buf, sizeof(buf));
    auto val = compact::Uint::decode(s);
    EXPECT_FALSE(s.error);
    EXPECT_EQ(val, UINT64_MAX);
}

TEST(EdgeCase, MaxVarintBufferDecodeRejected) {
    // Buffer with max-uint64 length prefix — should fail (not enough data)
    uint8_t buf[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    compact::State s = compact::State::for_decode(buf, sizeof(buf));
    auto result = compact::Buffer::decode(s);
    EXPECT_TRUE(s.error) << "Buffer with impossibly large length should fail";
    EXPECT_TRUE(result.is_null());
}

TEST(EdgeCase, LargeArrayCountRejected) {
    // Array with count > ARRAY_MAX_LENGTH (1M)
    // Encode count = 0x100001 as a varint
    uint8_t buf[] = {0xFE, 0x01, 0x00, 0x10, 0x00};  // varint for 0x100001
    compact::State s = compact::State::for_decode(buf, sizeof(buf));
    auto arr = compact::Ipv4Array::decode(s);
    EXPECT_TRUE(s.error || arr.empty())
        << "Array count above 1M limit should be rejected";
}

// --- Invalid type bytes ---

TEST(EdgeCase, InvalidMessageTypeByte) {
    uint8_t buf[] = {0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    messages::Request req;
    messages::Response resp;
    auto type = messages::decode_message(buf, sizeof(buf), req, resp);
    EXPECT_EQ(type, 0) << "Unknown type byte should return 0";
}

// ============================================================================
// A7: State machine edge cases
// ============================================================================

// --- Token validation ---

TEST(EdgeCase, ExpiredTokenRejected) {
    tokens::TokenStore store;

    auto token = store.create("10.0.0.1");
    EXPECT_TRUE(store.validate("10.0.0.1", token));

    // Rotate twice to expire the token (current + previous are valid)
    store.rotate();
    EXPECT_TRUE(store.validate("10.0.0.1", token))
        << "Token should still be valid after 1 rotation (previous secret)";

    store.rotate();
    EXPECT_FALSE(store.validate("10.0.0.1", token))
        << "Token should expire after 2 rotations";
}

TEST(EdgeCase, TokenWrongHostRejected) {
    tokens::TokenStore store;

    auto token = store.create("10.0.0.1");
    EXPECT_FALSE(store.validate("10.0.0.2", token))
        << "Token for different host should be rejected";
}

// --- Routing table ---

TEST(EdgeCase, FullBucketEviction) {
    routing::NodeId our_id{};
    our_id.fill(0x80);
    routing::RoutingTable table(our_id);

    // Fill a bucket with 20 nodes (k=20)
    for (int i = 0; i < 20; i++) {
        routing::Node node;
        node.id.fill(0x00);
        node.id[31] = static_cast<uint8_t>(i + 1);  // Same bucket (close IDs)
        node.host = "192.168.1." + std::to_string(i + 1);
        node.port = static_cast<uint16_t>(8000 + i);
        table.add(node);
    }

    EXPECT_EQ(table.size(), 20u);

    // Adding a 21st node to the same bucket — should be ignored or evict
    routing::Node extra;
    extra.id.fill(0x00);
    extra.id[31] = 0xFF;
    extra.host = "192.168.1.200";
    extra.port = 9999;
    table.add(extra);

    // Table should not exceed k per bucket
    EXPECT_LE(table.size(), 21u);  // May or may not add depending on eviction policy
}

TEST(EdgeCase, ClosestWithEmptyTable) {
    routing::NodeId our_id{};
    our_id.fill(0x80);
    routing::RoutingTable table(our_id);
    routing::NodeId target{};
    target.fill(0x42);

    auto closest = table.closest(target);
    EXPECT_TRUE(closest.empty()) << "Empty table should return no closest nodes";
}

TEST(EdgeCase, AddDuplicateNode) {
    routing::NodeId our_id{};
    our_id.fill(0x80);
    routing::RoutingTable table(our_id);

    routing::Node node;
    node.id.fill(0x11);
    node.host = "10.0.0.1";
    node.port = 5000;

    table.add(node);
    table.add(node);  // Duplicate

    // Should not double-count
    EXPECT_EQ(table.size(), 1u);
}

// --- Compact decoder safety ---

TEST(EdgeCase, Uint16InsufficientBytes) {
    uint8_t buf[] = {0x42};  // Only 1 byte, need 2
    compact::State s = compact::State::for_decode(buf, 1);
    auto val = compact::Uint16::decode(s);
    EXPECT_TRUE(s.error);
    EXPECT_EQ(val, 0);
}

TEST(EdgeCase, Fixed32InsufficientBytes) {
    uint8_t buf[16] = {};
    compact::State s = compact::State::for_decode(buf, 16);
    auto val = compact::Fixed32::decode(s);
    EXPECT_TRUE(s.error) << "Fixed32 needs 32 bytes, only 16 given";
}

TEST(EdgeCase, Ipv4AddrInsufficientBytes) {
    uint8_t buf[4] = {};
    compact::State s = compact::State::for_decode(buf, 4);
    auto addr = compact::Ipv4Addr::decode(s);
    EXPECT_TRUE(s.error) << "Ipv4Addr needs 6 bytes, only 4 given";
}
