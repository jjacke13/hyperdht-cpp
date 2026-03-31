#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "hyperdht/messages.hpp"

using namespace hyperdht::messages;
using namespace hyperdht::compact;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

static std::string to_hex(const std::vector<uint8_t>& v) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (auto b : v) {
        out.push_back(hex_chars[b >> 4]);
        out.push_back(hex_chars[b & 0x0F]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Request encoding/decoding round-trip
// ---------------------------------------------------------------------------

TEST(Messages, RequestMinimal) {
    Request req;
    req.tid = 42;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", 8080);
    req.command = CMD_PING;

    auto buf = encode_request(req);
    EXPECT_EQ(buf[0], REQUEST_ID);  // 0x03

    Request decoded;
    Response unused;
    auto type = decode_message(buf.data(), buf.size(), decoded, unused);
    EXPECT_EQ(type, REQUEST_ID);
    EXPECT_EQ(decoded.tid, 42u);
    EXPECT_EQ(decoded.to.addr.port, 8080u);
    EXPECT_EQ(decoded.command, CMD_PING);
    EXPECT_FALSE(decoded.id.has_value());
    EXPECT_FALSE(decoded.token.has_value());
    EXPECT_FALSE(decoded.target.has_value());
    EXPECT_FALSE(decoded.value.has_value());
}

TEST(Messages, RequestWithAllFields) {
    Request req;
    req.tid = 1000;
    req.to.addr = Ipv4Address::from_string("192.168.1.1", 49737);
    req.command = CMD_FIND_NODE;

    std::array<uint8_t, 32> id{};
    id.fill(0xAA);
    req.id = id;

    std::array<uint8_t, 32> token{};
    token.fill(0xBB);
    req.token = token;

    std::array<uint8_t, 32> target{};
    target.fill(0xCC);
    req.target = target;

    req.value = std::vector<uint8_t>{0x01, 0x02, 0x03};
    req.internal = true;

    auto buf = encode_request(req);

    Request decoded;
    Response unused;
    auto type = decode_message(buf.data(), buf.size(), decoded, unused);
    EXPECT_EQ(type, REQUEST_ID);
    EXPECT_EQ(decoded.tid, 1000u);
    EXPECT_EQ(decoded.command, CMD_FIND_NODE);
    EXPECT_TRUE(decoded.internal);

    ASSERT_TRUE(decoded.id.has_value());
    EXPECT_EQ(*decoded.id, id);

    ASSERT_TRUE(decoded.token.has_value());
    EXPECT_EQ(*decoded.token, token);

    ASSERT_TRUE(decoded.target.has_value());
    EXPECT_EQ(*decoded.target, target);

    ASSERT_TRUE(decoded.value.has_value());
    EXPECT_EQ(decoded.value->size(), 3u);
    EXPECT_EQ((*decoded.value)[0], 0x01);
}

// ---------------------------------------------------------------------------
// Response encoding/decoding round-trip
// ---------------------------------------------------------------------------

TEST(Messages, ResponseMinimal) {
    Response resp;
    resp.tid = 42;
    resp.from.addr = Ipv4Address::from_string("10.0.0.1", 3000);

    auto buf = encode_response(resp);
    EXPECT_EQ(buf[0], RESPONSE_ID);  // 0x13

    Request unused;
    Response decoded;
    auto type = decode_message(buf.data(), buf.size(), unused, decoded);
    EXPECT_EQ(type, RESPONSE_ID);
    EXPECT_EQ(decoded.tid, 42u);
    EXPECT_EQ(decoded.from.addr.port, 3000u);
}

TEST(Messages, ResponseWithCloserNodes) {
    Response resp;
    resp.tid = 100;
    resp.from.addr = Ipv4Address::from_string("10.0.0.1", 3000);

    resp.closer_nodes.push_back(Ipv4Address::from_string("192.168.1.1", 8001));
    resp.closer_nodes.push_back(Ipv4Address::from_string("192.168.1.2", 8002));

    std::array<uint8_t, 32> id{};
    id.fill(0xDD);
    resp.id = id;

    std::array<uint8_t, 32> token{};
    token.fill(0xEE);
    resp.token = token;

    auto buf = encode_response(resp);

    Request unused;
    Response decoded;
    auto type = decode_message(buf.data(), buf.size(), unused, decoded);
    EXPECT_EQ(type, RESPONSE_ID);
    EXPECT_EQ(decoded.tid, 100u);

    ASSERT_TRUE(decoded.id.has_value());
    EXPECT_EQ(*decoded.id, id);

    ASSERT_TRUE(decoded.token.has_value());
    EXPECT_EQ(*decoded.token, token);

    EXPECT_EQ(decoded.closer_nodes.size(), 2u);
    EXPECT_EQ(decoded.closer_nodes[0].port, 8001u);
    EXPECT_EQ(decoded.closer_nodes[1].port, 8002u);
}

TEST(Messages, ResponseWithError) {
    Response resp;
    resp.tid = 55;
    resp.from.addr = Ipv4Address::from_string("10.0.0.1", 3000);
    resp.error = 2;  // INVALID_TOKEN

    auto buf = encode_response(resp);

    Request unused;
    Response decoded;
    auto type = decode_message(buf.data(), buf.size(), unused, decoded);
    EXPECT_EQ(type, RESPONSE_ID);
    ASSERT_TRUE(decoded.error.has_value());
    EXPECT_EQ(*decoded.error, 2u);
}

// ---------------------------------------------------------------------------
// Invalid messages
// ---------------------------------------------------------------------------

TEST(Messages, TooShort) {
    uint8_t buf[] = {0x03};
    Request req;
    Response resp;
    EXPECT_EQ(decode_message(buf, 1, req, resp), 0u);
}

TEST(Messages, UnknownType) {
    uint8_t buf[] = {0xFF, 0x00};
    Request req;
    Response resp;
    EXPECT_EQ(decode_message(buf, 2, req, resp), 0u);
}

// ---------------------------------------------------------------------------
// Flags byte is correct
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Cross-test with JS dht-rpc encoding
// ---------------------------------------------------------------------------

TEST(Messages, CrossPingRequest) {
    Request req;
    req.tid = 42;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", 8080);
    req.command = CMD_PING;

    auto buf = encode_request(req);
    EXPECT_EQ(to_hex(buf), "03002a007f000001901f00")
        << "PING request should match JS dht-rpc encoding";
}

TEST(Messages, CrossFindNodeRequest) {
    Request req;
    req.tid = 1000;
    req.to.addr = Ipv4Address::from_string("192.168.1.1", 49737);
    req.command = CMD_FIND_NODE;

    std::array<uint8_t, 32> id{};
    id.fill(0xAA);
    req.id = id;

    std::array<uint8_t, 32> token{};
    token.fill(0xBB);
    req.token = token;

    std::array<uint8_t, 32> target{};
    target.fill(0xCC);
    req.target = target;

    req.value = std::vector<uint8_t>{0x01, 0x02, 0x03};

    auto buf = encode_request(req);
    EXPECT_EQ(to_hex(buf),
        "031be803c0a8010149c2"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "02"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        "03010203")
        << "FIND_NODE request should match JS dht-rpc encoding";
}

TEST(Messages, CrossMinimalResponse) {
    Response resp;
    resp.tid = 42;
    resp.from.addr = Ipv4Address::from_string("10.0.0.1", 3000);

    auto buf = encode_response(resp);
    EXPECT_EQ(to_hex(buf), "13002a000a000001b80b")
        << "Minimal response should match JS dht-rpc encoding";
}

TEST(Messages, CrossCloserResponse) {
    Response resp;
    resp.tid = 100;
    resp.from.addr = Ipv4Address::from_string("10.0.0.1", 3000);

    std::array<uint8_t, 32> id{};
    id.fill(0xDD);
    resp.id = id;

    std::array<uint8_t, 32> token{};
    token.fill(0xEE);
    resp.token = token;

    resp.closer_nodes.push_back(Ipv4Address::from_string("192.168.1.1", 8001));
    resp.closer_nodes.push_back(Ipv4Address::from_string("192.168.1.2", 8002));

    auto buf = encode_response(resp);
    EXPECT_EQ(to_hex(buf),
        "130764000a000001b80b"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "02c0a80101411fc0a80102421f")
        << "Response with closer nodes should match JS";
}

TEST(Messages, CrossErrorResponse) {
    Response resp;
    resp.tid = 55;
    resp.from.addr = Ipv4Address::from_string("10.0.0.1", 3000);
    resp.error = 2;

    auto buf = encode_response(resp);
    EXPECT_EQ(to_hex(buf), "130837000a000001b80b02")
        << "Error response should match JS";
}

TEST(Messages, FlagBits) {
    Request req;
    req.tid = 1;
    req.to.addr = Ipv4Address::from_string("127.0.0.1", 1234);
    req.command = 0;
    req.id = std::array<uint8_t, 32>{};
    req.token = std::array<uint8_t, 32>{};
    req.target = std::array<uint8_t, 32>{};
    req.value = std::vector<uint8_t>{0x00};

    auto buf = encode_request(req);
    // buf[0] = 0x03 (type), buf[1] = flags byte
    uint8_t flags = buf[1];
    EXPECT_TRUE(flags & FLAG_HAS_ID);
    EXPECT_TRUE(flags & FLAG_HAS_TOKEN);
    EXPECT_TRUE(flags & FLAG_HAS_TARGET);
    EXPECT_TRUE(flags & FLAG_HAS_VALUE);
    EXPECT_EQ(flags, FLAG_HAS_ID | FLAG_HAS_TOKEN | FLAG_HAS_TARGET | FLAG_HAS_VALUE);
}
