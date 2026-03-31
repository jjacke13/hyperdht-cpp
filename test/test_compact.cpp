#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "hyperdht/compact.hpp"

using namespace hyperdht::compact;

// ---------------------------------------------------------------------------
// Helpers — preencode → allocate → encode → return buffer
// ---------------------------------------------------------------------------

template <typename Enc, typename T>
static std::vector<uint8_t> encode_value(const T& v) {
    State s;
    Enc::preencode(s, v);
    std::vector<uint8_t> buf(s.end);
    s.buffer = buf.data();
    s.start = 0;
    Enc::encode(s, v);
    EXPECT_FALSE(s.error);
    EXPECT_EQ(s.start, s.end);
    return buf;
}

template <typename Enc, typename T>
static T decode_value(const std::vector<uint8_t>& buf) {
    auto s = State::for_decode(buf.data(), buf.size());
    auto v = Enc::decode(s);
    EXPECT_FALSE(s.error);
    EXPECT_EQ(s.start, s.end);
    return v;
}

template <typename Enc, typename T>
static void round_trip(const T& v) {
    auto buf = encode_value<Enc>(v);
    auto decoded = decode_value<Enc, T>(buf);
    EXPECT_EQ(v, decoded);
}

// ===========================================================================
// Varint (Uint)
// ===========================================================================

TEST(Varint, SingleByte) {
    // Values 0..252 encode as 1 byte
    for (uint64_t v = 0; v <= 0xFC; ++v) {
        auto buf = encode_value<Uint>(v);
        ASSERT_EQ(buf.size(), 1) << "v=" << v;
        EXPECT_EQ(buf[0], static_cast<uint8_t>(v));
        auto decoded = decode_value<Uint, uint64_t>(buf);
        EXPECT_EQ(decoded, v);
    }
}

TEST(Varint, TwoByteMarker) {
    // 0xFD..0xFFFF → 3 bytes: [0xFD] [uint16 LE]
    auto buf = encode_value<Uint>(uint64_t{0xFD});
    ASSERT_EQ(buf.size(), 3);
    EXPECT_EQ(buf[0], 0xFD);
    EXPECT_EQ(buf[1], 0xFD);
    EXPECT_EQ(buf[2], 0x00);
}

TEST(Varint, KnownVectors) {
    // From PROTOCOL.md examples
    {  // 42 → [0x2A]
        auto buf = encode_value<Uint>(uint64_t{42});
        ASSERT_EQ(buf.size(), 1);
        EXPECT_EQ(buf[0], 0x2A);
    }
    {  // 4200 → [0xFD, 0x68, 0x10]
        auto buf = encode_value<Uint>(uint64_t{4200});
        ASSERT_EQ(buf.size(), 3);
        EXPECT_EQ(buf[0], 0xFD);
        EXPECT_EQ(buf[1], 0x68);
        EXPECT_EQ(buf[2], 0x10);
    }
    {  // 300000 = 0x493E0 → [0xFE, 0xE0, 0x93, 0x04, 0x00]
        auto buf = encode_value<Uint>(uint64_t{300000});
        ASSERT_EQ(buf.size(), 5);
        EXPECT_EQ(buf[0], 0xFE);
        EXPECT_EQ(buf[1], 0xE0);
        EXPECT_EQ(buf[2], 0x93);
        EXPECT_EQ(buf[3], 0x04);
        EXPECT_EQ(buf[4], 0x00);
    }
}

TEST(Varint, FourByteMarker) {
    round_trip<Uint>(uint64_t{0x10000});
    round_trip<Uint>(uint64_t{0xFFFFFFFF});
}

TEST(Varint, EightByteMarker) {
    round_trip<Uint>(uint64_t{0x100000000ULL});
    round_trip<Uint>(uint64_t{0xFFFFFFFFFFFFFFFFULL});
}

TEST(Varint, BoundaryValues) {
    round_trip<Uint>(uint64_t{0});
    round_trip<Uint>(uint64_t{0xFC});       // max 1-byte
    round_trip<Uint>(uint64_t{0xFD});       // min 3-byte
    round_trip<Uint>(uint64_t{0xFFFF});     // max 3-byte
    round_trip<Uint>(uint64_t{0x10000});    // min 5-byte
    round_trip<Uint>(uint64_t{0xFFFFFFFF}); // max 5-byte
    round_trip<Uint>(uint64_t{0x100000000ULL});  // min 9-byte
}

TEST(Varint, DecodeEmptyBuffer) {
    auto s = State::for_decode(nullptr, 0);
    Uint::decode(s);
    EXPECT_TRUE(s.error);
}

TEST(Varint, DecodeTruncated) {
    // 0xFD marker but only 1 byte of uint16
    uint8_t buf[] = {0xFD, 0x42};
    auto s = State::for_decode(buf, 2);
    Uint::decode(s);
    EXPECT_TRUE(s.error);
}

// ===========================================================================
// Fixed-size integers
// ===========================================================================

TEST(Uint8, RoundTrip) {
    round_trip<Uint8>(uint8_t{0});
    round_trip<Uint8>(uint8_t{255});
    round_trip<Uint8>(uint8_t{42});
}

TEST(Uint16, RoundTrip) {
    round_trip<Uint16>(uint16_t{0});
    round_trip<Uint16>(uint16_t{0xFFFF});
    round_trip<Uint16>(uint16_t{0x1234});
}

TEST(Uint16, LittleEndian) {
    auto buf = encode_value<Uint16>(uint16_t{0x0102});
    ASSERT_EQ(buf.size(), 2);
    EXPECT_EQ(buf[0], 0x02);  // low byte first
    EXPECT_EQ(buf[1], 0x01);
}

TEST(Uint32, RoundTrip) {
    round_trip<Uint32>(uint32_t{0});
    round_trip<Uint32>(uint32_t{0xFFFFFFFF});
    round_trip<Uint32>(uint32_t{0xDEADBEEF});
}

TEST(Uint64, RoundTrip) {
    round_trip<Uint64>(uint64_t{0});
    round_trip<Uint64>(uint64_t{0xFFFFFFFFFFFFFFFF});
    round_trip<Uint64>(uint64_t{0xDEADBEEFCAFEBABE});
}

// ===========================================================================
// Bool
// ===========================================================================

TEST(Bool, RoundTrip) {
    round_trip<Bool>(true);
    round_trip<Bool>(false);
}

TEST(Bool, WireFormat) {
    auto t = encode_value<Bool>(true);
    auto f = encode_value<Bool>(false);
    ASSERT_EQ(t.size(), 1);
    ASSERT_EQ(f.size(), 1);
    EXPECT_EQ(t[0], 0x01);
    EXPECT_EQ(f[0], 0x00);
}

// ===========================================================================
// Buffer (nullable, length-prefixed)
// ===========================================================================

TEST(Buffer, NullEncoding) {
    State s;
    Buffer::preencode_null(s);
    EXPECT_EQ(s.end, 1);

    std::vector<uint8_t> buf(s.end);
    s.buffer = buf.data();
    s.start = 0;
    Buffer::encode_null(s);
    EXPECT_EQ(buf[0], 0x00);

    auto ds = State::for_decode(buf.data(), buf.size());
    auto result = Buffer::decode(ds);
    EXPECT_TRUE(result.is_null());
}

TEST(Buffer, NonNullRoundTrip) {
    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};

    State s;
    Buffer::preencode(s, payload.data(), payload.size());
    std::vector<uint8_t> buf(s.end);
    s.buffer = buf.data();
    s.start = 0;
    Buffer::encode(s, payload.data(), payload.size());
    EXPECT_FALSE(s.error);

    auto ds = State::for_decode(buf.data(), buf.size());
    auto result = Buffer::decode(ds);
    EXPECT_FALSE(result.is_null());
    EXPECT_EQ(result.len, 4);
    EXPECT_EQ(std::memcmp(result.data, payload.data(), 4), 0);
}

TEST(Buffer, EmptyIsNull) {
    // Empty buffer (nullptr, len=0) encodes as null
    State s;
    Buffer::preencode(s, nullptr, 0);
    EXPECT_EQ(s.end, 1);  // just the 0x00 marker
}

// ===========================================================================
// Raw
// ===========================================================================

TEST(Raw, RoundTrip) {
    std::vector<uint8_t> payload = {1, 2, 3, 4, 5};

    State s;
    Raw::preencode(s, payload.data(), payload.size());
    std::vector<uint8_t> buf(s.end);
    s.buffer = buf.data();
    s.start = 0;
    Raw::encode(s, payload.data(), payload.size());
    EXPECT_FALSE(s.error);
    EXPECT_EQ(buf, payload);

    auto ds = State::for_decode(buf.data(), buf.size());
    auto result = Raw::decode(ds);
    EXPECT_EQ(result.len, 5);
    EXPECT_EQ(ds.start, ds.end);  // consumed everything
}

// ===========================================================================
// Fixed32 / Fixed64
// ===========================================================================

TEST(Fixed32, RoundTrip) {
    Fixed32::Value v{};
    for (size_t i = 0; i < 32; ++i) v[i] = static_cast<uint8_t>(i);
    round_trip<Fixed32>(v);
}

TEST(Fixed32, WireFormat) {
    Fixed32::Value v{};
    v[0] = 0xAA;
    v[31] = 0xBB;
    auto buf = encode_value<Fixed32>(v);
    ASSERT_EQ(buf.size(), 32);
    EXPECT_EQ(buf[0], 0xAA);
    EXPECT_EQ(buf[31], 0xBB);
}

TEST(Fixed64, RoundTrip) {
    Fixed64::Value v{};
    for (size_t i = 0; i < 64; ++i) v[i] = static_cast<uint8_t>(i * 3);
    round_trip<Fixed64>(v);
}

// ===========================================================================
// IPv4 Address
// ===========================================================================

TEST(Ipv4Address, FromString) {
    auto addr = Ipv4Address::from_string("192.168.1.1", 8080);
    EXPECT_EQ(addr.host[0], 192);
    EXPECT_EQ(addr.host[1], 168);
    EXPECT_EQ(addr.host[2], 1);
    EXPECT_EQ(addr.host[3], 1);
    EXPECT_EQ(addr.port, 8080);
}

TEST(Ipv4Address, ToString) {
    Ipv4Address addr;
    addr.host = {10, 0, 0, 1};
    addr.port = 443;
    EXPECT_EQ(addr.host_string(), "10.0.0.1");
}

TEST(Ipv4Address, StringRoundTrip) {
    auto addr = Ipv4Address::from_string("88.99.3.86", 49737);
    EXPECT_EQ(addr.host_string(), "88.99.3.86");
    EXPECT_EQ(addr.port, 49737);
}

TEST(Ipv4Addr, RoundTrip) {
    auto addr = Ipv4Address::from_string("192.168.1.1", 8080);
    round_trip<Ipv4Addr>(addr);
}

TEST(Ipv4Addr, WireFormat) {
    auto addr = Ipv4Address::from_string("10.20.30.40", 0x1234);
    auto buf = encode_value<Ipv4Addr>(addr);
    ASSERT_EQ(buf.size(), 6);
    // IP octets in order
    EXPECT_EQ(buf[0], 10);
    EXPECT_EQ(buf[1], 20);
    EXPECT_EQ(buf[2], 30);
    EXPECT_EQ(buf[3], 40);
    // Port LE
    EXPECT_EQ(buf[4], 0x34);  // low byte
    EXPECT_EQ(buf[5], 0x12);  // high byte
}

TEST(Ipv4Addr, BootstrapNode) {
    // Real HyperDHT bootstrap node
    auto addr = Ipv4Address::from_string("88.99.3.86", 49737);
    auto buf = encode_value<Ipv4Addr>(addr);
    auto decoded = decode_value<Ipv4Addr, Ipv4Address>(buf);
    EXPECT_EQ(decoded.host_string(), "88.99.3.86");
    EXPECT_EQ(decoded.port, 49737);
}

// ===========================================================================
// Array combinator
// ===========================================================================

TEST(Ipv4Array, Empty) {
    std::vector<Ipv4Address> addrs;
    auto buf = encode_value<Ipv4Array>(addrs);
    // varint(0) = 1 byte
    ASSERT_EQ(buf.size(), 1);
    EXPECT_EQ(buf[0], 0x00);

    auto decoded = decode_value<Ipv4Array, std::vector<Ipv4Address>>(buf);
    EXPECT_TRUE(decoded.empty());
}

TEST(Ipv4Array, MultipleAddresses) {
    std::vector<Ipv4Address> addrs = {
        Ipv4Address::from_string("192.168.1.1", 8080),
        Ipv4Address::from_string("10.0.0.1", 443),
        Ipv4Address::from_string("88.99.3.86", 49737),
    };

    auto buf = encode_value<Ipv4Array>(addrs);
    // varint(3)=1 + 3*6=18 = 19 bytes
    EXPECT_EQ(buf.size(), 19);

    auto decoded = decode_value<Ipv4Array, std::vector<Ipv4Address>>(buf);
    ASSERT_EQ(decoded.size(), 3);
    EXPECT_EQ(decoded[0], addrs[0]);
    EXPECT_EQ(decoded[1], addrs[1]);
    EXPECT_EQ(decoded[2], addrs[2]);
}

TEST(Array, DoSCap) {
    // Craft a buffer claiming 0x100001 elements — should error
    State s;
    Uint::preencode(s, ARRAY_MAX_LENGTH + 1);
    std::vector<uint8_t> buf(s.end);
    s.buffer = buf.data();
    s.start = 0;
    Uint::encode(s, ARRAY_MAX_LENGTH + 1);

    auto ds = State::for_decode(buf.data(), buf.size());
    auto result = Ipv4Array::decode(ds);
    EXPECT_TRUE(ds.error);
    EXPECT_TRUE(result.empty());
}

// ===========================================================================
// Sequential encode/decode (multiple fields in one buffer)
// ===========================================================================

TEST(Sequential, MultiFieldRoundTrip) {
    // Simulate a simple message: uint flags + bool connected + fixed32 key
    uint64_t flags = 0x07;
    bool connected = true;
    Fixed32::Value key{};
    for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(0xA0 + i);

    // Preencode
    State s;
    Uint::preencode(s, flags);
    Bool::preencode(s, connected);
    Fixed32::preencode(s, key);

    // Allocate + encode
    std::vector<uint8_t> buf(s.end);
    s.buffer = buf.data();
    s.start = 0;
    Uint::encode(s, flags);
    Bool::encode(s, connected);
    Fixed32::encode(s, key);
    EXPECT_FALSE(s.error);
    EXPECT_EQ(s.start, s.end);

    // Decode
    auto ds = State::for_decode(buf.data(), buf.size());
    auto d_flags = Uint::decode(ds);
    auto d_connected = Bool::decode(ds);
    auto d_key = Fixed32::decode(ds);
    EXPECT_FALSE(ds.error);
    EXPECT_EQ(d_flags, flags);
    EXPECT_EQ(d_connected, connected);
    EXPECT_EQ(d_key, key);
}

// ===========================================================================
// Error propagation
// ===========================================================================

TEST(Error, PropagatesAcrossDecodes) {
    // Once error is set, subsequent decodes should also fail
    auto s = State::for_decode(nullptr, 0);
    Uint::decode(s);
    EXPECT_TRUE(s.error);

    // Subsequent calls should return defaults without crashing
    auto v = Uint::decode(s);
    EXPECT_EQ(v, 0);
    EXPECT_TRUE(s.error);

    auto b = Bool::decode(s);
    EXPECT_EQ(b, false);
    EXPECT_TRUE(s.error);
}

TEST(Error, EncodeOverflow) {
    // Buffer too small
    uint8_t tiny[1];
    State s;
    s.buffer = tiny;
    s.end = 1;
    Uint::encode(s, 0xFFFF);  // needs 3 bytes
    EXPECT_TRUE(s.error);
}
