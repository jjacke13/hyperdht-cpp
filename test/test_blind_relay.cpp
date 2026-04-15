// Blind relay unit tests — message encoding, token generation,
// BlindRelayClient, BlindRelayServer pairing flow.
//
// Tests the core blind-relay logic without a real network:
// - Pair/Unpair message encode/decode round-trip
// - Token generation (32 bytes, random)
// - BlindRelayClient pair/unpair over loopback Protomux
// - BlindRelayServer/Session token matching and relay setup
// - ConnectOptions relay field defaults

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "hyperdht/blind_relay.hpp"
#include "hyperdht/dht.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/protomux.hpp"

using namespace hyperdht;
using namespace hyperdht::blind_relay;

// ===========================================================================
// Pair message encoding/decoding
// ===========================================================================

TEST(BlindRelayPair, EncodeDecodeRoundTrip) {
    PairMessage msg;
    msg.is_initiator = true;
    msg.token.fill(0xAA);
    msg.id = 42;
    msg.seq = 0;

    auto encoded = encode_pair(msg);
    ASSERT_GT(encoded.size(), 33u);  // flags(1) + token(32) + id + seq

    auto decoded = decode_pair(encoded.data(), encoded.size());
    EXPECT_TRUE(decoded.is_initiator);
    EXPECT_EQ(decoded.token, msg.token);
    EXPECT_EQ(decoded.id, 42u);
    EXPECT_EQ(decoded.seq, 0u);
}

TEST(BlindRelayPair, EncodeDecodeNonInitiator) {
    PairMessage msg;
    msg.is_initiator = false;
    msg.token.fill(0xBB);
    msg.id = 9999;
    msg.seq = 0;

    auto encoded = encode_pair(msg);
    auto decoded = decode_pair(encoded.data(), encoded.size());

    EXPECT_FALSE(decoded.is_initiator);
    EXPECT_EQ(decoded.token, msg.token);
    EXPECT_EQ(decoded.id, 9999u);
    EXPECT_EQ(decoded.seq, 0u);
}

TEST(BlindRelayPair, EncodeDecodeLargeId) {
    PairMessage msg;
    msg.is_initiator = true;
    msg.token.fill(0x11);
    msg.id = 0xFFFFFFFF;
    msg.seq = 0;

    auto encoded = encode_pair(msg);
    auto decoded = decode_pair(encoded.data(), encoded.size());

    EXPECT_EQ(decoded.id, 0xFFFFFFFFu);
}

TEST(BlindRelayPair, DecodeEmptyBuffer) {
    PairMessage decoded = decode_pair(nullptr, 0);
    // Should return default values without crashing
    EXPECT_FALSE(decoded.is_initiator);
    EXPECT_EQ(decoded.id, 0u);
}

TEST(BlindRelayPair, DecodeTruncatedBuffer) {
    // Only flags byte, no token
    uint8_t buf[1] = {1};
    PairMessage decoded = decode_pair(buf, 1);
    EXPECT_TRUE(decoded.is_initiator);
    // Token should be zeros (not enough data)
}

// ===========================================================================
// Unpair message encoding/decoding
// ===========================================================================

TEST(BlindRelayUnpair, EncodeDecodeRoundTrip) {
    UnpairMessage msg;
    msg.token.fill(0xCC);

    auto encoded = encode_unpair(msg);
    EXPECT_EQ(encoded.size(), 33u);  // flags(1) + token(32)

    auto decoded = decode_unpair(encoded.data(), encoded.size());
    EXPECT_EQ(decoded.token, msg.token);
}

TEST(BlindRelayUnpair, DecodeEmptyBuffer) {
    UnpairMessage decoded = decode_unpair(nullptr, 0);
    Token zero{};
    EXPECT_EQ(decoded.token, zero);
}

// ===========================================================================
// Token generation
// ===========================================================================

TEST(BlindRelayToken, GenerateReturns32Bytes) {
    Token t = generate_token();
    // Should not be all zeros (astronomically unlikely for 32 random bytes)
    Token zero{};
    EXPECT_NE(t, zero);
}

TEST(BlindRelayToken, GenerateUniqueness) {
    Token t1 = generate_token();
    Token t2 = generate_token();
    EXPECT_NE(t1, t2);
}

TEST(BlindRelayToken, HexConversion) {
    Token t{};
    t[0] = 0xDE;
    t[1] = 0xAD;
    t[31] = 0xFF;

    auto hex = token_hex(t);
    EXPECT_EQ(hex.size(), 64u);
    EXPECT_EQ(hex.substr(0, 4), "dead");
    EXPECT_EQ(hex.substr(62, 2), "ff");
}

TEST(BlindRelayToken, HexAllZeros) {
    Token t{};
    auto hex = token_hex(t);
    EXPECT_EQ(hex, std::string(64, '0'));
}

// ===========================================================================
// BlindRelayClient — unit tests with mock Protomux
// ===========================================================================

// Helper: creates a Mux pair connected by captured frames
struct MuxPair {
    std::vector<std::vector<uint8_t>> a_to_b;
    std::vector<std::vector<uint8_t>> b_to_a;

    protomux::Mux mux_a{[this](const uint8_t* data, size_t len) -> bool {
        a_to_b.emplace_back(data, data + len);
        return true;
    }};
    protomux::Mux mux_b{[this](const uint8_t* data, size_t len) -> bool {
        b_to_a.emplace_back(data, data + len);
        return true;
    }};

    // Deliver all pending frames in both directions
    void flush() {
        // Flush a→b
        auto pending_ab = std::move(a_to_b);
        a_to_b.clear();
        for (auto& frame : pending_ab) {
            mux_b.on_data(frame.data(), frame.size());
        }
        // Flush b→a
        auto pending_ba = std::move(b_to_a);
        b_to_a.clear();
        for (auto& frame : pending_ba) {
            mux_a.on_data(frame.data(), frame.size());
        }
    }
};

TEST(BlindRelayClient, CreateAndOpen) {
    MuxPair mux;
    auto* ch = mux.mux_a.create_channel(PROTOCOL_NAME);
    ASSERT_NE(ch, nullptr);

    BlindRelayClient client(ch);
    EXPECT_FALSE(client.is_closed());
    EXPECT_FALSE(client.is_destroyed());

    client.open();
    EXPECT_FALSE(client.is_closed());
}

TEST(BlindRelayClient, PairSendsMessage) {
    MuxPair mux;
    auto* ch = mux.mux_a.create_channel(PROTOCOL_NAME);
    BlindRelayClient client(ch);
    client.open();

    Token token;
    token.fill(0x42);
    bool paired = false;
    client.pair(true, token, 100,
                [&paired](uint32_t remote_id) { paired = true; },
                nullptr);

    // The pair message should have been written to the mux
    EXPECT_FALSE(mux.a_to_b.empty());
}

TEST(BlindRelayClient, DuplicatePairFails) {
    MuxPair mux;
    auto* ch = mux.mux_a.create_channel(PROTOCOL_NAME);
    BlindRelayClient client(ch);
    client.open();

    Token token;
    token.fill(0x42);

    int error_code = 0;
    client.pair(true, token, 100, [](uint32_t) {}, nullptr);
    client.pair(true, token, 200, [](uint32_t) {},
                [&error_code](int err) { error_code = err; });

    EXPECT_EQ(error_code, RelayError::ALREADY_PAIRING);
}

TEST(BlindRelayClient, UnpairCancelsPending) {
    MuxPair mux;
    auto* ch = mux.mux_a.create_channel(PROTOCOL_NAME);
    BlindRelayClient client(ch);
    client.open();

    Token token;
    token.fill(0x42);
    int error_code = 0;
    client.pair(true, token, 100, [](uint32_t) {},
                [&error_code](int err) { error_code = err; });

    client.unpair(token);
    EXPECT_EQ(error_code, RelayError::PAIRING_CANCELLED);
}

TEST(BlindRelayClient, DestroyFailsAllPending) {
    MuxPair mux;
    auto* ch = mux.mux_a.create_channel(PROTOCOL_NAME);
    BlindRelayClient client(ch);
    client.open();

    Token t1, t2;
    t1.fill(0x11);
    t2.fill(0x22);

    int err1 = 0, err2 = 0;
    client.pair(true, t1, 1, [](uint32_t) {},
                [&err1](int e) { err1 = e; });
    client.pair(false, t2, 2, [](uint32_t) {},
                [&err2](int e) { err2 = e; });

    client.destroy();
    EXPECT_NE(err1, 0);
    EXPECT_NE(err2, 0);
    EXPECT_TRUE(client.is_destroyed());
}

TEST(BlindRelayClient, PairAfterDestroyFails) {
    MuxPair mux;
    auto* ch = mux.mux_a.create_channel(PROTOCOL_NAME);
    BlindRelayClient client(ch);
    client.open();
    client.destroy();

    Token token;
    token.fill(0x42);
    int error_code = 0;
    client.pair(true, token, 100, [](uint32_t) {},
                [&error_code](int err) { error_code = err; });

    EXPECT_EQ(error_code, RelayError::CHANNEL_DESTROYED);
}

// ===========================================================================
// BlindRelayServer — pairing and relay setup
// ===========================================================================

TEST(BlindRelayServer, CreateAndAccept) {
    int streams_created = 0;
    BlindRelayServer server([&streams_created]() -> udx_stream_t* {
        streams_created++;
        return nullptr;  // Can't create real streams without libuv
    });

    // Without a real Mux we can't fully test accept(), but we can test
    // the pairing data structures directly.
    Token token;
    token.fill(0xAA);

    auto& pair = server.get_or_create_pair(token);
    EXPECT_FALSE(pair.paired());
    EXPECT_FALSE(pair.has(true));
    EXPECT_FALSE(pair.has(false));

    // Simulate initiator arriving
    pair.links[1].session = reinterpret_cast<BlindRelaySession*>(0x1);  // mock
    pair.links[1].is_initiator = true;
    pair.links[1].remote_id = 42;

    EXPECT_TRUE(pair.has(true));
    EXPECT_FALSE(pair.has(false));
    EXPECT_FALSE(pair.paired());

    // Simulate non-initiator arriving
    pair.links[0].session = reinterpret_cast<BlindRelaySession*>(0x2);  // mock
    pair.links[0].is_initiator = false;
    pair.links[0].remote_id = 99;

    EXPECT_TRUE(pair.has(false));
    EXPECT_TRUE(pair.paired());

    // Remote lookup
    EXPECT_EQ(pair.remote(true).remote_id, 99u);   // initiator's remote = non-init
    EXPECT_EQ(pair.remote(false).remote_id, 42u);   // non-init's remote = initiator
}

TEST(BlindRelayServer, RemovePair) {
    BlindRelayServer server([]() -> udx_stream_t* { return nullptr; });

    Token token;
    token.fill(0xBB);

    server.get_or_create_pair(token);
    server.remove_pair(token);

    // Creating again should give a fresh pair
    auto& pair = server.get_or_create_pair(token);
    EXPECT_FALSE(pair.paired());
}

TEST(BlindRelayServer, RemovePairByKey) {
    BlindRelayServer server([]() -> udx_stream_t* { return nullptr; });

    Token token;
    token.fill(0xCC);
    auto key = token_hex(token);

    server.get_or_create_pair(token);
    server.remove_pair_by_key(key);

    // Fresh pair
    auto& pair = server.get_or_create_pair(token);
    EXPECT_FALSE(pair.paired());
}

// ===========================================================================
// ConnectOptions relay field defaults
// ===========================================================================

TEST(ConnectOptions, RelayThroughDefaultEmpty) {
    ConnectOptions opts;
    EXPECT_FALSE(opts.relay_through.has_value());
    EXPECT_EQ(opts.relay_keep_alive, 5000u);

    Token zero{};
    EXPECT_EQ(opts.relay_token, zero);
}

TEST(ConnectOptions, RelayThroughSet) {
    ConnectOptions opts;
    noise::PubKey pk;
    pk.fill(0xFF);
    opts.relay_through = pk;
    opts.relay_keep_alive = 10000;

    EXPECT_TRUE(opts.relay_through.has_value());
    EXPECT_EQ(*opts.relay_through, pk);
    EXPECT_EQ(opts.relay_keep_alive, 10000u);
}

// ===========================================================================
// Stats — relay stats type
// ===========================================================================

TEST(RelayingStats, DefaultZero) {
    HyperDHT::RelayingStats stats;
    EXPECT_EQ(stats.attempts, 0);
    EXPECT_EQ(stats.successes, 0);
    EXPECT_EQ(stats.aborts, 0);
}

TEST(RelayingStats, Increment) {
    HyperDHT::RelayingStats stats;
    stats.attempts++;
    stats.successes++;
    stats.aborts++;
    EXPECT_EQ(stats.attempts, 1);
    EXPECT_EQ(stats.successes, 1);
    EXPECT_EQ(stats.aborts, 1);
}

// ===========================================================================
// Server relay_through field
// ===========================================================================

TEST(ServerRelay, DefaultEmpty) {
    // Can't instantiate Server without RpcSocket, but we can check
    // the field types compile correctly via ConnectOptions
    ConnectOptions opts;
    EXPECT_FALSE(opts.relay_through.has_value());
}

// ===========================================================================
// Pair message wire format validation
// ===========================================================================

TEST(BlindRelayPair, WireFormatFlagsByte) {
    PairMessage msg;
    msg.is_initiator = true;
    msg.token.fill(0x00);
    msg.id = 1;
    msg.seq = 0;

    auto encoded = encode_pair(msg);
    EXPECT_EQ(encoded[0], 1);  // flags byte: bit 0 set = isInitiator

    msg.is_initiator = false;
    encoded = encode_pair(msg);
    EXPECT_EQ(encoded[0], 0);  // flags byte: bit 0 clear
}

TEST(BlindRelayPair, WireFormatTokenPosition) {
    PairMessage msg;
    msg.is_initiator = false;
    msg.token.fill(0xDE);
    msg.id = 0;
    msg.seq = 0;

    auto encoded = encode_pair(msg);
    // Token starts at byte 1 (after flags)
    for (int i = 1; i <= 32; i++) {
        EXPECT_EQ(encoded[i], 0xDE) << "Mismatch at byte " << i;
    }
}

TEST(BlindRelayUnpair, WireFormatFlagsByte) {
    UnpairMessage msg;
    msg.token.fill(0x00);

    auto encoded = encode_unpair(msg);
    EXPECT_EQ(encoded[0], 0);  // empty flags byte
}

// ===========================================================================
// Cross-decode: verify C++ can decode what JS would send
// ===========================================================================

TEST(BlindRelayPair, DecodeKnownVector) {
    // Construct a known Pair message manually:
    // flags=0x01 (isInitiator=true)
    // token=0x0102...1f20 (32 sequential bytes)
    // id=42 (varint: 0x2A)
    // seq=0 (varint: 0x00)
    std::vector<uint8_t> data;
    data.push_back(0x01);  // flags: isInitiator=true
    for (uint8_t i = 1; i <= 32; i++) data.push_back(i);  // token
    data.push_back(42);    // id as varint
    data.push_back(0);     // seq as varint

    auto decoded = decode_pair(data.data(), data.size());
    EXPECT_TRUE(decoded.is_initiator);
    for (int i = 0; i < 32; i++) {
        EXPECT_EQ(decoded.token[i], static_cast<uint8_t>(i + 1));
    }
    EXPECT_EQ(decoded.id, 42u);
    EXPECT_EQ(decoded.seq, 0u);
}

TEST(BlindRelayUnpair, DecodeKnownVector) {
    // flags=0x00 (empty)
    // token=all 0xFF
    std::vector<uint8_t> data;
    data.push_back(0x00);
    for (int i = 0; i < 32; i++) data.push_back(0xFF);

    auto decoded = decode_unpair(data.data(), data.size());
    Token expected;
    expected.fill(0xFF);
    EXPECT_EQ(decoded.token, expected);
}

// ===========================================================================
// Constants
// ===========================================================================

TEST(BlindRelayConstants, ProtocolName) {
    EXPECT_STREQ(PROTOCOL_NAME, "blind-relay");
}

TEST(BlindRelayConstants, Timeouts) {
    EXPECT_EQ(RELAY_TIMEOUT_MS, 15000u);
    EXPECT_EQ(RELAY_KEEP_ALIVE_MS, 5000u);
}
