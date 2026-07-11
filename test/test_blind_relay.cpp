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

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "hyperdht/blind_relay.hpp"
#include "hyperdht/dht.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/protomux.hpp"
#include "hyperdht/udx.hpp"

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
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->is_initiator);
    EXPECT_EQ(decoded->token, msg.token);
    EXPECT_EQ(decoded->id, 42u);
    EXPECT_EQ(decoded->seq, 0u);
}

TEST(BlindRelayPair, EncodeDecodeNonInitiator) {
    PairMessage msg;
    msg.is_initiator = false;
    msg.token.fill(0xBB);
    msg.id = 9999;
    msg.seq = 0;

    auto encoded = encode_pair(msg);
    auto decoded = decode_pair(encoded.data(), encoded.size());

    ASSERT_TRUE(decoded.has_value());
    EXPECT_FALSE(decoded->is_initiator);
    EXPECT_EQ(decoded->token, msg.token);
    EXPECT_EQ(decoded->id, 9999u);
    EXPECT_EQ(decoded->seq, 0u);
}

TEST(BlindRelayPair, EncodeDecodeLargeId) {
    PairMessage msg;
    msg.is_initiator = true;
    msg.token.fill(0x11);
    msg.id = 0xFFFFFFFF;
    msg.seq = 0;

    auto encoded = encode_pair(msg);
    auto decoded = decode_pair(encoded.data(), encoded.size());

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->id, 0xFFFFFFFFu);
}

TEST(BlindRelayPair, DecodeEmptyBuffer) {
    // Truncated/empty buffer must signal failure (nullopt), not a zero struct —
    // JS decode throws here, tearing the connection down (finding blind-relay-6).
    auto decoded = decode_pair(nullptr, 0);
    EXPECT_FALSE(decoded.has_value());
}

TEST(BlindRelayPair, DecodeTruncatedBuffer) {
    // Only flags byte, no token → nullopt.
    uint8_t buf[1] = {1};
    auto decoded = decode_pair(buf, 1);
    EXPECT_FALSE(decoded.has_value());
}

TEST(BlindRelayPair, DecodeTruncatedMissingSeq) {
    // flags + token + id but no seq → nullopt (all four fields required).
    std::vector<uint8_t> data;
    data.push_back(0x01);
    for (uint8_t i = 1; i <= 32; i++) data.push_back(i);
    data.push_back(42);  // id, but no seq byte
    auto decoded = decode_pair(data.data(), data.size());
    EXPECT_FALSE(decoded.has_value());
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
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->token, msg.token);
}

TEST(BlindRelayUnpair, DecodeEmptyBuffer) {
    // Truncated → nullopt (finding blind-relay-6).
    auto decoded = decode_unpair(nullptr, 0);
    EXPECT_FALSE(decoded.has_value());
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
    BlindRelayServer server(
        [&streams_created](udx_stream_close_cb, void*) -> udx_stream_t* {
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
    BlindRelayServer server(
        [](udx_stream_close_cb, void*) -> udx_stream_t* { return nullptr; });

    Token token;
    token.fill(0xBB);

    server.get_or_create_pair(token);
    server.remove_pair(token);

    // Creating again should give a fresh pair
    auto& pair = server.get_or_create_pair(token);
    EXPECT_FALSE(pair.paired());
}

TEST(BlindRelayServer, RemovePairByKey) {
    BlindRelayServer server(
        [](udx_stream_close_cb, void*) -> udx_stream_t* { return nullptr; });

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

// JS: connect.js:842-848 — selectRelay() precedence + shape coverage.
TEST(ConnectOptions, SelectRelayThroughNone) {
    ConnectOptions opts;
    EXPECT_FALSE(opts.select_relay_through().has_value());
}

TEST(ConnectOptions, SelectRelayThroughSingleKey) {
    ConnectOptions opts;
    noise::PubKey pk;
    pk.fill(0x11);
    opts.relay_through = pk;

    auto sel = opts.select_relay_through();
    ASSERT_TRUE(sel.has_value());
    EXPECT_EQ(*sel, pk);
}

TEST(ConnectOptions, SelectRelayThroughArrayDeterministic) {
    ConnectOptions opts;
    noise::PubKey a, b, c;
    a.fill(0xAA); b.fill(0xBB); c.fill(0xCC);
    opts.relay_through_array = {a, b, c};

    // Deterministic PRNG — always returns 1 → picks element 1 % 3 = 1 (b).
    auto sel = opts.select_relay_through(+[]() -> uint64_t { return 1; });
    ASSERT_TRUE(sel.has_value());
    EXPECT_EQ(*sel, b);

    // Returns 5 → 5 % 3 = 2 (c).
    auto sel2 = opts.select_relay_through(+[]() -> uint64_t { return 5; });
    ASSERT_TRUE(sel2.has_value());
    EXPECT_EQ(*sel2, c);
}

TEST(ConnectOptions, SelectRelayThroughFunctionWinsOverArrayAndSingle) {
    // JS order: function → array → single. Function output should win
    // even if the other two fields are populated.
    ConnectOptions opts;
    noise::PubKey fn_pk, array_pk, single_pk;
    fn_pk.fill(0x11);
    array_pk.fill(0x22);
    single_pk.fill(0x33);

    opts.relay_through_fn = [fn_pk]() -> std::optional<noise::PubKey> {
        return fn_pk;
    };
    opts.relay_through_array = {array_pk};
    opts.relay_through = single_pk;

    auto sel = opts.select_relay_through();
    ASSERT_TRUE(sel.has_value());
    EXPECT_EQ(*sel, fn_pk);
}

TEST(ConnectOptions, SelectRelayThroughFunctionReturnsNull) {
    // JS: `if (relayThrough === null) return null` — a function that
    // returns nullopt disables the relay entirely (array/single ignored).
    ConnectOptions opts;
    noise::PubKey array_pk;
    array_pk.fill(0x22);
    opts.relay_through_fn = []() -> std::optional<noise::PubKey> {
        return std::nullopt;
    };
    opts.relay_through_array = {array_pk};

    EXPECT_FALSE(opts.select_relay_through().has_value());
}

TEST(ConnectOptions, SelectRelayThroughArrayWinsOverSingle) {
    ConnectOptions opts;
    noise::PubKey array_pk, single_pk;
    array_pk.fill(0x22);
    single_pk.fill(0x33);
    opts.relay_through_array = {array_pk};
    opts.relay_through = single_pk;

    auto sel = opts.select_relay_through(+[]() -> uint64_t { return 0; });
    ASSERT_TRUE(sel.has_value());
    EXPECT_EQ(*sel, array_pk);
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
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->is_initiator);
    for (int i = 0; i < 32; i++) {
        EXPECT_EQ(decoded->token[i], static_cast<uint8_t>(i + 1));
    }
    EXPECT_EQ(decoded->id, 42u);
    EXPECT_EQ(decoded->seq, 0u);
}

TEST(BlindRelayUnpair, DecodeKnownVector) {
    // flags=0x00 (empty)
    // token=all 0xFF
    std::vector<uint8_t> data;
    data.push_back(0x00);
    for (int i = 0; i < 32; i++) data.push_back(0xFF);

    auto decoded = decode_unpair(data.data(), data.size());
    ASSERT_TRUE(decoded.has_value());
    Token expected;
    expected.fill(0xFF);
    EXPECT_EQ(decoded->token, expected);
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

// ===========================================================================
// finding blind-relay-1 — end-to-end relay DATA over real udx sockets.
//
// Two peers each connect a raw stream to a relay stream id; the relay streams
// learn each peer's UDP source via relay_firewall_cb (connect-on-first-packet,
// return 0 = accept + relay). Bytes written on peer A arrive at peer B and
// vice-versa — the real proof that the firewall/connect wiring works.
// ===========================================================================

namespace {

struct RelayData {
    std::string a_recv;   // bytes peer A received (originated by B)
    std::string b_recv;   // bytes peer B received (originated by A)
    int peers_closed = 0;
    int relays_closed = 0;
    hyperdht::udx::UdxSocket* sockA = nullptr;
    hyperdht::udx::UdxSocket* sockR = nullptr;
    hyperdht::udx::UdxSocket* sockB = nullptr;
    hyperdht::udx::UdxStream* relayA = nullptr;
    hyperdht::udx::UdxStream* relayB = nullptr;
};

RelayData* g_rd = nullptr;

sockaddr_in rd_loopback(uint16_t port) {
    sockaddr_in a{};
    uv_ip4_addr("127.0.0.1", port, &a);
    return a;
}

sockaddr_in rd_bound(hyperdht::udx::UdxSocket& s) {
    sockaddr_in a{};
    int len = sizeof(a);
    s.getsockname(reinterpret_cast<sockaddr*>(&a), &len);
    return a;
}

void rd_on_read_a(udx_stream_t*, ssize_t n, const uv_buf_t* buf) {
    if (n > 0) g_rd->a_recv.append(buf->base, static_cast<size_t>(n));
}
void rd_on_read_b(udx_stream_t*, ssize_t n, const uv_buf_t* buf) {
    if (n > 0) g_rd->b_recv.append(buf->base, static_cast<size_t>(n));
}

void rd_on_relay_close(udx_stream_t* s, int) {
    // The relay stream carries a heap RelayStreamCtx (as production would).
    delete static_cast<RelayStreamCtx*>(s->data);
    s->data = nullptr;
    if (++g_rd->relays_closed == 2) {
        g_rd->sockA->close();
        g_rd->sockR->close();
        g_rd->sockB->close();
    }
}

void rd_on_peer_close(udx_stream_t*, int) {
    // Once both peer streams have fully closed (mutual write_end), tear down
    // the relay streams so the loop can drain.
    if (++g_rd->peers_closed == 2) {
        g_rd->relayA->destroy();
        g_rd->relayB->destroy();
    }
}

}  // namespace

TEST(BlindRelayData, RelaysBytesThroughFirewallConnect) {
    using namespace hyperdht::udx;

    uv_loop_t loop;
    uv_loop_init(&loop);
    Udx udx(&loop);

    UdxSocket sockA(udx), sockR(udx), sockB(udx);
    auto a0 = rd_loopback(0), r0 = rd_loopback(0), b0 = rd_loopback(0);
    ASSERT_EQ(sockA.bind(reinterpret_cast<sockaddr*>(&a0)), 0);
    ASSERT_EQ(sockR.bind(reinterpret_cast<sockaddr*>(&r0)), 0);
    ASSERT_EQ(sockB.bind(reinterpret_cast<sockaddr*>(&b0)), 0);
    auto relay_addr = rd_bound(sockR);

    // Relay streams (ids 100/200). Each carries a ctx with the PEER's stream id
    // so relay_firewall_cb connects it back to that peer, then relays.
    auto* ctxA = new RelayStreamCtx{};
    ctxA->remote_id = 1;  // peer A's stream id
    auto* ctxB = new RelayStreamCtx{};
    ctxB->remote_id = 2;  // peer B's stream id

    UdxStream relayA(udx, 100, rd_on_relay_close, nullptr);
    UdxStream relayB(udx, 200, rd_on_relay_close, nullptr);
    relayA.handle()->data = ctxA;
    relayB.handle()->data = ctxB;
    ASSERT_EQ(relayA.firewall(relay_firewall_cb), 0);
    ASSERT_EQ(relayB.firewall(relay_firewall_cb), 0);
    ASSERT_EQ(relayA.relay_to(relayB), 0);
    ASSERT_EQ(relayB.relay_to(relayA), 0);

    // Peer streams (ids 1/2), each connected to its relay stream id.
    UdxStream peerA(udx, 1, rd_on_peer_close, nullptr);
    UdxStream peerB(udx, 2, rd_on_peer_close, nullptr);
    ASSERT_EQ(peerA.connect(sockA, 100, reinterpret_cast<sockaddr*>(&relay_addr)), 0);
    ASSERT_EQ(peerB.connect(sockB, 200, reinterpret_cast<sockaddr*>(&relay_addr)), 0);
    ASSERT_EQ(peerA.read_start(rd_on_read_a), 0);
    ASSERT_EQ(peerB.read_start(rd_on_read_b), 0);

    RelayData rd;
    rd.sockA = &sockA;
    rd.sockR = &sockR;
    rd.sockB = &sockB;
    rd.relayA = &relayA;
    rd.relayB = &relayB;
    g_rd = &rd;

    // Write in both directions, then signal end-of-writes.
    std::string mA = "A2B", mB = "B2A";
    uv_buf_t bufA = uv_buf_init(mA.data(), 3);
    uv_buf_t bufB = uv_buf_init(mB.data(), 3);
    auto* wA = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
    auto* wB = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
    auto* eA = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
    auto* eB = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
    ASSERT_GE(peerA.write(wA, &bufA, 1, nullptr), 0);
    ASSERT_GE(peerB.write(wB, &bufB, 1, nullptr), 0);
    ASSERT_GE(peerA.write_end(eA, nullptr, 0, nullptr), 0);
    ASSERT_GE(peerB.write_end(eB, nullptr, 0, nullptr), 0);

    ASSERT_EQ(uv_run(&loop, UV_RUN_DEFAULT), 0);

    EXPECT_EQ(rd.b_recv, "A2B");  // A → relay → B
    EXPECT_EQ(rd.a_recv, "B2A");  // B → relay → A
    EXPECT_EQ(rd.peers_closed, 2);
    EXPECT_EQ(rd.relays_closed, 2);

    free(wA);
    free(wB);
    free(eA);
    free(eB);
    g_rd = nullptr;
    ASSERT_EQ(uv_loop_close(&loop), 0);
}

// ===========================================================================
// finding blind-relay-5 — the client ignores an inbound unpair.
// A relay that (mis)sends an unpair to a client with a pending request must
// NOT cancel that request (JS registers unpair for sending only).
// ===========================================================================

TEST(BlindRelayClient, InboundUnpairIsIgnored) {
    MuxPair mux;
    auto* chA = mux.mux_a.create_channel(PROTOCOL_NAME);
    BlindRelayClient client(chA);
    client.open();

    // Bare peer channel on the other side, paired with the client channel.
    auto* chB = mux.mux_b.create_channel(PROTOCOL_NAME);
    chB->open();
    mux.flush();

    Token token;
    token.fill(0x42);
    bool err_fired = false;
    bool paired = false;
    client.pair(true, token, 100,
                [&](uint32_t) { paired = true; },
                [&](int) { err_fired = true; });
    mux.flush();

    // Peer sends an inbound unpair (message index 1) for the pending token.
    UnpairMessage um;
    um.token = token;
    auto enc = encode_unpair(um);
    ASSERT_TRUE(chB->send(1, enc.data(), enc.size()));
    mux.flush();

    EXPECT_FALSE(err_fired);  // request NOT cancelled
    EXPECT_FALSE(paired);     // and not spuriously paired
}

// ===========================================================================
// finding blind-relay-6 — a truncated pair message tears the session down
// instead of pairing a zero token.
// ===========================================================================

TEST(BlindRelaySession, TruncatedPairTearsDown) {
    MuxPair mux;
    BlindRelayServer server(
        [](udx_stream_close_cb, void*) -> udx_stream_t* { return nullptr; });

    auto* session = server.accept(&mux.mux_b);
    ASSERT_NE(session, nullptr);

    auto* chA = mux.mux_a.create_channel(PROTOCOL_NAME);
    chA->open();
    mux.flush();
    ASSERT_FALSE(session->is_closed());

    // Pair message (index 0) with only the flags byte — no token/id/seq.
    uint8_t truncated[1] = {0x01};
    ASSERT_TRUE(chA->send(0, truncated, sizeof(truncated)));
    mux.flush();

    EXPECT_TRUE(session->is_closed());  // torn down, not paired
}

// ===========================================================================
// finding blind-relay-3 — graceful close drains an in-flight pairing.
// server.close() with a session mid-pairing must NOT destroy it immediately;
// on_closed fires only once the pairing resolves (here via unpair).
// ===========================================================================

TEST(BlindRelayServer, GracefulCloseDrainsInFlightPairing) {
    MuxPair mux;
    BlindRelayServer server(
        [](udx_stream_close_cb, void*) -> udx_stream_t* { return nullptr; });
    bool closed_fired = false;
    server.on_closed = [&]() { closed_fired = true; };

    auto* chA = mux.mux_a.create_channel(PROTOCOL_NAME);
    BlindRelayClient client(chA);
    client.open();
    auto* session = server.accept(&mux.mux_b);
    ASSERT_NE(session, nullptr);
    mux.flush();

    Token token;
    token.fill(0x77);
    client.pair(true, token, 100, [](uint32_t) {}, [](int) {});
    mux.flush();  // session now has an in-flight (unmatched) pairing

    // Graceful close: the in-flight session must keep draining, not vanish.
    server.close();
    EXPECT_FALSE(closed_fired);

    // Resolve the pairing → the session ends → last session gone → on_closed.
    client.unpair(token);
    mux.flush();
    EXPECT_TRUE(closed_fired);
}

// ===========================================================================
// finding blind-relay-2 — the pair confirmation is sent BEFORE a pending-close
// session's channel closes. A session that end()s while its pairing is in
// flight must still deliver its confirmation to its client.
// ===========================================================================

TEST(BlindRelayServer, ConfirmationSentBeforeSessionCloses) {
    using namespace hyperdht::udx;

    uv_loop_t loop;
    uv_loop_init(&loop);
    Udx udx(&loop);

    // Real relay streams handed out by the factory (one pairing → two streams).
    udx_stream_t s0{}, s1{};
    udx_stream_t* slots[2] = {&s0, &s1};
    int handed = 0;

    // muxes declared BEFORE server so the server (and its sessions) destruct
    // first — sessions reference channels the muxes own.
    MuxPair mpA, mpB;

    BlindRelayServer server(
        [&](udx_stream_close_cb cb, void* ud) -> udx_stream_t* {
            if (handed >= 2) return nullptr;
            udx_stream_t* s = slots[handed++];
            udx_stream_init(udx.handle(), s, 1000u + handed, cb, nullptr);
            s->data = ud;
            return s;
        });

    auto* chA = mpA.mux_a.create_channel(PROTOCOL_NAME);
    auto* chB = mpB.mux_a.create_channel(PROTOCOL_NAME);
    BlindRelayClient clientA(chA), clientB(chB);
    clientA.open();
    clientB.open();
    auto* sessionA = server.accept(&mpA.mux_b);
    auto* sessionB = server.accept(&mpB.mux_b);
    ASSERT_NE(sessionA, nullptr);
    ASSERT_NE(sessionB, nullptr);
    mpA.flush();
    mpB.flush();

    Token token;
    token.fill(0x33);
    bool paired_a = false, paired_b = false;

    // Client A pairs as INITIATOR (→ pair.links[1], processed last in pass 3,
    // so its endMaybe close cascade doesn't disturb B's earlier confirmation).
    clientA.pair(true, token, 10, [&](uint32_t) { paired_a = true; }, nullptr);
    mpA.flush();  // sessionA in-flight

    // sessionA ends while its pairing is in flight (pending_close_).
    sessionA->close();

    clientB.pair(false, token, 20, [&](uint32_t) { paired_b = true; }, nullptr);
    mpB.flush();  // sessionB matches → confirmations sent

    mpA.flush();  // deliver sessionA's confirmation to client A
    mpB.flush();  // deliver sessionB's confirmation to client B

    EXPECT_TRUE(paired_a);  // finding-2: confirmation not dropped on close
    EXPECT_TRUE(paired_b);

    // Teardown: make sure both relay streams are destroyed, then drain.
    udx_stream_destroy(&s0);
    udx_stream_destroy(&s1);
    uv_run(&loop, UV_RUN_DEFAULT);
    ASSERT_EQ(uv_loop_close(&loop), 0);
}
