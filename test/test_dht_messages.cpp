#include <gtest/gtest.h>

#include <cstring>

#include <sodium.h>

#include "hyperdht/dht_messages.hpp"

using namespace hyperdht;
using namespace hyperdht::dht_messages;
using Ipv4Address = compact::Ipv4Address;

// ---------------------------------------------------------------------------
// Namespace hashes
// ---------------------------------------------------------------------------

TEST(DhtMessages, NamespaceHashesNonZero) {
    // Verify all NS hashes are computed (non-zero)
    auto zero = std::array<uint8_t, 32>{};
    EXPECT_NE(ns_announce(), zero);
    EXPECT_NE(ns_unannounce(), zero);
    EXPECT_NE(ns_mutable_put(), zero);
    EXPECT_NE(ns_peer_handshake(), zero);
    EXPECT_NE(ns_peer_holepunch(), zero);

    // All should be different
    EXPECT_NE(ns_announce(), ns_unannounce());
    EXPECT_NE(ns_announce(), ns_mutable_put());
    EXPECT_NE(ns_peer_handshake(), ns_peer_holepunch());
}

TEST(DhtMessages, NamespaceHashesDeterministic) {
    // Same call twice → same result
    EXPECT_EQ(ns_announce(), ns_announce());
    EXPECT_EQ(ns_unannounce(), ns_unannounce());
}

// ---------------------------------------------------------------------------
// PeerRecord
// ---------------------------------------------------------------------------

TEST(PeerRecord, RoundTrip) {
    PeerRecord p;
    p.public_key.fill(0x42);
    p.relay_addresses.push_back(Ipv4Address::from_string("1.2.3.4", 5000));
    p.relay_addresses.push_back(Ipv4Address::from_string("5.6.7.8", 6000));

    auto buf = encode_peer_record(p);
    auto decoded = decode_peer_record(buf.data(), buf.size());

    EXPECT_EQ(decoded.public_key, p.public_key);
    ASSERT_EQ(decoded.relay_addresses.size(), 2u);
    EXPECT_EQ(decoded.relay_addresses[0].host_string(), "1.2.3.4");
    EXPECT_EQ(decoded.relay_addresses[0].port, 5000u);
    EXPECT_EQ(decoded.relay_addresses[1].host_string(), "5.6.7.8");
    EXPECT_EQ(decoded.relay_addresses[1].port, 6000u);
}

TEST(PeerRecord, EmptyRelays) {
    PeerRecord p;
    p.public_key.fill(0xAA);

    auto buf = encode_peer_record(p);
    auto decoded = decode_peer_record(buf.data(), buf.size());

    EXPECT_EQ(decoded.public_key, p.public_key);
    EXPECT_TRUE(decoded.relay_addresses.empty());
}

// ---------------------------------------------------------------------------
// AnnounceMessage
// ---------------------------------------------------------------------------

TEST(AnnounceMessage, MinimalRoundTrip) {
    AnnounceMessage m;
    // No fields set — flags = 0

    auto buf = encode_announce_msg(m);
    EXPECT_EQ(buf.size(), 1u);  // Just the flags byte

    auto decoded = decode_announce_msg(buf.data(), buf.size());
    EXPECT_FALSE(decoded.peer.has_value());
    EXPECT_FALSE(decoded.refresh.has_value());
    EXPECT_FALSE(decoded.signature.has_value());
    EXPECT_EQ(decoded.bump, 0u);
}

TEST(AnnounceMessage, FullRoundTrip) {
    AnnounceMessage m;

    PeerRecord peer;
    peer.public_key.fill(0x42);
    peer.relay_addresses.push_back(Ipv4Address::from_string("10.0.0.1", 3000));
    m.peer = peer;

    std::array<uint8_t, 32> refresh{};
    refresh.fill(0xBB);
    m.refresh = refresh;

    std::array<uint8_t, 64> sig{};
    sig.fill(0xCC);
    m.signature = sig;

    m.bump = 1234567890;

    auto buf = encode_announce_msg(m);
    auto decoded = decode_announce_msg(buf.data(), buf.size());

    ASSERT_TRUE(decoded.peer.has_value());
    EXPECT_EQ(decoded.peer->public_key[0], 0x42);
    ASSERT_EQ(decoded.peer->relay_addresses.size(), 1u);
    EXPECT_EQ(decoded.peer->relay_addresses[0].port, 3000u);

    ASSERT_TRUE(decoded.refresh.has_value());
    EXPECT_EQ((*decoded.refresh)[0], 0xBB);

    ASSERT_TRUE(decoded.signature.has_value());
    EXPECT_EQ((*decoded.signature)[0], 0xCC);

    EXPECT_EQ(decoded.bump, 1234567890u);
}

TEST(AnnounceMessage, PeerOnly) {
    AnnounceMessage m;
    PeerRecord peer;
    peer.public_key.fill(0x11);
    m.peer = peer;

    auto buf = encode_announce_msg(m);
    auto decoded = decode_announce_msg(buf.data(), buf.size());

    ASSERT_TRUE(decoded.peer.has_value());
    EXPECT_EQ(decoded.peer->public_key[0], 0x11);
    EXPECT_FALSE(decoded.refresh.has_value());
    EXPECT_FALSE(decoded.signature.has_value());
    EXPECT_EQ(decoded.bump, 0u);
}

// ---------------------------------------------------------------------------
// MutablePutRequest
// ---------------------------------------------------------------------------

TEST(MutablePut, RoundTrip) {
    MutablePutRequest m;
    m.public_key.fill(0x42);
    m.seq = 42;
    m.value = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    m.signature.fill(0xDD);

    auto buf = encode_mutable_put(m);
    auto decoded = decode_mutable_put(buf.data(), buf.size());

    EXPECT_EQ(decoded.public_key, m.public_key);
    EXPECT_EQ(decoded.seq, 42u);
    EXPECT_EQ(decoded.value, m.value);
    EXPECT_EQ(decoded.signature, m.signature);
}

// ---------------------------------------------------------------------------
// MutableGetResponse
// ---------------------------------------------------------------------------

TEST(MutableGetResp, RoundTrip) {
    MutableGetResponse m;
    m.seq = 7;
    m.value = {1, 2, 3};
    m.signature.fill(0xEE);

    auto buf = encode_mutable_get_resp(m);
    auto decoded = decode_mutable_get_resp(buf.data(), buf.size());

    EXPECT_EQ(decoded.seq, 7u);
    EXPECT_EQ(decoded.value, m.value);
    EXPECT_EQ(decoded.signature, m.signature);
}

// ---------------------------------------------------------------------------
// MutableSignable
// ---------------------------------------------------------------------------

TEST(MutableSignable, Encoding) {
    auto buf = encode_mutable_signable(42, reinterpret_cast<const uint8_t*>("test"), 4);
    EXPECT_GT(buf.size(), 0u);

    // Should be deterministic
    auto buf2 = encode_mutable_signable(42, reinterpret_cast<const uint8_t*>("test"), 4);
    EXPECT_EQ(buf, buf2);
}

// ---------------------------------------------------------------------------
// LookupRawReply
// ---------------------------------------------------------------------------

TEST(LookupReply, RoundTrip) {
    LookupRawReply r;

    // Add two peer records as raw bytes
    PeerRecord p1;
    p1.public_key.fill(0x11);
    r.peers.push_back(encode_peer_record(p1));

    PeerRecord p2;
    p2.public_key.fill(0x22);
    p2.relay_addresses.push_back(Ipv4Address::from_string("1.2.3.4", 5000));
    r.peers.push_back(encode_peer_record(p2));

    r.bump = 999;

    auto buf = encode_lookup_reply(r);
    auto decoded = decode_lookup_reply(buf.data(), buf.size());

    ASSERT_EQ(decoded.peers.size(), 2u);
    EXPECT_EQ(decoded.bump, 999u);

    // Decode the first peer record
    auto dp1 = decode_peer_record(decoded.peers[0].data(), decoded.peers[0].size());
    EXPECT_EQ(dp1.public_key[0], 0x11);

    auto dp2 = decode_peer_record(decoded.peers[1].data(), decoded.peers[1].size());
    EXPECT_EQ(dp2.public_key[0], 0x22);
    ASSERT_EQ(dp2.relay_addresses.size(), 1u);
}

TEST(LookupReply, Empty) {
    LookupRawReply r;

    auto buf = encode_lookup_reply(r);
    auto decoded = decode_lookup_reply(buf.data(), buf.size());

    EXPECT_TRUE(decoded.peers.empty());
    EXPECT_EQ(decoded.bump, 0u);
}
