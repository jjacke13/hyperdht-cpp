#include <gtest/gtest.h>

#include <sodium.h>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/noise_wrap.hpp"

using namespace hyperdht;
using namespace hyperdht::announce_sig;
using namespace hyperdht::dht_messages;

// ---------------------------------------------------------------------------
// Announce signature
// ---------------------------------------------------------------------------

TEST(AnnounceSig, SignAndVerify) {
    // Generate a keypair
    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    target.fill(0x11);

    std::array<uint8_t, 32> node_id{};
    node_id.fill(0x22);

    std::array<uint8_t, 32> token{};
    token.fill(0x33);

    AnnounceMessage ann;
    PeerRecord peer;
    peer.public_key = kp.public_key;
    peer.relay_addresses.push_back(
        compact::Ipv4Address::from_string("1.2.3.4", 5000));
    ann.peer = peer;

    auto sig = sign_announce(target, node_id,
                             token.data(), token.size(),
                             ann, kp);

    // Verify with correct key → true
    EXPECT_TRUE(verify_announce(
        ns_announce(), target, node_id,
        token.data(), token.size(),
        ann, sig, kp.public_key));
}

TEST(AnnounceSig, WrongKeyFails) {
    noise::Seed seed1{};
    seed1.fill(0x42);
    auto kp1 = noise::generate_keypair(seed1);

    noise::Seed seed2{};
    seed2.fill(0x43);
    auto kp2 = noise::generate_keypair(seed2);

    std::array<uint8_t, 32> target{};
    std::array<uint8_t, 32> node_id{};
    std::array<uint8_t, 32> token{};

    AnnounceMessage ann;
    PeerRecord peer;
    peer.public_key = kp1.public_key;
    ann.peer = peer;

    auto sig = sign_announce(target, node_id,
                             token.data(), token.size(),
                             ann, kp1);

    // Verify with WRONG key → false
    EXPECT_FALSE(verify_announce(
        ns_announce(), target, node_id,
        token.data(), token.size(),
        ann, sig, kp2.public_key));
}

TEST(AnnounceSig, TamperedTargetFails) {
    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    target.fill(0x11);

    std::array<uint8_t, 32> node_id{};
    std::array<uint8_t, 32> token{};

    AnnounceMessage ann;
    PeerRecord peer;
    peer.public_key = kp.public_key;
    ann.peer = peer;

    auto sig = sign_announce(target, node_id,
                             token.data(), token.size(),
                             ann, kp);

    // Tamper with target
    std::array<uint8_t, 32> bad_target{};
    bad_target.fill(0xFF);

    EXPECT_FALSE(verify_announce(
        ns_announce(), bad_target, node_id,
        token.data(), token.size(),
        ann, sig, kp.public_key));
}

TEST(AnnounceSig, UnannounceUsesDifferentNS) {
    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    std::array<uint8_t, 32> node_id{};
    std::array<uint8_t, 32> token{};

    AnnounceMessage ann;
    PeerRecord peer;
    peer.public_key = kp.public_key;
    ann.peer = peer;

    auto sig_ann = sign_announce(target, node_id,
                                 token.data(), token.size(),
                                 ann, kp);

    auto sig_unann = sign_unannounce(target, node_id,
                                      token.data(), token.size(),
                                      ann, kp);

    // Different signatures (different namespace)
    EXPECT_NE(sig_ann, sig_unann);

    // Announce sig verifies with announce NS
    EXPECT_TRUE(verify_announce(
        ns_announce(), target, node_id,
        token.data(), token.size(),
        ann, sig_ann, kp.public_key));

    // Announce sig does NOT verify with unannounce NS
    EXPECT_FALSE(verify_announce(
        ns_unannounce(), target, node_id,
        token.data(), token.size(),
        ann, sig_ann, kp.public_key));

    // Unannounce sig verifies with unannounce NS
    EXPECT_TRUE(verify_announce(
        ns_unannounce(), target, node_id,
        token.data(), token.size(),
        ann, sig_unann, kp.public_key));
}

TEST(AnnounceSig, WithRefreshToken) {
    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    std::array<uint8_t, 32> target{};
    std::array<uint8_t, 32> node_id{};
    std::array<uint8_t, 32> token{};

    AnnounceMessage ann;
    PeerRecord peer;
    peer.public_key = kp.public_key;
    ann.peer = peer;

    std::array<uint8_t, 32> refresh{};
    refresh.fill(0xAA);
    ann.refresh = refresh;

    auto sig = sign_announce(target, node_id,
                             token.data(), token.size(),
                             ann, kp);

    EXPECT_TRUE(verify_announce(
        ns_announce(), target, node_id,
        token.data(), token.size(),
        ann, sig, kp.public_key));
}

// ---------------------------------------------------------------------------
// Mutable signature
// ---------------------------------------------------------------------------

TEST(MutableSig, SignAndVerify) {
    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    std::vector<uint8_t> value = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    uint64_t seq = 1;

    auto sig = sign_mutable(seq, value.data(), value.size(), kp);

    EXPECT_TRUE(verify_mutable(sig, seq, value.data(), value.size(),
                               kp.public_key));
}

TEST(MutableSig, WrongSeqFails) {
    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    std::vector<uint8_t> value = {1, 2, 3};
    auto sig = sign_mutable(1, value.data(), value.size(), kp);

    // Wrong seq → fails
    EXPECT_FALSE(verify_mutable(sig, 2, value.data(), value.size(),
                                kp.public_key));
}

TEST(MutableSig, WrongValueFails) {
    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    std::vector<uint8_t> value = {1, 2, 3};
    auto sig = sign_mutable(1, value.data(), value.size(), kp);

    std::vector<uint8_t> bad_value = {4, 5, 6};
    EXPECT_FALSE(verify_mutable(sig, 1, bad_value.data(), bad_value.size(),
                                kp.public_key));
}

TEST(MutableSig, Deterministic) {
    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    std::vector<uint8_t> value = {1, 2, 3};
    auto sig1 = sign_mutable(1, value.data(), value.size(), kp);
    auto sig2 = sign_mutable(1, value.data(), value.size(), kp);

    // Ed25519 is deterministic for same key+message
    EXPECT_EQ(sig1, sig2);
}
