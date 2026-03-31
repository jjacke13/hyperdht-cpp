#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <sodium.h>

#include "hyperdht/noise_wrap.hpp"

using namespace hyperdht::noise;

// ---------------------------------------------------------------------------
// Hex helper
// ---------------------------------------------------------------------------

static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        auto byte_str = hex.substr(i * 2, 2);
        out[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
    return out;
}

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(hex_chars[data[i] >> 4]);
        out.push_back(hex_chars[data[i] & 0x0F]);
    }
    return out;
}

template <size_t N>
static std::string to_hex(const std::array<uint8_t, N>& arr) {
    return to_hex(arr.data(), N);
}

static std::string to_hex(const std::vector<uint8_t>& v) {
    return to_hex(v.data(), v.size());
}

// ---------------------------------------------------------------------------
// BLAKE2b-512 — test against JS vector
// ---------------------------------------------------------------------------

TEST(NoiseBlake2b, MatchesJS) {
    auto h = blake2b_512(reinterpret_cast<const uint8_t*>("hello"), 5);
    EXPECT_EQ(to_hex(h),
        "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a6"
        "5ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94");
}

// ---------------------------------------------------------------------------
// HMAC-BLAKE2b — test against JS vector
// ---------------------------------------------------------------------------

TEST(NoiseHmac, MatchesJS) {
    // Key: 32 bytes of 0x42
    std::vector<uint8_t> key(32, 0x42);
    auto msg = std::string("test message");
    auto result = hmac_blake2b(key.data(), key.size(),
                               reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    EXPECT_EQ(to_hex(result),
        "58a20710507a4931ff0aa2f28f5165a6f1af673ff0ad7feab595919313f0b94f"
        "493a1010d700731ce042e7c5719e9ae8804628cc3891bafd1c72dd9cb0f7eb6f");
}

// ---------------------------------------------------------------------------
// HKDF — test against JS vector
// ---------------------------------------------------------------------------

TEST(NoiseHkdf, MatchesJS) {
    std::vector<uint8_t> salt(32, 0x11);
    std::vector<uint8_t> ikm(32, 0x22);
    auto [ck, k] = hkdf(salt.data(), salt.size(), ikm.data(), ikm.size());
    EXPECT_EQ(to_hex(ck),
        "37a233fb2b3c9d028e79ee72a0d452a8b9a31676e3d3b501a3963aa7c1a369d6"
        "5eb31bf8a40ac249a874d87cedfd2ed110cb1ab232f7e5fefc534bedad5df517");
    EXPECT_EQ(to_hex(k),
        "1495ca6d7b399bd8a77ad1fdbbaae63c7265f836ec4b354edea2db021520bcfe"
        "775ad29b1e2f7f9e9f201643a0eb8804f486e082a50e94873877cdaf55d28c10");
}

// ---------------------------------------------------------------------------
// Ed25519 keypair generation — test against JS vector
// ---------------------------------------------------------------------------

TEST(NoiseKeypair, MatchesJS) {
    Seed seed{};
    seed.fill(0x00);
    auto kp = generate_keypair(seed);
    EXPECT_EQ(to_hex(kp.public_key),
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    // SK = seed || pubkey
    EXPECT_EQ(to_hex(kp.secret_key),
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
}

// ---------------------------------------------------------------------------
// Ed25519 DH — test against JS vector
// ---------------------------------------------------------------------------

TEST(NoiseDH, MatchesJS) {
    Seed seed1{};
    seed1.fill(0x33);
    auto kp1 = generate_keypair(seed1);

    Seed seed2{};
    seed2.fill(0x44);
    auto kp2 = generate_keypair(seed2);

    EXPECT_EQ(to_hex(kp1.public_key),
        "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce");
    EXPECT_EQ(to_hex(kp2.public_key),
        "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48");

    auto dh12 = dh(kp1, kp2.public_key);
    auto dh21 = dh(kp2, kp1.public_key);

    EXPECT_EQ(to_hex(dh12),
        "2572797264060a08dfb5a49c0f662b0c8692f0865dad369c5e97c57f3f549733");
    EXPECT_EQ(dh12, dh21) << "DH should be symmetric";
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 — test against JS vectors
// ---------------------------------------------------------------------------

TEST(NoiseChaChaPoly, EncryptCounter0) {
    Key key{};
    key.fill(0x55);
    std::string pt_str = "secret message";
    auto pt = reinterpret_cast<const uint8_t*>(pt_str.data());

    auto ct = encrypt(key, 0, nullptr, 0, pt, pt_str.size());
    EXPECT_EQ(to_hex(ct),
        "6cc476dc854578908eb46136e750585e0f3495a38f21dc9baf0232bf11b7");
}

TEST(NoiseChaChaPoly, EncryptCounter1) {
    Key key{};
    key.fill(0x55);
    std::string pt_str = "secret message";
    auto pt = reinterpret_cast<const uint8_t*>(pt_str.data());

    auto ct = encrypt(key, 1, nullptr, 0, pt, pt_str.size());
    EXPECT_EQ(to_hex(ct),
        "b92456e424546249f0f8215fe2b401abcb28c9c348e28d216a3ce042765d");
}

TEST(NoiseChaChaPoly, DecryptRoundTrip) {
    Key key{};
    key.fill(0x55);
    std::string pt_str = "secret message";
    auto pt = reinterpret_cast<const uint8_t*>(pt_str.data());

    auto ct = encrypt(key, 42, nullptr, 0, pt, pt_str.size());
    auto dec = decrypt(key, 42, nullptr, 0, ct.data(), ct.size());
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(std::string(dec->begin(), dec->end()), pt_str);
}

TEST(NoiseChaChaPoly, DecryptWrongKey) {
    Key key{};
    key.fill(0x55);
    Key wrong_key{};
    wrong_key.fill(0xAA);
    std::string pt_str = "secret message";
    auto pt = reinterpret_cast<const uint8_t*>(pt_str.data());

    auto ct = encrypt(key, 0, nullptr, 0, pt, pt_str.size());
    auto dec = decrypt(wrong_key, 0, nullptr, 0, ct.data(), ct.size());
    EXPECT_FALSE(dec.has_value());
}

// ---------------------------------------------------------------------------
// Full Noise IK handshake — test against JS vectors
// ---------------------------------------------------------------------------

TEST(NoiseIKHandshake, MatchesJS) {
    // Fixed seeds from JS test vectors
    Seed i_seed{};
    i_seed.fill(0x00);
    Seed r_seed{};
    r_seed.fill(0xFF);

    auto i_kp = generate_keypair(i_seed);
    auto r_kp = generate_keypair(r_seed);

    EXPECT_EQ(to_hex(i_kp.public_key),
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    EXPECT_EQ(to_hex(r_kp.public_key),
        "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5");

    // Fixed ephemeral seeds for deterministic vectors
    Seed ie_seed{};
    ie_seed.fill(0xAA);
    Seed re_seed{};
    re_seed.fill(0xBB);

    // Prologue: single byte 0x00 (PEER_HANDSHAKE)
    uint8_t prologue[] = {0x00};

    // Create initiator and responder with fixed ephemerals
    NoiseIK initiator(true, i_kp, prologue, 1, &r_kp.public_key);
    initiator.set_ephemeral(generate_keypair(ie_seed));

    NoiseIK responder(false, r_kp, prologue, 1, nullptr);
    responder.set_ephemeral(generate_keypair(re_seed));

    // Verify init state matches JS
    EXPECT_EQ(to_hex(initiator.symmetric().digest),
        "e84460f514e85a7f02e73e67e98a21720e05f1fe2a4cd8fb596a4d44d36de6ff"
        "5abba8fda24d103ea94558684528c7362b6f403e8c06088a55ee6b32f96d9197")
        << "Initiator h after init should match JS";
    EXPECT_EQ(to_hex(initiator.symmetric().chaining_key),
        "4e6f6973655f494b5f456432353531395f436861436861506f6c795f424c414b"
        "4532620000000000000000000000000000000000000000000000000000000000")
        << "Initiator ck after init should match JS";

    // Both sides should have same h and ck after init
    EXPECT_EQ(initiator.symmetric().digest, responder.symmetric().digest);
    EXPECT_EQ(initiator.symmetric().chaining_key, responder.symmetric().chaining_key);

    // Message 1: initiator → responder
    auto msg1 = initiator.send();
    EXPECT_EQ(msg1.size(), 96u) << "Message 1 should be 96 bytes";
    EXPECT_EQ(to_hex(msg1),
        "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"
        "3565138aeef4e5ee9103380e2dd215f67b9416a8cfdc18b104bd146a34565c2b"
        "1578570ce40f5b0bbbda97f6f1317329d01c2fc955b26b950b7ed4cd2e380e9d")
        << "Message 1 bytes should match JS";

    // Verify intermediate state after msg1
    EXPECT_EQ(to_hex(initiator.symmetric().chaining_key),
        "92f491f11fb4f700116af6d745c56691ed471a9fe069e9a9700b3074fc188e98"
        "e7fae6486b84e2350a8ee6a4554063801e3a67b81bc7eb676f5c6b150f62541f")
        << "Initiator ck after msg1";
    EXPECT_EQ(to_hex(initiator.symmetric().digest),
        "12b0da0babcc6e5b4d3c43bb6f0da94292fc110f2b38ae8679247e71a8f92d79"
        "41698e505829633b7b9cd8b01ad62268a9fbaa08f351de9f7d4d8557c2fa6c6b")
        << "Initiator h after msg1";

    // Responder receives message 1
    auto payload1 = responder.recv(msg1.data(), msg1.size());
    ASSERT_TRUE(payload1.has_value()) << "Responder should decrypt msg1";
    EXPECT_TRUE(payload1->empty()) << "Payload should be empty";

    // Responder state should match initiator's after msg1
    EXPECT_EQ(responder.symmetric().chaining_key, initiator.symmetric().chaining_key);
    EXPECT_EQ(responder.symmetric().digest, initiator.symmetric().digest);

    // Message 2: responder → initiator
    auto msg2 = responder.send();
    EXPECT_EQ(msg2.size(), 48u) << "Message 2 should be 48 bytes";
    EXPECT_EQ(to_hex(msg2),
        "7d59c5623dd40a74aa4d5a32ac645d3b3f95daeae4c22be25476dd6a486f7382"
        "a97e9496ac90ae735d989b291d521f65")
        << "Message 2 bytes should match JS";

    EXPECT_TRUE(responder.is_complete());

    // Initiator receives message 2
    auto payload2 = initiator.recv(msg2.data(), msg2.size());
    ASSERT_TRUE(payload2.has_value()) << "Initiator should decrypt msg2";
    EXPECT_TRUE(payload2->empty());

    EXPECT_TRUE(initiator.is_complete());

    // Final state verification
    EXPECT_EQ(to_hex(initiator.handshake_hash()),
        "ccfcc4094a69988cd7dd122552e5daf9807bd22cc2533c19c75e61fcaa03470d"
        "ca405d20008453c6536d881205fb8b748dbbe386f2442ab8af2864d1f15a8470");
    EXPECT_EQ(initiator.handshake_hash(), responder.handshake_hash());

    // Split keys
    EXPECT_EQ(to_hex(initiator.tx_key()),
        "16fee93353b581b9051c01800409667f1cfa37250c9f44578068b85940b4846d");
    EXPECT_EQ(to_hex(initiator.rx_key()),
        "a81f0b514b4e37786e8a5aa1704c0115f2a37e7846f3cdb765c0597ff279952b");

    // tx/rx complementary
    EXPECT_EQ(initiator.tx_key(), responder.rx_key());
    EXPECT_EQ(initiator.rx_key(), responder.tx_key());
}

// ---------------------------------------------------------------------------
// Self-handshake (random keys) — both sides produce complementary keys
// ---------------------------------------------------------------------------

TEST(NoiseIKHandshake, SelfHandshakeRandomKeys) {
    ASSERT_EQ(sodium_init(), 0);

    auto i_kp = generate_keypair();
    auto r_kp = generate_keypair();

    uint8_t prologue[] = {0x00};
    NoiseIK initiator(true, i_kp, prologue, 1, &r_kp.public_key);
    NoiseIK responder(false, r_kp, prologue, 1, nullptr);

    auto msg1 = initiator.send();
    auto payload1 = responder.recv(msg1.data(), msg1.size());
    ASSERT_TRUE(payload1.has_value());

    auto msg2 = responder.send();
    auto payload2 = initiator.recv(msg2.data(), msg2.size());
    ASSERT_TRUE(payload2.has_value());

    EXPECT_TRUE(initiator.is_complete());
    EXPECT_TRUE(responder.is_complete());
    EXPECT_EQ(initiator.tx_key(), responder.rx_key());
    EXPECT_EQ(initiator.rx_key(), responder.tx_key());
    EXPECT_EQ(initiator.handshake_hash(), responder.handshake_hash());
}
