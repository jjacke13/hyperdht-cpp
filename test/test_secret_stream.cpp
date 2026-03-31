#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <sodium.h>

#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/secret_stream.hpp"

using namespace hyperdht::noise;
using namespace hyperdht::secret_stream;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Stream ID — verify against JS namespace values
// ---------------------------------------------------------------------------

TEST(SecretStreamId, ComputeMatchesJS) {
    // Use a known handshake hash (all 0x03) — same as JS test
    Hash hh{};
    hh.fill(0x03);

    auto id_i = compute_stream_id(hh, true);
    auto id_r = compute_stream_id(hh, false);

    // Verify against JS-computed values
    EXPECT_EQ(to_hex(id_i),
        "a4c8a368031ef0728b3c0d42f16e97922e45f2d2b01dfc06708e1973b4585ce3")
        << "Initiator stream ID should match JS";
    EXPECT_EQ(to_hex(id_r),
        "d7f3a6c98dba0cc220b799ee63cf8202d2a5ce2db07afea79aa01231e77e3366")
        << "Responder stream ID should match JS";

    // Initiator ≠ responder
    EXPECT_NE(id_i, id_r);
}

// ---------------------------------------------------------------------------
// uint24_le framing
// ---------------------------------------------------------------------------

TEST(SecretStreamFrame, Uint24LE) {
    uint8_t buf[3];

    write_uint24_le(buf, 56);
    EXPECT_EQ(buf[0], 56);
    EXPECT_EQ(buf[1], 0);
    EXPECT_EQ(buf[2], 0);
    EXPECT_EQ(read_uint24_le(buf), 56u);

    write_uint24_le(buf, 0x123456);
    EXPECT_EQ(read_uint24_le(buf), 0x123456u);
}

// ---------------------------------------------------------------------------
// Header exchange — self test (C++ initiator ↔ C++ responder)
// ---------------------------------------------------------------------------

TEST(SecretStreamHeader, SelfExchange) {
    // Do a Noise handshake to get real keys
    Seed i_seed{};
    i_seed.fill(0x00);
    Seed r_seed{};
    r_seed.fill(0xFF);
    auto i_kp = generate_keypair(i_seed);
    auto r_kp = generate_keypair(r_seed);

    uint8_t prologue[] = {0x00};
    NoiseIK initiator(true, i_kp, prologue, 1, &r_kp.public_key);
    NoiseIK responder(false, r_kp, prologue, 1, nullptr);

    auto msg1 = initiator.send();
    auto p1 = responder.recv(msg1.data(), msg1.size());
    ASSERT_TRUE(p1.has_value());

    auto msg2 = responder.send();
    auto p2 = initiator.recv(msg2.data(), msg2.size());
    ASSERT_TRUE(p2.has_value());

    ASSERT_TRUE(initiator.is_complete());
    ASSERT_TRUE(responder.is_complete());

    // Create SecretStream for both sides
    SecretStream ss_i(initiator.tx_key(), initiator.rx_key(),
                      initiator.handshake_hash(), true);
    SecretStream ss_r(responder.tx_key(), responder.rx_key(),
                      responder.handshake_hash(), false);

    // Stream IDs should be complementary
    EXPECT_EQ(ss_i.local_id(), ss_r.remote_id());
    EXPECT_EQ(ss_i.remote_id(), ss_r.local_id());

    // Create header messages
    auto hdr_i = ss_i.create_header_message();
    auto hdr_r = ss_r.create_header_message();

    EXPECT_EQ(hdr_i.size(), 59u);  // 3 + 56
    EXPECT_EQ(hdr_r.size(), 59u);

    // Verify length prefix
    EXPECT_EQ(read_uint24_le(hdr_i.data()), 56u);
    EXPECT_EQ(read_uint24_le(hdr_r.data()), 56u);

    // Exchange headers (strip the 3-byte length prefix)
    EXPECT_TRUE(ss_i.receive_header(hdr_r.data() + 3, 56));
    EXPECT_TRUE(ss_r.receive_header(hdr_i.data() + 3, 56));

    EXPECT_TRUE(ss_i.is_ready());
    EXPECT_TRUE(ss_r.is_ready());
}

// ---------------------------------------------------------------------------
// Wrong stream ID — header should be rejected
// ---------------------------------------------------------------------------

TEST(SecretStreamHeader, WrongStreamIdRejected) {
    Seed i_seed{};
    i_seed.fill(0x00);
    Seed r_seed{};
    r_seed.fill(0xFF);
    auto i_kp = generate_keypair(i_seed);
    auto r_kp = generate_keypair(r_seed);

    uint8_t prologue[] = {0x00};
    NoiseIK initiator(true, i_kp, prologue, 1, &r_kp.public_key);
    NoiseIK responder(false, r_kp, prologue, 1, nullptr);

    auto msg1 = initiator.send();
    responder.recv(msg1.data(), msg1.size());
    auto msg2 = responder.send();
    initiator.recv(msg2.data(), msg2.size());

    SecretStream ss_i(initiator.tx_key(), initiator.rx_key(),
                      initiator.handshake_hash(), true);

    // Create a fake header with wrong stream ID
    uint8_t fake_header[56] = {};
    std::memset(fake_header, 0xAA, 32);  // Wrong stream ID
    EXPECT_FALSE(ss_i.receive_header(fake_header, 56));
    EXPECT_FALSE(ss_i.is_ready());
}

// ---------------------------------------------------------------------------
// Full encrypt/decrypt round-trip
// ---------------------------------------------------------------------------

TEST(SecretStreamData, EncryptDecryptRoundTrip) {
    Seed i_seed{};
    i_seed.fill(0x00);
    Seed r_seed{};
    r_seed.fill(0xFF);
    auto i_kp = generate_keypair(i_seed);
    auto r_kp = generate_keypair(r_seed);

    uint8_t prologue[] = {0x00};
    NoiseIK initiator(true, i_kp, prologue, 1, &r_kp.public_key);
    NoiseIK responder(false, r_kp, prologue, 1, nullptr);

    auto msg1 = initiator.send();
    responder.recv(msg1.data(), msg1.size());
    auto msg2 = responder.send();
    initiator.recv(msg2.data(), msg2.size());

    SecretStream ss_i(initiator.tx_key(), initiator.rx_key(),
                      initiator.handshake_hash(), true);
    SecretStream ss_r(responder.tx_key(), responder.rx_key(),
                      responder.handshake_hash(), false);

    // Exchange headers
    auto hdr_i = ss_i.create_header_message();
    auto hdr_r = ss_r.create_header_message();
    ASSERT_TRUE(ss_i.receive_header(hdr_r.data() + 3, 56));
    ASSERT_TRUE(ss_r.receive_header(hdr_i.data() + 3, 56));

    // Initiator → Responder
    std::string msg = "hello secret stream";
    auto encrypted = ss_i.encrypt(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    // Verify framing: uint24_le(len) + encrypted_payload
    uint32_t enc_len = read_uint24_le(encrypted.data());
    EXPECT_EQ(enc_len, msg.size() + ABYTES);
    EXPECT_EQ(encrypted.size(), 3 + enc_len);

    // Decrypt on responder side
    auto decrypted = ss_r.decrypt(encrypted.data() + 3, enc_len);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(std::string(decrypted->begin(), decrypted->end()), msg);

    // Responder → Initiator
    std::string reply = "reply from responder";
    auto enc_reply = ss_r.encrypt(
        reinterpret_cast<const uint8_t*>(reply.data()), reply.size());
    uint32_t reply_len = read_uint24_le(enc_reply.data());
    auto dec_reply = ss_i.decrypt(enc_reply.data() + 3, reply_len);
    ASSERT_TRUE(dec_reply.has_value());
    EXPECT_EQ(std::string(dec_reply->begin(), dec_reply->end()), reply);
}

// ---------------------------------------------------------------------------
// Multiple messages maintain secretstream state
// ---------------------------------------------------------------------------

TEST(SecretStreamData, MultipleMessages) {
    Seed i_seed{};
    i_seed.fill(0x00);
    Seed r_seed{};
    r_seed.fill(0xFF);
    auto i_kp = generate_keypair(i_seed);
    auto r_kp = generate_keypair(r_seed);

    uint8_t prologue[] = {0x00};
    NoiseIK initiator(true, i_kp, prologue, 1, &r_kp.public_key);
    NoiseIK responder(false, r_kp, prologue, 1, nullptr);

    auto msg1 = initiator.send();
    responder.recv(msg1.data(), msg1.size());
    auto msg2 = responder.send();
    initiator.recv(msg2.data(), msg2.size());

    SecretStream ss_i(initiator.tx_key(), initiator.rx_key(),
                      initiator.handshake_hash(), true);
    SecretStream ss_r(responder.tx_key(), responder.rx_key(),
                      responder.handshake_hash(), false);

    auto hdr_i = ss_i.create_header_message();
    auto hdr_r = ss_r.create_header_message();
    ss_i.receive_header(hdr_r.data() + 3, 56);
    ss_r.receive_header(hdr_i.data() + 3, 56);

    // Send 10 messages, verify all decrypt correctly
    for (int i = 0; i < 10; i++) {
        std::string msg = "message #" + std::to_string(i);
        auto enc = ss_i.encrypt(
            reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        uint32_t len = read_uint24_le(enc.data());
        auto dec = ss_r.decrypt(enc.data() + 3, len);
        ASSERT_TRUE(dec.has_value()) << "Failed to decrypt message " << i;
        EXPECT_EQ(std::string(dec->begin(), dec->end()), msg);
    }
}

// ---------------------------------------------------------------------------
// Tampered ciphertext — decryption should fail
// ---------------------------------------------------------------------------

TEST(SecretStreamData, TamperedCiphertextFails) {
    Seed i_seed{};
    i_seed.fill(0x00);
    Seed r_seed{};
    r_seed.fill(0xFF);
    auto i_kp = generate_keypair(i_seed);
    auto r_kp = generate_keypair(r_seed);

    uint8_t prologue[] = {0x00};
    NoiseIK initiator(true, i_kp, prologue, 1, &r_kp.public_key);
    NoiseIK responder(false, r_kp, prologue, 1, nullptr);

    auto msg1 = initiator.send();
    responder.recv(msg1.data(), msg1.size());
    auto msg2 = responder.send();
    initiator.recv(msg2.data(), msg2.size());

    SecretStream ss_i(initiator.tx_key(), initiator.rx_key(),
                      initiator.handshake_hash(), true);
    SecretStream ss_r(responder.tx_key(), responder.rx_key(),
                      responder.handshake_hash(), false);

    auto hdr_i = ss_i.create_header_message();
    auto hdr_r = ss_r.create_header_message();
    ss_i.receive_header(hdr_r.data() + 3, 56);
    ss_r.receive_header(hdr_i.data() + 3, 56);

    std::string msg = "sensitive data";
    auto enc = ss_i.encrypt(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    // Tamper with encrypted payload
    enc[5] ^= 0xFF;

    uint32_t len = read_uint24_le(enc.data());
    auto dec = ss_r.decrypt(enc.data() + 3, len);
    EXPECT_FALSE(dec.has_value()) << "Tampered ciphertext should fail";
}
