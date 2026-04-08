#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <sodium.h>
#include <uv.h>

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

// ---------------------------------------------------------------------------
// Helper: create a handshake pair and return ready SecretStreams
// ---------------------------------------------------------------------------

struct StreamPair {
    std::unique_ptr<SecretStream> initiator;
    std::unique_ptr<SecretStream> responder;
};

static StreamPair make_stream_pair(uv_loop_t* loop = nullptr) {
    Seed i_seed{};
    i_seed.fill(0x11);
    Seed r_seed{};
    r_seed.fill(0x22);
    auto i_kp = generate_keypair(i_seed);
    auto r_kp = generate_keypair(r_seed);

    uint8_t prologue[] = {0x00};
    NoiseIK initiator(true, i_kp, prologue, 1, &r_kp.public_key);
    NoiseIK responder(false, r_kp, prologue, 1, nullptr);

    auto msg1 = initiator.send();
    responder.recv(msg1.data(), msg1.size());
    auto msg2 = responder.send();
    initiator.recv(msg2.data(), msg2.size());

    auto ss_i = std::make_unique<SecretStream>(
        initiator.tx_key(), initiator.rx_key(),
        initiator.handshake_hash(), true, loop);
    auto ss_r = std::make_unique<SecretStream>(
        responder.tx_key(), responder.rx_key(),
        responder.handshake_hash(), false, loop);

    auto hdr_i = ss_i->create_header_message();
    auto hdr_r = ss_r->create_header_message();
    ss_i->receive_header(hdr_r.data() + 3, 56);
    ss_r->receive_header(hdr_i.data() + 3, 56);

    return {std::move(ss_i), std::move(ss_r)};
}

// ---------------------------------------------------------------------------
// Timeout timer tests
// ---------------------------------------------------------------------------

TEST(SecretStreamTimeout, FiresOnInactivity) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    auto [ss_i, ss_r] = make_stream_pair(&loop);

    bool timed_out = false;
    ss_r->set_timeout(50, [&timed_out]() { timed_out = true; });

    EXPECT_EQ(ss_r->timeout(), 50u);

    // Run loop — timeout should fire after ~50ms
    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_TRUE(timed_out);

    ss_i->stop_timers();
    ss_r->stop_timers();
    uv_run(&loop, UV_RUN_DEFAULT);  // drain close callbacks
    uv_loop_close(&loop);
}

TEST(SecretStreamTimeout, RefreshedByDecrypt) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    auto [ss_i, ss_r] = make_stream_pair(&loop);

    int timeout_count = 0;
    ss_r->set_timeout(100, [&timeout_count]() { timeout_count++; });

    // After 60ms, send a message to refresh the timer
    uv_timer_t refresh_timer;
    uv_timer_init(&loop, &refresh_timer);
    struct RefreshCtx {
        SecretStream* sender;
        SecretStream* receiver;
    };
    RefreshCtx ctx{ss_i.get(), ss_r.get()};
    refresh_timer.data = &ctx;

    uv_timer_start(&refresh_timer, [](uv_timer_t* t) {
        auto* c = static_cast<RefreshCtx*>(t->data);
        std::string msg = "keepalive data";
        auto enc = c->sender->encrypt(
            reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        uint32_t len = read_uint24_le(enc.data());
        c->receiver->decrypt(enc.data() + 3, len);  // refreshes timeout
    }, 60, 0);

    // After 180ms, stop everything — timeout should NOT have fired
    // (was refreshed at 60ms, so next fire would be at 160ms... let's check)
    uv_timer_t stop_timer;
    uv_timer_init(&loop, &stop_timer);
    stop_timer.data = &loop;
    uv_timer_start(&stop_timer, [](uv_timer_t* t) {
        uv_stop(static_cast<uv_loop_t*>(t->data));
    }, 130, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    // Timeout should NOT have fired (refreshed at 60ms → would fire at 160ms)
    EXPECT_EQ(timeout_count, 0);

    ss_i->stop_timers();
    ss_r->stop_timers();
    uv_close(reinterpret_cast<uv_handle_t*>(&refresh_timer), nullptr);
    uv_close(reinterpret_cast<uv_handle_t*>(&stop_timer), nullptr);
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Keepalive timer tests
// ---------------------------------------------------------------------------

TEST(SecretStreamKeepalive, FiresOnIdle) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    auto [ss_i, ss_r] = make_stream_pair(&loop);

    int keepalive_count = 0;
    ss_i->set_keep_alive(30, [&keepalive_count]() { keepalive_count++; });

    EXPECT_EQ(ss_i->keep_alive(), 30u);

    // Run for 100ms — should fire ~3 times
    uv_timer_t stop_timer;
    uv_timer_init(&loop, &stop_timer);
    stop_timer.data = &loop;
    uv_timer_start(&stop_timer, [](uv_timer_t* t) {
        uv_stop(static_cast<uv_loop_t*>(t->data));
    }, 100, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    EXPECT_GE(keepalive_count, 2);
    EXPECT_LE(keepalive_count, 4);

    ss_i->stop_timers();
    ss_r->stop_timers();
    uv_close(reinterpret_cast<uv_handle_t*>(&stop_timer), nullptr);
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(SecretStreamKeepalive, RefreshedByEncrypt) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    auto [ss_i, ss_r] = make_stream_pair(&loop);

    int keepalive_count = 0;
    ss_i->set_keep_alive(80, [&keepalive_count]() { keepalive_count++; });

    // Send data every 50ms — keepalive should never fire (refreshed each time)
    uv_timer_t send_timer;
    uv_timer_init(&loop, &send_timer);
    send_timer.data = ss_i.get();
    uv_timer_start(&send_timer, [](uv_timer_t* t) {
        auto* ss = static_cast<SecretStream*>(t->data);
        std::string msg = "data";
        ss->encrypt(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    }, 50, 50);

    // Stop after 200ms
    uv_timer_t stop_timer;
    uv_timer_init(&loop, &stop_timer);
    stop_timer.data = &loop;
    uv_timer_start(&stop_timer, [](uv_timer_t* t) {
        uv_stop(static_cast<uv_loop_t*>(t->data));
    }, 200, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    // Keepalive should NOT have fired (encrypt refreshes it)
    EXPECT_EQ(keepalive_count, 0);

    ss_i->stop_timers();
    ss_r->stop_timers();
    uv_close(reinterpret_cast<uv_handle_t*>(&send_timer), nullptr);
    uv_close(reinterpret_cast<uv_handle_t*>(&stop_timer), nullptr);
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// Empty message suppression
// ---------------------------------------------------------------------------

TEST(SecretStreamKeepalive, EmptyMessageSuppressed) {
    auto [ss_i, ss_r] = make_stream_pair();

    // Set keepalive on responder so empty messages are suppressed
    ss_r->set_keep_alive(1000, []() {});

    // Encrypt an empty message (keepalive heartbeat)
    auto enc = ss_i->encrypt(nullptr, 0);
    ASSERT_FALSE(enc.empty());

    // Decrypt — should return nullopt (suppressed)
    uint32_t len = read_uint24_le(enc.data());
    auto dec = ss_r->decrypt(enc.data() + 3, len);
    EXPECT_FALSE(dec.has_value()) << "Empty keepalive should be suppressed";
}

TEST(SecretStreamKeepalive, EmptyMessagePassesThroughWithoutKeepalive) {
    auto [ss_i, ss_r] = make_stream_pair();

    // No keepalive set — empty messages should pass through
    EXPECT_EQ(ss_r->keep_alive(), 0u);

    auto enc = ss_i->encrypt(nullptr, 0);
    ASSERT_FALSE(enc.empty());

    uint32_t len = read_uint24_le(enc.data());
    auto dec = ss_r->decrypt(enc.data() + 3, len);
    ASSERT_TRUE(dec.has_value());
    EXPECT_TRUE(dec->empty()) << "Empty message should pass through without keepalive";
}
