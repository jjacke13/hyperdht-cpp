#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include <sodium.h>

#include "hyperdht/holepunch.hpp"

using namespace hyperdht::holepunch;
using namespace hyperdht::compact;
using namespace hyperdht::peer_connect;

using Ipv4Address = hyperdht::compact::Ipv4Address;

// ---------------------------------------------------------------------------
// SecurePayload
// ---------------------------------------------------------------------------

TEST(SecurePayload, EncryptDecryptRoundTrip) {
    std::array<uint8_t, 32> key{};
    key.fill(0x42);
    SecurePayload sp(key);

    std::string msg = "holepunch test data";
    auto encrypted = sp.encrypt(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    // Should be 24 (nonce) + msg.size() + 16 (mac)
    EXPECT_EQ(encrypted.size(), 24 + msg.size() + 16);

    auto decrypted = sp.decrypt(encrypted.data(), encrypted.size());
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(std::string(decrypted->begin(), decrypted->end()), msg);
}

TEST(SecurePayload, WrongKeyFails) {
    std::array<uint8_t, 32> key1{};
    key1.fill(0x42);
    std::array<uint8_t, 32> key2{};
    key2.fill(0x43);

    SecurePayload sp1(key1);
    SecurePayload sp2(key2);

    std::string msg = "secret";
    auto encrypted = sp1.encrypt(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    auto decrypted = sp2.decrypt(encrypted.data(), encrypted.size());
    EXPECT_FALSE(decrypted.has_value());
}

TEST(SecurePayload, TokenDeterministic) {
    std::array<uint8_t, 32> key{};
    key.fill(0x42);
    SecurePayload sp(key);

    auto t1 = sp.token("10.0.0.1");
    auto t2 = sp.token("10.0.0.1");
    EXPECT_EQ(t1, t2);

    auto t3 = sp.token("10.0.0.2");
    EXPECT_NE(t1, t3);
}

// ---------------------------------------------------------------------------
// HolepunchPayload encoding
// ---------------------------------------------------------------------------

TEST(HolepunchPayload, EncodeDecodeMinimal) {
    HolepunchPayload p;
    p.error = 0;
    p.firewall = FIREWALL_OPEN;
    p.round = 0;

    auto buf = encode_holepunch_payload(p);
    auto decoded = decode_holepunch_payload(buf.data(), buf.size());

    EXPECT_FALSE(decoded.connected);
    EXPECT_FALSE(decoded.punching);
    EXPECT_EQ(decoded.error, 0u);
    EXPECT_EQ(decoded.firewall, FIREWALL_OPEN);
    EXPECT_EQ(decoded.round, 0u);
    EXPECT_TRUE(decoded.addresses.empty());
    EXPECT_FALSE(decoded.remote_address.has_value());
    EXPECT_FALSE(decoded.token.has_value());
}

TEST(HolepunchPayload, EncodeDecodeWithAll) {
    HolepunchPayload p;
    p.connected = true;
    p.punching = true;
    p.error = 0;
    p.firewall = FIREWALL_CONSISTENT;
    p.round = 5;
    p.addresses.push_back(Ipv4Address::from_string("192.168.1.1", 8001));
    p.remote_address = Ipv4Address::from_string("10.0.0.1", 3000);

    std::array<uint8_t, 32> tok{};
    tok.fill(0xAA);
    p.token = tok;

    std::array<uint8_t, 32> rtok{};
    rtok.fill(0xBB);
    p.remote_token = rtok;

    auto buf = encode_holepunch_payload(p);
    auto decoded = decode_holepunch_payload(buf.data(), buf.size());

    EXPECT_TRUE(decoded.connected);
    EXPECT_TRUE(decoded.punching);
    EXPECT_EQ(decoded.firewall, FIREWALL_CONSISTENT);
    EXPECT_EQ(decoded.round, 5u);
    EXPECT_EQ(decoded.addresses.size(), 1u);
    EXPECT_EQ(decoded.addresses[0].port, 8001u);
    ASSERT_TRUE(decoded.remote_address.has_value());
    EXPECT_EQ(decoded.remote_address->port, 3000u);
    ASSERT_TRUE(decoded.token.has_value());
    EXPECT_EQ((*decoded.token)[0], 0xAA);
    ASSERT_TRUE(decoded.remote_token.has_value());
    EXPECT_EQ((*decoded.remote_token)[0], 0xBB);
}

TEST(HolepunchPayload, EncryptedRoundTrip) {
    std::array<uint8_t, 32> key{};
    key.fill(0x42);
    SecurePayload sp(key);

    HolepunchPayload p;
    p.firewall = FIREWALL_CONSISTENT;
    p.round = 3;
    p.punching = true;
    p.addresses.push_back(Ipv4Address::from_string("192.168.1.1", 8001));

    auto payload_bytes = encode_holepunch_payload(p);
    auto encrypted = sp.encrypt(payload_bytes.data(), payload_bytes.size());
    auto decrypted = sp.decrypt(encrypted.data(), encrypted.size());
    ASSERT_TRUE(decrypted.has_value());

    auto decoded = decode_holepunch_payload(decrypted->data(), decrypted->size());
    EXPECT_EQ(decoded.firewall, FIREWALL_CONSISTENT);
    EXPECT_EQ(decoded.round, 3u);
    EXPECT_TRUE(decoded.punching);
}

// ---------------------------------------------------------------------------
// OPEN firewall shortcut
// ---------------------------------------------------------------------------

TEST(Holepunch, OpenFirewallDirect) {
    HandshakeResult hs;
    hs.success = true;
    hs.remote_payload.firewall = FIREWALL_OPEN;
    hs.remote_payload.addresses4.push_back(
        Ipv4Address::from_string("1.2.3.4", 49737));

    HolepunchResult result;
    EXPECT_TRUE(try_direct_connect(hs, result));
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.address.port, 49737u);
    EXPECT_EQ(result.address.host_string(), "1.2.3.4");
}

TEST(Holepunch, NonOpenFirewallNoDirect) {
    HandshakeResult hs;
    hs.success = true;
    hs.remote_payload.firewall = FIREWALL_CONSISTENT;
    hs.remote_payload.addresses4.push_back(
        Ipv4Address::from_string("1.2.3.4", 49737));

    HolepunchResult result;
    EXPECT_FALSE(try_direct_connect(hs, result));
}

// ---------------------------------------------------------------------------
// Holepuncher strategy selection
// ---------------------------------------------------------------------------

TEST(Holepuncher, ConsistentConsistent) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    Holepuncher hp(&loop, true);
    hp.set_local_firewall(FIREWALL_CONSISTENT);
    hp.set_remote_firewall(FIREWALL_CONSISTENT);
    hp.set_remote_addresses({Ipv4Address::from_string("10.0.0.1", 3000)});

    EXPECT_TRUE(hp.punch());
    EXPECT_TRUE(hp.is_punching());

    hp.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Holepuncher, RandomRandomFails) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    Holepuncher hp(&loop, true);
    hp.set_local_firewall(FIREWALL_RANDOM);
    hp.set_remote_firewall(FIREWALL_RANDOM);

    EXPECT_FALSE(hp.punch()) << "RANDOM+RANDOM should fail";
    EXPECT_FALSE(hp.is_punching());

    hp.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Holepuncher, OnMessageConnect) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    Holepuncher hp(&loop, true);
    hp.set_local_firewall(FIREWALL_CONSISTENT);
    hp.set_remote_firewall(FIREWALL_CONSISTENT);

    bool connected = false;
    Ipv4Address connected_addr;
    hp.on_connect([&](const HolepunchResult& result) {
        connected = result.success;
        connected_addr = result.address;
    });

    hp.set_remote_addresses({Ipv4Address::from_string("10.0.0.1", 3000)});
    hp.punch();

    // Simulate receiving a UDP probe from the peer
    hp.on_message(Ipv4Address::from_string("10.0.0.1", 3000));

    EXPECT_TRUE(connected);
    EXPECT_TRUE(hp.is_connected());
    EXPECT_FALSE(hp.is_punching());
    EXPECT_EQ(connected_addr.port, 3000u);

    hp.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// ---------------------------------------------------------------------------
// SendProbeFn wiring
// ---------------------------------------------------------------------------

TEST(Holepuncher, SendProbeCallsSendFn) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    Holepuncher hp(&loop, true);

    std::vector<Ipv4Address> probed_addrs;
    hp.set_send_fn([&](const Ipv4Address& addr) {
        probed_addrs.push_back(addr);
    });

    auto target = Ipv4Address::from_string("10.0.0.1", 5000);
    hp.send_probe(target);
    hp.send_probe(target);

    EXPECT_EQ(probed_addrs.size(), 2u);
    EXPECT_EQ(probed_addrs[0].port, 5000u);

    hp.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Holepuncher, SendProbeNoop) {
    // Without set_send_fn, send_probe should not crash
    uv_loop_t loop;
    uv_loop_init(&loop);

    Holepuncher hp(&loop, true);
    hp.send_probe(Ipv4Address::from_string("10.0.0.1", 5000));  // No crash

    hp.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(Holepunch, FailedHandshakeNoDirect) {
    HandshakeResult hs;
    hs.success = false;

    HolepunchResult result;
    EXPECT_FALSE(try_direct_connect(hs, result));
}
