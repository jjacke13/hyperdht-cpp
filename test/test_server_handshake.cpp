// Test server-side PEER_HANDSHAKE — Noise IK responder.
// Verifies that the server can process a client's Noise msg1,
// derive matching keys, and produce a valid Noise msg2.

#include <gtest/gtest.h>

#include <sodium.h>

#include "hyperdht/dht_messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/server_connection.hpp"

using namespace hyperdht;
using namespace hyperdht::server_connection;

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; i++) {
        out.push_back(h[data[i] >> 4]);
        out.push_back(h[data[i] & 0x0F]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Helper: simulate client-side Noise msg1
// ---------------------------------------------------------------------------

struct ClientHandshake {
    std::vector<uint8_t> noise_msg1;
    std::shared_ptr<noise::NoiseIK> noise_ik;
};

static ClientHandshake make_client_msg1(
    const noise::Keypair& client_kp,
    const noise::PubKey& server_pk,
    uint32_t client_udx_id) {

    // Same prologue as real HyperDHT
    const auto& prol = dht_messages::ns_peer_handshake();

    auto noise_ik = std::make_shared<noise::NoiseIK>(
        true, client_kp, prol.data(), prol.size(), &server_pk);

    // Build client's NoisePayload
    peer_connect::NoisePayload payload;
    payload.version = 1;
    payload.error = peer_connect::ERROR_NONE;
    payload.firewall = peer_connect::FIREWALL_CONSISTENT;
    payload.udx = peer_connect::UdxInfo{1, false, client_udx_id, 0};
    payload.has_secret_stream = true;

    auto payload_bytes = peer_connect::encode_noise_payload(payload);
    auto msg1 = noise_ik->send(payload_bytes.data(), payload_bytes.size());

    ClientHandshake result;
    result.noise_msg1 = std::move(msg1);
    result.noise_ik = noise_ik;
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(ServerHandshake, BasicHandshake) {
    // Generate keypairs
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    // Client creates Noise msg1
    auto client = make_client_msg1(client_kp, server_kp.public_key, 12345);

    // Server processes it
    auto result = handle_handshake(
        server_kp,
        client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000),
        0,   // holepunch_id
        {},  // our_addresses (empty = not OPEN)
        {},  // relay_infos
        nullptr);  // no firewall

    ASSERT_TRUE(result.has_value());
    auto& conn = *result;

    EXPECT_FALSE(conn.has_error);
    EXPECT_EQ(conn.error_code, peer_connect::ERROR_NONE);
    EXPECT_FALSE(conn.reply_noise.empty());
    EXPECT_GT(conn.local_udx_id, 0u);
    EXPECT_NE(conn.secure, nullptr);

    // Server should have learned the client's public key
    EXPECT_EQ(conn.remote_public_key, client_kp.public_key);

    // Server should have the client's UDX ID
    ASSERT_TRUE(conn.remote_payload.udx.has_value());
    EXPECT_EQ(conn.remote_payload.udx->id, 12345u);

    // Client decrypts Noise msg2
    auto server_payload_bytes = client.noise_ik->recv(
        conn.reply_noise.data(), conn.reply_noise.size());
    ASSERT_TRUE(server_payload_bytes.has_value());
    EXPECT_TRUE(client.noise_ik->is_complete());

    auto server_payload = peer_connect::decode_noise_payload(
        server_payload_bytes->data(), server_payload_bytes->size());
    EXPECT_EQ(server_payload.error, peer_connect::ERROR_NONE);
    EXPECT_EQ(server_payload.version, 1u);
    EXPECT_TRUE(server_payload.has_secret_stream);
    ASSERT_TRUE(server_payload.udx.has_value());
    EXPECT_EQ(server_payload.udx->id, conn.local_udx_id);
}

TEST(ServerHandshake, KeysMatch) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);
    auto result = handle_handshake(server_kp, client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 0, {}, {});
    ASSERT_TRUE(result.has_value());

    // Client processes msg2
    client.noise_ik->recv(result->reply_noise.data(), result->reply_noise.size());

    // Keys should be complementary: client tx = server rx, client rx = server tx
    EXPECT_EQ(client.noise_ik->tx_key(), result->rx_key);
    EXPECT_EQ(client.noise_ik->rx_key(), result->tx_key);

    // Handshake hashes should match
    EXPECT_EQ(client.noise_ik->handshake_hash(), result->handshake_hash);
}

TEST(ServerHandshake, FirewallRejects) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);

    // Firewall rejects all connections
    auto result = handle_handshake(server_kp, client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 0, {}, {},
        [](const auto&, const auto&, const auto&) { return true; });

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->firewalled);
    EXPECT_TRUE(result->has_error);
    EXPECT_EQ(result->error_code, peer_connect::ERROR_ABORTED);
    // Still has reply noise (error response)
    EXPECT_FALSE(result->reply_noise.empty());
}

TEST(ServerHandshake, HolepunchInfoWhenNotOpen) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);

    // Server has no addresses → not OPEN → should include holepunch info
    peer_connect::RelayInfo relay;
    relay.relay_address = compact::Ipv4Address::from_string("1.2.3.4", 49737);
    relay.peer_address = compact::Ipv4Address::from_string("5.6.7.8", 30000);

    auto result = handle_handshake(server_kp, client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 7,
        {}, {relay});
    ASSERT_TRUE(result.has_value());

    // Decode server's response
    auto resp_bytes = client.noise_ik->recv(
        result->reply_noise.data(), result->reply_noise.size());
    auto resp = peer_connect::decode_noise_payload(
        resp_bytes->data(), resp_bytes->size());

    EXPECT_EQ(resp.firewall, peer_connect::FIREWALL_UNKNOWN);
    ASSERT_TRUE(resp.holepunch.has_value());
    EXPECT_EQ(resp.holepunch->id, 7u);
    ASSERT_EQ(resp.holepunch->relays.size(), 1u);
    EXPECT_EQ(resp.holepunch->relays[0].relay_address.host_string(), "1.2.3.4");
}

TEST(ServerHandshake, ConsistentFirewallWithHolepunch) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    auto client = make_client_msg1(client_kp, server_kp.public_key, 1);

    // Server has addresses → reports CONSISTENT (not OPEN) to force
    // holepunch path. Direct-connect (OPEN) needs UDX rawStream firewall.
    std::vector<compact::Ipv4Address> addrs = {
        compact::Ipv4Address::from_string("1.2.3.4", 49737)
    };
    peer_connect::RelayInfo relay;
    relay.relay_address = compact::Ipv4Address::from_string("9.8.7.6", 49737);

    auto result = handle_handshake(server_kp, client.noise_msg1,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 0,
        addrs, {relay});
    ASSERT_TRUE(result.has_value());

    auto resp_bytes = client.noise_ik->recv(
        result->reply_noise.data(), result->reply_noise.size());
    auto resp = peer_connect::decode_noise_payload(
        resp_bytes->data(), resp_bytes->size());

    EXPECT_EQ(resp.firewall, peer_connect::FIREWALL_CONSISTENT);
    ASSERT_TRUE(resp.holepunch.has_value());
    EXPECT_EQ(resp.holepunch->id, 0u);
}

TEST(ServerHandshake, InvalidNoiseFails) {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    // Garbage noise data
    std::vector<uint8_t> garbage(100, 0xFF);

    auto result = handle_handshake(server_kp, garbage,
        compact::Ipv4Address::from_string("10.0.0.1", 5000), 0, {}, {});

    EXPECT_FALSE(result.has_value());
}
