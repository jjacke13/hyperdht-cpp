// Test server-side PEER_HOLEPUNCH handler.
// Verifies that the server can decrypt holepunch payloads, update state,
// and respond correctly for both probe (round 0) and punch (round 1) phases.

#include <gtest/gtest.h>

#include <sodium.h>

#include "hyperdht/dht_messages.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/server_connection.hpp"

using namespace hyperdht;
using namespace hyperdht::server_connection;
using Ipv4Address = compact::Ipv4Address;

// ---------------------------------------------------------------------------
// Helper: set up a handshake and get the shared holepunch secret
// ---------------------------------------------------------------------------

struct TestSetup {
    ServerConnection conn;
    std::shared_ptr<holepunch::SecurePayload> client_secure;
};

static TestSetup make_test_setup() {
    noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = noise::generate_keypair(server_seed);

    noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = noise::generate_keypair(client_seed);

    // Client builds Noise msg1
    const auto& prol = dht_messages::ns_peer_handshake();
    auto noise_ik = std::make_shared<noise::NoiseIK>(
        true, client_kp, prol.data(), prol.size(), &server_kp.public_key);

    peer_connect::NoisePayload payload;
    payload.version = 1;
    payload.firewall = peer_connect::FIREWALL_CONSISTENT;
    payload.udx = peer_connect::UdxInfo{1, false, 100, 0};
    payload.has_secret_stream = true;

    auto payload_bytes = peer_connect::encode_noise_payload(payload);
    auto msg1 = noise_ik->send(payload_bytes.data(), payload_bytes.size());

    // Server processes handshake
    auto result = handle_handshake(server_kp, msg1,
        Ipv4Address::from_string("10.0.0.1", 5000), 0, {}, {});

    // Client finishes handshake
    noise_ik->recv(result->reply_noise.data(), result->reply_noise.size());

    // Derive client-side holepunch secret (same as server)
    const auto& ns_hp = dht_messages::ns_peer_holepunch();
    std::array<uint8_t, 32> hp_secret{};
    crypto_generichash(hp_secret.data(), 32,
                       ns_hp.data(), 32,
                       noise_ik->handshake_hash().data(), 64);
    auto client_secure = std::make_shared<holepunch::SecurePayload>(hp_secret);

    TestSetup setup;
    setup.conn = std::move(*result);
    setup.client_secure = client_secure;
    return setup;
}

// ---------------------------------------------------------------------------
// Helper: build a PEER_HOLEPUNCH value from client
// ---------------------------------------------------------------------------

static std::vector<uint8_t> make_client_holepunch(
    holepunch::SecurePayload& secure,
    const holepunch::HolepunchPayload& hp) {

    auto hp_bytes = holepunch::encode_holepunch_payload(hp);
    auto encrypted = secure.encrypt(hp_bytes.data(), hp_bytes.size());

    holepunch::HolepunchMessage msg;
    msg.mode = peer_connect::MODE_FROM_CLIENT;
    msg.id = 0;
    msg.payload = std::move(encrypted);
    msg.peer_address = Ipv4Address::from_string("10.0.0.1", 5000);

    return holepunch::encode_holepunch_msg(msg);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(ServerHolepunch, ProbeRound) {
    auto setup = make_test_setup();

    // Client sends round 0 (probe)
    holepunch::HolepunchPayload hp;
    hp.firewall = peer_connect::FIREWALL_CONSISTENT;
    hp.round = 0;
    hp.punching = false;

    auto value = make_client_holepunch(*setup.client_secure, hp);

    // is_server_relay=true so token is returned (matches JS behavior)
    auto reply = handle_holepunch(
        setup.conn, value,
        Ipv4Address::from_string("10.0.0.1", 5000),
        peer_connect::FIREWALL_CONSISTENT,
        {Ipv4Address::from_string("5.6.7.8", 49737)},
        true);  // is_server_relay

    EXPECT_FALSE(reply.value.empty());
    EXPECT_FALSE(reply.should_punch);  // Client isn't punching yet

    // Decrypt the server's reply
    auto resp_msg = holepunch::decode_holepunch_msg(reply.value.data(), reply.value.size());
    auto decrypted = setup.client_secure->decrypt(
        resp_msg.payload.data(), resp_msg.payload.size());
    ASSERT_TRUE(decrypted.has_value());

    auto resp = holepunch::decode_holepunch_payload(
        decrypted->data(), decrypted->size());
    EXPECT_EQ(resp.error, peer_connect::ERROR_NONE);
    EXPECT_EQ(resp.firewall, peer_connect::FIREWALL_CONSISTENT);
    EXPECT_TRUE(resp.token.has_value());  // Token returned because is_server_relay
    EXPECT_EQ(resp.addresses.size(), 1u);
}

TEST(ServerHolepunch, PunchRound) {
    auto setup = make_test_setup();

    // Client sends round 1 (punch) with addresses
    holepunch::HolepunchPayload hp;
    hp.firewall = peer_connect::FIREWALL_CONSISTENT;
    hp.round = 1;
    hp.punching = true;
    hp.addresses.push_back(Ipv4Address::from_string("10.0.0.1", 5000));

    auto value = make_client_holepunch(*setup.client_secure, hp);

    auto reply = handle_holepunch(
        setup.conn, value,
        Ipv4Address::from_string("10.0.0.1", 5000),
        peer_connect::FIREWALL_CONSISTENT,
        {Ipv4Address::from_string("5.6.7.8", 49737)});

    EXPECT_FALSE(reply.value.empty());
    EXPECT_TRUE(reply.should_punch);  // Client is punching → we should too
    EXPECT_EQ(reply.remote_firewall, peer_connect::FIREWALL_CONSISTENT);
    EXPECT_EQ(reply.remote_addresses.size(), 1u);
}

// JS parity: server.js:553-574 — when throttle flag fires on a random punch
// the server responds with TRY_LATER and does NOT start probing.
TEST(ServerHolepunch, RandomThrottledReturnsTryLater) {
    auto setup = make_test_setup();

    // Client reports RANDOM firewall and wants to punch.
    holepunch::HolepunchPayload hp;
    hp.firewall = peer_connect::FIREWALL_RANDOM;
    hp.round = 1;
    hp.punching = true;
    hp.addresses.push_back(Ipv4Address::from_string("10.0.0.1", 5000));

    auto value = make_client_holepunch(*setup.client_secure, hp);

    auto reply = handle_holepunch(
        setup.conn, value,
        Ipv4Address::from_string("10.0.0.1", 5000),
        peer_connect::FIREWALL_CONSISTENT,
        {Ipv4Address::from_string("5.6.7.8", 49737)},
        /*is_server_relay*/ false,
        /*random_throttled*/ true);

    EXPECT_TRUE(reply.try_later);
    EXPECT_FALSE(reply.should_punch);  // MUST NOT start probing when throttled
    ASSERT_FALSE(reply.value.empty());

    auto resp_msg = holepunch::decode_holepunch_msg(reply.value.data(), reply.value.size());
    auto decrypted = setup.client_secure->decrypt(
        resp_msg.payload.data(), resp_msg.payload.size());
    ASSERT_TRUE(decrypted.has_value());
    auto resp = holepunch::decode_holepunch_payload(
        decrypted->data(), decrypted->size());
    EXPECT_EQ(resp.error, peer_connect::ERROR_TRY_LATER);
}

// Throttle flag is only honored when at least one side is RANDOM.
// Two CONSISTENT peers are unaffected even with `random_throttled = true`.
TEST(ServerHolepunch, ThrottleIgnoredOnConsistentConsistent) {
    auto setup = make_test_setup();

    holepunch::HolepunchPayload hp;
    hp.firewall = peer_connect::FIREWALL_CONSISTENT;
    hp.round = 1;
    hp.punching = true;
    hp.addresses.push_back(Ipv4Address::from_string("10.0.0.1", 5000));

    auto value = make_client_holepunch(*setup.client_secure, hp);

    auto reply = handle_holepunch(
        setup.conn, value,
        Ipv4Address::from_string("10.0.0.1", 5000),
        peer_connect::FIREWALL_CONSISTENT,
        {Ipv4Address::from_string("5.6.7.8", 49737)},
        /*is_server_relay*/ false,
        /*random_throttled*/ true);

    EXPECT_FALSE(reply.try_later);
    EXPECT_TRUE(reply.should_punch);  // Consistent-consistent: punch normally.
}

TEST(ServerHolepunch, ClientErrorAborts) {
    auto setup = make_test_setup();

    // Client sends an error
    holepunch::HolepunchPayload hp;
    hp.error = peer_connect::ERROR_ABORTED;
    hp.round = 0;

    auto value = make_client_holepunch(*setup.client_secure, hp);

    auto reply = handle_holepunch(
        setup.conn, value,
        Ipv4Address::from_string("10.0.0.1", 5000),
        peer_connect::FIREWALL_CONSISTENT, {});

    EXPECT_FALSE(reply.value.empty());
    EXPECT_FALSE(reply.should_punch);

    // Server's reply should also be an error
    auto resp_msg = holepunch::decode_holepunch_msg(reply.value.data(), reply.value.size());
    auto decrypted = setup.client_secure->decrypt(
        resp_msg.payload.data(), resp_msg.payload.size());
    ASSERT_TRUE(decrypted.has_value());

    auto resp = holepunch::decode_holepunch_payload(
        decrypted->data(), decrypted->size());
    EXPECT_EQ(resp.error, peer_connect::ERROR_ABORTED);
}

TEST(ServerHolepunch, NoSecureFails) {
    ServerConnection conn;
    conn.secure = nullptr;  // No holepunch secret

    auto reply = handle_holepunch(
        conn, {0x00}, Ipv4Address::from_string("10.0.0.1", 5000),
        peer_connect::FIREWALL_CONSISTENT, {});

    EXPECT_TRUE(reply.value.empty());
}
