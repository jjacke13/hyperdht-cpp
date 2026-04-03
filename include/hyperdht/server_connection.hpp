#pragma once

// Server-side connection handling — processes incoming PEER_HANDSHAKE
// as Noise IK responder, derives keys, and manages the connection state
// through holepunching to stream establishment.

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "hyperdht/compact.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"

namespace hyperdht {
namespace server_connection {

// ---------------------------------------------------------------------------
// ServerConnection — per-incoming-connection state on the server side
// ---------------------------------------------------------------------------

struct ServerConnection {
    int id = -1;                      // Holepunch slot ID
    int round = 0;                    // Current holepunch round

    // Noise handshake results
    noise::Key tx_key{};
    noise::Key rx_key{};
    noise::Hash handshake_hash{};
    std::array<uint8_t, 32> remote_public_key{};
    peer_connect::NoisePayload remote_payload;

    // Our reply (Noise msg2 bytes)
    std::vector<uint8_t> reply_noise;

    // Holepunch encryption
    std::unique_ptr<holepunch::SecurePayload> secure;

    // UDX stream ID we assigned
    uint32_t local_udx_id = 0;

    // Server's address info for the response
    uint32_t our_firewall = peer_connect::FIREWALL_UNKNOWN;
    std::vector<compact::Ipv4Address> our_addresses;

    // State flags
    bool firewalled = false;   // Rejected by firewall callback
    bool has_error = false;
    uint32_t error_code = peer_connect::ERROR_NONE;
};

// ---------------------------------------------------------------------------
// Firewall callback type
// ---------------------------------------------------------------------------

using FirewallFn = std::function<bool(
    const std::array<uint8_t, 32>& remote_public_key,
    const peer_connect::NoisePayload& remote_payload,
    const compact::Ipv4Address& client_address)>;

// ---------------------------------------------------------------------------
// handle_handshake — process incoming PEER_HANDSHAKE as Noise IK responder
// ---------------------------------------------------------------------------

// Processes the incoming Noise msg1 from a client, performs the server-side
// Noise IK handshake, and returns the connection state + reply Noise msg2.
//
// server_keypair: the server's Ed25519 keypair
// noise_msg1: the raw Noise message from the client
// client_address: the client's address as seen by the relay
// firewall: optional callback to reject connections (return true to reject)
// holepunch_id: the slot ID for this connection's holepunch session
// relay_addresses: our relay addresses from the Announcer
//
// Returns: populated ServerConnection, or nullopt on failure.
// On success, reply_noise contains the Noise msg2 to send back.
std::optional<ServerConnection> handle_handshake(
    const noise::Keypair& server_keypair,
    const std::vector<uint8_t>& noise_msg1,
    const compact::Ipv4Address& client_address,
    int holepunch_id,
    const std::vector<compact::Ipv4Address>& our_addresses,
    const std::vector<peer_connect::RelayInfo>& relay_infos,
    FirewallFn firewall = nullptr);

// ---------------------------------------------------------------------------
// handle_holepunch — process incoming PEER_HOLEPUNCH on the server side
// ---------------------------------------------------------------------------

// Processes an encrypted holepunch payload from the client.
// conn: the ServerConnection from handle_handshake (must have conn.secure set)
// value: the raw PEER_HOLEPUNCH message value (encrypted)
// client_address: the client's address as seen by the relay
//
// Returns: encrypted reply value (for the response), or empty on error.
// Side effects: updates conn.round, may start server-side probing.
struct HolepunchReply {
    std::vector<uint8_t> value;      // Encrypted reply payload
    bool should_punch = false;        // True if server should start probing
    uint32_t remote_firewall = 0;     // Client's reported firewall
    std::vector<compact::Ipv4Address> remote_addresses;  // Client's addresses to probe
};

HolepunchReply handle_holepunch(
    ServerConnection& conn,
    const std::vector<uint8_t>& value,
    const compact::Ipv4Address& client_address,
    uint32_t our_firewall,
    const std::vector<compact::Ipv4Address>& our_addresses);

}  // namespace server_connection
}  // namespace hyperdht
