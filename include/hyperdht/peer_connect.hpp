#pragma once

// PEER_HANDSHAKE — Noise IK handshake via DHT relay.
// Exchanges Noise msg1/msg2 through DHT nodes that store the target's
// announcement. The noisePayload (encrypted by Noise) carries connection
// metadata: addresses, UDX stream ID, firewall status.

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "hyperdht/compact.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/rpc.hpp"

namespace hyperdht {
namespace peer_connect {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Handshake/holepunch message modes (from router.js)
constexpr uint32_t MODE_FROM_CLIENT = 0;
constexpr uint32_t MODE_FROM_SERVER = 1;
constexpr uint32_t MODE_FROM_RELAY = 2;
constexpr uint32_t MODE_FROM_SECOND_RELAY = 3;
constexpr uint32_t MODE_REPLY = 4;

// Firewall status
constexpr uint32_t FIREWALL_UNKNOWN = 0;
constexpr uint32_t FIREWALL_OPEN = 1;
constexpr uint32_t FIREWALL_CONSISTENT = 2;
constexpr uint32_t FIREWALL_RANDOM = 3;

// Error codes
constexpr uint32_t ERROR_NONE = 0;
constexpr uint32_t ERROR_ABORTED = 1;
constexpr uint32_t ERROR_VERSION_MISMATCH = 2;
constexpr uint32_t ERROR_TRY_LATER = 3;

// ---------------------------------------------------------------------------
// UDX connection info (from noisePayload)
// ---------------------------------------------------------------------------

struct UdxInfo {
    uint32_t version = 1;
    bool reusable_socket = false;
    uint32_t id = 0;    // UDX stream ID
    uint32_t seq = 0;
};

// ---------------------------------------------------------------------------
// NoisePayload — the data encrypted inside Noise messages
// ---------------------------------------------------------------------------

struct RelayInfo {
    compact::Ipv4Address relay_address;
    compact::Ipv4Address peer_address;
};

struct HolepunchInfo {
    uint32_t id = 0;
    std::vector<RelayInfo> relays;
};

struct RelayThroughInfo {
    uint32_t version = 1;
    std::array<uint8_t, 32> public_key{};
    std::array<uint8_t, 32> token{};
};

struct NoisePayload {
    uint32_t version = 1;
    uint32_t error = ERROR_NONE;
    uint32_t firewall = FIREWALL_UNKNOWN;

    // Optional fields (flag bits)
    std::optional<HolepunchInfo> holepunch;               // bit 0
    std::vector<compact::Ipv4Address> addresses4;         // bit 1
    std::vector<compact::Ipv6Address> addresses6;         // bit 2
    std::optional<UdxInfo> udx;                           // bit 3
    bool has_secret_stream = false;                       // bit 4
    std::optional<RelayThroughInfo> relay_through;        // bit 5
    std::vector<compact::Ipv4Address> relay_addresses;    // bit 6
};

// Encode/decode noisePayload
std::vector<uint8_t> encode_noise_payload(const NoisePayload& p);
NoisePayload decode_noise_payload(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// Handshake message — the DHT RPC value wrapping Noise bytes
// ---------------------------------------------------------------------------

struct HandshakeMessage {
    uint32_t mode = MODE_FROM_CLIENT;
    std::vector<uint8_t> noise;  // Raw Noise msg1 or msg2 bytes
    std::optional<compact::Ipv4Address> peer_address;
    std::optional<compact::Ipv4Address> relay_address;
};

std::vector<uint8_t> encode_handshake_msg(const HandshakeMessage& m);
HandshakeMessage decode_handshake_msg(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// Handshake result — returned after successful PEER_HANDSHAKE
// ---------------------------------------------------------------------------

struct HandshakeResult {
    bool success = false;
    noise::Key tx_key;
    noise::Key rx_key;
    noise::Hash handshake_hash;
    std::array<uint8_t, 32> remote_public_key;
    NoisePayload remote_payload;  // Server's connection metadata
};

// Callback for handshake completion
using OnHandshakeCallback = std::function<void(const HandshakeResult& result)>;

// ---------------------------------------------------------------------------
// peer_handshake — initiate a Noise IK handshake through a DHT relay
// ---------------------------------------------------------------------------

// Sends PEER_HANDSHAKE to a relay node that stores the target's announcement.
// relay_addr: address of a DHT node that responded to findPeer with a value
// our_keypair: our Ed25519 keypair
// remote_pubkey: the target's public key (known from findPeer)
// our_udx_id: our UDX stream ID for the connection
// firewall: our firewall status (OPEN if public, UNKNOWN if behind NAT)
// addresses4: our addresses to advertise (public addr if OPEN + validated LAN)
//   JS: connect.js:386-394 — remoteAddress() + localAddresses(serverSocket)
void peer_handshake(rpc::RpcSocket& socket,
                    const compact::Ipv4Address& relay_addr,
                    const noise::Keypair& our_keypair,
                    const noise::PubKey& remote_pubkey,
                    uint32_t our_udx_id,
                    uint32_t firewall,
                    const std::vector<compact::Ipv4Address>& addresses4,
                    OnHandshakeCallback on_done);

// Overload that includes relayThrough in the Noise payload (Phase E).
// JS: connect.js:409-410 — relayThrough: { publicKey, token }
void peer_handshake(rpc::RpcSocket& socket,
                    const compact::Ipv4Address& relay_addr,
                    const noise::Keypair& our_keypair,
                    const noise::PubKey& remote_pubkey,
                    uint32_t our_udx_id,
                    uint32_t firewall,
                    const std::vector<compact::Ipv4Address>& addresses4,
                    const std::optional<RelayThroughInfo>& relay_through,
                    OnHandshakeCallback on_done);

}  // namespace peer_connect
}  // namespace hyperdht
