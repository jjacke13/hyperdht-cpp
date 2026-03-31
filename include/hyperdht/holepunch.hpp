#pragma once

// PEER_HOLEPUNCH — NAT traversal for direct P2P connections.
//
// Strategies (based on firewall combo):
//   OPEN+any:             Direct connect, no punching needed
//   CONSISTENT+CONSISTENT: 10 rounds of UDP probes, 1s apart
//   CONSISTENT+RANDOM:    1750 probes to random ports (~35s)
//   RANDOM+CONSISTENT:    256 birthday-paradox sockets
//   RANDOM+RANDOM:        Impossible — fail
//
// Holepunch payloads are encrypted with XSalsa20-Poly1305 using
// the holepunchSecret derived from the Noise handshake hash.

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include <uv.h>

#include "hyperdht/compact.hpp"
#include "hyperdht/peer_connect.hpp"

namespace hyperdht {
namespace holepunch {

// ---------------------------------------------------------------------------
// SecurePayload — encrypt/decrypt holepunch messages
// ---------------------------------------------------------------------------

class SecurePayload {
public:
    // key = holepunchSecret from Noise handshake
    explicit SecurePayload(const std::array<uint8_t, 32>& key);

    // Encrypt a holepunch payload.
    // Output: nonce(24) + ciphertext + mac(16)
    std::vector<uint8_t> encrypt(const uint8_t* data, size_t len);

    // Decrypt a holepunch payload.
    // Input: nonce(24) + ciphertext + mac(16)
    std::optional<std::vector<uint8_t>> decrypt(const uint8_t* data, size_t len);

    // Generate a token for address verification: BLAKE2b(host, localSecret)
    std::array<uint8_t, 32> token(const std::string& host);

private:
    std::array<uint8_t, 32> shared_secret_;
    std::array<uint8_t, 32> local_secret_;
};

// ---------------------------------------------------------------------------
// HolepunchPayload — the data inside encrypted holepunch messages
// ---------------------------------------------------------------------------

struct HolepunchPayload {
    // Flag bits
    bool connected = false;    // bit 0
    bool punching = false;     // bit 1
    uint32_t error = 0;
    uint32_t firewall = 0;
    uint32_t round = 0;

    // Optional fields
    std::vector<compact::Ipv4Address> addresses;        // bit 2
    std::optional<compact::Ipv4Address> remote_address;  // bit 3
    std::optional<std::array<uint8_t, 32>> token;        // bit 4
    std::optional<std::array<uint8_t, 32>> remote_token;  // bit 5
};

std::vector<uint8_t> encode_holepunch_payload(const HolepunchPayload& p);
HolepunchPayload decode_holepunch_payload(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// Holepunch result
// ---------------------------------------------------------------------------

struct HolepunchResult {
    bool success = false;
    compact::Ipv4Address address;  // Peer's address to connect to
    uint32_t firewall = 0;         // Peer's firewall status
};

using OnHolepunchCallback = std::function<void(const HolepunchResult& result)>;

// ---------------------------------------------------------------------------
// try_direct_connect — OPEN firewall shortcut (no holepunch needed)
// ---------------------------------------------------------------------------

// If the remote peer's firewall is OPEN, we can connect directly
// using the address from the PEER_HANDSHAKE response.
// Returns true if direct connection is possible.
bool try_direct_connect(const peer_connect::HandshakeResult& hs,
                        HolepunchResult& result);

// ---------------------------------------------------------------------------
// Holepuncher — the UDP probe engine
// ---------------------------------------------------------------------------

class Holepuncher {
public:
    Holepuncher(uv_loop_t* loop, bool is_initiator);
    ~Holepuncher();

    Holepuncher(const Holepuncher&) = delete;
    Holepuncher& operator=(const Holepuncher&) = delete;

    // Set our firewall type and the remote's
    void set_local_firewall(uint32_t fw) { local_firewall_ = fw; }
    void set_remote_firewall(uint32_t fw) { remote_firewall_ = fw; }

    // Set target addresses to probe
    void set_remote_addresses(const std::vector<compact::Ipv4Address>& addrs) {
        remote_addresses_ = addrs;
    }

    // Set callback for when a connection is established
    void on_connect(OnHolepunchCallback cb) { on_connect_ = std::move(cb); }

    // Start punching — picks the right strategy based on firewall combo
    // Returns false if RANDOM+RANDOM (impossible)
    bool punch();

    // Stop punching
    void stop();

    // Send a single probe to an address (1 byte 0x00)
    void send_probe(const compact::Ipv4Address& addr);

    // Handle incoming UDP from a peer (success detection)
    void on_message(const compact::Ipv4Address& from);

    bool is_connected() const { return connected_; }
    bool is_punching() const { return punching_; }

    // Exposed for test cleanup (libuv requires explicit handle close)
    uv_timer_t punch_timer_;

private:
    uv_loop_t* loop_;
    bool is_initiator_;
    bool connected_ = false;
    bool punching_ = false;
    uint32_t local_firewall_ = peer_connect::FIREWALL_UNKNOWN;
    uint32_t remote_firewall_ = peer_connect::FIREWALL_UNKNOWN;

    std::vector<compact::Ipv4Address> remote_addresses_;
    int punch_round_ = 0;
    int random_probes_left_ = 0;

    OnHolepunchCallback on_connect_;

    // Strategy implementations
    void consistent_probe();   // CONSISTENT+CONSISTENT
    void random_probes();      // CONSISTENT+RANDOM
    // RANDOM+CONSISTENT would need multiple sockets — simplified for now

    static void on_punch_timer(uv_timer_t* timer);
};

}  // namespace holepunch
}  // namespace hyperdht
