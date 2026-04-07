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
#include "hyperdht/rpc.hpp"

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

// Callback for sending a UDP probe to an address
using SendProbeFn = std::function<void(const compact::Ipv4Address& addr)>;
// Callback for sending a probe with custom TTL (JS: openSession uses TTL=5)
using SendProbeTtlFn = std::function<void(const compact::Ipv4Address& addr, int ttl)>;

// Remote address with verification status (JS: addr.verified in holepuncher.js)
struct RemoteAddr {
    compact::Ipv4Address addr;
    bool verified = false;
};

class Holepuncher {
public:
    Holepuncher(uv_loop_t* loop, bool is_initiator);
    ~Holepuncher();

    Holepuncher(const Holepuncher&) = delete;
    Holepuncher& operator=(const Holepuncher&) = delete;

    // Set the function used to send UDP probes (typically RpcSocket::send_probe)
    void set_send_fn(SendProbeFn fn) { send_fn_ = std::move(fn); }
    void set_send_ttl_fn(SendProbeTtlFn fn) { send_ttl_fn_ = std::move(fn); }

    // JS: openSession(addr) — send low-TTL (5) probe to prime NAT mapping
    void open_session(const compact::Ipv4Address& addr);

    // Set our firewall type and the remote's
    void set_local_firewall(uint32_t fw) { local_firewall_ = fw; }
    void set_remote_firewall(uint32_t fw) { remote_firewall_ = fw; }

    // Set target addresses (all unverified)
    void set_remote_addresses(const std::vector<compact::Ipv4Address>& addrs) {
        remote_addresses_.clear();
        for (const auto& a : addrs) remote_addresses_.push_back({a, false});
    }

    // JS: updateRemote — set addresses with optional verified host
    void update_remote(const std::vector<compact::Ipv4Address>& addrs,
                       const std::string& verified_host = "") {
        remote_addresses_.clear();
        for (const auto& a : addrs) {
            bool v = (!verified_host.empty() && a.host_string() == verified_host) ||
                     is_verified(a.host_string());
            remote_addresses_.push_back({a, v});
        }
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

    // Close the timer handle. Must be called before destruction if the event
    // loop is still running. Calls on_closed when the handle is fully closed.
    void close(std::function<void()> on_closed = nullptr);

    bool is_connected() const { return connected_; }
    bool is_punching() const { return punching_; }

private:
    uv_loop_t* loop_;
    bool is_initiator_;
    bool connected_ = false;
    bool punching_ = false;
    bool closing_ = false;
    uint32_t local_firewall_ = peer_connect::FIREWALL_UNKNOWN;
    uint32_t remote_firewall_ = peer_connect::FIREWALL_UNKNOWN;

    std::vector<RemoteAddr> remote_addresses_;
    int punch_round_ = 0;
    int random_probes_left_ = 0;

    SendProbeFn send_fn_;
    SendProbeTtlFn send_ttl_fn_;
    OnHolepunchCallback on_connect_;

    // Heap-allocated so libuv can outlive this object during async close
    uv_timer_t* punch_timer_;

    // Strategy implementations
    void consistent_probe();   // CONSISTENT+CONSISTENT
    void random_probes();      // CONSISTENT+RANDOM
    // RANDOM+CONSISTENT would need multiple sockets — simplified for now

    bool is_verified(const std::string& host) const {
        for (const auto& ra : remote_addresses_) {
            if (ra.verified && ra.addr.host_string() == host) return true;
        }
        return false;
    }

    static void on_punch_timer(uv_timer_t* timer);
};

// ---------------------------------------------------------------------------
// PEER_HOLEPUNCH RPC message (wraps encrypted HolepunchPayload)
// ---------------------------------------------------------------------------

struct HolepunchMessage {
    uint32_t mode = 0;        // FROM_CLIENT=0, FROM_RELAY=1, etc.
    uint32_t id = 0;          // Holepunch session ID (from PEER_HANDSHAKE response)
    std::vector<uint8_t> payload;  // Encrypted HolepunchPayload
    std::optional<compact::Ipv4Address> peer_address;
};

std::vector<uint8_t> encode_holepunch_msg(const HolepunchMessage& m);
HolepunchMessage decode_holepunch_msg(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// holepunch_connect — full relay round-trip to establish a direct connection
// ---------------------------------------------------------------------------

// Performs the PEER_HOLEPUNCH relay flow:
// 1. Send probe round (our firewall + addresses) via relay
// 2. Receive server's firewall + addresses
// 3. If server is reachable, start UDP probing
// 4. Call on_done with the result
//
// hs_result: completed PEER_HANDSHAKE result
// relay_addr: the DHT node that relayed the handshake
// socket: RPC socket for sending PEER_HOLEPUNCH messages
// on_done: called when holepunch completes or fails
// peer_addr: the server's address as seen by the relay (from holepunch relays info)
// local_firewall: our firewall type from NAT sampling (or FIREWALL_UNKNOWN)
// local_addresses: our detected public addresses (from NAT sampler)
void holepunch_connect(rpc::RpcSocket& socket,
                       const peer_connect::HandshakeResult& hs_result,
                       const compact::Ipv4Address& relay_addr,
                       const compact::Ipv4Address& peer_addr,
                       uint32_t holepunch_id,
                       uint32_t local_firewall,
                       const std::vector<compact::Ipv4Address>& local_addresses,
                       OnHolepunchCallback on_done);

}  // namespace holepunch
}  // namespace hyperdht
