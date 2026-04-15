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
#include "hyperdht/messages.hpp"
#include "hyperdht/nat_sampler.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/socket_pool.hpp"

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
    compact::Ipv4Address address;       // Peer's address to connect to
    uint32_t firewall = 0;              // Peer's firewall status
    udx_socket_t* socket = nullptr;     // Socket that received the probe (JS: ref.socket)
    // Keeps the pool socket alive while the UDX stream uses it. The raw
    // `socket` pointer above points into this object. Caller must hold
    // this shared_ptr for the stream's lifetime (type-erased PoolSocket).
    std::shared_ptr<void> socket_keepalive;
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

// ---------------------------------------------------------------------------
// PoolSocket — lightweight UDP socket for holepunch probing
// ---------------------------------------------------------------------------
// JS: dht._socketPool.acquire() returns a fresh socket per holepunch.
// This is a stripped-down RPC sender: encode request → send → match TID.
// No congestion, no drain, no routing — just PING (for NAT discovery)
// and probe send/recv.

class PoolSocket {
public:
    PoolSocket(uv_loop_t* loop, udx_t* udx);
    ~PoolSocket();

    PoolSocket(const PoolSocket&) = delete;
    PoolSocket& operator=(const PoolSocket&) = delete;

    int bind();
    bool is_bound() const { return bound_; }

    // Send an RPC request from this socket. Minimal: no retries, 2s timeout.
    void request(const messages::Request& req,
                 rpc::OnResponseCallback on_response,
                 rpc::OnTimeoutCallback on_timeout = nullptr);

    // Probes
    void send_probe(const compact::Ipv4Address& to);
    void send_probe_ttl(const compact::Ipv4Address& to, int ttl);
    void on_holepunch_probe(rpc::OnProbeCallback cb) { on_probe_ = std::move(cb); }

    // NAT sampler (fed from PING responses)
    nat::NatSampler& nat_sampler() { return nat_sampler_; }
    const std::vector<compact::Ipv4Address>& addresses() const {
        return nat_sampler_.addresses();
    }

    void close();
    udx_socket_t* socket_handle() { return &socket_; }
    bool is_closing() const { return closing_; }

private:
    struct Inflight {
        uint16_t tid = 0;
        rpc::OnResponseCallback on_response;
        rpc::OnTimeoutCallback on_timeout;
        uv_timer_t* timer = nullptr;
        PoolSocket* pool = nullptr;  // Back-pointer for timer callback cleanup
    };

    uv_loop_t* loop_;
    udx_socket_t socket_{};
    bool bound_ = false;
    bool closing_ = false;

    nat::NatSampler nat_sampler_;
    uint16_t next_tid_ = 0;
    std::vector<Inflight*> inflight_;
    rpc::OnProbeCallback on_probe_;

    void handle_message(const uint8_t* data, size_t len,
                        const struct sockaddr_in* addr);
    static void on_recv(udx_socket_t* socket, ssize_t nread,
                        const uv_buf_t* buf, const struct sockaddr* addr);
};

// Discover pool socket's external address by PINGing DHT nodes.
// Calls on_done(true) when enough samples collected, false on failure.
void discover_pool_addresses(
    PoolSocket& pool,
    const routing::RoutingTable& table,
    const compact::Ipv4Address& relay_addr,
    std::function<void(bool)> on_done);

// ---------------------------------------------------------------------------
// Holepuncher — the UDP probe engine
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Punch stats — shared counters for throttling (JS: dht._randomPunches, stats)
// ---------------------------------------------------------------------------

struct PunchStats {
    int random_punches = 0;          // Active random punch count
    uint64_t last_random_punch = 0;  // Timestamp of last random punch completion
    int punches_consistent = 0;      // Total consistent punches attempted
    int punches_random = 0;          // Total random punches attempted
    int punches_open = 0;            // Total OPEN-firewall direct connects (B2)
    int random_punch_limit = 1;      // Max concurrent random punches (JS default: 1)
    uint64_t random_punch_interval = 20000;  // Min ms between random punches (JS: 20s)

    // JS: roundPunch rate-limit check (connect.js:638-664)
    bool can_random_punch(uint64_t now) const {
        if (random_punches >= random_punch_limit) return false;
        if (last_random_punch > 0 && (now - last_random_punch) < random_punch_interval) return false;
        return true;
    }
};

// Holepunch strategy constants
constexpr int BIRTHDAY_SOCKETS = 256;
constexpr int HOLEPUNCH_TTL = 5;
constexpr int DEFAULT_TTL = 64;
constexpr int MAX_REOPENS = 3;
constexpr int CONSISTENT_ROUNDS = 10;
constexpr int RANDOM_PROBES_COUNT = 1750;
constexpr uint64_t CONSISTENT_INTERVAL_MS = 1000;
constexpr uint64_t RANDOM_PROBE_INTERVAL_MS = 20;

class Holepuncher {
public:
    Holepuncher(uv_loop_t* loop, bool is_initiator,
                socket_pool::SocketPool* pool = nullptr,
                PunchStats* stats = nullptr);
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

    // Callbacks
    void on_connect(OnHolepunchCallback cb) { on_connect_ = std::move(cb); }
    void on_abort(std::function<void()> cb) { on_abort_ = std::move(cb); }

    // Start punching — picks the right strategy based on firewall combo
    // Returns false if RANDOM+RANDOM (impossible)
    bool punch();

    // Stop punching
    void stop();

    // Send a single probe to an address (1 byte 0x00)
    void send_probe(const compact::Ipv4Address& addr);

    // Handle incoming UDP from a peer (success detection)
    void on_message(const compact::Ipv4Address& from,
                    udx_socket_t* recv_socket = nullptr,
                    socket_pool::SocketRef* ref = nullptr);

    // Close the timer handle. Must be called before destruction if the event
    // loop is still running. Calls on_closed when the handle is fully closed.
    void close(std::function<void()> on_closed = nullptr);

    // Destroy — release all sockets, fire abort if not connected
    void destroy();

    // Analyze local NAT stability (JS: analyze(allowReopen))
    // Returns true if NAT is stable enough for punching.
    // If unstable and allowReopen is true, increments reopen counter.
    // Calls on_done(stable) when analysis completes.
    using OnAnalyzeDone = std::function<void(bool stable)>;
    void analyze(bool allow_reopen, OnAnalyzeDone on_done);

    // Reset callback — called when analyze determines a reopen is needed.
    // The caller should: destroy the current NAT sampler, acquire a fresh socket,
    // re-sample, and call analyze() again.
    using OnResetFn = std::function<void()>;
    void on_reset(OnResetFn fn) { on_reset_ = std::move(fn); }

    // How many reopens have been attempted
    int reopen_count() const { return reopen_count_; }

    bool is_connected() const { return connected_; }
    bool is_punching() const { return punching_; }
    bool is_destroyed() const { return destroyed_; }
    bool is_randomized() const { return randomized_; }

    // Number of held socket refs (for birthday paradox tracking)
    size_t holder_count() const { return holders_.size(); }

private:
    uv_loop_t* loop_;
    bool is_initiator_;
    bool connected_ = false;
    bool punching_ = false;
    bool closing_ = false;
    bool destroyed_ = false;
    bool randomized_ = false;
    uint32_t local_firewall_ = peer_connect::FIREWALL_UNKNOWN;
    uint32_t remote_firewall_ = peer_connect::FIREWALL_UNKNOWN;

    std::vector<RemoteAddr> remote_addresses_;
    int punch_round_ = 0;
    int random_probes_left_ = 0;
    size_t birthday_index_ = 0;      // Current index for keepAliveRandomNat cycling
    int low_ttl_rounds_ = 1;         // First cycle uses low TTL (JS: lowTTLRounds)

    SendProbeFn send_fn_;
    SendProbeTtlFn send_ttl_fn_;
    OnHolepunchCallback on_connect_;
    std::function<void()> on_abort_;

    // Socket pool integration (JS: dht._socketPool)
    socket_pool::SocketPool* pool_ = nullptr;
    PunchStats* stats_ = nullptr;
    std::vector<socket_pool::SocketRef*> holders_;  // JS: _allHolders
    OnResetFn on_reset_;

    void increment_randomized();
    void decrement_randomized();

    // Heap-allocated so libuv can outlive this object during async close
    uv_timer_t* punch_timer_;

    // Strategy implementations
    void consistent_probe();          // CONSISTENT+CONSISTENT
    void random_probes();             // CONSISTENT+RANDOM
    void open_birthday_sockets();     // RANDOM+CONSISTENT: acquire sockets
    void keep_alive_random_nat();     // RANDOM+CONSISTENT: cycle through birthday sockets

    // NAT stability analysis
    bool is_unstable() const;         // JS: _unstable()
    int reopen_count_ = 0;            // Tracks reopen attempts (max MAX_REOPENS)

    bool is_done() const { return destroyed_ || connected_; }

    bool is_verified(const std::string& host) const {
        for (const auto& ra : remote_addresses_) {
            if (ra.verified && ra.addr.host_string() == host) return true;
        }
        return false;
    }

    // Find first verified remote address (for random strategies)
    const RemoteAddr* verified_remote() const {
        for (const auto& ra : remote_addresses_) {
            if (ra.verified) return &ra;
        }
        return nullptr;
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
// 1. (optional) Fast-open: low-TTL probe to peer_addr to prime NAT mapping
// 2. Send probe round (our firewall + addresses) via relay
// 3. Receive server's firewall + addresses
// 4. If server is reachable, start UDP probing
// 5. Call on_done with the result
//
// hs_result: completed PEER_HANDSHAKE result
// relay_addr: the DHT node that relayed the handshake
// socket: RPC socket for sending PEER_HOLEPUNCH messages
// on_done: called when holepunch completes or fails
// peer_addr: the server's address as seen by the relay (from holepunch relays info)
// local_firewall: our firewall type from NAT sampling (or FIREWALL_UNKNOWN)
// local_addresses: our detected public addresses (from NAT sampler)
// fast_open: if true, send a low-TTL (5) probe to peer_addr before Round 1.
//            Primes our NAT mapping so the first round-trip is closer to
//            immediate on CONSISTENT+CONSISTENT NATs. Matches JS opts.fastOpen.
void holepunch_connect(rpc::RpcSocket& socket,
                       const peer_connect::HandshakeResult& hs_result,
                       const compact::Ipv4Address& relay_addr,
                       const compact::Ipv4Address& peer_addr,
                       uint32_t holepunch_id,
                       uint32_t local_firewall,
                       const std::vector<compact::Ipv4Address>& local_addresses,
                       OnHolepunchCallback on_done,
                       bool fast_open = true);

// ---------------------------------------------------------------------------
// Utility functions (JS: Holepuncher.localAddresses, Holepuncher.matchAddress)
// ---------------------------------------------------------------------------

// Get all local IPv4 addresses from network interfaces.
// Returns addresses with the given port. Excludes internal (loopback).
// Falls back to 127.0.0.1 if no external addresses found.
std::vector<compact::Ipv4Address> local_addresses(uint16_t port);

// Find the best matching remote address for LAN connections.
// Matches by IP prefix: 3-octet match (same /24) > 2-octet > 1-octet.
// Returns std::nullopt if no match found.
//
// Returns by value (not pointer) so callers don't need to reason about
// the lifetime of the input vectors. The returned address is a copy.
std::optional<compact::Ipv4Address> match_address(
    const std::vector<compact::Ipv4Address>& my_addresses,
    const std::vector<compact::Ipv4Address>& remote_addresses);

}  // namespace holepunch
}  // namespace hyperdht
