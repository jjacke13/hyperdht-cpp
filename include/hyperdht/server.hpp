#pragma once

// Server — listens for incoming HyperDHT connections at a public key.
//
// Usage:
//   Server server(socket, router, handlers);
//   server.listen(keypair, [](const ConnectionInfo& info) {
//       // New encrypted connection from a peer
//   });
//   // ... later ...
//   server.close();
//
// Internally:
//   - Registers in the Router so PEER_HANDSHAKE/HOLEPUNCH are dispatched here
//   - Starts an Announcer to periodically announce on the DHT
//   - Manages per-connection state (ServerConnection) through handshake + holepunch
//   - When a peer connects, creates SecretStream and calls on_connection

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

#include "hyperdht/announcer.hpp"
#include "hyperdht/compact.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"
#include "hyperdht/server_connection.hpp"

namespace hyperdht {
namespace server {

// ---------------------------------------------------------------------------
// ConnectionInfo — passed to the on_connection callback
// ---------------------------------------------------------------------------

struct ConnectionInfo {
    noise::Key tx_key;
    noise::Key rx_key;
    noise::Hash handshake_hash;
    std::array<uint8_t, 32> remote_public_key;
    compact::Ipv4Address peer_address;
    uint32_t remote_udx_id = 0;     // Peer's UDX stream ID
    uint32_t local_udx_id = 0;      // Our UDX stream ID
    bool is_initiator = false;       // Server is always responder
    udx_stream_t* raw_stream = nullptr;  // Pre-created during handshake (like JS rawStream)
};

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

class Server {
public:
    using OnConnectionCb = std::function<void(const ConnectionInfo& info)>;
    using FirewallCb = std::function<bool(
        const std::array<uint8_t, 32>& remote_pk,
        const peer_connect::NoisePayload& payload,
        const compact::Ipv4Address& client_addr)>;

    Server(rpc::RpcSocket& socket, router::Router& router);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Start listening at the given keypair.
    // on_connection is called for each new peer that connects.
    void listen(const noise::Keypair& keypair, OnConnectionCb on_connection);

    // Stop listening: stop announcer, remove from router, clean up connections.
    void close(std::function<void()> on_done = nullptr);

    // Set firewall callback (return true to reject a connection)
    void set_firewall(FirewallCb cb) { firewall_ = std::move(cb); }

    // Refresh announcements
    void refresh();

    // State
    bool is_listening() const { return listening_; }
    bool is_closed() const { return closed_; }
    const noise::PubKey& public_key() const { return keypair_.public_key; }
    const std::vector<peer_connect::RelayInfo>& relay_addresses() const;

private:
    rpc::RpcSocket& socket_;
    router::Router& router_;

    noise::Keypair keypair_;
    std::array<uint8_t, 32> target_{};
    std::unique_ptr<announcer::Announcer> announcer_;
    OnConnectionCb on_connection_;
    FirewallCb firewall_;

    bool listening_ = false;
    bool closed_ = false;

    // Active holepunch sessions indexed by ID
    uint32_t next_hp_id_ = 0;
    std::unordered_map<uint32_t, std::unique_ptr<server_connection::ServerConnection>> connections_;

    // Handshake deduplication — JS: _connects Map keyed by noise hex string.
    // Same noise bytes (same client) arriving via different relays reuse the
    // same session instead of creating duplicates. Maps noise_hex → hp_id.
    // Entries removed when connection completes or times out.
    std::unordered_map<std::string, uint32_t> handshake_dedup_;

    // Pending punches: connections waiting for the client's UDX packet
    // to arrive via the rawStream firewall. Maps local_udx_id → hp_id.
    std::unordered_map<uint32_t, uint32_t> pending_punch_streams_;
public:
    // Called by rawStream firewall callback (static C function needs access)
    void on_raw_stream_firewall(udx_stream_t* stream, const struct sockaddr* from);
private:

    // Per-session cleanup — matches JS _clearLater / HANDSHAKE_INITIAL_TIMEOUT (10s)
    static constexpr uint64_t HP_TIMEOUT_MS = 10000;
    std::unordered_map<uint32_t, uv_timer_t*> session_timers_;
    void clear_session(uint32_t hp_id);

    // Router callbacks
    void on_peer_handshake(const std::vector<uint8_t>& noise,
                           const compact::Ipv4Address& peer_address,
                           std::function<void(std::vector<uint8_t>)> reply_fn);

    void on_peer_holepunch(const std::vector<uint8_t>& value,
                           const compact::Ipv4Address& peer_address,
                           std::function<void(std::vector<uint8_t>)> reply_fn);

    // Called when holepunch or direct connect succeeds
    void on_socket(server_connection::ServerConnection& conn,
                   const compact::Ipv4Address& peer_addr);
};

}  // namespace server
}  // namespace hyperdht
