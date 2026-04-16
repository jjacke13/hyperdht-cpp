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
#include "hyperdht/async_utils.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"
#include "hyperdht/server_connection.hpp"

namespace hyperdht {

// Forward declaration — Server holds a non-owning `HyperDHT*`
// back-pointer (§16) but can't include `dht.hpp` to avoid a circular
// include. Full type is included in `src/server.cpp` where needed.
class HyperDHT;

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
    udx_socket_t* udx_socket = nullptr; // Socket that received the probe (JS: ref.socket)
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

    // Async firewall callback — receives a completion handler the user
    // must invoke with the accept/reject decision. JS parity for
    // `await this.firewall(...)` at server.js:251: enables policy
    // lookups that hit a DB / remote service without blocking the
    // event loop.
    //
    // Usage:
    //   server->set_firewall_async([](auto pk, auto payload, auto addr,
    //                                 auto done) {
    //       db->check(pk, [done](bool found) {
    //           done(/*reject=*/!found);
    //       });
    //   });
    //
    // The completion handler must be invoked EXACTLY once. If it's
    // never called, the handshake stalls until the session timer
    // (`handshake_clear_wait`, default 10s) GCs the state.
    //
    // Sync and async callbacks are mutually exclusive. Installing one
    // clears the other.
    using FirewallDoneCb = std::function<void(bool reject)>;
    using AsyncFirewallCb = std::function<void(
        const std::array<uint8_t, 32>& remote_pk,
        const peer_connect::NoisePayload& payload,
        const compact::Ipv4Address& client_addr,
        FirewallDoneCb done)>;

    // Forward declaration — server can call back into the DHT for the
    // cached validated local-address list (§16).
    Server(rpc::RpcSocket& socket, router::Router& router);

    // §16: constructor overload with a HyperDHT back-pointer so the
    // server can read `dht->validated_local_addresses()` when building
    // its handshake reply. Without the back-pointer, `share_local_address`
    // silently drops the LAN addrs.
    Server(rpc::RpcSocket& socket, router::Router& router, HyperDHT* dht);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Start listening at the given keypair.
    // on_connection is called for each new peer that connects.
    void listen(const noise::Keypair& keypair, OnConnectionCb on_connection);

    // JS: `emit('listening')` — server.js:195. Fires once the announcer
    // has been started and the server is fully ready to accept peers.
    // Our listen() is synchronous, so the callback fires on the same
    // tick as listen() returns (unlike JS which awaits internal async).
    //
    // A later listen() / close()+listen() cycle re-arms the hook.
    using OnListeningCb = std::function<void()>;
    void on_listening(OnListeningCb cb) { on_listening_cb_ = std::move(cb); }

    // Stop listening: stop announcer, remove from router, clean up
    // connections.
    //
    // `force = false` (default): announcer emits UNANNOUNCE to its
    // active relays before tearing down — peers learn we're gone.
    //
    // `force = true`: skip UNANNOUNCE emission; still stops libuv
    // handles so the event loop can drain. Matches JS
    // `dht.destroy({ force: true })` intent.
    void close(bool force, std::function<void()> on_done = nullptr);
    void close(std::function<void()> on_done = nullptr);  // force=false

    // Set firewall callback (return true to reject a connection)
    // Install a synchronous firewall callback. Clears any async callback.
    void set_firewall(FirewallCb cb) {
        firewall_ = std::move(cb);
        firewall_async_ = nullptr;
    }
    // Install an async firewall callback. Clears any sync callback.
    void set_firewall_async(AsyncFirewallCb cb) {
        firewall_async_ = std::move(cb);
        firewall_ = nullptr;
    }

    // Holepunch veto callback (JS: opts.holepunch)
    // Called during holepunch negotiation. Return false to abort.
    // Args: remote_fw, local_fw, remote_addrs, local_addrs
    using HolepunchCb = std::function<bool(
        uint32_t remote_fw, uint32_t local_fw,
        const std::vector<compact::Ipv4Address>& remote_addrs,
        const std::vector<compact::Ipv4Address>& local_addrs)>;
    void set_holepunch(HolepunchCb cb) { holepunch_cb_ = std::move(cb); }

    // Suspend: stop announcer, clear pending holepunches (JS: server.suspend()).
    //
    // Optional `log` sink mirrors JS `server.suspend({ log })` where the
    // log function is called with progress messages across the suspend
    // phases (pre-listening gate, clear-all, announcer.suspend). Pass
    // `nullptr` / default for a silent suspend.
    using LogFn = std::function<void(const char*)>;
    void suspend(LogFn log = nullptr);
    // Resume: restart announcer (JS: server.resume())
    void resume();

    // Refresh announcements
    void refresh();

    // JS: `server.notifyOnline()` — called by the DHT when a network-update
    // fires after coming back online. Wakes the announcer so it re-queries
    // its relays immediately instead of waiting for the next background tick.
    // No-op if closed, suspended, or not listening.
    void notify_online();

    // Server's listening address (JS: `server.address()`).
    //
    // Contract:
    //  - Before listen(): returns an all-zero sentinel (JS returns `null`).
    //    Callers should check `is_listening()` or `public_key != {0}`.
    //  - After listen() but before NAT sampling: `public_key` is set but
    //    `host` is empty and `port` is 0. The NAT sampler needs responses
    //    from ≥1 node to fill them in, and classification takes ≥3 samples.
    //  - After NAT sampling: `host`/`port` reflect the public address as
    //    seen by the network (JS: `dht.host`/`dht.port` → `nat._host/_port`).
    //
    // The bound local socket port is intentionally NOT reported here — it
    // would lie about reachability on NAT'd nodes.
    struct AddressInfo {
        noise::PubKey public_key{};  // zero-initialized; serves as "null" sentinel
        std::string host;
        uint16_t port = 0;
    };
    AddressInfo address() const;

    // State
    bool is_listening() const { return listening_; }
    bool is_closed() const { return closed_; }
    bool is_suspended() const { return suspended_; }
    const noise::PubKey& public_key() const { return keypair_.public_key; }
    const std::vector<peer_connect::RelayInfo>& relay_addresses() const;

    // Configuration (JS: opts)
    bool share_local_address = true;   // JS: opts.shareLocalAddress (default true)
    uint64_t handshake_clear_wait = 10000;  // JS: opts.handshakeClearWait (default 10s)

    // Blind-relay options (Phase E)
    // JS: server.js:28-29 — this.relayThrough, this.relayKeepAlive
    //
    // `relay_through`: public key of a node to relay through. When set,
    // the server includes `relayThrough: { publicKey, token }` in the
    // Noise payload, enabling the client to connect via relay.
    // Can be empty (default, no relay).
    std::optional<noise::PubKey> relay_through;
    uint64_t relay_keep_alive = 5000;  // JS default: 5000ms

private:
    rpc::RpcSocket& socket_;
    router::Router& router_;
    // §16 non-owning back-pointer: optional, may be null for tests that
    // construct Server directly without a HyperDHT owner. When non-null
    // the server queries `dht_->validated_local_addresses()` during
    // handshake reply construction if `share_local_address == true`.
    //
    // Lifetime invariant: every Server that carries a non-null `dht_`
    // must outlive its parent HyperDHT's `servers_` vector (the
    // `unique_ptr` ownership guarantees this in normal usage because
    // HyperDHT::destroy() only finishes after all servers have been
    // closed). Standalone test Servers always pass the 2-arg ctor and
    // get `dht_ == nullptr`.
    HyperDHT* dht_ = nullptr;

    noise::Keypair keypair_;
    std::array<uint8_t, 32> target_{};
    std::unique_ptr<announcer::Announcer> announcer_;
    OnConnectionCb on_connection_;
    FirewallCb firewall_;
    AsyncFirewallCb firewall_async_;
    HolepunchCb holepunch_cb_;
    OnListeningCb on_listening_cb_;

    bool listening_ = false;
    bool closed_ = false;
    bool suspended_ = false;

    // Liveness sentinel for async callbacks. Captured by `std::weak_ptr`
    // in user-facing continuation lambdas (notably the `FirewallDoneCb`
    // passed to `AsyncFirewallCb`) so they can safely detect a
    // destroyed Server without dereferencing `this`. Flipped to `false`
    // in `close()` and the destructor — any lambda that locks the
    // weak_ptr and sees `*alive_ == false` must bail out.
    //
    // Matches the `HyperDHT::alive_` pattern (src/dht.cpp, the
    // `*alive_ = false` line in `destroy()`).
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);

    // Probe echo listener ID (0 = not installed).
    // Installed once on first holepunch, removed on close.
    uint32_t probe_listener_id_ = 0;

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
    void on_raw_stream_firewall(udx_stream_t* stream, udx_socket_t* socket,
                               const struct sockaddr* from);
private:

    // Per-session cleanup — uses configurable handshake_clear_wait
    std::unordered_map<uint32_t, std::unique_ptr<async_utils::UvTimer>> session_timers_;
    void clear_session(uint32_t hp_id);

    // Router callbacks
    void on_peer_handshake(const std::vector<uint8_t>& noise,
                           const compact::Ipv4Address& peer_address,
                           std::function<void(std::vector<uint8_t>)> reply_fn);

    void on_peer_holepunch(const std::vector<uint8_t>& value,
                           const compact::Ipv4Address& peer_address,
                           std::function<void(std::vector<uint8_t>)> reply_fn);

    // Common post-handshake work: send reply, set up rawStream, attach
    // blind-relay (if configured), store session state, arm session timer.
    // Shared by the sync firewall path (called inline from
    // on_peer_handshake) and the async firewall path (called from the
    // user completion callback).
    void on_handshake_result(
        uint32_t hp_id,
        std::string noise_key,
        bool has_remote_addr,
        std::optional<peer_connect::RelayThroughInfo> relay_through_info,
        std::function<void(std::vector<uint8_t>)> reply_fn,
        std::optional<server_connection::ServerConnection> result);

    // Called when holepunch or direct connect succeeds
    void on_socket(server_connection::ServerConnection& conn,
                   const compact::Ipv4Address& peer_addr,
                   udx_socket_t* udx_sock = nullptr);
};

}  // namespace server
}  // namespace hyperdht
