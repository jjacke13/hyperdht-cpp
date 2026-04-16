#pragma once

// Phase 3: DHT RPC — UDP message dispatch with UDX sockets.
// Sends/receives compact-encoded DHT messages, matches responses to requests
// by transaction ID, handles timeouts, retries, congestion control, and
// periodic token rotation.

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include <udx.h>
#include <uv.h>

#include "hyperdht/compact.hpp"
#include "hyperdht/health.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/nat_sampler.hpp"
#include "hyperdht/routing_table.hpp"
#include "hyperdht/tokens.hpp"

namespace hyperdht {
namespace rpc {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr int DEFAULT_MAX_WINDOW = 80;
constexpr int DEFAULT_RETRIES = 3;
constexpr uint64_t DEFAULT_TIMEOUT_MS = 1000;
constexpr uint64_t DRAIN_INTERVAL_MS = 750;
constexpr int TOKEN_ROTATE_TICKS = 10;    // 10 * 750ms = 7.5s
constexpr uint64_t BG_TICK_MS = 5000;     // Background tick interval
constexpr int REFRESH_TICKS = 60;         // 60 * 5s = 5 minutes
constexpr int STABLE_TICKS_INIT = 240;    // 240 * 5s = 20 minutes
constexpr int STABLE_TICKS_MORE = 720;    // 720 * 5s = 60 minutes
constexpr uint64_t DEFAULT_MAX_PING_DELAY_MS = 10000;  // JS dht.maxPingDelay default (10s)

// Ping-and-swap eviction constants (match JS dht-rpc index.js)
constexpr uint32_t RECENT_NODE_TICKS = 12;   // < 1 min at 5s ticks: "recently alive"
constexpr uint32_t OLD_NODE_TICKS    = 360;  // > 30 min at 5s ticks: "well established"
constexpr int MAX_REPINGING          = 3;    // max concurrent ping-and-swap in flight
constexpr int MAX_CHECKS             = 10;   // max concurrent DOWN_HINT driven checks

// ---------------------------------------------------------------------------
// Callback types
// ---------------------------------------------------------------------------

using OnRequestCallback = std::function<void(const messages::Request& req)>;
using OnResponseCallback = std::function<void(const messages::Response& resp)>;
using OnTimeoutCallback = std::function<void(uint16_t tid)>;
using OnProbeCallback = std::function<void(const compact::Ipv4Address& from)>;

// Filter for network-observed nodes (JS `_filterNode`). Return true to
// accept, false to silently reject the peer before it enters our routing
// table or query frontier. Useful for rejecting private IPs, bogons, etc.
using FilterNodeCallback =
    std::function<bool(const routing::NodeId& id, const compact::Ipv4Address& addr)>;

// Compute the canonical peer id from an address (matches JS `peer.id()`):
// BLAKE2b-256 of the 6-byte compact ipv4 encoding (4-byte host LE + 2-byte port LE).
routing::NodeId compute_peer_id(const compact::Ipv4Address& addr);

// ---------------------------------------------------------------------------
// CongestionWindow — sliding window flow control (4 time buckets)
// ---------------------------------------------------------------------------

class CongestionWindow {
public:
    explicit CongestionWindow(int max_window = DEFAULT_MAX_WINDOW);

    bool is_full() const;
    void send();
    void recv();
    void drain();  // Called every 750ms — rotates to next bucket
    void clear();

    int total() const { return total_; }

private:
    int i_ = 0;          // Current bucket index [0-3]
    int total_ = 0;      // Total across all buckets
    int window_[4] = {}; // 4 time buckets
    int max_window_;
};

// ---------------------------------------------------------------------------
// Inflight request tracking
// ---------------------------------------------------------------------------

class RpcSocket;  // Forward declaration

struct InflightRequest {
    RpcSocket* owner = nullptr;   // Back-pointer for timeout callback
    uint16_t tid = 0;
    uint32_t command = 0;
    OnResponseCallback on_response;
    OnTimeoutCallback on_timeout;
    int sent = 0;            // Total sends so far (1 after first transmission, timeout fires when sent > retries)
    int retries = DEFAULT_RETRIES;
    uint64_t sent_at = 0;   // Timestamp of last send (for RTT measurement)
    uint64_t timeout_override_ms = 0;  // 0 = use adaptive/default; nonzero overrides (DELAYED_PING)
    std::vector<uint8_t> buffer;  // Encoded message, reused for retries
    compact::Ipv4Address to;      // Destination for retry
    uv_timer_t timer;             // Per-request timeout timer
    bool destroyed = false;
};

// ---------------------------------------------------------------------------
// RpcSocket — single UDP socket for DHT communication
// ---------------------------------------------------------------------------

class RpcSocket {
public:
    // Create an RPC socket on the given loop.
    // local_id: our 32-byte node ID
    RpcSocket(uv_loop_t* loop, const routing::NodeId& local_id);
    ~RpcSocket();

    // Non-copyable, non-movable
    RpcSocket(const RpcSocket&) = delete;
    RpcSocket& operator=(const RpcSocket&) = delete;

    // Bind to a port (0 = ephemeral) on a specific host (default 0.0.0.0).
    // JS: io.js:244 — `serverSocket.bind(port, host)`.
    int bind(uint16_t port = 0, const std::string& host = "0.0.0.0");

    // Get the bound port
    uint16_t port() const;

    // Send a request and register response handler.
    // Returns the transaction ID, or 0 on failure (congestion full and queued).
    uint16_t request(const messages::Request& req,
                     OnResponseCallback on_response,
                     OnTimeoutCallback on_timeout = nullptr);

    // Send a request with a custom per-request timeout and retry count.
    // timeout_override_ms: 0 = use adaptive/default; nonzero overrides.
    // retries: number of retry attempts on timeout (0 = send once, no retries).
    // Used by delayed_ping() which needs timeout = delayMs + grace and retries=0.
    uint16_t request(const messages::Request& req,
                     uint64_t timeout_override_ms,
                     int retries,
                     OnResponseCallback on_response,
                     OnTimeoutCallback on_timeout = nullptr);

    // Cancel an in-flight request by transaction id. Fires neither
    // on_response nor on_timeout — the request is silently discarded
    // and its congestion budget returned. Returns true if a request
    // with this tid was found and cancelled, false otherwise.
    //
    // Used by `rpc::Session::destroy()` to batch-cancel outstanding
    // requests that belong to a logical operation (JS
    // dht-rpc/lib/session.js:39-46 — `session.destroy()` iterates
    // `this.inflight` and destroys each request).
    bool cancel_request(uint16_t tid);

    // Send a DELAYED_PING — server replies after delay_ms milliseconds.
    // Matches JS dht.delayedPing(). Returns 0 if delay_ms > max_ping_delay_ms.
    uint16_t delayed_ping(const compact::Ipv4Address& to,
                          uint32_t delay_ms,
                          OnResponseCallback on_response,
                          OnTimeoutCallback on_timeout = nullptr);

    // Configure maximum accepted delay for DELAYED_PING (default 10s, matches JS).
    uint64_t max_ping_delay_ms() const { return max_ping_delay_ms_; }
    void set_max_ping_delay_ms(uint64_t ms) { max_ping_delay_ms_ = ms; }

    // Send a response (reply to a received request)
    void reply(const messages::Response& resp);

    // Set handler for incoming requests
    void on_request(OnRequestCallback cb) { on_request_ = std::move(cb); }

    // Add a handler for incoming holepunch probes (1-byte [0x00] UDP packets).
    // Returns an ID for later removal. Supports multiple concurrent listeners
    // so concurrent holepunch sessions don't clobber each other.
    uint32_t add_probe_listener(OnProbeCallback cb);
    void remove_probe_listener(uint32_t id);

    // Legacy single-slot API (sets/clears a catch-all listener).
    // Prefer add_probe_listener/remove_probe_listener for per-session use.
    void on_holepunch_probe(OnProbeCallback cb) {
        if (cb) {
            legacy_probe_id_ = add_probe_listener(std::move(cb));
        } else if (legacy_probe_id_ != 0) {
            remove_probe_listener(legacy_probe_id_);
            legacy_probe_id_ = 0;
        }
    }

    // Send a 1-byte [0x00] UDP probe to the given address
    void send_probe(const compact::Ipv4Address& to);

    // Send a 1-byte [0x00] probe with custom TTL (JS: openSession uses TTL=5)
    void send_probe_ttl(const compact::Ipv4Address& to, int ttl);

    // Send raw UDP bytes to an address (used for probes and RPC)
    void udp_send(const std::vector<uint8_t>& buf, const compact::Ipv4Address& to);

    // Access the event loop
    uv_loop_t* loop() const { return loop_; }

    // Access the underlying UDX handles (for stream connect through same socket)
    udx_t* udx_handle() { return &udx_; }
    udx_socket_t* socket_handle() { return &socket_; }

    // Close the socket and stop all timers
    void close();

    // Suspend/resume background tick timer (JS: dht.suspend/resume)
    void stop_tick();
    void start_tick();

    // --- Node state ---
    bool is_ephemeral() const { return ephemeral_; }
    bool is_firewalled() const { return firewalled_; }
    const health::HealthMonitor& health() const { return health_; }

    // Callbacks for state changes (caller wires these to query engine)
    using OnRefreshCallback = std::function<void()>;
    using OnStateCallback = std::function<void()>;
    void on_refresh(OnRefreshCallback cb) { on_refresh_ = std::move(cb); }
    void on_persistent(OnStateCallback cb) { on_persistent_ = std::move(cb); }

    // §15: fires whenever `health_.state()` transitions (ONLINE <-> DEGRADED
    // <-> OFFLINE) during a background tick. JS fires `network-update` on
    // every `_online()` / `_degraded()` / `_offline()` transition. C++
    // caller wires this to `HyperDHT::fire_network_update()`.
    void on_health_change(OnStateCallback cb) { on_health_change_ = std::move(cb); }

    // Reset the refresh timer (called by query engine when queries are active)
    void reset_refresh_timer() { refresh_ticks_ = REFRESH_TICKS; }

    // Force an immediate ephemeral → persistent re-evaluation. Exposed
    // so tests can drive the `on_persistent_` callback deterministically
    // without waiting for `STABLE_TICKS_INIT` to elapse; production code
    // reaches this path through the background tick countdown. Safe to
    // call repeatedly: the target `check_persistent()` is idempotent —
    // once `ephemeral_` has flipped to false, further calls are no-ops.
    void force_check_persistent() { check_persistent(); }

    // Directly fire the `on_health_change_` callback. Test-only hook used
    // to verify §15 network-update wiring without driving four background
    // ticks worth of synthetic timeouts through the health monitor.
    // Production code never reaches this — the background tick path
    // compares pre/post `health_.state()` and fires the callback only on
    // a real transition.
    void force_fire_health_change_for_test() {
        if (on_health_change_) on_health_change_();
    }

    // Get adaptive timeout for a peer (returns DEFAULT_TIMEOUT_MS if unknown)
    uint64_t timeout_for(const compact::Ipv4Address& peer) const;

    // Access internals for testing
    const routing::RoutingTable& table() const { return table_; }
    routing::RoutingTable& table() { return table_; }
    tokens::TokenStore& token_store() { return tokens_; }
    nat::NatSampler& nat_sampler() { return nat_sampler_; }
    const nat::NatSampler& nat_sampler() const { return nat_sampler_; }
    const CongestionWindow& congestion() const { return congestion_; }
    size_t inflight_count() const { return inflight_.size(); }
    size_t pending_count() const { return pending_.size(); }

    // Background tick count (increments every BG_TICK_MS). Used for
    // ping-and-swap bookkeeping and exposed for tests that want to
    // simulate time passing without waiting.
    uint32_t tick() const { return tick_; }
    void bump_tick(uint32_t n = 1) { tick_ += n; }

    // `bootstrapped` flag (JS `this.bootstrapped`). Ping-and-swap is
    // disabled until the owning layer marks the RPC socket bootstrapped
    // — this prevents premature eviction while the routing table is
    // still being populated. The caller (the DHT class, or tests) is
    // responsible for flipping this after the initial bootstrap walk.
    bool is_bootstrapped() const { return bootstrapped_; }
    void set_bootstrapped(bool b) { bootstrapped_ = b; }

    // Record a peer we just heard from at the routing table level.
    // Mirrors JS dht-rpc `_addNodeFromNetwork`: updates pinged/seen on the
    // existing node, or adds a new one and may trigger ping-and-swap.
    void add_node_from_network(const routing::NodeId& id,
                               const compact::Ipv4Address& from);

    // Ping-and-swap counters (exposed for tests).
    int repinging() const { return repinging_; }

    // DOWN_HINT-driven check counter (exposed for tests and handler rate limit).
    int checks() const { return checks_; }

    // Install a filter callback that can reject network-observed peers
    // (matches JS `_filterNode`). Applied before adding to the routing
    // table and before adding to a Query frontier.
    void set_filter_node(FilterNodeCallback cb) { filter_node_ = std::move(cb); }
    bool filter_accept(const routing::NodeId& id,
                       const compact::Ipv4Address& addr) const {
        return !filter_node_ || filter_node_(id, addr);
    }

    // Schedule a PING check for a known node (JS: `_check`). Used by the
    // DOWN_HINT handler to verify reportedly-dead peers. If the ping
    // succeeds and we have not heard from the node via another path, or
    // if it times out, the node is removed from the routing table.
    void check_node(const routing::Node& node);

private:
    uv_loop_t* loop_;
    udx_t udx_;
    udx_socket_t socket_;
    bool socket_bound_ = false;
    bool closing_ = false;

    routing::RoutingTable table_;
    tokens::TokenStore tokens_;
    nat::NatSampler nat_sampler_;
    CongestionWindow congestion_;

    uint16_t next_tid_ = 0;
    // Raw pointers: ownership transferred to uv_close callback in destroy_request
    std::vector<InflightRequest*> inflight_;
    std::deque<InflightRequest*> pending_;   // Queued when congestion full (O(1) pop_front)

    // Drain timer (750ms interval) — heap-allocated to outlive RpcSocket on close
    uv_timer_t* drain_timer_ = nullptr;
    int rotate_counter_ = TOKEN_ROTATE_TICKS;

    // Background tick timer (5s interval) — heap-allocated for same reason
    uv_timer_t* bg_timer_ = nullptr;
    health::HealthMonitor health_;
    int refresh_ticks_ = REFRESH_TICKS;
    bool ephemeral_ = true;
    bool firewalled_ = true;
    int stable_ticks_ = STABLE_TICKS_INIT;
    std::string last_nat_host_;

    // Per-tick response/timeout counters (reset each background tick)
    uint32_t tick_responses_ = 0;
    uint32_t tick_timeouts_ = 0;

    // Adaptive timeout: per-peer smoothed RTT (exponential moving average)
    std::unordered_map<std::string, uint64_t> peer_rtt_;

    // Max accepted delay for DELAYED_PING command (configurable per-instance).
    uint64_t max_ping_delay_ms_ = DEFAULT_MAX_PING_DELAY_MS;

    // Ping-and-swap (JS: `_repinging`, `_tick`, `_onfullrow`, `_repingAndSwap`).
    uint32_t tick_ = 0;
    int repinging_ = 0;
    int checks_ = 0;  // JS `_checks` — in-flight DOWN_HINT-driven checks
    bool bootstrapped_ = false;  // gates ping-and-swap; set by owning DHT layer

    // Called when the routing table rejects a new node because its bucket
    // is full. Picks the oldest candidate and triggers ping-and-swap.
    void on_bucket_full(size_t bucket_idx, const routing::Node& new_node);

    // Send a PING to the `oldest` node and swap in `new_node` if the ping
    // times out (or if `oldest.seen` hasn't advanced before we hear back).
    void reping_and_swap(const routing::Node& new_node,
                         const routing::Node& oldest);

    OnRequestCallback on_request_;
    std::unordered_map<uint32_t, OnProbeCallback> probe_listeners_;
    uint32_t next_probe_id_ = 1;
    uint32_t legacy_probe_id_ = 0;
    OnRefreshCallback on_refresh_;
    OnStateCallback on_persistent_;
    OnStateCallback on_health_change_;
    FilterNodeCallback filter_node_;

    // Generate next transaction ID
    uint16_t alloc_tid();

    // Find inflight request by tid
    InflightRequest* find_inflight(uint16_t tid);

    // Remove and destroy an inflight request
    void destroy_request(InflightRequest* req);

    // Send a request immediately (bypasses congestion check)
    void send_now(InflightRequest* req);

    // Try to send queued requests
    void drain_pending();

    // Timer callbacks
    static void on_drain_tick(uv_timer_t* timer);
    static void on_bg_tick(uv_timer_t* timer);
    static void on_request_timeout(uv_timer_t* timer);

    // Background tick: health, refresh, ephemeral/persistent
    void background_tick();
    void check_persistent();

    // Adaptive timeout: record RTT sample
    void record_rtt(const compact::Ipv4Address& peer, uint64_t rtt_ms);

    // UDP receive callback
    static void on_recv(udx_socket_t* socket, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr);
    void handle_message(const uint8_t* data, size_t len,
                        const struct sockaddr_in* addr);
};

// ---------------------------------------------------------------------------
// Session — batched request cancellation wrapper
// ---------------------------------------------------------------------------
//
// JS: dht-rpc/lib/session.js — a lightweight container that tracks all
// outstanding requests issued through it. `destroy()` cancels every
// tracked request in one call. Primary use case: a higher-level
// operation (e.g. a Query walk) that fans out N parallel requests and
// wants to cancel the whole batch atomically on abort.
//
// Usage:
//   rpc::Session session(socket);
//   auto tid = session.request(req, on_resp);
//   ...
//   session.destroy();  // cancels every request issued through `session`
//
// Requests issued directly on the RpcSocket (not through the session)
// are unaffected.
class Session {
public:
    explicit Session(RpcSocket& socket) : socket_(socket) {}
    ~Session() { destroy(); }

    // Non-copyable AND non-movable: lambdas registered with
    // RpcSocket::request capture the raw `this` pointer into
    // `tids_`, so relocating the Session object (move-construct out
    // of a container, etc.) would leave dangling pointers in the
    // socket's inflight table. Stick to stack or fixed-storage
    // (unique_ptr) ownership.
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) = delete;
    Session& operator=(Session&&) = delete;

    // Issue a request that will be tracked by this session. Returns the
    // transaction id, or 0 on congestion failure.
    uint16_t request(const messages::Request& req,
                     OnResponseCallback on_response,
                     OnTimeoutCallback on_timeout = nullptr);

    // Cancel every outstanding request attached to this session.
    void destroy();

    // Number of tracked requests (inflight AND queued).
    size_t inflight_count() const { return tids_.size(); }

private:
    RpcSocket& socket_;
    std::vector<uint16_t> tids_;
};

}  // namespace rpc
}  // namespace hyperdht
