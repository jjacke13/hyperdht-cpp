#pragma once

// Phase 3: DHT RPC — UDP message dispatch with UDX sockets.
// Sends/receives compact-encoded DHT messages, matches responses to requests
// by transaction ID, handles timeouts, retries, congestion control, and
// periodic token rotation.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include <udx.h>
#include <uv.h>

#include "hyperdht/compact.hpp"
#include "hyperdht/messages.hpp"
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
constexpr int TOKEN_ROTATE_TICKS = 10;  // 10 * 750ms = 7.5s

// ---------------------------------------------------------------------------
// Callback types
// ---------------------------------------------------------------------------

using OnRequestCallback = std::function<void(const messages::Request& req)>;
using OnResponseCallback = std::function<void(const messages::Response& resp)>;
using OnTimeoutCallback = std::function<void(uint16_t tid)>;

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
    int sent = 0;            // Number of times sent (0-based, increments each attempt)
    int retries = DEFAULT_RETRIES;
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

    // Bind to a port (0 = ephemeral)
    int bind(uint16_t port = 0);

    // Get the bound port
    uint16_t port() const;

    // Send a request and register response handler.
    // Returns the transaction ID, or 0 on failure (congestion full and queued).
    uint16_t request(const messages::Request& req,
                     OnResponseCallback on_response,
                     OnTimeoutCallback on_timeout = nullptr);

    // Send a response (reply to a received request)
    void reply(const messages::Response& resp);

    // Set handler for incoming requests
    void on_request(OnRequestCallback cb) { on_request_ = std::move(cb); }

    // Close the socket and stop all timers
    void close();

    // Access internals for testing
    const routing::RoutingTable& table() const { return table_; }
    routing::RoutingTable& table() { return table_; }
    tokens::TokenStore& token_store() { return tokens_; }
    const CongestionWindow& congestion() const { return congestion_; }
    size_t inflight_count() const { return inflight_.size(); }
    size_t pending_count() const { return pending_.size(); }

private:
    uv_loop_t* loop_;
    udx_t udx_;
    udx_socket_t socket_;
    bool socket_bound_ = false;
    bool closing_ = false;

    routing::RoutingTable table_;
    tokens::TokenStore tokens_;
    CongestionWindow congestion_;

    uint16_t next_tid_ = 0;
    std::vector<InflightRequest*> inflight_;
    std::vector<InflightRequest*> pending_;  // Queued when congestion full

    // Drain timer (750ms interval)
    uv_timer_t drain_timer_;
    int rotate_counter_ = TOKEN_ROTATE_TICKS;

    OnRequestCallback on_request_;

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

    // UDP send helper
    void udp_send(const std::vector<uint8_t>& buf, const compact::Ipv4Address& to);

    // Timer callbacks
    static void on_drain_tick(uv_timer_t* timer);
    static void on_request_timeout(uv_timer_t* timer);

    // UDP receive callback
    static void on_recv(udx_socket_t* socket, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr);
    void handle_message(const uint8_t* data, size_t len,
                        const struct sockaddr_in* addr);
};

}  // namespace rpc
}  // namespace hyperdht
