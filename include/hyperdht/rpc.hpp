#pragma once

// Phase 3: DHT RPC — UDP message dispatch with UDX sockets.
// Sends/receives compact-encoded DHT messages, matches responses to requests
// by transaction ID, handles timeouts and retries.

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
// Callback types
// ---------------------------------------------------------------------------

using OnRequestCallback = std::function<void(const messages::Request& req)>;
using OnResponseCallback = std::function<void(const messages::Response& resp)>;
using OnTimeoutCallback = std::function<void(uint16_t tid)>;

// ---------------------------------------------------------------------------
// Inflight request tracking
// ---------------------------------------------------------------------------

struct InflightRequest {
    uint16_t tid = 0;
    uint32_t command = 0;
    OnResponseCallback on_response;
    OnTimeoutCallback on_timeout;
    uint64_t sent_at = 0;
    int retries_left = 3;
    std::vector<uint8_t> buffer;  // encoded message for retry
    compact::Ipv4Address to;      // destination for retry
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

    // Send a request and register response handler
    uint16_t request(const messages::Request& req,
                     OnResponseCallback on_response,
                     OnTimeoutCallback on_timeout = nullptr);

    // Send a response (reply to a received request)
    void reply(const messages::Response& resp);

    // Set handler for incoming requests
    void on_request(OnRequestCallback cb) { on_request_ = std::move(cb); }

    // Close the socket
    void close();

    // Access internals for testing
    const routing::RoutingTable& table() const { return table_; }
    routing::RoutingTable& table() { return table_; }
    tokens::TokenStore& token_store() { return tokens_; }

private:
    uv_loop_t* loop_;
    udx_t udx_;
    udx_socket_t socket_;
    bool socket_bound_ = false;

    routing::RoutingTable table_;
    tokens::TokenStore tokens_;

    uint16_t next_tid_ = 0;
    std::vector<InflightRequest> inflight_;

    OnRequestCallback on_request_;

    // Generate next transaction ID
    uint16_t alloc_tid();

    // Find and remove inflight request by tid
    InflightRequest* find_inflight(uint16_t tid);
    void remove_inflight(uint16_t tid);

    // UDP receive callback
    static void on_recv(udx_socket_t* socket, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr);
    void handle_message(const uint8_t* data, size_t len,
                        const struct sockaddr_in* addr);
};

}  // namespace rpc
}  // namespace hyperdht
