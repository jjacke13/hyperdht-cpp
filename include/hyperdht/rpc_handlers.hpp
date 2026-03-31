#pragma once

// DHT RPC request handlers — respond to incoming PING, FIND_NODE, DOWN_HINT.
// These are the "server-side" handlers that make our node a participant
// in the DHT network, not just a client.

#include "hyperdht/messages.hpp"
#include "hyperdht/rpc.hpp"

namespace hyperdht {
namespace rpc {

// ---------------------------------------------------------------------------
// RpcHandlers — processes incoming base dht-rpc commands
// ---------------------------------------------------------------------------

class RpcHandlers {
public:
    explicit RpcHandlers(RpcSocket& socket);

    // Install the handler on the RpcSocket (calls socket.on_request)
    void install();

    // Handle an incoming request — dispatches to the appropriate handler
    void handle(const messages::Request& req);

private:
    RpcSocket& socket_;

    // Individual command handlers
    void handle_ping(const messages::Request& req);
    void handle_find_node(const messages::Request& req);
    void handle_down_hint(const messages::Request& req);
};

}  // namespace rpc
}  // namespace hyperdht
