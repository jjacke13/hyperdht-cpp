#pragma once

// DHT RPC request handlers — respond to incoming dht-rpc and HyperDHT commands.
// dht-rpc (internal): PING, PING_NAT, FIND_NODE, DOWN_HINT
// HyperDHT (external): FIND_PEER, LOOKUP, ANNOUNCE, UNANNOUNCE
//
// These handlers make our node a full participant in the DHT network,
// able to answer queries and store announcements for other peers.

#include "hyperdht/announce.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"

namespace hyperdht {
namespace rpc {

// ---------------------------------------------------------------------------
// RpcHandlers — processes incoming dht-rpc and HyperDHT commands
// ---------------------------------------------------------------------------

class RpcHandlers {
public:
    // router is optional — if null, PEER_HANDSHAKE/HOLEPUNCH are not dispatched
    explicit RpcHandlers(RpcSocket& socket, router::Router* router = nullptr);

    // Install the handler on the RpcSocket (calls socket.on_request)
    void install();

    // Handle an incoming request — dispatches to the appropriate handler
    void handle(const messages::Request& req);

    // Access the announce store (for testing)
    const announce::AnnounceStore& store() const { return store_; }
    announce::AnnounceStore& store() { return store_; }

private:
    RpcSocket& socket_;
    router::Router* router_ = nullptr;
    announce::AnnounceStore store_;

    // dht-rpc internal commands
    void handle_ping(const messages::Request& req);
    void handle_ping_nat(const messages::Request& req);
    void handle_find_node(const messages::Request& req);
    void handle_down_hint(const messages::Request& req);

    // HyperDHT external commands
    void handle_find_peer(const messages::Request& req);
    void handle_lookup(const messages::Request& req);
    void handle_announce(const messages::Request& req);
    void handle_unannounce(const messages::Request& req);

    // Build a response with closer nodes to the target
    messages::Response make_query_response(const messages::Request& req);
};

}  // namespace rpc
}  // namespace hyperdht
