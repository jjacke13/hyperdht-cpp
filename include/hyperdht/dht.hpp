#pragma once

// HyperDHT — the main entry point for the C++ HyperDHT library.
//
// Usage:
//   uv_loop_t loop;
//   uv_loop_init(&loop);
//
//   HyperDHT dht(&loop);
//   dht.bind();
//
//   // Client: connect to a peer
//   dht.connect(remote_pk, [](int err, const ConnectionInfo& info) { ... });
//
//   // Server: listen for connections
//   auto* srv = dht.create_server();
//   srv->listen(keypair, [](const server::ConnectionInfo& info) { ... });
//
//   // Cleanup
//   dht.destroy();
//   uv_run(&loop, UV_RUN_DEFAULT);

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <uv.h>

#include "hyperdht/compact.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/query.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"
#include "hyperdht/server.hpp"

namespace hyperdht {

// ---------------------------------------------------------------------------
// Options for HyperDHT construction
// ---------------------------------------------------------------------------

struct DhtOptions {
    uint16_t port = 0;                               // 0 = ephemeral
    std::vector<compact::Ipv4Address> bootstrap;     // Empty = use public bootstrap
    noise::Keypair default_keypair;                   // Auto-generated if zero
    bool ephemeral = true;
};

// ---------------------------------------------------------------------------
// Connection result (client side)
// ---------------------------------------------------------------------------

struct ConnectResult {
    bool success = false;
    noise::Key tx_key{};
    noise::Key rx_key{};
    noise::Hash handshake_hash{};
    std::array<uint8_t, 32> remote_public_key{};
    compact::Ipv4Address peer_address;
    uint32_t remote_udx_id = 0;
    uint32_t local_udx_id = 0;
    udx_stream_t* raw_stream = nullptr;   // Pre-created during handshake (like JS rawStream)
    udx_socket_t* udx_socket = nullptr;   // Socket for UDX connect (JS: ref.socket from probe)
};

using ConnectCallback = std::function<void(int error, const ConnectResult& result)>;

// ---------------------------------------------------------------------------
// HyperDHT
// ---------------------------------------------------------------------------

class HyperDHT {
public:
    explicit HyperDHT(uv_loop_t* loop, DhtOptions opts = {});
    ~HyperDHT();

    HyperDHT(const HyperDHT&) = delete;
    HyperDHT& operator=(const HyperDHT&) = delete;

    // Bind the UDP socket (called automatically by connect/listen if needed)
    int bind();

    // --- Client API ---

    // Connect to a remote peer by public key.
    // Orchestrates: findPeer → handshake → holepunch → ready.
    // Callback receives error code (0 = success) and connection info.
    void connect(const noise::PubKey& remote_public_key,
                 ConnectCallback on_done);

    // Connect with a specific keypair (instead of default)
    void connect(const noise::PubKey& remote_public_key,
                 const noise::Keypair& keypair,
                 ConnectCallback on_done);

    // --- Server API ---

    // Create a server instance. HyperDHT owns the returned pointer.
    server::Server* create_server();

    // --- DHT Operations ---

    std::shared_ptr<query::Query> find_peer(
        const noise::PubKey& public_key,
        query::OnReplyCallback on_reply,
        query::OnDoneCallback on_done);

    std::shared_ptr<query::Query> lookup(
        const routing::NodeId& target,
        query::OnReplyCallback on_reply,
        query::OnDoneCallback on_done);

    std::shared_ptr<query::Query> announce(
        const routing::NodeId& target,
        const std::vector<uint8_t>& value,
        query::OnDoneCallback on_done);

    // --- Lifecycle ---

    void destroy(std::function<void()> on_done = nullptr);
    bool is_destroyed() const { return destroyed_; }

    // --- Accessors ---

    uv_loop_t* loop() const { return loop_; }
    rpc::RpcSocket& socket() { return *socket_; }
    router::Router& router() { return router_; }
    const noise::Keypair& default_keypair() const { return opts_.default_keypair; }
    uint16_t port() const { return socket_ ? socket_->port() : 0; }
    bool is_bound() const { return bound_; }

private:
    uv_loop_t* loop_;
    DhtOptions opts_;
    std::unique_ptr<rpc::RpcSocket> socket_;
    std::unique_ptr<rpc::RpcHandlers> handlers_;
    router::Router router_;
    std::vector<std::unique_ptr<server::Server>> servers_;
    bool bound_ = false;
    bool destroyed_ = false;
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);  // Sentinel for async safety

    void ensure_bound();
    void do_connect(const noise::PubKey& remote_pk,
                    const noise::Keypair& keypair,
                    ConnectCallback on_done);
};

}  // namespace hyperdht
