#pragma once

// Socket Pool — manages reusable UDX sockets for holepunching and connections.
//
// Matches JS hyperdht/lib/socket-pool.js:
// - SocketRef: ref-counted UDX socket with linger-on-close behavior
// - SocketPool: factory and tracker for SocketRefs
// - SocketRoutes: maps remote public keys to socket+address for connection reuse
//
// Used by Holepuncher for birthday paradox (256 sockets) and by connect
// pipeline for retryRoute (reuse socket from previous successful connection).

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <uv.h>

#include "hyperdht/compact.hpp"
#include "hyperdht/udx.hpp"

namespace hyperdht {
namespace socket_pool {

constexpr uint64_t LINGER_TIME_MS = 3000;

class SocketPool;

// ---------------------------------------------------------------------------
// SocketRef — ref-counted UDX socket wrapper
// ---------------------------------------------------------------------------

class SocketRef {
public:
    explicit SocketRef(SocketPool& pool, uv_loop_t* loop, udx_t* udx,
                       const std::string& host = "0.0.0.0");
    ~SocketRef();

    // Non-copyable (ref-counted, shared via raw pointer)
    SocketRef(const SocketRef&) = delete;
    SocketRef& operator=(const SocketRef&) = delete;

    // Ref counting — caller must balance active/inactive calls
    void active();
    void inactive();
    void release();

    bool is_free() const { return refs_ == 0; }
    bool is_closed() const { return closed_; }

    // The underlying UDX socket
    udx_socket_t* socket() { return &socket_; }
    const udx_socket_t* socket() const { return &socket_; }

    // Whether this socket should linger after becoming idle (for reuse)
    bool reusable = false;

    // Holepunch message callback (1-byte probe packets)
    using OnHolepunchFn = std::function<void(const uint8_t* data, size_t len,
                                              const compact::Ipv4Address& from,
                                              SocketRef* ref)>;
    OnHolepunchFn on_holepunch_message;

    // Socket address
    compact::Ipv4Address address() const;

private:
    friend class SocketPool;

    SocketPool& pool_;
    uv_loop_t* loop_;
    udx_socket_t socket_;
    uv_timer_t* linger_timer_ = nullptr;

    int refs_ = 1;
    bool released_ = false;
    bool closed_ = false;
    bool was_busy_ = false;

    void close_maybe();
    void do_close();
    void unlinger();

    static void on_linger_timeout(uv_timer_t* handle);
    static void on_linger_close(uv_handle_t* handle);
    static void on_socket_close(udx_socket_t* socket);
    static void on_message(udx_socket_t* socket, ssize_t read_len,
                           const uv_buf_t* buf, const struct sockaddr* addr);
};

// ---------------------------------------------------------------------------
// SocketRoute — cached connection route for a remote peer
// ---------------------------------------------------------------------------

struct SocketRoute {
    udx_socket_t* socket = nullptr;
    compact::Ipv4Address address;
};

// ---------------------------------------------------------------------------
// SocketPool — creates and manages SocketRefs
// ---------------------------------------------------------------------------

class SocketPool {
public:
    SocketPool(uv_loop_t* loop, udx_t* udx, const std::string& host = "0.0.0.0");
    ~SocketPool();

    // Acquire a new socket reference
    SocketRef* acquire();

    // Look up a SocketRef by its raw udx_socket_t*
    SocketRef* lookup(udx_socket_t* socket);

    // Mark a socket as reusable or not
    void set_reusable(udx_socket_t* socket, bool reusable);

    // Destroy all sockets
    void destroy();

    // -----------------------------------------------------------------------
    // Routes — map public key → socket+address for connection reuse
    // -----------------------------------------------------------------------

    // Add a route for a remote peer
    void add_route(const std::array<uint8_t, 32>& public_key,
                   udx_socket_t* socket,
                   const compact::Ipv4Address& address);

    // Get a cached route for a remote peer (nullptr if none)
    const SocketRoute* get_route(const std::array<uint8_t, 32>& public_key) const;

    // Remove a route
    void remove_route(const std::array<uint8_t, 32>& public_key);

    // Number of active sockets
    size_t size() const { return sockets_.size(); }

    // Callback for incoming DHT messages (>1 byte)
    using OnMessageFn = std::function<void(udx_socket_t* socket,
                                            const uint8_t* data, size_t len,
                                            const compact::Ipv4Address& from)>;
    OnMessageFn on_message;

private:
    friend class SocketRef;

    uv_loop_t* loop_;
    udx_t* udx_;
    std::string host_;

    std::unordered_map<udx_socket_t*, SocketRef*> sockets_;
    std::unordered_set<SocketRef*> lingering_;

    // Routes: hex(pubkey) → SocketRoute
    std::unordered_map<std::string, SocketRoute> routes_;

    void add(SocketRef* ref);
    void remove(SocketRef* ref);

    static std::string key_hex(const std::array<uint8_t, 32>& key);
};

}  // namespace socket_pool
}  // namespace hyperdht
