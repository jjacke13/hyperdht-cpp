#pragma once

// Connection Pool — deduplicates connections by remote public key.
//
// Matches JS hyperdht/lib/connection-pool.js:
// - Tracks connections in two states: connecting (not yet open) and connected
// - Deduplicates: if a connection to the same remote pubkey already exists,
//   deterministic tie-breaking decides which one survives
// - Tie-breaking rule: if same initiator mode OR our pubkey > remote pubkey,
//   keep the new stream; otherwise keep the existing one
// - Servers can attach to the pool so inbound connections are deduped against
//   outbound connections to the same peer
//
// Used by connect() and createServer() to prevent duplicate streams.

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

namespace hyperdht {

// Forward declarations — attach_server() binds the pool to a Server without
// dragging the full server.hpp include into this header (impl in
// connection_pool.cpp). server::ConnectionInfo is the inbound-connection
// payload delivered to the pool's on_connection event.
namespace server {
class Server;
struct ConnectionInfo;
}  // namespace server

namespace connection_pool {

// ---------------------------------------------------------------------------
// Connection info — represents one end of a connection
// ---------------------------------------------------------------------------

struct ConnectionInfo {
    std::array<uint8_t, 32> local_public_key{};
    std::array<uint8_t, 32> remote_public_key{};
    bool is_initiator = false;
    uint32_t id = 0;  // Caller-assigned ID for tracking
};

// ---------------------------------------------------------------------------
// ConnectionRef — wraps a connection with ref-counting
// ---------------------------------------------------------------------------

class ConnectionRef {
public:
    explicit ConnectionRef(const ConnectionInfo& info);

    void active() { refs_++; }
    void inactive() { refs_--; }
    int refs() const { return refs_; }

    const ConnectionInfo& info() const { return info_; }
    uint32_t id() const { return info_.id; }
    const std::array<uint8_t, 32>& remote_public_key() const {
        return info_.remote_public_key;
    }
    bool is_initiator() const { return info_.is_initiator; }

    // Caller sets this to destroy the underlying stream
    using DestroyFn = std::function<void()>;
    DestroyFn on_destroy;

    // Caller sets this — fires when moved from connecting to connected
    std::function<void()> on_open;
    // Caller sets this — fires when connection closes
    std::function<void()> on_close;

    // Pool sets this — fires the pool's unified 'connection' event once this
    // ref is attached-and-opened (JS connection-pool.js:74,92 emit('connection')).
    std::function<void()> on_emit;

    // Close bookkeeping for the deferred keep-new swap (dhttop-8). The pool
    // flips this via on_stream_closed(); the deferred attach checks it so a
    // new stream that died before the old one closed is not resurrected.
    void mark_closed() { closed_ = true; }
    bool closed() const { return closed_; }

private:
    ConnectionInfo info_;
    int refs_ = 0;
    bool closed_ = false;
};

// ---------------------------------------------------------------------------
// DedupResult — returned by attach_stream
// ---------------------------------------------------------------------------

enum class AttachResult {
    ATTACHED,           // New connection, added to pool
    DUPLICATE_KEPT_NEW, // Duplicate found, new stream wins (old destroyed)
    DUPLICATE_KEPT_OLD, // Duplicate found, old stream wins (new destroyed)
};

// ---------------------------------------------------------------------------
// ConnectionPool — deduplicates connections by remote public key
// ---------------------------------------------------------------------------

class ConnectionPool {
public:
    ConnectionPool() = default;

    // Attach an outbound connection (not yet open).
    // Returns ATTACHED if new, or DUPLICATE_KEPT_* if dedup occurred.
    //
    // dhttop-8: on DUPLICATE_KEPT_NEW the new ref is NOT inserted yet. The
    // existing ref is destroyed (on_destroy) and the new ref is held in
    // pending_swaps_ until the old ref's close is signalled via
    // on_stream_closed() — mirrors JS connection-pool.js:37-55 keepNew.
    AttachResult attach_stream(std::shared_ptr<ConnectionRef> ref, bool opened);

    // Mark a connecting stream as now open (moves from connecting → connected).
    void mark_opened(const std::array<uint8_t, 32>& remote_key);

    // Signal that a ref's underlying stream has closed. Drives the deferred
    // keep-new swap: when the closing ref is the currently-attached one, it is
    // removed and any pending keep-new ref is promoted (unless it too has
    // closed). JS: connection-pool.js 'close' handlers.
    void on_stream_closed(const std::shared_ptr<ConnectionRef>& ref);

    // Remove a connection (on close/error).
    void remove(const std::array<uint8_t, 32>& remote_key);

    // Bind an inbound-connection source (a listening Server) to the pool.
    // Inbound streams are deduped against outbound streams by remote public
    // key, then re-emitted through the pool's on_connection event. Chains onto
    // the Server's connection callback (Server::add_connection_listener) — it
    // does NOT replace the user's own on_connection handler. JS: pool()
    // ._attachServer (connection-pool.js:15-27).
    //
    // NOTE: the pool tracks dedup state and fires on_connection for accepted
    // connections; tearing down the losing stream of a rejected duplicate is
    // the consumer's responsibility (the pool does not own the
    // SecretStreamDuplex wrapping the raw stream). Wire ConnectionRef::on_destroy
    // if teardown is needed.
    void attach_server(server::Server& server);

    // The pool's unified 'connection' event — fires once per accepted
    // (deduplicated) inbound connection. JS: pool.on('connection', ...).
    using OnConnectionCb = std::function<void(const server::ConnectionInfo&)>;
    void set_on_connection(OnConnectionCb cb) { on_connection_ = std::move(cb); }

    // Check if we have a connection (connecting or connected) to a peer.
    bool has(const std::array<uint8_t, 32>& remote_key) const;

    // Get existing connection to a peer (connected first, then connecting).
    // Returns nullptr if none.
    std::shared_ptr<ConnectionRef> get(const std::array<uint8_t, 32>& remote_key) const;

    // Number of connections in each state
    size_t connecting_count() const { return connecting_.size(); }
    size_t connected_count() const { return connections_.size(); }

    // Iterate connected refs
    using ConnectionMap = std::unordered_map<std::string, std::shared_ptr<ConnectionRef>>;
    const ConnectionMap& connections() const { return connections_; }

private:
    ConnectionMap connecting_;
    ConnectionMap connections_;

    // dhttop-8: keep-new swaps awaiting the old ref's close, keyed by remote
    // pubkey hex. The held ref is attached once the old one closes.
    struct PendingSwap {
        std::shared_ptr<ConnectionRef> ref;
        bool opened = false;
    };
    std::unordered_map<std::string, PendingSwap> pending_swaps_;

    OnConnectionCb on_connection_;

    static std::string key_hex(const std::array<uint8_t, 32>& key);

    // Deterministic tie-breaking (JS: connection-pool.js lines 42-49)
    // Returns true if new_ref should win over existing
    static bool should_keep_new(const ConnectionRef& existing,
                                const ConnectionRef& new_ref);
};

}  // namespace connection_pool
}  // namespace hyperdht
