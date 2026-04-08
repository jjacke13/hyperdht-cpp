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

private:
    ConnectionInfo info_;
    int refs_ = 0;
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
    AttachResult attach_stream(std::shared_ptr<ConnectionRef> ref, bool opened);

    // Mark a connecting stream as now open (moves from connecting → connected).
    void mark_opened(const std::array<uint8_t, 32>& remote_key);

    // Remove a connection (on close/error).
    void remove(const std::array<uint8_t, 32>& remote_key);

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

    static std::string key_hex(const std::array<uint8_t, 32>& key);

    // Deterministic tie-breaking (JS: connection-pool.js lines 42-49)
    // Returns true if new_ref should win over existing
    static bool should_keep_new(const ConnectionRef& existing,
                                const ConnectionRef& new_ref);
};

}  // namespace connection_pool
}  // namespace hyperdht
