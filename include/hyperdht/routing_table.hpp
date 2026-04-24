#pragma once

// Kademlia routing table — k=20, 256 buckets for 256-bit IDs.
// Pure data structure: no networking, no automatic eviction.
// Emits events via callbacks when buckets are full.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace hyperdht {
namespace routing {

constexpr size_t ID_LEN = 32;           // 256-bit node ID
constexpr size_t ID_BITS = ID_LEN * 8;  // 256
#ifdef HYPERDHT_EMBEDDED
constexpr size_t K = 10;                // Reduced bucket size for embedded
#else
constexpr size_t K = 20;                // Bucket size
#endif

using NodeId = std::array<uint8_t, ID_LEN>;

// ---------------------------------------------------------------------------
// Node — a peer in the routing table
// ---------------------------------------------------------------------------

struct Node {
    NodeId id;
    std::string host;
    uint16_t port = 0;

    // Optional metadata (application-managed)
    std::vector<uint8_t> token;
    uint64_t round_trip_time = 0;
    uint64_t added_at = 0;  // timestamp when added

    // Ping-and-swap + down-hint metadata — tick-based counters matching
    // JS dht-rpc. `added` / `pinged` / `seen` / `sampled` are the background
    // tick values at which each event last occurred (0 = never).
    uint32_t added = 0;
    uint32_t pinged = 0;
    uint32_t seen = 0;
    uint32_t sampled = 0;
    uint32_t down_hints = 0;  // number of DOWN_HINT reports received for this node
};

// ---------------------------------------------------------------------------
// XOR distance utilities
// ---------------------------------------------------------------------------

// Compute the bucket index for a node ID relative to our ID.
// Returns the position of the first differing bit (0-255),
// or ID_BITS (256) if the IDs are equal.
size_t bucket_index(const NodeId& local_id, const NodeId& remote_id);

// Compare two IDs by XOR distance from a target.
// Returns negative if a is closer, positive if b is closer, 0 if equal.
int compare_distance(const NodeId& target, const NodeId& a, const NodeId& b);

// ---------------------------------------------------------------------------
// Bucket — a single k-bucket holding up to K nodes
// ---------------------------------------------------------------------------

class Bucket {
public:
    // Add a node. Returns true if added, false if bucket is full.
    bool add(const Node& node);

    // Remove a node by ID. Returns true if found and removed.
    bool remove(const NodeId& id);

    // Get a node by ID. Returns nullptr if not found.
    const Node* get(const NodeId& id) const;

    // Mutable lookup for metadata updates (pinged/seen/sampled counters).
    Node* get_mut(const NodeId& id);

    // Number of nodes in the bucket
    size_t size() const { return nodes_.size(); }
    bool empty() const { return nodes_.empty(); }
    bool is_full() const { return nodes_.size() >= K; }

    // Access all nodes (sorted by binary ID order).
    const std::vector<Node>& nodes() const { return nodes_; }
    std::vector<Node>& nodes_mut() { return nodes_; }

    // The oldest node (first in the list — candidate for eviction)
    const Node* oldest() const;

private:
    std::vector<Node> nodes_;

    // Binary search for a node by ID. Returns index or insertion point.
    size_t find_index(const NodeId& id) const;
    bool has_id(const NodeId& id) const;
};

// ---------------------------------------------------------------------------
// RoutingTable — 256 k-buckets indexed by XOR distance
// ---------------------------------------------------------------------------

// Callback types
using OnFullCallback = std::function<void(size_t bucket_idx, const Node& rejected)>;

class RoutingTable {
public:
    explicit RoutingTable(const NodeId& local_id);

    // Our node ID
    const NodeId& id() const { return id_; }

    // Add a node. Returns true if added.
    // If bucket is full, calls on_full callback (if set) and returns false.
    bool add(const Node& node);

    // Remove a node by ID. Returns true if found and removed.
    bool remove(const NodeId& id);

    // Get a node by ID. Returns nullptr if not found.
    const Node* get(const NodeId& id) const;

    // Mutable lookup — used by the RPC layer to update per-node metadata
    // (pinged/seen/sampled/down_hints counters).
    Node* get_mut(const NodeId& id);

    // Check if a node exists
    bool has(const NodeId& id) const;

    // Find the k closest nodes to a target ID
    std::vector<const Node*> closest(const NodeId& target, size_t count = K) const;

    // Pick a random node (uniform across all nodes)
    const Node* random() const;

    // Total number of nodes in the table
    size_t size() const { return size_; }

    // Rebuild the table with a new local ID. All existing nodes are
    // re-inserted into new bucket positions (XOR distances change).
    // Nodes that don't fit (bucket full) are silently dropped.
    // The on_full callback is suppressed during migration to avoid
    // triggering ping-and-swap for nodes being copied over.
    // JS: dht-rpc/index.js:854-864 (ephemeral → persistent transition)
    void rebuild_with_id(const NodeId& new_id);

    // Set callback for bucket-full events
    void on_full(OnFullCallback cb) { on_full_ = std::move(cb); }

    // Access a specific bucket (const + mutable variants).
    const Bucket& bucket(size_t idx) const { return buckets_[idx]; }
    Bucket& bucket_mut(size_t idx) { return buckets_[idx]; }

private:
    NodeId id_;
    std::array<Bucket, ID_BITS> buckets_;
    size_t size_ = 0;
    OnFullCallback on_full_;
};

}  // namespace routing
}  // namespace hyperdht
