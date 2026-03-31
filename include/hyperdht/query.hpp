#pragma once

// Iterative DHT query engine — walks the network to find the k closest
// nodes to a target key. Used by findNode, lookup, announce.
//
// Algorithm:
//   1. Seed with k closest from local routing table (+ bootstrap if sparse)
//   2. Pop closest unqueried node from pending stack
//   3. Send FIND_NODE (or custom command) to it
//   4. On response: merge closerNodes into pending, track in closestReplies
//   5. Repeat until no unqueried nodes are closer than k-th closest reply
//   6. Optionally: commit phase (send ANNOUNCE to k closest with tokens)

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "hyperdht/messages.hpp"
#include "hyperdht/routing_table.hpp"
#include "hyperdht/rpc.hpp"

namespace hyperdht {
namespace query {

constexpr int DEFAULT_CONCURRENCY = 10;
constexpr int SLOWDOWN_CONCURRENCY = 3;

// ---------------------------------------------------------------------------
// Query result — a response from a node during the query
// ---------------------------------------------------------------------------

struct QueryReply {
    routing::NodeId from_id;
    compact::Ipv4Address from_addr;
    std::optional<std::array<uint8_t, 32>> token;
    std::optional<std::vector<uint8_t>> value;
    std::vector<compact::Ipv4Address> closer_nodes;
};

// ---------------------------------------------------------------------------
// Callback types
// ---------------------------------------------------------------------------

// Called for each reply during the query
using OnReplyCallback = std::function<void(const QueryReply& reply)>;

// Called when the query completes (with the k closest replies)
using OnDoneCallback = std::function<void(const std::vector<QueryReply>& closest)>;

// Called during commit phase for each of the k closest nodes
// Should send the ANNOUNCE/store request with the provided token
using OnCommitCallback = std::function<void(const QueryReply& node,
                                            rpc::OnResponseCallback on_done)>;

// ---------------------------------------------------------------------------
// Query — iterative DHT walk
// ---------------------------------------------------------------------------

class Query : public std::enable_shared_from_this<Query> {
public:
    // Use Query::create() instead of constructing directly
    static std::shared_ptr<Query> create(rpc::RpcSocket& socket,
                                          const routing::NodeId& target,
                                          uint32_t command,
                                          const std::vector<uint8_t>* value = nullptr);

    Query(rpc::RpcSocket& socket, const routing::NodeId& target,
          uint32_t command, const std::vector<uint8_t>* value = nullptr);

    // Configuration (call before start())
    void set_concurrency(int c) { concurrency_ = c; }
    void set_commit(OnCommitCallback cb) { on_commit_ = std::move(cb); }
    void set_internal(bool b) { internal_ = b; }

    // Callbacks
    void on_reply(OnReplyCallback cb) { on_reply_ = std::move(cb); }
    void on_done(OnDoneCallback cb) { on_done_ = std::move(cb); }

    // Start the query — seeds from routing table and begins iteration
    void start();

    // Add bootstrap nodes (call before start if routing table is sparse)
    void add_bootstrap(const compact::Ipv4Address& addr);

    // Is the query finished?
    bool is_done() const { return done_; }

    // Access results
    const std::vector<QueryReply>& closest_replies() const { return closest_replies_; }

private:
    rpc::RpcSocket& socket_;
    routing::NodeId target_;
    uint32_t command_;
    std::optional<std::vector<uint8_t>> value_;
    int concurrency_ = DEFAULT_CONCURRENCY;
    bool internal_ = false;
    bool done_ = false;
    bool committing_ = false;
    int inflight_ = 0;
    int commit_inflight_ = 0;

    // Closest k replies sorted by XOR distance
    std::vector<QueryReply> closest_replies_;

    // Pending nodes to query (LIFO stack — pop closest first)
    struct PendingNode {
        routing::NodeId id;
        compact::Ipv4Address addr;
    };
    std::vector<PendingNode> pending_;

    // Seen nodes: address → state
    enum class NodeState { PENDING, DONE, DOWN };
    std::unordered_map<std::string, NodeState> seen_;

    OnReplyCallback on_reply_;
    OnDoneCallback on_done_;
    OnCommitCallback on_commit_;

    // Add nodes from local routing table
    void seed_from_table();

    // Add a node to the pending list (if not already seen)
    void add_pending(const routing::NodeId& id, const compact::Ipv4Address& addr);

    // Try to send more queries (up to concurrency limit)
    void read_more();

    // Send a query to a specific node
    void visit(const PendingNode& node);

    // Handle a response
    void on_visit_response(const PendingNode& node, const messages::Response& resp);

    // Handle a timeout
    void on_visit_timeout(const PendingNode& node);

    // Insert a reply into closest_replies (sorted, capped at k)
    void push_closest(const QueryReply& reply);

    // Check if a node ID is closer than the k-th closest reply
    bool is_closer(const routing::NodeId& id) const;

    // XOR distance comparison
    int compare(const routing::NodeId& a, const routing::NodeId& b) const;

    // Check if query is complete and fire callbacks
    void maybe_finish();

    // Commit phase — send to k closest with tokens
    void do_commit();
};

}  // namespace query
}  // namespace hyperdht
