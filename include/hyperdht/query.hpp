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

// JS dht-rpc/lib/query.js:28-29 — a query command's request retries default to
// 5 (DOWN_HINT walks use 3). io.js oncycle resends until `sent > retries`, i.e.
// 6 transmissions to a silent node. Callers may lower this (tests, or the
// seeded-reconnect findPeer path in connect.js which uses retries=1).
constexpr int QUERY_RETRIES = 5;

// Commit-phase error codes passed as OnDoneCallback's first arg (0 = success).
// JS query.js:211-248 (`_endAfterCommit`): an empty commit set OR all-failed
// commits reject the query ('Too few nodes responded'); tokenless closest
// replies count as failed commits (autoCommit rejects, query.js:392-403).
// Non-commit queries (plain lookup/get) always end with success.
constexpr int QUERY_OK = 0;
constexpr int QUERY_ERR_TOO_FEW_NODES = 1;

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

// Called when the query completes. `error` is 0 on success, or a QUERY_ERR_*
// code when the commit phase failed (empty/all-failed commit set). JS surfaces
// this via `query.finished()` rejecting; announce/put callers must observe it
// (query.js:225-248, hyperdht/index.js awaits query.finished()). Non-commit
// queries always report success. `closest` is the k closest replies collected.
using OnDoneCallback =
    std::function<void(int error, const std::vector<QueryReply>& closest)>;

// Called during commit phase for each of the k closest nodes. Should send
// the ANNOUNCE/store request with the provided token, wiring BOTH callbacks
// into RpcSocket::request so the query settles on a response OR a timeout.
// A commit that only handles the response wedges the query when a single
// store packet is lost (JS decrements on both ondone/onerror, query.js:236).
using OnCommitCallback = std::function<void(const QueryReply& node,
                                            rpc::OnResponseCallback on_response,
                                            rpc::OnTimeoutCallback on_timeout)>;

// ---------------------------------------------------------------------------
// Query — iterative DHT walk
// ---------------------------------------------------------------------------

class Query : public std::enable_shared_from_this<Query> {
public:
    // Factory — always use this instead of constructing directly
    static std::shared_ptr<Query> create(rpc::RpcSocket& socket,
                                          const routing::NodeId& target,
                                          uint32_t command,
                                          const std::vector<uint8_t>* value = nullptr);

    // Configuration (call before start())
    void set_concurrency(int c) { concurrency_ = c; }
    void set_commit(OnCommitCallback cb) { on_commit_ = std::move(cb); }
    void set_internal(bool b) { internal_ = b; }

    // Per-visit request retry count (JS `opts.retries`, query.js:28-29,380).
    // Defaults to QUERY_RETRIES (5). Tests use a low value to avoid waiting the
    // full retry budget on deliberately-dead loopback nodes.
    void set_retries(int r) { retries_ = r; }

    // JS `opts.onlyClosestNodes` (query.js:41,69,141): when set, the walk visits
    // ONLY the seeded frontier and never expands from responses' closerNodes.
    // Must be set before start() (mirrors JS setting the flag after seeding).
    void set_only_closest_nodes(bool b) { only_closest_nodes_ = b; }

    // Callbacks
    void on_reply(OnReplyCallback cb) { on_reply_ = std::move(cb); }
    void on_done(OnDoneCallback cb) { on_done_ = std::move(cb); }

    // Start the query — seeds from routing table (if caller has not already
    // pre-filled pending via add_seed_node()) and begins iteration.
    // Matches JS `_open()` in dht-rpc/lib/query.js:122-131.
    void start();

    // Add bootstrap nodes (call before start if routing table is sparse)
    void add_bootstrap(const compact::Ipv4Address& addr);

    // Pre-seed the pending frontier with a specific node (equivalent to JS
    // `opts.nodes` / `opts.closestReplies` in dht-rpc/lib/query.js:47-67).
    // Must be called BEFORE start().
    //
    // **Order matters.** Call in CLOSEST-FIRST order (same convention JS
    // takes from `opts.nodes`): the collected seeds are pushed onto the
    // pending stack in reverse at `start()` time, so the first seed added
    // ends up on top and is visited first. This mirrors JS query.js:52-62.
    //
    // When the caller seeds enough nodes to satisfy the k-frontier, the
    // table-seed is skipped and the cold-start slowdown
    // (SLOWDOWN_CONCURRENCY) kicks in for the first responses.
    void add_seed_node(const routing::NodeId& id, const compact::Ipv4Address& addr);

    // Is the query finished?
    bool is_done() const { return done_; }

    // Early termination — equivalent to JS `query.destroy()` (or exiting
    // the `for await (const node of query)` loop). Flags the query as
    // done, suppresses further `on_reply_` dispatches, skips any pending
    // commit phase, and fires `on_done_` once with whatever closest
    // replies have accumulated so far. Idempotent: a second call is a
    // no-op. Callers should use this from inside an `on_reply` handler
    // once they have found the answer they were looking for (e.g.
    // immutable_get's first verified value, mutable_get with
    // `latest=false`). JS: dht-rpc/lib/query.js:385-390 (_destroy).
    void destroy();

    // Access results
    const std::vector<QueryReply>& closest_replies() const { return closest_replies_; }

    // Convenience: the `from` address of every closest reply, in XOR-distance order.
    // JS: dht-rpc/lib/query.js:72-80 (`get closestNodes()`).
    std::vector<compact::Ipv4Address> closest_nodes() const;

    // Socket accessor (for commit lambdas that need lifetime-safe access)
    rpc::RpcSocket& socket() { return socket_; }

    // State introspection (used by tests and for observability). These
    // mirror the JS query.js internal flags described in the slowdown /
    // table-retry comments below.
    bool from_table() const { return from_table_; }
    bool slowdown_engaged() const { return slowdown_; }
    int successes() const { return successes_; }
    int errors() const { return errors_; }

private:
    rpc::RpcSocket& socket_;
    // Private constructor — use Query::create()
    Query(rpc::RpcSocket& socket, const routing::NodeId& target,
          uint32_t command, const std::vector<uint8_t>* value = nullptr);

    routing::NodeId target_;
    uint32_t command_;
    std::optional<std::vector<uint8_t>> value_;
    int concurrency_ = DEFAULT_CONCURRENCY;
    int retries_ = QUERY_RETRIES;   // per-visit request retries (JS opts.retries)
    bool internal_ = false;
    bool only_closest_nodes_ = false;  // JS opts.onlyClosestNodes (query-4)
    bool done_ = false;
    bool committing_ = false;
    int commit_success_ = 0;  // commits that got a response (vs timeout/drop)
    int inflight_ = 0;
    int commit_inflight_ = 0;
    // JS `_slow` (query.js:32,250-257,312-316) — count of in-flight requests
    // that have retried at least once (fired their oncycle). Effective
    // concurrency = (slowdown?3:concurrency) + slow_, so slow peers don't
    // starve the frontier, and the flush can start early once every remaining
    // in-flight request is slow and we already hold k closest replies.
    int slow_ = 0;
    // Set true only while start() re-inserts the caller's pre-seeds so the
    // onlyClosestNodes gate (which blocks table-seeds and closerNodes) does not
    // also block the seeds. JS adds seeds in the constructor BEFORE the flag is
    // set (query.js:51-69), so seeds are always admitted.
    bool seeding_pre_ = false;

    // Re-entrancy state for destroy() / on_done_ scheduling.
    //   dispatching_reply_   : true while on_visit_response is inside
    //                          `on_reply_(reply)`. destroy() called in
    //                          that window defers on_done_ firing to
    //                          the end of on_visit_response.
    //   pending_done_        : set by destroy() when dispatching_reply_
    //                          was true. Drained at the end of
    //                          on_visit_response.
    //   pending_done_fired_  : idempotency guard so on_done_ cannot
    //                          fire twice even if destroy() is called
    //                          from both the re-entrant and the
    //                          external paths.
    bool dispatching_reply_ = false;
    bool pending_done_ = false;
    bool pending_done_fired_ = false;

    // JS parity: slowdown optimisation + table-fallback.
    //   from_table_: set true when the frontier was filled from the routing
    //                table. When it stays false (caller pre-seeded), both
    //                the cold-start slowdown and the <k/4-success table
    //                retry activate. JS: query.js:36, 111-120.
    //   slowdown_  : binary cold-start throttle. While true, read_more()
    //                caps concurrency at SLOWDOWN_CONCURRENCY (3). Turned
    //                on before the first reply, off once we have heard
    //                back from `concurrency_` peers. JS: query.js:33,
    //                189-191, 283-285.
    //   successes_ /
    //   errors_    : tick-scoped response counters used by the slowdown
    //                and table-retry heuristics. JS: query.js:23-24.
    bool from_table_ = false;
    bool slowdown_ = false;
    int successes_ = 0;
    int errors_ = 0;

    // Closest k replies sorted by XOR distance
    std::vector<QueryReply> closest_replies_;

    // Pending nodes to query (LIFO stack — pop closest first)
    struct PendingNode {
        routing::NodeId id;
        compact::Ipv4Address addr;
    };
    std::vector<PendingNode> pending_;

    // Seeds collected via add_seed_node() before start(). Stored in
    // caller-order (closest-first) and reverse-inserted into pending_ at
    // start() time so the closest node sits on top of the stack.
    // Matches JS query.js:47-67.
    std::vector<PendingNode> pre_seeds_;

    // Seen nodes: address → state
    enum class NodeState { PENDING, DONE, DOWN };
    std::unordered_map<std::string, NodeState> seen_;

    // Referrers per seen address (JS overloads `_seen` to hold the refs array).
    // `refs_[addr]` = the addresses of nodes that told us about `addr`. When
    // `addr` later times out we emit a DOWN_HINT to each referrer so they can
    // re-check and evict it (JS query.js:140-169,298-332). Downhint emission +
    // rate limiting live on the RpcSocket (JS dht._downHints*).
    std::unordered_map<std::string, std::vector<compact::Ipv4Address>> refs_;

    OnReplyCallback on_reply_;
    OnDoneCallback on_done_;
    OnCommitCallback on_commit_;

    // Add nodes from local routing table
    void seed_from_table();

    // Add a node to the pending list (if not already seen). `ref`, when set, is
    // the address of the node that referred us to `addr` (JS `_addPending`'s
    // `ref` arg = `m.from`); it is recorded for DOWN_HINT gossip on timeout.
    void add_pending(const routing::NodeId& id, const compact::Ipv4Address& addr,
                     const compact::Ipv4Address* ref = nullptr);

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

    // Idempotent on_done_ dispatch. All completion paths (maybe_finish,
    // do_commit, destroy) go through this so on_done_ fires AT MOST once
    // across the lifetime of a Query. `error` is 0 on success or a QUERY_ERR_*
    // code (only the commit-phase paths ever pass non-zero).
    void fire_done_once(int error);
};

}  // namespace query
}  // namespace hyperdht
