// Iterative Kademlia query engine implementation — walks the network
// towards a target, maintaining a sorted frontier of k closest nodes.
// Drives FIND_NODE (and any wrapped command) with configurable parallelism.
//
// Resource limits: seen_ map capped at 4096 entries; port-0 addresses
// from closer_nodes are filtered before insertion.

#include "hyperdht/query.hpp"

#include <algorithm>

namespace hyperdht {
namespace query {

// ---------------------------------------------------------------------------
// Query — construction, bootstrap, start
//
// JS: .analysis/js/dht-rpc/lib/query.js:9-70 (Query extends Readable —
//     concurrency, retries, _seen map, optional commit hook, seeded with
//     opts.nodes / opts.replies if provided)
//     .analysis/js/dht-rpc/lib/query.js:122-131 (_open — _addFromTable then
//     resolveBootstrapNodes)
//     .analysis/js/dht-rpc/lib/query.js:111-120 (_addFromTable)
//
// C++ diffs from JS:
//   - JS Query is a streamx Readable that pushes replies via this.push(data)
//     and exposes a `finished()` Promise. C++ uses three explicit callbacks
//     (on_reply / on_done / on_commit) and `maybe_finish()` is the
//     equivalent of JS's `_flush` / "drain to end" logic.
//   - JS's `_seen` map overloads its value to hold DONE/DOWN sentinels OR the
//     refs array; C++ uses a NodeState enum plus a parallel `refs_` map. Both
//     drive DOWN_HINT gossip on timeout (downhint-1).
//   - JS holds an explicit `_session` (with auto-destroy); C++ has none —
//     the RpcSocket layer owns request lifecycles.
// ---------------------------------------------------------------------------

std::shared_ptr<Query> Query::create(rpc::RpcSocket& socket,
                                      const routing::NodeId& target,
                                      uint32_t command,
                                      const std::vector<uint8_t>* value) {
    auto q = std::shared_ptr<Query>(new Query(socket, target, command, value));
    return q;
}

Query::Query(rpc::RpcSocket& socket, const routing::NodeId& target,
             uint32_t command, const std::vector<uint8_t>* value)
    : socket_(socket), target_(target), command_(command) {
    if (value) value_ = *value;
}

// JS: dht-rpc/lib/query.js:122-131 — `_open` first calls _addFromTable (which
// early-returns if pending already contains k entries) and then, only if
// still short, iterates `dht._resolveBootstrapNodes()` to top up the frontier.
//
// C++ implements the _addFromTable half faithfully (the early-return +
// `from_table_` flag mirror JS exactly) but does NOT do the bootstrap
// top-up automatically. Callers with a sparse routing table must prime the
// query by calling `add_bootstrap()` before `start()`. This is a deliberate
// split so that `Query` does not need to reach through the DHT class for
// bootstrap resolution. See docs/JS-PARITY-GAPS.md bootstrap-walk note.
void Query::start() {
    // JS query.js:50-62: caller seeds are pushed in reverse so the closest
    // entry ends up on top of the LIFO pending stack. seeding_pre_ lets these
    // seeds bypass the onlyClosestNodes gate (JS sets that flag AFTER seeding).
    seeding_pre_ = true;
    for (auto it = pre_seeds_.rbegin(); it != pre_seeds_.rend(); ++it) {
        add_pending(it->id, it->addr);
    }
    seeding_pre_ = false;
    pre_seeds_.clear();

    if (pending_.size() < routing::K) {
        seed_from_table();
    }
    read_more();
}

void Query::add_bootstrap(const compact::Ipv4Address& addr) {
    // Bootstrap nodes don't have IDs — use a zeroed ID
    // They'll be queried but won't be in closest_replies
    routing::NodeId zero_id{};
    zero_id.fill(0);
    add_pending(zero_id, addr);
}

// JS: dht-rpc/lib/query.js:47-67 — caller-provided `opts.nodes` /
// `opts.closestReplies` are pushed onto the pending stack in reverse so the
// closest entry ends up on top. C++ collects the caller-supplied seeds in
// natural (closest-first) order here and defers the reverse-insertion to
// `start()`, which keeps the public API close to the JS spec while still
// producing the correct pop order.
void Query::add_seed_node(const routing::NodeId& id, const compact::Ipv4Address& addr) {
    pre_seeds_.push_back({id, addr});
}

// ---------------------------------------------------------------------------
// Seeding
//
// JS: .analysis/js/dht-rpc/lib/query.js:111-120 (_addFromTable — picks the
//     k closest from the routing table and adds them in natural order)
// ---------------------------------------------------------------------------

// JS: dht-rpc/lib/query.js:111-120 — `_addFromTable` first checks
// `_pending.length >= k` and returns without touching `_fromTable`, otherwise
// flips the flag and tops the frontier up from the routing table. We
// replicate both: `from_table_` is only set when the table actually filled
// slots, and the `closest()` call is sized to respect any caller pre-seeds.
void Query::seed_from_table() {
    if (pending_.size() >= routing::K) return;
    from_table_ = true;

    const size_t need = routing::K - pending_.size();
    auto closest = socket_.table().closest(target_, need);
    // Add in reverse order so closest ends up on top of the stack
    for (auto it = closest.rbegin(); it != closest.rend(); ++it) {
        auto addr = compact::Ipv4Address::from_string((*it)->host, (*it)->port);
        add_pending((*it)->id, addr);
    }
}

// ---------------------------------------------------------------------------
// Pending management
//
// JS: .analysis/js/dht-rpc/lib/query.js:140-169 (_addPending — checks
//     _seen[addr] for DONE/DOWN/refs and dedupes; rejects nodes that are
//     not closer than the current k-th closest)
//
// C++ diffs from JS:
//   - C++ does the closeness check inside read_more() instead of inside
//     add_pending(); add_pending here does the seen-set + filter check plus the
//     refs/DOWN dispatch (records referrers, DOWN_HINTs a re-seen dead node).
// ---------------------------------------------------------------------------

void Query::add_pending(const routing::NodeId& id, const compact::Ipv4Address& addr,
                        const compact::Ipv4Address* ref) {
    // JS query.js:141 — onlyClosestNodes queries never expand the frontier.
    // The caller's pre-seeds bypass this (seeding_pre_), matching JS which sets
    // the flag only after the constructor seeds are added.
    if (only_closest_nodes_ && !seeding_pre_) return;

    std::string key = addr.host_string() + ":" + std::to_string(addr.port);

    // JS query.js:144-159 — dispatch on the existing _seen state.
    auto it = seen_.find(key);
    if (it != seen_.end()) {
        if (it->second == NodeState::DOWN) {
            // Already known-dead: gossip a fresh DOWN_HINT to the new referrer
            // (JS query.js:151-154 `_downHint(ref, node)`).
            if (ref) socket_.try_send_down_hint(*ref, addr);
        } else if (it->second == NodeState::PENDING) {
            // Still queued: just record the extra referrer (JS query.js:156-159).
            if (ref) refs_[key].push_back(*ref);
        }
        // DONE: nothing to do. Never re-add (dedup).
        return;
    }

    constexpr size_t MAX_SEEN = 4096;  // C13: cap to prevent heap exhaustion
    if (seen_.size() >= MAX_SEEN) return;

    // Honour the RpcSocket's filter_node callback (JS `_filterNode`).
    if (!socket_.filter_accept(id, addr)) return;

    seen_[key] = NodeState::PENDING;
    if (ref) refs_[key].push_back(*ref);
    pending_.push_back({id, addr});
}

// ---------------------------------------------------------------------------
// Iteration
//
// JS: .analysis/js/dht-rpc/lib/query.js:171-209 (_read / _readMore — pops up
//     to `concurrency + _slow` pending nodes per tick, skips ones no longer
//     closer than the kth, and `_flush()`es when nothing remains in flight)
//     .analysis/js/dht-rpc/lib/query.js:362-383 (_visit — fires
//     this.dht._request with the visit/error callbacks and a configurable
//     retry count)
//
// C++ parity with JS:
//   - Cold-start "slowdown" (query.js:189-191): caps concurrency at 3 until the
//     first reply on a caller-seeded query — implemented via slowdown_.
//   - Retries default 5 (query.js:28-29): plumbed through retries_ → the
//     RpcSocket per-request retry count (query-1).
//   - Unresponsive nodes are marked DOWN and gossiped via DOWN_HINT to every
//     referrer (query.js:298-332) — see on_visit_timeout (downhint-1).
// ---------------------------------------------------------------------------

// JS: dht-rpc/lib/query.js:176-209 — `_readMore` applies the cold-start
// slowdown, drains pending up to the effective concurrency (widened by the
// `_slow` retry count), engages the slowdown flag on the very first tick when
// the caller pre-seeded the frontier, and — once pending is empty and either
// nothing is in flight OR every remaining request is slow with k already
// satisfied — either retries from the routing table (if most cached nodes
// failed) or flushes the query.
//
// C++ diffs from JS:
//   - The additive `_slow` counter IS ported (query-3): visit() registers a
//     per-request oncycle hook on the RpcSocket that widens concurrency and
//     enables the early flush.
//   - C++ has no streamx Readable backpressure, so there is no equivalent of
//     `this.push(data)` returning false to pause iteration.
void Query::read_more() {
    // JS query.js:177 — `if (this.destroying || this._commiting) return`. Once
    // the commit phase has begun the walk must not fan out again (a late slow
    // reply landing mid-commit would otherwise re-enter here).
    if (done_ || committing_) return;

    // JS query.js:179 — effective concurrency widens by _slow so that requests
    // still waiting on a retry don't hold back new fan-out.
    const int base = slowdown_ ? SLOWDOWN_CONCURRENCY : concurrency_;
    const int effective_concurrency = base + slow_;

    while (inflight_ < effective_concurrency && !pending_.empty()) {
        auto next = pending_.back();
        pending_.pop_back();

        // Skip if not closer than k-th closest (JS query.js:183).
        // is_closer() already returns true while closest_replies_ is under
        // k, so there is no need for a redundant size guard here.
        // Bootstrap nodes (zeroed id) always pass through — mirrors
        // JS's `next.id` null-check that short-circuits the skip.
        routing::NodeId zero_id{};
        zero_id.fill(0);
        if (next.id != zero_id && !is_closer(next.id)) continue;

        visit(next);
    }

    // JS query.js:189-191: if the caller pre-seeded the frontier and nothing
    // has come back yet, give the closest pre-seeded node a head start by
    // capping concurrency at SLOWDOWN_CONCURRENCY until the first reply.
    if (!from_table_ && successes_ == 0 && errors_ == 0) {
        slowdown_ = true;
    }

    if (!pending_.empty()) return;

    // JS query.js:196-199 — enter the flush/retry path when either there is
    // nothing in flight OR every remaining in-flight request is slow (has
    // retried) and we already hold a full k-result set. The latter lets the
    // commit start without waiting out the slow peers' full retry budgets.
    const bool all_slow_and_full =
        slow_ == inflight_ && closest_replies_.size() >= routing::K;
    if (inflight_ > 0 && !all_slow_and_full) return;

    // JS query.js:200-205: once the frontier drains and everything in flight
    // has resolved, if we were running on caller-provided seeds and most of
    // them failed, re-seed from the routing table and keep walking. This is
    // the "cold-cache tripped, fall back to the live table" path.
    //
    // The recursive read_more() below is bounded by one extra stack frame:
    // if seed_from_table() added nodes, the next read_more() dispatches
    // them and returns (pending non-empty after the pop loop); if it added
    // nothing, from_table_ is now true and the retry guard cannot fire a
    // second time. Recursion cannot grow beyond depth 2 in this path.
    if (!from_table_ &&
        successes_ < static_cast<int>(routing::K) / 4) {
        seed_from_table();
        if (from_table_) {
            read_more();
            return;
        }
    }

    maybe_finish();
}

// JS: query.js:362-383 — _visit(to): increments inflight, calls
//     dht._request with the bound _onvisit / _onerror callbacks, sets
//     req.retries / req.oncycle for slowdown tracking.
void Query::visit(const PendingNode& node) {
    inflight_++;

    messages::Request req;
    req.to.addr = node.addr;
    req.command = command_;
    req.target = target_;
    if (value_.has_value()) {
        req.value = *value_;
    }

    // Capture shared_ptr to prevent use-after-free if Query is released early
    auto self = shared_from_this();
    auto captured_node = node;

    // JS `_slow` bookkeeping (query.js:250-257,312-316): a per-request oncycle
    // hook fires once — on the request's first retry cycle — marking it "slow".
    // `cycled` mirrors JS `req.oncycle === noop`: set when the hook fired, and
    // drives the matching `_slow--` when the request finally settles.
    auto cycled = std::make_shared<bool>(false);
    auto dec_slow = [self, cycled]() {
        if (*cycled) self->slow_--;
    };

    // JS query.js:28-29,380 — query-walk requests retry `retries_` times
    // (default 5 → 6 transmissions to a silent node) and register the oncycle
    // hook. Both plumb through the RpcSocket's per-request request() overload.
    socket_.request(req,
        /*timeout_override_ms=*/0, retries_,
        [self, captured_node, dec_slow](const messages::Response& resp) {
            self->inflight_--;
            dec_slow();
            self->on_visit_response(captured_node, resp);
        },
        [self, captured_node, dec_slow](uint16_t) {
            self->inflight_--;
            dec_slow();
            self->on_visit_timeout(captured_node);
        },
        [self, cycled](uint16_t) {  // oncycle — first retry marks the req slow
            if (self->done_) return;
            if (*cycled) return;    // fire once (JS resets req.oncycle to noop)
            *cycled = true;
            self->slow_++;
            self->read_more();
        });
}

// JS: query.js:259-296 — _onvisit(m, req): marks DONE in _seen, bumps the
//     success/error counters, pushes onto closestReplies if it has an id and
//     is closer than the kth, iterates m.closerNodes (filtering with
//     dht._filterNode + skipping our own id), and once enough results have
//     come back turns the cold-start slowdown off.
void Query::on_visit_response(const PendingNode& node, const messages::Response& resp) {
    // Early termination: destroy() may have been called from a previous
    // on_reply dispatch. Any in-flight responses that land afterwards
    // must not re-enter the pipeline (would re-fire on_reply_, restart
    // read_more, etc.). JS achieves the same via the destroyed flag in
    // query.js:177.
    if (done_) return;

    // Mark as done
    std::string key = node.addr.host_string() + ":" + std::to_string(node.addr.port);
    seen_[key] = NodeState::DONE;

    // JS query.js:265 — a reply that lands after the commit phase has begun
    // still marks the node DONE but does no further walk/push work.
    if (committing_) return;

    // JS query.js:267-268 — error code 0 counts as a success, anything else
    // counts towards the error budget. The counters feed both the cold-start
    // slowdown and the <k/4 table-retry path. Note: C++ `resp.error` is a
    // `std::optional<uint32_t>` while JS's compact decoder defaults the
    // field to 0 when absent. We replicate JS by treating "missing error"
    // as success, NOT as failure (otherwise optional::operator== would
    // quietly count every successful reply as an error).
    const bool is_success =
        !resp.error.has_value() || *resp.error == 0;
    if (is_success) {
        successes_++;
    } else {
        errors_++;
    }

    // Build query reply.
    // JS: from.id comes solely from the wire (validated by io.js:619
    // validateId), not from the frontier's pre-computed ID. Zero-init
    // so replies without a validated resp.id get from_id = all-zeros,
    // which the push_closest gate below filters out (matching JS
    // query.js:270 `m.from.id !== null`).
    QueryReply reply;
    reply.from_id = {};
    reply.from_addr = node.addr;
    reply.token = resp.token;
    reply.value = resp.value;
    reply.closer_nodes = resp.closer_nodes;

    // Set ID from validated response (already cleaned by rpc.cpp validateId)
    if (resp.id.has_value()) {
        std::copy(resp.id->begin(), resp.id->end(), reply.from_id.begin());
    }

    // Add to closest replies (only on success + non-zero id, matching
    // JS query.js:270 which gates `_pushClosest` on `m.error === 0`).
    routing::NodeId zero_id{};
    zero_id.fill(0);
    if (is_success && reply.from_id != zero_id) {
        push_closest(reply);
    }

    // Add closer nodes to pending. Compute the id from the address so we
    // can apply the filter, deduplicate correctly, and rank honestly in
    // `closest_replies_`. Matches JS `query.js:273-280`. The responding node's
    // address (node.addr = JS `m.from`) is recorded as the referrer so a later
    // timeout on any of these can gossip a DOWN_HINT back to it.
    for (const auto& closer : resp.closer_nodes) {
        if (closer.port == 0) continue;  // H13: skip port 0 addresses
        auto closer_id = rpc::compute_peer_id(closer);
        // Skip if equal to our own id.
        if (closer_id == socket_.table().id()) continue;
        add_pending(closer_id, closer, &node.addr);
    }

    // JS query.js:283-285 — once we have heard back from the initial cohort
    // the slowdown has served its purpose; reopen the full concurrency.
    if (!from_table_ && successes_ + errors_ >= concurrency_) {
        slowdown_ = false;
    }

    // Notify caller. JS query.js:287-294 — error replies (m.error !== 0) are
    // NOT surfaced to the consumer (map/push); they still contributed
    // closerNodes + success/error bookkeeping above. Only success replies are
    // dispatched. dispatching_reply_ defers a destroy()-from-on_reply so its
    // on_done_ fires after read_more() unwinds.
    if (is_success && on_reply_) {
        dispatching_reply_ = true;
        on_reply_(reply);
        dispatching_reply_ = false;
    }

    // Continue iterating. read_more() checks `done_`/`committing_` and no-ops
    // if destroy() ran during on_reply_.
    read_more();

    // If destroy() was deferred from inside on_reply_, fire on_done_ now that
    // we're about to unwind past this frame (destroy = success, error 0).
    if (pending_done_) {
        pending_done_ = false;
        fire_done_once(QUERY_OK);
    }
}

// JS: query.js:298-310 — _onerror(err, req): marks DOWN if the error code
//     is REQUEST_TIMEOUT, fires DOWN_HINTs at every ref of this addr, bumps
//     the error counter, and calls _readMore().
//
// Note: JS `_onerror` intentionally does NOT disengage `_slowdown` — only
// `_onvisit` does. Timeouts alone never trip the slowdown off, even after
// `concurrency_` of them. That biases the throttle toward waiting for real
// replies rather than discounting silent peers. C++ matches the JS by
// performing the disengage check only in `on_visit_response`.
void Query::on_visit_timeout(const PendingNode& node) {
    if (done_) return;  // destroy()'d — suppress late timeouts

    std::string key = node.addr.host_string() + ":" + std::to_string(node.addr.port);

    // JS query.js:302-305 — on REQUEST_TIMEOUT mark the node DOWN and gossip a
    // DOWN_HINT to every node that referred us to it, so those referrers can
    // re-check and evict the dead node. RpcSocket applies the per-tick rate
    // limit (JS dht._downHintsRateLimit). A C++ RPC timeout is always the
    // retry-exhausted case, i.e. JS's REQUEST_TIMEOUT.
    seen_[key] = NodeState::DOWN;
    auto it = refs_.find(key);
    if (it != refs_.end()) {
        for (const auto& ref : it->second) {
            socket_.try_send_down_hint(ref, node.addr);
        }
    }

    // JS query.js:308 — a timeout counts towards the error budget so the
    // <k/4-success table-retry path can trip when the cold cache was bad.
    errors_++;

    read_more();
}

// ---------------------------------------------------------------------------
// Closest replies management
//
// JS: .analysis/js/dht-rpc/lib/query.js:334-351 (_pushClosest — insertion
//     sort by XOR distance to target, dedupes equal-id entries, caps at k)
//     .analysis/js/dht-rpc/lib/query.js:133-138 (_isCloser — true while we
//     have fewer than k replies, otherwise compare against the kth)
//     .analysis/js/dht-rpc/lib/query.js:353-360 (_compare — XOR distance
//     comparator against `this.target`)
// ---------------------------------------------------------------------------

void Query::push_closest(const QueryReply& reply) {
    // Insertion sort into sorted vector (by XOR distance to target).
    // JS: query.js:334-351 — bubble the new entry toward the front until
    // sorted, dedupe equal ids by splicing out the entry currently at
    // `i + 1` (which, after prior swaps, is the still-unsorted copy of
    // the new reply), and cap the list at k.
    closest_replies_.push_back(reply);

    for (int i = static_cast<int>(closest_replies_.size()) - 2; i >= 0; i--) {
        int cmp = compare(closest_replies_[static_cast<size_t>(i)].from_id,
                          reply.from_id);
        if (cmp < 0) break;    // Already in right place
        if (cmp == 0) {
            // Duplicate: the newly-added entry has bubbled to index i+1
            // (possibly after swaps above). Splice it out specifically —
            // `pop_back()` would remove the *tail* element, which is only
            // the duplicate on the first iteration.
            closest_replies_.erase(
                closest_replies_.begin() + static_cast<std::ptrdiff_t>(i + 1));
            return;
        }
        std::swap(closest_replies_[static_cast<size_t>(i)],
                  closest_replies_[static_cast<size_t>(i + 1)]);
    }

    // Cap at k
    if (closest_replies_.size() > routing::K) {
        closest_replies_.pop_back();
    }
}

// JS: dht-rpc/lib/query.js:72-80 — `get closestNodes()` flattens closestReplies[].from.
std::vector<compact::Ipv4Address> Query::closest_nodes() const {
    std::vector<compact::Ipv4Address> out;
    out.reserve(closest_replies_.size());
    for (const auto& reply : closest_replies_) {
        out.push_back(reply.from_addr);
    }
    return out;
}

bool Query::is_closer(const routing::NodeId& id) const {
    if (closest_replies_.size() < routing::K) return true;
    return compare(id, closest_replies_.back().from_id) < 0;
}

int Query::compare(const routing::NodeId& a, const routing::NodeId& b) const {
    return routing::compare_distance(target_, a, b);
}

// ---------------------------------------------------------------------------
// Completion
//
// JS: .analysis/js/dht-rpc/lib/query.js:211-223 (_flush — sets _commiting,
//     either pushes null to end the readable or kicks the commit pass)
//     .analysis/js/dht-rpc/lib/query.js:225-248 (_endAfterCommit — awaits
//     all commit promises, ends the stream on success, errors out if every
//     commit failed)
//     .analysis/js/dht-rpc/lib/query.js:392-403 (autoCommit — the default
//     commit fn: re-issues the original command with the per-reply token)
//
// C++ parity with JS (commit-1):
//   - do_commit() hands a continuation callback to the caller's on_commit_ and
//     fires on_done_ when commit_inflight_ reaches zero, mirroring JS's
//     Promise.all over the per-reply commit promises.
//   - An empty closest set OR all-failed commits report QUERY_ERR_TOO_FEW_NODES
//     via on_done_'s error arg (JS destroy('Too few nodes responded')). A
//     tokenless closest reply counts as a failed commit (JS autoCommit rejects).
//   - A commit only triggers when on_commit_ is set (JS `_commit !== null`);
//     otherwise a plain lookup/get ends with success.
// ---------------------------------------------------------------------------

void Query::maybe_finish() {
    if (done_ || committing_) return;
    if (!pending_.empty()) return;

    // Mirror read_more's flush gate: proceed when nothing is in flight OR every
    // remaining request is slow and we already hold a full k-result set.
    const bool all_slow_and_full =
        slow_ == inflight_ && closest_replies_.size() >= routing::K;
    if (inflight_ > 0 && !all_slow_and_full) return;

    // Query iteration complete
    if (on_commit_) {
        do_commit();
    } else {
        // JS query.js:215-218 — no commit fn ⇒ push(null): a plain lookup/get
        // ends successfully regardless of how many nodes replied.
        done_ = true;
        fire_done_once(QUERY_OK);
    }
}

void Query::destroy() {
    if (done_) return;          // idempotent
    done_ = true;
    pending_.clear();           // stop fanning out
    committing_ = true;         // short-circuit do_commit() if pending

    // When destroy() is invoked from inside an on_reply_ callback (the
    // typical "I found what I was looking for" pattern — see
    // dht_ops::immutable_get / mutable_get(latest=false)), firing
    // on_done_ here would run the caller's completion handler while
    // on_visit_response is still executing on the stack. Any future
    // work after the on_reply_ invocation in on_visit_response would
    // then be touching a query whose caller already saw "done". That's
    // brittle, even though the current on_visit_response body doesn't
    // actually touch `this` after on_reply_.
    //
    // Solution: defer the on_done_ firing to after on_visit_response
    // unwinds. For externally-initiated destroy() (no reply dispatch
    // in progress) we fire immediately, preserving idempotency for
    // callers that just want to tear the query down synchronously.
    if (dispatching_reply_) {
        pending_done_ = true;
    } else {
        // destroy() is the "found what I wanted" / caller teardown path — a
        // successful early exit (JS destroy() with no error). error = 0.
        fire_done_once(QUERY_OK);
    }
}

void Query::fire_done_once(int error) {
    if (!pending_done_fired_ && on_done_) {
        pending_done_fired_ = true;
        on_done_(error, closest_replies_);
    }
}

void Query::do_commit() {
    committing_ = true;
    commit_success_ = 0;

    // JS query.js:220-228 — `ps` is EVERY closest reply mapped through the
    // commit fn. An empty closest set means no node responded → destroy the
    // query with 'Too few nodes responded'.
    if (closest_replies_.empty()) {
        done_ = true;
        fire_done_once(QUERY_ERR_TOO_FEW_NODES);
        return;
    }

    // Pending counter covers the FULL closest set (not just tokened replies),
    // and is set before dispatching any commit so a synchronously-settling
    // commit (tokenless reply, or a store dropped by a full congestion queue)
    // cannot drive it to zero before every commit is issued.
    commit_inflight_ = static_cast<int>(closest_replies_.size());
    auto self = shared_from_this();

    // JS _endAfterCommit (query.js:238-247): succeed if ANY commit resolved,
    // otherwise reject with the last error. Settles exactly once per commit —
    // RpcSocket guarantees exactly one of on_response/on_timeout fires; the
    // drop path (request() == 0) is turned into a timeout by the commit sender.
    auto finish = [self](bool ok) {
        if (ok) self->commit_success_++;
        if (--self->commit_inflight_ == 0) {
            self->done_ = true;
            self->fire_done_once(self->commit_success_ > 0
                                     ? QUERY_OK
                                     : QUERY_ERR_TOO_FEW_NODES);
        }
    };

    for (const auto& reply : closest_replies_) {
        if (!reply.token.has_value()) {
            // JS autoCommit (query.js:392-393): a tokenless closest reply
            // rejects — a FAILED commit. on_commit_ can't run without a token.
            finish(false);
            continue;
        }
        on_commit_(reply,
            [finish](const messages::Response&) { finish(true); },
            [finish](uint16_t) { finish(false); });
    }
}

}  // namespace query
}  // namespace hyperdht
