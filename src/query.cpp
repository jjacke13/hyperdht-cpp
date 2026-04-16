// Iterative Kademlia query engine implementation — walks the network
// towards a target, maintaining a sorted frontier of k closest nodes.
// Drives FIND_NODE (and any wrapped command) with configurable parallelism.

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
//   - JS's `_seen` map tracks DONE/DOWN/[refs]; C++ uses a NodeState enum
//     and does NOT track refs (no DOWN_HINT propagation yet — see the
//     gaps doc).
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
    // entry ends up on top of the LIFO pending stack.
    for (auto it = pre_seeds_.rbegin(); it != pre_seeds_.rend(); ++it) {
        add_pending(it->id, it->addr);
    }
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
//     add_pending(); add_pending here only does the seen-set + filter check.
//   - The DOWN/refs path is not implemented (no DOWN_HINT yet).
// ---------------------------------------------------------------------------

void Query::add_pending(const routing::NodeId& id, const compact::Ipv4Address& addr) {
    std::string key = addr.host_string() + ":" + std::to_string(addr.port);
    if (seen_.count(key) > 0) return;  // Already seen

    // Honour the RpcSocket's filter_node callback (JS `_filterNode`).
    if (!socket_.filter_accept(id, addr)) return;

    seen_[key] = NodeState::PENDING;
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
// C++ diffs from JS:
//   - JS implements a "slowdown" optimisation: after the first readMore tick
//     it caps concurrency at 3 until the first node replies, to give the
//     true closest node a head start. C++ does NOT implement this — every
//     iteration uses the static `concurrency_` value.
//   - JS retries failed visits up to opts.retries (default 5). C++ relies on
//     the RpcSocket-level retry policy and treats any timeout as a single
//     failure.
//   - JS marks unresponsive nodes DOWN and propagates a DOWN_HINT back to
//     the original ref. C++ marks DOWN but does not gossip the hint.
// ---------------------------------------------------------------------------

// JS: dht-rpc/lib/query.js:176-209 — `_readMore` applies the cold-start
// slowdown, drains pending up to the effective concurrency, engages the
// slowdown flag on the very first tick when the caller pre-seeded the
// frontier, and — once pending is empty and no requests are in flight —
// either retries from the routing table (if most of the cached nodes
// failed) or flushes the query.
//
// C++ diffs from JS:
//   - The additive `_slow` oncycle counter is NOT ported: RpcSocket does not
//     expose a per-retry hook. Tracked as a follow-up in docs/JS-PARITY-GAPS.
//   - C++ has no streamx Readable backpressure, so there is no equivalent of
//     `this.push(data)` returning false to pause iteration.
void Query::read_more() {
    if (done_) return;

    const int effective_concurrency = slowdown_ ? SLOWDOWN_CONCURRENCY : concurrency_;

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

    // JS query.js:196-199 also allows entering the flush/retry path when
    //   `_slow === inflight && closestReplies.length >= k`
    // (i.e. every remaining in-flight request has been marked slow by the
    // oncycle hook and we already have a full result set). C++ does NOT
    // implement the oncycle counter — see the `_slow` deferral note in
    // docs/JS-PARITY-GAPS.md. Consequence: flush is delayed until all
    // in-flight requests finalise. Latency gap only; final result matches.
    if (inflight_ > 0) return;

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

    socket_.request(req,
        [self, captured_node](const messages::Response& resp) {
            self->inflight_--;
            self->on_visit_response(captured_node, resp);
        },
        [self, captured_node](uint16_t) {
            self->inflight_--;
            self->on_visit_timeout(captured_node);
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

    // Build query reply
    QueryReply reply;
    reply.from_id = node.id;
    reply.from_addr = node.addr;
    reply.token = resp.token;
    reply.value = resp.value;
    reply.closer_nodes = resp.closer_nodes;

    // Update ID from response if available
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
    // `closest_replies_`. Matches JS `query.js:273-280`.
    for (const auto& closer : resp.closer_nodes) {
        auto closer_id = rpc::compute_peer_id(closer);
        // Skip if equal to our own id.
        if (closer_id == socket_.table().id()) continue;
        add_pending(closer_id, closer);
    }

    // JS query.js:283-285 — once we have heard back from the initial cohort
    // the slowdown has served its purpose; reopen the full concurrency.
    if (!from_table_ && successes_ + errors_ >= concurrency_) {
        slowdown_ = false;
    }

    // Notify caller. Set `dispatching_reply_` so that a `destroy()`
    // call from inside this callback defers its on_done_ firing to
    // after `read_more()` unwinds below. That keeps the completion
    // hook off the same call stack as an in-progress visit — JS-style
    // event-loop semantics without needing a timer.
    if (on_reply_) {
        dispatching_reply_ = true;
        on_reply_(reply);
        dispatching_reply_ = false;
    }

    // Continue iterating. read_more() checks `done_` and no-ops if
    // destroy() ran during on_reply_.
    read_more();

    // If destroy() was deferred from inside on_reply_, fire on_done_
    // now that we're about to unwind past this frame.
    if (pending_done_) {
        pending_done_ = false;
        fire_done_once();
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
    seen_[key] = NodeState::DOWN;

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
// C++ diffs from JS:
//   - C++'s do_commit() hands a continuation callback to the caller's
//     on_commit_, fires on_done_ when commit_inflight_ reaches zero. JS uses
//     Promise.all over the per-reply commit promises and either push(null)s
//     or destroy()s on failure.
//   - JS treats "no nodes responded" (`!ps.length`) as a destroy error;
//     C++ treats an empty closest set as success and fires on_done_ with
//     an empty vector.
//   - JS's commit only triggers when `this._commit !== null`. C++ behaves
//     identically by guarding on `if (on_commit_)`.
// ---------------------------------------------------------------------------

void Query::maybe_finish() {
    if (done_ || committing_) return;
    if (inflight_ > 0) return;
    if (!pending_.empty()) return;

    // Query iteration complete
    if (on_commit_) {
        do_commit();
    } else {
        done_ = true;
        fire_done_once();
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
        fire_done_once();
    }
}

void Query::fire_done_once() {
    if (!pending_done_fired_ && on_done_) {
        pending_done_fired_ = true;
        on_done_(closest_replies_);
    }
}

void Query::do_commit() {
    committing_ = true;
    commit_inflight_ = 0;

    if (closest_replies_.empty()) {
        done_ = true;
        fire_done_once();
        return;
    }

    for (const auto& reply : closest_replies_) {
        if (!reply.token.has_value()) continue;

        commit_inflight_++;
        auto self = shared_from_this();
        on_commit_(reply, [self](const messages::Response&) {
            self->commit_inflight_--;
            if (self->commit_inflight_ == 0) {
                self->done_ = true;
                self->fire_done_once();
            }
        });
    }

    // If no commits were sent (no tokens), finish immediately
    if (commit_inflight_ == 0) {
        done_ = true;
        fire_done_once();
    }
}

}  // namespace query
}  // namespace hyperdht
