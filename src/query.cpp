#include "hyperdht/query.hpp"

#include <algorithm>

namespace hyperdht {
namespace query {

Query::Query(rpc::RpcSocket& socket, const routing::NodeId& target,
             uint32_t command, const std::vector<uint8_t>* value)
    : socket_(socket), target_(target), command_(command) {
    if (value) value_ = *value;
}

void Query::start() {
    seed_from_table();
    read_more();
}

void Query::add_bootstrap(const compact::Ipv4Address& addr) {
    // Bootstrap nodes don't have IDs — use a zeroed ID
    // They'll be queried but won't be in closest_replies
    routing::NodeId zero_id{};
    zero_id.fill(0);
    add_pending(zero_id, addr);
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

void Query::seed_from_table() {
    auto closest = socket_.table().closest(target_, routing::K);
    // Add in reverse order so closest ends up on top of the stack
    for (auto it = closest.rbegin(); it != closest.rend(); ++it) {
        auto addr = compact::Ipv4Address::from_string((*it)->host, (*it)->port);
        add_pending((*it)->id, addr);
    }
}

// ---------------------------------------------------------------------------
// Pending management
// ---------------------------------------------------------------------------

void Query::add_pending(const routing::NodeId& id, const compact::Ipv4Address& addr) {
    std::string key = addr.host_string() + ":" + std::to_string(addr.port);
    if (seen_.count(key) > 0) return;  // Already seen

    seen_[key] = NodeState::PENDING;
    pending_.push_back({id, addr});
}

// ---------------------------------------------------------------------------
// Iteration
// ---------------------------------------------------------------------------

void Query::read_more() {
    if (done_) return;

    while (inflight_ < concurrency_ && !pending_.empty()) {
        auto next = pending_.back();
        pending_.pop_back();

        // Skip if not closer than k-th closest (optimization)
        // But always query bootstrap nodes (zeroed ID)
        routing::NodeId zero_id{};
        zero_id.fill(0);
        if (next.id != zero_id && !is_closer(next.id) &&
            closest_replies_.size() >= routing::K) {
            continue;
        }

        visit(next);
    }

    maybe_finish();
}

void Query::visit(const PendingNode& node) {
    inflight_++;

    messages::Request req;
    req.to.addr = node.addr;
    req.command = command_;
    req.target = target_;
    if (value_.has_value()) {
        req.value = *value_;
    }

    // Capture node by value for callbacks
    auto captured_node = node;

    socket_.request(req,
        [this, captured_node](const messages::Response& resp) {
            inflight_--;
            on_visit_response(captured_node, resp);
        },
        [this, captured_node](uint16_t) {
            inflight_--;
            on_visit_timeout(captured_node);
        });
}

void Query::on_visit_response(const PendingNode& node, const messages::Response& resp) {
    // Mark as done
    std::string key = node.addr.host_string() + ":" + std::to_string(node.addr.port);
    seen_[key] = NodeState::DONE;

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

    // Add to closest replies (if it has an ID)
    routing::NodeId zero_id{};
    zero_id.fill(0);
    if (reply.from_id != zero_id) {
        push_closest(reply);
    }

    // Add closer nodes to pending
    for (const auto& closer : resp.closer_nodes) {
        // We don't know the ID of closer nodes yet — compute from address
        // (dht-rpc computes id = BLAKE2b(ipv4_bytes))
        // For now, use a placeholder — the real ID comes when we query them
        routing::NodeId placeholder{};
        placeholder.fill(0);
        add_pending(placeholder, closer);
    }

    // Notify caller
    if (on_reply_) {
        on_reply_(reply);
    }

    // Continue iterating
    read_more();
}

void Query::on_visit_timeout(const PendingNode& node) {
    std::string key = node.addr.host_string() + ":" + std::to_string(node.addr.port);
    seen_[key] = NodeState::DOWN;

    read_more();
}

// ---------------------------------------------------------------------------
// Closest replies management
// ---------------------------------------------------------------------------

void Query::push_closest(const QueryReply& reply) {
    // Insertion sort into sorted vector (by XOR distance to target)
    closest_replies_.push_back(reply);

    // Bubble the new entry to its sorted position
    for (int i = static_cast<int>(closest_replies_.size()) - 2; i >= 0; i--) {
        int cmp = compare(closest_replies_[static_cast<size_t>(i)].from_id,
                          reply.from_id);
        if (cmp < 0) break;    // Already in right place
        if (cmp == 0) {
            // Duplicate — remove the one we just added
            closest_replies_.pop_back();
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

bool Query::is_closer(const routing::NodeId& id) const {
    if (closest_replies_.size() < routing::K) return true;
    return compare(id, closest_replies_.back().from_id) < 0;
}

int Query::compare(const routing::NodeId& a, const routing::NodeId& b) const {
    return routing::compare_distance(target_, a, b);
}

// ---------------------------------------------------------------------------
// Completion
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
        if (on_done_) {
            on_done_(closest_replies_);
        }
    }
}

void Query::do_commit() {
    committing_ = true;
    commit_inflight_ = 0;

    if (closest_replies_.empty()) {
        done_ = true;
        if (on_done_) on_done_(closest_replies_);
        return;
    }

    for (const auto& reply : closest_replies_) {
        if (!reply.token.has_value()) continue;

        commit_inflight_++;
        on_commit_(reply, [this](const messages::Response&) {
            commit_inflight_--;
            if (commit_inflight_ == 0) {
                done_ = true;
                if (on_done_) on_done_(closest_replies_);
            }
        });
    }

    // If no commits were sent (no tokens), finish immediately
    if (commit_inflight_ == 0) {
        done_ = true;
        if (on_done_) on_done_(closest_replies_);
    }
}

}  // namespace query
}  // namespace hyperdht
