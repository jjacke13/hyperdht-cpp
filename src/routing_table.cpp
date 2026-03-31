#include "hyperdht/routing_table.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <random>

namespace hyperdht {
namespace routing {

// ---------------------------------------------------------------------------
// XOR distance utilities
// ---------------------------------------------------------------------------

size_t bucket_index(const NodeId& local_id, const NodeId& remote_id) {
    // Find the first differing bit position (0 = most significant)
    for (size_t i = 0; i < ID_LEN; i++) {
        uint8_t xor_byte = local_id[i] ^ remote_id[i];
        if (xor_byte != 0) {
            int clz = std::countl_zero(xor_byte);
            return i * 8 + static_cast<size_t>(clz);
        }
    }
    return ID_BITS;  // IDs are equal
}

int compare_distance(const NodeId& target, const NodeId& a, const NodeId& b) {
    for (size_t i = 0; i < ID_LEN; i++) {
        uint8_t da = target[i] ^ a[i];
        uint8_t db = target[i] ^ b[i];
        if (da < db) return -1;
        if (da > db) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Bucket
// ---------------------------------------------------------------------------

size_t Bucket::find_index(const NodeId& id) const {
    // Binary search by ID (lexicographic order)
    size_t lo = 0;
    size_t hi = nodes_.size();
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (nodes_[mid].id < id) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

bool Bucket::has_id(const NodeId& id) const {
    size_t idx = find_index(id);
    return idx < nodes_.size() && nodes_[idx].id == id;
}

bool Bucket::add(const Node& node) {
    if (has_id(node.id)) {
        return false;  // Already exists
    }
    if (is_full()) {
        return false;  // Bucket full
    }
    size_t idx = find_index(node.id);
    nodes_.insert(nodes_.begin() + static_cast<ptrdiff_t>(idx), node);
    return true;
}

bool Bucket::remove(const NodeId& id) {
    size_t idx = find_index(id);
    if (idx < nodes_.size() && nodes_[idx].id == id) {
        nodes_.erase(nodes_.begin() + static_cast<ptrdiff_t>(idx));
        return true;
    }
    return false;
}

const Node* Bucket::get(const NodeId& id) const {
    size_t idx = find_index(id);
    if (idx < nodes_.size() && nodes_[idx].id == id) {
        return &nodes_[idx];
    }
    return nullptr;
}

const Node* Bucket::oldest() const {
    if (nodes_.empty()) return nullptr;
    return &nodes_.front();
}

// ---------------------------------------------------------------------------
// RoutingTable
// ---------------------------------------------------------------------------

RoutingTable::RoutingTable(const NodeId& local_id) : id_(local_id) {}

bool RoutingTable::add(const Node& node) {
    if (node.id == id_) return false;  // Don't add ourselves

    size_t idx = bucket_index(id_, node.id);
    if (idx >= ID_BITS) return false;  // Equal IDs

    auto& bucket = buckets_[idx];

    if (bucket.add(node)) {
        size_++;
        return true;
    }

    // Bucket is full
    if (on_full_) {
        on_full_(idx, node);
    }
    return false;
}

bool RoutingTable::remove(const NodeId& id) {
    size_t idx = bucket_index(id_, id);
    if (idx >= ID_BITS) return false;

    if (buckets_[idx].remove(id)) {
        size_--;
        return true;
    }
    return false;
}

const Node* RoutingTable::get(const NodeId& id) const {
    size_t idx = bucket_index(id_, id);
    if (idx >= ID_BITS) return nullptr;
    return buckets_[idx].get(id);
}

bool RoutingTable::has(const NodeId& id) const {
    return get(id) != nullptr;
}

std::vector<const Node*> RoutingTable::closest(const NodeId& target, size_t count) const {
    std::vector<const Node*> result;
    result.reserve(count);

    size_t d = bucket_index(id_, target);
    if (d >= ID_BITS) d = ID_BITS - 1;

    // Collect from the target bucket first, then expand outward
    auto collect_from = [&](size_t bucket_idx) {
        const auto& nodes = buckets_[bucket_idx].nodes();
        for (const auto& node : nodes) {
            if (result.size() >= count) return;
            result.push_back(&node);
        }
    };

    // Start from bucket d, go down (closer buckets)
    for (size_t i = d; i < ID_BITS && result.size() < count; i++) {
        collect_from(i);
    }

    // Then go up (farther buckets) if we need more
    for (size_t i = d; i > 0 && result.size() < count; ) {
        --i;
        collect_from(i);
    }

    // Sort by XOR distance to target
    std::sort(result.begin(), result.end(),
              [&target](const Node* a, const Node* b) {
                  return compare_distance(target, a->id, b->id) < 0;
              });

    if (result.size() > count) {
        result.resize(count);
    }
    return result;
}

const Node* RoutingTable::random() const {
    if (size_ == 0) return nullptr;

    // Generate random index [0, size_)
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<size_t> dist(0, size_ - 1);
    size_t n = dist(rng);

    // Walk through buckets to find the n-th node
    for (const auto& bucket : buckets_) {
        if (n < bucket.size()) {
            return &bucket.nodes()[n];
        }
        n -= bucket.size();
    }
    return nullptr;  // Should never reach here
}

}  // namespace routing
}  // namespace hyperdht
