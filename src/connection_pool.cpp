#include "hyperdht/connection_pool.hpp"

#include <cstring>

namespace hyperdht {
namespace connection_pool {

// ---------------------------------------------------------------------------
// ConnectionRef
// ---------------------------------------------------------------------------

ConnectionRef::ConnectionRef(const ConnectionInfo& info)
    : info_(info) {}

// ---------------------------------------------------------------------------
// ConnectionPool helpers
// ---------------------------------------------------------------------------

std::string ConnectionPool::key_hex(const std::array<uint8_t, 32>& key) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (auto b : key) {
        out.push_back(h[b >> 4]);
        out.push_back(h[b & 0x0F]);
    }
    return out;
}

bool ConnectionPool::should_keep_new(const ConnectionRef& existing,
                                      const ConnectionRef& new_ref) {
    // JS: connection-pool.js lines 42-49
    // Keep new if:
    //   - Same initiator mode (both outbound or both inbound)
    //   - OR our public key sorts higher than remote
    if (new_ref.is_initiator() == existing.is_initiator()) {
        return true;
    }
    return std::memcmp(new_ref.info().local_public_key.data(),
                       new_ref.remote_public_key().data(), 32) > 0;
}

// ---------------------------------------------------------------------------
// ConnectionPool
// ---------------------------------------------------------------------------

AttachResult ConnectionPool::attach_stream(std::shared_ptr<ConnectionRef> ref,
                                            bool opened) {
    auto hex = key_hex(ref->remote_public_key());

    // Check for existing connection (dedup)
    auto existing = get(ref->remote_public_key());
    if (existing) {
        if (should_keep_new(*existing, *ref)) {
            // Keep new, destroy old
            remove(existing->remote_public_key());
            if (existing->on_destroy) existing->on_destroy();
            // Fall through to attach new
        } else {
            // Keep old, destroy new
            if (ref->on_destroy) ref->on_destroy();
            return AttachResult::DUPLICATE_KEPT_OLD;
        }
    }

    if (opened) {
        connections_[hex] = ref;
    } else {
        connecting_[hex] = ref;
    }

    return existing ? AttachResult::DUPLICATE_KEPT_NEW : AttachResult::ATTACHED;
}

void ConnectionPool::mark_opened(const std::array<uint8_t, 32>& remote_key) {
    auto hex = key_hex(remote_key);
    auto it = connecting_.find(hex);
    if (it == connecting_.end()) return;

    auto ref = std::move(it->second);
    connecting_.erase(it);
    connections_[hex] = ref;

    if (ref->on_open) ref->on_open();
}

void ConnectionPool::remove(const std::array<uint8_t, 32>& remote_key) {
    auto hex = key_hex(remote_key);
    connections_.erase(hex);
    connecting_.erase(hex);
}

bool ConnectionPool::has(const std::array<uint8_t, 32>& remote_key) const {
    auto hex = key_hex(remote_key);
    return connections_.count(hex) > 0 || connecting_.count(hex) > 0;
}

std::shared_ptr<ConnectionRef> ConnectionPool::get(
    const std::array<uint8_t, 32>& remote_key) const {
    auto hex = key_hex(remote_key);
    auto it = connections_.find(hex);
    if (it != connections_.end()) return it->second;
    it = connecting_.find(hex);
    if (it != connecting_.end()) return it->second;
    return nullptr;
}

}  // namespace connection_pool
}  // namespace hyperdht
