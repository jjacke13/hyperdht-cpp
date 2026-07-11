// Connection pool implementation — deduplicates in-flight and established
// connections by remote public key so we open only one stream per peer.
// Matches JS hyperdht/lib/connection-pool.js.

#include "hyperdht/connection_pool.hpp"

#include <cstring>

#include "hyperdht/server.hpp"

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
            // dhttop-8: keep-new, but DEFER the swap. Destroy the old stream
            // now; hold the new ref until the old ref's close is signalled
            // (on_stream_closed). Do NOT remove/attach synchronously —
            // matches JS connection-pool.js:37-55 where _attachStream(new)
            // runs from the OLD stream's 'close' handler. The old ref stays
            // in the pool (its own close removes it) until then.
            pending_swaps_[hex] = PendingSwap{ref, opened};
            if (existing->on_destroy) existing->on_destroy();
            return AttachResult::DUPLICATE_KEPT_NEW;
        } else {
            // Keep old, destroy new (synchronous — JS:56-58)
            if (ref->on_destroy) ref->on_destroy();
            return AttachResult::DUPLICATE_KEPT_OLD;
        }
    }

    if (opened) {
        connections_[hex] = ref;
        if (ref->on_emit) ref->on_emit();  // JS emit 'connection' (:74)
    } else {
        connecting_[hex] = ref;
    }

    return AttachResult::ATTACHED;
}

void ConnectionPool::mark_opened(const std::array<uint8_t, 32>& remote_key) {
    auto hex = key_hex(remote_key);
    auto it = connecting_.find(hex);
    if (it == connecting_.end()) return;

    auto ref = std::move(it->second);
    connecting_.erase(it);
    connections_[hex] = ref;

    if (ref->on_open) ref->on_open();
    if (ref->on_emit) ref->on_emit();  // JS emit 'connection' on open (:92)
}

void ConnectionPool::on_stream_closed(const std::shared_ptr<ConnectionRef>& ref) {
    if (!ref) return;
    ref->mark_closed();
    auto hex = key_hex(ref->remote_public_key());

    // Case 1: the closing ref is the currently-attached connection. Remove it,
    // then promote any deferred keep-new (dhttop-8 / JS:46-52).
    auto attached = get(ref->remote_public_key());
    if (attached && attached.get() == ref.get()) {
        remove(ref->remote_public_key());
        auto it = pending_swaps_.find(hex);
        if (it != pending_swaps_.end()) {
            PendingSwap pend = it->second;
            pending_swaps_.erase(it);
            // JS:47 — `if (closed) return`: skip the swap if the new stream
            // already closed while the old one was tearing down.
            if (!pend.ref->closed()) {
                attach_stream(pend.ref, pend.opened);  // no existing → ATTACHED
            }
        }
        if (ref->on_close) ref->on_close();
        return;
    }

    // Case 2: the closing ref is a pending keep-new that died before the old
    // one closed. Drop it so it is never resurrected (JS onclose flag).
    auto it = pending_swaps_.find(hex);
    if (it != pending_swaps_.end() && it->second.ref.get() == ref.get()) {
        pending_swaps_.erase(it);
    }
    if (ref->on_close) ref->on_close();
}

// ---------------------------------------------------------------------------
// attach_server — funnel a Server's inbound connections through the pool.
//
// JS: hyperdht/lib/connection-pool.js:15-27 (_attachServer). We chain a
// listener onto the Server's connection callback (NOT replacing the user's),
// build a dedup ref keyed by the peer's public key, run it through
// attach_stream, and re-emit accepted connections via on_connection_.
// ---------------------------------------------------------------------------

void ConnectionPool::attach_server(server::Server& server) {
    server::Server* sp = &server;
    server.add_connection_listener(
        [this, sp](const server::ConnectionInfo& info) {
            ConnectionInfo cp;
            cp.local_public_key = sp->public_key();
            cp.remote_public_key = info.remote_public_key;
            cp.is_initiator = info.is_initiator;  // false for a server
            auto ref = std::make_shared<ConnectionRef>(cp);
            // Emit the unified 'connection' event when this ref is attached.
            ref->on_emit = [this, info]() {
                if (on_connection_) on_connection_(info);
            };
            attach_stream(ref, /*opened=*/true);
        });
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
