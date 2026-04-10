// Announce store implementation — hash map keyed by 32-byte target.
// Records are appended with a TTL and scanned/expired on access.
// Used by the ANNOUNCE / UNANNOUNCE / FIND_PEER / LOOKUP handlers.

#include "hyperdht/announce.hpp"

#include <algorithm>

namespace hyperdht {
namespace announce {

void AnnounceStore::put(const TargetKey& target, const PeerAnnouncement& ann) {
    auto& peers = store_[target];

    // Replace existing from same address
    for (auto& existing : peers) {
        if (existing.from.host_string() == ann.from.host_string()
            && existing.from.port == ann.from.port) {
            existing = ann;
            return;
        }
    }

    // Evict oldest if at capacity
    if (peers.size() >= MAX_PEERS_PER_TARGET) {
        // Remove the oldest entry
        auto oldest = std::min_element(peers.begin(), peers.end(),
            [](const PeerAnnouncement& a, const PeerAnnouncement& b) {
                return a.created_at < b.created_at;
            });
        *oldest = ann;
        return;
    }

    peers.push_back(ann);
}

bool AnnounceStore::remove(const TargetKey& target, const compact::Ipv4Address& from) {
    auto it = store_.find(target);
    if (it == store_.end()) return false;

    auto& peers = it->second;
    auto host = from.host_string();
    auto removed = std::remove_if(peers.begin(), peers.end(),
        [&](const PeerAnnouncement& a) {
            return a.from.host_string() == host && a.from.port == from.port;
        });

    if (removed == peers.end()) return false;

    peers.erase(removed, peers.end());
    if (peers.empty()) store_.erase(it);
    return true;
}

std::vector<PeerAnnouncement> AnnounceStore::get(const TargetKey& target) const {
    auto it = store_.find(target);
    if (it == store_.end()) return {};
    return it->second;
}

void AnnounceStore::gc(uint64_t now_ms) {
    for (auto it = store_.begin(); it != store_.end(); ) {
        auto& peers = it->second;
        peers.erase(
            std::remove_if(peers.begin(), peers.end(),
                [now_ms](const PeerAnnouncement& a) {
                    if (now_ms < a.created_at) return false;  // Guard underflow
                    return now_ms - a.created_at > a.ttl;
                }),
            peers.end());

        if (peers.empty()) {
            it = store_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t AnnounceStore::size() const {
    size_t total = 0;
    for (const auto& [_, peers] : store_) {
        total += peers.size();
    }
    return total;
}

}  // namespace announce
}  // namespace hyperdht
