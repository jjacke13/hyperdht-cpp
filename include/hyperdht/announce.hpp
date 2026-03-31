#pragma once

// Announce storage — in-memory store for peer announcements.
// Peers announce at a 32-byte target key. Each announcement has a TTL
// and is removed when expired. Used by ANNOUNCE/FIND_PEER commands.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "hyperdht/compact.hpp"

namespace hyperdht {
namespace announce {

constexpr uint64_t DEFAULT_TTL_MS = 20 * 60 * 1000;  // 20 minutes
constexpr size_t MAX_PEERS_PER_TARGET = 20;

using TargetKey = std::array<uint8_t, 32>;

// ---------------------------------------------------------------------------
// Stored peer announcement
// ---------------------------------------------------------------------------

struct PeerAnnouncement {
    compact::Ipv4Address from;          // Who announced
    std::vector<uint8_t> value;         // Announcement payload (noisePayload etc.)
    uint64_t created_at = 0;            // Timestamp when stored
    uint64_t ttl = DEFAULT_TTL_MS;      // Time to live
};

// ---------------------------------------------------------------------------
// AnnounceStore — stores peer announcements indexed by target key
// ---------------------------------------------------------------------------

struct KeyHash {
    size_t operator()(const TargetKey& k) const {
        // Use first 8 bytes as hash (already random/hashed data)
        size_t h = 0;
        for (size_t i = 0; i < 8; i++) {
            h = (h << 8) | k[i];
        }
        return h;
    }
};

class AnnounceStore {
public:
    // Store a peer announcement at a target key.
    // Replaces existing announcement from the same address.
    void put(const TargetKey& target, const PeerAnnouncement& ann);

    // Remove a peer announcement from a target key (by sender address).
    bool remove(const TargetKey& target, const compact::Ipv4Address& from);

    // Get all announcements for a target key.
    std::vector<const PeerAnnouncement*> get(const TargetKey& target) const;

    // Remove expired announcements. Call periodically.
    // now_ms: current timestamp in milliseconds
    void gc(uint64_t now_ms);

    // Total number of stored announcements
    size_t size() const;

    // Number of targets with announcements
    size_t target_count() const { return store_.size(); }

private:
    std::unordered_map<TargetKey, std::vector<PeerAnnouncement>, KeyHash> store_;
};

}  // namespace announce
}  // namespace hyperdht
