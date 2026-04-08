#pragma once

// NAT Sampler — determines our firewall type by collecting address samples
// from DHT node responses. Each DHT response includes a `to` field showing
// how the remote node sees our address. By collecting these from multiple
// nodes, we determine if our external address is CONSISTENT or RANDOM.
//
// Algorithm (from hyperdht/lib/nat.js):
//   - Maintain two sorted-by-hits lists: host-only and host+port
//   - Deduplicate by source node (don't sample same node twice)
//   - After ≥3 samples, classify:
//     max_hits ≥ 3          → CONSISTENT
//     max_hits = 1          → RANDOM
//     max_hits = 2          → edge cases (see _update_firewall)
//
// Used by holepunch to report our firewall type to the server.

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_set>
#include <vector>

#include "hyperdht/compact.hpp"

namespace hyperdht {
namespace nat {

// ---------------------------------------------------------------------------
// Address sample — (host, port) with hit count
// ---------------------------------------------------------------------------

struct Sample {
    std::string host;
    uint16_t port = 0;
    int hits = 1;
};

// ---------------------------------------------------------------------------
// NatSampler — collects samples and determines firewall type
// ---------------------------------------------------------------------------

class NatSampler {
public:
    NatSampler();

    // Add a sample: addr is our address as seen by a remote node,
    // from is the remote node's address (used for deduplication).
    // Returns true if the sample was new (not a duplicate).
    bool add(const compact::Ipv4Address& addr,
             const compact::Ipv4Address& from);

    // Current firewall classification
    uint32_t firewall() const { return firewall_; }

    // Number of unique samples collected
    int sampled() const { return sampled_; }

    // Our detected addresses (for holepunch payload).
    // Empty if UNKNOWN. For RANDOM: just the host (port=0).
    // For CONSISTENT: addresses with ≥2 hits (minimum 2 entries).
    const std::vector<compact::Ipv4Address>& addresses() const {
        return addresses_;
    }

    // Our most-seen host (null string if unknown)
    const std::string& host() const { return host_; }

    // Our most-seen port (0 if unknown or random)
    uint16_t port() const { return port_; }

    // Freeze/unfreeze — prevents classification updates during holepunch.
    // JS: nat.freeze() called before roundPunch gossip, unfreeze() after.
    void freeze() { frozen_ = true; }
    void unfreeze();
    bool is_frozen() const { return frozen_; }

    // Callback fired when firewall classification changes
    using OnChangeFn = std::function<void(uint32_t old_fw, uint32_t new_fw)>;
    void on_change(OnChangeFn fn) { on_change_ = std::move(fn); }

    // Reset all state
    void reset();

private:
    uint32_t firewall_ = 0;  // FIREWALL_UNKNOWN
    int sampled_ = 0;
    bool frozen_ = false;
    std::string host_;
    uint16_t port_ = 0;

    std::vector<Sample> samples_host_;   // sorted by hits, host-only (port=0)
    std::vector<Sample> samples_full_;   // sorted by hits, host+port
    std::unordered_set<std::string> visited_;  // "host:port" of source nodes

    std::vector<compact::Ipv4Address> addresses_;
    OnChangeFn on_change_;

    void update_firewall();
    void update_addresses();
};

}  // namespace nat
}  // namespace hyperdht
