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
#include <memory>
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

// ---------------------------------------------------------------------------
// RingSampler — line-faithful port of the `nat-sampler` npm package
// (.analysis/js/nat-sampler/index.js, the whole 64-line class).
//
// This is a DIFFERENT sampler from NatSampler above. dht-rpc uses this one as
// `this._nat` (dht-rpc/index.js:69) purely to decide our external host/port
// and the "port random" signal. It is a 32-slot ring with NO source dedup:
// the same node re-observing us counts again, so the sampler keeps adapting to
// NAT remaps instead of freezing. Winner selection is threshold-gated, so a
// consistent host with random ports publishes (host, port=0).
//
// NatSampler (hyperdht/lib/nat.js) is a separate, source-deduped classifier
// that layers a firewall ladder on top; keep using that for holepunch/server/
// connect. Use RingSampler only for the dht-rpc host/port + persistence gate.
// ---------------------------------------------------------------------------

class RingSampler {
public:
    RingSampler() = default;

    // JS: index.js:14-50 (add). Returns the current hit count of the
    // host+port sample (JS `return a.hits`).
    int add(const std::string& host, uint16_t port);

    // JS getters: index.js:3-4. host() == "" mirrors JS `this.host === null`.
    const std::string& host() const { return host_; }
    uint16_t port() const { return port_; }

    // JS `this.size` (index.js:5) — number of samples added, capped at the
    // 16 pairs that fill the 32-slot ring.
    int size() const { return size_; }

    // JS `this._threshold` (index.js:9). Exposed read-only for parity tests.
    int threshold() const { return threshold_; }

    void reset();

private:
    // JS: index.js:52-63 (_bump). Scans the 4 most-recent slots of matching
    // parity; on a hit increments and returns the shared sample, otherwise
    // returns a brand-new sample. shared_ptr preserves JS object aliasing:
    // the same object lives in `_samples` and in `_a`/`_b`, so an eviction
    // hit-decrement affects the exact object a previous _bump returned.
    std::shared_ptr<Sample> bump(const std::string& host, uint16_t port,
                                 int inc);

    std::string host_;                              // JS this.host ("" == null)
    uint16_t port_ = 0;                             // JS this.port
    int size_ = 0;                                  // JS this.size
    std::shared_ptr<Sample> a_;                     // JS this._a (host+port best)
    std::shared_ptr<Sample> b_;                     // JS this._b (host-only best)
    int threshold_ = 0;                             // JS this._threshold
    int top_ = 0;                                   // JS this._top
    std::vector<std::shared_ptr<Sample>> samples_;  // JS this._samples
};

}  // namespace nat
}  // namespace hyperdht
