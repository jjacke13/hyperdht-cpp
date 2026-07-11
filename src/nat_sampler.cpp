// NAT sampler implementation — collects the `to` address reported by
// remote DHT nodes and classifies our firewall as CONSISTENT or RANDOM
// once enough samples are observed. visited_ set capped at 1024 entries.
//
// JS: .analysis/js/nat-sampler/index.js:1-64 (whole NatSampler class)
//
// C++ diffs from JS:
//   - JS uses a single fixed-size ring (`_samples` of length 32) and
//     bumps two ranks (`_a` = host+port, `_b` = host) per sample.
//     C++ uses two separate sorted-by-hits vectors (samples_full_ for
//     host+port, samples_host_ for host-only) — no ring eviction.
//   - JS dynamically adjusts `_threshold` based on `size` (size-1/2/3
//     depending on bucket count). C++ keys decisions on a fixed `>=3`
//     sample minimum and a max-hits ladder.
//   - JS picks the winner via `_threshold` against `_a.hits` /
//     `_b.hits`. C++ uses an explicit `update_firewall()` ladder
//     mirroring `nat.js _updateFirewall` from hyperdht (NOT the
//     nat-sampler package — JS DHT actually consumes the simpler
//     nat-sampler output and runs its own firewall classification on
//     top in hyperdht/lib/nat.js).
//   - C++ adds `visited_` set so the same source node doesn't
//     contribute multiple samples (JS allows it because the ring will
//     eventually evict duplicates).
//   - C++ also tracks `frozen_` and exposes `unfreeze()` — used after
//     a holepunch round to lock in classification.

#include "hyperdht/nat_sampler.hpp"
#include "hyperdht/peer_connect.hpp"

#include <algorithm>

namespace hyperdht {
namespace nat {

constexpr uint32_t FW_UNKNOWN = peer_connect::FIREWALL_UNKNOWN;
constexpr uint32_t FW_CONSISTENT = peer_connect::FIREWALL_CONSISTENT;
constexpr uint32_t FW_RANDOM = peer_connect::FIREWALL_RANDOM;

// ---------------------------------------------------------------------------
// add_sample — insert or increment a sample in a sorted-by-hits list
// (internal helper, not exposed in header)
//
// JS: .analysis/js/nat-sampler/index.js:52-63 (_bump) — JS only walks
// the most recent 4 entries in the ring. C++ scans the full vector and
// bubbles up to maintain descending sort by hits.
// ---------------------------------------------------------------------------

static void add_sample(std::vector<Sample>& samples,
                       const std::string& host, uint16_t port) {
    // Look for existing match
    for (size_t i = 0; i < samples.size(); i++) {
        auto& s = samples[i];
        if (s.host != host || s.port != port) continue;

        s.hits++;

        // Bubble up: maintain descending sort by hits
        for (; i > 0; i--) {
            auto& prev = samples[i - 1];
            if (prev.hits >= s.hits) break;
            std::swap(samples[i - 1], samples[i]);
        }
        return;
    }

    // New sample
    samples.push_back(Sample{host, port, 1});
}

// ---------------------------------------------------------------------------
// NatSampler
// ---------------------------------------------------------------------------

NatSampler::NatSampler() = default;

void NatSampler::reset() {
    firewall_ = FW_UNKNOWN;
    sampled_ = 0;
    frozen_ = false;
    host_.clear();
    port_ = 0;
    samples_host_.clear();
    samples_full_.clear();
    visited_.clear();
    addresses_.clear();
}

void NatSampler::unfreeze() {
    frozen_ = false;
    update_firewall();
    update_addresses();
}

// JS: .analysis/js/nat-sampler/index.js:14-50 (add)
// JS treats every call as a fresh sample (with ring eviction). C++
// dedups by source node so a single peer can't skew the classification.
bool NatSampler::add(const compact::Ipv4Address& addr,
                     const compact::Ipv4Address& from) {
    // Deduplicate by source node — don't sample the same node twice
    auto ref = from.host_string() + ":" + std::to_string(from.port);
    if (visited_.count(ref)) return false;
    constexpr size_t MAX_VISITED = 1024;  // H24: cap visited set
    if (visited_.size() >= MAX_VISITED) return false;
    visited_.insert(ref);

    add_sample(samples_host_, addr.host_string(), 0);
    add_sample(samples_full_, addr.host_string(), addr.port);
    sampled_++;

    // Update classification after ≥3 samples, unless frozen
    if (sampled_ >= 3 && !frozen_) {
        update_firewall();
        update_addresses();
    }

    // Update our detected address from top samples
    if (!samples_full_.empty()) {
        host_ = samples_full_[0].host;
        port_ = samples_full_[0].port;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Firewall classification (from nat.js _updateFirewall)
//
// JS: .analysis/js/hyperdht/lib/nat.js _updateFirewall (NOT nat-sampler;
//     hyperdht layers its own classifier on top of nat-sampler's host/port
//     winner). The ladder: max_hits>=3 → CONSISTENT, max_hits==1 → RANDOM,
//     max_hits==2 → edge cases on sample count + bucket distribution.
// ---------------------------------------------------------------------------

void NatSampler::update_firewall() {
    if (sampled_ < 3) return;
    if (samples_full_.empty()) return;

    uint32_t old_fw = firewall_;
    int max_hits = samples_full_[0].hits;

    if (max_hits >= 3) {
        firewall_ = FW_CONSISTENT;
    } else if (max_hits == 1) {
        firewall_ = FW_RANDOM;
    } else {
        // max_hits == 2 — edge cases

        // 1 host, ≥4 total samples → 2 bad ones → random
        if (samples_host_.size() == 1 && sampled_ > 3) {
            firewall_ = FW_RANDOM;
        }
        // Double hit on two different IPs → assume consistent
        else if (samples_host_.size() > 1 && samples_full_.size() > 1 &&
                 samples_full_[1].hits > 1) {
            firewall_ = FW_CONSISTENT;
        }
        // >4 samples, no decision → assume random
        else if (sampled_ > 4) {
            firewall_ = FW_RANDOM;
        }
    }

    if (firewall_ != old_fw && on_change_) {
        on_change_(old_fw, firewall_);
    }
}

// ---------------------------------------------------------------------------
// Address extraction (from nat.js _updateAddresses)
//
// JS: .analysis/js/hyperdht/lib/nat.js _updateAddresses
//   - RANDOM: emit a single host:0 (port unpredictable).
//   - CONSISTENT: emit up to 4 entries; require >=2 hits except for the
//     first 2 entries which are always included.
// ---------------------------------------------------------------------------

void NatSampler::update_addresses() {
    addresses_.clear();

    if (firewall_ == FW_UNKNOWN) {
        return;
    }

    if (firewall_ == FW_RANDOM && !samples_host_.empty()) {
        // For RANDOM: just the host (server only needs our IP, port is unpredictable)
        addresses_.push_back(compact::Ipv4Address::from_string(
            samples_host_[0].host, 0));
        return;
    }

    if (firewall_ == FW_CONSISTENT) {
        // All samples with ≥2 hits, minimum 2 entries, max 4
        constexpr size_t MAX_ADDRESSES = 4;
        for (const auto& s : samples_full_) {
            if (addresses_.size() >= MAX_ADDRESSES) break;
            if (s.hits >= 2 || addresses_.size() < 2) {
                addresses_.push_back(compact::Ipv4Address::from_string(
                    s.host, s.port));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RingSampler — line-faithful port of .analysis/js/nat-sampler/index.js
//
// Comments cite the JS line each block mirrors. Fidelity notes:
//   - `_a`/`_b` best-pointers are only REPLACED by a strictly-higher-hits
//     sample (JS `this._a.hits < a.hits`). They can go stale after a ring
//     eviction decrements their hits — replicated, not "improved".
//   - A stale best-pointer's hits can drop below the threshold, sending
//     host() back to "" (JS null). Intended.
//   - shared_ptr<Sample> preserves the JS object aliasing between `_samples`
//     and `_a`/`_b`, so evicting decrements the SAME object `bump` returned.
// ---------------------------------------------------------------------------

void RingSampler::reset() {
    host_.clear();
    port_ = 0;
    size_ = 0;
    a_.reset();
    b_.reset();
    threshold_ = 0;
    top_ = 0;
    samples_.clear();
}

// JS: index.js:52-63 (_bump)
std::shared_ptr<Sample> RingSampler::bump(const std::string& host,
                                          uint16_t port, int inc) {
    for (int i = 0; i < 4; i++) {
        // JS: index.js:54 — `(this._top - inc - (2 * i)) & 31`. In C++20 int
        // is two's complement and `& 31` keeps the low 5 bits, so a negative
        // intermediate yields the same slot index as JS's 32-bit `&`.
        int j = (top_ - inc - (2 * i)) & 31;
        // JS: index.js:55 — index past the current fill → brand-new sample.
        if (static_cast<size_t>(j) >= samples_.size()) {
            return std::make_shared<Sample>(Sample{host, port, 1});
        }
        auto& s = samples_[j];
        if (s->port == port && s->host == host) {
            s->hits++;  // JS: index.js:58
            return s;   // JS: index.js:59 — return the shared object
        }
    }
    return std::make_shared<Sample>(Sample{host, port, 1});  // JS: index.js:62
}

// JS: index.js:14-50 (add)
int RingSampler::add(const std::string& host, uint16_t port) {
    // JS: index.js:15-16
    auto a = bump(host, port, 2);
    auto b = bump(host, 0, 1);

    if (samples_.size() < 32) {
        // JS: index.js:19-22 — grow the ring, recompute the dynamic threshold.
        size_++;
        threshold_ = size_ - (size_ < 4 ? 0 : size_ < 8 ? 1 : size_ < 12 ? 2 : 3);
        samples_.push_back(a);
        samples_.push_back(b);
        top_ += 2;
    } else {
        // JS: index.js:24-32 — overwrite the oldest pair, decrementing the
        // evicted samples' hits.
        if (top_ == 32) top_ = 0;

        auto oa = samples_[top_];
        samples_[top_++] = a;
        oa->hits--;

        auto ob = samples_[top_];
        samples_[top_++] = b;
        ob->hits--;
    }

    // JS: index.js:35-36 — best-pointers replaced only on strictly higher hits.
    if (!a_ || a_->hits < a->hits) a_ = a;
    if (!b_ || b_->hits < b->hits) b_ = b;

    // JS: index.js:38-47 — three publish states.
    if (a_->hits >= threshold_) {
        host_ = a_->host;
        port_ = a_->port;
    } else if (b_->hits >= threshold_) {
        host_ = b_->host;
        port_ = 0;
    } else {
        host_.clear();  // JS `this.host = null`
        port_ = 0;
    }

    return a->hits;  // JS: index.js:49
}

}  // namespace nat
}  // namespace hyperdht
