#include "hyperdht/health.hpp"

namespace hyperdht {
namespace health {

HealthMonitor::HealthMonitor() = default;

void HealthMonitor::reset() {
    window_ = {};
    head_ = -1;
    count_ = 0;
    degraded_ticks_ = 0;
    healthy_ticks_ = 0;
    state_ = State::ONLINE;
}

bool HealthMonitor::is_idle() const {
    return (total_responses() + total_timeouts()) < IDLE_THRESHOLD;
}

uint32_t HealthMonitor::total_responses() const {
    uint32_t total = 0;
    for (int i = 0; i < count_; i++) {
        total += window_[i].responses;
    }
    return total;
}

uint32_t HealthMonitor::total_timeouts() const {
    uint32_t total = 0;
    for (int i = 0; i < count_; i++) {
        total += window_[i].timeouts;
    }
    return total;
}

State HealthMonitor::update(uint32_t new_responses, uint32_t new_timeouts) {
    // Advance head (circular buffer)
    int prev_head = head_;
    head_ = (head_ + 1) % WINDOW_SIZE;

    // Remove oldest observation from degraded/healthy counts
    if (count_ == WINDOW_SIZE) {
        auto& oldest = window_[head_];
        if (oldest.degraded == 1) degraded_ticks_--;
        else if (oldest.degraded == 0) healthy_ticks_--;
    } else {
        count_++;
    }

    // Record new snapshot
    window_[head_] = Snapshot{new_responses, new_timeouts, -1};

    // Don't evaluate during warmup or idle periods
    if (is_cold() || is_idle()) return state_;

    // Classify this tick
    uint32_t activity = new_responses + new_timeouts;
    bool tick_degraded = false;
    if (activity > 0) {
        double timeout_rate = static_cast<double>(new_timeouts) / activity;
        tick_degraded = timeout_rate > DEGRADED_RATE;
    }

    window_[head_].degraded = tick_degraded ? 1 : 0;
    if (tick_degraded) degraded_ticks_++;
    else healthy_ticks_++;

    // State transitions
    bool has_responses = (total_responses() > 0);

    if (has_responses && all_degraded()) {
        state_ = State::DEGRADED;
    } else if (!has_responses) {
        state_ = State::OFFLINE;
    } else if (has_responses && all_healthy()) {
        state_ = State::ONLINE;
    }
    // Otherwise: keep current state (hysteresis)

    return state_;
}

}  // namespace health
}  // namespace hyperdht
