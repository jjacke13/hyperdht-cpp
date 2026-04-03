#pragma once

// Health Monitor — tracks network health from response/timeout statistics.
//
// Uses a sliding window of 4 observation periods (ticks). Each tick records
// how many responses and timeouts occurred. Based on the aggregate:
//   - ONLINE:   receiving responses, timeout rate < 50%
//   - DEGRADED: receiving responses, but timeout rate > 50% for all 4 ticks
//   - OFFLINE:  no responses in the observation window
//
// Port of dht-rpc/lib/health.js

#include <array>
#include <cstdint>

namespace hyperdht {
namespace health {

constexpr int WINDOW_SIZE = 4;
constexpr int IDLE_THRESHOLD = 4;     // min activity to evaluate health
constexpr double DEGRADED_RATE = 0.5; // 50% timeout rate = degraded

enum class State { ONLINE, DEGRADED, OFFLINE };

struct Snapshot {
    uint32_t responses = 0;
    uint32_t timeouts = 0;
    int degraded = -1;  // -1 = not evaluated, 0 = healthy, 1 = degraded
};

class HealthMonitor {
public:
    HealthMonitor();

    // Call once per background tick with the delta counts since last tick.
    // Returns the new state.
    State update(uint32_t new_responses, uint32_t new_timeouts);

    // Reset all state (e.g., on network wakeup)
    void reset();

    State state() const { return state_; }
    bool is_online() const { return state_ != State::OFFLINE; }
    bool is_degraded() const { return state_ == State::DEGRADED; }

    // Aggregate stats across the window
    uint32_t total_responses() const;
    uint32_t total_timeouts() const;

private:
    std::array<Snapshot, WINDOW_SIZE> window_{};
    int head_ = -1;
    int count_ = 0;  // number of filled slots (up to WINDOW_SIZE)
    int degraded_ticks_ = 0;
    int healthy_ticks_ = 0;
    State state_ = State::ONLINE;

    bool is_cold() const { return count_ < WINDOW_SIZE; }
    bool is_idle() const;
    bool all_degraded() const { return degraded_ticks_ == WINDOW_SIZE; }
    bool all_healthy() const { return healthy_ticks_ == WINDOW_SIZE; }
};

}  // namespace health
}  // namespace hyperdht
