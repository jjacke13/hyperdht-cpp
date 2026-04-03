#include <gtest/gtest.h>

#include "hyperdht/health.hpp"

using namespace hyperdht::health;

TEST(HealthMonitor, StartsOnline) {
    HealthMonitor h;
    EXPECT_EQ(h.state(), State::ONLINE);
    EXPECT_TRUE(h.is_online());
    EXPECT_FALSE(h.is_degraded());
}

TEST(HealthMonitor, ColdPeriodNoStateChange) {
    HealthMonitor h;

    // First 3 ticks with all timeouts — still ONLINE (cold period)
    h.update(0, 10);
    EXPECT_EQ(h.state(), State::ONLINE);
    h.update(0, 10);
    EXPECT_EQ(h.state(), State::ONLINE);
    h.update(0, 10);
    EXPECT_EQ(h.state(), State::ONLINE);
}

TEST(HealthMonitor, DegradedAfterFullWindow) {
    HealthMonitor h;

    // 3 cold ticks (window filling up, not evaluated)
    // + 4 evaluated degraded ticks = 7 total needed
    for (int i = 0; i < 7; i++) {
        h.update(1, 10);  // >50% timeout rate each tick
    }

    EXPECT_EQ(h.state(), State::DEGRADED);
}

TEST(HealthMonitor, OfflineWhenNoResponses) {
    HealthMonitor h;

    // Fill 4 ticks with only timeouts
    h.update(0, 10);
    h.update(0, 10);
    h.update(0, 10);
    h.update(0, 10);

    EXPECT_EQ(h.state(), State::OFFLINE);
}

TEST(HealthMonitor, RecoverFromDegraded) {
    HealthMonitor h;

    // 7 ticks to reach degraded (3 cold + 4 evaluated)
    for (int i = 0; i < 7; i++) {
        h.update(1, 10);
    }
    EXPECT_EQ(h.state(), State::DEGRADED);

    // 4 healthy ticks to recover
    for (int i = 0; i < 4; i++) {
        h.update(10, 0);
    }
    EXPECT_EQ(h.state(), State::ONLINE);
}

TEST(HealthMonitor, IdlePeriodNoStateChange) {
    HealthMonitor h;

    // Fill window first
    h.update(10, 0);
    h.update(10, 0);
    h.update(10, 0);
    h.update(10, 0);
    EXPECT_EQ(h.state(), State::ONLINE);

    // Now go idle (less than 4 total activity in window)
    h.update(0, 0);
    h.update(0, 0);
    h.update(0, 0);
    h.update(0, 0);
    // Should stay ONLINE — idle doesn't trigger state change
    EXPECT_EQ(h.state(), State::ONLINE);
}

TEST(HealthMonitor, Reset) {
    HealthMonitor h;

    h.update(0, 10);
    h.update(0, 10);
    h.update(0, 10);
    h.update(0, 10);
    EXPECT_EQ(h.state(), State::OFFLINE);

    h.reset();
    EXPECT_EQ(h.state(), State::ONLINE);
    EXPECT_EQ(h.total_responses(), 0u);
    EXPECT_EQ(h.total_timeouts(), 0u);
}

TEST(HealthMonitor, TotalCounts) {
    HealthMonitor h;

    h.update(5, 3);
    h.update(2, 1);
    EXPECT_EQ(h.total_responses(), 7u);
    EXPECT_EQ(h.total_timeouts(), 4u);
}
