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

    // Now go idle (less than 4 outcomes in each tick)
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

TEST(HealthMonitor, IdleTimeoutTickDoesNotCountAsDegraded) {
    HealthMonitor h;
    for (int i = 0; i < 4; i++) h.update(10, 0);

    h.update(0, 3);  // Below JS's per-tick activity threshold.
    for (int i = 0; i < 3; i++) h.update(1, 10);
    EXPECT_EQ(h.state(), State::ONLINE);
    EXPECT_EQ(h.update(1, 10), State::DEGRADED);
}

class HealthIdleThreshold : public ::testing::TestWithParam<uint32_t> {};

TEST_P(HealthIdleThreshold, OnlyActiveTicksCountTowardsRecovery) {
    HealthMonitor h;
    for (int i = 0; i < 7; i++) h.update(1, 10);
    ASSERT_EQ(h.state(), State::DEGRADED);

    h.update(GetParam(), 0);
    for (int i = 0; i < 3; i++) h.update(10, 0);
    EXPECT_EQ(h.state(), GetParam() < IDLE_THRESHOLD
                            ? State::DEGRADED : State::ONLINE);
    EXPECT_EQ(h.update(10, 0), State::ONLINE);
}

INSTANTIATE_TEST_SUITE_P(Activity, HealthIdleThreshold,
                        ::testing::Values(0u, 1u, 2u, 3u, 4u));

TEST(HealthMonitor, ActiveTimeoutTickOverridesEarlierResponses) {
    HealthMonitor h;
    for (int i = 0; i < 4; i++) h.update(10, 0);

    EXPECT_EQ(h.update(0, 4), State::OFFLINE);
    EXPECT_FALSE(h.is_online());
    EXPECT_FALSE(h.is_degraded());
}

class HealthRecovery : public ::testing::TestWithParam<uint32_t> {};

TEST_P(HealthRecovery, FirstRespondingActiveTickRecovers) {
    HealthMonitor h;
    for (int i = 0; i < 4; i++) h.update(0, 10);
    ASSERT_EQ(h.state(), State::OFFLINE);

    EXPECT_EQ(h.update(4 - GetParam(), GetParam()), State::ONLINE);
    EXPECT_TRUE(h.is_online());
    EXPECT_FALSE(h.is_degraded());
}

INSTANTIATE_TEST_SUITE_P(Timeouts, HealthRecovery,
                        ::testing::Values(0u, 3u));

TEST(HealthMonitor, OfflineClearsDegradationForRecovery) {
    HealthMonitor h;
    for (int i = 0; i < 7; i++) h.update(1, 10);
    ASSERT_EQ(h.state(), State::DEGRADED);

    EXPECT_EQ(h.update(0, 4), State::OFFLINE);
    EXPECT_EQ(h.update(4, 0), State::ONLINE);
}

TEST(HealthMonitor, FullDegradedWindowStillAppliesOnRecovery) {
    HealthMonitor h;
    for (int i = 0; i < 7; i++) h.update(0, 10);
    ASSERT_EQ(h.state(), State::OFFLINE);

    EXPECT_EQ(h.update(1, 3), State::DEGRADED);
    EXPECT_TRUE(h.is_online());
}

TEST(HealthMonitor, IdleResponsesDoNotRecoverOffline) {
    HealthMonitor h;
    for (int i = 0; i < 4; i++) h.update(0, 10);
    ASSERT_EQ(h.state(), State::OFFLINE);

    EXPECT_EQ(h.update(1, 0), State::OFFLINE);
    EXPECT_EQ(h.update(0, 0), State::OFFLINE);
    EXPECT_EQ(h.update(4, 0), State::ONLINE);
}

TEST(HealthMonitor, IdleTimeoutsDoNotReportOffline) {
    HealthMonitor h;
    for (int i = 0; i < 4; i++) h.update(10, 0);

    EXPECT_EQ(h.update(0, 3), State::ONLINE);
}
