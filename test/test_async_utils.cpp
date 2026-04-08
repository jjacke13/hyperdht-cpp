#include <gtest/gtest.h>

#include <vector>

#include <uv.h>

#include "hyperdht/async_utils.hpp"

using namespace hyperdht::async_utils;

// ===========================================================================
// Sleeper tests
// ===========================================================================

class SleeperTest : public ::testing::Test {
protected:
    uv_loop_t loop_;
    void SetUp() override { uv_loop_init(&loop_); }
    void TearDown() override {
        uv_run(&loop_, UV_RUN_DEFAULT);
        uv_loop_close(&loop_);
    }
};

TEST_F(SleeperTest, PauseFiresCallback) {
    Sleeper sleeper(&loop_);

    bool fired = false;
    sleeper.pause(10, [&]() { fired = true; });

    EXPECT_TRUE(sleeper.is_paused());
    uv_run(&loop_, UV_RUN_DEFAULT);
    EXPECT_TRUE(fired);
    EXPECT_FALSE(sleeper.is_paused());
}

TEST_F(SleeperTest, ResumeFiresImmediately) {
    Sleeper sleeper(&loop_);

    bool fired = false;
    sleeper.pause(5000, [&]() { fired = true; });  // 5s — should NOT fire naturally

    EXPECT_FALSE(fired);
    sleeper.resume();
    EXPECT_TRUE(fired);
    EXPECT_FALSE(sleeper.is_paused());
}

TEST_F(SleeperTest, ResumeWithNoPause) {
    Sleeper sleeper(&loop_);
    sleeper.resume();  // No crash, no-op
    EXPECT_FALSE(sleeper.is_paused());
}

TEST_F(SleeperTest, NewPauseCancelsPrevious) {
    Sleeper sleeper(&loop_);

    bool first_fired = false;
    bool second_fired = false;

    sleeper.pause(5000, [&]() { first_fired = true; });
    sleeper.pause(10, [&]() { second_fired = true; });

    // First callback should fire immediately (cancelled by second pause)
    EXPECT_TRUE(first_fired);
    EXPECT_FALSE(second_fired);

    uv_run(&loop_, UV_RUN_DEFAULT);
    EXPECT_TRUE(second_fired);
}

TEST_F(SleeperTest, CancelSuppressesCallback) {
    Sleeper sleeper(&loop_);

    bool fired = false;
    sleeper.pause(10, [&]() { fired = true; });

    sleeper.cancel();
    EXPECT_FALSE(sleeper.is_paused());

    uv_run(&loop_, UV_RUN_DEFAULT);
    EXPECT_FALSE(fired);
}

// ===========================================================================
// Semaphore tests
// ===========================================================================

TEST(Semaphore, ImmediateAcquire) {
    Semaphore sem(2);

    bool acquired = false;
    sem.wait([&](bool ok) { acquired = ok; });
    EXPECT_TRUE(acquired);
    EXPECT_EQ(sem.active(), 1);
}

TEST(Semaphore, BlocksAtLimit) {
    Semaphore sem(1);

    bool first = false, second = false;
    sem.wait([&](bool ok) { first = ok; });
    sem.wait([&](bool ok) { second = ok; });

    EXPECT_TRUE(first);
    EXPECT_FALSE(second);  // Blocked — limit reached
    EXPECT_EQ(sem.active(), 1);
    EXPECT_EQ(sem.waiting(), 1u);
}

TEST(Semaphore, SignalDequeuess) {
    Semaphore sem(1);

    bool first = false, second = false;
    sem.wait([&](bool ok) { first = ok; });
    sem.wait([&](bool ok) { second = ok; });

    EXPECT_TRUE(first);
    EXPECT_FALSE(second);

    sem.signal();
    EXPECT_TRUE(second);  // Dequeued
    EXPECT_EQ(sem.active(), 1);
    EXPECT_EQ(sem.waiting(), 0u);
}

TEST(Semaphore, LimitTwo) {
    Semaphore sem(2);

    int acquired = 0;
    bool third = false;

    sem.wait([&](bool ok) { if (ok) acquired++; });
    sem.wait([&](bool ok) { if (ok) acquired++; });
    sem.wait([&](bool ok) { third = ok; });

    EXPECT_EQ(acquired, 2);
    EXPECT_FALSE(third);  // Blocked at limit=2
    EXPECT_EQ(sem.active(), 2);

    sem.signal();
    EXPECT_TRUE(third);
    EXPECT_EQ(sem.active(), 2);  // Third took the freed slot
}

TEST(Semaphore, FlushWhenIdle) {
    Semaphore sem(2);

    bool flushed = false;
    sem.flush([&](bool ok) { flushed = ok; });
    EXPECT_TRUE(flushed);  // Already idle — fires immediately
}

TEST(Semaphore, FlushWaitsForActive) {
    Semaphore sem(1);

    bool acquired = false, flushed = false;
    sem.wait([&](bool ok) { acquired = ok; });
    EXPECT_TRUE(acquired);

    sem.flush([&](bool ok) { flushed = ok; });
    EXPECT_FALSE(flushed);  // Active=1, must wait

    sem.signal();
    EXPECT_TRUE(flushed);  // Now idle → flush fires
}

TEST(Semaphore, DestroyRejectsWaiters) {
    Semaphore sem(1);

    bool first = false;
    bool second_result = true;  // Should become false

    sem.wait([&](bool ok) { first = ok; });
    sem.wait([&](bool ok) { second_result = ok; });

    EXPECT_TRUE(first);
    EXPECT_TRUE(second_result);  // Not yet called

    sem.destroy();
    EXPECT_FALSE(second_result);  // Rejected
    EXPECT_TRUE(sem.is_destroyed());
    EXPECT_EQ(sem.active(), 0);
}

TEST(Semaphore, DestroyRejectsFlush) {
    Semaphore sem(1);

    sem.wait([](bool) {});

    bool flush_result = true;
    sem.flush([&](bool ok) { flush_result = ok; });

    sem.destroy();
    EXPECT_FALSE(flush_result);
}

TEST(Semaphore, WaitAfterDestroy) {
    Semaphore sem(1);
    sem.destroy();

    bool result = true;
    sem.wait([&](bool ok) { result = ok; });
    EXPECT_FALSE(result);
}

TEST(Semaphore, MultipleSignals) {
    Semaphore sem(1);

    std::vector<int> order;

    sem.wait([&](bool) { order.push_back(1); });
    sem.wait([&](bool) { order.push_back(2); });
    sem.wait([&](bool) { order.push_back(3); });

    EXPECT_EQ(order, std::vector<int>({1}));

    sem.signal();
    EXPECT_EQ(order, (std::vector<int>{1, 2}));

    sem.signal();
    EXPECT_EQ(order, (std::vector<int>{1, 2, 3}));
}
