// Background-tick JS parity: wake-from-sleep detection (_onwakeup),
// periodic stale-node pings (_pingSome), and thin-table refresh.
//
// JS reference: .analysis/js/dht-rpc/index.js
//   _ontick    :764-799  (wakeup gap check, pingSome every 8th tick,
//                         refresh when (tick&63)==0 && nodes < k)
//   _onwakeup  :552-573  (age-out tick math, force refresh, revert ephemeral)
//   _pingSome  :715-735  (3-5 oldest nodes, 2 if oldest was pinged recently)

#include <gtest/gtest.h>

#include <uv.h>

#include "hyperdht/routing_table.hpp"
#include "hyperdht/rpc.hpp"

using namespace hyperdht;
using namespace hyperdht::rpc;
using namespace hyperdht::routing;

namespace {

NodeId make_id(uint8_t seed) {
    NodeId id{};
    for (size_t i = 0; i < id.size(); i++) id[i] = static_cast<uint8_t>(seed + i);
    return id;
}

Node make_node(uint8_t seed, uint32_t pinged, uint32_t seen) {
    Node n;
    n.id = make_id(seed);
    n.host = "127.0.0.1";
    n.port = static_cast<uint16_t>(40000 + seed);
    n.pinged = pinged;
    n.seen = seen;
    n.added = 1;
    return n;
}

class TickTest : public ::testing::Test {
protected:
    void SetUp() override {
        uv_loop_init(&loop_);
        rpc_ = new RpcSocket(&loop_, make_id(200));
        ASSERT_EQ(rpc_->bind(0, "127.0.0.1"), 0);
        // tick-8: the ctor seeds tick_ with a random offset (JS index.js:74).
        // These tests assert on absolute (tick & 7)/(tick & 63) schedules, so
        // pin a deterministic base. RandomOffsetsAtConstruction covers the seed.
        rpc_->set_tick_for_test(0);
        rpc_->set_bootstrapped(true);
        rpc_->on_refresh([this]() { refreshes_++; });
        rpc_->on_wakeup([this]() { wakeups_++; });
    }

    void TearDown() override {
        rpc_->close();
        // Drain libuv close callbacks.
        while (uv_run(&loop_, UV_RUN_NOWAIT) != 0) {}
        delete rpc_;
        uv_loop_close(&loop_);
    }

    // Advance the socket's tick counter to `target` without side effects.
    void set_tick(uint32_t target) {
        while (rpc_->tick() < target) rpc_->bump_tick();
    }

    uv_loop_t loop_;
    RpcSocket* rpc_ = nullptr;
    int refreshes_ = 0;
    int wakeups_ = 0;
};

// --- wakeup detection ------------------------------------------------------

TEST_F(TickTest, NormalTickNoWakeup) {
    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_));  // fresh — no gap
    const uint32_t before = rpc_->tick();

    rpc_->background_tick();

    EXPECT_EQ(wakeups_, 0);
    EXPECT_EQ(rpc_->tick(), before + 1);
}

TEST_F(TickTest, ClockGapTriggersWakeup) {
    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_) - (SLEEPING_INTERVAL_MS + 1000));
    const uint32_t before = rpc_->tick();

    rpc_->background_tick();

    EXPECT_EQ(wakeups_, 1);
    // JS: _tick += 2 * OLD_NODE, then aligned so (tick & 7) == 6 —
    // everything in the table now looks old, pings fire in two ticks.
    EXPECT_GE(rpc_->tick(), before + 2 * OLD_NODE_TICKS);
    EXPECT_EQ(rpc_->tick() & 7u, 6u);
}

TEST_F(TickTest, WakeupTriggersImmediateRefresh) {
    // JS: _onwakeup sets _refreshTicks = 1, and the same _ontick then
    // decrements it to 0 → refresh fires within the wakeup tick itself.
    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_) - (SLEEPING_INTERVAL_MS + 1000));

    rpc_->background_tick();

    EXPECT_EQ(refreshes_, 1);
}

TEST_F(TickTest, FirstTickNeverWakesUp) {
    // last_tick_ms_ starts at 0 — a huge "gap", but the very first tick
    // must not count as a wakeup (JS seeds _lastTick = Date.now() at start).
    const uint32_t before = rpc_->tick();
    rpc_->background_tick();
    EXPECT_EQ(wakeups_, 0);
    EXPECT_EQ(rpc_->tick(), before + 1);
}

// --- _pingSome -------------------------------------------------------------

TEST_F(TickTest, PingSomeMarksOldestNodesOnEighthTick) {
    // 6 nodes, all stale (pinged=1, seen=1). tick will land on a multiple
    // of 8, inflight is empty → cnt = 5 → exactly 5 get pinged this tick.
    for (uint8_t i = 0; i < 6; i++) {
        ASSERT_TRUE(rpc_->table().add(make_node(i, 1, 1)));
    }
    set_tick(15);  // background_tick() → tick 16, (16 & 7) == 0
    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_));

    rpc_->background_tick();

    int pinged_now = 0;
    for (uint8_t i = 0; i < 6; i++) {
        const Node* n = rpc_->table().get(make_id(i));
        ASSERT_NE(n, nullptr);
        if (n->pinged == rpc_->tick()) pinged_now++;
    }
    EXPECT_EQ(pinged_now, 5);
}

TEST_F(TickTest, PingSomeSkipsOffCycleTicks) {
    for (uint8_t i = 0; i < 4; i++) {
        ASSERT_TRUE(rpc_->table().add(make_node(i, 1, 1)));
    }
    set_tick(16);  // background_tick() → tick 17, (17 & 7) != 0
    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_));

    rpc_->background_tick();

    for (uint8_t i = 0; i < 4; i++) {
        const Node* n = rpc_->table().get(make_id(i));
        ASSERT_NE(n, nullptr);
        EXPECT_EQ(n->pinged, 1u);
    }
}

TEST_F(TickTest, PingSomeOnlyTwoWhenOldestIsRecent) {
    // Oldest node pinged very recently (within RECENT_NODE_TICKS) → JS
    // drops the batch to 2.
    set_tick(15);
    const uint32_t next_tick = rpc_->tick() + 1;
    for (uint8_t i = 0; i < 5; i++) {
        // pinged just now relative to next_tick (gap 0 < RECENT_NODE_TICKS)
        ASSERT_TRUE(rpc_->table().add(make_node(i, next_tick - 1, 1)));
    }
    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_));

    rpc_->background_tick();

    int pinged_now = 0;
    for (uint8_t i = 0; i < 5; i++) {
        const Node* n = rpc_->table().get(make_id(i));
        ASSERT_NE(n, nullptr);
        if (n->pinged == rpc_->tick()) pinged_now++;
    }
    EXPECT_EQ(pinged_now, 2);
}

TEST_F(TickTest, PingSomeEmptyTableRefreshesInstead) {
    // JS: tiny dht → this.refresh() immediately.
    set_tick(15);
    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_));

    rpc_->background_tick();

    EXPECT_EQ(refreshes_, 1);
}

// --- thin-table refresh ----------------------------------------------------

TEST_F(TickTest, ThinTableRefreshesEverySixtyFourTicks) {
    // Table has fewer than K nodes and (tick & 63) == 0 → refresh fires
    // even though refresh_ticks_ hasn't expired.
    ASSERT_TRUE(rpc_->table().add(make_node(1, 1, 1)));
    set_tick(63);  // background_tick() → tick 64, (64 & 63) == 0
    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_));

    rpc_->background_tick();

    EXPECT_EQ(refreshes_, 1);
}

// --- tick-1: eviction PINGs must retry -------------------------------------

TEST_F(TickTest, CheckNodePingUsesRetries) {
    // tick-1: check_node()'s PING must carry retries=3 (JS _check → _request →
    // io.createRequest default, io.js:366) so a node survives dropped packets —
    // 4 transmissions, not 1. reping_and_swap() takes the identical fix.
    Node n = make_node(7, 1, 1);
    ASSERT_TRUE(rpc_->table().add(n));
    rpc_->check_node(n);
    EXPECT_EQ(rpc_->first_inflight_retries_for_test(), DEFAULT_RETRIES);
}

// --- tick-5: adaptive gate on the wakeup ephemeral revert -------------------

TEST_F(TickTest, WakeupRevertsEphemeralWhenAdaptive) {
    // Default RpcSocket is adaptive → a sleep gap reverts persistent→ephemeral
    // so the node re-derives its NAT/firewall state (JS index.js:560-570).
    ASSERT_TRUE(rpc_->is_adaptive());
    rpc_->force_check_persistent();
    ASSERT_FALSE(rpc_->is_ephemeral());

    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_) - (SLEEPING_INTERVAL_MS + 1000));
    rpc_->background_tick();

    EXPECT_EQ(wakeups_, 1);
    EXPECT_TRUE(rpc_->is_ephemeral())
        << "adaptive node must revert to ephemeral on wakeup";
}

TEST_F(TickTest, WakeupKeepsPersistentWhenNotAdaptive) {
    // A forced-persistent (non-adaptive) node keeps its id across a sleep gap.
    rpc_->set_adaptive(false);
    ASSERT_FALSE(rpc_->is_adaptive());
    rpc_->force_check_persistent();
    ASSERT_FALSE(rpc_->is_ephemeral());

    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_) - (SLEEPING_INTERVAL_MS + 1000));
    rpc_->background_tick();

    EXPECT_EQ(wakeups_, 1);
    EXPECT_FALSE(rpc_->is_ephemeral())
        << "non-adaptive node must stay persistent on wakeup";
}

TEST_F(TickTest, NotBootstrappedSkipsPingAndRefresh) {
    rpc_->set_bootstrapped(false);
    for (uint8_t i = 0; i < 3; i++) {
        ASSERT_TRUE(rpc_->table().add(make_node(i, 1, 1)));
    }
    set_tick(15);
    uv_update_time(&loop_);
    rpc_->set_last_tick_ms(uv_now(&loop_));

    rpc_->background_tick();

    EXPECT_EQ(refreshes_, 0);
    for (uint8_t i = 0; i < 3; i++) {
        const Node* n = rpc_->table().get(make_id(i));
        ASSERT_NE(n, nullptr);
        EXPECT_EQ(n->pinged, 1u);
    }
}

// --- tick-8: tick/refresh counters random-offset at construction -----------

TEST(TickConstruction, RandomOffsetsAtConstruction) {
    // tick-8: JS index.js:74-75 seeds `_tick = randomOffset(100)` ∈ (50,100] and
    // `_refreshTicks = randomOffset(60)` ∈ (30,60] so a fleet de-syncs its
    // maintenance traffic. randomOffset(n) = n - floor(random*0.5*n)
    // (index.js:1046-1048). Assert the bounds over several fresh sockets.
    uv_loop_t loop;
    uv_loop_init(&loop);

    for (int i = 0; i < 8; i++) {
        auto* s = new RpcSocket(&loop, make_id(static_cast<uint8_t>(i)));
        ASSERT_EQ(s->bind(0, "127.0.0.1"), 0);

        EXPECT_GE(s->tick(), 51u);
        EXPECT_LE(s->tick(), 100u);
        EXPECT_GE(s->refresh_ticks_for_test(), 31);
        EXPECT_LE(s->refresh_ticks_for_test(), 60);

        s->close();
        while (uv_run(&loop, UV_RUN_NOWAIT) != 0) {}
        delete s;
    }

    uv_loop_close(&loop);
}

}  // namespace
