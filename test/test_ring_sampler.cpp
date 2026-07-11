#include <gtest/gtest.h>

#include "hyperdht/nat_sampler.hpp"

using hyperdht::nat::RingSampler;

// ---------------------------------------------------------------------------
// RingSampler — line-faithful port of the `nat-sampler` npm package
// (.analysis/js/nat-sampler/index.js). Every expected value below was derived
// by executing the JS algorithm by hand; see the per-test notes.
// ---------------------------------------------------------------------------

// JS: index.js:20 — threshold = size - (size<4?0 : size<8?1 : size<12?2 : 3).
// size increments once per add while the 32-slot ring is filling (16 pairs).
TEST(RingSampler, ThresholdTableSizes1To16) {
    RingSampler s;
    const int expected[17] = {
        0,              // size 0 (unused)
        1, 2, 3,        // sizes 1-3:  -0
        3, 4, 5, 6,     // sizes 4-7:  -1
        6, 7, 8, 9,     // sizes 8-11: -2
        9, 10, 11, 12, 13  // sizes 12-16: -3
    };
    for (int size = 1; size <= 16; size++) {
        s.add("1.2.3.4", 5000);
        EXPECT_EQ(s.size(), size);
        EXPECT_EQ(s.threshold(), expected[size]) << "size=" << size;
    }
}

// 3 identical (host, port) samples cross the threshold → publish host+port.
TEST(RingSampler, ConsistentPublishesHostPort) {
    RingSampler s;
    for (int i = 0; i < 3; i++) s.add("1.2.3.4", 5000);
    EXPECT_EQ(s.host(), "1.2.3.4");
    EXPECT_EQ(s.port(), 5000u);
    EXPECT_EQ(s.size(), 3);
}

// Same host, different ports every time: the host-only sample (b) crosses the
// threshold while the host+port sample (a) does not → publish (host, port=0).
// This is the JS "host consistent, port random" signal.
TEST(RingSampler, PortRandomPublishesHostPortZero) {
    RingSampler s;
    s.add("1.2.3.4", 5000);
    s.add("1.2.3.4", 5001);
    s.add("1.2.3.4", 5002);
    EXPECT_EQ(s.host(), "1.2.3.4");
    EXPECT_EQ(s.port(), 0u) << "consistent host but random ports → port 0";
}

// Two fully-different observations: neither best-pointer reaches threshold=2
// after the second add → host() is empty (JS `this.host = null`).
TEST(RingSampler, NoWinnerHostEmpty) {
    RingSampler s;
    s.add("1.1.1.1", 1000);
    EXPECT_EQ(s.host(), "1.1.1.1");  // first sample publishes (threshold 1)
    s.add("2.2.2.2", 2000);
    EXPECT_TRUE(s.host().empty()) << "no winner crosses threshold 2";
    EXPECT_EQ(s.port(), 0u);
}

// No source dedup: the package takes no source argument, so repeating the same
// observation keeps incrementing hits (add() returns a.hits). The old
// NatSampler would ignore repeats from one source; RingSampler must not.
TEST(RingSampler, NoSourceDedupHitsAccumulate) {
    RingSampler s;
    EXPECT_EQ(s.add("9.9.9.9", 4000), 1);
    EXPECT_EQ(s.add("9.9.9.9", 4000), 2);
    EXPECT_EQ(s.add("9.9.9.9", 4000), 3);
    EXPECT_EQ(s.host(), "9.9.9.9");
    EXPECT_EQ(s.port(), 4000u);
}

// Ring eviction (17th+ pair evicts the oldest, decrementing its hits) and
// adaptation to an address change. Hand-derived:
//   - 16x "A": ring full, A.hits=16, threshold=13, host=A.
//   - +4x "C": each evicts an "A" pair → A.hits 16→12. 12 < 13, and the stale
//     _a best-pointer still points at A, so host() goes empty (JS: a stale
//     best-pointer dropping below threshold sends host back to null).
//   - +12x "C" (16 total): "C" fully overtakes → host=C. size stays 16.
TEST(RingSampler, RingEvictionAndAdaptation) {
    RingSampler s;
    for (int i = 0; i < 16; i++) s.add("10.0.0.1", 1000);
    EXPECT_EQ(s.size(), 16);
    EXPECT_EQ(s.host(), "10.0.0.1");
    EXPECT_EQ(s.port(), 1000u);

    for (int i = 0; i < 4; i++) s.add("10.0.0.99", 2000);
    EXPECT_TRUE(s.host().empty())
        << "stale winner eroded below threshold by evictions";

    for (int i = 0; i < 12; i++) s.add("10.0.0.99", 2000);
    EXPECT_EQ(s.host(), "10.0.0.99");
    EXPECT_EQ(s.port(), 2000u);
    EXPECT_EQ(s.size(), 16) << "size caps at 16 pairs once the ring is full";
}

// reset() returns to the constructed state.
TEST(RingSampler, Reset) {
    RingSampler s;
    for (int i = 0; i < 3; i++) s.add("1.2.3.4", 5000);
    ASSERT_EQ(s.host(), "1.2.3.4");
    s.reset();
    EXPECT_TRUE(s.host().empty());
    EXPECT_EQ(s.port(), 0u);
    EXPECT_EQ(s.size(), 0);
    EXPECT_EQ(s.threshold(), 0);
}
