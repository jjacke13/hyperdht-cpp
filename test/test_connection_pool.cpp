#include <gtest/gtest.h>

#include <array>
#include <memory>

#include "hyperdht/connection_pool.hpp"

using namespace hyperdht::connection_pool;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static ConnectionInfo make_info(uint8_t local_fill, uint8_t remote_fill,
                                bool initiator, uint32_t id = 0) {
    ConnectionInfo info;
    info.local_public_key.fill(local_fill);
    info.remote_public_key.fill(remote_fill);
    info.is_initiator = initiator;
    info.id = id;
    return info;
}

static std::shared_ptr<ConnectionRef> make_ref(uint8_t local_fill,
                                                uint8_t remote_fill,
                                                bool initiator,
                                                uint32_t id = 0) {
    return std::make_shared<ConnectionRef>(
        make_info(local_fill, remote_fill, initiator, id));
}

// ---------------------------------------------------------------------------
// Basic operations
// ---------------------------------------------------------------------------

TEST(ConnectionPool, AttachAndGet) {
    ConnectionPool pool;

    auto ref = make_ref(0xAA, 0xBB, true, 1);
    auto result = pool.attach_stream(ref, false);

    EXPECT_EQ(result, AttachResult::ATTACHED);
    EXPECT_EQ(pool.connecting_count(), 1u);
    EXPECT_EQ(pool.connected_count(), 0u);
    EXPECT_TRUE(pool.has(ref->remote_public_key()));

    auto found = pool.get(ref->remote_public_key());
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->id(), 1u);
}

TEST(ConnectionPool, AttachOpened) {
    ConnectionPool pool;

    auto ref = make_ref(0xAA, 0xBB, false, 2);
    pool.attach_stream(ref, true);

    EXPECT_EQ(pool.connecting_count(), 0u);
    EXPECT_EQ(pool.connected_count(), 1u);
    EXPECT_TRUE(pool.has(ref->remote_public_key()));
}

TEST(ConnectionPool, MarkOpened) {
    ConnectionPool pool;

    auto ref = make_ref(0xAA, 0xBB, true, 3);
    bool opened_fired = false;
    ref->on_open = [&]() { opened_fired = true; };

    pool.attach_stream(ref, false);
    EXPECT_EQ(pool.connecting_count(), 1u);
    EXPECT_EQ(pool.connected_count(), 0u);

    pool.mark_opened(ref->remote_public_key());
    EXPECT_EQ(pool.connecting_count(), 0u);
    EXPECT_EQ(pool.connected_count(), 1u);
    EXPECT_TRUE(opened_fired);
}

TEST(ConnectionPool, Remove) {
    ConnectionPool pool;

    auto ref = make_ref(0xAA, 0xBB, true);
    pool.attach_stream(ref, true);
    EXPECT_TRUE(pool.has(ref->remote_public_key()));

    pool.remove(ref->remote_public_key());
    EXPECT_FALSE(pool.has(ref->remote_public_key()));
    EXPECT_EQ(pool.connected_count(), 0u);
}

TEST(ConnectionPool, GetNotFound) {
    ConnectionPool pool;
    std::array<uint8_t, 32> key{};
    key.fill(0xFF);
    EXPECT_EQ(pool.get(key), nullptr);
    EXPECT_FALSE(pool.has(key));
}

TEST(ConnectionPool, GetPrefersConnected) {
    ConnectionPool pool;

    // Simulate: same remote key in both connecting and connected
    // This shouldn't normally happen, but test that get() prefers connected
    auto ref1 = make_ref(0xAA, 0xBB, true, 10);
    pool.attach_stream(ref1, false);  // connecting

    // Manually mark opened
    pool.mark_opened(ref1->remote_public_key());

    auto found = pool.get(ref1->remote_public_key());
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->id(), 10u);
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

TEST(ConnectionPool, DedupSameInitiatorKeepsNew) {
    ConnectionPool pool;

    // Both are initiators → keep new
    auto old_ref = make_ref(0xAA, 0xBB, true, 1);
    auto new_ref = make_ref(0xAA, 0xBB, true, 2);

    bool old_destroyed = false;
    old_ref->on_destroy = [&]() { old_destroyed = true; };

    pool.attach_stream(old_ref, true);
    auto result = pool.attach_stream(new_ref, true);

    EXPECT_EQ(result, AttachResult::DUPLICATE_KEPT_NEW);
    EXPECT_TRUE(old_destroyed);

    auto found = pool.get(new_ref->remote_public_key());
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->id(), 2u);  // New one survived
}

TEST(ConnectionPool, DedupDifferentInitiatorHighKeyKeepsNew) {
    ConnectionPool pool;

    // Different initiator modes, our key (0xCC) > remote key (0xBB) → keep new
    auto old_ref = make_ref(0xCC, 0xBB, false, 1);
    auto new_ref = make_ref(0xCC, 0xBB, true, 2);

    bool old_destroyed = false;
    old_ref->on_destroy = [&]() { old_destroyed = true; };

    pool.attach_stream(old_ref, true);
    auto result = pool.attach_stream(new_ref, true);

    EXPECT_EQ(result, AttachResult::DUPLICATE_KEPT_NEW);
    EXPECT_TRUE(old_destroyed);
}

TEST(ConnectionPool, DedupDifferentInitiatorLowKeyKeepsOld) {
    ConnectionPool pool;

    // Different initiator modes, our key (0x11) < remote key (0xBB) → keep old
    auto old_ref = make_ref(0x11, 0xBB, false, 1);
    auto new_ref = make_ref(0x11, 0xBB, true, 2);

    bool new_destroyed = false;
    new_ref->on_destroy = [&]() { new_destroyed = true; };

    pool.attach_stream(old_ref, true);
    auto result = pool.attach_stream(new_ref, true);

    EXPECT_EQ(result, AttachResult::DUPLICATE_KEPT_OLD);
    EXPECT_TRUE(new_destroyed);

    auto found = pool.get(old_ref->remote_public_key());
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->id(), 1u);  // Old one survived
}

TEST(ConnectionPool, DedupConnectingVsConnected) {
    ConnectionPool pool;

    // Existing is connecting, new is opened — same initiator → keep new
    auto old_ref = make_ref(0xAA, 0xBB, true, 1);
    auto new_ref = make_ref(0xAA, 0xBB, true, 2);

    bool old_destroyed = false;
    old_ref->on_destroy = [&]() { old_destroyed = true; };

    pool.attach_stream(old_ref, false);  // connecting
    auto result = pool.attach_stream(new_ref, true);  // connected

    EXPECT_EQ(result, AttachResult::DUPLICATE_KEPT_NEW);
    EXPECT_TRUE(old_destroyed);
    EXPECT_EQ(pool.connecting_count(), 0u);
    EXPECT_EQ(pool.connected_count(), 1u);
}

// ---------------------------------------------------------------------------
// Ref counting
// ---------------------------------------------------------------------------

TEST(ConnectionPool, RefCounting) {
    auto ref = make_ref(0xAA, 0xBB, true);
    EXPECT_EQ(ref->refs(), 0);

    ref->active();
    EXPECT_EQ(ref->refs(), 1);

    ref->active();
    EXPECT_EQ(ref->refs(), 2);

    ref->inactive();
    EXPECT_EQ(ref->refs(), 1);

    ref->inactive();
    EXPECT_EQ(ref->refs(), 0);
}

// ---------------------------------------------------------------------------
// Multiple peers
// ---------------------------------------------------------------------------

TEST(ConnectionPool, MultiplePeers) {
    ConnectionPool pool;

    auto ref1 = make_ref(0xAA, 0x11, true, 1);
    auto ref2 = make_ref(0xAA, 0x22, true, 2);
    auto ref3 = make_ref(0xAA, 0x33, true, 3);

    pool.attach_stream(ref1, true);
    pool.attach_stream(ref2, true);
    pool.attach_stream(ref3, false);

    EXPECT_EQ(pool.connected_count(), 2u);
    EXPECT_EQ(pool.connecting_count(), 1u);

    EXPECT_TRUE(pool.has(ref1->remote_public_key()));
    EXPECT_TRUE(pool.has(ref2->remote_public_key()));
    EXPECT_TRUE(pool.has(ref3->remote_public_key()));

    pool.remove(ref2->remote_public_key());
    EXPECT_EQ(pool.connected_count(), 1u);
    EXPECT_FALSE(pool.has(ref2->remote_public_key()));
}

TEST(ConnectionPool, NoDedupDifferentPeers) {
    ConnectionPool pool;

    // Different remote keys — no dedup
    auto ref1 = make_ref(0xAA, 0x11, true, 1);
    auto ref2 = make_ref(0xAA, 0x22, true, 2);

    auto r1 = pool.attach_stream(ref1, true);
    auto r2 = pool.attach_stream(ref2, true);

    EXPECT_EQ(r1, AttachResult::ATTACHED);
    EXPECT_EQ(r2, AttachResult::ATTACHED);
    EXPECT_EQ(pool.connected_count(), 2u);
}
