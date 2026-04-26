#include <gtest/gtest.h>

#include "hyperdht/lru_cache.hpp"

using namespace hyperdht;

TEST(LruCache, PutGet) {
    LruCache<std::string, int> cache(10);
    cache.put("a", 1, 1000);
    cache.put("b", 2, 1000);

    auto* a = cache.get("a");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(*a, 1);

    auto* b = cache.get("b");
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(*b, 2);

    EXPECT_EQ(cache.get("c"), nullptr);
    EXPECT_EQ(cache.size(), 2u);
}

TEST(LruCache, EvictsOldest) {
    LruCache<std::string, int> cache(3);
    cache.put("a", 1, 1000);
    cache.put("b", 2, 2000);
    cache.put("c", 3, 3000);
    EXPECT_EQ(cache.size(), 3u);

    // Insert 4th — "a" (oldest) should be evicted
    cache.put("d", 4, 4000);
    EXPECT_EQ(cache.size(), 3u);
    EXPECT_EQ(cache.get("a"), nullptr) << "Oldest entry should be evicted";
    EXPECT_NE(cache.get("b"), nullptr);
    EXPECT_NE(cache.get("d"), nullptr);
}

TEST(LruCache, GetPromotesEntry) {
    LruCache<std::string, int> cache(3);
    cache.put("a", 1, 1000);
    cache.put("b", 2, 2000);
    cache.put("c", 3, 3000);

    // Access "a" — promotes it to front
    cache.get("a");

    // Insert "d" — "b" should be evicted (oldest after promotion), not "a"
    cache.put("d", 4, 4000);
    EXPECT_NE(cache.get("a"), nullptr) << "Promoted entry should survive";
    EXPECT_EQ(cache.get("b"), nullptr) << "Non-promoted oldest should be evicted";
}

TEST(LruCache, GcRemovesExpired) {
    LruCache<std::string, int> cache(100);
    cache.put("old", 1, 1000);
    cache.put("fresh", 2, 5000);

    // GC with 2s TTL at time=4000 — "old" (created at 1000) expired, "fresh" (5000) not
    cache.gc(4000, 2000);
    EXPECT_EQ(cache.get("old"), nullptr) << "Expired entry should be removed";
    EXPECT_NE(cache.get("fresh"), nullptr) << "Fresh entry should remain";
}

TEST(LruCache, GcKeepsFresh) {
    LruCache<std::string, int> cache(100);
    cache.put("a", 1, 1000);
    cache.put("b", 2, 2000);
    cache.put("c", 3, 3000);

    // GC at time=3500 with 5s TTL — all entries are fresh
    cache.gc(3500, 5000);
    EXPECT_EQ(cache.size(), 3u) << "All fresh entries should remain";
}

TEST(LruCache, Remove) {
    LruCache<std::string, int> cache(10);
    cache.put("a", 1, 1000);
    cache.put("b", 2, 1000);

    cache.remove("a");
    EXPECT_EQ(cache.get("a"), nullptr);
    EXPECT_NE(cache.get("b"), nullptr);
    EXPECT_EQ(cache.size(), 1u);

    // Remove non-existent — no crash
    cache.remove("zzz");
    EXPECT_EQ(cache.size(), 1u);
}

TEST(LruCache, PutOverwrite) {
    LruCache<std::string, int> cache(10);
    cache.put("a", 1, 1000);
    cache.put("a", 99, 2000);

    auto* a = cache.get("a");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(*a, 99) << "Overwrite should update value";
    EXPECT_EQ(cache.size(), 1u) << "Overwrite should not create duplicate";
}

TEST(LruCache, OverwriteRefreshesTimestamp) {
    LruCache<std::string, int> cache(100);
    cache.put("a", 1, 1000);
    cache.put("a", 2, 5000);  // Refresh timestamp to 5000

    // GC at time=4000 with 2s TTL — "a" was refreshed to 5000, not expired
    cache.gc(4000, 2000);
    EXPECT_NE(cache.get("a"), nullptr) << "Refreshed entry should survive GC";
}

// Regression: gc() must walk the entire list, not stop at the first
// un-expired tail entry. `get()` promotes by moving an entry to the
// front WITHOUT updating `created_at`, so list-tail order is LRU
// access order, not chronological created_at order. After a `get()`,
// an old (truly-expired) entry can sit at the front while a younger
// (un-expired) entry sits at the back. An early `break` at the back
// would leak the expired entry indefinitely.
TEST(LruCache, GcWalksFullListAfterGetPromotion) {
    LruCache<std::string, int> cache(100);
    cache.put("old", 1, 1000);
    cache.put("fresh", 2, 5000);

    // Promote "old" to the front — list is now [old(1000), fresh(5000)]
    // (front-to-back). The back is now "fresh", which is un-expired.
    ASSERT_NE(cache.get("old"), nullptr);

    // GC at time=4000 with 2s TTL.
    // - "old" (created_at=1000, age=3000) IS expired.
    // - "fresh" (created_at=5000) is fresh.
    // A buggy gc that stops at the first un-expired tail entry would
    // see "fresh" at the back, break, and leave "old" forever.
    cache.gc(4000, 2000);
    EXPECT_EQ(cache.get("old"), nullptr)
        << "Expired entry must be evicted even when it's not at the list tail";
    EXPECT_NE(cache.get("fresh"), nullptr)
        << "Un-expired entry must survive";
    EXPECT_EQ(cache.size(), 1u);
}
