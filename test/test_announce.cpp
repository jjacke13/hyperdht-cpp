#include <gtest/gtest.h>

#include <cstdint>

#include "hyperdht/announce.hpp"

using namespace hyperdht::announce;
using namespace hyperdht::compact;

static TargetKey make_target(uint8_t fill) {
    TargetKey k{};
    k.fill(fill);
    return k;
}

static PeerAnnouncement make_ann(const char* host, uint16_t port, uint64_t time = 1000) {
    PeerAnnouncement ann;
    ann.from = Ipv4Address::from_string(host, port);
    ann.value = {0x01, 0x02};
    ann.created_at = time;
    return ann;
}

TEST(AnnounceStore, PutAndGet) {
    AnnounceStore store;
    auto target = make_target(0xAA);
    store.put(target, make_ann("10.0.0.1", 3000));

    auto peers = store.get(target);
    EXPECT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0]->from.port, 3000u);
    EXPECT_EQ(store.size(), 1u);
}

TEST(AnnounceStore, MultiplePeersPerTarget) {
    AnnounceStore store;
    auto target = make_target(0xAA);
    store.put(target, make_ann("10.0.0.1", 3001));
    store.put(target, make_ann("10.0.0.2", 3002));
    store.put(target, make_ann("10.0.0.3", 3003));

    auto peers = store.get(target);
    EXPECT_EQ(peers.size(), 3u);
    EXPECT_EQ(store.size(), 3u);
}

TEST(AnnounceStore, ReplaceSameAddress) {
    AnnounceStore store;
    auto target = make_target(0xAA);

    auto ann1 = make_ann("10.0.0.1", 3000, 1000);
    ann1.value = {0x01};
    store.put(target, ann1);

    auto ann2 = make_ann("10.0.0.1", 3000, 2000);
    ann2.value = {0x02};
    store.put(target, ann2);

    auto peers = store.get(target);
    EXPECT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0]->value[0], 0x02);  // Updated
}

TEST(AnnounceStore, Remove) {
    AnnounceStore store;
    auto target = make_target(0xAA);
    store.put(target, make_ann("10.0.0.1", 3000));
    store.put(target, make_ann("10.0.0.2", 3001));

    auto from = Ipv4Address::from_string("10.0.0.1", 3000);
    EXPECT_TRUE(store.remove(target, from));
    EXPECT_EQ(store.size(), 1u);

    // Remove non-existent
    EXPECT_FALSE(store.remove(target, from));
}

TEST(AnnounceStore, GetEmptyTarget) {
    AnnounceStore store;
    auto peers = store.get(make_target(0xFF));
    EXPECT_TRUE(peers.empty());
}

TEST(AnnounceStore, GarbageCollection) {
    AnnounceStore store;
    auto target = make_target(0xAA);

    auto ann1 = make_ann("10.0.0.1", 3000, 1000);
    ann1.ttl = 5000;  // Expires at 6000
    store.put(target, ann1);

    auto ann2 = make_ann("10.0.0.2", 3001, 3000);
    ann2.ttl = 5000;  // Expires at 8000
    store.put(target, ann2);

    // At time 7000: ann1 expired, ann2 still alive
    store.gc(7000);
    auto peers = store.get(target);
    EXPECT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0]->from.port, 3001u);

    // At time 9000: both expired
    store.gc(9000);
    EXPECT_EQ(store.size(), 0u);
    EXPECT_EQ(store.target_count(), 0u);
}

TEST(AnnounceStore, EvictOldestAtCapacity) {
    AnnounceStore store;
    auto target = make_target(0xAA);

    // Fill to MAX_PEERS_PER_TARGET
    for (size_t i = 0; i < MAX_PEERS_PER_TARGET; i++) {
        std::string host = "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
        auto ann = make_ann(host.c_str(), static_cast<uint16_t>(3000 + i),
                           static_cast<uint64_t>(1000 + i));
        store.put(target, ann);
    }
    EXPECT_EQ(store.size(), MAX_PEERS_PER_TARGET);

    // One more should evict the oldest (created_at=1000)
    auto extra = make_ann("10.99.99.99", 9999, 99999);
    store.put(target, extra);
    EXPECT_EQ(store.size(), MAX_PEERS_PER_TARGET);  // Still at capacity
}
