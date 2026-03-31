#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <set>
#include <string>

#include "hyperdht/routing_table.hpp"

using namespace hyperdht::routing;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static NodeId make_id(uint8_t fill) {
    NodeId id{};
    id.fill(fill);
    return id;
}

static NodeId make_id_with_prefix(const NodeId& base, size_t bit_pos, bool flip) {
    // Create an ID that differs from base at the given bit position
    NodeId id = base;
    size_t byte_idx = bit_pos / 8;
    uint8_t bit_mask = static_cast<uint8_t>(0x80 >> (bit_pos % 8));
    if (flip) {
        id[byte_idx] ^= bit_mask;
    }
    return id;
}

static Node make_node(const NodeId& id) {
    Node n;
    n.id = id;
    n.host = "127.0.0.1";
    n.port = 1234;
    return n;
}

// ---------------------------------------------------------------------------
// XOR distance
// ---------------------------------------------------------------------------

TEST(RoutingXor, BucketIndex) {
    NodeId a{};
    a.fill(0x00);
    NodeId b{};
    b.fill(0x00);

    // Equal IDs → ID_BITS (256)
    EXPECT_EQ(bucket_index(a, b), ID_BITS);

    // Differ in first bit
    b[0] = 0x80;
    EXPECT_EQ(bucket_index(a, b), 0u);

    // Differ in second bit
    b[0] = 0x40;
    EXPECT_EQ(bucket_index(a, b), 1u);

    // Differ in last bit of first byte
    b[0] = 0x01;
    EXPECT_EQ(bucket_index(a, b), 7u);

    // Differ in first bit of second byte
    b[0] = 0x00;
    b[1] = 0x80;
    EXPECT_EQ(bucket_index(a, b), 8u);

    // Differ in last bit of last byte
    b[1] = 0x00;
    b[31] = 0x01;
    EXPECT_EQ(bucket_index(a, b), 255u);
}

TEST(RoutingXor, CompareDistance) {
    NodeId target = make_id(0x00);
    NodeId a{};
    a.fill(0x00);
    a[0] = 0x01;  // Distance = 1 (in first byte)
    NodeId b{};
    b.fill(0x00);
    b[0] = 0x02;  // Distance = 2 (in first byte)

    EXPECT_LT(compare_distance(target, a, b), 0);  // a is closer
    EXPECT_GT(compare_distance(target, b, a), 0);  // b is farther
    EXPECT_EQ(compare_distance(target, a, a), 0);  // equal
}

// ---------------------------------------------------------------------------
// Bucket operations
// ---------------------------------------------------------------------------

TEST(RoutingBucket, AddAndGet) {
    Bucket bucket;
    NodeId id = make_id(0x42);
    auto node = make_node(id);

    EXPECT_TRUE(bucket.add(node));
    EXPECT_EQ(bucket.size(), 1u);
    EXPECT_FALSE(bucket.empty());

    auto* found = bucket.get(id);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->id, id);
}

TEST(RoutingBucket, DuplicateRejected) {
    Bucket bucket;
    auto node = make_node(make_id(0x42));

    EXPECT_TRUE(bucket.add(node));
    EXPECT_FALSE(bucket.add(node));  // Duplicate
    EXPECT_EQ(bucket.size(), 1u);
}

TEST(RoutingBucket, FullBucket) {
    Bucket bucket;
    for (size_t i = 0; i < K; i++) {
        NodeId id{};
        id.fill(0x00);
        id[0] = static_cast<uint8_t>(i + 1);
        EXPECT_TRUE(bucket.add(make_node(id)));
    }
    EXPECT_TRUE(bucket.is_full());

    // One more should fail
    NodeId extra{};
    extra.fill(0xFF);
    EXPECT_FALSE(bucket.add(make_node(extra)));
}

TEST(RoutingBucket, Remove) {
    Bucket bucket;
    NodeId id = make_id(0x42);
    bucket.add(make_node(id));
    EXPECT_EQ(bucket.size(), 1u);

    EXPECT_TRUE(bucket.remove(id));
    EXPECT_EQ(bucket.size(), 0u);
    EXPECT_TRUE(bucket.empty());
    EXPECT_EQ(bucket.get(id), nullptr);

    // Remove non-existent
    EXPECT_FALSE(bucket.remove(make_id(0x99)));
}

// ---------------------------------------------------------------------------
// RoutingTable operations
// ---------------------------------------------------------------------------

TEST(RoutingTable, AddAndGet) {
    NodeId local = make_id(0x00);
    RoutingTable table(local);

    NodeId remote = make_id(0x01);
    EXPECT_TRUE(table.add(make_node(remote)));
    EXPECT_EQ(table.size(), 1u);

    auto* found = table.get(remote);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->id, remote);
    EXPECT_TRUE(table.has(remote));
}

TEST(RoutingTable, DoNotAddSelf) {
    NodeId local = make_id(0x42);
    RoutingTable table(local);

    EXPECT_FALSE(table.add(make_node(local)));
    EXPECT_EQ(table.size(), 0u);
}

TEST(RoutingTable, RemoveNode) {
    NodeId local = make_id(0x00);
    RoutingTable table(local);

    NodeId remote = make_id(0x01);
    table.add(make_node(remote));
    EXPECT_EQ(table.size(), 1u);

    EXPECT_TRUE(table.remove(remote));
    EXPECT_EQ(table.size(), 0u);
    EXPECT_FALSE(table.has(remote));
}

TEST(RoutingTable, FullBucketCallback) {
    NodeId local = make_id(0x00);
    RoutingTable table(local);

    bool callback_called = false;
    Node rejected_node;

    table.on_full([&](size_t, const Node& node) {
        callback_called = true;
        rejected_node = node;
    });

    // Fill bucket 7 (IDs differing in bit 7, i.e., byte 0 bit 0)
    // All IDs: 0x01, 0x02, 0x03, ... will go to different buckets
    // We need K nodes in the SAME bucket.
    // Bucket 0 = IDs with bit 0 (0x80) differing
    for (size_t i = 0; i < K; i++) {
        NodeId id = local;
        id[0] = 0x80;  // Flip first bit → bucket 0
        // Vary lower bits to make unique IDs
        id[31] = static_cast<uint8_t>(i + 1);
        EXPECT_TRUE(table.add(make_node(id)));
    }

    EXPECT_EQ(table.size(), K);
    EXPECT_FALSE(callback_called);

    // One more in the same bucket → should trigger callback
    NodeId extra = local;
    extra[0] = 0x80;
    extra[31] = static_cast<uint8_t>(K + 1);
    EXPECT_FALSE(table.add(make_node(extra)));
    EXPECT_TRUE(callback_called);
    EXPECT_EQ(rejected_node.id, extra);
}

TEST(RoutingTable, Closest) {
    NodeId local = make_id(0x00);
    RoutingTable table(local);

    // Add nodes at various distances
    std::vector<NodeId> ids;
    for (int i = 1; i <= 10; i++) {
        NodeId id{};
        id.fill(0x00);
        id[0] = static_cast<uint8_t>(i);  // Various distances
        ids.push_back(id);
        table.add(make_node(id));
    }

    // Find 5 closest to local ID
    auto closest = table.closest(local, 5);
    EXPECT_EQ(closest.size(), 5u);

    // Verify they're sorted by XOR distance to local (which is 0x00...00)
    for (size_t i = 1; i < closest.size(); i++) {
        EXPECT_LE(compare_distance(local, closest[i - 1]->id, closest[i]->id), 0)
            << "Nodes should be sorted by distance";
    }

    // The closest node to 0x00...00 should be 0x01...00
    EXPECT_EQ(closest[0]->id[0], 0x01);
}

TEST(RoutingTable, ClosestToTarget) {
    NodeId local = make_id(0x00);
    RoutingTable table(local);

    // Add 20 nodes spread across buckets
    for (int i = 0; i < 20; i++) {
        NodeId id{};
        id.fill(0x00);
        id[i / 8] |= static_cast<uint8_t>(0x80 >> (i % 8));
        id[31] = static_cast<uint8_t>(i + 1);  // Make unique
        table.add(make_node(id));
    }

    // Search for nodes closest to a specific target
    NodeId target{};
    target.fill(0xFF);
    auto closest = table.closest(target, 5);
    EXPECT_LE(closest.size(), 5u);

    // Verify sorting
    for (size_t i = 1; i < closest.size(); i++) {
        EXPECT_LE(compare_distance(target, closest[i - 1]->id, closest[i]->id), 0);
    }
}

TEST(RoutingTable, Random) {
    NodeId local = make_id(0x00);
    RoutingTable table(local);

    // Empty table
    EXPECT_EQ(table.random(), nullptr);

    // Add some nodes
    for (int i = 1; i <= 5; i++) {
        NodeId id{};
        id.fill(0x00);
        id[0] = static_cast<uint8_t>(i);
        table.add(make_node(id));
    }

    // Random should return something
    auto* node = table.random();
    ASSERT_NE(node, nullptr);
    EXPECT_TRUE(table.has(node->id));

    // Call it many times — should not crash
    std::set<uint8_t> seen;
    for (int i = 0; i < 100; i++) {
        auto* n = table.random();
        ASSERT_NE(n, nullptr);
        seen.insert(n->id[0]);
    }
    // Should hit at least 2 different nodes over 100 tries
    EXPECT_GE(seen.size(), 2u);
}

TEST(RoutingTable, ManyNodes) {
    NodeId local = make_id(0x00);
    RoutingTable table(local);

    // Add 100 nodes in different buckets
    size_t added = 0;
    for (int byte = 0; byte < 32 && added < 100; byte++) {
        for (int bit = 0; bit < 8 && added < 100; bit++) {
            NodeId id{};
            id.fill(0x00);
            id[byte] = static_cast<uint8_t>(0x80 >> bit);
            id[31] = static_cast<uint8_t>(added + 1);  // Unique
            if (table.add(make_node(id))) {
                added++;
            }
        }
    }

    EXPECT_EQ(table.size(), added);

    // Closest should return K nodes
    auto closest = table.closest(make_id(0xFF), K);
    EXPECT_EQ(closest.size(), K);
}
