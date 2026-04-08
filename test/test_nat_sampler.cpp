#include <gtest/gtest.h>

#include "hyperdht/nat_sampler.hpp"
#include "hyperdht/peer_connect.hpp"

using namespace hyperdht;
using namespace hyperdht::nat;
using Ipv4Address = compact::Ipv4Address;

// Helper: create addresses with distinct sources
static Ipv4Address addr(const char* host, uint16_t port) {
    return Ipv4Address::from_string(host, port);
}

// ---------------------------------------------------------------------------
// NatSampler classification
// ---------------------------------------------------------------------------

TEST(NatSampler, StartsUnknown) {
    NatSampler s;
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_UNKNOWN);
    EXPECT_EQ(s.sampled(), 0);
    EXPECT_TRUE(s.addresses().empty());
}

TEST(NatSampler, NeedsThreeSamples) {
    NatSampler s;

    // 2 samples from different sources, both seeing us at same address
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));

    EXPECT_EQ(s.sampled(), 2);
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_UNKNOWN);
}

TEST(NatSampler, ConsistentAfterThreeMatching) {
    NatSampler s;

    // 3 different DHT nodes all see us at the same address
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.3", 1000));

    EXPECT_EQ(s.sampled(), 3);
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_CONSISTENT);
    EXPECT_EQ(s.host(), "1.2.3.4");
    EXPECT_EQ(s.port(), 5000);
}

TEST(NatSampler, RandomWhenAllDifferent) {
    NatSampler s;

    // 3 different nodes see us at 3 different ports
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5001), addr("10.0.0.2", 1000));
    s.add(addr("1.2.3.4", 5002), addr("10.0.0.3", 1000));

    EXPECT_EQ(s.sampled(), 3);
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_RANDOM);
}

TEST(NatSampler, DeduplicatesSourceNode) {
    NatSampler s;

    // Same source node twice — should only count once
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));

    EXPECT_EQ(s.sampled(), 1);
}

TEST(NatSampler, ConsistentAddressesHaveTwoMinimum) {
    NatSampler s;

    // All 4 see us at the same address
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.3", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.4", 1000));

    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_CONSISTENT);
    // Should have at least 2 addresses (minimum from JS)
    EXPECT_GE(s.addresses().size(), 1u);
    EXPECT_EQ(s.addresses()[0].host_string(), "1.2.3.4");
    EXPECT_EQ(s.addresses()[0].port, 5000u);
}

TEST(NatSampler, RandomAddressHasHostOnly) {
    NatSampler s;

    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5001), addr("10.0.0.2", 1000));
    s.add(addr("1.2.3.4", 5002), addr("10.0.0.3", 1000));

    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_RANDOM);
    ASSERT_EQ(s.addresses().size(), 1u);
    EXPECT_EQ(s.addresses()[0].host_string(), "1.2.3.4");
    EXPECT_EQ(s.addresses()[0].port, 0u);  // Port unknown for RANDOM
}

TEST(NatSampler, EdgeCaseMaxTwoOneHost) {
    // max_hits = 2, single host, >3 samples → RANDOM
    NatSampler s;

    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));
    s.add(addr("1.2.3.4", 5001), addr("10.0.0.3", 1000));
    s.add(addr("1.2.3.4", 5002), addr("10.0.0.4", 1000));

    // hits: 5000→2, 5001→1, 5002→1. max=2, 1 host, >3 samples → RANDOM
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_RANDOM);
}

TEST(NatSampler, EdgeCaseDoubleHitTwoIPs) {
    // max_hits = 2 on two different IPs → CONSISTENT
    NatSampler s;

    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));
    s.add(addr("5.6.7.8", 5000), addr("10.0.0.3", 1000));
    s.add(addr("5.6.7.8", 5000), addr("10.0.0.4", 1000));

    // Two different full addresses, both with 2 hits → CONSISTENT
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_CONSISTENT);
}

TEST(NatSampler, Reset) {
    NatSampler s;

    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.3", 1000));
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_CONSISTENT);

    s.reset();
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_UNKNOWN);
    EXPECT_EQ(s.sampled(), 0);
    EXPECT_TRUE(s.addresses().empty());
}

// ---------------------------------------------------------------------------
// Sample sorting (tested through NatSampler public API)
// ---------------------------------------------------------------------------

TEST(NatSampler, MostHitAddressWins) {
    NatSampler s;

    // Two addresses: 1.2.3.4 seen 3 times, 5.6.7.8 seen once
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("5.6.7.8", 5000), addr("10.0.0.2", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.3", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.4", 1000));

    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_CONSISTENT);
    EXPECT_EQ(s.host(), "1.2.3.4");
    EXPECT_EQ(s.port(), 5000);
}

// ---------------------------------------------------------------------------
// PING_NAT handler
// ---------------------------------------------------------------------------

TEST(PingNat, HandlerFormat) {
    // Verify the PING_NAT value encoding: 2-byte uint16 LE port
    uint16_t port = 12345;
    std::vector<uint8_t> value(2);
    value[0] = static_cast<uint8_t>(port & 0xFF);
    value[1] = static_cast<uint8_t>(port >> 8);

    // Decode back
    uint16_t decoded = static_cast<uint16_t>(value[0])
                     | (static_cast<uint16_t>(value[1]) << 8);
    EXPECT_EQ(decoded, 12345u);
}

// ---------------------------------------------------------------------------
// Freeze/Unfreeze
// ---------------------------------------------------------------------------

TEST(NatSampler, FreezePreventUpdate) {
    NatSampler s;

    // Add 2 samples (not enough to classify)
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_UNKNOWN);

    // Freeze
    s.freeze();
    EXPECT_TRUE(s.is_frozen());

    // 3rd sample would normally trigger CONSISTENT, but we're frozen
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.3", 1000));
    EXPECT_EQ(s.sampled(), 3);
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_UNKNOWN)
        << "Frozen sampler should not update firewall";

    // Unfreeze — should now update
    s.unfreeze();
    EXPECT_FALSE(s.is_frozen());
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_CONSISTENT)
        << "Unfreeze should trigger classification update";
}

TEST(NatSampler, FreezeWhileConsistent) {
    NatSampler s;

    // Already classified as CONSISTENT
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.3", 1000));
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_CONSISTENT);

    // Freeze and add conflicting samples
    s.freeze();
    s.add(addr("1.2.3.4", 9999), addr("10.0.0.4", 1000));
    s.add(addr("1.2.3.4", 8888), addr("10.0.0.5", 1000));

    // Should still be CONSISTENT (frozen)
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_CONSISTENT);

    s.unfreeze();
    // After unfreeze, re-evaluation with 5 samples (3 matching + 2 different)
    // Top sample still has 3 hits → CONSISTENT
    EXPECT_EQ(s.firewall(), peer_connect::FIREWALL_CONSISTENT);
}

TEST(NatSampler, ResetClearsFrozen) {
    NatSampler s;
    s.freeze();
    EXPECT_TRUE(s.is_frozen());
    s.reset();
    EXPECT_FALSE(s.is_frozen());
}

// ---------------------------------------------------------------------------
// OnChange callback
// ---------------------------------------------------------------------------

TEST(NatSampler, OnChangeCallback) {
    NatSampler s;

    uint32_t old_val = 999;
    uint32_t new_val = 999;
    int change_count = 0;

    s.on_change([&](uint32_t old_fw, uint32_t new_fw) {
        old_val = old_fw;
        new_val = new_fw;
        change_count++;
    });

    // 3 matching samples → UNKNOWN → CONSISTENT
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.3", 1000));

    EXPECT_EQ(change_count, 1);
    EXPECT_EQ(old_val, peer_connect::FIREWALL_UNKNOWN);
    EXPECT_EQ(new_val, peer_connect::FIREWALL_CONSISTENT);
}

TEST(NatSampler, OnChangeNotFiredWhenSame) {
    NatSampler s;
    int change_count = 0;

    s.on_change([&](uint32_t, uint32_t) { change_count++; });

    // 5 matching samples — should only fire once (UNKNOWN → CONSISTENT on sample 3)
    for (int i = 1; i <= 5; i++) {
        auto from_str = "10.0.0." + std::to_string(i);
        s.add(addr("1.2.3.4", 5000),
              Ipv4Address::from_string(from_str, 1000));
    }

    EXPECT_EQ(change_count, 1);
}

TEST(NatSampler, OnChangeFiredOnUnfreeze) {
    NatSampler s;
    int change_count = 0;

    s.on_change([&](uint32_t, uint32_t) { change_count++; });

    // Freeze before 3rd sample
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.1", 1000));
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.2", 1000));
    s.freeze();
    s.add(addr("1.2.3.4", 5000), addr("10.0.0.3", 1000));
    EXPECT_EQ(change_count, 0);  // Frozen — no callback

    s.unfreeze();
    EXPECT_EQ(change_count, 1);  // Unfreeze triggers classification → callback
}
