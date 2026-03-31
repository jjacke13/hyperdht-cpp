#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/dht_ops.hpp"

using namespace hyperdht;
using namespace hyperdht::dht_ops;
using namespace hyperdht::rpc;
using namespace hyperdht::routing;
using namespace hyperdht::query;

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; i++) {
        out.push_back(h[data[i] >> 4]);
        out.push_back(h[data[i] & 0x0F]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Test: hash_public_key matches JS
// ---------------------------------------------------------------------------

TEST(DhtOps, HashPublicKey) {
    // Verify our hash matches JS: hash = BLAKE2b-256(pubkey)
    std::array<uint8_t, 32> pk{};
    pk.fill(0x42);
    auto target = hash_public_key(pk.data(), pk.size());

    // Compute expected with raw libsodium
    uint8_t expected[32];
    crypto_generichash(expected, 32, pk.data(), 32, nullptr, 0);
    EXPECT_EQ(std::memcmp(target.data(), expected, 32), 0);
}

// ---------------------------------------------------------------------------
// Test: findPeer on live network with a random key (should find no peers
// but should still complete the iterative walk)
// ---------------------------------------------------------------------------

TEST(DhtOps, FindPeerRandomKey) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    NodeId our_id{};
    our_id.fill(0x42);
    RpcSocket rpc(&loop, our_id);
    rpc.bind(0);

    // Random public key — unlikely to have any announcements
    std::array<uint8_t, 32> random_pk{};
    random_pk.fill(0xDE);

    bool done = false;
    size_t replies = 0;
    size_t values_found = 0;

    auto q = find_peer(rpc, random_pk,
        [&](const QueryReply& reply) {
            replies++;
            if (reply.value.has_value() && !reply.value->empty()) {
                values_found++;
            }
        },
        [&](const std::vector<QueryReply>& closest) {
            done = true;
            rpc.close();
        });

    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &rpc;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* r = static_cast<RpcSocket*>(t->data);
        r->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 15000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    if (done) {
        printf("  findPeer completed: %zu replies, %zu values\n", replies, values_found);
        EXPECT_GE(replies, 3u) << "Should get replies from iterative walk";
    } else {
        GTEST_SKIP() << "Network unreachable";
    }

    // q is a shared_ptr, automatically cleaned up
    uv_loop_close(&loop);
}
