#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/dht_ops.hpp"
#include "hyperdht/dht_messages.hpp"

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

TEST(DhtOps, FindPeerFiltersMalformedRecordsWithoutLosingClosestNodes) {
    uv_loop_t loop;
    ASSERT_EQ(uv_loop_init(&loop), 0);
    NodeId id{};
    id.fill(0x42);
    RpcSocket client(&loop, id), relay(&loop, id);
    ASSERT_EQ(client.bind(0), 0);
    ASSERT_EQ(relay.bind(0), 0);
    const auto addr = compact::Ipv4Address::from_string("127.0.0.1", relay.port());
    Node node;
    node.id = compute_peer_id(addr);
    node.host = addr.host_string();
    node.port = addr.port;
    client.table().add(node);  // Keep this walk entirely on loopback.

    dht_messages::PeerRecord peer;
    peer.public_key.fill(0x55);
    const auto no_relays = dht_messages::encode_peer_record(peer);
    peer.relay_addresses.push_back(addr);
    const auto one_relay = dht_messages::encode_peer_record(peer);
    auto trailing = one_relay;
    trailing.push_back(0x99);  // JS compact-encoding permits trailing bytes.
    auto short_relay = one_relay;
    short_relay.pop_back();
    auto bad_count = no_relays;
    bad_count.back() = 0xfd;  // Truncated uint16 relay count.
    auto oversized = std::vector<uint8_t>(32, 0x55);
    oversized.insert(oversized.end(), {0xfd, 0x01, 0x10});  // 4097 relays.
    const std::vector<std::pair<std::optional<std::vector<uint8_t>>, bool>> cases = {
        {std::nullopt, false}, {std::vector<uint8_t>{}, false},
        {std::vector<uint8_t>{0x01}, false},
        {std::vector<uint8_t>(32, 0x55), false}, {short_relay, false},
        {bad_count, false}, {oversized, false},
        {no_relays, true}, {one_relay, true}, {trailing, true}
    };

    for (size_t i = 0; i < cases.size(); ++i) {
        SCOPED_TRACE(i);
        relay.on_request([&](const messages::Request& req) {
            messages::Response resp;
            resp.tid = req.tid;
            resp.from.addr = req.from.addr;
            resp.id = node.id;
            resp.value = cases[i].first;
            relay.reply(resp, req.from_server);
        });
        bool done = false;
        size_t delivered = 0, closest_count = 0;
        auto q = find_peer(client, peer.public_key,
            [&](const QueryReply& reply) {
                ++delivered;
                EXPECT_EQ(reply.value, cases[i].first);
            },
            [&](int error, const std::vector<QueryReply>& closest) {
                EXPECT_EQ(error, QUERY_OK);
                closest_count = closest.size();
                done = true;
            });
        const auto deadline = uv_hrtime() + 2000000000ULL;
        while (!done && uv_hrtime() < deadline) {
            uv_run(&loop, UV_RUN_NOWAIT);
            uv_sleep(1);
        }
        EXPECT_TRUE(done);
        EXPECT_EQ(delivered, cases[i].second ? 1u : 0u);
        EXPECT_EQ(closest_count, 1u);
        q->destroy();
    }
    client.close();
    relay.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    EXPECT_EQ(uv_loop_close(&loop), 0);
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
        [&](int /*error*/, const std::vector<QueryReply>& closest) {
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
        EXPECT_GE(q->closest_replies().size(), 3u) << "Should get routing replies";
        EXPECT_EQ(replies, 0u) << "An unknown key should yield no decoded peer records";
    } else {
        GTEST_SKIP() << "Network unreachable";
    }

    // q is a shared_ptr, automatically cleaned up
    uv_loop_close(&loop);
}
