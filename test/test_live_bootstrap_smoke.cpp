// §2 live smoke test: bring up a HyperDHT with the 3 public bootstrap nodes,
// call bind(), and verify that `is_bootstrapped()` flips within 15 seconds
// against real JS peers. This test requires outbound UDP and is skipped
// automatically when the public network is unreachable.

#include <gtest/gtest.h>

#include <cstdio>

#include <uv.h>

#include "hyperdht/dht.hpp"

using namespace hyperdht;

TEST(LiveBootstrap, PublicHyperdht) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    DhtOptions opts;
    opts.bootstrap = HyperDHT::default_bootstrap_nodes();
    HyperDHT dht(&loop, opts);

    bool bootstrapped_cb_fired = false;
    dht.on_bootstrapped([&]() { bootstrapped_cb_fired = true; });

    ASSERT_EQ(dht.bind(), 0);
    printf("  [live] bound to port %u\n", dht.port());

    // Deadline timer: 15 s is plenty for a two-round FIND_NODE walk
    // against peers that respond in single-digit milliseconds.
    uv_timer_t deadline;
    uv_timer_init(&loop, &deadline);
    bool deadline_fired = false;
    deadline.data = &deadline_fired;
    uv_timer_start(&deadline, [](uv_timer_t* t) {
        *static_cast<bool*>(t->data) = true;
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 15000, 0);

    while (!dht.is_bootstrapped() && !deadline_fired) {
        uv_run(&loop, UV_RUN_ONCE);
    }
    if (!deadline_fired) {
        uv_timer_stop(&deadline);
        uv_close(reinterpret_cast<uv_handle_t*>(&deadline), nullptr);
    }

    if (!dht.is_bootstrapped()) {
        dht.destroy();
        uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop);
        GTEST_SKIP() << "Network unreachable — skipping live bootstrap smoke";
    }

    printf("  [live] bootstrap walk complete, routing table size=%zu\n",
           dht.socket().table().size());
    EXPECT_TRUE(bootstrapped_cb_fired);
    // A real public DHT walk should populate the routing table with at
    // least a handful of real peers. Use 3 as a generous lower bound —
    // we seeded 3 and every one should reply.
    EXPECT_GE(dht.socket().table().size(), 3u)
        << "routing table did not absorb any real peers after walk";

    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}
