#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include <uv.h>

#include "hyperdht/socket_pool.hpp"

using namespace hyperdht;
using namespace hyperdht::socket_pool;

// ---------------------------------------------------------------------------
// Test fixture — sets up libuv loop and libudx
// ---------------------------------------------------------------------------

class SocketPoolTest : public ::testing::Test {
protected:
    uv_loop_t loop_;
    udx_t udx_;

    void SetUp() override {
        uv_loop_init(&loop_);
        udx_init(&loop_, &udx_, nullptr);
    }

    void TearDown() override {
        // Run the loop briefly to process close callbacks
        uv_run(&loop_, UV_RUN_DEFAULT);
        uv_loop_close(&loop_);
    }

    // Run loop until all handles close
    void run_loop() {
        uv_run(&loop_, UV_RUN_DEFAULT);
    }
};

// ---------------------------------------------------------------------------
// SocketPool basic tests
// ---------------------------------------------------------------------------

TEST_F(SocketPoolTest, AcquireCreatesSocket) {
    SocketPool pool(&loop_, &udx_);
    EXPECT_EQ(pool.size(), 0u);

    auto* ref = pool.acquire();
    ASSERT_NE(ref, nullptr);
    EXPECT_EQ(pool.size(), 1u);
    EXPECT_FALSE(ref->is_free());
    EXPECT_FALSE(ref->is_closed());

    ref->release();
    pool.destroy();
    run_loop();
}

TEST_F(SocketPoolTest, AcquireMultiple) {
    SocketPool pool(&loop_, &udx_);

    auto* ref1 = pool.acquire();
    auto* ref2 = pool.acquire();
    auto* ref3 = pool.acquire();

    EXPECT_EQ(pool.size(), 3u);
    EXPECT_NE(ref1->socket(), ref2->socket());
    EXPECT_NE(ref2->socket(), ref3->socket());

    ref1->release();
    ref2->release();
    ref3->release();
    pool.destroy();
    run_loop();
}

TEST_F(SocketPoolTest, LookupBySocket) {
    SocketPool pool(&loop_, &udx_);

    auto* ref = pool.acquire();
    auto* found = pool.lookup(ref->socket());
    EXPECT_EQ(found, ref);

    auto* not_found = pool.lookup(nullptr);
    EXPECT_EQ(not_found, nullptr);

    ref->release();
    pool.destroy();
    run_loop();
}

TEST_F(SocketPoolTest, SetReusable) {
    SocketPool pool(&loop_, &udx_);

    auto* ref = pool.acquire();
    EXPECT_FALSE(ref->reusable);

    pool.set_reusable(ref->socket(), true);
    EXPECT_TRUE(ref->reusable);

    pool.set_reusable(ref->socket(), false);
    EXPECT_FALSE(ref->reusable);

    ref->release();
    pool.destroy();
    run_loop();
}

// ---------------------------------------------------------------------------
// Ref counting
// ---------------------------------------------------------------------------

TEST_F(SocketPoolTest, RefCounting) {
    SocketPool pool(&loop_, &udx_);

    auto* ref = pool.acquire();
    EXPECT_FALSE(ref->is_free());  // starts with refs=1

    ref->active();   // refs=2
    ref->inactive();  // refs=1
    EXPECT_FALSE(ref->is_free());

    ref->inactive();  // refs=0
    EXPECT_TRUE(ref->is_free());

    // Socket should close (not reusable, no linger)
    pool.destroy();
    run_loop();
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

TEST_F(SocketPoolTest, AddGetRoute) {
    SocketPool pool(&loop_, &udx_);

    std::array<uint8_t, 32> pk{};
    pk.fill(0xAA);
    auto addr = compact::Ipv4Address::from_string("1.2.3.4", 5000);

    auto* ref = pool.acquire();
    pool.add_route(pk, ref->socket(), addr);

    auto* route = pool.get_route(pk);
    ASSERT_NE(route, nullptr);
    EXPECT_EQ(route->socket, ref->socket());
    EXPECT_EQ(route->address.host_string(), "1.2.3.4");
    EXPECT_EQ(route->address.port, 5000);

    ref->release();
    pool.destroy();
    run_loop();
}

TEST_F(SocketPoolTest, GetRouteNotFound) {
    SocketPool pool(&loop_, &udx_);

    std::array<uint8_t, 32> pk{};
    pk.fill(0xBB);

    auto* route = pool.get_route(pk);
    EXPECT_EQ(route, nullptr);

    pool.destroy();
    run_loop();
}

TEST_F(SocketPoolTest, RemoveRoute) {
    SocketPool pool(&loop_, &udx_);

    std::array<uint8_t, 32> pk{};
    pk.fill(0xCC);
    auto addr = compact::Ipv4Address::from_string("5.6.7.8", 9000);

    auto* ref = pool.acquire();
    pool.add_route(pk, ref->socket(), addr);
    ASSERT_NE(pool.get_route(pk), nullptr);

    pool.remove_route(pk);
    EXPECT_EQ(pool.get_route(pk), nullptr);

    ref->release();
    pool.destroy();
    run_loop();
}

TEST_F(SocketPoolTest, AddRouteSetsReusable) {
    SocketPool pool(&loop_, &udx_);

    auto* ref = pool.acquire();
    EXPECT_FALSE(ref->reusable);

    std::array<uint8_t, 32> pk{};
    pk.fill(0xDD);
    pool.add_route(pk, ref->socket(),
                   compact::Ipv4Address::from_string("1.1.1.1", 80));

    EXPECT_TRUE(ref->reusable);

    ref->release();
    pool.destroy();
    run_loop();
}

// ---------------------------------------------------------------------------
// Destroy
// ---------------------------------------------------------------------------

TEST_F(SocketPoolTest, DestroyClosesAll) {
    SocketPool pool(&loop_, &udx_);

    pool.acquire();
    pool.acquire();
    pool.acquire();
    EXPECT_EQ(pool.size(), 3u);

    pool.destroy();
    run_loop();

    EXPECT_EQ(pool.size(), 0u);
}
