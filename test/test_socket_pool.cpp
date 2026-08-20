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

// h-6: JS socket-pool.js:79-91 gc's a route when its socket closes
// (`socket.on('close', gc)`). C++ had no hook — get_route() handed back a dead
// socket forever. Closing the socket must drop the route.
TEST_F(SocketPoolTest, RouteGcOnSocketClose) {
    SocketPool pool(&loop_, &udx_);

    std::array<uint8_t, 32> pk{};
    pk.fill(0xAB);
    auto addr = compact::Ipv4Address::from_string("10.0.0.1", 4242);

    auto* ref = pool.acquire();
    pool.add_route(pk, ref->socket(), addr);
    ASSERT_NE(pool.get_route(pk), nullptr);

    // Close the socket → SocketPool::remove() must gc the route.
    ref->release();
    run_loop();

    EXPECT_EQ(pool.get_route(pk), nullptr)
        << "route must be gc'd when its socket closes";

    pool.destroy();
    run_loop();
}

// h-6: JS socket-pool.js:96-100 — a rawStream error marks its socket
// non-reusable and gc's the route so it is never handed out again.
TEST_F(SocketPoolTest, RouteGcOnStreamError) {
    SocketPool pool(&loop_, &udx_);

    std::array<uint8_t, 32> pk{};
    pk.fill(0xCD);
    auto addr = compact::Ipv4Address::from_string("10.0.0.2", 5252);

    auto* ref = pool.acquire();
    pool.add_route(pk, ref->socket(), addr);  // sets reusable = true
    ASSERT_NE(pool.get_route(pk), nullptr);
    EXPECT_TRUE(ref->reusable);

    pool.on_stream_error(ref->socket());

    EXPECT_EQ(pool.get_route(pk), nullptr) << "stream error must gc the route";
    EXPECT_FALSE(ref->reusable) << "stream error must mark socket non-reusable";

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

// A holder that still carries an adopted stream cannot close: udx returns
// UV_EBUSY (udx.c:2175). Flagging it closed anyway is the dangerous half —
// on_socket_close never fires, so remove() never runs, and destroy() then skips
// the ref without nulling socket_.data, leaving one late datagram able to reach
// a SocketRef whose pool is gone. The ref must stay guarded and closeable.
TEST_F(SocketPoolTest, BusyCloseLeavesRefOpenAndGuarded) {
    SocketPool pool(&loop_, &udx_);
    auto* ref = pool.acquire();
    ASSERT_NE(ref, nullptr);

    udx_stream_t stream{};
    ASSERT_EQ(udx_stream_init(&udx_, &stream, 7777,
                              [](udx_stream_t*, int) {}, nullptr), 0);
    struct sockaddr_in dest{};
    uv_ip4_addr("127.0.0.1", 12345, &dest);
    ASSERT_EQ(udx_stream_connect(&stream, ref->socket(), 1,
                                 reinterpret_cast<const struct sockaddr*>(&dest)),
              0);

    uint64_t before = hyperdht::udx::busy_close_count();
    ref->release();  // refs → 0 → do_close()

    EXPECT_EQ(hyperdht::udx::busy_close_count(), before + 1);
    EXPECT_FALSE(ref->is_closed()) << "ref claims closed while udx refused";
    EXPECT_EQ(pool.lookup(ref->socket()), ref) << "ref must stay registered";
    EXPECT_EQ(ref->socket()->data, static_cast<void*>(ref))
        << "still routable, so still guarded";

    // Stream gone → the next close attempt succeeds: the refusal is not
    // sticky, which is what makes "no retry timer" an acceptable policy.
    // (A bounded pump, not run_loop(): UV_RUN_DEFAULT cannot return while the
    // socket this test deliberately left open still holds the loop.)
    hyperdht::udx::destroy_stream_once(&stream);
    for (int i = 0; i < 50 && ref->socket()->streams != nullptr; i++) {
        uv_run(&loop_, UV_RUN_NOWAIT);
    }
    ASSERT_EQ(ref->socket()->streams, nullptr) << "stream never detached";

    ref->active();
    ref->inactive();  // refs → 0 again → do_close() retries
    EXPECT_TRUE(ref->is_closed());

    run_loop();  // close callback → pool.remove() → ref deleted; don't touch it
    EXPECT_EQ(pool.size(), 0u);
    pool.destroy();
}

// `SocketPool::destroy()` used an UNCHECKED `udx_socket_close`, so a refusal
// (UV_EBUSY, i.e. a stream is still attached) was swallowed whole: no counter,
// and in a Release build no log either. It must go through the checked close.
//
// It must NOT also copy the other half of `SocketRef::do_close` and leave
// `closed_` false so the next `inactive()` retries. A ref that survives
// destroy() outlives the udx_t too — `udx_t` is a value member of RpcSocket
// and HyperDHT declares `socket_` before `socket_pool_`, so the pool is torn
// down first and the udx_t dies moments later in the same destructor. That
// retry would be `udx_socket_close` on freed memory. Destroy reports the
// refusal and then disarms the ref permanently.
TEST_F(SocketPoolTest, DestroyCountsBusyRefusalAndDisarmsRef) {
    SocketPool pool(&loop_, &udx_);
    auto* ref = pool.acquire();
    ASSERT_NE(ref, nullptr);
    // The dangerous shape: a route made this ref reusable, so any later
    // do_close would take the linger branch into the dead pool.
    ref->reusable = true;

    udx_stream_t stream{};
    ASSERT_EQ(udx_stream_init(&udx_, &stream, 7778,
                              [](udx_stream_t*, int) {}, nullptr), 0);
    struct sockaddr_in dest{};
    uv_ip4_addr("127.0.0.1", 12346, &dest);
    ASSERT_EQ(udx_stream_connect(&stream, ref->socket(), 1,
                                 reinterpret_cast<const struct sockaddr*>(&dest)),
              0);

    uint64_t before = hyperdht::udx::busy_close_count();
    pool.destroy();
    EXPECT_EQ(hyperdht::udx::busy_close_count(), before + 1)
        << "destroy must use the checked close so the refusal is counted";
    EXPECT_TRUE(ref->is_closed())
        << "a ref that outlives the udx_t must never retry its close";
    EXPECT_FALSE(ref->reusable)
        << "a ref outliving its pool must never try to linger";

    // The adopted stream's owner finally lets go. Every remaining ref-count
    // path must now be inert — none of them may reach udx_socket_close.
    hyperdht::udx::destroy_stream_once(&stream);
    for (int i = 0; i < 50 && ref->socket()->streams != nullptr; i++) {
        uv_run(&loop_, UV_RUN_NOWAIT);
    }
    ASSERT_EQ(ref->socket()->streams, nullptr) << "stream never detached";
    ref->release();      // refs → 0 → close_maybe() → must stay a no-op
    ref->active();
    ref->inactive();     // the keepalive-deleter path, same requirement

    // The fd really is parked — that is the documented price of the refusal,
    // and only an explicit close reclaims it. Doing it here is also what lets
    // the fixture's UV_RUN_DEFAULT drain.
    udx_socket_close(ref->socket());
    for (int i = 0; i < 200; i++) uv_run(&loop_, UV_RUN_NOWAIT);
    // destroy() deliberately never deletes refs (outstanding keepalives may
    // still call inactive() on them), and socket_.data was nulled, so
    // on_socket_close skipped remove(). This orphan is ours to reap.
    delete ref;
}

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
