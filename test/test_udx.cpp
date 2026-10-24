#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include "hyperdht/udx.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/holepunch.hpp"

using namespace hyperdht::udx;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static struct sockaddr_in loopback_addr(uint16_t port) {
    struct sockaddr_in addr{};
    uv_ip4_addr("127.0.0.1", port, &addr);
    return addr;
}

static struct sockaddr_in get_bound_addr(UdxSocket& sock) {
    struct sockaddr_in addr{};
    int len = sizeof(addr);
    sock.getsockname(reinterpret_cast<struct sockaddr*>(&addr), &len);
    return addr;
}

// ---------------------------------------------------------------------------
// Init and bind test
// ---------------------------------------------------------------------------

TEST(UdxInit, SocketBindAndClose) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    Udx udx(&loop);
    UdxSocket sock(udx);

    auto addr = loopback_addr(0);
    int rc = sock.bind(reinterpret_cast<const struct sockaddr*>(&addr));
    ASSERT_EQ(rc, 0);

    auto bound = get_bound_addr(sock);
    EXPECT_NE(ntohs(bound.sin_port), 0);
    EXPECT_EQ(bound.sin_family, AF_INET);

    sock.close();

    // Run the loop to drain close callbacks while udx/sock are still alive
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

TEST(UdxClose, RpcCloseDrainsStreamsBeforeOwnerIsFreed) {
    uv_loop_t loop;
    ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        hyperdht::rpc::RpcSocket rpc(&loop, {});
        ASSERT_EQ(rpc.bind(0, "127.0.0.1"), 0);
        int finalized = 0;
        udx_stream_t attached{}, detached{};
        for (auto* stream : {&attached, &detached}) {
            ASSERT_EQ(udx_stream_init(rpc.udx_handle(), stream,
                stream == &attached ? 1 : 2, nullptr,
                [](udx_stream_t* s) { ++*static_cast<int*>(s->data); }), 0);
            stream->data = &finalized;
        }
        auto remote = loopback_addr(rpc.port());
        ASSERT_EQ(udx_stream_connect(&attached, rpc.socket_handle(), 3,
            reinterpret_cast<const sockaddr*>(&remote)), 0);

        rpc.close();
        rpc.close();
        for (int i = 0; i < 50 && finalized != 2; ++i) {
            uv_run(&loop, UV_RUN_NOWAIT);
            uv_sleep(1);
        }
        EXPECT_EQ(finalized, 2);
        EXPECT_TRUE(udx_is_idle(rpc.udx_handle()));

        // Keep the failing implementation's cleanup safe and bounded too.
        for (auto* stream : {&attached, &detached}) destroy_stream_once(stream);
        for (auto* socket : {rpc.client_socket_handle(), rpc.socket_handle()}) {
            if (!(socket->status & UDX_SOCKET_CLOSED)) udx_socket_close(socket);
        }
        uv_run(&loop, UV_RUN_DEFAULT);
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

TEST(UdxClose, InterfaceCloseCallbackCanDeleteItsHandle) {
    uv_loop_t loop;
    ASSERT_EQ(uv_loop_init(&loop), 0);
    Udx udx(&loop);
    bool closed = false;
    auto* watcher = new udx_interface_event_t{};
    ASSERT_EQ(udx_interface_event_init(udx.handle(), watcher,
        [](udx_interface_event_t* handle) {
            *static_cast<bool*>(handle->data) = true;
            delete handle;
        }), 0);
    watcher->data = &closed;
    udx_teardown(udx.handle());
    uv_run(&loop, UV_RUN_DEFAULT);
    EXPECT_TRUE(closed);
    EXPECT_TRUE(udx_is_idle(udx.handle()));
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

TEST(UdxClose, StreamCloseCallbackCanCloseItsSocket) {
    uv_loop_t loop;
    ASSERT_EQ(uv_loop_init(&loop), 0);
    Udx udx(&loop);
    UdxSocket socket(udx);
    auto address = loopback_addr(0);
    ASSERT_EQ(socket.bind(reinterpret_cast<const sockaddr*>(&address)), 0);
    address = get_bound_addr(socket);
    UdxStream stream(udx, 1, [](udx_stream_t* s, int) {
        EXPECT_EQ(static_cast<UdxSocket*>(s->data)->close(), 0);
    }, nullptr);
    stream.handle()->data = &socket;
    ASSERT_EQ(stream.connect(socket, 2, reinterpret_cast<const sockaddr*>(&address)), 0);
    udx_teardown(udx.handle());
    uv_run(&loop, UV_RUN_DEFAULT);
    EXPECT_TRUE(udx_is_idle(udx.handle()));
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

TEST(UdxClose, RpcCloseDoesNotRepeatAnInProgressDestroy) {
    uv_loop_t loop;
    ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        hyperdht::rpc::RpcSocket rpc(&loop, {});
        ASSERT_EQ(rpc.bind(0, "127.0.0.1"), 0);
        udx_stream_t stream{};
        ASSERT_EQ(udx_stream_init(rpc.udx_handle(), &stream, 1, nullptr, nullptr), 0);
        auto remote = loopback_addr(rpc.port());
        ASSERT_EQ(udx_stream_connect(&stream, rpc.socket_handle(), 2,
            reinterpret_cast<const sockaddr*>(&remote)), 0);
        // This is the state while libuv still owes a queued destroy-send callback.
        stream.status |= UDX_STREAM_DESTROYING;
        rpc.close();
        udx_teardown(rpc.udx_handle());
        EXPECT_FALSE(stream.status & UDX_STREAM_CLOSED);
        // Finish the simulated pending destroy while its owner is still alive.
        stream.status &= ~UDX_STREAM_DESTROYING;
        destroy_stream_once(&stream);
        uv_run(&loop, UV_RUN_DEFAULT);
        EXPECT_TRUE(udx_is_idle(rpc.udx_handle()));
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

TEST(UdxClose, UdxTeardownCancelsPoolRetriesBeforeFreeingSocket) {
    uv_loop_t loop;
    ASSERT_EQ(uv_loop_init(&loop), 0);
    Udx udx(&loop);
    hyperdht::holepunch::PoolSocket pool(&loop, udx.handle());
    ASSERT_EQ(pool.bind(), 0);
    sockaddr_in address{};
    int len = sizeof(address);
    ASSERT_EQ(udx_socket_getsockname(pool.socket_handle(),
        reinterpret_cast<sockaddr*>(&address), &len), 0);
    hyperdht::messages::Request request;
    request.internal = true;
    request.command = hyperdht::messages::CMD_PING;
    request.to.addr = hyperdht::compact::Ipv4Address::from_string(
        "127.0.0.1", ntohs(address.sin_port));
    pool.request(request, [](const auto&) { ADD_FAILURE(); });
    udx_teardown(udx.handle());
    uv_run(&loop, UV_RUN_DEFAULT);
    EXPECT_TRUE(pool.is_closing());
    EXPECT_FALSE(pool.is_bound());
    EXPECT_EQ(pool.socket_handle(), nullptr);
    EXPECT_TRUE(udx_is_idle(udx.handle()));
    pool.send_probe(request.to.addr);
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

// ---------------------------------------------------------------------------
// Loopback stream test — context and callbacks
// ---------------------------------------------------------------------------

struct LoopbackCtx {
    // Flags verified after the loop exits
    bool read_called = false;
    bool eof_received = false;
    std::string received_data;

    // Raw pointers for use in C callbacks (not owned)
    UdxSocket* sock1 = nullptr;
    UdxSocket* sock2 = nullptr;
    int streams_closed = 0;
};

static void on_stream_close(udx_stream_t* stream, int) {
    auto* ctx = static_cast<LoopbackCtx*>(stream->data);
    ctx->streams_closed++;

    // Both streams closed — now close the sockets so the loop can exit
    if (ctx->streams_closed == 2) {
        ctx->sock1->close();
        ctx->sock2->close();
    }
}

static void on_read(udx_stream_t* stream, ssize_t read_len, const uv_buf_t* buf) {
    auto* ctx = static_cast<LoopbackCtx*>(stream->data);

    if (read_len == UV_EOF) {
        ctx->eof_received = true;
        return;
    }
    if (read_len < 0) return;  // error — ignore

    ctx->read_called = true;
    ctx->received_data.append(buf->base, static_cast<size_t>(read_len));
}

TEST(UdxStream, LoopbackWriteRead) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    Udx udx(&loop);

    // Create and bind two sockets to OS-assigned ports
    UdxSocket sock1(udx);
    UdxSocket sock2(udx);

    auto addr1_in = loopback_addr(0);
    auto addr2_in = loopback_addr(0);

    ASSERT_EQ(sock1.bind(reinterpret_cast<const struct sockaddr*>(&addr1_in)), 0);
    ASSERT_EQ(sock2.bind(reinterpret_cast<const struct sockaddr*>(&addr2_in)), 0);

    auto bound1 = get_bound_addr(sock1);
    auto bound2 = get_bound_addr(sock2);

    // Create two streams — on_close fires when both ends finish
    UdxStream stream1(udx, 1, on_stream_close, nullptr);
    UdxStream stream2(udx, 2, on_stream_close, nullptr);

    // Set up shared context on both streams
    LoopbackCtx ctx;
    ctx.sock1 = &sock1;
    ctx.sock2 = &sock2;
    stream1.handle()->data = &ctx;
    stream2.handle()->data = &ctx;

    // Connect streams: stream1 → sock1, targets stream2's address/id
    ASSERT_EQ(stream1.connect(sock1, 2,
              reinterpret_cast<const struct sockaddr*>(&bound2)), 0);
    ASSERT_EQ(stream2.connect(sock2, 1,
              reinterpret_cast<const struct sockaddr*>(&bound1)), 0);

    // Start reading on stream 1 (the receiver side)
    stream1.read_start(on_read);

    // Write "hello udx" from stream 2 and signal end of writes
    const std::string msg = "hello udx";
    uv_buf_t buf = uv_buf_init(const_cast<char*>(msg.data()),
                                static_cast<unsigned int>(msg.size()));

    auto* write_req = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
    // write/write_end return 0 (backpressure) or 1 (drained), negative on error
    int rc = udx_stream_write(&(*write_req), stream2.handle(), &buf, 1, nullptr);
    ASSERT_GE(rc, 0);

    // Both sides must call write_end so the streams can fully close
    auto* end_req1 = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
    auto* end_req2 = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));

    ASSERT_GE(stream1.write_end(end_req1, nullptr, 0, nullptr), 0);
    ASSERT_GE(stream2.write_end(end_req2, nullptr, 0, nullptr), 0);

    // Run the event loop — exits when both streams close + sockets close
    int e = uv_run(&loop, UV_RUN_DEFAULT);
    ASSERT_EQ(e, 0);

    // Verify the read callback received the correct data
    EXPECT_TRUE(ctx.read_called);
    EXPECT_TRUE(ctx.eof_received);
    EXPECT_EQ(ctx.received_data, "hello udx");
    EXPECT_EQ(ctx.streams_closed, 2);

    free(write_req);
    free(end_req1);
    free(end_req2);

    e = uv_loop_close(&loop);
    ASSERT_EQ(e, 0);
}
