#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <udx.h>

#include "hyperdht/udx.hpp"

using namespace hyperdht::udx;

// ---------------------------------------------------------------------------
// UDX wire format constants (from deps/libudx/include/udx.h)
// ---------------------------------------------------------------------------

// Header layout (20 bytes):
//   [0] magic = 0xFF
//   [1] version = 0x01
//   [2] type flags (DATA=0x01, END=0x02, SACK=0x04, MESSAGE=0x08, ...)
//   [3] data_offset
//   [4..7] stream_id (LE)
//   [8..11] recv_window (LE)
//   [12..15] seq (LE)
//   [16..19] ack (LE)

// ---------------------------------------------------------------------------
// Captured packet
// ---------------------------------------------------------------------------

struct CapturedPacket {
    std::vector<uint8_t> data;
    struct sockaddr_in from;
    struct sockaddr_in to_addr;  // which side received it
};

// ---------------------------------------------------------------------------
// Proxy context — sits between two UDX sockets, forwarding and capturing
// ---------------------------------------------------------------------------

struct ProxyCtx {
    uv_udp_t proxy;
    struct sockaddr_in addr_a;  // UDX socket A's address
    struct sockaddr_in addr_b;  // UDX socket B's address
    std::vector<CapturedPacket> packets;
};

static struct sockaddr_in make_addr(uint16_t port) {
    struct sockaddr_in addr{};
    uv_ip4_addr("127.0.0.1", port, &addr);
    return addr;
}

static uint16_t addr_port(const struct sockaddr_in& addr) {
    return ntohs(addr.sin_port);
}

static uint16_t get_bound_port(uv_udp_t* handle) {
    struct sockaddr_in addr{};
    int len = sizeof(addr);
    uv_udp_getsockname(handle, reinterpret_cast<struct sockaddr*>(&addr), &len);
    return ntohs(addr.sin_port);
}

static uint16_t get_sock_port(UdxSocket& sock) {
    struct sockaddr_in addr{};
    int len = sizeof(addr);
    sock.getsockname(reinterpret_cast<struct sockaddr*>(&addr), &len);
    return ntohs(addr.sin_port);
}

// ---------------------------------------------------------------------------
// Proxy callbacks
// ---------------------------------------------------------------------------

static void on_proxy_alloc(uv_handle_t*, size_t suggested, uv_buf_t* buf) {
    buf->base = new char[suggested];
    buf->len = static_cast<unsigned int>(suggested);
}

struct ProxySend {
    uv_udp_send_t req;
    char* buf;
};

static void on_proxy_send_done(uv_udp_send_t* req, int) {
    auto* ps = reinterpret_cast<ProxySend*>(req);
    delete[] ps->buf;
    delete ps;
}

static void on_proxy_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                           const struct sockaddr* addr, unsigned) {
    auto* ctx = static_cast<ProxyCtx*>(handle->data);

    if (nread > 0 && addr != nullptr) {
        auto* from = reinterpret_cast<const struct sockaddr_in*>(addr);

        // Capture the raw packet
        CapturedPacket pkt;
        pkt.data.assign(reinterpret_cast<uint8_t*>(buf->base),
                        reinterpret_cast<uint8_t*>(buf->base) + nread);
        pkt.from = *from;
        ctx->packets.push_back(pkt);

        // Forward: if from A's port → send to B, and vice versa
        const struct sockaddr* dest = nullptr;
        if (addr_port(*from) == addr_port(ctx->addr_a)) {
            dest = reinterpret_cast<const struct sockaddr*>(&ctx->addr_b);
        } else if (addr_port(*from) == addr_port(ctx->addr_b)) {
            dest = reinterpret_cast<const struct sockaddr*>(&ctx->addr_a);
        }

        if (dest) {
            // Copy the buffer — uv_udp_send does NOT copy, and on_proxy_recv
            // returns before the send completes. ProxySend owns the copy.
            auto* ps = new ProxySend;
            ps->buf = new char[nread];
            memcpy(ps->buf, buf->base, static_cast<size_t>(nread));
            uv_buf_t fwd_buf = uv_buf_init(ps->buf, static_cast<unsigned int>(nread));
            uv_udp_send(&ps->req, handle, &fwd_buf, 1, dest, on_proxy_send_done);
        }
    }

    delete[] buf->base;
}

// ---------------------------------------------------------------------------
// Stream context
// ---------------------------------------------------------------------------

struct StreamCtx {
    bool read_called = false;
    bool eof_received = false;
    std::string received_data;
    UdxSocket* sock1 = nullptr;
    UdxSocket* sock2 = nullptr;
    ProxyCtx* proxy_ctx = nullptr;
    int streams_closed = 0;
};

static void on_stream_close(udx_stream_t* stream, int) {
    auto* ctx = static_cast<StreamCtx*>(stream->data);
    ctx->streams_closed++;

    if (ctx->streams_closed == 2) {
        ctx->sock1->close();
        ctx->sock2->close();
        uv_udp_recv_stop(&ctx->proxy_ctx->proxy);
        uv_close(reinterpret_cast<uv_handle_t*>(&ctx->proxy_ctx->proxy), nullptr);
    }
}

static void on_read(udx_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<StreamCtx*>(stream->data);

    if (nread == UV_EOF) {
        ctx->eof_received = true;
        return;
    }
    if (nread < 0) return;

    ctx->read_called = true;
    ctx->received_data.append(buf->base, static_cast<size_t>(nread));
}

// ---------------------------------------------------------------------------
// Test: capture raw UDP packets through a proxy
// ---------------------------------------------------------------------------

TEST(UdxPacketCapture, ProxyCapture) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    Udx udx(&loop);

    // Two UDX sockets — but they'll talk through the proxy, not directly
    UdxSocket sock1(udx);
    UdxSocket sock2(udx);

    auto bind1 = make_addr(0);
    auto bind2 = make_addr(0);
    ASSERT_EQ(sock1.bind(reinterpret_cast<const struct sockaddr*>(&bind1)), 0);
    ASSERT_EQ(sock2.bind(reinterpret_cast<const struct sockaddr*>(&bind2)), 0);

    uint16_t port1 = get_sock_port(sock1);
    uint16_t port2 = get_sock_port(sock2);

    // Set up the UDP proxy
    ProxyCtx proxy_ctx{};
    uv_udp_init(&loop, &proxy_ctx.proxy);
    auto proxy_bind = make_addr(0);
    uv_udp_bind(&proxy_ctx.proxy, reinterpret_cast<const struct sockaddr*>(&proxy_bind), 0);
    uint16_t proxy_port = get_bound_port(&proxy_ctx.proxy);

    proxy_ctx.addr_a = make_addr(port1);
    proxy_ctx.addr_b = make_addr(port2);
    proxy_ctx.proxy.data = &proxy_ctx;

    uv_udp_recv_start(&proxy_ctx.proxy, on_proxy_alloc, on_proxy_recv);

    // Streams: stream1 (ID=1) on sock1, stream2 (ID=2) on sock2
    // Both connect through the proxy instead of directly to each other
    UdxStream stream1(udx, 1, on_stream_close, nullptr);
    UdxStream stream2(udx, 2, on_stream_close, nullptr);

    StreamCtx ctx;
    ctx.sock1 = &sock1;
    ctx.sock2 = &sock2;
    ctx.proxy_ctx = &proxy_ctx;
    stream1.handle()->data = &ctx;
    stream2.handle()->data = &ctx;

    // stream1 connects to proxy (targeting stream2's ID=2)
    auto proxy_addr = make_addr(proxy_port);
    ASSERT_EQ(stream1.connect(sock1, 2,
              reinterpret_cast<const struct sockaddr*>(&proxy_addr)), 0);
    // stream2 connects to proxy (targeting stream1's ID=1)
    ASSERT_EQ(stream2.connect(sock2, 1,
              reinterpret_cast<const struct sockaddr*>(&proxy_addr)), 0);

    // Read on stream1 (receiver)
    stream1.read_start(on_read);

    // Write "hello-wire" from stream2
    const std::string msg = "hello-wire";
    uv_buf_t buf = uv_buf_init(const_cast<char*>(msg.data()),
                                static_cast<unsigned int>(msg.size()));

    auto* write_req = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
    ASSERT_GE(udx_stream_write(write_req, stream2.handle(), &buf, 1, nullptr), 0);

    // Both sides write_end so streams can close
    auto* end1 = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
    auto* end2 = static_cast<udx_stream_write_t*>(
        malloc(static_cast<size_t>(udx_stream_write_sizeof(1))));
    ASSERT_GE(stream1.write_end(end1, nullptr, 0, nullptr), 0);
    ASSERT_GE(stream2.write_end(end2, nullptr, 0, nullptr), 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    // --- Verify the data got through ---
    EXPECT_TRUE(ctx.read_called);
    EXPECT_TRUE(ctx.eof_received);
    EXPECT_EQ(ctx.received_data, "hello-wire");
    EXPECT_EQ(ctx.streams_closed, 2);

    // --- Verify captured packets ---
    ASSERT_GE(proxy_ctx.packets.size(), 3u)
        << "Expected at least 3 packets (data + end + acks)";

    // Every packet must start with UDX magic byte and version
    for (size_t i = 0; i < proxy_ctx.packets.size(); i++) {
        const auto& pkt = proxy_ctx.packets[i];
        ASSERT_GE(pkt.data.size(), 20u)
            << "Packet " << i << " too small for UDX header";
        EXPECT_EQ(pkt.data[0], 0xFF)
            << "Packet " << i << " missing UDX magic byte";
        EXPECT_EQ(pkt.data[1], 0x01)
            << "Packet " << i << " wrong UDX version";
    }

    // At least one packet must have DATA flag (0x01) set
    bool found_data = false;
    bool found_end = false;
    bool found_payload = false;

    for (const auto& pkt : proxy_ctx.packets) {
        uint8_t type = pkt.data[2];
        if (type & 0x01) found_data = true;
        if (type & 0x02) found_end = true;

        // Check if payload bytes appear after the 20-byte header
        if (pkt.data.size() > 20) {
            std::string payload(reinterpret_cast<const char*>(pkt.data.data() + 20),
                                pkt.data.size() - 20);
            if (payload.find("hello-wire") != std::string::npos) {
                found_payload = true;
            }
        }
    }

    EXPECT_TRUE(found_data) << "No packet with DATA flag found";
    EXPECT_TRUE(found_end) << "No packet with END flag found";
    EXPECT_TRUE(found_payload) << "Payload 'hello-wire' not found in any packet";

    // Print summary for visibility
    printf("  Captured %zu UDP packets through proxy\n", proxy_ctx.packets.size());
    for (size_t i = 0; i < proxy_ctx.packets.size(); i++) {
        const auto& pkt = proxy_ctx.packets[i];
        uint8_t type = pkt.data[2];
        printf("    pkt[%zu]: %zu bytes, type=0x%02x (", i, pkt.data.size(), type);
        if (type & 0x01) printf("DATA ");
        if (type & 0x02) printf("END ");
        if (type & 0x04) printf("SACK ");
        if (type & 0x08) printf("MSG ");
        if (type & 0x20) printf("HEARTBEAT ");
        printf(") from port %u\n", addr_port(pkt.from));
    }

    free(write_req);
    free(end1);
    free(end2);

    ASSERT_EQ(uv_loop_close(&loop), 0);
}
