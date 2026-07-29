#pragma once

// RAII wrappers around libudx (udx_t, udx_socket_t, udx_stream_t).
// Owns the C handles; lifetime is tied to the wrapper objects.
// The caller owns the uv_loop_t and must outlive these wrappers.

#include <cstdint>
#include <udx.h>
#include <uv.h>

namespace hyperdht::udx {

// ---------------------------------------------------------------------------
// Udx -- RAII wrapper around udx_t
//
// Owns the udx_t instance. Caller owns the uv_loop_t and must ensure it
// outlives this object.
//
// Non-copyable, non-movable: the C struct contains internal linked-list
// pointers that become invalid on move.
// ---------------------------------------------------------------------------
class Udx {
  public:
    explicit Udx(uv_loop_t* loop);

    Udx(const Udx&) = delete;
    Udx& operator=(const Udx&) = delete;
    Udx(Udx&&) = delete;
    Udx& operator=(Udx&&) = delete;

    udx_t* handle() { return &handle_; }
    const udx_t* handle() const { return &handle_; }

    int is_idle() const;

  private:
    udx_t handle_{};
};

// ---------------------------------------------------------------------------
// UdxSocket -- RAII wrapper around udx_socket_t
//
// Constructor calls udx_socket_init. Caller must call close() before the
// socket goes out of scope (libuv async close pattern).
//
// Non-copyable, non-movable.
// ---------------------------------------------------------------------------
class UdxSocket {
  public:
    explicit UdxSocket(Udx& udx, udx_socket_close_cb close_cb = nullptr);

    UdxSocket(const UdxSocket&) = delete;
    UdxSocket& operator=(const UdxSocket&) = delete;
    UdxSocket(UdxSocket&&) = delete;
    UdxSocket& operator=(UdxSocket&&) = delete;

    int bind(const struct sockaddr* addr, unsigned int flags = 0);
    int recv_start(udx_socket_recv_cb cb);
    int send(udx_socket_send_t* req, const uv_buf_t bufs[],
             unsigned int nbufs, const struct sockaddr* dest,
             udx_socket_send_cb cb);
    int close();

    int getsockname(struct sockaddr* name, int* name_len);

    udx_socket_t* handle() { return &handle_; }
    const udx_socket_t* handle() const { return &handle_; }

  private:
    udx_socket_t handle_{};
};

// ---------------------------------------------------------------------------
// UdxStream -- RAII wrapper around udx_stream_t
//
// Constructor calls udx_stream_init. Caller must call destroy() to tear
// down the stream (libuv async pattern).
//
// Non-copyable, non-movable.
// ---------------------------------------------------------------------------
class UdxStream {
  public:
    UdxStream(Udx& udx, uint32_t local_id,
              udx_stream_close_cb close_cb,
              udx_stream_finalize_cb finalize_cb);

    UdxStream(const UdxStream&) = delete;
    UdxStream& operator=(const UdxStream&) = delete;
    UdxStream(UdxStream&&) = delete;
    UdxStream& operator=(UdxStream&&) = delete;

    int connect(UdxSocket& socket, uint32_t remote_id,
                const struct sockaddr* addr);
    int firewall(udx_stream_firewall_cb cb);
    int read_start(udx_stream_read_cb cb);
    int recv_start(udx_stream_recv_cb cb);
    int write(udx_stream_write_t* req, const uv_buf_t bufs[],
              unsigned int nbufs, udx_stream_ack_cb cb);
    int write_end(udx_stream_write_t* req, const uv_buf_t bufs[],
                  unsigned int nbufs, udx_stream_ack_cb cb);
    int send(udx_stream_send_t* req, const uv_buf_t bufs[],
             unsigned int nbufs, udx_stream_send_cb cb);
    int destroy();
    int relay_to(UdxStream& dest);

    udx_stream_t* handle() { return &handle_; }
    const udx_stream_t* handle() const { return &handle_; }

  private:
    udx_stream_t handle_{};
};

// ---------------------------------------------------------------------------
// destroy_stream_once — tear down a raw stream we own, tolerating a teardown
// that is already under way. Returns true if a destroy was actually issued.
//
// `udx_stream_destroy()` guards on UDX_STREAM_CLOSED but NEVER on
// UDX_STREAM_DESTROYING (deps/libudx/src/udx.c:2709-2720). Those are not the
// same window. On the slow send path — `uv_udp_try_send` returns UV_EAGAIN, so
// the destroy packet goes out via `uv_udp_send` — `close_stream_internal()` is
// deferred to that send's completion callback, leaving the stream
// DESTROYING-but-not-CLOSED (and still CONNECTED) for a full loop turn.
//
// A second `udx_stream_destroy()` inside that window walks straight past the
// CLOSED guard, queues a SECOND destroy packet, and ends with
// `close_stream_internal()` running twice. That function `uv_close()`s the
// stream's five timers, so the second run closes already-closing handles and
// trips libuv's `assert(!uv__is_closing(handle))`. Its own
// `assert(CLOSED == 0)` does not catch it: asserts are compiled out in Release,
// which is exactly where the field crash was seen (Finding J — SIGABRT in
// ~ConnState teardown on the connect failure path).
//
// Skipping is always semantically correct: a stream that is already
// DESTROYING or CLOSED is on its way out and will free itself through its
// finalize callback.
inline bool destroy_stream_once(udx_stream_t* stream) {
    if (stream == nullptr) return false;
    if (stream->status & (UDX_STREAM_DESTROYING | UDX_STREAM_CLOSED)) {
        return false;
    }
    udx_stream_destroy(stream);
    return true;
}

}  // namespace hyperdht::udx
