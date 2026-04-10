// RAII libudx wrapper implementations — constructors/destructors for
// Udx, UdxSocket and UdxStream, with thin method forwards to the C API.

#include "hyperdht/udx.hpp"

namespace hyperdht::udx {

// ---------------------------------------------------------------------------
// Udx
// ---------------------------------------------------------------------------

Udx::Udx(uv_loop_t* loop) {
    udx_init(loop, &handle_, nullptr);
}

int Udx::is_idle() const {
    return udx_is_idle(const_cast<udx_t*>(&handle_));
}

// ---------------------------------------------------------------------------
// UdxSocket
// ---------------------------------------------------------------------------

UdxSocket::UdxSocket(Udx& udx, udx_socket_close_cb close_cb) {
    udx_socket_init(udx.handle(), &handle_, close_cb);
}

int UdxSocket::bind(const struct sockaddr* addr, unsigned int flags) {
    return udx_socket_bind(&handle_, addr, flags);
}

int UdxSocket::recv_start(udx_socket_recv_cb cb) {
    return udx_socket_recv_start(&handle_, cb);
}

int UdxSocket::send(udx_socket_send_t* req, const uv_buf_t bufs[],
                    unsigned int nbufs, const struct sockaddr* dest,
                    udx_socket_send_cb cb) {
    return udx_socket_send(req, &handle_, bufs, nbufs, dest, cb);
}

int UdxSocket::close() {
    return udx_socket_close(&handle_);
}

int UdxSocket::getsockname(struct sockaddr* name, int* name_len) {
    return udx_socket_getsockname(&handle_, name, name_len);
}

// ---------------------------------------------------------------------------
// UdxStream
// ---------------------------------------------------------------------------

UdxStream::UdxStream(Udx& udx, uint32_t local_id,
                     udx_stream_close_cb close_cb,
                     udx_stream_finalize_cb finalize_cb) {
    udx_stream_init(udx.handle(), &handle_, local_id, close_cb, finalize_cb);
}

int UdxStream::connect(UdxSocket& socket, uint32_t remote_id,
                       const struct sockaddr* addr) {
    return udx_stream_connect(&handle_, socket.handle(), remote_id, addr);
}

int UdxStream::firewall(udx_stream_firewall_cb cb) {
    return udx_stream_firewall(&handle_, cb);
}

int UdxStream::read_start(udx_stream_read_cb cb) {
    return udx_stream_read_start(&handle_, cb);
}

int UdxStream::recv_start(udx_stream_recv_cb cb) {
    return udx_stream_recv_start(&handle_, cb);
}

int UdxStream::write(udx_stream_write_t* req, const uv_buf_t bufs[],
                     unsigned int nbufs, udx_stream_ack_cb cb) {
    return udx_stream_write(req, &handle_, bufs, nbufs, cb);
}

int UdxStream::write_end(udx_stream_write_t* req, const uv_buf_t bufs[],
                         unsigned int nbufs, udx_stream_ack_cb cb) {
    return udx_stream_write_end(req, &handle_, bufs, nbufs, cb);
}

int UdxStream::send(udx_stream_send_t* req, const uv_buf_t bufs[],
                    unsigned int nbufs, udx_stream_send_cb cb) {
    return udx_stream_send(req, &handle_, bufs, nbufs, cb);
}

int UdxStream::destroy() {
    return udx_stream_destroy(&handle_);
}

int UdxStream::relay_to(UdxStream& dest) {
    return udx_stream_relay_to(&handle_, dest.handle());
}

}  // namespace hyperdht::udx
