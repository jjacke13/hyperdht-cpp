#include "hyperdht/rpc.hpp"

#include <cstring>
#include <random>

namespace hyperdht {
namespace rpc {

// ---------------------------------------------------------------------------
// RpcSocket
// ---------------------------------------------------------------------------

RpcSocket::RpcSocket(uv_loop_t* loop, const routing::NodeId& local_id)
    : loop_(loop), table_(local_id) {

    udx_init(loop_, &udx_, nullptr);
    udx_socket_init(&udx_, &socket_, nullptr);
    socket_.data = this;

    // Random initial tid
    std::random_device rd;
    next_tid_ = static_cast<uint16_t>(rd() & 0xFFFF);
}

RpcSocket::~RpcSocket() = default;

int RpcSocket::bind(uint16_t port) {
    struct sockaddr_in addr{};
    uv_ip4_addr("0.0.0.0", port, &addr);
    int rc = udx_socket_bind(&socket_, reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (rc == 0) {
        socket_bound_ = true;
        // Start receiving
        udx_socket_recv_start(&socket_, on_recv);
    }
    return rc;
}

uint16_t RpcSocket::port() const {
    struct sockaddr_in addr{};
    int len = sizeof(addr);
    udx_socket_getsockname(const_cast<udx_socket_t*>(&socket_),
                           reinterpret_cast<struct sockaddr*>(&addr), &len);
    return ntohs(addr.sin_port);
}

uint16_t RpcSocket::alloc_tid() {
    uint16_t tid = next_tid_++;
    if (next_tid_ == 0) next_tid_ = 1;  // Skip 0
    return tid;
}

InflightRequest* RpcSocket::find_inflight(uint16_t tid) {
    for (auto& req : inflight_) {
        if (req.tid == tid) return &req;
    }
    return nullptr;
}

void RpcSocket::remove_inflight(uint16_t tid) {
    for (size_t i = 0; i < inflight_.size(); i++) {
        if (inflight_[i].tid == tid) {
            // Swap with last and pop (O(1) removal)
            inflight_[i] = std::move(inflight_.back());
            inflight_.pop_back();
            return;
        }
    }
}

uint16_t RpcSocket::request(const messages::Request& req,
                            OnResponseCallback on_response,
                            OnTimeoutCallback on_timeout) {
    // Build request with our tid
    messages::Request msg = req;
    msg.tid = alloc_tid();

    // Encode
    auto buf = messages::encode_request(msg);

    // Send UDP
    auto* send_req = static_cast<udx_socket_send_t*>(
        malloc(sizeof(udx_socket_send_t)));
    send_req->data = nullptr;

    // Copy buffer for send (libuv needs it alive until send completes)
    auto* send_buf = new std::vector<uint8_t>(std::move(buf));
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(send_buf->data()),
                                    static_cast<unsigned int>(send_buf->size()));

    struct sockaddr_in dest{};
    uv_ip4_addr(msg.to.addr.host_string().c_str(), msg.to.addr.port, &dest);

    udx_socket_send(send_req, &socket_, &uv_buf, 1,
                    reinterpret_cast<const struct sockaddr*>(&dest),
                    [](udx_socket_send_t* req, int) {
                        delete static_cast<std::vector<uint8_t>*>(req->data);
                        free(req);
                    });
    send_req->data = send_buf;

    // Track inflight
    InflightRequest inflight;
    inflight.tid = msg.tid;
    inflight.command = msg.command;
    inflight.on_response = std::move(on_response);
    inflight.on_timeout = std::move(on_timeout);
    inflight.to = msg.to.addr;
    inflight_.push_back(std::move(inflight));

    return msg.tid;
}

void RpcSocket::reply(const messages::Response& resp) {
    auto buf = messages::encode_response(resp);

    auto* send_req = static_cast<udx_socket_send_t*>(
        malloc(sizeof(udx_socket_send_t)));

    auto* send_buf = new std::vector<uint8_t>(std::move(buf));
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(send_buf->data()),
                                    static_cast<unsigned int>(send_buf->size()));

    struct sockaddr_in dest{};
    uv_ip4_addr(resp.from.addr.host_string().c_str(), resp.from.addr.port, &dest);

    udx_socket_send(send_req, &socket_, &uv_buf, 1,
                    reinterpret_cast<const struct sockaddr*>(&dest),
                    [](udx_socket_send_t* req, int) {
                        delete static_cast<std::vector<uint8_t>*>(req->data);
                        free(req);
                    });
    send_req->data = send_buf;
}

void RpcSocket::close() {
    udx_socket_close(&socket_);
}

// ---------------------------------------------------------------------------
// UDP receive callback
// ---------------------------------------------------------------------------

void RpcSocket::on_recv(udx_socket_t* socket, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr) {
    if (nread <= 0 || addr == nullptr) return;

    auto* self = static_cast<RpcSocket*>(socket->data);
    auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(addr);
    self->handle_message(reinterpret_cast<const uint8_t*>(buf->base),
                         static_cast<size_t>(nread), addr_in);
}

void RpcSocket::handle_message(const uint8_t* data, size_t len,
                               const struct sockaddr_in* addr) {
    if (len < 2) return;

    messages::Request req;
    messages::Response resp;
    uint8_t type = messages::decode_message(data, len, req, resp);

    if (type == messages::REQUEST_ID) {
        // Fill in sender address
        char host[INET_ADDRSTRLEN];
        uv_ip4_name(addr, host, sizeof(host));
        req.to.addr = compact::Ipv4Address::from_string(host, ntohs(addr->sin_port));

        if (on_request_) {
            on_request_(req);
        }
    } else if (type == messages::RESPONSE_ID) {
        // Match to inflight request
        auto* inflight = find_inflight(resp.tid);
        if (inflight && inflight->on_response) {
            inflight->on_response(resp);
            remove_inflight(resp.tid);
        }
    }
}

}  // namespace rpc
}  // namespace hyperdht
