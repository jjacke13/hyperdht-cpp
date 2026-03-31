#include "hyperdht/rpc.hpp"

#include <cstring>
#include <random>

namespace hyperdht {
namespace rpc {

// ---------------------------------------------------------------------------
// CongestionWindow
// ---------------------------------------------------------------------------

CongestionWindow::CongestionWindow(int max_window) : max_window_(max_window) {}

bool CongestionWindow::is_full() const {
    return total_ >= 2 * max_window_ || window_[i_] >= max_window_;
}

void CongestionWindow::send() {
    total_++;
    window_[i_]++;
}

void CongestionWindow::recv() {
    if (window_[i_] > 0) {
        window_[i_]--;
        total_--;
    }
}

void CongestionWindow::drain() {
    i_ = (i_ + 1) & 3;          // Rotate to next bucket
    total_ -= window_[i_];       // Remove oldest bucket's count
    window_[i_] = 0;             // Clear it
}

void CongestionWindow::clear() {
    i_ = 0;
    total_ = 0;
    std::memset(window_, 0, sizeof(window_));
}

// ---------------------------------------------------------------------------
// RpcSocket
// ---------------------------------------------------------------------------

RpcSocket::RpcSocket(uv_loop_t* loop, const routing::NodeId& local_id)
    : loop_(loop), table_(local_id) {

    udx_init(loop_, &udx_, nullptr);
    udx_socket_init(&udx_, &socket_, nullptr);
    socket_.data = this;

    // Drain timer
    uv_timer_init(loop_, &drain_timer_);
    drain_timer_.data = this;

    // Random initial tid
    std::random_device rd;
    next_tid_ = static_cast<uint16_t>(rd() & 0xFFFF);
}

RpcSocket::~RpcSocket() {
    // Ensure close() was called — if not, close now to prevent dangling timers
    if (!closing_) {
        close();
    }
}

int RpcSocket::bind(uint16_t port) {
    struct sockaddr_in addr{};
    uv_ip4_addr("0.0.0.0", port, &addr);
    int rc = udx_socket_bind(&socket_, reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (rc == 0) {
        socket_bound_ = true;
        udx_socket_recv_start(&socket_, on_recv);

        // Start drain timer
        uv_timer_start(&drain_timer_, on_drain_tick, DRAIN_INTERVAL_MS, DRAIN_INTERVAL_MS);
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
    if (next_tid_ == 0) next_tid_ = 1;
    return tid;
}

InflightRequest* RpcSocket::find_inflight(uint16_t tid) {
    for (auto* req : inflight_) {
        if (req->tid == tid) return req;
    }
    return nullptr;
}

void RpcSocket::destroy_request(InflightRequest* req) {
    if (req->destroyed) return;
    req->destroyed = true;

    // Stop per-request timer
    uv_timer_stop(&req->timer);
    uv_close(reinterpret_cast<uv_handle_t*>(&req->timer), [](uv_handle_t* h) {
        auto* r = static_cast<InflightRequest*>(h->data);
        delete r;
    });

    // Remove from inflight list (O(1) swap-and-pop)
    for (size_t i = 0; i < inflight_.size(); i++) {
        if (inflight_[i] == req) {
            inflight_[i] = inflight_.back();
            inflight_.pop_back();
            break;
        }
    }

    congestion_.recv();
}

void RpcSocket::udp_send(const std::vector<uint8_t>& buf, const compact::Ipv4Address& to) {
    auto* send_req = static_cast<udx_socket_send_t*>(malloc(sizeof(udx_socket_send_t)));
    auto* send_buf = new std::vector<uint8_t>(buf);
    send_req->data = send_buf;

    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(send_buf->data()),
                                    static_cast<unsigned int>(send_buf->size()));

    struct sockaddr_in dest{};
    uv_ip4_addr(to.host_string().c_str(), to.port, &dest);

    udx_socket_send(send_req, &socket_, &uv_buf, 1,
                    reinterpret_cast<const struct sockaddr*>(&dest),
                    [](udx_socket_send_t* req, int) {
                        delete static_cast<std::vector<uint8_t>*>(req->data);
                        free(req);
                    });
}

void RpcSocket::send_now(InflightRequest* req) {
    if (req->destroyed || closing_) return;

    req->sent++;
    congestion_.send();

    // Send the cached buffer
    udp_send(req->buffer, req->to);

    // Start/restart per-request timeout timer
    uv_timer_stop(&req->timer);
    uv_timer_start(&req->timer, on_request_timeout, DEFAULT_TIMEOUT_MS, 0);
}

void RpcSocket::drain_pending() {
    while (!congestion_.is_full() && !pending_.empty()) {
        auto* req = pending_.front();
        pending_.erase(pending_.begin());

        if (!req->destroyed) {
            inflight_.push_back(req);
            send_now(req);
        } else {
            delete req;
        }
    }
}

uint16_t RpcSocket::request(const messages::Request& req,
                            OnResponseCallback on_response,
                            OnTimeoutCallback on_timeout) {
    if (closing_) return 0;

    // Build request with our tid
    messages::Request msg = req;
    msg.tid = alloc_tid();

    // Create inflight entry
    auto* inflight = new InflightRequest;
    inflight->owner = this;
    inflight->tid = msg.tid;
    inflight->command = msg.command;
    inflight->on_response = std::move(on_response);
    inflight->on_timeout = std::move(on_timeout);
    inflight->to = msg.to.addr;
    inflight->buffer = messages::encode_request(msg);

    // Init per-request timer
    uv_timer_init(loop_, &inflight->timer);
    inflight->timer.data = inflight;

    // Check congestion window
    if (congestion_.is_full()) {
        pending_.push_back(inflight);
        return msg.tid;
    }

    inflight_.push_back(inflight);
    send_now(inflight);
    return msg.tid;
}

void RpcSocket::reply(const messages::Response& resp) {
    if (closing_) return;
    auto buf = messages::encode_response(resp);
    udp_send(buf, resp.from.addr);
}

void RpcSocket::close() {
    if (closing_) return;
    closing_ = true;

    uv_timer_stop(&drain_timer_);
    uv_close(reinterpret_cast<uv_handle_t*>(&drain_timer_), nullptr);

    // Destroy all inflight requests
    auto inflight_copy = inflight_;  // Copy since destroy_request modifies the vector
    for (auto* req : inflight_copy) {
        destroy_request(req);
    }

    // Clean pending
    for (auto* req : pending_) {
        uv_close(reinterpret_cast<uv_handle_t*>(&req->timer), [](uv_handle_t* h) {
            delete static_cast<InflightRequest*>(h->data);
        });
    }
    pending_.clear();

    udx_socket_close(&socket_);
}

// ---------------------------------------------------------------------------
// Timer callbacks
// ---------------------------------------------------------------------------

void RpcSocket::on_drain_tick(uv_timer_t* timer) {
    auto* self = static_cast<RpcSocket*>(timer->data);
    if (self->closing_) return;

    // Token rotation
    if (--self->rotate_counter_ == 0) {
        self->rotate_counter_ = TOKEN_ROTATE_TICKS;
        self->tokens_.rotate();
    }

    // Congestion window rotation
    self->congestion_.drain();

    // Send queued requests
    self->drain_pending();
}

void RpcSocket::on_request_timeout(uv_timer_t* timer) {
    auto* req = static_cast<InflightRequest*>(timer->data);
    if (req->destroyed) return;

    auto* self = req->owner;
    if (self->closing_) return;

    if (req->sent > req->retries) {
        // Exhausted retries — final timeout
        auto on_timeout = std::move(req->on_timeout);
        uint16_t tid = req->tid;
        self->destroy_request(req);

        if (on_timeout) {
            on_timeout(tid);
        }
    } else {
        // Retry: resend the same buffer
        self->send_now(req);
    }
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
    if (len < 2 || closing_) return;

    messages::Request req;
    messages::Response resp;
    uint8_t type = messages::decode_message(data, len, req, resp);

    if (type == messages::REQUEST_ID) {
        char host[INET_ADDRSTRLEN];
        uv_ip4_name(addr, host, sizeof(host));
        req.to.addr = compact::Ipv4Address::from_string(host, ntohs(addr->sin_port));

        if (on_request_) {
            on_request_(req);
        }
    } else if (type == messages::RESPONSE_ID) {
        auto* inflight = find_inflight(resp.tid);
        if (inflight && !inflight->destroyed) {
            auto on_response = std::move(inflight->on_response);
            destroy_request(inflight);

            if (on_response) {
                on_response(resp);
            }
        }
    }
}

}  // namespace rpc
}  // namespace hyperdht
