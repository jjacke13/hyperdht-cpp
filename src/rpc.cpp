#include "hyperdht/rpc.hpp"

#include <cassert>
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
    if (total_ < 0) total_ = 0;  // Clamp — guard against underflow from mismatched recv
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

    // Drain timer (heap-allocated to outlive RpcSocket on close)
    drain_timer_ = new uv_timer_t;
    uv_timer_init(loop_, drain_timer_);
    drain_timer_->data = this;

    // Background tick timer (same pattern)
    bg_timer_ = new uv_timer_t;
    uv_timer_init(loop_, bg_timer_);
    bg_timer_->data = this;

    // Random initial tid
    std::random_device rd;
    next_tid_ = static_cast<uint16_t>(rd() & 0xFFFF);
}

RpcSocket::~RpcSocket() {
    assert(!socket_bound_ || closing_);
    // Safety: if destroyed without close(), detach timers so callbacks don't use 'this'
    if (drain_timer_) drain_timer_->data = nullptr;
    if (bg_timer_) bg_timer_->data = nullptr;
}

int RpcSocket::bind(uint16_t port) {
    struct sockaddr_in addr{};
    uv_ip4_addr("0.0.0.0", port, &addr);
    int rc = udx_socket_bind(&socket_, reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (rc == 0) {
        socket_bound_ = true;
        udx_socket_recv_start(&socket_, on_recv);

        // Start drain timer
        uv_timer_start(drain_timer_, on_drain_tick, DRAIN_INTERVAL_MS, DRAIN_INTERVAL_MS);

        // Start background tick timer
        uv_timer_start(bg_timer_, on_bg_tick, BG_TICK_MS, BG_TICK_MS);
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

// Single allocation holding both the send request and the data buffer
struct SendContext {
    udx_socket_send_t req;
    std::vector<uint8_t> buf;
};

void RpcSocket::udp_send(const std::vector<uint8_t>& buf, const compact::Ipv4Address& to) {
    auto* ctx = new SendContext;
    ctx->buf = buf;
    ctx->req.data = ctx;

    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                    static_cast<unsigned int>(ctx->buf.size()));

    struct sockaddr_in dest{};
    uv_ip4_addr(to.host_string().c_str(), to.port, &dest);

    udx_socket_send(&ctx->req, &socket_, &uv_buf, 1,
                    reinterpret_cast<const struct sockaddr*>(&dest),
                    [](udx_socket_send_t* req, int) {
                        delete static_cast<SendContext*>(req->data);
                    });
}

void RpcSocket::send_now(InflightRequest* req) {
    if (req->destroyed || closing_) return;

    req->sent++;
    req->sent_at = uv_now(loop_);
    congestion_.send();

    // Send the cached buffer
    udp_send(req->buffer, req->to);

    // Start/restart per-request timeout timer (adaptive or default)
    uint64_t timeout = timeout_for(req->to);
    uv_timer_stop(&req->timer);
    uv_timer_start(&req->timer, on_request_timeout, timeout, 0);
}

void RpcSocket::drain_pending() {
    while (!congestion_.is_full() && !pending_.empty()) {
        auto* req = pending_.front();
        pending_.pop_front();

        if (!req->destroyed) {
            inflight_.push_back(req);
            send_now(req);
        } else {
            // Timer was uv_timer_init'd — must uv_close before freeing
            uv_close(reinterpret_cast<uv_handle_t*>(&req->timer), [](uv_handle_t* h) {
                delete static_cast<InflightRequest*>(h->data);
            });
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

void RpcSocket::stop_tick() {
    if (bg_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(bg_timer_))) {
        uv_timer_stop(bg_timer_);
    }
}

void RpcSocket::start_tick() {
    if (bg_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(bg_timer_))) {
        uv_timer_start(bg_timer_, on_bg_tick, BG_TICK_MS, BG_TICK_MS);
    }
}

void RpcSocket::close() {
    if (closing_) return;
    closing_ = true;

    auto free_timer = [](uv_handle_t* h) {
        delete reinterpret_cast<uv_timer_t*>(h);
    };

    if (drain_timer_) {
        uv_timer_stop(drain_timer_);
        drain_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(drain_timer_), free_timer);
        drain_timer_ = nullptr;
    }

    if (bg_timer_) {
        uv_timer_stop(bg_timer_);
        bg_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(bg_timer_), free_timer);
        bg_timer_ = nullptr;
    }

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
    if (!self || self->closing_) return;

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
        self->tick_timeouts_++;
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

void RpcSocket::send_probe(const compact::Ipv4Address& to) {
    static const std::vector<uint8_t> probe_byte = {0x00};
    udp_send(probe_byte, to);
}

void RpcSocket::send_probe_ttl(const compact::Ipv4Address& to, int ttl) {
    auto* ctx = new SendContext;
    ctx->buf = {0x00};
    ctx->req.data = ctx;

    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                    static_cast<unsigned int>(ctx->buf.size()));

    struct sockaddr_in dest{};
    uv_ip4_addr(to.host_string().c_str(), to.port, &dest);

    udx_socket_send_ttl(&ctx->req, &socket_, &uv_buf, 1,
                        reinterpret_cast<const struct sockaddr*>(&dest),
                        ttl,
                        [](udx_socket_send_t* req, int) {
                            delete static_cast<SendContext*>(req->data);
                        });
}

void RpcSocket::handle_message(const uint8_t* data, size_t len,
                               const struct sockaddr_in* addr) {
    if (closing_) return;

    // Holepunch probe: single byte 0x00
    if (len == 1 && data[0] == 0x00) {
        if (on_probe_) {
            char host[INET_ADDRSTRLEN];
            uv_ip4_name(addr, host, sizeof(host));
            auto from = compact::Ipv4Address::from_string(host, ntohs(addr->sin_port));
            on_probe_(from);
        }
        return;
    }

    if (len < 2) return;

    messages::Request req;
    messages::Response resp;
    uint8_t type = messages::decode_message(data, len, req, resp);

    if (type == messages::REQUEST_ID) {
        char host[INET_ADDRSTRLEN];
        uv_ip4_name(addr, host, sizeof(host));
        req.from.addr = compact::Ipv4Address::from_string(host, ntohs(addr->sin_port));

        if (on_request_) {
            on_request_(req);
        }
    } else if (type == messages::RESPONSE_ID) {
        // Feed NAT sampler: resp.from.addr is the wire `to` field — how
        // the remote sees us. The UDP source (addr) is the remote node.
        char remote_host[INET_ADDRSTRLEN];
        uv_ip4_name(addr, remote_host, sizeof(remote_host));
        auto remote_addr = compact::Ipv4Address::from_string(
            remote_host, ntohs(addr->sin_port));
        nat_sampler_.add(resp.from.addr, remote_addr);

        auto* inflight = find_inflight(resp.tid);
        if (inflight && !inflight->destroyed) {
            tick_responses_++;

            // Record RTT for adaptive timeout (only first 2 attempts)
            if (inflight->sent <= 2 && inflight->sent_at > 0) {
                uint64_t rtt = uv_now(loop_) - inflight->sent_at;
                record_rtt(inflight->to, rtt);
            }

            auto on_response = std::move(inflight->on_response);
            destroy_request(inflight);

            if (on_response) {
                on_response(resp);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Background tick (5s) — health, refresh, ephemeral/persistent
// ---------------------------------------------------------------------------

void RpcSocket::on_bg_tick(uv_timer_t* timer) {
    auto* self = static_cast<RpcSocket*>(timer->data);
    if (!self || self->closing_) return;
    self->background_tick();
}

void RpcSocket::background_tick() {
    // 1. Health monitoring
    health_.update(tick_responses_, tick_timeouts_);
    tick_responses_ = 0;
    tick_timeouts_ = 0;

    // 2. Routing table refresh
    if (--refresh_ticks_ <= 0) {
        refresh_ticks_ = REFRESH_TICKS;
        if (on_refresh_) on_refresh_();
    }

    // 3. Ephemeral → persistent transition
    if (ephemeral_ && --stable_ticks_ <= 0) {
        check_persistent();
    }
}

void RpcSocket::check_persistent() {
    auto current_host = nat_sampler_.host();

    if (current_host.empty() || nat_sampler_.port() == 0) {
        stable_ticks_ = STABLE_TICKS_MORE;
        return;
    }

    stable_ticks_ = STABLE_TICKS_MORE;
    last_nat_host_ = current_host;

    // If NAT sampler has determined we're consistent or open → become persistent
    uint32_t fw = nat_sampler_.firewall();
    if (fw == 2 /* FIREWALL_CONSISTENT */ || fw == 1 /* FIREWALL_OPEN */) {
        ephemeral_ = false;
        firewalled_ = (fw != 1);
        if (on_persistent_) on_persistent_();
    }
}

// ---------------------------------------------------------------------------
// Adaptive timeout — per-peer RTT tracking
// ---------------------------------------------------------------------------

void RpcSocket::record_rtt(const compact::Ipv4Address& peer, uint64_t rtt_ms) {
    constexpr size_t MAX_PEER_RTT_ENTRIES = 1024;

    auto key = peer.host_string() + ":" + std::to_string(peer.port);
    auto it = peer_rtt_.find(key);
    if (it == peer_rtt_.end()) {
        // Evict a random entry if at capacity
        if (peer_rtt_.size() >= MAX_PEER_RTT_ENTRIES) {
            peer_rtt_.erase(peer_rtt_.begin());
        }
        peer_rtt_[key] = rtt_ms;
    } else {
        // Exponential moving average: new = 0.75 * old + 0.25 * sample
        // +2 before /4 for rounding to nearest instead of truncation
        it->second = (it->second * 3 + rtt_ms + 2) / 4;
    }
}

uint64_t RpcSocket::timeout_for(const compact::Ipv4Address& peer) const {
    auto key = peer.host_string() + ":" + std::to_string(peer.port);
    auto it = peer_rtt_.find(key);
    if (it == peer_rtt_.end()) return DEFAULT_TIMEOUT_MS;

    // Timeout = 2x smoothed RTT, clamped to [200ms, 5000ms]
    uint64_t timeout = it->second * 2;
    if (timeout < 200) timeout = 200;
    if (timeout > 5000) timeout = 5000;
    return timeout;
}

}  // namespace rpc
}  // namespace hyperdht
