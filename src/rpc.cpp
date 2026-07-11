// DHT RPC socket implementation — UDP send/receive over a UDX socket,
// TID-based response matching, retries/timeouts, per-peer adaptive RTT,
// congestion control, NAT probe detection, and ID validation.
//
// JS: .analysis/js/dht-rpc/index.js:32-1003 (DHT class)
//     .analysis/js/dht-rpc/lib/io.js:15-349  (IO class — wire send/recv)
//     .analysis/js/dht-rpc/lib/io.js:351-554 (Request class)
//     .analysis/js/dht-rpc/lib/io.js:556-591 (CongestionWindow class)
//
// C++ diffs from JS:
//   - JS splits responsibilities across DHT (lifecycle, ticking) + IO
//     (sockets, congestion, requests). C++ collapses both into RpcSocket.
//   - Dual sockets (client_socket_ + server_socket_) matching JS
//     io.js clientSocket/serverSocket. Firewall probe (_checkIfFirewalled)
//     sends PING_NAT from client asking remote to reply to server port.
//   - bind() takes an explicit `host` param vs JS's default `0.0.0.0`.
//   - Per-peer RTT stored in `peer_rtt_` map (EMA via record_rtt) vs
//     JS using the `adaptive-timeout` package.
//   - Drain timer fires every 750ms (matches JS io.js:286) handling
//     congestion window rotation + token rotation in one tick.
//   - Background tick at 5s matches JS index.js:18 (TICK_INTERVAL).
//
// Resource limits:
//   - pending_ queue capped at 640 (4x congestion window)
//   - probe_replied_hosts_ capped at 16 during firewall probe

#include "hyperdht/rpc.hpp"
#include "hyperdht/debug.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>
#include <random>
#include <utility>

#include <sodium.h>

namespace hyperdht {
namespace rpc {

// Compute a peer id from an ipv4 address — BLAKE2b-256 over the 6-byte
// compact encoding (4 host bytes LE + 2 port bytes LE).
// JS: .analysis/js/dht-rpc/lib/peer.js (id function)
routing::NodeId compute_peer_id(const compact::Ipv4Address& addr) {
    uint8_t buf[6];
    // Host bytes in LE order (JS: c.uint32.encode writes LE).
    buf[0] = static_cast<uint8_t>(addr.host[0]);
    buf[1] = static_cast<uint8_t>(addr.host[1]);
    buf[2] = static_cast<uint8_t>(addr.host[2]);
    buf[3] = static_cast<uint8_t>(addr.host[3]);
    // Port LE.
    buf[4] = static_cast<uint8_t>(addr.port & 0xFF);
    buf[5] = static_cast<uint8_t>((addr.port >> 8) & 0xFF);

    routing::NodeId id{};
    crypto_generichash(id.data(), id.size(), buf, 6, nullptr, 0);
    return id;
}

namespace {
// State shared between the ping-and-swap request and its response/timeout
// callbacks. Heap-allocated via shared_ptr so it outlives any callback path.
struct SwapState {
    routing::Node new_node;
    routing::NodeId old_id{};
    uint32_t last_seen = 0;
};

// State shared between a DOWN_HINT-driven check and its callbacks.
struct CheckState {
    routing::NodeId target_id{};
    uint32_t last_seen = 0;
};

// JS: dht-rpc/index.js:1046-1048 —
//   function randomOffset(n) { return n - ((Math.random() * 0.5 * n) | 0) }
// i.e. n minus a uniform integer in [0, floor(n/2)-1]. Used to random-offset the
// tick counter and the refresh countdown at construction so a fleet of nodes
// doesn't sync its maintenance traffic (index.js:74-75).
uint32_t random_offset(uint32_t n) {
    uint32_t half = n / 2;
    if (half == 0) return n;
    return n - randombytes_uniform(half);
}
}  // namespace

// ---------------------------------------------------------------------------
// CongestionWindow
//
// JS: .analysis/js/dht-rpc/lib/io.js:556-591 (CongestionWindow class)
//
// 4-bucket sliding window: drain() rotates the index, oldest bucket
// becomes "current" and is cleared. is_full() guards both per-bucket
// and total inflight requests.
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
//
// JS: .analysis/js/dht-rpc/index.js:33-100 (DHT constructor — sets up
//                                            io, table, nat, ticks)
//     .analysis/js/dht-rpc/lib/io.js:16-79  (IO constructor)
//
// C++ diffs from JS:
//   - Random initial tid via std::random_device (JS uses Math.random).
//   - Drain + bg timers heap-allocated so they outlive RpcSocket close
//     (uv_close async dance).
//   - on_full hook installed at construction; JS does it via
//     `table.on('row', _onrow)` per-row.
// ---------------------------------------------------------------------------

RpcSocket::RpcSocket(uv_loop_t* loop, const routing::NodeId& local_id)
    : loop_(loop), table_(local_id) {

    udx_init(loop_, &udx_, nullptr);
    udx_socket_init(&udx_, &client_socket_, nullptr);
    client_socket_.data = this;
#ifndef HYPERDHT_EMBEDDED
    // EMBEDDED (ESP32): single-socket build. Skip server_socket_ init —
    // node never goes persistent, never passes firewall probe.
    udx_socket_init(&udx_, &server_socket_, nullptr);
    server_socket_.data = this;
#endif

    // Drain timer (heap-allocated to outlive RpcSocket on close)
    drain_timer_ = new uv_timer_t;
    uv_timer_init(loop_, drain_timer_);
    drain_timer_->data = this;

    // Background tick timer (same pattern)
    bg_timer_ = new uv_timer_t;
    uv_timer_init(loop_, bg_timer_);
    bg_timer_->data = this;

    // Wire the routing table's bucket-full hook to our ping-and-swap logic.
    // Uses a weak pointer pattern: captured `this` is stable for the table's
    // lifetime (the table is a member of this object).
    table_.on_full([this](size_t idx, const routing::Node& new_node) {
        on_bucket_full(idx, new_node);
    });

    // Random initial tid
    std::random_device rd;
    next_tid_ = static_cast<uint16_t>(rd() & 0xFFFF);

    // JS index.js:74-75 — random-offset the network ticks at construction so a
    // fleet's maintenance traffic (the tick&7 / tick&63 / refresh schedules)
    // doesn't fire in lockstep. tick_ ∈ (50,100], refresh_ticks_ ∈ (REFRESH/2,REFRESH].
    tick_ = random_offset(100);
    refresh_ticks_ = static_cast<int>(random_offset(REFRESH_TICKS));
}

RpcSocket::~RpcSocket() {
    assert((!client_bound_ && !server_bound_) || closing_);
    // Safety: if destroyed without close(), detach timers so callbacks don't use 'this'
    if (drain_timer_) drain_timer_->data = nullptr;
    if (bg_timer_) bg_timer_->data = nullptr;
    if (probe_timer_) probe_timer_->data = nullptr;
}

// JS: io.js:224-228 (bind) + io.js:230-295 (_bindSockets — JS binds
//     serverSocket to user port, clientSocket to random port.)
//
// EMBEDDED (ESP32): single-socket build. Bind client_socket_ to the
// user-supplied port (the only socket); skip server_socket_ entirely.
int RpcSocket::bind(uint16_t port, const std::string& host) {
#ifdef HYPERDHT_EMBEDDED
    // Single socket: bind to user port (or 0 for OS-assigned).
    struct sockaddr_in addr{};
    if (uv_ip4_addr(host.c_str(), port, &addr) != 0) return UV_EINVAL;
    int rc = udx_socket_bind(&client_socket_,
                             reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (rc != 0) return rc;
    client_bound_ = true;

    udx_socket_recv_start(&client_socket_, on_recv_client);
#else
    // Server socket: user-specified port (or 0 for OS-assigned)
    struct sockaddr_in server_addr{};
    if (uv_ip4_addr(host.c_str(), port, &server_addr) != 0) return UV_EINVAL;
    int rc = udx_socket_bind(&server_socket_,
                             reinterpret_cast<const struct sockaddr*>(&server_addr), 0);
    if (rc != 0) return rc;
    server_bound_ = true;

    // Client socket: always random port (ephemeral outbound)
    struct sockaddr_in client_addr{};
    if (uv_ip4_addr(host.c_str(), 0, &client_addr) != 0) {
        udx_socket_close(&server_socket_);
        server_bound_ = false;
        return UV_EINVAL;
    }
    rc = udx_socket_bind(&client_socket_,
                         reinterpret_cast<const struct sockaddr*>(&client_addr), 0);
    if (rc != 0) {
        udx_socket_close(&server_socket_);
        server_bound_ = false;
        return rc;
    }
    client_bound_ = true;

    // Both sockets receive messages
    udx_socket_recv_start(&client_socket_, on_recv_client);
    udx_socket_recv_start(&server_socket_, on_recv_server);
#endif

    // Start drain timer
    uv_timer_start(drain_timer_, on_drain_tick, DRAIN_INTERVAL_MS, DRAIN_INTERVAL_MS);

    // Start background tick timer. Seed the wakeup clock so the first
    // tick isn't mistaken for a sleep gap (JS: _lastTick = Date.now()).
    last_tick_ms_ = uv_now(loop_);
    uv_timer_start(bg_timer_, on_bg_tick, BG_TICK_MS, BG_TICK_MS);
    return 0;
}

uint16_t RpcSocket::port() const {
    // Return server socket port — the persistent/advertised port.
    // EMBEDDED: read client_socket_ — the only socket on this build.
    struct sockaddr_in addr{};
    int len = sizeof(addr);
#ifdef HYPERDHT_EMBEDDED
    udx_socket_getsockname(const_cast<udx_socket_t*>(&client_socket_),
                           reinterpret_cast<struct sockaddr*>(&addr), &len);
#else
    udx_socket_getsockname(const_cast<udx_socket_t*>(&server_socket_),
                           reinterpret_cast<struct sockaddr*>(&addr), &len);
#endif
    return ntohs(addr.sin_port);
}

uint16_t RpcSocket::alloc_tid() {
    // C++ reserves tid 0 as the request() failure sentinel (callers treat a
    // returned 0 as "congestion/queue full"), so alloc_tid must never hand it
    // out. JS uses the full 0..65535 range (io.js:318-320); this guard is a
    // C++-sentinel consequence, not a JS-parity divergence. next_tid_ can be 0
    // here from the random_device seed (constructor) or from the uint16 wrap
    // after returning 65535 — the top-of-call guard covers both.
    if (next_tid_ == 0) next_tid_ = 1;
    return next_tid_++;
}

bool RpcSocket::cancel_request(uint16_t tid) {
    auto* req = find_inflight(tid);
    if (!req) return false;
    // destroy_request handles timer close + congestion bookkeeping and
    // marks the request `destroyed`, so any later arrivals hitting
    // find_inflight return nullptr and fall through.
    destroy_request(req);
    return true;
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

    // If still congestion-queued, also drop it from the pending queue so the
    // drain path never sees (and never double-frees) a destroyed request —
    // destroy_request is the sole owner of teardown once it runs.
    if (req->queued) {
        for (auto it = pending_.begin(); it != pending_.end(); ++it) {
            if (*it == req) { pending_.erase(it); break; }
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
    udp_send_on(buf, to, active_socket());
}

void RpcSocket::udp_send_on(const std::vector<uint8_t>& buf,
                            const compact::Ipv4Address& to,
                            udx_socket_t* socket) {
    auto* ctx = new SendContext;
    ctx->buf = buf;
    ctx->req.data = ctx;

    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                    (ctx->buf.size() <= UINT_MAX
                                        ? static_cast<unsigned int>(ctx->buf.size())
                                        : 0u));

    struct sockaddr_in dest{};
    uv_ip4_addr(to.host_string().c_str(), to.port, &dest);

    udx_socket_send(&ctx->req, socket, &uv_buf, 1,
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

    // Start/restart per-request timeout timer.
    // Custom override wins (DELAYED_PING sets it to delay+grace). Otherwise use
    // JS's deployed flat 1000ms (io.js:457-459 `this.timeout || 1000`, since
    // hyperdht never constructs an AdaptiveTimeout). The per-peer EMA is a C++
    // opt-in extension gated behind adaptive_timeout_ (default off).
    uint64_t timeout = req->timeout_override_ms > 0
                     ? req->timeout_override_ms
                     : (adaptive_timeout_ ? timeout_for(req->to)
                                          : DEFAULT_TIMEOUT_MS);
    uv_timer_stop(&req->timer);
    uv_timer_start(&req->timer, on_request_timeout, timeout, 0);
}

void RpcSocket::drain_pending() {
    while (!congestion_.is_full() && !pending_.empty()) {
        auto* req = pending_.front();
        pending_.pop_front();

        // A cancelled queued request is removed from pending_ by
        // destroy_request (which owns its timer close + delete), so anything
        // still here is live. Guard defensively — never touch a destroyed req.
        if (req->destroyed) continue;

        // Already in inflight_ since request() queued it — just flip the flag
        // and transmit. send_now() bumps the congestion window.
        req->queued = false;
        send_now(req);
    }
}

uint16_t RpcSocket::request(const messages::Request& req,
                            OnResponseCallback on_response,
                            OnTimeoutCallback on_timeout) {
    return request(req, 0, DEFAULT_RETRIES,
                   std::move(on_response), std::move(on_timeout));
}

uint16_t RpcSocket::request(const messages::Request& req,
                            uint64_t timeout_override_ms,
                            int retries,
                            OnResponseCallback on_response,
                            OnTimeoutCallback on_timeout) {
    return request(req, timeout_override_ms, retries,
                   std::move(on_response), std::move(on_timeout), nullptr);
}

// JS: io.js:315-348 (createRequest) + io.js:431-445 (Request.send)
//     C++ collapses createRequest+send into one entry point and skips
//     the JS `session` object that detaches/reattaches inflight reqs.
uint16_t RpcSocket::request(const messages::Request& req,
                            uint64_t timeout_override_ms,
                            int retries,
                            OnResponseCallback on_response,
                            OnTimeoutCallback on_timeout,
                            OnCycleCallback on_cycle) {
    if (closing_) return 0;

    // Build request with our tid
    messages::Request msg = req;
    msg.tid = alloc_tid();

    // sweep-miss-b: advertise our node id on outgoing requests when persistent
    // AND the request egresses the server socket. JS io.js:521 —
    // `const id = this._io.ephemeral === false && socket === this._io.serverSocket`.
    // In C++'s dual-socket model a request egresses active_socket() = firewalled_
    // ? client_socket_ : server_socket_, so `socket === serverSocket` ⟺
    // !firewalled_. Without this, a persistent node's own pings/finds/announce
    // walks never carry its id, so peers' validateId never adds it to their
    // routing tables — defeating persistence. table_.id() is the address-based
    // id rebuilt at do_persistent_transition() (peer.id(host,port)), so it
    // matches how peers see us on the server socket. Firewall-probe PING_NATs go
    // out via udp_send_on() (not request()), so they are unaffected.
    if (!ephemeral_ && !firewalled_) {
        msg.id = table_.id();
    }

    // Create inflight entry
    auto* inflight = new InflightRequest;
    inflight->owner = this;
    inflight->tid = msg.tid;
    inflight->command = msg.command;
    inflight->on_response = std::move(on_response);
    inflight->on_timeout = std::move(on_timeout);
    inflight->on_cycle = std::move(on_cycle);
    inflight->timeout_override_ms = timeout_override_ms;
    inflight->retries = retries;
    inflight->to = msg.to.addr;
    inflight->buffer = messages::encode_request(msg);

    // Init per-request timer
    uv_timer_init(loop_, &inflight->timer);
    inflight->timer.data = inflight;

    // Check congestion window
    if (congestion_.is_full()) {
        // C12: cap pending queue to prevent unbounded memory growth
        constexpr size_t MAX_PENDING = 640;
        if (pending_.size() >= MAX_PENDING) {
            uv_close(reinterpret_cast<uv_handle_t*>(&inflight->timer), nullptr);
            delete inflight;
            return 0;
        }
        // JS io.js:337 — createRequest pushes EVERY request into io.inflight
        // immediately, even when congestion-queued in _pending. That is what
        // lets req.destroy / session.destroy find and cancel a still-queued
        // request (io.js:471, session.js:39-46). Mirror it: the request lives
        // in BOTH inflight_ (cancellation lookup) and pending_ (drain queue).
        // `queued` tells drain_pending it is already in inflight_ (don't re-add)
        // and tells destroy_request to also erase it from pending_.
        inflight->queued = true;
        inflight_.push_back(inflight);
        pending_.push_back(inflight);
        return msg.tid;
    }

    inflight_.push_back(inflight);
    send_now(inflight);
    return msg.tid;
}

// JS: dht-rpc/lib/query.js:318-332 (_downHint) — gossip a dead node to a peer.
bool RpcSocket::try_send_down_hint(const compact::Ipv4Address& to,
                                   const compact::Ipv4Address& down) {
    if (closing_) return false;

    // Per-tick rate limit (JS index.js:320-323). rate_limit == -1 disables it.
    if (down_hints_rate_limit_ != -1 &&
        down_hints_sent_this_tick_ >= down_hints_rate_limit_) {
        return false;
    }
    down_hints_sent_this_tick_++;

    // value = 6-byte compact ipv4 of the down node (JS query.js:329-331). The
    // receiver hashes these 6 bytes to look the node up (index.js:667-668).
    compact::State ps;
    compact::Ipv4Addr::preencode(ps, down);
    std::vector<uint8_t> value(ps.end);
    ps.buffer = value.data();
    ps.start = 0;
    compact::Ipv4Addr::encode(ps, down);

    // JS `_request(node, false, true, DOWN_HINT, null, buffer, ...)`: internal,
    // no target, retries default 3 (query.js:29), fire-and-forget.
    messages::Request req;
    req.to.addr = to;
    req.command = messages::CMD_DOWN_HINT;
    req.internal = true;
    req.value = std::move(value);
    request(req, /*timeout_override_ms=*/0, /*retries=*/3, nullptr, nullptr);
    return true;
}

// JS: dht-rpc/index.js:278-299 (delayedPing) — creates a DELAYED_PING
// request with `req.timeout = delayMs + 1_000`. C++ returns 0 instead of
// throwing on overflow.
uint16_t RpcSocket::delayed_ping(const compact::Ipv4Address& to,
                                 uint32_t delay_ms,
                                 OnResponseCallback on_response,
                                 OnTimeoutCallback on_timeout) {
    // Mirror JS: reject if delay exceeds max (JS throws; we return 0)
    if (delay_ms > max_ping_delay_ms_) return 0;

    // Build the request: internal DELAYED_PING with 4-byte LE uint32 value
    messages::Request req;
    req.to.addr = to;
    req.command = messages::CMD_DELAYED_PING;
    req.internal = true;

    std::vector<uint8_t> value(4);
    value[0] = static_cast<uint8_t>(delay_ms & 0xFF);
    value[1] = static_cast<uint8_t>((delay_ms >> 8) & 0xFF);
    value[2] = static_cast<uint8_t>((delay_ms >> 16) & 0xFF);
    value[3] = static_cast<uint8_t>((delay_ms >> 24) & 0xFF);
    req.value = std::move(value);

    // Timeout = delay + 1s grace (matches JS: req.timeout = delayMs + 1_000).
    // No retries: retrying a deliberately-delayed reply would duplicate work
    // and the timeout already accounts for server-side scheduling.
    uint64_t timeout_ms = static_cast<uint64_t>(delay_ms) + 1000;

    return request(req, timeout_ms, /*retries=*/0,
                   std::move(on_response), std::move(on_timeout));
}

void RpcSocket::reply(const messages::Response& resp, bool from_server) {
    if (closing_) return;
    auto buf = messages::encode_response(resp);
    // JS parity: dht-rpc replies leave on the same socket the request
    // arrived on (io.js: Request.socket / _sendReply). Without that,
    // stateful conntrack/firewalls (NixOS host firewall, carrier CGNAT)
    // drop our reply because the source port differs from the destination
    // port of the original outbound request — see the long comment on
    // the declaration in rpc.hpp.
    //
    // The single-socket EMBEDDED build only has client_socket_; the
    // active_socket() helper returns it in both branches so the explicit
    // socket selection below collapses to the same result.
    udx_socket_t* sock = from_server ? &server_socket_ : &client_socket_;
    udp_send_on(buf, resp.from.addr, sock);
}

void RpcSocket::stop_tick() {
    if (bg_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(bg_timer_))) {
        uv_timer_stop(bg_timer_);
    }
}

void RpcSocket::start_tick() {
    if (bg_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(bg_timer_))) {
        uv_timer_start(bg_timer_, on_bg_tick, BG_TICK_MS, BG_TICK_MS);
        // JS: dht-rpc resume() (index.js:174-185) — run wakeup recovery
        // and refresh immediately; don't wait for the first 5s tick.
        last_tick_ms_ = uv_now(loop_);
        do_wakeup();
        trigger_refresh();
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

#ifndef HYPERDHT_EMBEDDED
    // Cancel firewall probe if running. EMBEDDED: probe never runs (node
    // is always ephemeral), so this block is dead code on that build.
    if (firewall_probe_running_) {
        firewall_probe_running_ = false;
        if (probe_timer_) uv_timer_stop(probe_timer_);
    }
    if (probe_timer_) {
        probe_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(probe_timer_), free_timer);
        probe_timer_ = nullptr;
    }
#endif

    // Close socket(s). EMBEDDED: single-socket build, only client_socket_.
    if (client_bound_) udx_socket_close(&client_socket_);
#ifndef HYPERDHT_EMBEDDED
    if (server_bound_) udx_socket_close(&server_socket_);
#endif
}

// ---------------------------------------------------------------------------
// Timer callbacks
//
// JS: .analysis/js/dht-rpc/lib/io.js:286-313 (_drain interval at 750ms)
//     .analysis/js/dht-rpc/lib/io.js:595-606 (oncycle — request timeout)
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

    // JS io.js:596-597 — `req.oncycle(req)` fires on every cycle, before the
    // retry/give-up decision. We fire it once (clear it after), matching the
    // Query engine which resets its hook to noop on first fire.
    if (req->on_cycle) {
        auto cb = std::move(req->on_cycle);
        req->on_cycle = nullptr;
        cb(req->tid);
        // The oncycle callback can re-enter the socket (Query::read_more →
        // request/cancel). Re-validate the request is still alive before use.
        if (req->destroyed) return;
    }

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
//
// JS: .analysis/js/dht-rpc/lib/io.js:83-146 (onmessage — REQUEST_ID and
//     RESPONSE_ID dispatch, RTT recording, congestion.recv, inflight pop)
// ---------------------------------------------------------------------------

void RpcSocket::on_recv_client(udx_socket_t* socket, ssize_t nread, const uv_buf_t* buf,
                               const struct sockaddr* addr) {
    if (nread <= 0 || addr == nullptr) return;
    auto* self = static_cast<RpcSocket*>(socket->data);
    auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(addr);
    self->handle_message(reinterpret_cast<const uint8_t*>(buf->base),
                         static_cast<size_t>(nread), addr_in, false);
}

void RpcSocket::on_recv_server(udx_socket_t* socket, ssize_t nread, const uv_buf_t* buf,
                               const struct sockaddr* addr) {
    if (nread <= 0 || addr == nullptr) return;
    auto* self = static_cast<RpcSocket*>(socket->data);
    auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(addr);

    // During firewall probe: track which hosts reached the server socket.
    if (self->firewall_probe_running_) {
        char host[INET_ADDRSTRLEN];
        uv_ip4_name(addr_in, host, sizeof(host));
        if (self->probe_replied_hosts_.size() < 16)  // H26: cap
            self->probe_replied_hosts_.insert(host);
    }

    // Decode + dispatch first: for a firewall-probe reply this feeds
    // probe_ring_ with the server-observed `to` field (handle_message), so the
    // finish check below sees a populated sampler even when the host threshold
    // is 1 (small networks) and this is the very first reply.
    self->handle_message(reinterpret_cast<const uint8_t*>(buf->base),
                         static_cast<size_t>(nread), addr_in, true);

    if (self->firewall_probe_running_ &&
        self->probe_replied_hosts_.size() >= self->probe_threshold()) {
        self->finish_firewall_probe();
    }
}

// Register a new holepunch probe listener. Returns an ID for later removal.
// Multiple listeners are supported so concurrent holepunch sessions don't
// clobber each other (previous single-slot API was a concurrency bug).
// IDs start at 1 — 0 is reserved as "not installed" sentinel in callers.
uint32_t RpcSocket::add_probe_listener(OnProbeCallback cb) {
    uint32_t id = next_probe_id_++;
    probe_listeners_[id] = std::move(cb);
    return id;
}

void RpcSocket::remove_probe_listener(uint32_t id) {
    probe_listeners_.erase(id);
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
                                    (ctx->buf.size() <= UINT_MAX
                                        ? static_cast<unsigned int>(ctx->buf.size())
                                        : 0u));

    struct sockaddr_in dest{};
    uv_ip4_addr(to.host_string().c_str(), to.port, &dest);

    udx_socket_send_ttl(&ctx->req, active_socket(), &uv_buf, 1,
                        reinterpret_cast<const struct sockaddr*>(&dest),
                        ttl,
                        [](udx_socket_send_t* req, int) {
                            delete static_cast<SendContext*>(req->data);
                        });
}

// JS: io.js:83-146 (onmessage). JS rejects 1-byte payloads at io.js:84
// (`buffer.byteLength < 2`). C++ uses 1-byte 0x00 as a holepunch probe
// (matching DHT::onmessage at index.js:153 which only forwards >1 byte
// payloads to io.js — leaving 1-byte for holepunch detection).
//
// `from_server` indicates which socket received this message. Used for
// ID suppression logic: JS only includes the node ID in responses when
// `!ephemeral && socket === serverSocket` (io.js:488).
void RpcSocket::handle_message(const uint8_t* data, size_t len,
                               const struct sockaddr_in* addr,
                               bool from_server) {
    if (closing_) return;

    // Holepunch probe: single byte 0x00
    if (len == 1 && data[0] == 0x00) {
        if (!probe_listeners_.empty()) {
            char host[INET_ADDRSTRLEN];
            uv_ip4_name(addr, host, sizeof(host));
            auto from = compact::Ipv4Address::from_string(host, ntohs(addr->sin_port));
            // Copy — a listener callback might remove itself during dispatch
            auto listeners = probe_listeners_;
            for (auto& [id, cb] : listeners) {
                if (cb) cb(from);
            }
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
        req.from_server = from_server;

        // JS: io.js:94-101 — central token validation. When a request carries
        // a token, it must match either the current or the previous secret;
        // otherwise reply with req.error(INVALID_TOKEN, { token: true }) and
        // DROP the request before it reaches any command handler. This is the
        // single choke point (io.js `onmessage`) — the per-handler token
        // checks in rpc_handlers.cpp remain as unreachable backstops.
        if (req.token.has_value() &&
            !tokens_.validate(req.from.addr.host_string(), *req.token)) {
            // JS: io.js:419-423 — error(2) → _sendReply(2, null, token=true,
            // closerNodes=true, from, socket).
            messages::Response resp;
            resp.tid = req.tid;
            resp.from.addr = req.from.addr;
            resp.error = messages::ERR_INVALID_TOKEN;
            // token:true → include a fresh valid token (JS token(from, 1)).
            resp.token = tokens_.create(req.from.addr.host_string());
            // id only when persistent AND on the server socket (JS io.js:488).
            if (!ephemeral_ && from_server) {
                resp.id = table_.id();
            }
            // closerNodes only when the request carried a target
            // (JS io.js:489-490; closerNodes defaults to true).
            if (req.target.has_value()) {
                routing::NodeId target{};
                std::copy(req.target->begin(), req.target->end(), target.begin());
                for (const auto* node : table_.closest(target)) {
                    resp.closer_nodes.push_back(
                        compact::Ipv4Address::from_string(node->host, node->port));
                }
            }
            reply(resp, from_server);
            return;
        }

        // Validate and observe the peer in the routing table.
        // JS: io.js:392 `from.id = validateId(id, from)` — recomputes
        // peer.id(host, port) and rejects mismatches. Prevents a malicious
        // node from claiming an arbitrary position in our routing table.
        if (req.id.has_value()) {
            auto expected = compute_peer_id(req.from.addr);
            if (*req.id == expected) {
                add_node_from_network(expected, req.from.addr);

                // JS dht-rpc/index.js:632-635 — _onrequest also feeds the NAT
                // sampler from incoming requests:
                //   if (req.from.id !== null) _addNodeFromNetwork(!external, from, to)
                // where `to` (req.to.addr) is our external address as the
                // requester sees it, and `sample = !external`. `external` is
                // "arrived on the wrong socket for our firewall state"
                // (io.js:88-91): expected = firewalled ? clientSocket
                // : serverSocket; external = socket !== expected. With C++
                // from_server marking the server socket, sample reduces to
                // (from_server != firewalled_). Mirror the RESPONSE path below:
                // feed both the ring sampler (external host/port + persistence
                // gate) and the Nat classifier, using req.from.addr as the
                // dedup source (matches nat_sampler_.add(to, from)).
                if (from_server != firewalled_) {
                    nat_sampler_.add(req.to.addr, req.from.addr);
                    ring_sampler_.add(req.to.addr.host_string(), req.to.addr.port);
                }
            }
            // else: ID mismatch — treat as no-ID (don't add to table)
        }

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
        // Feed the dht-rpc ring sampler the same observation. JS feeds
        // `this._nat` from _addNodeFromNetwork (index.js:480,500,533); the C++
        // architecture centralizes external-address sampling on the response
        // path, so we mirror JS's `_natAdd(to.host, to.port)` here. resp.from
        // is the wire `to` field = how the remote sees us.
        ring_sampler_.add(resp.from.addr.host_string(), resp.from.addr.port);
#ifndef HYPERDHT_EMBEDDED
        // Firewall probe: replies land on the server socket. Feed a FRESH
        // sampler with the server-observed `to` so finish_firewall_probe can
        // check host consistency + port preservation and swap it in.
        // JS: index.js:940 — `natSampler.add(res.to.host, res.to.port)`.
        if (from_server && firewall_probe_running_) {
            probe_ring_.add(resp.from.addr.host_string(), resp.from.addr.port);
        }
#endif

        // Validate and observe the responding peer.
        // JS: io.js:619 `from.id = validateId(id, from)` — same validation
        // as requests. Clear resp.id on mismatch so the query layer
        // (which reads resp.id to set reply.from_id) sees clean data.
        if (resp.id.has_value()) {
            auto expected = compute_peer_id(remote_addr);
            if (*resp.id == expected) {
                add_node_from_network(expected, remote_addr);
            } else {
                resp.id = std::nullopt;
            }
        }

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
// Routing table observation + ping-and-swap eviction (JS parity)
//
// JS: .analysis/js/dht-rpc/index.js:483-521 (_addNodeFromNetwork)
//     .analysis/js/dht-rpc/index.js:523-537 (_addNode)
//     .analysis/js/dht-rpc/index.js:575-594 (_onfullrow — bucket-full hook)
//     .analysis/js/dht-rpc/index.js:601-630 (_repingAndSwap)
// ---------------------------------------------------------------------------

void RpcSocket::add_node_from_network(const routing::NodeId& id,
                                      const compact::Ipv4Address& from) {
    // Respect a user-installed filter (JS `_filterNode`).
    if (!filter_accept(id, from)) return;

    // Already in the table — just refresh metadata.
    if (auto* existing = table_.get_mut(id)) {
        existing->pinged = tick_;
        existing->seen = tick_;
        return;
    }

    // Not in the table: try to insert. If the bucket is full, on_full_
    // fires and ping-and-swap takes over.
    routing::Node node;
    node.id = id;
    node.host = from.host_string();
    node.port = from.port;
    node.added = tick_;
    node.pinged = tick_;
    node.seen = tick_;
    table_.add(node);
}

void RpcSocket::on_bucket_full(size_t bucket_idx,
                               const routing::Node& new_node) {
    // JS: `if (!this.bootstrapped || this._repinging >= 3) return`.
    // We must NOT ping-and-swap until the initial bootstrap walk has
    // populated the table — otherwise valid nodes arriving during bootstrap
    // get evicted before their RTT is known, degrading table quality.
    if (!bootstrapped_) return;
    if (repinging_ >= MAX_REPINGING) return;

    // Find the oldest candidate that has NOT been pinged this tick.
    // "Oldest" = smallest `pinged` tick, ties broken by smallest `added`.
    auto& bucket = table_.bucket_mut(bucket_idx);
    routing::Node* oldest = nullptr;
    for (auto& n : bucket.nodes_mut()) {
        if (n.pinged == tick_) continue;
        if (!oldest
            || oldest->pinged > n.pinged
            || (oldest->pinged == n.pinged && oldest->added > n.added)) {
            oldest = &n;
        }
    }
    if (!oldest) return;

    // Skip eviction if the candidate was seen recently AND is well
    // established (JS: `_tick - oldest.pinged < RECENT_NODE && _tick - oldest.added > OLD_NODE`).
    // tick_ is monotonic; guard against underflow if counters are uninitialized.
    uint32_t since_pinged = tick_ - oldest->pinged;
    uint32_t since_added  = tick_ - oldest->added;
    if (since_pinged < RECENT_NODE_TICKS && since_added > OLD_NODE_TICKS) return;

    reping_and_swap(new_node, *oldest);
}

void RpcSocket::reping_and_swap(const routing::Node& new_node,
                                const routing::Node& oldest) {
    // Snapshot the fields we need — the reference may be invalidated if the
    // bucket's vector reallocates before our callbacks fire.
    auto state = std::make_shared<SwapState>();
    state->new_node = new_node;
    state->old_id = oldest.id;
    state->last_seen = oldest.seen;

    // Mark the oldest as "pinged this tick" so we don't re-select it.
    if (auto* o = table_.get_mut(oldest.id)) {
        o->pinged = tick_;
    }

    repinging_++;

    messages::Request req;
    req.to.addr = compact::Ipv4Address::from_string(oldest.host, oldest.port);
    req.command = messages::CMD_PING;
    req.internal = true;

    auto do_swap = [this, state]() {
        table_.remove(state->old_id);
        // The bucket now has a free slot — insert the new node.
        table_.add(state->new_node);
    };

    // JS `_repingAndSwap` (index.js:601-630) issues its PING via `_request` →
    // `io.createRequest`, whose Request defaults to retries=3 (io.js:366): up to
    // 4 transmissions before `onswap` fires. Match it — a single PING would evict
    // far too aggressively on one dropped packet.
    request(req, /*timeout_override_ms=*/0, /*retries=*/DEFAULT_RETRIES,
        [this, state, do_swap](const messages::Response&) {
            // Ping succeeded. If the node's seen counter has NOT advanced
            // in the meantime (i.e. we haven't heard from it via another
            // path), JS still swaps. Otherwise keep the old node.
            repinging_--;
            if (auto* n = table_.get_mut(state->old_id)) {
                if (n->seen <= state->last_seen) {
                    do_swap();
                }
            }
        },
        [this, do_swap](uint16_t) {
            // Ping timed out — evict and swap in the new node.
            repinging_--;
            do_swap();
        });
}

// JS: dht-rpc/index.js:737-762 (_check). PINGs the node (via `_request` →
// retries=3 default, io.js:366) and either removes-if-stale on success or
// removes outright once every transmission has timed out. Used by DOWN_HINT
// and _pingSome.
void RpcSocket::check_node(const routing::Node& node) {
    // Snapshot identity + last_seen before marking pinged (JS: `_check`).
    auto state = std::make_shared<CheckState>();
    state->target_id = node.id;
    state->last_seen = node.seen;

    if (auto* n = table_.get_mut(node.id)) {
        n->pinged = tick_;
    }

    checks_++;

    messages::Request req;
    req.to.addr = compact::Ipv4Address::from_string(node.host, node.port);
    req.command = messages::CMD_PING;
    req.internal = true;

    request(req, /*timeout_override_ms=*/0, /*retries=*/DEFAULT_RETRIES,
        [this, state](const messages::Response&) {
            // Ping OK: if `seen` has advanced (via `add_node_from_network`
            // firing on this same response), the node is alive and we keep
            // it. Otherwise JS still removes it — matches `_removeStaleNode`.
            checks_--;
            if (auto* n = table_.get_mut(state->target_id)) {
                if (n->seen <= state->last_seen) {
                    table_.remove(state->target_id);
                }
            }
        },
        [this, state](uint16_t) {
            // Ping timed out: the DOWN_HINT was right — remove the node.
            checks_--;
            table_.remove(state->target_id);
        });
}

// ---------------------------------------------------------------------------
// Background tick (5s) — health, refresh, ephemeral/persistent
//
// JS: .analysis/js/dht-rpc/index.js:764-799 (_ontick) — runs at 5s
//     interval (TICK_INTERVAL). Wakeup detection via `_lastTick` drift,
//     then: NAT recheck countdown, _pingSome every 8th tick, refresh on
//     thin table (every 64 ticks) or _refreshTicks expiry, health last.
// ---------------------------------------------------------------------------

void RpcSocket::on_bg_tick(uv_timer_t* timer) {
    auto* self = static_cast<RpcSocket*>(timer->data);
    if (!self || self->closing_) return;
    self->background_tick();
}

void RpcSocket::background_tick() {
    // JS: _ontick:765-773 — a wall-clock gap while the timer was
    // nominally running means the host slept (laptop lid, phone doze);
    // run wakeup recovery instead of a normal bump. The first tick
    // (last_tick_ms_ == 0, timer not started via bind) is exempt.
    const uint64_t now = uv_now(loop_);
    if (last_tick_ms_ != 0 && now - last_tick_ms_ > SLEEPING_INTERVAL_MS) {
        do_wakeup();
    } else {
        tick_++;
    }
    last_tick_ms_ = now;

    // JS: _ontick:775 — nothing below runs until bootstrapped.
    if (!bootstrapped_) return;

    // 1. Ephemeral → persistent recheck (JS: _ontick:777-784). Only adaptive
    // nodes run this countdown — a forced-persistent/forced-ephemeral node
    // (adaptive_ == false) never re-derives its NAT state. Skip the probe when
    // the NAT host hasn't changed since the last check.
    if (adaptive_ && ephemeral_ && --stable_ticks_ <= 0) {
        // JS: index.js:778 — compares the cached host against `this._nat.host`
        // (the ring sampler), skipping the probe if the network is unchanged.
        if (!last_nat_host_.empty() && last_nat_host_ == ring_sampler_.host()) {
            stable_ticks_ = STABLE_TICKS_MORE;
        } else {
            check_persistent();
        }
    }

    // 2. Ping a few of the oldest nodes every 8th tick (JS: _ontick:786-788)
    // so stale entries get refreshed or evicted and pinholes stay warm.
    if ((tick_ & 7) == 0) {
        ping_some();
    }

    // 3. Routing table refresh: thin-table top-up every 64 ticks, or the
    // regular refresh countdown (JS: _ontick:790-795).
    if (((tick_ & 63) == 0 && table_.size() < routing::K) ||
        --refresh_ticks_ <= 0) {
        trigger_refresh();
    }

    // 4. Health monitoring, last (JS: _ontick:798). JS emits
    // `network-update` on every `_online()` / `_degraded()` / `_offline()`
    // transition (dht-rpc/index.js:982-1002); we fire `on_health_change_`
    // on any observed state transition so the HyperDHT layer can derive
    // `network-update` from it.
    const health::State prev_health = health_.state();
    health_.update(tick_responses_, tick_timeouts_);
    tick_responses_ = 0;
    tick_timeouts_ = 0;
    // JS index.js:797 — reset the per-tick DOWN_HINT emission budget.
    down_hints_sent_this_tick_ = 0;
    if (health_.state() != prev_health && on_health_change_) {
        on_health_change_();
    }
}

// JS: dht-rpc/index.js:552-573 (_onwakeup). Ages out the whole routing
// table, forces a refresh next tick, invalidates the NAT-host cache, and
// reverts a persistent node to ephemeral so NAT/firewall state is
// re-derived. Sockets and the routing id are left untouched (JS keeps
// `io.firewalled` reset commented out for the same reason).
void RpcSocket::do_wakeup() {
    tick_ += 2 * OLD_NODE_TICKS;      // everything in the table looks old
    tick_ += 8 - (tick_ & 7) - 2;     // (tick & 7) == 6 → pings in two ticks
    stable_ticks_ = STABLE_TICKS_MORE;
    refresh_ticks_ = 1;               // refresh next tick, network needs a beat
    last_nat_host_.clear();           // force the NAT recheck to actually run
    health_.reset();

    // JS index.js:560-570 — only an adaptive node reverts to ephemeral on
    // wakeup (so it re-derives NAT/firewall state). A forced-persistent node
    // keeps its persistent id across a sleep gap.
    if (adaptive_ && !ephemeral_) {
        ephemeral_ = true;
    }

    if (on_wakeup_) on_wakeup_();
}

// JS: dht-rpc/index.js:715-735 (_pingSome). Ping the 3-5 least recently
// seen nodes (2 when the oldest was pinged within the last minute) via
// check_node, which refreshes-or-evicts each one.
void RpcSocket::ping_some() {
    int cnt = inflight_.size() > 2 ? 3 : 5;

    // JS keeps a global least-recently-seen list (`nodes.oldest`). We
    // scan the table instead — at most K * ID_BITS entries every 8th
    // tick (40s), which is cheap.
    std::vector<const routing::Node*> by_age;
    by_age.reserve(table_.size());
    for (size_t b = 0; b < routing::ID_BITS; b++) {
        for (const auto& n : table_.bucket(b).nodes()) {
            by_age.push_back(&n);
        }
    }

    if (by_age.empty()) {
        // JS: tiny dht — refresh pings the bootstrap nodes again.
        trigger_refresh();
        return;
    }

    std::sort(by_age.begin(), by_age.end(),
              [](const routing::Node* a, const routing::Node* b) {
                  if (a->seen != b->seen) return a->seen < b->seen;
                  return a->added < b->added;
              });

    // Recently pinged the oldest → only trigger a couple of repings.
    if (tick_ - by_age.front()->pinged < RECENT_NODE_TICKS) {
        cnt = 2;
    }

    // Faithful to the JS loop: an already-pinged-this-tick node burns a
    // slot without advancing.
    size_t i = 0;
    while (cnt-- > 0) {
        if (i >= by_age.size()) continue;
        if (by_age[i]->pinged == tick_) continue;
        check_node(*by_age[i]);
        i++;
    }
}

void RpcSocket::trigger_refresh() {
    refresh_ticks_ = REFRESH_TICKS;
    if (on_refresh_) on_refresh_();
}

// JS: dht-rpc/index.js:801-875 (_updateNetworkState).
//
// Now matches JS: when NAT sampler says CONSISTENT, we run a firewall
// probe (PING_NAT from client_socket_, replies expected on server_socket_)
// before committing to the persistent transition. This correctly detects
// port-restricted cone NATs that map consistently but block unsolicited
// inbound — JS: _checkIfFirewalled (index.js:916-963).
//
// Idempotency: once `ephemeral_` has flipped to false, this is a no-op.
void RpcSocket::check_persistent() {
#ifdef HYPERDHT_EMBEDDED
    // ESP32 is always behind home WiFi NAT and never goes persistent. The
    // firewall probe, persistent transition, and the second socket are all
    // skipped on this build — see HYPERDHT_EMBEDDED in rpc.cpp::bind() and
    // RpcSocket::active_socket().
    return;
#else
    if (!ephemeral_) return;
    if (firewall_probe_running_) return;  // probe already in flight

    // JS: index.js:805 — `const { host, port } = this._nat` (the ring
    // sampler). The ring's threshold gating is what makes `port() == 0`
    // report the JS "host consistent, port random" signal below.
    auto current_host = ring_sampler_.host();

    if (current_host.empty() || ring_sampler_.port() == 0) {
        // JS: index.js:814 — `if (host === null || port === 0) return false`.
        DHT_LOG("  [rpc] check_persistent: no address yet (host=%s port=%u)\n",
                current_host.c_str(), ring_sampler_.port());
        stable_ticks_ = STABLE_TICKS_MORE;
        return;
    }

    stable_ticks_ = STABLE_TICKS_MORE;
    last_nat_host_ = current_host;

    // Firewall TYPE still comes from the hyperdht-Nat classifier (nat_sampler_)
    // — its holepunch/server/connect consumers rely on it. This is the
    // accepted C++ divergence noted on nat_sampler_.
    uint32_t fw = nat_sampler_.firewall();
    const char* fw_str = fw == 0 ? "UNKNOWN" : fw == 1 ? "OPEN" :
                         fw == 2 ? "CONSISTENT" : fw == 3 ? "RANDOM" : "?";
    DHT_LOG("  [rpc] check_persistent: host=%s:%u firewall=%s (%u)\n",
            current_host.c_str(), ring_sampler_.port(), fw_str, fw);

    if (fw == 2 /* CONSISTENT */ || fw == 1 /* OPEN */) {
        // Don't transition immediately — run firewall probe first.
        // JS: index.js:821 — `const firewalled = this.firewalled && (await this._checkIfFirewalled(natSampler))`
        start_firewall_probe();
    }
#endif  // HYPERDHT_EMBEDDED
}

// ---------------------------------------------------------------------------
// Firewall probe — verify server socket is reachable before going persistent
//
// JS: dht-rpc/index.js:916-963 (_checkIfFirewalled)
// Sends PING_NAT from client_socket_ asking remote nodes to reply to
// server_socket_'s port. If replies arrive on server_socket_, the port
// is reachable from the network → not firewalled → go persistent.
// ---------------------------------------------------------------------------

void RpcSocket::start_firewall_probe() {
    if (firewall_probe_running_ || closing_) return;
    firewall_probe_running_ = true;
    probe_replied_hosts_.clear();
    // JS: index.js:818 — a fresh `new NatSampler()` for the probe, fed only
    // from the server socket's PING_NAT replies (see handle_message).
    probe_ring_.reset();

    auto nodes = collect_probe_nodes(5);
    probe_expected_ = nodes.size();
    if (nodes.empty()) {
        DHT_LOG("  [rpc] firewall probe: no nodes to probe\n");
        firewall_probe_running_ = false;
        return;
    }

    // Encode server socket port as PING_NAT value (uint16le)
    struct sockaddr_in saddr{};
    int slen = sizeof(saddr);
    udx_socket_getsockname(&server_socket_,
                           reinterpret_cast<struct sockaddr*>(&saddr), &slen);
    uint16_t server_port = ntohs(saddr.sin_port);

    std::vector<uint8_t> value = {
        static_cast<uint8_t>(server_port & 0xFF),
        static_cast<uint8_t>((server_port >> 8) & 0xFF)
    };

    DHT_LOG("  [rpc] firewall probe: sending PING_NAT to %zu nodes, server_port=%u\n",
            nodes.size(), server_port);

    // Send PING_NAT from client_socket_ to each node.
    // The remote's PING_NAT handler (rpc_handlers.cpp) reads the port from
    // value and replies to (our_host, server_port) instead of (our_host, client_port).
    for (const auto& node : nodes) {
        messages::Request req;
        req.internal = true;
        req.command = messages::CMD_PING_NAT;
        req.value = value;
        auto buf = messages::encode_request(req);
        auto addr = compact::Ipv4Address::from_string(node.host, node.port);
        udp_send_on(buf, addr, &client_socket_);
    }

    // 5 second timeout
    if (!probe_timer_) {
        probe_timer_ = new uv_timer_t;
        uv_timer_init(loop_, probe_timer_);
        probe_timer_->data = this;
    }
    uv_timer_start(probe_timer_, [](uv_timer_t* t) {
        auto* self = static_cast<RpcSocket*>(t->data);
        if (self) self->finish_firewall_probe();
    }, 5000, 0);
}

void RpcSocket::finish_firewall_probe() {
    if (!firewall_probe_running_) return;
    firewall_probe_running_ = false;
    if (probe_timer_) uv_timer_stop(probe_timer_);

    size_t threshold = probe_threshold();
    bool is_firewalled = probe_replied_hosts_.size() < threshold;

    DHT_LOG("  [rpc] firewall probe: %zu/%zu replied, threshold=%zu → %s\n",
            probe_replied_hosts_.size(), probe_expected_, threshold,
            is_firewalled ? "FIREWALLED" : "NOT FIREWALLED");

    if (is_firewalled) {
        firewalled_ = true;
        // Stay ephemeral — retry on next stable_ticks_ cycle
        return;
    }

    // JS: index.js:950-956 — the fresh probe sampler (fed from the server
    // socket's PING_NAT replies) must agree on host with the main ring
    // sampler, and its observed port must equal the server socket's LOCAL
    // port (the replies only reach us if the NAT preserved that port).
    if (probe_ring_.host().empty() ||
        ring_sampler_.host() != probe_ring_.host()) {
        DHT_LOG("  [rpc] firewall probe: host mismatch (client=%s server=%s) → FIREWALLED\n",
                ring_sampler_.host().c_str(), probe_ring_.host().c_str());
        firewalled_ = true;
        return;
    }

    struct sockaddr_in server_addr{};
    int server_len = sizeof(server_addr);
    udx_socket_getsockname(&server_socket_,
                           reinterpret_cast<struct sockaddr*>(&server_addr), &server_len);
    uint16_t server_local = ntohs(server_addr.sin_port);
    if (probe_ring_.port() == 0 || probe_ring_.port() != server_local) {
        DHT_LOG("  [rpc] firewall probe: port remapped (server local=%u external=%u) → FIREWALLED\n",
                server_local, probe_ring_.port());
        firewalled_ = true;
        return;
    }

    // JS: index.js:837-845 — swap the fresh sampler into `this._nat` so the
    // node ID is computed from the probe-confirmed address.
    ring_sampler_ = probe_ring_;

    // Not firewalled — proceed with persistent transition
    do_persistent_transition();
}

std::vector<routing::Node> RpcSocket::collect_probe_nodes(size_t max) {
    std::vector<routing::Node> out;
    for (size_t i = 0; i < 256 && out.size() < max; i++) {
        for (const auto& n : table_.bucket(i).nodes()) {
            out.push_back(n);
            if (out.size() >= max) return out;
        }
    }
    return out;
}

// The actual ephemeral → persistent transition logic, extracted so both
// the firewall probe callback and force_check_persistent() can use it.
//
// JS: index.js:824 — `this.firewalled = this.io.firewalled = false`
// After the firewall probe succeeds (or we're forced persistent),
// firewalled_ flips to false and all traffic switches to server_socket_.
void RpcSocket::do_persistent_transition() {
    if (!ephemeral_) return;

    ephemeral_ = false;
    firewalled_ = false;  // Probe passed (or forced) → server socket is reachable

    // Rebuild routing table with the address-based ID.
    // JS: index.js:831,854-864 — `peer.id(natSampler.host, natSampler.port)`
    // then create new Table(id), copy nodes, re-bootstrap.
    adopt_address_id_from_ring();

    if (on_persistent_) on_persistent_();
}

// JS: index.js:831 — `peer.id(natSampler.host, natSampler.port)` where
// natSampler is the ring sampler (swapped in by finish_firewall_probe). Reading
// the ring — not the frozen nat_sampler_ — is what lets the node ID track a NAT
// remap after a wakeup re-runs the probe.
void RpcSocket::adopt_address_id_from_ring() {
    auto current_host = ring_sampler_.host();
    if (current_host.empty()) return;  // no confirmed address yet
    auto our_addr = compact::Ipv4Address::from_string(
        current_host, ring_sampler_.port());
    auto new_id = compute_peer_id(our_addr);
    if (new_id != table_.id()) {
        table_.rebuild_with_id(new_id);
    }
}

// JS: index.js:406-432 (`_bootstrap` ondata). See the header comment for the
// full rationale. This is a lone PING_NAT to the first bootstrap responder; its
// reply (matched cross-socket by tid on the server socket) clears `firewalled`
// early — the JS `_updateNetworkState(onlyFirewall)` effect — without flipping
// ephemeral. The reduced/deferred pieces vs JS's full 2-pass bootstrap are
// documented in dht_network.cpp::start_bootstrap_walk.
void RpcSocket::quick_firewall_ping(const compact::Ipv4Address& to) {
#ifdef HYPERDHT_EMBEDDED
    (void)to;  // single-socket build never goes persistent
    return;
#else
    if (quick_firewall_done_) return;
    if (!quick_firewall_ || !firewalled_ || !ephemeral_ || closing_) return;
    quick_firewall_done_ = true;

    // Ask the responder to reply to our SERVER socket's local port (uint16le).
    struct sockaddr_in saddr{};
    int slen = sizeof(saddr);
    udx_socket_getsockname(&server_socket_,
                           reinterpret_cast<struct sockaddr*>(&saddr), &slen);
    uint16_t server_port = ntohs(saddr.sin_port);
    if (server_port == 0) return;

    messages::Request req;
    req.to.addr = to;
    req.command = messages::CMD_PING_NAT;
    req.internal = true;
    req.value = std::vector<uint8_t>{
        static_cast<uint8_t>(server_port & 0xFF),
        static_cast<uint8_t>((server_port >> 8) & 0xFF)
    };

    DHT_LOG("  [rpc] quick-firewall: PING_NAT to %s:%u (reply→server port %u)\n",
            to.host_string().c_str(), to.port, server_port);

    // Sent from client_socket_ (active_socket() while firewalled). A reply on
    // server_socket_ proves the port is reachable → clear firewalled_ (JS
    // index.js:824). retries=3 (JS default). No id: ephemeral node (io.js:521).
    request(req, /*timeout_override_ms=*/0, /*retries=*/DEFAULT_RETRIES,
        [this](const messages::Response&) {
            if (firewalled_) {
                DHT_LOG("  [rpc] quick-firewall: server socket reachable → "
                        "clearing firewalled\n");
                firewalled_ = false;
            }
        },
        nullptr);
#endif
}

// ---------------------------------------------------------------------------
// Adaptive timeout — per-peer RTT tracking (C++ opt-in extension)
//
// JS: .analysis/js/dht-rpc/lib/io.js:78 (this._adt = adaptiveTimeout ? ... : null)
//     .analysis/js/dht-rpc/lib/io.js:116-118 (_adt?.put on response)
//     .analysis/js/dht-rpc/lib/io.js:457-459 (`this.timeout || _adt?.get(...) || 1000`)
//
// IMPORTANT: this does NOT match JS's deployed path. AdaptiveTimeout is only
// built when the `adaptiveTimeout` option is passed to IO (io.js:78), and
// hyperdht never passes it — so the real retransmit timeout is a flat
// `req.timeout || 1000` (see send_now). record_rtt keeps collecting samples
// unconditionally, but timeout_for is consulted only when adaptive_timeout_
// is explicitly enabled — a C++ extension, off by default.
//
// The EMA itself: per-peer `(old*3 + sample + 2) / 4`, timeout = 2x smoothed
// clamped to [200ms, 5000ms]; LRU cap of 1024 entries.
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

// ---------------------------------------------------------------------------
// Session (JS: dht-rpc/lib/session.js)
// ---------------------------------------------------------------------------

uint16_t Session::request(const messages::Request& req,
                          OnResponseCallback on_response,
                          OnTimeoutCallback on_timeout) {
    // Wrap the caller's callbacks so we automatically detach from the
    // session's tid list on completion. Capturing `this` is safe: if
    // the Session is destroyed first it cancels every tid before
    // returning, so the inner callback can never fire against a dead
    // Session.
    auto* self = this;
    auto tid = socket_.request(req,
        [self, on_response = std::move(on_response)](const messages::Response& resp) {
            // Response arrived — detach from session tracker. Use the
            // response's tid for the detach, not a captured value, so
            // we survive congestion-queued sends that allocated a tid
            // later than initial request().
            self->tids_.erase(
                std::remove(self->tids_.begin(), self->tids_.end(), resp.tid),
                self->tids_.end());
            if (on_response) on_response(resp);
        },
        [self, on_timeout = std::move(on_timeout)](uint16_t tid) {
            self->tids_.erase(
                std::remove(self->tids_.begin(), self->tids_.end(), tid),
                self->tids_.end());
            if (on_timeout) on_timeout(tid);
        });
    if (tid != 0) tids_.push_back(tid);
    return tid;
}

void Session::destroy() {
    // Atomically swap out the tid list with an empty one, then iterate
    // the snapshot. This keeps us safe from any callback that might
    // re-enter via cancel_request (cancel_request itself is silent, but
    // `this` is captured in every outstanding request closure we
    // registered — defensive).
    auto local = std::exchange(tids_, {});
    for (auto tid : local) {
        // JS session.js:39-46 — for each still-outstanding request the session
        // does `this.dht.io.congestion.recv()` AND then `req.destroy()` (which
        // itself calls congestion.recv() at io.js:480). We mirror both: the
        // cancel_request → destroy_request path is the second recv(); this is
        // the first. Guarded by cancel success so we only recv() for a request
        // that was actually still tracked (recv() clamps at 0 regardless).
        if (socket_.cancel_request(tid)) {
            socket_.congestion_.recv();
        }
    }
}

}  // namespace rpc
}  // namespace hyperdht
