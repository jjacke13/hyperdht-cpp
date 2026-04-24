// DHT RPC socket implementation — UDP send/receive over a UDX socket,
// TID-based response matching, retries/timeouts, per-peer adaptive RTT,
// congestion control, and NAT probe detection.
//
// JS: .analysis/js/dht-rpc/index.js:32-1003 (DHT class)
//     .analysis/js/dht-rpc/lib/io.js:15-349  (IO class — wire send/recv)
//     .analysis/js/dht-rpc/lib/io.js:351-554 (Request class)
//     .analysis/js/dht-rpc/lib/io.js:556-591 (CongestionWindow class)
//
// C++ diffs from JS:
//   - JS splits responsibilities across DHT (lifecycle, ticking) + IO
//     (sockets, congestion, requests). C++ collapses both into RpcSocket.
//   - Single UDP socket vs JS's two (clientSocket + serverSocket). The
//     PING_NAT firewall probe (JS DHT::_checkIfFirewalled) is therefore
//     not implemented here.
//   - bind() takes an explicit `host` param vs JS's default `0.0.0.0`.
//   - Per-peer RTT stored in `peer_rtt_` map (EMA via record_rtt) vs
//     JS using the `adaptive-timeout` package.
//   - Drain timer fires every 750ms (matches JS io.js:286) handling
//     congestion window rotation + token rotation in one tick.
//   - Background tick at 5s matches JS index.js:18 (TICK_INTERVAL).

#include "hyperdht/rpc.hpp"

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

    // Wire the routing table's bucket-full hook to our ping-and-swap logic.
    // Uses a weak pointer pattern: captured `this` is stable for the table's
    // lifetime (the table is a member of this object).
    table_.on_full([this](size_t idx, const routing::Node& new_node) {
        on_bucket_full(idx, new_node);
    });

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

// JS: io.js:224-228 (bind) + io.js:230-295 (_bindSockets — JS binds two
//     sockets here, server + client. C++ binds just one.)
int RpcSocket::bind(uint16_t port, const std::string& host) {
    struct sockaddr_in addr{};
    // uv_ip4_addr rejects malformed IPv4 strings; pass through the caller's
    // host (JS default "0.0.0.0", but apps may want to bind a specific
    // interface for multi-homed hosts or dev/testing isolation).
    if (uv_ip4_addr(host.c_str(), port, &addr) != 0) return UV_EINVAL;
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

    // Start/restart per-request timeout timer.
    // Custom override wins (DELAYED_PING sets it to delay+grace); else adaptive/default.
    uint64_t timeout = req->timeout_override_ms > 0
                     ? req->timeout_override_ms
                     : timeout_for(req->to);
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
    return request(req, 0, DEFAULT_RETRIES,
                   std::move(on_response), std::move(on_timeout));
}

// JS: io.js:315-348 (createRequest) + io.js:431-445 (Request.send)
//     C++ collapses createRequest+send into one entry point and skips
//     the JS `session` object that detaches/reattaches inflight reqs.
uint16_t RpcSocket::request(const messages::Request& req,
                            uint64_t timeout_override_ms,
                            int retries,
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
    inflight->timeout_override_ms = timeout_override_ms;
    inflight->retries = retries;
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

void RpcSocket::on_recv(udx_socket_t* socket, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr) {
    if (nread <= 0 || addr == nullptr) return;

    auto* self = static_cast<RpcSocket*>(socket->data);
    auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(addr);
    self->handle_message(reinterpret_cast<const uint8_t*>(buf->base),
                         static_cast<size_t>(nread), addr_in);
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

// JS: io.js:83-146 (onmessage). JS rejects 1-byte payloads at io.js:84
// (`buffer.byteLength < 2`). C++ uses 1-byte 0x00 as a holepunch probe
// (matching DHT::onmessage at index.js:153 which only forwards >1 byte
// payloads to io.js — leaving 1-byte for holepunch detection).
void RpcSocket::handle_message(const uint8_t* data, size_t len,
                               const struct sockaddr_in* addr) {
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

        // Validate and observe the peer in the routing table.
        // JS: io.js:392 `from.id = validateId(id, from)` — recomputes
        // peer.id(host, port) and rejects mismatches. Prevents a malicious
        // node from claiming an arbitrary position in our routing table.
        if (req.id.has_value()) {
            auto expected = compute_peer_id(req.from.addr);
            if (*req.id == expected) {
                add_node_from_network(expected, req.from.addr);
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

    // No retries — JS `_repingAndSwap` only sends once, and the retry logic
    // would artificially delay the swap decision.
    request(req, /*timeout_override_ms=*/0, /*retries=*/0,
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

// JS: dht-rpc/index.js:737-762 (_check). Sends a single PING and either
// removes-if-stale on success or removes outright on failure. Used by
// DOWN_HINT and _pingSome.
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

    request(req, /*timeout_override_ms=*/0, /*retries=*/0,
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
//     interval (TICK_INTERVAL). Bumps tick, runs _pingSome every 8th
//     tick, refresh on _refreshTicks expiry, health.update at end.
//     C++ skips JS's wakeup detection (`_lastTick` drift) since we
//     don't have a sleeping interval semantic yet.
// ---------------------------------------------------------------------------

void RpcSocket::on_bg_tick(uv_timer_t* timer) {
    auto* self = static_cast<RpcSocket*>(timer->data);
    if (!self || self->closing_) return;
    self->background_tick();
}

void RpcSocket::background_tick() {
    // Monotonic tick counter — consumed by ping-and-swap / down-hint logic.
    tick_++;

    // 1. Health monitoring. JS emits `network-update` on every
    // `_online()` / `_degraded()` / `_offline()` transition
    // (dht-rpc/index.js:982-1002). We fire `on_health_change_` on any
    // observed state transition so the HyperDHT layer can derive
    // `network-update` from it (see §15 in docs/JS-PARITY-GAPS.md).
    const health::State prev_health = health_.state();
    health_.update(tick_responses_, tick_timeouts_);
    tick_responses_ = 0;
    tick_timeouts_ = 0;
    if (health_.state() != prev_health && on_health_change_) {
        on_health_change_();
    }

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

// JS: dht-rpc/index.js:801-875 (_updateNetworkState). Our version is
// simplified: we trust the NAT sampler's classification rather than
// running a separate PING_NAT firewall probe (JS:916-963 _checkIfFirewalled
// requires the dual-socket setup we don't have).
//
// Idempotency: once `ephemeral_` has flipped to false, this is a no-op.
// The production background tick already guards the call with
// `if (ephemeral_ && --stable_ticks_ <= 0)`, but `force_check_persistent()`
// is publicly callable and the JS parity semantic is "emit once".
// Re-entering after the flip would fire `on_persistent_` a second time.
void RpcSocket::check_persistent() {
    if (!ephemeral_) return;

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

        // Rebuild routing table with address-based ID.
        // JS: index.js:831 — `const id = peer.id(natSampler.host, natSampler.port)`
        // JS: index.js:854-864 — create new Table(id), copy nodes, re-bootstrap.
        auto our_addr = compact::Ipv4Address::from_string(
            current_host, nat_sampler_.port());
        auto new_id = compute_peer_id(our_addr);
        if (new_id != table_.id()) {
            table_.rebuild_with_id(new_id);
        }

        if (on_persistent_) on_persistent_();
    }
}

// ---------------------------------------------------------------------------
// Adaptive timeout — per-peer RTT tracking
//
// JS: .analysis/js/dht-rpc/lib/io.js:78 (this._adt = new AdaptiveTimeout)
//     .analysis/js/dht-rpc/lib/io.js:116-118 (_adt.put on response)
//     .analysis/js/dht-rpc/lib/io.js:457-460 (_adt.get for next timeout)
//
// C++ diffs from JS:
//   - JS uses the `adaptive-timeout` package (per-peer hash table).
//   - We re-implement: per-peer EMA `(old*3 + sample + 2) / 4`,
//     timeout = 2x smoothed clamped to [200ms, 5000ms].
//   - LRU cap of 1024 entries; JS package has its own eviction.
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
        socket_.cancel_request(tid);
    }
}

}  // namespace rpc
}  // namespace hyperdht
