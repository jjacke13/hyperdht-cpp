#include "hyperdht/holepunch.hpp"

#include "hyperdht/debug.hpp"
#include "hyperdht/dht_messages.hpp"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <memory>

namespace hyperdht {
namespace holepunch {

using compact::State;
using compact::Uint;
using compact::Buffer;
using compact::Fixed32;
using compact::Ipv4Addr;
using compact::Ipv4Address;
using compact::Array;

// ---------------------------------------------------------------------------
// SecurePayload
// ---------------------------------------------------------------------------

SecurePayload::SecurePayload(const std::array<uint8_t, 32>& key)
    : shared_secret_(key) {
    // Generate a random local secret for token generation
    randombytes_buf(local_secret_.data(), 32);
}

std::vector<uint8_t> SecurePayload::encrypt(const uint8_t* data, size_t len) {
    // Output: nonce(24) + ciphertext(len + 16)
    std::vector<uint8_t> out(24 + len + crypto_secretbox_MACBYTES);

    // Random nonce
    randombytes_buf(out.data(), 24);

    // Encrypt: crypto_secretbox_easy(cipher, msg, msg_len, nonce, key)
    crypto_secretbox_easy(out.data() + 24,
                          data, len,
                          out.data(),  // nonce
                          shared_secret_.data());
    return out;
}

std::optional<std::vector<uint8_t>> SecurePayload::decrypt(const uint8_t* data, size_t len) {
    if (len < 24 + crypto_secretbox_MACBYTES) return std::nullopt;

    const uint8_t* nonce = data;
    const uint8_t* ciphertext = data + 24;
    size_t ct_len = len - 24;

    std::vector<uint8_t> plaintext(ct_len - crypto_secretbox_MACBYTES);

    int rc = crypto_secretbox_open_easy(plaintext.data(),
                                         ciphertext, ct_len,
                                         nonce,
                                         shared_secret_.data());
    if (rc != 0) return std::nullopt;
    return plaintext;
}

std::array<uint8_t, 32> SecurePayload::token(const std::string& host) {
    std::array<uint8_t, 32> out{};
    crypto_generichash(out.data(), 32,
                       reinterpret_cast<const uint8_t*>(host.data()), host.size(),
                       local_secret_.data(), 32);
    return out;
}

// ---------------------------------------------------------------------------
// HolepunchPayload encoding
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_holepunch_payload(const HolepunchPayload& p) {
    uint32_t flags = 0;
    if (p.connected) flags |= 1;
    if (p.punching) flags |= 2;
    if (!p.addresses.empty()) flags |= 4;
    if (p.remote_address.has_value()) flags |= 8;
    if (p.token.has_value()) flags |= 16;
    if (p.remote_token.has_value()) flags |= 32;

    State state;
    Uint::preencode(state, flags);
    Uint::preencode(state, p.error);
    Uint::preencode(state, p.firewall);
    Uint::preencode(state, p.round);
    if (!p.addresses.empty()) {
        Array<Ipv4Addr, Ipv4Address>::preencode(state, p.addresses);
    }
    if (p.remote_address.has_value()) Ipv4Addr::preencode(state, *p.remote_address);
    if (p.token.has_value()) Fixed32::preencode(state, *p.token);
    if (p.remote_token.has_value()) Fixed32::preencode(state, *p.remote_token);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, flags);
    Uint::encode(state, p.error);
    Uint::encode(state, p.firewall);
    Uint::encode(state, p.round);
    if (!p.addresses.empty()) {
        Array<Ipv4Addr, Ipv4Address>::encode(state, p.addresses);
    }
    if (p.remote_address.has_value()) Ipv4Addr::encode(state, *p.remote_address);
    if (p.token.has_value()) Fixed32::encode(state, *p.token);
    if (p.remote_token.has_value()) Fixed32::encode(state, *p.remote_token);

    return buf;
}

HolepunchPayload decode_holepunch_payload(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    HolepunchPayload p;

    uint32_t flags = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;

    p.connected = (flags & 1) != 0;
    p.punching = (flags & 2) != 0;
    p.error = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;
    p.firewall = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;
    p.round = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;

    if (flags & 4) {
        p.addresses = Array<Ipv4Addr, Ipv4Address>::decode(state);
        if (state.error) return p;
    }
    if (flags & 8) {
        p.remote_address = Ipv4Addr::decode(state);
        if (state.error) return p;
    }
    if (flags & 16) {
        p.token = Fixed32::decode(state);
        if (state.error) return p;
    }
    if (flags & 32) {
        p.remote_token = Fixed32::decode(state);
        if (state.error) return p;
    }

    return p;
}

// ---------------------------------------------------------------------------
// OPEN firewall shortcut
// ---------------------------------------------------------------------------

bool try_direct_connect(const peer_connect::HandshakeResult& hs,
                        HolepunchResult& result) {
    if (!hs.success) return false;

    // If remote firewall is OPEN, we can connect directly
    if (hs.remote_payload.firewall == peer_connect::FIREWALL_OPEN) {
        if (!hs.remote_payload.addresses4.empty()) {
            result.success = true;
            result.address = hs.remote_payload.addresses4[0];
            result.firewall = peer_connect::FIREWALL_OPEN;
            return true;
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// Holepuncher
// ---------------------------------------------------------------------------

Holepuncher::Holepuncher(uv_loop_t* loop, bool is_initiator)
    : loop_(loop), is_initiator_(is_initiator) {
    punch_timer_ = new uv_timer_t;
    uv_timer_init(loop, punch_timer_);
    punch_timer_->data = this;
}

Holepuncher::~Holepuncher() {
    stop();
    if (punch_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        // Timer outlives us — null the back-pointer so callbacks don't dereference
        punch_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(punch_timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        punch_timer_ = nullptr;
    }
}

void Holepuncher::close(std::function<void()> on_closed) {
    stop();
    closing_ = true;
    if (!punch_timer_ || uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        if (on_closed) on_closed();
        return;
    }

    struct CloseCtx { std::function<void()> cb; };
    auto* ctx = new CloseCtx{std::move(on_closed)};
    punch_timer_->data = ctx;

    uv_close(reinterpret_cast<uv_handle_t*>(punch_timer_), [](uv_handle_t* h) {
        auto* ctx = static_cast<CloseCtx*>(reinterpret_cast<uv_timer_t*>(h)->data);
        if (ctx) {
            if (ctx->cb) ctx->cb();
            delete ctx;
        }
        delete reinterpret_cast<uv_timer_t*>(h);
    });
    punch_timer_ = nullptr;
}

bool Holepuncher::punch() {
    using namespace peer_connect;

    if (connected_) return true;

    // Determine strategy based on firewall combo.
    // Treat UNKNOWN as CONSISTENT — we don't know our NAT type yet, but
    // the standard 10-round probe is the safest default.
    bool local_consistent = (local_firewall_ != FIREWALL_RANDOM);
    bool remote_consistent = (remote_firewall_ != FIREWALL_RANDOM);

    if (local_consistent && remote_consistent) {
        // CONSISTENT+CONSISTENT or OPEN+CONSISTENT: 10 rounds, 1s apart
        punching_ = true;
        punch_round_ = 0;
        consistent_probe();
        return true;
    }

    if (local_consistent && remote_firewall_ == FIREWALL_RANDOM) {
        // CONSISTENT+RANDOM: 1750 probes to random ports
        punching_ = true;
        random_probes_left_ = 1750;
        random_probes();
        return true;
    }

    if (local_firewall_ == FIREWALL_RANDOM && remote_consistent) {
        // RANDOM+CONSISTENT: would need birthday sockets
        // Simplified: try consistent probe (may work if NAT is somewhat predictable)
        punching_ = true;
        punch_round_ = 0;
        consistent_probe();
        return true;
    }

    // RANDOM+RANDOM: impossible
    return false;
}

void Holepuncher::stop() {
    punching_ = false;
    if (punch_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        uv_timer_stop(punch_timer_);
    }
}

void Holepuncher::send_probe(const compact::Ipv4Address& addr) {
    if (send_fn_) {
        DHT_LOG("  [hp] Sending probe to %s:%u\n",
                addr.host_string().c_str(), addr.port);
        send_fn_(addr);
    }
}

void Holepuncher::open_session(const compact::Ipv4Address& addr) {
    if (send_ttl_fn_) {
        DHT_LOG("  [hp] openSession (TTL=5) to %s:%u\n",
                addr.host_string().c_str(), addr.port);
        send_ttl_fn_(addr, 5);  // HOLEPUNCH_TTL = 5
    }
}

void Holepuncher::on_message(const compact::Ipv4Address& from, udx_socket_t* recv_socket) {
    DHT_LOG("  [hp] PROBE RECEIVED from %s:%u!\n",
            from.host_string().c_str(), from.port);
    if (connected_) return;

    // JS: non-initiator echoes probe back, does NOT set connected (holepuncher.js:125-128)
    if (!is_initiator_) {
        send_probe(from);
        return;
    }

    // Initiator: probe echo received → connection established
    connected_ = true;
    punching_ = false;
    if (punch_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        uv_timer_stop(punch_timer_);
    }

    auto cb = std::move(on_connect_);
    if (cb) {
        HolepunchResult result;
        result.success = true;
        result.address = from;
        result.firewall = remote_firewall_;
        result.socket = recv_socket;  // JS: onconnect(ref.socket, port, host)
        cb(result);
    }
}

// ---------------------------------------------------------------------------
// CONSISTENT+CONSISTENT: 10 rounds, 1s apart
// ---------------------------------------------------------------------------

void Holepuncher::consistent_probe() {
    if (!punching_ || connected_ || punch_round_ >= 10) {
        if (punching_ && !connected_) {
            punching_ = false;
        }
        return;
    }

    // JS: non-initiator waits 1s before first round (holepuncher.js:217)
    // Gives initiator's openSession time to prime NAT
    if (!is_initiator_ && punch_round_ == 0) {
        punch_round_++;
        uv_timer_start(punch_timer_, on_punch_timer, 1000, 0);
        return;
    }

    // Send probes, filtering unverified addrs (JS: holepuncher.js:224)
    for (const auto& ra : remote_addresses_) {
        if (!ra.verified && (punch_round_ & 3) != 0) continue;
        if (ra.addr.port == 0) continue;
        send_probe(ra.addr);
    }

    punch_round_++;
    uv_timer_start(punch_timer_, on_punch_timer, 1000, 0);
}

// ---------------------------------------------------------------------------
// CONSISTENT+RANDOM: 1750 probes to random ports, 20ms apart
// ---------------------------------------------------------------------------

void Holepuncher::random_probes() {
    if (!punching_ || connected_) return;
    if (random_probes_left_ <= 0) {
        punching_ = false;  // Exhausted — stop, don't fall through to consistent_probe
        return;
    }

    // Send probe to a random port on the remote host
    if (!remote_addresses_.empty()) {
        auto addr = remote_addresses_[0].addr;
        // Random port between 1000-65535
        uint16_t random_port = static_cast<uint16_t>(1000 + randombytes_uniform(64536));
        auto probe_addr = Ipv4Address::from_string(addr.host_string(), random_port);
        send_probe(probe_addr);
    }

    random_probes_left_--;

    // Schedule next probe in 20ms
    uv_timer_start(punch_timer_, on_punch_timer, 20, 0);
}

void Holepuncher::on_punch_timer(uv_timer_t* timer) {
    auto* self = static_cast<Holepuncher*>(timer->data);
    if (!self) return;

    if (self->random_probes_left_ > 0) {
        self->random_probes();
    } else {
        self->consistent_probe();
    }
}

// ---------------------------------------------------------------------------
// PoolSocket — lightweight UDP socket for holepunch probing
// ---------------------------------------------------------------------------

PoolSocket::PoolSocket(uv_loop_t* loop, udx_t* udx)
    : loop_(loop) {
    udx_socket_init(udx, &socket_, nullptr);
    socket_.data = this;
    next_tid_ = static_cast<uint16_t>(randombytes_uniform(0xFFFF));
}

PoolSocket::~PoolSocket() {
    if (!closing_) close();
}

int PoolSocket::bind() {
    struct sockaddr_in addr{};
    uv_ip4_addr("0.0.0.0", 0, &addr);
    int rc = udx_socket_bind(&socket_, reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (rc == 0) {
        bound_ = true;
        udx_socket_recv_start(&socket_, on_recv);
    }
    return rc;
}

void PoolSocket::on_recv(udx_socket_t* s, ssize_t nread,
                          const uv_buf_t* buf, const struct sockaddr* addr) {
    if (nread <= 0 || !addr) return;
    auto* self = static_cast<PoolSocket*>(s->data);
    if (!self || self->closing_) return;
    self->handle_message(reinterpret_cast<const uint8_t*>(buf->base),
                         static_cast<size_t>(nread),
                         reinterpret_cast<const struct sockaddr_in*>(addr));
}

void PoolSocket::handle_message(const uint8_t* data, size_t len,
                                 const struct sockaddr_in* addr) {
    char host[INET_ADDRSTRLEN];
    uv_ip4_name(addr, host, sizeof(host));
    DHT_LOG("  [pool] Recv %zu bytes from %s:%u (type=0x%02x)\n",
            len, host, ntohs(addr->sin_port), len > 0 ? data[0] : 0);

    // 1-byte probe → holepunch callback
    if (len == 1 && data[0] == 0x00) {
        if (on_probe_) {
            char host[INET_ADDRSTRLEN];
            uv_ip4_name(addr, host, sizeof(host));
            auto from = Ipv4Address::from_string(host, ntohs(addr->sin_port));
            on_probe_(from);
        }
        return;
    }

    // Try to decode as RPC message
    if (len < 2) return;
    messages::Request req;
    messages::Response resp;
    auto type = messages::decode_message(data, len, req, resp);

    if (type == messages::RESPONSE_ID) {
        // Feed NAT sampler: resp.from.addr = wire `to` field = our external address
        char host[INET_ADDRSTRLEN];
        uv_ip4_name(addr, host, sizeof(host));
        auto remote_addr = Ipv4Address::from_string(host, ntohs(addr->sin_port));
        nat_sampler_.add(resp.from.addr, remote_addr);

        // Match TID → call response callback
        for (auto it = inflight_.begin(); it != inflight_.end(); ++it) {
            if ((*it)->tid == resp.tid) {
                auto* inf = *it;
                inflight_.erase(it);
                if (inf->timer) {
                    uv_timer_stop(inf->timer);
                    uv_close(reinterpret_cast<uv_handle_t*>(inf->timer),
                             [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
                }
                auto cb = std::move(inf->on_response);
                delete inf;
                if (cb) cb(resp);
                return;
            }
        }
    }
}

void PoolSocket::request(const messages::Request& req,
                          rpc::OnResponseCallback on_response,
                          rpc::OnTimeoutCallback on_timeout) {
    auto* inf = new Inflight;
    inf->tid = next_tid_++;
    inf->on_response = std::move(on_response);
    inf->on_timeout = std::move(on_timeout);

    // Encode request with our TID
    messages::Request msg = req;
    msg.tid = inf->tid;
    auto buf = messages::encode_request(msg);

    // Send from pool socket
    struct SendCtx {
        udx_socket_send_t req{};
        std::vector<uint8_t> buf;
    };
    auto* ctx = new SendCtx;
    ctx->buf = std::move(buf);
    ctx->req.data = ctx;
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                    static_cast<unsigned int>(ctx->buf.size()));
    struct sockaddr_in dest{};
    uv_ip4_addr(req.to.addr.host_string().c_str(), req.to.addr.port, &dest);
    DHT_LOG("  [pool] Sending request (tid=%u, cmd=%u, %zu bytes) to %s:%u\n",
            inf->tid, msg.command, ctx->buf.size(),
            req.to.addr.host_string().c_str(), req.to.addr.port);
    int rc = udx_socket_send(&ctx->req, &socket_, &uv_buf, 1,
                    reinterpret_cast<const struct sockaddr*>(&dest),
                    [](udx_socket_send_t* r, int status) {
                        if (status < 0) {
                            DHT_LOG("  [pool] Send failed: %d\n", status);
                        }
                        delete static_cast<SendCtx*>(r->data);
                    });
    if (rc < 0) {
        DHT_LOG("  [pool] udx_socket_send returned: %d\n", rc);
    }

    // Timeout (2s, no retries — matches JS {retry: false})
    inf->timer = new uv_timer_t;
    uv_timer_init(loop_, inf->timer);
    inf->timer->data = inf;
    uv_timer_start(inf->timer, [](uv_timer_t* t) {
        auto* inf = static_cast<Inflight*>(t->data);
        auto timeout_cb = std::move(inf->on_timeout);
        uv_close(reinterpret_cast<uv_handle_t*>(t),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        uint16_t tid = inf->tid;
        delete inf;
        if (timeout_cb) timeout_cb(tid);
    }, 2000, 0);

    inflight_.push_back(inf);
}

void PoolSocket::send_probe(const Ipv4Address& to) {
    if (closing_) return;
    struct SendCtx {
        udx_socket_send_t req{};
        uint8_t buf = 0x00;
    };
    auto* ctx = new SendCtx;
    ctx->req.data = ctx;
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(&ctx->buf), 1);
    struct sockaddr_in dest{};
    uv_ip4_addr(to.host_string().c_str(), to.port, &dest);
    udx_socket_send(&ctx->req, &socket_, &uv_buf, 1,
                    reinterpret_cast<const struct sockaddr*>(&dest),
                    [](udx_socket_send_t* r, int) {
                        delete static_cast<SendCtx*>(r->data);
                    });
}

void PoolSocket::send_probe_ttl(const Ipv4Address& to, int ttl) {
    if (closing_) return;
    struct SendCtx {
        udx_socket_send_t req{};
        uint8_t buf = 0x00;
    };
    auto* ctx = new SendCtx;
    ctx->req.data = ctx;
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(&ctx->buf), 1);
    struct sockaddr_in dest{};
    uv_ip4_addr(to.host_string().c_str(), to.port, &dest);
    udx_socket_send_ttl(&ctx->req, &socket_, &uv_buf, 1,
                        reinterpret_cast<const struct sockaddr*>(&dest), ttl,
                        [](udx_socket_send_t* r, int) {
                            delete static_cast<SendCtx*>(r->data);
                        });
}

void PoolSocket::close() {
    if (closing_) return;
    closing_ = true;
    socket_.data = nullptr;
    // Clean up inflight
    for (auto* inf : inflight_) {
        if (inf->timer) {
            uv_timer_stop(inf->timer);
            uv_close(reinterpret_cast<uv_handle_t*>(inf->timer),
                     [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        }
        delete inf;
    }
    inflight_.clear();
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&socket_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&socket_), nullptr);
    }
}

// ---------------------------------------------------------------------------
// discover_pool_addresses — PING DHT nodes from pool socket for NAT discovery
// ---------------------------------------------------------------------------

void discover_pool_addresses(
    PoolSocket& pool,
    const routing::RoutingTable& table,
    const compact::Ipv4Address& relay_addr,
    std::function<void(bool)> on_done) {

    struct DiscoverCtx {
        PoolSocket* pool;
        std::function<void(bool)> on_done;
        int pending = 0;
        bool done = false;
    };
    auto ctx = std::make_shared<DiscoverCtx>();
    ctx->pool = &pool;
    ctx->on_done = std::move(on_done);

    auto finish = [ctx]() {
        if (ctx->done) return;
        if (--ctx->pending <= 0) {
            ctx->done = true;
            bool ok = ctx->pool->nat_sampler().sampled() >= 2;
            if (ctx->on_done) ctx->on_done(ok);
        }
    };

    // Pick up to 5 DHT nodes for PING (JS: nat.autoSample with 4+ nodes)
    std::vector<compact::Ipv4Address> targets;
    targets.push_back(relay_addr);

    // Use routing table nodes if available
    auto closest = table.closest(routing::NodeId{}, 20);
    int skip = closest.size() >= 8 ? 5 : 0;
    for (size_t i = skip; i < closest.size() && targets.size() < 5; i++) {
        targets.push_back(Ipv4Address::from_string(closest[i]->host, closest[i]->port));
    }

    // Fallback: use bootstrap nodes when routing table is sparse
    if (targets.size() < 4) {
        static const char* bootstrap[] = {
            "88.99.3.86", "142.93.90.113", "138.68.147.8"  // Public HyperDHT bootstrap
        };
        for (const auto& host : bootstrap) {
            if (targets.size() >= 5) break;
            targets.push_back(Ipv4Address::from_string(host, 49737));
        }
    }

    ctx->pending = static_cast<int>(targets.size()) + 1;  // +1 for initial decrement

    for (const auto& target : targets) {
        messages::Request ping;
        ping.command = messages::CMD_PING;
        ping.internal = true;
        ping.to.addr = target;

        pool.request(ping,
            [ctx, finish](const messages::Response&) { finish(); },
            [ctx, finish](uint16_t) { finish(); });
    }

    finish();  // Decrement initial +1
}

// ---------------------------------------------------------------------------
// PEER_HOLEPUNCH message encoding
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_holepunch_msg(const HolepunchMessage& m) {
    State state;
    uint8_t flags = m.peer_address.has_value() ? 1 : 0;
    Uint::preencode(state, flags);
    Uint::preencode(state, m.mode);
    Uint::preencode(state, m.id);
    Buffer::preencode(state, m.payload.data(), m.payload.size());
    if (m.peer_address.has_value()) Ipv4Addr::preencode(state, *m.peer_address);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, flags);
    Uint::encode(state, m.mode);
    Uint::encode(state, m.id);
    Buffer::encode(state, m.payload.data(), m.payload.size());
    if (m.peer_address.has_value()) Ipv4Addr::encode(state, *m.peer_address);

    return buf;
}

HolepunchMessage decode_holepunch_msg(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    HolepunchMessage m;

    uint8_t flags = static_cast<uint8_t>(Uint::decode(state));
    if (state.error) return m;
    m.mode = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return m;
    m.id = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return m;

    auto payload_result = Buffer::decode(state);
    if (state.error) return m;
    if (!payload_result.is_null()) {
        m.payload.assign(payload_result.data, payload_result.data + payload_result.len);
    }

    if (flags & 1) {
        m.peer_address = Ipv4Addr::decode(state);
    }
    return m;
}

// ---------------------------------------------------------------------------
// PunchState — shared state for the async holepunch flow
// ---------------------------------------------------------------------------

namespace {

constexpr uint64_t HOLEPUNCH_TIMEOUT_MS = 15000;  // 15 seconds overall

struct PunchState {
    std::shared_ptr<SecurePayload> secure;
    std::shared_ptr<Holepuncher> puncher;
    std::shared_ptr<PoolSocket> pool;  // JS: dht._socketPool.acquire()
    OnHolepunchCallback on_done;
    rpc::RpcSocket* socket = nullptr;
    uv_timer_t* timeout = nullptr;
    bool completed = false;
    int round = 0;
    bool retried_unknown = false;

    void complete(const HolepunchResult& result) {
        if (completed) return;
        completed = true;

        if (puncher) puncher->stop();

        // Close pool socket
        if (pool) pool->close();

        // Clear probe listener on main socket
        if (socket) socket->on_holepunch_probe(nullptr);

        // Stop and close timeout timer
        if (timeout && !uv_is_closing(reinterpret_cast<uv_handle_t*>(timeout))) {
            uv_timer_stop(timeout);
            timeout->data = nullptr;
            uv_close(reinterpret_cast<uv_handle_t*>(timeout),
                     [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
            timeout = nullptr;
        }

        auto cb = std::move(on_done);
        if (cb) cb(result);
    }
};

}  // anonymous namespace

// ---------------------------------------------------------------------------
// holepunch_connect — full 2-round relay + UDP probe flow
// ---------------------------------------------------------------------------

void holepunch_connect(rpc::RpcSocket& socket,
                       const peer_connect::HandshakeResult& hs_result,
                       const compact::Ipv4Address& relay_addr,
                       const compact::Ipv4Address& peer_addr,
                       uint32_t holepunch_id,
                       uint32_t local_firewall,
                       const std::vector<compact::Ipv4Address>& local_addresses,
                       OnHolepunchCallback on_done) {

    // Derive holepunchSecret from handshake hash
    // holepunchSecret = BLAKE2b-256(NS_PEER_HOLEPUNCH, key=handshake_hash)
    const auto& ns_hp = dht_messages::ns_peer_holepunch();
    std::array<uint8_t, 32> holepunch_secret{};
    crypto_generichash(holepunch_secret.data(), 32,
                       ns_hp.data(), 32,
                       hs_result.handshake_hash.data(), 64);

    auto state = std::make_shared<PunchState>();
    state->secure = std::make_shared<SecurePayload>(holepunch_secret);
    state->on_done = std::move(on_done);
    state->socket = &socket;

    // Create pool socket (JS: dht._socketPool.acquire())
    state->pool = std::make_shared<PoolSocket>(socket.loop(), socket.udx_handle());
    state->pool->bind();

    // Compute target hash (reused for both rounds)
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32,
                       hs_result.remote_public_key.data(), 32,
                       nullptr, 0);

    // Discover pool socket's external address via PINGs (JS: nat.autoSample())
    discover_pool_addresses(*state->pool, socket.table(), relay_addr,
        [state, &socket, target, relay_addr, peer_addr, holepunch_id,
         local_firewall, local_addresses](bool addr_ok) {

        if (state->completed) return;

        // Use pool socket's discovered addresses if available, else fall back to main
        auto pool_addrs = state->pool->addresses();
        auto& addrs = pool_addrs.empty() ? local_addresses : pool_addrs;

        DHT_LOG("  [hp] Pool NAT: fw=%u, %zu addrs (discovered=%s)\n",
                state->pool->nat_sampler().firewall(), pool_addrs.size(),
                addr_ok ? "yes" : "no");

    // -----------------------------------------------------------------------
    // Round 1: probe exchange — send our firewall info, get server's
    // -----------------------------------------------------------------------
    HolepunchPayload probe;
    probe.error = peer_connect::ERROR_NONE;
    probe.firewall = local_firewall;
    probe.round = 0;
    probe.addresses = addrs;
    probe.remote_address = peer_addr;

    auto probe_bytes = encode_holepunch_payload(probe);
    auto encrypted_probe = state->secure->encrypt(probe_bytes.data(), probe_bytes.size());

    HolepunchMessage hp_msg;
    hp_msg.mode = peer_connect::MODE_FROM_CLIENT;
    hp_msg.id = holepunch_id;
    hp_msg.payload = std::move(encrypted_probe);
    hp_msg.peer_address = peer_addr;

    messages::Request req;
    req.to.addr = relay_addr;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.target = target;
    req.value = encode_holepunch_msg(hp_msg);

    DHT_LOG( "  [hp] Sending round 1 to relay %s:%u (id=%u, peer=%s:%u)\n",
            relay_addr.host_string().c_str(), relay_addr.port,
            holepunch_id,
            peer_addr.host_string().c_str(), peer_addr.port);

    // Send Round 1 from MAIN socket — the relay must see the same address
    // as the handshake so the server's rawStream can reach us. Pool socket
    // is used for probes only.
    socket.request(req,
        [state, &socket, relay_addr, peer_addr, holepunch_id, target, local_firewall]
        (const messages::Response& resp) {
            if (state->completed) return;

            if (!resp.value.has_value() || resp.value->empty()) {
                DHT_LOG( "  [hp] Round 1: no response value\n");
                state->complete({});
                return;
            }
            DHT_LOG( "  [hp] Round 1: got response (%zu bytes)\n",
                    resp.value->size());

            auto hp_resp = decode_holepunch_msg(resp.value->data(), resp.value->size());
            if (hp_resp.payload.empty()) {
                DHT_LOG( "  [hp] Round 1: empty payload in decoded msg\n");
                state->complete({});
                return;
            }
            DHT_LOG( "  [hp] Round 1: payload %zu bytes, peerAddr=%s\n",
                    hp_resp.payload.size(),
                    hp_resp.peer_address.has_value()
                        ? (hp_resp.peer_address->host_string() + ":" +
                           std::to_string(hp_resp.peer_address->port)).c_str()
                        : "none");

            // Decrypt server's round 1 response
            auto decrypted = state->secure->decrypt(
                hp_resp.payload.data(), hp_resp.payload.size());
            if (!decrypted) {
                DHT_LOG( "  [hp] Round 1: decrypt FAILED\n");
                // Decrypt failed — use peerAddress from relay as fallback
                if (hp_resp.peer_address.has_value()) {
                    HolepunchResult result;
                    result.success = true;
                    result.address = *hp_resp.peer_address;
                    state->complete(result);
                }  else {
                    state->complete({});
                }
                return;
            }

            auto server_r1 = decode_holepunch_payload(decrypted->data(), decrypted->size());
            DHT_LOG( "  [hp] Round 1 server: fw=%u err=%u round=%u "
                    "addrs=%zu punching=%d connected=%d token=%s\n",
                    server_r1.firewall, server_r1.error, server_r1.round,
                    server_r1.addresses.size(),
                    server_r1.punching ? 1 : 0, server_r1.connected ? 1 : 0,
                    server_r1.token.has_value() ? "yes" : "no");

            if (server_r1.error != peer_connect::ERROR_NONE) {
                DHT_LOG( "  [hp] Round 1: server error %u\n", server_r1.error);
                state->complete({});
                return;
            }

            // JS: if remote firewall is UNKNOWN AND both sides would be
            // unknown/random, abort. If only remote is UNKNOWN, treat as
            // CONSISTENT (optimistic) — the server may not have sampled
            // enough yet but is likely reachable.
            uint32_t effective_remote_fw = server_r1.firewall;
            if (effective_remote_fw == peer_connect::FIREWALL_UNKNOWN) {
                DHT_LOG("  [hp] Server firewall UNKNOWN, treating as CONSISTENT\n");
                effective_remote_fw = peer_connect::FIREWALL_CONSISTENT;
            }

            // JS: abort if both sides are RANDOM (impossible to punch)
            if (effective_remote_fw >= peer_connect::FIREWALL_RANDOM &&
                local_firewall >= peer_connect::FIREWALL_RANDOM) {
                DHT_LOG("  [hp] Both sides RANDOM — cannot holepunch\n");
                state->complete({});
                return;
            }

            // Collect server's addresses (from payload + relay peerAddress)
            std::vector<Ipv4Address> server_addrs = server_r1.addresses;
            if (hp_resp.peer_address.has_value()) {
                server_addrs.push_back(*hp_resp.peer_address);
            }
            for (size_t i = 0; i < server_addrs.size(); i++) {
                DHT_LOG("  [hp] Server addr[%zu]: %s:%u\n", i,
                        server_addrs[i].host_string().c_str(), server_addrs[i].port);
            }
            if (server_addrs.empty()) {
                state->complete({});
                return;
            }

            // If server is OPEN, direct connect — no probing needed
            if (server_r1.firewall == peer_connect::FIREWALL_OPEN) {
                HolepunchResult result;
                result.success = true;
                result.firewall = peer_connect::FIREWALL_OPEN;
                result.address = server_addrs[0];
                state->complete(result);
                return;
            }

            // -------------------------------------------------------------------
            // Set up the Holepuncher
            // -------------------------------------------------------------------
            auto puncher = std::make_shared<Holepuncher>(socket.loop(), true);
            puncher->set_local_firewall(local_firewall);
            puncher->set_remote_firewall(effective_remote_fw);
            // Use update_remote with first address verified (from relay)
            std::string verified_host;
            if (!server_addrs.empty()) verified_host = server_addrs[0].host_string();
            puncher->update_remote(server_addrs, verified_host);

            // Send probes from BOTH main socket and pool socket.
            // Main socket: opens CGNAT mapping so server's probes to our
            // main address (from relay) get through.
            // Pool socket: creates secondary mapping for the pool address.
            puncher->set_send_fn([state, &socket](const Ipv4Address& addr) {
                socket.send_probe(addr);  // Main socket — opens CGNAT for server
                if (state->pool) state->pool->send_probe(addr);  // Pool socket
            });
            puncher->set_send_ttl_fn([state, &socket](const Ipv4Address& addr, int ttl) {
                socket.send_probe_ttl(addr, ttl);
                if (state->pool) state->pool->send_probe_ttl(addr, ttl);
            });

            puncher->on_connect([state](const HolepunchResult& result) {
                state->complete(result);
            });

            state->puncher = puncher;

            // Listen for probes on BOTH pool socket and main socket.
            // Pass the receiving socket so UDX connect uses the right one.
            state->pool->on_holepunch_probe([state](const Ipv4Address& from) {
                if (state->puncher) state->puncher->on_message(from,
                    state->pool ? state->pool->socket_handle() : nullptr);
            });
            socket.on_holepunch_probe([state, &socket](const Ipv4Address& from) {
                if (state->puncher) state->puncher->on_message(from, socket.socket_handle());
            });

            // Start overall timeout
            auto* timer = new uv_timer_t;
            uv_timer_init(socket.loop(), timer);
            auto timeout_state = state;  // prevent shared_ptr from dying
            timer->data = new std::shared_ptr<PunchState>(timeout_state);
            state->timeout = timer;

            uv_timer_start(timer, [](uv_timer_t* t) {
                auto* sp = static_cast<std::shared_ptr<PunchState>*>(t->data);
                if (sp && *sp) {
                    (*sp)->complete({});  // Timeout — fail
                }
                delete sp;
                t->data = nullptr;
            }, HOLEPUNCH_TIMEOUT_MS, 0);

            // -------------------------------------------------------------------
            // Round 2: punch exchange — tell server to start probing
            // -------------------------------------------------------------------

            // Our public address from relay response `to` field. Since Round 1
            // was sent from the pool socket, this is the POOL socket's external
            // address — exactly what the server needs to probe.
            Ipv4Address our_addr = resp.from.addr;
            DHT_LOG("  [hp] Our pool address (from relay): %s:%u\n",
                    our_addr.host_string().c_str(), our_addr.port);

            HolepunchPayload punch;
            punch.error = peer_connect::ERROR_NONE;
            punch.firewall = local_firewall;
            punch.round = 1;
            punch.punching = true;
            punch.addresses.push_back(our_addr);

            // Generate our token for address verification
            punch.token = state->secure->token(server_addrs[0].host_string());
            // Echo back the server's token
            if (server_r1.token.has_value()) {
                punch.remote_token = server_r1.token;
            }

            auto punch_bytes = encode_holepunch_payload(punch);
            auto encrypted_punch = state->secure->encrypt(
                punch_bytes.data(), punch_bytes.size());

            HolepunchMessage hp_msg2;
            hp_msg2.mode = peer_connect::MODE_FROM_CLIENT;
            hp_msg2.id = holepunch_id;
            hp_msg2.payload = std::move(encrypted_punch);
            hp_msg2.peer_address = peer_addr;

            messages::Request req2;
            req2.to.addr = relay_addr;
            req2.command = messages::CMD_PEER_HOLEPUNCH;
            req2.target = target;
            req2.value = encode_holepunch_msg(hp_msg2);

            DHT_LOG( "  [hp] Sending round 2 (punching=true) to %s:%u\n",
                    relay_addr.host_string().c_str(), relay_addr.port);

            // Send Round 2 from MAIN socket (same address as handshake)
            socket.request(req2,
                [state, puncher, server_addrs](const messages::Response& r2resp) {
                    if (state->completed) return;

                    // Decode round 2 response to check for errors
                    bool server_punching = false;
                    if (r2resp.value.has_value() && !r2resp.value->empty()) {
                        auto r2_msg = decode_holepunch_msg(
                            r2resp.value->data(), r2resp.value->size());
                        if (!r2_msg.payload.empty()) {
                            auto r2_dec = state->secure->decrypt(
                                r2_msg.payload.data(), r2_msg.payload.size());
                            if (r2_dec) {
                                auto r2_pay = decode_holepunch_payload(
                                    r2_dec->data(), r2_dec->size());
                                DHT_LOG(
                                    "  [hp] Round 2 server: fw=%u err=%u "
                                    "punching=%d connected=%d addrs=%zu\n",
                                    r2_pay.firewall, r2_pay.error,
                                    r2_pay.punching ? 1 : 0,
                                    r2_pay.connected ? 1 : 0,
                                    r2_pay.addresses.size());

                                if (r2_pay.error != peer_connect::ERROR_NONE) {
                                    state->complete({});
                                    return;
                                }
                                server_punching = r2_pay.punching;
                            }
                        }
                    }

                    // JS: openSession before punching (connect.js:557)
                    // Prime NAT with low-TTL probe
                    if (!server_addrs.empty()) {
                        puncher->open_session(server_addrs[0]);
                    }

                    // Start probing. Wait for incoming probe echo from server
                    // (JS: onconnect fires when probe arrives).
                    puncher->punch();
                },
                [state, puncher](uint16_t) {
                    DHT_LOG( "  [hp] Round 2: TIMEOUT\n");
                    // Round 2 relay timeout — still start probing.
                    // The puncher on_connect or overall timeout handles completion.
                    if (!state->completed) {
                        puncher->punch();
                    }
                });
        },
        [state](uint16_t) {
            DHT_LOG( "  [hp] Round 1: TIMEOUT (no response from relay)\n");
            state->complete({});
        });
    });  // end discover_pool_addresses callback
}

}  // namespace holepunch
}  // namespace hyperdht
