// Socket pool implementation — reusable UDX sockets for holepunching.
// Matches JS socket-pool.js: bind/release by stable key, with idle
// timeout cleanup and refcount tracking.

#include "hyperdht/socket_pool.hpp"

#include <cstring>

namespace hyperdht {
namespace socket_pool {

// ---------------------------------------------------------------------------
// Hex helper
// ---------------------------------------------------------------------------

std::string SocketPool::key_hex(const std::array<uint8_t, 32>& key) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (auto b : key) {
        out.push_back(h[b >> 4]);
        out.push_back(h[b & 0x0F]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// SocketRef
// ---------------------------------------------------------------------------

SocketRef::SocketRef(SocketPool& pool, uv_loop_t* loop, udx_t* udx,
                     const std::string& host)
    : pool_(pool), loop_(loop) {
    udx_socket_init(udx, &socket_, on_socket_close);
    socket_.data = this;

    udx_socket_recv_start(&socket_, on_message);

    struct sockaddr_in addr;
    uv_ip4_addr(host.c_str(), 0, &addr);
    udx_socket_bind(&socket_, reinterpret_cast<const struct sockaddr*>(&addr), 0);

    pool_.add(this);
}

SocketRef::~SocketRef() {
    unlinger();
}

void SocketRef::active() {
    refs_++;
    unlinger();
}

void SocketRef::inactive() {
    refs_--;
    close_maybe();
}

void SocketRef::release() {
    if (released_) return;
    released_ = true;
    on_holepunch_message = nullptr;
    refs_--;
    close_maybe();
}

compact::Ipv4Address SocketRef::address() const {
    struct sockaddr_in addr;
    int len = sizeof(addr);
    uv_udp_getsockname(
        reinterpret_cast<const uv_udp_t*>(&socket_),
        reinterpret_cast<struct sockaddr*>(&addr),
        &len);
    compact::Ipv4Address result;
    std::memcpy(result.host.data(), &addr.sin_addr, 4);
    result.port = ntohs(addr.sin_port);
    return result;
}

void SocketRef::close_maybe() {
    if (refs_ == 0 && !closed_ && linger_timer_ == nullptr) {
        do_close();
    }
}

void SocketRef::do_close() {
    unlinger();

    if (reusable && was_busy_) {
        was_busy_ = false;
        pool_.lingering_.insert(this);
        linger_timer_ = new uv_timer_t;
        uv_timer_init(loop_, linger_timer_);
        linger_timer_->data = this;
        uv_timer_start(linger_timer_, on_linger_timeout, LINGER_TIME_MS, 0);
        return;
    }

    closed_ = true;
    udx_socket_close(&socket_);
}

void SocketRef::unlinger() {
    if (linger_timer_ != nullptr) {
        uv_timer_stop(linger_timer_);
        uv_close(reinterpret_cast<uv_handle_t*>(linger_timer_), on_linger_close);
        pool_.lingering_.erase(this);
        linger_timer_ = nullptr;
    }
}

void SocketRef::on_linger_timeout(uv_timer_t* handle) {
    auto* self = static_cast<SocketRef*>(handle->data);
    self->pool_.lingering_.erase(self);
    self->linger_timer_ = nullptr;
    uv_close(reinterpret_cast<uv_handle_t*>(handle), on_linger_close);
    self->close_maybe();
}

void SocketRef::on_linger_close(uv_handle_t* handle) {
    delete reinterpret_cast<uv_timer_t*>(handle);
}

void SocketRef::on_socket_close(udx_socket_t* socket) {
    auto* self = static_cast<SocketRef*>(socket->data);
    self->pool_.remove(self);
}

void SocketRef::on_message(udx_socket_t* socket, ssize_t read_len,
                           const uv_buf_t* buf, const struct sockaddr* addr) {
    if (read_len <= 0 || !addr) return;
    auto* self = static_cast<SocketRef*>(socket->data);

    // Extract sender address
    auto* sin = reinterpret_cast<const struct sockaddr_in*>(addr);
    compact::Ipv4Address from;
    std::memcpy(from.host.data(), &sin->sin_addr, 4);
    from.port = ntohs(sin->sin_port);

    auto data = reinterpret_cast<const uint8_t*>(buf->base);
    auto len = static_cast<size_t>(read_len);

    if (len <= 1) {
        // Holepunch probe (0 or 1 byte)
        if (self->on_holepunch_message) {
            self->on_holepunch_message(data, len, from, self);
        }
    } else {
        // DHT message — forward to pool's message handler
        if (self->pool_.on_message) {
            self->pool_.on_message(socket, data, len, from);
        }
    }
}

// ---------------------------------------------------------------------------
// SocketPool
// ---------------------------------------------------------------------------

SocketPool::SocketPool(uv_loop_t* loop, udx_t* udx, const std::string& host)
    : loop_(loop), udx_(udx), host_(host) {}

SocketPool::~SocketPool() {
    destroy();
}

SocketRef* SocketPool::acquire() {
    return new SocketRef(*this, loop_, udx_, host_);
}

SocketRef* SocketPool::lookup(udx_socket_t* socket) {
    auto it = sockets_.find(socket);
    return (it != sockets_.end()) ? it->second : nullptr;
}

void SocketPool::set_reusable(udx_socket_t* socket, bool reusable) {
    auto* ref = lookup(socket);
    if (ref) ref->reusable = reusable;
}

void SocketPool::destroy() {
    // Collect refs to destroy (iteration invalidation safe)
    std::vector<SocketRef*> refs;
    for (auto& [_, ref] : sockets_) {
        refs.push_back(ref);
    }
    for (auto* ref : refs) {
        ref->unlinger();
        if (!ref->closed_) {
            ref->closed_ = true;
            udx_socket_close(&ref->socket_);
        }
    }
}

void SocketPool::add(SocketRef* ref) {
    sockets_[&ref->socket_] = ref;
}

void SocketPool::remove(SocketRef* ref) {
    sockets_.erase(&ref->socket_);
    lingering_.erase(ref);
    delete ref;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

void SocketPool::add_route(const std::array<uint8_t, 32>& public_key,
                           udx_socket_t* socket,
                           const compact::Ipv4Address& address) {
    auto hex = key_hex(public_key);
    routes_[hex] = SocketRoute{socket, address};
    set_reusable(socket, true);
}

const SocketRoute* SocketPool::get_route(
    const std::array<uint8_t, 32>& public_key) const {
    auto hex = key_hex(public_key);
    auto it = routes_.find(hex);
    return (it != routes_.end()) ? &it->second : nullptr;
}

void SocketPool::remove_route(const std::array<uint8_t, 32>& public_key) {
    auto hex = key_hex(public_key);
    routes_.erase(hex);
}

}  // namespace socket_pool
}  // namespace hyperdht
