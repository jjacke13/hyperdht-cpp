#include "hyperdht/server.hpp"

#include <sodium.h>

#include <cstdio>

#include "hyperdht/debug.hpp"

// Context stored in rawStream->data during handshake→connection window
struct RawStreamCtx {
    hyperdht::server::Server* server;
};

// Firewall callback for pre-created rawStreams. Fires when the client's
// first UDX packet arrives with the REAL peer address.
// Matches JS: rawStream firewall → hs.onsocket(socket, port, host)
static int server_raw_stream_firewall(udx_stream_t* stream, udx_socket_t* socket,
                                       const struct sockaddr* from) {
    auto* ctx = static_cast<RawStreamCtx*>(stream->data);
    if (ctx && ctx->server) {
        ctx->server->on_raw_stream_firewall(stream, from);
    }
    return 0;  // accept (like JS returns false)
}

namespace hyperdht {
namespace server {

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; i++) {
        out.push_back(h[data[i] >> 4]);
        out.push_back(h[data[i] & 0x0F]);
    }
    return out;
}

Server::Server(rpc::RpcSocket& socket, router::Router& router)
    : socket_(socket), router_(router) {}

Server::~Server() {
    if (listening_ && !closed_) {
        close();
    }
}

// ---------------------------------------------------------------------------
// listen
// ---------------------------------------------------------------------------

void Server::listen(const noise::Keypair& keypair, OnConnectionCb on_connection) {
    if (listening_) return;
    listening_ = true;
    keypair_ = keypair;
    on_connection_ = std::move(on_connection);

    // Compute target = BLAKE2b-256(publicKey)
    crypto_generichash(target_.data(), 32,
                       keypair_.public_key.data(), 32,
                       nullptr, 0);

    // Register in the Router
    router::ForwardEntry entry;
    entry.on_peer_handshake = [this](const std::vector<uint8_t>& noise,
                                      const compact::Ipv4Address& peer_addr,
                                      std::function<void(std::vector<uint8_t>)> reply_fn) {
        on_peer_handshake(noise, peer_addr, std::move(reply_fn));
    };
    entry.on_peer_holepunch = [this](const std::vector<uint8_t>& value,
                                      const compact::Ipv4Address& peer_addr,
                                      std::function<void(std::vector<uint8_t>)> reply_fn) {
        on_peer_holepunch(value, peer_addr, std::move(reply_fn));
    };

    // Start the Announcer
    announcer_ = std::make_unique<announcer::Announcer>(socket_, keypair_, target_);
    announcer_->start();

    // Set the peer record on the router entry (updated by announcer later)
    entry.record = announcer_->record();
    router_.set(target_, std::move(entry));

    DHT_LOG( "  [server] Listening on %s\n",
            to_hex(keypair_.public_key.data(), 8).c_str());
}

// ---------------------------------------------------------------------------
// close
// ---------------------------------------------------------------------------

void Server::close(std::function<void()> on_done) {
    if (closed_) {
        if (on_done) on_done();
        return;
    }
    closed_ = true;
    listening_ = false;

    // Stop announcer
    if (announcer_) {
        announcer_->stop();
        announcer_.reset();
    }

    // Cancel all session timers
    for (auto& [id, timer] : session_timers_) {
        uv_timer_stop(timer);
        auto* ctx = static_cast<std::pair<Server*, uint32_t>*>(timer->data);
        delete ctx;
        timer->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(timer),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
    }
    session_timers_.clear();
    pending_punch_streams_.clear();

    // Remove from router
    router_.remove(target_);

    // Clear active connections (ServerConnection destructor handles raw_stream)
    connections_.clear();
    handshake_dedup_.clear();

    if (on_done) on_done();
}

void Server::refresh() {
    if (announcer_) announcer_->refresh();
}

const std::vector<peer_connect::RelayInfo>& Server::relay_addresses() const {
    static const std::vector<peer_connect::RelayInfo> empty;
    if (announcer_) return announcer_->relays();
    return empty;
}

// ---------------------------------------------------------------------------
// on_peer_handshake — handle incoming Noise IK msg1
// ---------------------------------------------------------------------------

void Server::on_peer_handshake(const std::vector<uint8_t>& noise,
                                const compact::Ipv4Address& peer_address,
                                std::function<void(std::vector<uint8_t>)> reply_fn) {
    DHT_LOG( "  [server] on_peer_handshake: noise=%zu bytes, from=%s:%u\n",
            noise.size(), peer_address.host_string().c_str(), peer_address.port);
    if (closed_) return;

    // Dedup: same noise bytes = same client via different relay.
    // JS: k = noise.toString('hex'); if (_connects.has(k)) reuse session.
    auto noise_key = to_hex(noise.data(), noise.size());
    auto dedup_it = handshake_dedup_.find(noise_key);
    if (dedup_it != handshake_dedup_.end()) {
        // Already processed this handshake — resend the cached reply
        auto conn_it = connections_.find(dedup_it->second);
        if (conn_it != connections_.end()) {
            DHT_LOG( "  [server] Dedup: reusing session id=%u for same noise\n",
                    dedup_it->second);
            reply_fn(std::vector<uint8_t>(conn_it->second->reply_noise));
            return;
        }
        // Session was already completed/cleaned up — remove stale dedup entry
        handshake_dedup_.erase(dedup_it);
    }

    uint32_t hp_id = next_hp_id_++;

    // Get our addresses and relay info
    auto our_addrs = socket_.nat_sampler().addresses();
    std::vector<peer_connect::RelayInfo> relay_infos;
    if (announcer_) {
        relay_infos = announcer_->relays();
    }

    // Wrap the firewall callback
    server_connection::FirewallFn fw_cb = nullptr;
    if (firewall_) {
        fw_cb = [this](const auto& pk, const auto& payload, const auto& addr) {
            return firewall_(pk, payload, addr);
        };
    }

    // Process the handshake
    auto result = server_connection::handle_handshake(
        keypair_, noise, peer_address, hp_id,
        our_addrs, relay_infos, fw_cb);

    if (!result.has_value()) {
        DHT_LOG( "  [server] Noise handshake FAILED (recv or send error)\n");
        return;
    }
    DHT_LOG( "  [server] Noise handshake OK, error=%u\n", result->error_code);

    auto& conn = *result;

    // Send the Noise msg2 reply
    DHT_LOG( "  [server] Sending reply: %zu noise bytes\n", conn.reply_noise.size());
    auto reply_noise = conn.reply_noise;
    reply_fn(std::move(reply_noise));

    if (conn.has_error) {
        return;
    }

    // Create rawStream NOW (during handshake, before holepunch starts).
    // Matches JS: hs.rawStream = this.dht.createRawStream({firewall})
    // The stream is registered on the socket so the client's first UDX
    // packet triggers the firewall callback with the real address.
    auto* raw = new udx_stream_t;
    auto* raw_ctx = new RawStreamCtx{this};
    udx_stream_init(socket_.udx_handle(), raw, conn.local_udx_id,
                    [](udx_stream_t* s, int) {
                        delete static_cast<RawStreamCtx*>(s->data);
                        s->data = nullptr;
                    },
                    [](udx_stream_t* s) { delete s; });
    raw->data = raw_ctx;
    udx_stream_firewall(raw, server_raw_stream_firewall);
    conn.raw_stream = raw;

    auto conn_ptr = std::make_unique<server_connection::ServerConnection>(std::move(conn));

    // If client is OPEN, connect directly
    if (conn_ptr->remote_payload.firewall == peer_connect::FIREWALL_OPEN &&
        !conn_ptr->remote_payload.addresses4.empty()) {
        auto peer_addr = conn_ptr->remote_payload.addresses4[0];
        on_socket(*conn_ptr, peer_addr);
        return;
    }

    // Store connection for holepunch phase
    conn_ptr->created_at = uv_now(socket_.loop());
    connections_[hp_id] = std::move(conn_ptr);
    handshake_dedup_[noise_key] = hp_id;

    // Per-session timeout — matches JS _clearLater(hs, id, k)
    auto* timer = new uv_timer_t;
    uv_timer_init(socket_.loop(), timer);
    auto* ctx = new std::pair<Server*, uint32_t>(this, hp_id);
    timer->data = ctx;
    uv_timer_start(timer, [](uv_timer_t* t) {
        auto* c = static_cast<std::pair<Server*, uint32_t>*>(t->data);
        if (c->first && !c->first->closed_) {
            c->first->clear_session(c->second);
        }
        delete c;
        uv_close(reinterpret_cast<uv_handle_t*>(t),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
    }, HP_TIMEOUT_MS, 0);
    session_timers_[hp_id] = timer;

    DHT_LOG( "  [server] Handshake complete (id=%d), waiting for holepunch\n", hp_id);
}

// ---------------------------------------------------------------------------
// on_peer_holepunch — handle incoming holepunch rounds
// ---------------------------------------------------------------------------

void Server::on_peer_holepunch(const std::vector<uint8_t>& value,
                                const compact::Ipv4Address& peer_address,
                                std::function<void(std::vector<uint8_t>)> reply_fn) {
    if (closed_) return;

    // Decode the outer message to get the holepunch ID
    auto hp_msg = holepunch::decode_holepunch_msg(value.data(), value.size());

    // Find the connection by holepunch ID
    auto it = connections_.find(hp_msg.id);
    if (it == connections_.end()) {
        return;  // Unknown session
    }

    auto& conn = *it->second;

    // Get our NAT info
    auto our_fw = socket_.nat_sampler().firewall();
    auto our_addrs = socket_.nat_sampler().addresses();

    // Check if request came from one of our relay nodes (JS: _announcer.isRelay)
    bool is_relay = false;
    if (announcer_) {
        for (const auto& ri : announcer_->relays()) {
            if (ri.relay_address.host_string() == peer_address.host_string() &&
                ri.relay_address.port == peer_address.port) {
                is_relay = true;
                break;
            }
        }
    }

    // Process the holepunch
    auto reply = server_connection::handle_holepunch(
        conn, value, peer_address, our_fw, our_addrs, is_relay);

    // Send reply
    if (!reply.value.empty()) {
        reply_fn(std::move(reply.value));
    }

    if (reply.should_punch) {
        DHT_LOG("  [server] Client punching (id=%d, fw=%u, %zu addrs)\n",
                hp_msg.id, reply.remote_firewall,
                reply.remote_addresses.size());

        // JS: server creates Holepuncher(dht, session, false) and calls punch()
        // → 10 rounds of probes at 1s intervals. Non-initiator echoes received probes.
        if (!conn.puncher) {
            conn.puncher = std::make_shared<holepunch::Holepuncher>(socket_.loop(), false);
            conn.puncher->set_send_fn([this](const compact::Ipv4Address& addr) {
                if (!closed_) socket_.send_probe(addr);
            });
            conn.puncher->set_local_firewall(our_fw);
        }
        conn.puncher->set_remote_firewall(reply.remote_firewall);

        // Filter out port-0 addresses and set as remote targets
        std::vector<compact::Ipv4Address> valid_addrs;
        for (const auto& addr : reply.remote_addresses) {
            if (addr.port != 0) valid_addrs.push_back(addr);
        }
        conn.puncher->set_remote_addresses(valid_addrs);
        conn.puncher->punch();

        // Register for rawStream firewall detection
        if (conn.raw_stream) {
            pending_punch_streams_[conn.local_udx_id] = hp_msg.id;
        }

        // Install probe listener — routes to puncher's on_message (echoes back)
        // and also serves as a global echo for any probe from any client
        socket_.on_holepunch_probe([this](const compact::Ipv4Address& from) {
            if (closed_) return;
            socket_.send_probe(from);
        });
    }
}

// ---------------------------------------------------------------------------
// on_socket — connection established
// ---------------------------------------------------------------------------

void Server::on_socket(server_connection::ServerConnection& conn,
                       const compact::Ipv4Address& peer_addr) {
    if (!on_connection_) return;

    ConnectionInfo info;
    info.tx_key = conn.tx_key;
    info.rx_key = conn.rx_key;
    info.handshake_hash = conn.handshake_hash;
    info.remote_public_key = conn.remote_public_key;
    info.peer_address = peer_addr;
    info.local_udx_id = conn.local_udx_id;
    info.is_initiator = false;
    // Transfer rawStream ownership. Clean up the Server's firewall context.
    if (conn.raw_stream && conn.raw_stream->data) {
        delete static_cast<RawStreamCtx*>(conn.raw_stream->data);
        conn.raw_stream->data = nullptr;
    }
    info.raw_stream = conn.raw_stream;
    conn.raw_stream = nullptr;

    if (conn.remote_payload.udx.has_value()) {
        info.remote_udx_id = conn.remote_payload.udx->id;
    }

    DHT_LOG( "  [server] Connection from %s (udx: us=%u them=%u)\n",
            to_hex(conn.remote_public_key.data(), 8).c_str(),
            info.local_udx_id, info.remote_udx_id);

    on_connection_(info);
}

// ---------------------------------------------------------------------------
// Per-session cleanup — matches JS _clear(hs, id, k)
// ---------------------------------------------------------------------------

void Server::clear_session(uint32_t hp_id) {
    auto it = connections_.find(hp_id);
    if (it == connections_.end()) return;

    DHT_LOG("  [server] Session timeout id=%u\n", hp_id);

    // Remove dedup entry
    for (auto dit = handshake_dedup_.begin(); dit != handshake_dedup_.end(); ++dit) {
        if (dit->second == hp_id) { handshake_dedup_.erase(dit); break; }
    }
    // Remove session timer (already fired, but clean the map)
    session_timers_.erase(hp_id);
    // Erase connection (destructor handles raw_stream cleanup)
    connections_.erase(it);
}

// ---------------------------------------------------------------------------
// rawStream firewall — client's first UDX packet arrived with real address
// ---------------------------------------------------------------------------

void Server::on_raw_stream_firewall(udx_stream_t* stream, const struct sockaddr* from) {
    if (closed_) return;

    // Find the pending punch for this stream's local_id
    auto pit = pending_punch_streams_.find(stream->local_id);
    if (pit == pending_punch_streams_.end()) return;

    auto hp_id = pit->second;
    pending_punch_streams_.erase(pit);

    auto it = connections_.find(hp_id);
    if (it == connections_.end()) return;

    // Extract the real peer address from the incoming packet
    auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(from);
    char host[INET_ADDRSTRLEN];
    uv_ip4_name(addr_in, host, sizeof(host));
    auto real_addr = compact::Ipv4Address::from_string(host, ntohs(addr_in->sin_port));

    DHT_LOG("  [server] rawStream firewall: real addr %s:%u (id=%u)\n",
            host, ntohs(addr_in->sin_port), hp_id);

    // Take ownership and clean up
    auto conn_ptr = std::move(it->second);
    for (auto dit = handshake_dedup_.begin(); dit != handshake_dedup_.end(); ++dit) {
        if (dit->second == hp_id) { handshake_dedup_.erase(dit); break; }
    }
    auto tit = session_timers_.find(hp_id);
    if (tit != session_timers_.end()) {
        uv_timer_stop(tit->second);
        auto* ctx = static_cast<std::pair<Server*, uint32_t>*>(tit->second->data);
        delete ctx;
        tit->second->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(tit->second),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        session_timers_.erase(tit);
    }
    connections_.erase(it);

    // Connect with the REAL address from the UDX packet
    on_socket(*conn_ptr, real_addr);
}

}  // namespace server
}  // namespace hyperdht
