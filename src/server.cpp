#include "hyperdht/server.hpp"

#include <sodium.h>

#include <cstdio>

#include "hyperdht/debug.hpp"

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

    // Remove from router
    router_.remove(target_);

    // Clear active connections
    connections_.clear();

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
        // Firewalled or version mismatch — don't store connection
        return;
    }

    // Store connection (both paths need stable memory)
    auto conn_ptr = std::make_unique<server_connection::ServerConnection>(std::move(conn));

    // If client is OPEN, connect directly
    if (conn_ptr->remote_payload.firewall == peer_connect::FIREWALL_OPEN &&
        !conn_ptr->remote_payload.addresses4.empty()) {
        auto peer_addr = conn_ptr->remote_payload.addresses4[0];
        on_socket(*conn_ptr, peer_addr);
        return;
    }

    // Store connection for holepunch phase
    connections_[hp_id] = std::move(conn_ptr);

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

    // Process the holepunch
    auto reply = server_connection::handle_holepunch(
        conn, value, peer_address, our_fw, our_addrs);

    // Send reply
    if (!reply.value.empty()) {
        reply_fn(std::move(reply.value));
    }

    // If the client is punching and has addresses, the holepunch is in progress.
    // The actual NAT traversal happens via UDP probes on the same socket.
    // For now, we report success to the on_connection callback once the
    // client establishes the UDX stream (detected by the RpcSocket's probe
    // listener or UDX stream firewall callback).
    if (reply.should_punch) {
        DHT_LOG( "  [server] Client punching (id=%d, fw=%u, %zu addrs)\n",
                hp_msg.id, reply.remote_firewall,
                reply.remote_addresses.size());

        // Start sending probes to the client's addresses
        for (const auto& addr : reply.remote_addresses) {
            socket_.send_probe(addr);
        }

        // Report connection — erase from map BEFORE calling on_socket
        // to avoid use-after-free if the callback triggers close()
        if (!reply.remote_addresses.empty()) {
            auto peer_addr = reply.remote_addresses[0];
            auto conn_ptr = std::move(it->second);  // Take ownership
            connections_.erase(it);
            on_socket(*conn_ptr, peer_addr);
        }
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

    if (conn.remote_payload.udx.has_value()) {
        info.remote_udx_id = conn.remote_payload.udx->id;
    }

    DHT_LOG( "  [server] Connection from %s (udx: us=%u them=%u)\n",
            to_hex(conn.remote_public_key.data(), 8).c_str(),
            info.local_udx_id, info.remote_udx_id);

    on_connection_(info);
}

}  // namespace server
}  // namespace hyperdht
