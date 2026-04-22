// Nospoon VPN — Server mode
// Listens for peer connections on HyperDHT, routes IP packets between
// TUN device and authenticated peers.

#include "config.hpp"
#include "framing.hpp"
#include "routing.hpp"
#include "tun.hpp"

#include <hyperdht/dht.hpp>
#include <hyperdht/secret_stream.hpp>
#include <hyperdht/server.hpp>

#include <csignal>
#include <cstdio>
#include <map>
#include <memory>

using namespace hyperdht;
using namespace nospoon;

namespace {

struct PeerState {
    std::unique_ptr<secret_stream::SecretStreamDuplex> duplex;
    FrameDecoder decoder;
    uint32_t assigned_ip = 0;
    std::string pk_hex;
};

struct ServerCtx {
    HyperDHT* dht = nullptr;
    Tun tun;
    RoutingTable routes;
    Config config;
    noise::Keypair keypair;
    std::map<std::string, PeerState> peers;  // pk_hex -> state
    uv_timer_t keepalive_timer{};
    bool running = true;
};

void send_framed(secret_stream::SecretStreamDuplex* duplex,
                 const uint8_t* data, size_t len) {
    auto frame = frame_encode(data, len);
    duplex->write(frame.data(), frame.size(), nullptr);
}

void on_tun_packet(ServerCtx& ctx, const uint8_t* data, size_t len) {
    auto dest = RoutingTable::dest_ip(data, len);
    if (dest == 0) return;

    auto* stream = ctx.routes.lookup(dest);
    if (!stream) return;

    send_framed(static_cast<secret_stream::SecretStreamDuplex*>(stream),
                data, len);
}

void setup_peer_stream(ServerCtx& ctx, const server::ConnectionInfo& info) {
    auto pk_hex = bytes_to_hex(info.remote_public_key.data(), 32);

    // Look up assigned IP from peers map
    auto it = ctx.config.peers.find(pk_hex);
    if (it == ctx.config.peers.end()) {
        fprintf(stderr, "  Peer %s not in config, rejecting\n", pk_hex.c_str());
        return;
    }
    auto peer_ip = RoutingTable::string_to_ip(it->second);
    if (peer_ip == 0) {
        fprintf(stderr, "  Invalid IP for peer %s: %s\n",
                pk_hex.c_str(), it->second.c_str());
        return;
    }

    fprintf(stderr, "  Peer %s assigned %s\n",
            pk_hex.substr(0, 16).c_str(), it->second.c_str());

    // Build SecretStream handshake
    secret_stream::DuplexHandshake hs{};
    hs.tx_key = info.tx_key;
    hs.rx_key = info.rx_key;
    hs.handshake_hash = info.handshake_hash;
    std::memcpy(hs.remote_public_key.data(),
                info.remote_public_key.data(), 32);
    hs.public_key = ctx.keypair.public_key;
    hs.is_initiator = false;

    // Connect raw stream
    if (info.peer_address.port != 0 && info.raw_stream) {
        struct sockaddr_in dest{};
        uv_ip4_addr(info.peer_address.host_string().c_str(),
                     info.peer_address.port, &dest);
        udx_stream_connect(info.raw_stream, info.udx_socket,
                           info.remote_udx_id,
                           reinterpret_cast<const struct sockaddr*>(&dest));
    }

    auto duplex = std::make_unique<secret_stream::SecretStreamDuplex>(
        info.raw_stream, hs, ctx.dht->loop(),
        ctx.dht->make_duplex_options());

    auto* duplex_ptr = duplex.get();

    // Create peer state
    auto& peer = ctx.peers[pk_hex];
    peer.duplex = std::move(duplex);
    peer.assigned_ip = peer_ip;
    peer.pk_hex = pk_hex;

    // Add route
    ctx.routes.add(peer_ip, duplex_ptr);

    // Wire callbacks
    duplex_ptr->on_connect([pk_hex]() {
        fprintf(stderr, "  Stream open for %s\n", pk_hex.substr(0, 16).c_str());
    });

    duplex_ptr->on_message([&ctx, duplex_ptr](const uint8_t* data, size_t len) {
        // Decode framed packets, route to TUN or other peers
        // Find the peer by stream pointer
        PeerState* ps = nullptr;
        for (auto& [k, v] : ctx.peers) {
            if (v.duplex.get() == duplex_ptr) { ps = &v; break; }
        }
        if (!ps) return;

        ps->decoder.feed(data, len, [&ctx](const uint8_t* pkt, size_t pkt_len) {
            auto dest = RoutingTable::dest_ip(pkt, pkt_len);
            auto* target = ctx.routes.lookup(dest);
            if (target) {
                // Route to another peer
                send_framed(
                    static_cast<secret_stream::SecretStreamDuplex*>(target),
                    pkt, pkt_len);
            } else {
                // Route to TUN (local network or unknown dest)
                ctx.tun.write(pkt, pkt_len);
            }
        });
    });

    duplex_ptr->on_end([duplex_ptr]() {
        if (duplex_ptr) duplex_ptr->end();
    });

    duplex_ptr->on_close([&ctx, pk_hex](int) {
        fprintf(stderr, "  Peer %s disconnected\n", pk_hex.substr(0, 16).c_str());
        auto it = ctx.peers.find(pk_hex);
        if (it != ctx.peers.end()) {
            ctx.routes.remove(it->second.assigned_ip);
            ctx.peers.erase(it);
        }
    });

    duplex_ptr->start();
}

void keepalive_tick(uv_timer_t* handle) {
    auto* ctx = static_cast<ServerCtx*>(handle->data);
    auto ka = frame_keepalive();
    for (auto& [pk, peer] : ctx->peers) {
        if (peer.duplex && peer.duplex->is_connected()) {
            peer.duplex->write(ka.data(), ka.size(), nullptr);
        }
    }
}

}  // namespace

int run_server(const Config& config) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    // Derive keypair from seed
    noise::Keypair kp;
    if (!config.seed.empty()) {
        noise::Seed seed{};
        if (!hex_to_bytes(config.seed, seed.data(), 32)) {
            fprintf(stderr, "Error: invalid seed hex\n");
            return 1;
        }
        kp = noise::generate_keypair(seed);
    } else {
        kp = noise::generate_keypair();
    }

    // Build DHT
    DhtOptions opts;
    opts.bootstrap = HyperDHT::default_bootstrap_nodes();
    HyperDHT dht(&loop, opts);
    dht.bind();

    ServerCtx ctx;
    ctx.dht = &dht;
    ctx.config = config;
    ctx.keypair = kp;

    // Open TUN
    if (ctx.tun.open(config.ip, config.mtu) != 0) {
        fprintf(stderr, "Error: failed to open TUN device\n");
        return 1;
    }
    ctx.tun.start(&loop, [&ctx](const uint8_t* data, size_t len) {
        on_tun_packet(ctx, data, len);
    });

    // Create server with firewall
    auto* server = dht.create_server();
    server->set_firewall([&ctx](const std::array<uint8_t, 32>& remote_pk,
                                const peer_connect::NoisePayload&,
                                const compact::Ipv4Address&) -> bool {
        auto hex = bytes_to_hex(remote_pk.data(), 32);
        bool reject = ctx.config.peers.find(hex) == ctx.config.peers.end();
        if (reject) {
            fprintf(stderr, "  Firewall: rejected %s\n", hex.substr(0, 16).c_str());
        }
        return reject;
    });

    server->listen(kp, [&ctx](const server::ConnectionInfo& info) {
        auto hex = bytes_to_hex(info.remote_public_key.data(), 32);
        fprintf(stderr, "  Connection from %s:%u [%s]\n",
                info.peer_address.host_string().c_str(),
                info.peer_address.port,
                hex.substr(0, 16).c_str());
        setup_peer_stream(ctx, info);
    });

    // Keepalive timer (25s)
    uv_timer_init(&loop, &ctx.keepalive_timer);
    ctx.keepalive_timer.data = &ctx;
    uv_timer_start(&ctx.keepalive_timer, keepalive_tick, 25000, 25000);

    fprintf(stderr, R"(
  nospoon server — P2P VPN powered by hyperdht-cpp
  -------------------------------------------------

  TUN:         %s (%s, MTU %d)
  DHT port:    %u
  Public key:  %s
  Peers:       %zu configured

  Ctrl+C to stop

)",
        ctx.tun.name().c_str(), config.ip.c_str(), config.mtu,
        dht.port(),
        bytes_to_hex(kp.public_key.data(), 32).c_str(),
        config.peers.size());

    // Run event loop (UV_RUN_ONCE loop for signal handling)
    while (ctx.running && uv_run(&loop, UV_RUN_ONCE)) {}

    // Cleanup
    uv_timer_stop(&ctx.keepalive_timer);
    ctx.tun.close();
    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
    return 0;
}
