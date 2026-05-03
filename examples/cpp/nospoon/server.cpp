// Nospoon VPN — Server mode
// Listens for peer connections on HyperDHT, routes IP packets between
// TUN device and authenticated peers.

#include "config.hpp"
#include "framing.hpp"
#include "full_tunnel.hpp"
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
    std::string assigned_ip;  // empty in open mode (learned from first packet)
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
    auto dest = RoutingTable::read_dest_ip(data, len);
    if (dest.empty()) return;

    auto* stream = ctx.routes.lookup(dest);
    if (!stream) return;

    send_framed(static_cast<secret_stream::SecretStreamDuplex*>(stream),
                data, len);
}

void setup_peer_stream(ServerCtx& ctx, const server::ConnectionInfo& info) {
    auto pk_hex = bytes_to_hex(info.remote_public_key.data(), 32);

    // Look up assigned IP from peers config (if peers map present).
    // In open mode (no peers), assigned_ip stays empty and is learned from
    // the first packet arriving on the stream.
    std::string peer_ip;
    auto it = ctx.config.peers.find(pk_hex);
    if (it != ctx.config.peers.end()) {
        peer_ip = it->second;
        fprintf(stderr, "  Peer %s assigned %s\n",
                pk_hex.substr(0, 16).c_str(), peer_ip.c_str());
    } else {
        fprintf(stderr, "  Peer %s connected (open mode — IP TBD)\n",
                pk_hex.substr(0, 16).c_str());
    }

    // Build SecretStream handshake
    secret_stream::DuplexHandshake hs{};
    hs.tx_key = info.tx_key;
    hs.rx_key = info.rx_key;
    hs.handshake_hash = info.handshake_hash;
    std::memcpy(hs.remote_public_key.data(),
                info.remote_public_key.data(), 32);
    hs.public_key = ctx.keypair.public_key;
    hs.is_initiator = false;

    // Connect raw stream — use holepunch socket if available,
    // fall back to the main RPC socket (same as ffi_stream.cpp)
    if (info.peer_address.port != 0 && info.raw_stream) {
        struct sockaddr_in dest{};
        uv_ip4_addr(info.peer_address.host_string().c_str(),
                     info.peer_address.port, &dest);
        udx_socket_t* sock = info.udx_socket
            ? info.udx_socket
            : ctx.dht->socket().socket_handle();
        udx_stream_connect(info.raw_stream, sock,
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

    // Add route immediately if we have an assigned IP (auth mode).
    // In open mode it'll be added when the first packet arrives.
    if (!peer_ip.empty()) {
        ctx.routes.add(peer_ip, duplex_ptr);
    }

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

        ps->decoder.feed(data, len, [&ctx, ps, duplex_ptr]
                                   (const uint8_t* pkt, size_t pkt_len) {
            // Source-IP verification (auth mode) / IP learning (open mode).
            auto src = RoutingTable::read_src_ip(pkt, pkt_len);
            if (!ps->assigned_ip.empty()) {
                // Auth mode: drop packets that don't claim the assigned IP.
                if (src != ps->assigned_ip) return;
            } else if (!src.empty()) {
                // Open mode: learn this peer's IP from its first packet.
                // Skip IPv6 link-local (fe80:) — not useful for routing.
                if (src.rfind("fe80:", 0) == 0) return;
                if (!ctx.routes.lookup(src)) {
                    ps->assigned_ip = src;
                    ctx.routes.add(src, duplex_ptr);
                    fprintf(stderr, "  Learned peer IP %s for %s\n",
                            src.c_str(), ps->pk_hex.substr(0, 16).c_str());
                }
            }

            auto dest = RoutingTable::read_dest_ip(pkt, pkt_len);
            auto* target = dest.empty() ? nullptr : ctx.routes.lookup(dest);
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
            if (!it->second.assigned_ip.empty()) {
                ctx.routes.remove(it->second.assigned_ip);
            }
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

    // Build DHT — use the seed-derived keypair as the default identity
    DhtOptions opts;
    opts.bootstrap = HyperDHT::default_bootstrap_nodes();
    opts.default_keypair = kp;
    HyperDHT dht(&loop, opts);
    dht.bind();

    ServerCtx ctx;
    ctx.dht = &dht;
    ctx.config = config;
    ctx.keypair = kp;

    // Open TUN (IPv4 + optional IPv6)
    if (ctx.tun.open(config.ip, config.mtu, config.ipv6) != 0) {
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
        // Open mode (peers map empty) accepts all peers.
        if (ctx.config.peers.empty()) return false;
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

    // Full-tunnel: enable IP forwarding + NAT.
    bool full_tunnel_enabled = false;
    if (config.full_tunnel) {
        if (config.peers.empty()) {
            fprintf(stderr,
                "  WARNING: fullTunnel without peers creates an OPEN PROXY\n");
        }
        // Use the bare IP (no /prefix) as the NAT subnet's network address.
        // The user-provided ip is e.g. "10.0.0.1/24" — we translate to "10.0.0.0/24".
        std::string subnet;
        auto slash = config.ip.find('/');
        if (slash != std::string::npos) {
            // Quick & dirty: assume /24 mask → zero last octet.
            // Future: derive from parsed prefix length.
            std::string addr = config.ip.substr(0, slash);
            auto last_dot = addr.rfind('.');
            if (last_dot != std::string::npos) {
                subnet = addr.substr(0, last_dot) + ".0" + config.ip.substr(slash);
            } else {
                subnet = config.ip;
            }
        } else {
            subnet = config.ip;
        }
        full_tunnel_enabled = full_tunnel::enable_server_forwarding(
            ctx.tun.name(), subnet, config.out_iface);
    }

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
    if (full_tunnel_enabled) {
        full_tunnel::disable_server_forwarding();
    }
    uv_timer_stop(&ctx.keepalive_timer);
    ctx.tun.close();
    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
    return 0;
}
