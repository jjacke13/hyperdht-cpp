// Nospoon VPN — Client mode
// Connects to a nospoon server over HyperDHT, forwards IP packets
// between local TUN device and encrypted P2P stream.

#include "config.hpp"
#include "framing.hpp"
#include "full_tunnel.hpp"
#include "routing.hpp"
#include "tun.hpp"

#include <hyperdht/dht.hpp>
#include <hyperdht/secret_stream.hpp>

#include <algorithm>
#include <cstdio>
#include <memory>

using namespace hyperdht;
using namespace nospoon;

namespace {

struct ClientCtx {
    HyperDHT* dht = nullptr;
    Tun tun;
    Config config;
    noise::Keypair keypair;
    noise::PubKey server_pk{};
    std::unique_ptr<secret_stream::SecretStreamDuplex> duplex;
    FrameDecoder decoder;
    uv_timer_t keepalive_timer{};
    uv_timer_t reconnect_timer{};
    int backoff_ms = 1000;
    int failures = 0;
    bool connected = false;
    bool running = true;
    bool full_tunnel_active = false;  // tracks whether routes/DNS are installed
};

void do_connect(ClientCtx& ctx);

void send_framed(secret_stream::SecretStreamDuplex* duplex,
                 const uint8_t* data, size_t len) {
    auto frame = frame_encode(data, len);
    duplex->write(frame.data(), frame.size(), nullptr);
}

void on_tun_packet(ClientCtx& ctx, const uint8_t* data, size_t len) {
    if (!ctx.duplex || !ctx.duplex->is_connected()) return;
    send_framed(ctx.duplex.get(), data, len);
}

void keepalive_tick(uv_timer_t* handle) {
    auto* ctx = static_cast<ClientCtx*>(handle->data);
    if (ctx->duplex && ctx->duplex->is_connected()) {
        auto ka = frame_keepalive();
        ctx->duplex->write(ka.data(), ka.size(), nullptr);
    }
}

// After this many consecutive failures while full-tunnel is active, drop
// the tunnel routes so DHT lookups can reach the real internet again. Routes
// get re-added on the next successful connect. Matches the JS impl's
// MAX_FAILURES_BEFORE_RESTART (3).
constexpr int MAX_FAILURES_BEFORE_TUNNEL_RESET = 3;

void schedule_reconnect(ClientCtx& ctx) {
    if (!ctx.running) return;
    ctx.failures++;

    // Kill-switch lift: full-tunnel routes prevent DHT lookups from reaching
    // bootstrap nodes via the real network. After repeated failures, remove
    // the routes so DHT can reconnect; they'll be re-installed on success.
    if (ctx.full_tunnel_active &&
        ctx.failures >= MAX_FAILURES_BEFORE_TUNNEL_RESET) {
        fprintf(stderr,
                "  %d consecutive failures — dropping tunnel routes "
                "to let DHT recover\n", ctx.failures);
        full_tunnel::disable_client_full_tunnel();
        ctx.full_tunnel_active = false;
    }

    // Exponential backoff: 1s -> 2s -> 4s -> ... -> 30s max
    ctx.backoff_ms = std::min(ctx.backoff_ms * 2, 30000);

    fprintf(stderr, "  Reconnecting in %d ms (attempt %d)\n",
            ctx.backoff_ms, ctx.failures);

    ctx.reconnect_timer.data = &ctx;
    uv_timer_start(&ctx.reconnect_timer,
        [](uv_timer_t* t) {
            auto* c = static_cast<ClientCtx*>(t->data);
            do_connect(*c);
        },
        ctx.backoff_ms, 0);
}

void on_connect_result(ClientCtx& ctx, int error,
                       const ConnectResult& result) {
    if (error != 0) {
        fprintf(stderr, "  Connect failed: %d\n", error);
        schedule_reconnect(ctx);
        return;
    }

    fprintf(stderr, "  Connected to server at %s:%u\n",
            result.peer_address.host_string().c_str(),
            result.peer_address.port);

    // Reset backoff on success
    ctx.backoff_ms = 1000;
    ctx.failures = 0;
    ctx.connected = true;

    // Build SecretStream handshake
    secret_stream::DuplexHandshake hs{};
    hs.tx_key = result.tx_key;
    hs.rx_key = result.rx_key;
    hs.handshake_hash = result.handshake_hash;
    std::memcpy(hs.remote_public_key.data(),
                result.remote_public_key.data(), 32);
    hs.public_key = ctx.keypair.public_key;
    hs.is_initiator = true;

    // Connect raw stream
    if (result.peer_address.port != 0 && result.raw_stream) {
        struct sockaddr_in dest{};
        uv_ip4_addr(result.peer_address.host_string().c_str(),
                     result.peer_address.port, &dest);
        udx_socket_t* sock = result.udx_socket
            ? result.udx_socket
            : ctx.dht->socket().socket_handle();
        udx_stream_connect(result.raw_stream, sock,
                           result.remote_udx_id,
                           reinterpret_cast<const struct sockaddr*>(&dest));
    }

    ctx.duplex = std::make_unique<secret_stream::SecretStreamDuplex>(
        result.raw_stream, hs, ctx.dht->loop(),
        ctx.dht->make_duplex_options());

    auto* duplex_ptr = ctx.duplex.get();

    duplex_ptr->on_connect([]() {
        fprintf(stderr, "  Encrypted tunnel established\n");
    });

    duplex_ptr->on_message([&ctx](const uint8_t* data, size_t len) {
        ctx.decoder.feed(data, len, [&ctx](const uint8_t* pkt, size_t pkt_len) {
            ctx.tun.write(pkt, pkt_len);
        });
    });

    duplex_ptr->on_end([duplex_ptr]() {
        if (duplex_ptr) duplex_ptr->end();
    });

    duplex_ptr->on_close([&ctx](int) {
        fprintf(stderr, "  Server disconnected\n");
        ctx.connected = false;
        ctx.duplex.reset();
        ctx.decoder.reset();
        schedule_reconnect(ctx);
    });

    duplex_ptr->start();

    // Start keepalive
    uv_timer_start(&ctx.keepalive_timer, keepalive_tick, 25000, 25000);

    // Full-tunnel: install routes the first time we connect; on subsequent
    // reconnects (e.g. server moved hosts) just refresh the host exemption.
    if (ctx.config.full_tunnel) {
        std::string server_ip = result.peer_address.host_string();
        if (!ctx.full_tunnel_active) {
            if (full_tunnel::enable_client_full_tunnel(ctx.tun.name(), server_ip)) {
                ctx.full_tunnel_active = true;
            }
        } else {
            full_tunnel::add_host_exemption(server_ip);
        }
    }
}

void do_connect(ClientCtx& ctx) {
    if (!ctx.running) return;
    fprintf(stderr, "  Connecting to server...\n");

    ctx.dht->connect(ctx.server_pk,
        [&ctx](int error, const ConnectResult& result) {
            on_connect_result(ctx, error, result);
        });
}

}  // namespace

int run_client(const Config& config) {
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

    // Parse server public key
    noise::PubKey server_pk{};
    if (config.server_key.empty() ||
        !hex_to_bytes(config.server_key, server_pk.data(), 32)) {
        fprintf(stderr, "Error: client config needs \"server\" (64-char hex pubkey)\n");
        return 1;
    }

    // Build DHT — use the seed-derived keypair as the default identity
    DhtOptions opts;
    opts.bootstrap = HyperDHT::default_bootstrap_nodes();
    opts.default_keypair = kp;
    HyperDHT dht(&loop, opts);
    dht.bind();

    ClientCtx ctx;
    ctx.dht = &dht;
    ctx.config = config;
    ctx.keypair = kp;
    ctx.server_pk = server_pk;

    // Open TUN (IPv4 + optional IPv6)
    if (ctx.tun.open(config.ip, config.mtu, config.ipv6) != 0) {
        fprintf(stderr, "Error: failed to open TUN device\n");
        return 1;
    }
    ctx.tun.start(&loop, [&ctx](const uint8_t* data, size_t len) {
        on_tun_packet(ctx, data, len);
    });

    // Init timers
    uv_timer_init(&loop, &ctx.keepalive_timer);
    ctx.keepalive_timer.data = &ctx;
    uv_timer_init(&loop, &ctx.reconnect_timer);

    fprintf(stderr, R"(
  nospoon client — P2P VPN powered by hyperdht-cpp
  -------------------------------------------------

  TUN:         %s (%s, MTU %d)
  DHT port:    %u
  Our key:     %s
  Server key:  %s

  Connecting...

)",
        ctx.tun.name().c_str(), config.ip.c_str(), config.mtu,
        dht.port(),
        bytes_to_hex(kp.public_key.data(), 32).c_str(),
        config.server_key.c_str());

    // Start connection
    do_connect(ctx);

    // Run event loop (UV_RUN_ONCE loop for signal handling)
    while (ctx.running && uv_run(&loop, UV_RUN_ONCE)) {}

    // Cleanup
    if (ctx.full_tunnel_active) {
        full_tunnel::disable_client_full_tunnel();
        ctx.full_tunnel_active = false;
    }
    uv_timer_stop(&ctx.keepalive_timer);
    uv_timer_stop(&ctx.reconnect_timer);
    ctx.tun.close();
    dht.destroy();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
    return 0;
}
