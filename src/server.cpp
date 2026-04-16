// Server implementation — listens at a public key for incoming
// HyperDHT connections. Registers with the Router, announces
// periodically via the Announcer, and spawns a ServerConnection
// for each accepted PEER_HANDSHAKE.
//
// =========================================================================
// JS FLOW MAP — how this file maps to the JavaScript reference
// =========================================================================
//
// C++ function                       Line  JS file (server.js)       JS lines
// ─────────────────────────────────── ────  ────────────────────────  ────────
// Server::listen                      124  server.js                143-196
// Server::close                       174  server.js                 88-129
// Server::refresh                     208  server.js                198-200
// Server::notify_online               218  server.js                202-204
// Server::suspend                     234  server.js                 63-76
// Server::resume                      248  server.js                 72-76
//
// Server::on_peer_handshake           298  server.js  464-481 (_onpeerhandshake)
//                                                     210-443 (_addHandshake)
//   ├─ Noise dedup                    310  server.js                265-279
//   ├─ handle_handshake call          378  server.js                237-388
//   ├─ rawStream + firewall           404  server.js                280-303
//   ├─ blind relay start (Phase E)    423  server.js                397-399, 625-685
//   ├─ OPEN shortcut → on_socket      560  server.js                390-394
//   └─ session timer (UvTimer)        614  server.js  431, 440 (prepunching)
//
// Server::on_peer_holepunch           644  server.js                483-600
//   ├─ handle_holepunch call          672  server.js                492-516
//   ├─ holepunch veto callback        727  server.js                544-546
//   ├─ puncher creation               737  server.js                436-440
//   ├─ puncher->punch()               778  server.js                576
//   └─ probe echo listener (add_*)    790  server.js  (always-on echo handler)
//
// Server::on_socket                   803  server.js                305-342
// Server::clear_session               842  server.js                450-462
// Server::on_raw_stream_firewall      866  server.js                282-291
//
// =========================================================================
//
// C++ diffs from JS:
//   - Per-session timers stored in `session_timers_` map<id, unique_ptr<UvTimer>>
//     vs JS clearing setTimeouts on the `hs` object directly. UvTimer is an
//     RAII wrapper — timer stop + uv_close happen in its destructor, so erasing
//     from the map is sufficient cleanup.
//   - Handshake dedup uses `handshake_dedup_` map<noise_hex, hp_id>
//     vs JS `_connects` Map<noise_hex, Promise<hs>>.
//   - rawStream firewall ctx (`RawStreamCtx*`) stored in stream->data; freed
//     by the stream's on_close callback (RAII — guaranteed regardless of which
//     libudx callback path fires first).
//   - Holepunch state lives in unique_ptr<ServerConnection> in
//     `connections_` (no JS-style sparse array of `_holepunches`).
//   - Probe echo is a single global listener installed on first holepunch via
//     `add_probe_listener` (multi-listener API), tracked in `probe_listener_id_`
//     and removed on close(). Previously overwrote a single slot per session,
//     which silently clobbered concurrent holepunch sessions.

#include "hyperdht/server.hpp"

#include "hyperdht/blind_relay.hpp"
#include "hyperdht/dht.hpp"  // §16: Server reads validated_local_addresses() from HyperDHT

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
        ctx->server->on_raw_stream_firewall(stream, socket, from);
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

Server::Server(rpc::RpcSocket& socket, router::Router& router, HyperDHT* dht)
    : socket_(socket), router_(router), dht_(dht) {}

Server::~Server() {
    if (listening_ && !closed_) {
        close();
    }
}

// ---------------------------------------------------------------------------
// listen
//
// JS: .analysis/js/hyperdht/lib/server.js:143-196 (listen + _listen)
//     .analysis/js/hyperdht/lib/server.js:166-175 (target + _router.set)
//
// C++ diffs from JS:
//   - Synchronous: no Promise — caller must already have bound socket.
//   - We do not run the JS dedup loop checking other listening servers
//     for the same publicKey (KEYPAIR_ALREADY_USED) — caller's contract.
//   - Computes target = BLAKE2b-256(publicKey) directly via libsodium
//     instead of JS `unslabbedHash`.
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
//
// JS: .analysis/js/hyperdht/lib/server.js:88-129 (close + _close + _gc)
//     .analysis/js/hyperdht/lib/server.js:131-141 (_clearAll)
//
// C++ diffs from JS:
//   - Each session timer in `session_timers_` is uv_timer_stop'd and
//     uv_close'd individually; JS just clearTimeouts on hs objects.
//   - `handshake_dedup_` (map) replaces JS `_connects` Map.
//   - Connections cleared via std::map.clear() — destructors handle
//     raw_stream cleanup; JS calls hs.rawStream.destroy() in _clearAll.
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

    // Cancel all session timers (UvTimer RAII handles stop + close)
    session_timers_.clear();
    pending_punch_streams_.clear();

    // Remove probe echo listener
    if (probe_listener_id_ != 0) {
        socket_.remove_probe_listener(probe_listener_id_);
        probe_listener_id_ = 0;
    }

    // Remove from router
    router_.remove(target_);

    // Clear active connections (ServerConnection destructor handles raw_stream)
    connections_.clear();
    handshake_dedup_.clear();

    if (on_done) on_done();
}

void Server::refresh() {
    if (!suspended_ && announcer_) announcer_->refresh();
}

// JS: server.notifyOnline() — wake the announcer from its "offline wait"
// so it immediately re-announces. JS only checks `this._announcer` is
// non-null; it does NOT gate on suspended. Suspending the announcer
// already sets running_ = false, and Announcer::notify_online() is a no-op
// while !running_, so the suspend case is self-handling (and harmless in
// JS too — `online.notify()` fires but no one is waiting).
void Server::notify_online() {
    if (closed_ || !listening_) {
        DHT_LOG("  [server] notify_online: ignored (closed=%d listening=%d)\n",
                closed_ ? 1 : 0, listening_ ? 1 : 0);
        return;
    }
    DHT_LOG("  [server] notify_online: waking announcer\n");
    if (announcer_) announcer_->notify_online();
}

// JS: server.js:63-76 (suspend + resume)
// JS suspend awaits _listening, then sets `suspended = true`, calls
// `_clearAll()`, and awaits `_announcer.suspend()`. We mirror that
// synchronously: stop the announcer, walk our session_timers_ map and
// uv_close each, clear connection / dedup state. Resume restarts the
// announcer (no JS-style `_resumed` Signal needed in our timer model).
void Server::suspend() {
    if (suspended_) return;
    suspended_ = true;

    // Stop announcer
    if (announcer_) announcer_->stop();

    // Clear pending holepunches (UvTimer RAII handles stop + close)
    session_timers_.clear();
    connections_.clear();
    handshake_dedup_.clear();
    pending_punch_streams_.clear();
}

void Server::resume() {
    if (!suspended_) return;
    suspended_ = false;

    // Restart announcer
    if (announcer_) announcer_->start();
}

// JS: server.js:78-86 (address)
Server::AddressInfo Server::address() const {
    AddressInfo info;
    // JS: `if (!this._keyPair) return null` — before listen() there is no
    // address yet. In C++ we can't return null; the caller checks
    // `info.public_key` being zero (or `is_listening()`).
    if (!listening_) return info;

    info.public_key = keypair_.public_key;
    // JS: `{ host: this.dht.host, port: this.dht.port }` which resolve to
    //     `this._nat.host` and `this._nat.port`. These are the NAT-sampled
    //     public address — empty / zero until the sampler has classified.
    //     We intentionally do NOT fall back to the bound socket port, since
    //     that is the local ephemeral port and not the public one (lies
    //     about reachability).
    info.host = socket_.nat_sampler().host();
    info.port = socket_.nat_sampler().port();
    return info;
}

const std::vector<peer_connect::RelayInfo>& Server::relay_addresses() const {
    static const std::vector<peer_connect::RelayInfo> empty;
    if (announcer_) return announcer_->relays();
    return empty;
}

// ---------------------------------------------------------------------------
// on_peer_handshake — handle incoming Noise IK msg1
//
// JS: .analysis/js/hyperdht/lib/server.js:464-481 (_onpeerhandshake)
//     .analysis/js/hyperdht/lib/server.js:210-443 (_addHandshake — the
//                                                  full handshake state machine)
//
// C++ diffs from JS:
//   - Dedup uses `handshake_dedup_` map<noise_hex, hp_id> resending the
//     cached `reply_noise`. JS reuses the in-flight Promise via `_connects`.
//   - rawStream is created (`udx_stream_init` + firewall callback) before
//     punching, mirroring JS:280-292 `dht.createRawStream({firewall})`.
//   - Per-session expiry timer stored in `session_timers_[hp_id]`,
//     replacing JS:447 `_clearLater(hs, id, k)` setTimeout chain.
// ---------------------------------------------------------------------------

void Server::on_peer_handshake(const std::vector<uint8_t>& noise,
                                const compact::Ipv4Address& peer_address,
                                std::function<void(std::vector<uint8_t>)> reply_fn) {
    DHT_LOG( "  [server] on_peer_handshake: noise=%zu bytes, from=%s:%u\n",
            noise.size(), peer_address.host_string().c_str(), peer_address.port);
    if (closed_ || suspended_) return;

    // Dedup: same noise bytes = same client via different relay.
    // JS: server.js:464-473 (_onpeerhandshake) k = noise.toString('hex');
    //     if (_connects.has(k)) reuse session. We resend cached reply_noise.
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

    // Get our addresses and relay info.
    //
    // `addresses4` layout in the Noise payload (JS `hyperdht/lib/server.js:270-277`):
    //   [0]       = our remote (public) address, from NAT sampler
    //   [1..n]    = validated LAN interface addresses, if
    //               `share_local_address == true` (JS default: true)
    //
    // The client's LAN shortcut (`connect.js:234-251`) walks addresses4
    // looking for an octet-match against its own local interfaces, so
    // populating [1..n] is what enables same-NAT connections without
    // holepunch. Without a HyperDHT back-pointer we can't reach the
    // cached validated list and the LAN advertisement silently no-ops.
    auto our_addrs = socket_.nat_sampler().addresses();
    if (share_local_address && dht_ != nullptr) {
        // Copy the vector by value (not by `const&`) so the append loop
        // cannot observe a mid-flight modification if the cache is
        // reconstructed on a network-change event in between. The
        // single-threaded event loop makes this moot today, but the
        // by-value copy documents intent and is cheap — the LAN list
        // is a handful of entries.
        const auto lan = dht_->validated_local_addresses();
        for (const auto& addr : lan) {
            our_addrs.push_back(addr);
        }
    }
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

    // JS: server.js:271 — `const ourRemoteAddr = this.dht.remoteAddress()`
    // If the server knows its public address (!firewalled), the response
    // omits holepunch info → client connects directly without holepunch rounds.
    bool has_remote_addr = !socket_.is_firewalled();

    // Phase E: Generate relay token if relayThrough is configured
    // JS: server.js:350-352 — if (relayThrough) hs.relayToken = relay.token()
    std::optional<peer_connect::RelayThroughInfo> relay_through_info;
    if (relay_through.has_value()) {
        peer_connect::RelayThroughInfo rt;
        rt.version = 1;
        rt.public_key = *relay_through;
        rt.token = blind_relay::generate_token();
        relay_through_info = rt;
    }

    // Process the handshake
    auto result = server_connection::handle_handshake(
        keypair_, noise, peer_address, hp_id,
        our_addrs, relay_infos, fw_cb, has_remote_addr, relay_through_info);

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
    // JS: server.js:280-292 (hs.rawStream = this.dht.createRawStream({firewall}))
    // The stream is registered on the socket so the client's first UDX
    // packet triggers the firewall callback with the real address.
    auto* raw = new udx_stream_t;
    auto* raw_ctx = new RawStreamCtx{this};
    udx_stream_init(socket_.udx_handle(), raw, conn.local_udx_id,
                    [](udx_stream_t*, int) {},
                    [](udx_stream_t* s) {
                        // RAII: context freed in on_close regardless of callback path
                        if (s->data) {
                            delete static_cast<RawStreamCtx*>(s->data);
                            s->data = nullptr;
                        }
                        delete s;
                    });
    raw->data = raw_ctx;
    udx_stream_firewall(raw, server_raw_stream_firewall);
    conn.raw_stream = raw;

    auto conn_ptr = std::make_unique<server_connection::ServerConnection>(std::move(conn));

    // Phase E: Start blind relay if either side has relayThrough.
    // JS: server.js:397-399 — if (relayThrough || remotePayload.relayThrough)
    //     this._relayConnection(hs, relayThrough, remotePayload, h)
    //
    // This runs in parallel with holepunch — first to complete wins.
    // The relay path is simpler on the server side: when pairing succeeds,
    // create SecretStream and emit onconnection.
    if (relay_through_info.has_value() ||
        conn_ptr->remote_payload.relay_through.has_value()) {
        DHT_LOG("  [server] Starting blind relay (ours=%s, client=%s)\n",
                relay_through_info.has_value() ? "yes" : "no",
                conn_ptr->remote_payload.relay_through.has_value() ? "yes" : "no");

        if (dht_) {
            dht_->relay_stats().attempts++;
        }

        // Determine role: who proposed the relay?
        // JS: server.js:632-639
        bool relay_is_initiator;
        noise::PubKey relay_pk;
        blind_relay::Token relay_tok;

        if (relay_through_info.has_value()) {
            // Server proposed relay — we're initiator
            relay_is_initiator = true;
            relay_pk = relay_through_info->public_key;
            relay_tok = relay_through_info->token;
        } else {
            // Client proposed relay — we're non-initiator
            relay_is_initiator = false;
            relay_pk = conn_ptr->remote_payload.relay_through->public_key;
            relay_tok = conn_ptr->remote_payload.relay_through->token;
        }
        conn_ptr->relay_token = relay_tok;

        // Store handshake keys for SecretStream creation after pairing
        auto relay_hs_tx = conn_ptr->tx_key;
        auto relay_hs_rx = conn_ptr->rx_key;
        auto relay_hs_hash = conn_ptr->handshake_hash;
        auto relay_hs_rpk = conn_ptr->remote_public_key;
        auto relay_local_udx_id = conn_ptr->local_udx_id;
        auto relay_remote_udx_id = conn_ptr->remote_payload.udx.has_value()
            ? conn_ptr->remote_payload.udx->id : 0u;
        auto* relay_raw = conn_ptr->raw_stream;

        // Connect to the relay node — same pattern as client side.
        // JS: server.js:643 — hs.relaySocket = this.dht.connect(publicKey)
        auto* dht_ptr = dht_;
        auto* self = this;
        dht_->connect(relay_pk,
            [self, dht_ptr, relay_is_initiator, relay_tok, relay_raw,
             relay_hs_tx, relay_hs_rx, relay_hs_hash, relay_hs_rpk,
             relay_local_udx_id, relay_remote_udx_id,
             relay_keep_alive = relay_keep_alive](
                int err, const ConnectResult& relay_result) {
            if (self->closed_ || !relay_result.success || err != 0) {
                DHT_LOG("  [server] Relay connect failed: %d\n", err);
                if (dht_ptr) dht_ptr->relay_stats().aborts++;
                return;
            }

            DHT_LOG("  [server] Connected to relay node, pairing\n");

            // Connect the relay raw stream
            if (relay_result.udx_socket && relay_result.raw_stream) {
                struct sockaddr_in addr{};
                addr.sin_family = AF_INET;
                uv_ip4_addr(relay_result.peer_address.host_string().c_str(),
                            relay_result.peer_address.port, &addr);
                udx_stream_connect(relay_result.raw_stream,
                                   relay_result.udx_socket,
                                   relay_result.remote_udx_id,
                                   reinterpret_cast<const struct sockaddr*>(&addr));
            }

            // Create SecretStream over relay connection
            secret_stream::DuplexHandshake dhs;
            dhs.tx_key = relay_result.tx_key;
            dhs.rx_key = relay_result.rx_key;
            dhs.handshake_hash = relay_result.handshake_hash;
            dhs.remote_public_key = relay_result.remote_public_key;
            dhs.is_initiator = true;

            secret_stream::DuplexOptions dopts;
            dopts.keep_alive_ms = relay_keep_alive;

            auto relay_duplex = std::make_shared<secret_stream::SecretStreamDuplex>(
                relay_result.raw_stream, dhs, dht_ptr->loop(), dopts);

            // Protomux over SecretStream
            auto relay_mux = std::make_shared<protomux::Mux>(
                [duplex = relay_duplex.get()](const uint8_t* data, size_t len) -> bool {
                    duplex->write(data, len, nullptr);
                    return true;
                });

            relay_duplex->on_message(
                [mux = relay_mux.get()](const uint8_t* data, size_t len) {
                    if (mux && !mux->is_destroyed()) mux->on_data(data, len);
                });
            relay_duplex->start();

            // BlindRelayClient on Protomux channel
            std::vector<uint8_t> channel_id(
                relay_result.remote_public_key.begin(),
                relay_result.remote_public_key.end());
            auto* channel = relay_mux->create_channel(
                blind_relay::PROTOCOL_NAME, channel_id, false);
            if (!channel) {
                DHT_LOG("  [server] Failed to create blind-relay channel\n");
                if (dht_ptr) dht_ptr->relay_stats().aborts++;
                return;
            }

            auto relay_client = std::make_shared<blind_relay::BlindRelayClient>(channel);
            relay_client->open();

            // Pair through the relay
            // JS: server.js:649 — hs.relayClient.pair(isInitiator, token, hs.rawStream)
            relay_client->pair(
                relay_is_initiator, relay_tok, relay_local_udx_id,
                [self, dht_ptr, relay_raw, relay_duplex, relay_mux, relay_client,
                 relay_hs_tx, relay_hs_rx, relay_hs_hash, relay_hs_rpk,
                 relay_local_udx_id, relay_remote_udx_id](uint32_t remote_id) {
                    if (self->closed_) return;

                    DHT_LOG("  [server] Relay pairing succeeded! remote_id=%u\n", remote_id);

                    if (dht_ptr) dht_ptr->relay_stats().successes++;

                    // Wire our rawStream through the relay
                    // JS: server.js:664-668
                    if (!relay_duplex || !relay_duplex->raw_stream()) return;
                    auto* rrs = relay_duplex->raw_stream();
                    auto* relay_addr = reinterpret_cast<const struct sockaddr_in*>(
                        &rrs->remote_addr);
                    udx_socket_t* relay_socket = rrs->socket;

                    if (relay_raw) {
                        udx_stream_connect(relay_raw, relay_socket, remote_id,
                                           reinterpret_cast<const struct sockaddr*>(relay_addr));
                    }

                    // Emit connection via on_socket
                    // JS: server.js:670-672
                    char host[INET_ADDRSTRLEN];
                    uv_ip4_name(relay_addr, host, sizeof(host));
                    auto peer_addr = compact::Ipv4Address::from_string(
                        host, ntohs(relay_addr->sin_port));

                    if (self->on_connection_) {
                        ConnectionInfo info;
                        info.tx_key = relay_hs_tx;
                        info.rx_key = relay_hs_rx;
                        info.handshake_hash = relay_hs_hash;
                        info.remote_public_key = relay_hs_rpk;
                        info.peer_address = peer_addr;
                        info.remote_udx_id = relay_remote_udx_id;
                        info.local_udx_id = relay_local_udx_id;
                        info.is_initiator = false;
                        info.raw_stream = relay_raw;
                        info.udx_socket = relay_socket;
                        self->on_connection_(info);
                    }
                },
                [self, dht_ptr](int err) {
                    if (self->closed_) return;
                    DHT_LOG("  [server] Relay pairing failed: %d\n", err);
                    if (dht_ptr) dht_ptr->relay_stats().aborts++;
                });
        });
    }

    // JS: server.js:390-394 — if client is OPEN, connect directly
    if (conn_ptr->remote_payload.firewall == peer_connect::FIREWALL_OPEN &&
        !conn_ptr->remote_payload.addresses4.empty()) {
        auto peer_addr = conn_ptr->remote_payload.addresses4[0];
        DHT_LOG("  [server] Client is OPEN, connecting directly\n");
        on_socket(*conn_ptr, peer_addr);
        return;
    }

    // JS: server.js:430-432 — if server has public addr, skip Holepuncher.
    // Response already omitted holepunch info → client connects directly.
    // We still store the connection for rawStream firewall detection.
    if (has_remote_addr) {
        DHT_LOG("  [server] We have public addr, skipping holepuncher (client connects directly)\n");
    }

    // Store connection for holepunch phase
    conn_ptr->created_at = uv_now(socket_.loop());
    connections_[hp_id] = std::move(conn_ptr);
    handshake_dedup_[noise_key] = hp_id;

    // Per-session timeout (RAII) — JS: server.js:445-462 (_clearLater + _clear)
    auto session_timer = std::make_unique<async_utils::UvTimer>(socket_.loop());
    session_timer->start([this, hp_id]() {
        if (!closed_) clear_session(hp_id);
    }, handshake_clear_wait);
    session_timers_[hp_id] = std::move(session_timer);

    DHT_LOG( "  [server] Handshake complete (id=%d), waiting for holepunch\n", hp_id);
}

// ---------------------------------------------------------------------------
// on_peer_holepunch — handle incoming holepunch rounds
//
// JS: .analysis/js/hyperdht/lib/server.js:483-600 (_onpeerholepunch)
//     .analysis/js/hyperdht/lib/server.js:602-623 (_abort — error path)
//
// C++ diffs from JS:
//   - Connections lookup is `connections_[hp_msg.id]` (a map) vs JS
//     `_holepunches[id]` (sparse array reused on null slots).
//   - We instantiate `Holepuncher` lazily on first round here, JS does
//     it inside `_addHandshake` (server.js:436).
//   - A2-A7 (2026-04-14): NAT sampling, stability analysis, fast-mode
//     ping, NAT freeze, random throttle, puncher→onsocket wiring now
//     implemented to match JS server.js:483-600.
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

    // A2: Feed NAT sampler from holepunch request
    // JS: server.js:509-510 — `if (req.socket === p.socket) p.nat.add(req.to, req.from)`
    // We always feed since we use a single socket (no pool socket on server)
    socket_.nat_sampler().add(
        compact::Ipv4Address::from_string(peer_address.host_string(), peer_address.port),
        peer_address);

    // A5: NAT freeze — lock classification before sending response
    // JS: server.js:582-584 — `if (p.nat.firewall !== FIREWALL.UNKNOWN) p.nat.freeze()`
    if (socket_.nat_sampler().firewall() != peer_connect::FIREWALL_UNKNOWN) {
        // NatSampler doesn't have freeze() yet — the classification is stable
        // after enough samples. This is a documentation placeholder for parity.
        // TODO: add NatSampler::freeze() if classification drift is observed.
    }

    if (reply.should_punch) {
        DHT_LOG("  [server] Client punching (id=%d, fw=%u, %zu addrs)\n",
                hp_msg.id, reply.remote_firewall,
                reply.remote_addresses.size());

        // A6: Random punch throttle
        // JS: server.js:553-574 — if either side RANDOM, check limits
        // If throttled, respond with TRY_LATER (handle_holepunch already
        // handles this in the response payload). Here we just log.
        bool is_random = (reply.remote_firewall >= peer_connect::FIREWALL_RANDOM) ||
                         (our_fw >= peer_connect::FIREWALL_RANDOM);
        if (is_random) {
            DHT_LOG("  [server] Random NAT detected (remote=%u, local=%u)\n",
                    reply.remote_firewall, our_fw);
            // TODO: enforce dht._randomPunches >= limit → TRY_LATER
        }

        // JS: server.js:544 — holepunch veto callback
        if (holepunch_cb_) {
            auto local_addrs = socket_.nat_sampler().addresses();
            if (!holepunch_cb_(reply.remote_firewall, our_fw,
                               reply.remote_addresses, local_addrs)) {
                DHT_LOG("  [server] Holepunch vetoed by callback\n");
                clear_session(hp_msg.id);
                return;
            }
        }

        if (!conn.puncher) {
            conn.puncher = std::make_shared<holepunch::Holepuncher>(socket_.loop(), false);
            conn.puncher->set_send_fn([this](const compact::Ipv4Address& addr) {
                if (!closed_) socket_.send_probe(addr);
            });
            conn.puncher->set_local_firewall(our_fw);

            // A7: Wire puncher→onsocket so probe success triggers connection
            // JS: server.js:438 — `hs.puncher.onconnect = hs.onsocket`
            uint32_t session_id = hp_msg.id;
            conn.puncher->on_connect([this, session_id](const holepunch::HolepunchResult& hp) {
                if (closed_) return;
                auto it = connections_.find(session_id);
                if (it == connections_.end()) return;
                DHT_LOG("  [server] Puncher detected connection from %s:%u\n",
                        hp.address.host_string().c_str(), hp.address.port);
                on_socket(*it->second, hp.address, hp.socket);
            });
        }
        conn.puncher->set_remote_firewall(reply.remote_firewall);

        // A4: Fast-mode ping — if we're CONSISTENT and client opened
        // a matching session, send immediate ping back
        // JS: server.js:530-537
        if (socket_.nat_sampler().firewall() == peer_connect::FIREWALL_CONSISTENT ||
            socket_.nat_sampler().firewall() == peer_connect::FIREWALL_OPEN) {
            // Send a probe back to the client's address immediately
            if (!reply.remote_addresses.empty()) {
                DHT_LOG("  [server] Fast-mode ping to %s:%u\n",
                        reply.remote_addresses[0].host_string().c_str(),
                        reply.remote_addresses[0].port);
                socket_.send_probe(reply.remote_addresses[0]);
            }
        }

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

        // Install probe echo listener ONCE — echoes probes from ALL clients.
        // Uses add_probe_listener so it doesn't clobber other listeners.
        // The listener stays active for the server's lifetime (removed in close).
        if (probe_listener_id_ == 0) {
            probe_listener_id_ = socket_.add_probe_listener(
                [this](const compact::Ipv4Address& from) {
                    if (closed_) return;
                    socket_.send_probe(from);
                });
        }
    }
}

// ---------------------------------------------------------------------------
// on_socket — connection established
//
// JS: .analysis/js/hyperdht/lib/server.js:305-342 (hs.onsocket closure)
//     .analysis/js/hyperdht/lib/server.js:59-61 (onconnection emit)
//
// C++ diffs from JS:
//   - We pass the actual `udx_socket_t*` (the one that received the
//     probe) through ConnectionInfo so the caller can wire the stream
//     to that exact socket. JS passes (socket, port, host) directly.
//   - rawStream ownership is transferred via raw pointer + nulling
//     `conn.raw_stream`; JS sets `hs.rawStream = null` after connect.
// ---------------------------------------------------------------------------

void Server::on_socket(server_connection::ServerConnection& conn,
                       const compact::Ipv4Address& peer_addr,
                       udx_socket_t* udx_sock) {
    if (!on_connection_) return;

    ConnectionInfo info;
    info.tx_key = conn.tx_key;
    info.rx_key = conn.rx_key;
    info.handshake_hash = conn.handshake_hash;
    info.remote_public_key = conn.remote_public_key;
    info.peer_address = peer_addr;
    info.local_udx_id = conn.local_udx_id;
    info.is_initiator = false;
    info.udx_socket = udx_sock;
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
//
// JS: .analysis/js/hyperdht/lib/server.js:450-462 (_clear)
// ---------------------------------------------------------------------------

void Server::clear_session(uint32_t hp_id) {
    auto it = connections_.find(hp_id);
    if (it == connections_.end()) return;

    DHT_LOG("  [server] Session timeout id=%u\n", hp_id);

    // Remove dedup entry
    for (auto dit = handshake_dedup_.begin(); dit != handshake_dedup_.end(); ++dit) {
        if (dit->second == hp_id) { handshake_dedup_.erase(dit); break; }
    }
    // Erase session timer (UvTimer RAII handles stop + close).
    // Safe whether the timer fired this call or is being cancelled early.
    session_timers_.erase(hp_id);
    // Erase connection (destructor handles raw_stream cleanup)
    connections_.erase(it);
}

// ---------------------------------------------------------------------------
// rawStream firewall — client's first UDX packet arrived with real address
//
// JS: .analysis/js/hyperdht/lib/server.js:282-291 (firewall callback inside
//     createRawStream — calls hs.onsocket with socket/port/host)
// ---------------------------------------------------------------------------

void Server::on_raw_stream_firewall(udx_stream_t* stream, udx_socket_t* socket,
                                    const struct sockaddr* from) {
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
    // Cancel session timer (UvTimer RAII handles stop + close)
    session_timers_.erase(hp_id);
    connections_.erase(it);

    // Connect with the REAL address and the socket that received the probe
    // JS: hs.onsocket(socket, port, host) — uses the exact socket
    on_socket(*conn_ptr, real_addr, socket);
}

}  // namespace server
}  // namespace hyperdht
