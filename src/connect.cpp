// HyperDHT connect pipeline — findPeer -> handshake -> (relay | direct | LAN | holepunch).
//
// Split from src/dht.cpp. See dht.cpp for the JS flow map overview.

#include "hyperdht/dht.hpp"

#include <sodium.h>

#include <cassert>
#include <deque>
#include <cstdio>

#include "hyperdht/async_utils.hpp"
#include "hyperdht/blind_relay.hpp"
#include "hyperdht/debug.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/protomux.hpp"
#include "hyperdht/secret_stream.hpp"

// Context stored in client rawStream->data during handshake->connection window.
// Matches JS: rawStream created at connect() time with firewall callback.
struct ClientRawStreamCtx {
    std::weak_ptr<bool> alive;
    std::function<void(udx_stream_t*, udx_socket_t*, const struct sockaddr*)> on_firewall;
};

// Firewall callback for client-side rawStream. Fires when the server's
// first UDX packet arrives with the REAL peer address.
// Matches JS: rawStream firewall -> c.onsocket(socket, port, host)
static int client_raw_stream_firewall(udx_stream_t* stream, udx_socket_t* socket,
                                       const struct sockaddr* from) {
    auto* ctx = static_cast<ClientRawStreamCtx*>(stream->data);
    if (ctx && !ctx->alive.expired() && ctx->on_firewall) {
        ctx->on_firewall(stream, socket, from);
    }
    return 0;
}

namespace hyperdht {

// ---------------------------------------------------------------------------
// ConnState — shared state for the async connect pipeline.
// Extracted to namespace scope so helper functions (on_handshake_success,
// start_relay_path) can reference it. Previously nested inside do_connect.
// ---------------------------------------------------------------------------
struct ConnState {
    noise::PubKey remote_pk;
    noise::Keypair keypair;
    ConnectCallback on_done;
    compact::Ipv4Address relay_addr;  // Relay used by the winning handshake
    std::vector<compact::Ipv4Address> relays;  // All relays discovered
    peer_connect::HandshakeResult hs_result;
    std::shared_ptr<query::Query> query;
    std::weak_ptr<bool> alive;  // Sentinel — expired if HyperDHT destroyed
    rpc::RpcSocket* socket = nullptr;  // Raw pointer, guarded by alive
    HyperDHT* dht = nullptr;  // Raw pointer, guarded by alive
    bool found = false;
    uint32_t our_udx_id = 0;
    udx_stream_t* raw_stream = nullptr;  // Client rawStream (like JS)
    bool completed = false;

    // §AUDIT-2: pipelining state (replaces relay_idx + try_relay_fn).
    // Handshakes fire as findPeer results stream in, Semaphore(2).
    int handshakes_in_flight = 0;
    int handshakes_started = 0;
    std::deque<compact::Ipv4Address> pending_relays;
    bool query_done = false;  // True after on_done fires

    // Cached early firewall event — JS: c.serverSocket / c.serverAddress.
    // If the server's first UDX packet arrives BEFORE the handshake reply,
    // cache the firewall info here and replay it after hs_result is set.
    udx_socket_t* cached_fw_socket = nullptr;
    compact::Ipv4Address cached_fw_address;
    // Keepalive for the pool socket used by the holepunch probes. Set when
    // the puncher is started so the rawStream firewall callback can pass it
    // through to socket_keepalive in ConnectResult. Without this, the pool
    // socket can be freed while the UDX stream still references it — a
    // use-after-free that Android's scudo allocator exposes (zeroed memory
    // → SIGSEGV in uv_run) but glibc hides (stale data still readable).
    udx_socket_t* pool_socket_handle = nullptr;
    std::shared_ptr<void> pool_socket_keepalive;
    // Passive wait timer (OPEN firewall path) — RAII
    std::unique_ptr<async_utils::UvTimer> passive_timer;
    // §6 ConnectOptions snapshot (copied, not referenced — opts may
    // outlive the original scope once we enter async territory).
    bool fast_open = true;
    bool local_connection = true;

    // Phase E: blind-relay config (from ConnectOptions)
    std::optional<noise::PubKey> relay_through;
    std::array<uint8_t, 32> relay_token{};
    uint64_t relay_keep_alive = 5000;

    // Phase E: relay connection state — RAII struct that guarantees
    // correct teardown order regardless of destruction path.
    struct RelayState {
        bool paired = false;
        std::unique_ptr<async_utils::UvTimer> timeout;
        // Connection resources in dependency order (destroyed bottom-up):
        std::unique_ptr<blind_relay::BlindRelayClient> client;
        std::unique_ptr<protomux::Mux> mux;
        std::unique_ptr<secret_stream::SecretStreamDuplex> duplex;
        udx_stream_t* raw_stream = nullptr;  // owned by duplex

        ~RelayState() {
            client.reset();
            mux.reset();
            duplex.reset();
            raw_stream = nullptr;
            timeout.reset();  // UvTimer RAII handles stop + close
        }
    };
    std::unique_ptr<RelayState> relay;

    ~ConnState() {
        // Clean up rawStream if not transferred to ConnectResult.
        // Context is freed by the stream's on_close callback (RAII).
        if (raw_stream) {
            udx_stream_destroy(raw_stream);
        }
        // Relay cleanup is handled by RelayState's destructor
        relay.reset();
    }

    void complete(int err, const ConnectResult& result = {}) {
        if (completed) return;  // Prevent double invocation (firewall + holepunch race)
        completed = true;

        // §AUDIT-3: cache relay addresses after successful connect.
        // JS: connect.js:464-466
        if (err == 0 && dht && !relays.empty()) {
            dht->cache_relay_addresses(remote_pk, relays);
        }

        // §AUDIT-6: store route after successful connect.
        // JS: connect.js:474 — socketPool.routes.add(remotePublicKey, rawStream)
        if (err == 0 && dht && dht->socket_pool() &&
            result.udx_socket != nullptr) {
            dht->socket_pool()->add_route(
                remote_pk, result.udx_socket, result.peer_address);
        }

        auto cb = std::move(on_done);
        on_done = nullptr;
        if (cb) cb(err, result);
    }

    // Transfer rawStream ownership to result, cleaning up firewall ctx
    void take_raw_stream(ConnectResult& result) {
        if (raw_stream) {
            // Detach context — stream's on_close will handle cleanup
            raw_stream->data = nullptr;
            result.raw_stream = raw_stream;
            raw_stream = nullptr;
        }
    }
};

// Forward declarations for helper functions extracted from do_connect.
// See definitions below.
static void on_handshake_success(std::shared_ptr<ConnState> state,
                                  const peer_connect::HandshakeResult& hs);
static void start_relay_path(std::shared_ptr<ConnState> state,
                              bool is_initiator,
                              noise::PubKey relay_pk,
                              blind_relay::Token relay_token);
// §AUDIT-2: pipelining helpers
static void fire_handshake(std::shared_ptr<ConnState> state,
                            const compact::Ipv4Address& relay_addr);
static void try_next_relay(std::shared_ptr<ConnState> state);
static void check_exhaustion(std::shared_ptr<ConnState> state);
static void start_find_peer(std::shared_ptr<ConnState> state);

// ---------------------------------------------------------------------------
// §AUDIT-2: fire_handshake — start a single PEER_HANDSHAKE through a relay.
// Called as findPeer results stream in (pipelining) or from cached relays.
// JS: connect.js:355-368 (connectThroughNode inside for-await).
// ---------------------------------------------------------------------------
static void fire_handshake(std::shared_ptr<ConnState> state,
                            const compact::Ipv4Address& relay_addr) {
    if (state->completed || state->alive.expired()) return;
    state->handshakes_in_flight++;
    state->handshakes_started++;

    // Compute firewall + addresses4 for the handshake payload.
    // JS: connect.js:386-394 (connectThroughNode)
    uint32_t our_fw = peer_connect::FIREWALL_UNKNOWN;
    std::vector<compact::Ipv4Address> our_addrs;

    const auto& sampler = state->socket->nat_sampler();
    if (!sampler.host().empty() &&
        sampler.port() != 0 &&
        !state->socket->is_firewalled() &&
        sampler.port() == state->socket->port()) {
        our_fw = peer_connect::FIREWALL_OPEN;
        our_addrs.push_back(compact::Ipv4Address::from_string(
            sampler.host(), sampler.port()));
    }

    // LAN addresses (§6 local_connection support).
    if (state->local_connection) {
        for (const auto& la : state->dht->validated_local_addresses()) {
            our_addrs.push_back(la);
        }
    }

    // Build relayThrough for the Noise payload (Phase E)
    std::optional<peer_connect::RelayThroughInfo> relay_through_info;
    if (state->relay_through.has_value()) {
        peer_connect::RelayThroughInfo rt;
        rt.version = 1;
        rt.public_key = *state->relay_through;
        rt.token = state->relay_token;
        relay_through_info = rt;
    }

    DHT_LOG("  [connect] fire_handshake via %s:%u (%d in flight)\n",
            relay_addr.host_string().c_str(), relay_addr.port,
            state->handshakes_in_flight);

    peer_connect::peer_handshake(*state->socket, relay_addr,
        state->keypair, state->remote_pk, state->our_udx_id,
        our_fw, our_addrs, relay_through_info,
        [state, relay_addr](const peer_connect::HandshakeResult& hs) {
            state->handshakes_in_flight--;
            if (state->completed) return;  // First-success or destruction guard
            if (state->alive.expired() || !hs.success) {
                try_next_relay(state);
                return;
            }
            state->relay_addr = relay_addr;
            state->hs_result = hs;
            on_handshake_success(state, hs);
        });
}

// ---------------------------------------------------------------------------
// §AUDIT-2: check_exhaustion — single shared helper for detecting all
// relays exhausted. Called from both try_next_relay and on_done to avoid
// a termination gap between the two call sites.
// ---------------------------------------------------------------------------
static void check_exhaustion(std::shared_ptr<ConnState> state) {
    if (state->completed) return;
    if (state->handshakes_in_flight > 0) return;  // Still in progress
    if (!state->pending_relays.empty()) return;    // More to try
    if (!state->query_done) return;                // Query still running
    if (state->hs_result.success) return;          // Already succeeded
    state->complete(ConnectError::PEER_CONNECTION_FAILED);
}

// ---------------------------------------------------------------------------
// §AUDIT-2: try_next_relay — drain pending relay queue, Semaphore(2).
// Called when a handshake fails and there are relays waiting.
// ---------------------------------------------------------------------------
static void try_next_relay(std::shared_ptr<ConnState> state) {
    if (state->completed) return;
    while (!state->pending_relays.empty() &&
           state->handshakes_in_flight < 2) {
        auto addr = state->pending_relays.front();
        state->pending_relays.pop_front();
        fire_handshake(state, addr);
    }
    check_exhaustion(state);
}

// ---------------------------------------------------------------------------
// §AUDIT-2: start_find_peer — initiate the Kademlia findPeer query.
// Extracted so the route-shortcut failure path can fall through to it.
// ---------------------------------------------------------------------------
static void start_find_peer(std::shared_ptr<ConnState> state) {
    if (state->completed || state->alive.expired()) return;

    state->query = dht_ops::find_peer(*state->socket, state->remote_pk,
        // on_reply: fire handshake as results stream in (pipelining)
        [state](const query::QueryReply& reply) {
            if (state->completed) return;
            if (!reply.value.has_value() || reply.value->empty()) return;
            state->found = true;
            state->relays.push_back(reply.from_addr);
            if (state->handshakes_in_flight < 2) {
                fire_handshake(state, reply.from_addr);
            } else {
                state->pending_relays.push_back(reply.from_addr);
            }
        },
        // on_done: handle "nothing found" or let check_exhaustion detect
        // all-failed. Both try_next_relay and on_done call check_exhaustion
        // to prevent termination gaps regardless of interleaving.
        [state](const std::vector<query::QueryReply>&) {
            state->query.reset();
            state->query_done = true;
            if (state->completed) return;
            if (!state->found && state->handshakes_started == 0) {
                state->complete(ConnectError::PEER_NOT_FOUND);
                return;
            }
            check_exhaustion(state);
        });
}

// ---------------------------------------------------------------------------
// do_connect — entry point for HyperDHT::connect().
//
// Orchestrates: route shortcut -> cached relays -> findPeer (pipelined) ->
// peer_handshake (Semaphore(2)) -> on_handshake_success.
// ---------------------------------------------------------------------------
void HyperDHT::do_connect(const noise::PubKey& remote_pk,
                           const noise::Keypair& keypair,
                           const ConnectOptions& opts,
                           ConnectCallback on_done) {


    auto state = std::make_shared<ConnState>();
    state->remote_pk = remote_pk;
    state->keypair = keypair;
    state->on_done = std::move(on_done);
    state->alive = alive_;
    state->socket = socket_.get();
    state->dht = this;
    state->fast_open = opts.fast_open;
    state->local_connection = opts.local_connection;
    state->relay_keep_alive = opts.relay_keep_alive;

    // JS parity (connect.js:842-848): delegate to the ConnectOptions
    // helper which mirrors `selectRelay()` — function form wins, then
    // array (random pick), then literal.
    state->relay_through = opts.select_relay_through();

    // Generate relay token if relay_through is set
    // JS: connect.js:88 — relayToken: relayThrough ? relay.token() : null
    if (state->relay_through.has_value()) {
        auto zero_check = std::array<uint8_t, 32>{};
        if (opts.relay_token == zero_check) {
            state->relay_token = blind_relay::generate_token();
        } else {
            state->relay_token = opts.relay_token;
        }
    }

    // Generate random UDX stream ID
    randombytes_buf(&state->our_udx_id, sizeof(state->our_udx_id));

    // Create rawStream BEFORE the handshake — matching JS connect.js:73.
    // JS creates the rawStream with a firewall callback at the start of
    // the connect flow, not after the handshake reply. This is critical:
    // when the server has a public IP, it sends UDX data to us immediately
    // after processing the handshake. If the rawStream doesn't exist yet,
    // we miss the server's first packet and fall through to holepunch.
    {
        auto* raw = new udx_stream_t;
        auto* raw_ctx = new ClientRawStreamCtx{state->alive, nullptr};
        std::weak_ptr<ConnState> weak_state = state;
        raw_ctx->on_firewall = [weak_state](
            udx_stream_t* stream, udx_socket_t* sock,
            const struct sockaddr* from) {
            auto st = weak_state.lock();
            if (!st || st->completed) return;

            // Phase E: Skip relay traffic — don't treat relay packets as
            // a direct connection. JS: connect.js:124-126
            //   if (c.relaySocket && isRelay(c.relaySocket, socket, port, host))
            //     return false
            if (st->relay && st->relay->raw_stream &&
                st->relay->raw_stream->socket == sock) {
                auto* relay_addr = reinterpret_cast<const struct sockaddr_in*>(
                    &st->relay->raw_stream->remote_addr);
                auto* from_addr = reinterpret_cast<const struct sockaddr_in*>(from);
                if (relay_addr->sin_port == from_addr->sin_port &&
                    relay_addr->sin_addr.s_addr == from_addr->sin_addr.s_addr) {
                    DHT_LOG("  [connect] rawStream firewall: relay traffic, ignoring\n");
                    return;  // Relay traffic — let blind-relay handle it
                }
            }

            // Can't fill keys yet — handshake hasn't completed.
            // Store the firewall info and let the handshake callback
            // check for it. This is a simplified path — the full
            // result will be built when hs_result is available.
            if (!st->hs_result.success) {
                // Handshake not done yet — can't build ConnectResult.
                // Cache the firewall event; the handshake callback will
                // replay it. JS: c.serverSocket = socket; c.serverAddress = {port, host}
                auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(from);
                char host_buf[INET_ADDRSTRLEN];
                uv_ip4_name(addr_in, host_buf, sizeof(host_buf));
                st->cached_fw_socket = sock;
                st->cached_fw_address = compact::Ipv4Address::from_string(
                    host_buf, ntohs(addr_in->sin_port));
                DHT_LOG("  [connect] rawStream firewall cached (handshake pending): %s:%u\n",
                        host_buf, ntohs(addr_in->sin_port));
                return;
            }

            auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(from);
            char host[INET_ADDRSTRLEN];
            uv_ip4_name(addr_in, host, sizeof(host));
            auto real_addr = compact::Ipv4Address::from_string(
                host, ntohs(addr_in->sin_port));

            DHT_LOG("  [connect] rawStream firewall: %s:%u\n",
                    host, ntohs(addr_in->sin_port));

            ConnectResult result;
            result.success = true;
            result.tx_key = st->hs_result.tx_key;
            result.rx_key = st->hs_result.rx_key;
            result.handshake_hash = st->hs_result.handshake_hash;
            result.remote_public_key = st->hs_result.remote_public_key;
            result.peer_address = real_addr;
            result.udx_socket = sock;
            if (sock == st->pool_socket_handle)
                result.socket_keepalive = st->pool_socket_keepalive;
            result.local_udx_id = st->our_udx_id;
            if (st->hs_result.remote_payload.udx.has_value()) {
                result.remote_udx_id = st->hs_result.remote_payload.udx->id;
            }
            st->take_raw_stream(result);
            st->complete(0, result);
        };
        udx_stream_init(state->socket->udx_handle(), raw,
                        state->our_udx_id,
                        [](udx_stream_t*, int) {},
                        [](udx_stream_t* s) {
                            // RAII: delete context when stream closes, regardless
                            // of which callback path fires (firewall, recv, or error).
                            if (s->data) {
                                delete static_cast<ClientRawStreamCtx*>(s->data);
                                s->data = nullptr;
                            }
                            delete s;
                        });
        raw->data = raw_ctx;
        udx_stream_firewall(raw, client_raw_stream_firewall);
        state->raw_stream = raw;
    }

    // §AUDIT-6: Route shortcut — try cached socket+address before findPeer.
    // JS: connect.js:177-183 — retryRoute before findAndConnect.
    if (socket_pool_) {
        auto* route = socket_pool_->get_route(remote_pk);
        if (route) {
            DHT_LOG("  [connect] route shortcut: trying cached route\n");
            state->found = true;
            // Try handshake through cached route. On failure, fall through
            // to findPeer. We don't increment handshakes_in_flight because
            // this path returns early (line below) — no pipelining runs
            // concurrently. INVARIANT: the `return` below is load-bearing.
            auto route_addr = route->address;
            peer_connect::peer_handshake(*socket_, route_addr,
                keypair, remote_pk, state->our_udx_id,
                peer_connect::FIREWALL_UNKNOWN, {},
                std::nullopt,
                [state, route_addr](const peer_connect::HandshakeResult& hs) {
                    if (state->completed || state->alive.expired()) return;
                    if (hs.success) {
                        state->relay_addr = route_addr;
                        state->hs_result = hs;
                        on_handshake_success(state, hs);
                        return;
                    }
                    // Route failed — fall through to findPeer
                    DHT_LOG("  [connect] route shortcut failed, starting findPeer\n");
                    start_find_peer(state);
                });
            return;  // Route attempt in progress — findPeer deferred
        }
    }

    // §AUDIT-3: Pre-populate from relay address cache on reconnect.
    // JS: connect.js:323-324 — use cached relays as initial set.
    auto cached = get_cached_relay_addresses(remote_pk);
    if (!cached.empty()) {
        DHT_LOG("  [connect] relay cache hit: %zu cached relays\n",
                cached.size());
        state->found = true;
        for (const auto& addr : cached) {
            if (state->handshakes_in_flight < 2) {
                fire_handshake(state, addr);
            } else {
                state->pending_relays.push_back(addr);
            }
        }
    }

    // Step 1: findPeer with pipelining — handshakes fire as results
    // stream in. JS: connect.js:350-362 (for-await + Semaphore(2)).
    start_find_peer(state);
}

// ---------------------------------------------------------------------------
// on_handshake_success — post-handshake decision tree.
//
// Called from do_connect's peer_handshake callback after the handshake
// succeeds. Dispatches to one of the following paths:
//   1. Cached firewall replay (server sent data before handshake reply)
//   2. Blind relay (if either side has relayThrough)
//   3. Direct connect (OPEN firewall or no holepunch info)
//   4. Passive wait (our firewall is OPEN)
//   5. LAN shortcut (same NAT)
//   6. Holepunch
//
// Paths 2, 4, 5, 6 can run in parallel — first to complete wins via
// state->completed guard.
//
// JS: .analysis/js/hyperdht/lib/connect.js:405-503 (post-handshake block
// inside connectThroughNode)
// ---------------------------------------------------------------------------
static void on_handshake_success(std::shared_ptr<ConnState> state,
                                  const peer_connect::HandshakeResult& hs) {
    // Replay cached firewall event if server's first packet arrived before
    // the handshake reply. JS: connect.js:493-496
    //   if (c.serverSocket) { c.onsocket(c.serverSocket, ...); return }
    if (state->cached_fw_socket && !state->completed) {
        DHT_LOG("  [connect] Replaying cached firewall event\n");
        ConnectResult result;
        result.success = true;
        result.tx_key = hs.tx_key;
        result.rx_key = hs.rx_key;
        result.handshake_hash = hs.handshake_hash;
        result.remote_public_key = hs.remote_public_key;
        result.peer_address = state->cached_fw_address;
        result.udx_socket = state->cached_fw_socket;
        if (state->cached_fw_socket == state->pool_socket_handle)
            result.socket_keepalive = state->pool_socket_keepalive;
        result.local_udx_id = state->our_udx_id;
        if (hs.remote_payload.udx.has_value()) {
            result.remote_udx_id = hs.remote_payload.udx->id;
        }
        state->take_raw_stream(result);
        state->complete(0, result);
        return;
    }

    // Log the server's handshake reply
    DHT_LOG("  [connect] Server reply: fw=%u, addrs4=%zu, hp=%s, relays=%zu, "
            "relayThrough=%s\n",
            hs.remote_payload.firewall,
            hs.remote_payload.addresses4.size(),
            hs.remote_payload.holepunch.has_value() ? "yes" : "no",
            hs.remote_payload.holepunch.has_value()
                ? hs.remote_payload.holepunch->relays.size() : 0,
            hs.remote_payload.relay_through.has_value() ? "yes" : "no");

    // Phase E: Start blind relay if either side has relayThrough.
    // JS: connect.js:489-491 — if (payload.relayThrough || c.relayThrough)
    //     relayConnection(c, c.relayThrough, payload, hs)
    // This runs in PARALLEL with holepunch (not sequential).
    // First to complete wins via state->completed.
    if (hs.remote_payload.relay_through.has_value() ||
        state->relay_through.has_value()) {
        bool is_initiator;
        noise::PubKey relay_pk;
        blind_relay::Token relay_token;

        if (hs.remote_payload.relay_through.has_value()) {
            // Server proposed relay — we're non-initiator
            is_initiator = false;
            relay_pk = hs.remote_payload.relay_through->public_key;
            relay_token = hs.remote_payload.relay_through->token;
        } else {
            // We proposed relay — we're initiator
            is_initiator = true;
            relay_pk = *state->relay_through;
            relay_token = state->relay_token;
        }
        state->relay_token = relay_token;
        start_relay_path(state, is_initiator, relay_pk, relay_token);
    }

    // Check for direct connect (OPEN firewall)
    holepunch::HolepunchResult hp_result;
    if (holepunch::try_direct_connect(hs, hp_result)) {
        DHT_LOG("  [connect] *** DIRECT CONNECT (server OPEN) → %s:%u "
                "(no holepunch, no pool socket) ***\n",
                hp_result.address.host_string().c_str(), hp_result.address.port);
        ConnectResult result;
        result.success = true;
        result.tx_key = hs.tx_key;
        result.rx_key = hs.rx_key;
        result.handshake_hash = hs.handshake_hash;
        result.remote_public_key = hs.remote_public_key;
        result.peer_address = hp_result.address;
        result.local_udx_id = state->our_udx_id;
        if (hs.remote_payload.udx.has_value()) {
            result.remote_udx_id = hs.remote_payload.udx->id;
        }
        state->take_raw_stream(result);
        state->complete(0, result);
        return;
    }

    // JS: if no holepunch info (server is OPEN or unreachable for holepunching),
    // try direct connect using addresses
    if (!hs.remote_payload.holepunch.has_value() ||
        hs.remote_payload.holepunch->relays.empty()) {
        if (!hs.remote_payload.addresses4.empty()) {
            DHT_LOG("  [connect] *** NO HOLEPUNCH INFO → direct connect to %s:%u ***\n",
                    hs.remote_payload.addresses4[0].host_string().c_str(),
                    hs.remote_payload.addresses4[0].port);
            ConnectResult result;
            result.success = true;
            result.tx_key = hs.tx_key;
            result.rx_key = hs.rx_key;
            result.handshake_hash = hs.handshake_hash;
            result.remote_public_key = hs.remote_public_key;
            result.peer_address = hs.remote_payload.addresses4[0];
            result.local_udx_id = state->our_udx_id;
            if (hs.remote_payload.udx.has_value()) {
                result.remote_udx_id = hs.remote_payload.udx->id;
            }
            state->take_raw_stream(result);
            state->complete(0, result);
        } else {
            state->complete(ConnectError::NO_ADDRESSES);
        }
        return;
    }

    auto& hp_info = *hs.remote_payload.holepunch;

    // Use handshake relay if in holepunch relay list
    auto hp_relay = hp_info.relays[0].relay_address;
    auto hp_peer = hp_info.relays[0].peer_address;
    for (const auto& r : hp_info.relays) {
        if (r.relay_address.host_string() == state->relay_addr.host_string() &&
            r.relay_address.port == state->relay_addr.port) {
            hp_relay = r.relay_address;
            hp_peer = r.peer_address;
            break;
        }
    }

    auto fw = state->socket->nat_sampler().firewall();
    auto addrs = state->socket->nat_sampler().addresses();

    // JS: if our firewall is OPEN, wait passively for server to probe us
    // (via rawStream firewall callback). 10s timeout.
    // JS: connect.js:228-231 — passive wait when our firewall is OPEN
    if (fw == peer_connect::FIREWALL_OPEN) {
        DHT_LOG("  [connect] Our firewall is OPEN, waiting passively (10s)\n");
        state->passive_timer = std::make_unique<async_utils::UvTimer>(
            state->socket->loop());
        state->passive_timer->start([state]() {
            if (!state->completed) {
                state->complete(ConnectError::HOLEPUNCH_TIMEOUT);
            }
        }, 10000);
        return;
    }

    // --- §6: localConnection LAN shortcut ------------------
    // JS: connect.js:234-251 — same-NAT shortcut. See file header for details.
    {
        const bool relayed = !hs.remote_payload.addresses4.empty() &&
            (hs.remote_payload.addresses4[0] != state->relay_addr);

        if (state->local_connection && relayed &&
            !state->socket->nat_sampler().host().empty() &&
            state->socket->nat_sampler().host() ==
                hs.remote_payload.addresses4[0].host_string()) {

            auto my_local = holepunch::local_addresses(0);
            auto matched = holepunch::match_address(
                my_local, hs.remote_payload.addresses4);

            auto lan_addr = matched.value_or(hs.remote_payload.addresses4[0]);

            DHT_LOG("  [connect] LAN shortcut: target %s:%u (matched=%s)\n",
                    lan_addr.host_string().c_str(), lan_addr.port,
                    matched.has_value() ? "yes" : "fallback");

            assert(state->dht && "ConnState::dht must be set");
            state->dht->ping(lan_addr,
                [state, lan_addr](bool ok) {
                    if (state->completed) return;
                    if (!ok) {
                        DHT_LOG("  [connect] LAN ping failed, "
                                "falling back to holepunch\n");
                        return;  // holepunch path runs in parallel
                    }
                    DHT_LOG("  [connect] LAN ping OK — short-circuiting\n");
                    ConnectResult result;
                    result.success = true;
                    result.tx_key = state->hs_result.tx_key;
                    result.rx_key = state->hs_result.rx_key;
                    result.handshake_hash = state->hs_result.handshake_hash;
                    result.remote_public_key = state->hs_result.remote_public_key;
                    result.peer_address = lan_addr;
                    result.local_udx_id = state->our_udx_id;
                    if (state->hs_result.remote_payload.udx.has_value()) {
                        result.remote_udx_id =
                            state->hs_result.remote_payload.udx->id;
                    }
                    state->take_raw_stream(result);
                    state->complete(0, result);
                });
            // Note: we do NOT return here. The holepunch below runs in
            // parallel so a slow LAN ping doesn't block the connect —
            // whichever path completes first wins via state->completed.
        }
    }
    // --- end §6 LAN shortcut ------------------------------

    holepunch::holepunch_connect(*state->socket, hs,
        hp_relay, hp_peer, hp_info.id, fw, addrs,
        [state](const holepunch::HolepunchResult& hp) {
            if (state->completed) return;  // rawStream firewall already connected
            if (state->alive.expired() || !hp.success) {
                state->complete(ConnectError::HOLEPUNCH_FAILED);
                return;
            }
            ConnectResult result;
            result.success = true;
            result.tx_key = state->hs_result.tx_key;
            result.rx_key = state->hs_result.rx_key;
            result.handshake_hash = state->hs_result.handshake_hash;
            result.remote_public_key = state->hs_result.remote_public_key;
            result.peer_address = hp.address;
            result.udx_socket = hp.socket;  // JS: ref.socket from probe
            result.socket_keepalive = hp.socket_keepalive;
            result.local_udx_id = state->our_udx_id;
            if (state->hs_result.remote_payload.udx.has_value()) {
                result.remote_udx_id = state->hs_result.remote_payload.udx->id;
            }
            state->take_raw_stream(result);
            state->complete(0, result);
        },
        state->fast_open,
        &state->pool_socket_handle,
        &state->pool_socket_keepalive);
}

// ---------------------------------------------------------------------------
// start_relay_path — blind relay connection chain.
//
// dht.connect(relay_pk) -> SecretStream -> Protomux -> BlindRelayClient ->
// pair -> wire rawStream through relay.
//
// JS: .analysis/js/hyperdht/lib/connect.js:746-795 (relayConnection function)
// ---------------------------------------------------------------------------
static void start_relay_path(std::shared_ptr<ConnState> state,
                              bool is_initiator,
                              noise::PubKey relay_pk,
                              blind_relay::Token relay_token) {
    DHT_LOG("  [connect] Starting blind relay: initiator=%d, "
            "relay_pk=%02x%02x...\n",
            is_initiator, relay_pk[0], relay_pk[1]);

    // Create relay state (RAII — destructor handles teardown)
    state->relay = std::make_unique<ConnState::RelayState>();

    if (state->dht) {
        state->dht->relay_stats().attempts++;
    }

    // 15-second timeout for relay pairing (RAII — auto-cleaned)
    // JS: connect.js:765 — c.relayTimeout = setTimeout(onabort, 15000)
    state->relay->timeout = std::make_unique<async_utils::UvTimer>(
        state->dht->loop());
    state->relay->timeout->start([state]() {
        if (!state->completed) {
            DHT_LOG("  [connect] Relay pairing timed out (15s)\n");
            if (state->dht) {
                state->dht->relay_stats().aborts++;
            }
        }
    }, blind_relay::RELAY_TIMEOUT_MS);

    // Step 1: Connect to the relay node via normal DHT connect.
    // JS: connect.js:762 — c.relaySocket = c.dht.connect(publicKey)
    state->dht->connect(relay_pk,
        [state, is_initiator, relay_token](
            int err, const ConnectResult& relay_result) {
        if (state->completed || state->alive.expired()) return;
        if (err != 0 || !relay_result.success) {
            DHT_LOG("  [connect] Relay connect to relay node failed: %d\n", err);
            if (state->dht) state->dht->relay_stats().aborts++;
            return;  // Holepunch path may still succeed
        }

        DHT_LOG("  [connect] Connected to relay node, setting up Protomux\n");

        // Step 2: Create SecretStream over the relay connection.
        state->relay->raw_stream = relay_result.raw_stream;

        secret_stream::DuplexHandshake relay_hs;
        relay_hs.tx_key = relay_result.tx_key;
        relay_hs.rx_key = relay_result.rx_key;
        relay_hs.handshake_hash = relay_result.handshake_hash;
        relay_hs.remote_public_key = relay_result.remote_public_key;
        relay_hs.is_initiator = true;

        auto duplex_opts = state->dht->make_duplex_options();
        duplex_opts.keep_alive_ms = state->relay_keep_alive;

        // Connect the raw stream to the relay node's address
        if (relay_result.udx_socket && relay_result.raw_stream) {
            struct sockaddr_in relay_addr{};
            relay_addr.sin_family = AF_INET;
            relay_addr.sin_port = htons(relay_result.peer_address.port);
            uv_ip4_addr(relay_result.peer_address.host_string().c_str(),
                        relay_result.peer_address.port,
                        &relay_addr);
            udx_stream_connect(relay_result.raw_stream,
                               relay_result.udx_socket,
                               relay_result.remote_udx_id,
                               reinterpret_cast<const struct sockaddr*>(&relay_addr));
        }

        state->relay->duplex = std::make_unique<secret_stream::SecretStreamDuplex>(
            relay_result.raw_stream, relay_hs,
            state->dht->loop(), duplex_opts);

        // Step 3: Create Protomux over the SecretStream.
        state->relay->mux = std::make_unique<protomux::Mux>(
            [duplex = state->relay->duplex.get()](
                const uint8_t* data, size_t len) -> bool {
                if (!duplex) return false;
                duplex->write(data, len, nullptr);
                return true;
            });

        state->relay->duplex->on_message(
            [mux = state->relay->mux.get()](
                const uint8_t* data, size_t len) {
                if (mux && !mux->is_destroyed()) {
                    mux->on_data(data, len);
                }
            });

        state->relay->duplex->start();

        // Step 4: Create BlindRelayClient over the Protomux channel.
        // JS: relay.Client.from(relaySocket, { id: relaySocket.publicKey })
        std::vector<uint8_t> channel_id(
            relay_result.remote_public_key.begin(),
            relay_result.remote_public_key.end());
        auto* channel = state->relay->mux->create_channel(
            blind_relay::PROTOCOL_NAME, channel_id, false);
        if (!channel) {
            DHT_LOG("  [connect] Failed to create blind-relay channel\n");
            if (state->dht) state->dht->relay_stats().aborts++;
            return;
        }

        state->relay->client = std::make_unique<blind_relay::BlindRelayClient>(channel);
        state->relay->client->open();

        // Step 5: Pair our rawStream through the relay.
        // JS: c.relayClient.pair(isInitiator, token, c.rawStream)
        state->relay->client->pair(
            is_initiator, relay_token, state->our_udx_id,
            [state](uint32_t remote_id) {
                // Pair success!
                if (state->completed || state->alive.expired()) return;

                DHT_LOG("  [connect] Relay pairing succeeded! remote_id=%u\n",
                        remote_id);

                // Cancel timeout (RAII handles cleanup)
                state->relay->timeout.reset();

                state->relay->paired = true;
                if (state->dht) state->dht->relay_stats().successes++;

                // Step 6: Wire our rawStream through the relay.
                auto* relay_raw = state->relay->raw_stream;
                if (!relay_raw || !state->raw_stream) {
                    DHT_LOG("  [connect] Relay paired but streams gone\n");
                    return;
                }

                auto* relay_addr = reinterpret_cast<const struct sockaddr_in*>(
                    &relay_raw->remote_addr);
                udx_socket_t* relay_socket = relay_raw->socket;

                udx_stream_connect(state->raw_stream, relay_socket,
                                   remote_id,
                                   reinterpret_cast<const struct sockaddr*>(relay_addr));

                ConnectResult result;
                result.success = true;
                result.tx_key = state->hs_result.tx_key;
                result.rx_key = state->hs_result.rx_key;
                result.handshake_hash = state->hs_result.handshake_hash;
                result.remote_public_key = state->hs_result.remote_public_key;

                char host[INET_ADDRSTRLEN];
                uv_ip4_name(relay_addr, host, sizeof(host));
                result.peer_address = compact::Ipv4Address::from_string(
                    host, ntohs(relay_addr->sin_port));

                result.udx_socket = relay_socket;
                result.local_udx_id = state->our_udx_id;
                if (state->hs_result.remote_payload.udx.has_value()) {
                    result.remote_udx_id =
                        state->hs_result.remote_payload.udx->id;
                }
                state->take_raw_stream(result);
                state->complete(0, result);
            },
            [state](int err) {
                // Pair error — relay failed, holepunch may still work
                if (state->completed) return;
                DHT_LOG("  [connect] Relay pairing failed: %d\n", err);
                if (state->dht) state->dht->relay_stats().aborts++;
            });
    });
}

}  // namespace hyperdht
