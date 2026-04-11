// HyperDHT main class implementation — owns the RPC socket, routing
// table, announce store, query engine and connection pool. Provides
// connect(), listen(), suspend()/resume() and the tick/bootstrap loop.

#include "hyperdht/dht.hpp"

#include <sodium.h>

#include <cassert>
#include <cstdio>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/debug.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/peer_connect.hpp"

// Context stored in client rawStream->data during handshake→connection window.
// Matches JS: rawStream created at connect() time with firewall callback.
struct ClientRawStreamCtx {
    std::weak_ptr<bool> alive;
    std::function<void(udx_stream_t*, const struct sockaddr*)> on_firewall;
};

// Firewall callback for client-side rawStream. Fires when the server's
// first UDX packet arrives with the REAL peer address.
// Matches JS: rawStream firewall → c.onsocket(socket, port, host)
static int client_raw_stream_firewall(udx_stream_t* stream, udx_socket_t*,
                                       const struct sockaddr* from) {
    auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(from);
    char host[INET_ADDRSTRLEN];
    uv_ip4_name(addr_in, host, sizeof(host));
    printf("  [rawStream] FIREWALL FIRED from %s:%u (stream=%u)\n",
           host, ntohs(addr_in->sin_port), stream->local_id);
    fflush(stdout);
    auto* ctx = static_cast<ClientRawStreamCtx*>(stream->data);
    if (ctx && !ctx->alive.expired() && ctx->on_firewall) {
        ctx->on_firewall(stream, from);
    }
    return 0;
}

namespace hyperdht {

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

HyperDHT::HyperDHT(uv_loop_t* loop, DhtOptions opts)
    : loop_(loop), opts_(std::move(opts)) {

    // Resolve the default keypair — JS `opts.keyPair || createKeyPair(opts.seed)`.
    // Priority:
    //   1. If the caller pre-populated `default_keypair`, use as-is.
    //   2. Otherwise if `seed` is set, derive deterministically (§7).
    //   3. Otherwise generate random.
    auto zero_pk = noise::PubKey{};
    if (opts_.default_keypair.public_key == zero_pk) {
        if (opts_.seed.has_value()) {
            opts_.default_keypair = noise::generate_keypair(*opts_.seed);
        } else {
            opts_.default_keypair = noise::generate_keypair();
        }
    } else if (opts_.seed.has_value()) {
        // Both explicit keypair AND seed set — the keypair wins, seed is
        // silently ignored by JS too. Log a warning so the caller notices.
        DHT_LOG("  [dht] WARNING: both default_keypair and seed set; "
                "seed ignored (keypair takes priority)\n");
    }

    // Create RPC socket with our public key as node ID.
    // Both NodeId and PubKey are 32-byte arrays — assert the invariant
    // so any future divergence fails at compile time.
    static_assert(sizeof(routing::NodeId) == sizeof(noise::PubKey),
                  "NodeId must be the same size as PubKey");
    routing::NodeId our_id{};
    std::copy(opts_.default_keypair.public_key.begin(),
              opts_.default_keypair.public_key.end(),
              our_id.begin());

    socket_ = std::make_unique<rpc::RpcSocket>(loop_, our_id);

    // §7: thread storage cache tuning into the handlers.
    // max_size governs entry count (JS: opts.maxSize); ttl_ms is the
    // storage-specific 48h default (JS: hyperdht/index.js:611,615 —
    // `opts.maxAge || 48h` for mutable/immutable). max_age_ms is used
    // by other caches once they're added, not the storage caches.
    rpc::StorageCacheConfig cache_config;
    cache_config.max_size = opts_.max_size;
    cache_config.ttl_ms = opts_.storage_ttl_ms;
    handlers_ = std::make_unique<rpc::RpcHandlers>(
        *socket_, &router_, cache_config);
    handlers_->install();

    // §7: pre-seed the routing table with known-good nodes so the DHT
    // starts with a non-empty table and doesn't need the initial bootstrap
    // query to be useful. JS: `dht-rpc/index.js:95-99` iterates REVERSE;
    // `_addNode` at index.js:526 populates `added`/`pinged`/`seen` with
    // `this._tick`. Without the tick fields, ping-and-swap would immediately
    // evict these nodes (they'd look like "never seen" relative to any
    // node with a non-zero sampled tick). Use the current RPC tick.
    const uint32_t seed_tick = socket_->tick();
    for (auto it = opts_.nodes.rbegin(); it != opts_.nodes.rend(); ++it) {
        routing::Node node;
        node.id = rpc::compute_peer_id(*it);
        node.host = it->host_string();
        node.port = it->port;
        node.added = seed_tick;
        node.pinged = seed_tick;
        node.seen = seed_tick;
        socket_->table().add(node);
    }

    // §7: random-punch tuning and defer flag.
    punch_stats_.random_punch_interval = opts_.random_punch_interval;
    if (opts_.defer_random_punch) {
        // Seed `last_random_punch` with "now" so the first random punch
        // has to wait the full interval. JS: index.js:58.
        punch_stats_.last_random_punch = uv_now(loop_);
    }
}

HyperDHT::~HyperDHT() {
    if (!destroyed_) {
        destroy();
    }
}

// ---------------------------------------------------------------------------
// bind
//
// JS: .analysis/js/dht-rpc/index.js:157-159 (DHT.bind delegates to io.bind)
// ---------------------------------------------------------------------------

int HyperDHT::bind() {
    if (bound_) return 0;
    // §7: pass opts.host so multi-homed or specific-interface binds work.
    int rc = socket_->bind(opts_.port, opts_.host);
    if (rc == 0) bound_ = true;
    return rc;
}

void HyperDHT::ensure_bound() {
    if (!bound_) bind();
}

// ---------------------------------------------------------------------------
// connect — client connection to a remote peer.
//
// JS: .analysis/js/hyperdht/lib/connect.js:32-115 (module.exports = connect)
//
// C++ diffs from JS:
//   - JS returns the encryptedSocket synchronously and runs the connect
//     pipeline in the background; C++ takes a completion callback and runs
//     the same pipeline through nested lambdas.
//   - JS attaches the encryptedSocket to the pool inside connect() itself
//     (connect.js:54). C++ leaves pool wiring to ConnectionPool helpers.
//   - The 3 overloads collapse JS's `opts.keyPair` and pool/duplicate handling
//     (connect.js:33-52) into one fast-path branch each.
// ---------------------------------------------------------------------------

void HyperDHT::connect(const noise::PubKey& remote_public_key,
                        ConnectCallback on_done) {
    connect(remote_public_key, ConnectOptions{}, std::move(on_done));
}

void HyperDHT::connect(const noise::PubKey& remote_public_key,
                        const ConnectOptions& opts,
                        ConnectCallback on_done) {
    if (destroyed_) {
        DHT_LOG("  [dht] connect: rejected (destroyed)\n");
        on_done(-1, {});
        return;
    }
    // JS: connect.js:49-51 — `dht.suspended || !dht._connectable` rejects.
    if (suspended_) {
        DHT_LOG("  [dht] connect: rejected (suspended)\n");
        on_done(-8, {});  // SUSPENDED
        return;
    }
    ensure_bound();

    // JS: if pool has existing connection, return it
    if (opts.pool && opts.pool->has(remote_public_key)) {
        // Connection already exists — caller should use pool.get() directly
        DHT_LOG("  [dht] connect: rejected (duplicate in pool)\n");
        on_done(-7, {});  // DUPLICATE
        return;
    }

    // JS: `opts.keyPair || dht.defaultKeyPair` — per-connect override.
    const noise::Keypair& keypair = opts.keypair.has_value()
        ? *opts.keypair
        : opts_.default_keypair;

    DHT_LOG("  [dht] connect: remote=%02x%02x%02x%02x... "
            "(keypair=%s, fast_open=%d, local_connection=%d)\n",
            remote_public_key[0], remote_public_key[1],
            remote_public_key[2], remote_public_key[3],
            opts.keypair.has_value() ? "override" : "default",
            opts.fast_open ? 1 : 0, opts.local_connection ? 1 : 0);

    do_connect(remote_public_key, keypair, opts, std::move(on_done));
}

void HyperDHT::connect(const noise::PubKey& remote_public_key,
                        const noise::Keypair& keypair,
                        ConnectCallback on_done) {
    if (destroyed_) {
        DHT_LOG("  [dht] connect (keypair): rejected (destroyed)\n");
        on_done(-1, {});
        return;
    }
    // §6/§7 parity: suspended DHT must reject connect from all overloads,
    // matching JS `connect.js:49-51` (`dht.suspended || !dht._connectable`).
    if (suspended_) {
        DHT_LOG("  [dht] connect (keypair): rejected (suspended)\n");
        on_done(-8, {});  // SUSPENDED
        return;
    }
    ensure_bound();
    do_connect(remote_public_key, keypair, ConnectOptions{}, std::move(on_done));
}

// ---------------------------------------------------------------------------
// do_connect — orchestrates findPeer → handshake → holepunch → ready.
//
// JS: .analysis/js/hyperdht/lib/connect.js:176-194 (connectAndHolepunch)
//     .analysis/js/hyperdht/lib/connect.js:318-384 (findAndConnect)
//     .analysis/js/hyperdht/lib/connect.js:386-503 (connectThroughNode)
//     .analysis/js/hyperdht/lib/connect.js:205-316 (holepunch)
//
// C++ diffs from JS:
//   - No async/await: a ConnState shared_ptr is threaded through nested
//     lambdas. JS's `isDone(c)` (connect.js:138-153) check becomes
//     `state->completed`.
//   - JS uses Semaphore(2) over an async iterator (connect.js:336-368).
//     C++ implements a sequential retry loop (`try_relay_fn`) that fires
//     two attempts up front but otherwise advances on failure.
//   - `alive` weak_ptr sentinel replaces JS's `dht.destroyed` and
//     `c.encryptedSocket.destroying` checks.
//   - Client rawStream + firewall callback are created lazily (after the
//     handshake completes) rather than at connect() time as in JS
//     (connect.js:73). The firewall hook still mirrors JS's behaviour:
//     fire `c.onsocket` when the server's first packet arrives.
//   - LAN shortcut (§6) and holepunch run in parallel — first to complete
//     wins via `state->completed`. JS aborts on LAN ping failure
//     (connect.js:243-246); we fall through to holepunch instead.
// ---------------------------------------------------------------------------
void HyperDHT::do_connect(const noise::PubKey& remote_pk,
                           const noise::Keypair& keypair,
                           const ConnectOptions& opts,
                           ConnectCallback on_done) {

    // State shared across the async pipeline
    struct ConnState {
        noise::PubKey remote_pk;
        noise::Keypair keypair;
        ConnectCallback on_done;
        compact::Ipv4Address relay_addr;
        std::vector<compact::Ipv4Address> relays;  // All relays from findPeer
        int relay_idx = -1;  // Current retry index (counts down from end)
        peer_connect::HandshakeResult hs_result;
        std::shared_ptr<query::Query> query;
        std::shared_ptr<std::function<void()>> try_relay_fn;  // Relay retry loop
        std::weak_ptr<bool> alive;  // Sentinel — expired if HyperDHT destroyed
        rpc::RpcSocket* socket = nullptr;  // Raw pointer, guarded by alive
        HyperDHT* dht = nullptr;  // Raw pointer, guarded by alive
        bool found = false;
        uint32_t our_udx_id = 0;
        udx_stream_t* raw_stream = nullptr;  // Client rawStream (like JS)
        bool completed = false;
        // §6 ConnectOptions snapshot (copied, not referenced — opts may
        // outlive the original scope once we enter async territory).
        bool fast_open = true;
        bool local_connection = true;

        ~ConnState() {
            // Clean up rawStream if not transferred to ConnectResult
            if (raw_stream) {
                if (raw_stream->data) {
                    delete static_cast<ClientRawStreamCtx*>(raw_stream->data);
                    raw_stream->data = nullptr;
                }
                udx_stream_destroy(raw_stream);
            }
        }

        void complete(int err, const ConnectResult& result = {}) {
            if (completed) return;  // Prevent double invocation (firewall + holepunch race)
            completed = true;
            auto cb = std::move(on_done);
            on_done = nullptr;
            if (cb) cb(err, result);
        }

        // Transfer rawStream ownership to result, cleaning up firewall ctx
        void take_raw_stream(ConnectResult& result) {
            if (raw_stream) {
                if (raw_stream->data) {
                    delete static_cast<ClientRawStreamCtx*>(raw_stream->data);
                    raw_stream->data = nullptr;
                }
                result.raw_stream = raw_stream;
                raw_stream = nullptr;
            }
        }
    };

    auto state = std::make_shared<ConnState>();
    state->remote_pk = remote_pk;
    state->keypair = keypair;
    state->on_done = std::move(on_done);
    state->alive = alive_;
    state->socket = socket_.get();
    state->dht = this;
    state->fast_open = opts.fast_open;
    state->local_connection = opts.local_connection;

    // Generate random UDX stream ID
    randombytes_buf(&state->our_udx_id, sizeof(state->our_udx_id));

    // Step 1: findPeer — collect all relays that have the peer record.
    // JS: findAndConnect tries connectThroughNode for each result.
    // JS: connect.js:341-368 — for-await over findPeer query, semaphore(2)
    state->query = dht_ops::find_peer(*socket_, remote_pk,
        [state](const query::QueryReply& reply) {
            if (reply.value.has_value() && !reply.value->empty()) {
                state->found = true;
                state->relays.push_back(reply.from_addr);
            }
        },
        [state](const std::vector<query::QueryReply>&) {
            state->query.reset();

            if (state->alive.expired() || !state->found) {
                state->complete(-2);
                return;
            }

            // Step 2: try PEER_HANDSHAKE through relays, closest first.
            // JS: connectThroughNode for each relay, semaphore(2).
            // We try sequentially from end (closest = freshest),
            // but fire 2 initial attempts in parallel.
            state->relay_idx = static_cast<int>(state->relays.size()) - 1;
            state->try_relay_fn = std::make_shared<std::function<void()>>();
            *state->try_relay_fn = [state]() {
                if (state->completed || state->alive.expired()) return;
                if (state->relay_idx < 0) {
                    // Copy state before reset — reset destroys this lambda
                    // and its captured state, causing use-after-free
                    auto st = state;
                    st->try_relay_fn.reset();
                    st->complete(-3);
                    return;
                }

                state->relay_addr = state->relays[state->relay_idx];
                state->relay_idx--;

                peer_connect::peer_handshake(*state->socket, state->relay_addr,
                    state->keypair, state->remote_pk, state->our_udx_id,
                    [state](const peer_connect::HandshakeResult& hs) {
                        if (state->completed) return;
                        if (state->alive.expired() || !hs.success) {
                            if (state->try_relay_fn) (*state->try_relay_fn)();
                            return;
                        }
                        state->try_relay_fn.reset();  // Break cycle
                    state->hs_result = hs;

                    // Create rawStream NOW — like JS rawStream with firewall.
                    // When the server sends UDX packets directly (public IP),
                    // the firewall fires with the real address → connection.
                    {
                        auto* raw = new udx_stream_t;
                        auto* raw_ctx = new ClientRawStreamCtx{state->alive, nullptr};
                        std::weak_ptr<ConnState> weak_state = state;
                        raw_ctx->on_firewall = [weak_state](
                            udx_stream_t* stream, const struct sockaddr* from) {
                            auto st = weak_state.lock();
                            if (!st || st->completed) return;

                            auto* addr_in = reinterpret_cast<const struct sockaddr_in*>(from);
                            char host[INET_ADDRSTRLEN];
                            uv_ip4_name(addr_in, host, sizeof(host));
                            auto real_addr = compact::Ipv4Address::from_string(
                                host, ntohs(addr_in->sin_port));

                            ConnectResult result;
                            result.success = true;
                            result.tx_key = st->hs_result.tx_key;
                            result.rx_key = st->hs_result.rx_key;
                            result.handshake_hash = st->hs_result.handshake_hash;
                            result.remote_public_key = st->hs_result.remote_public_key;
                            result.peer_address = real_addr;
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
                                        [](udx_stream_t* s) { delete s; });
                        raw->data = raw_ctx;
                        udx_stream_firewall(raw, client_raw_stream_firewall);
                        state->raw_stream = raw;
                    }

                    // Check for direct connect (OPEN firewall)
                    holepunch::HolepunchResult hp_result;
                    if (holepunch::try_direct_connect(hs, hp_result)) {
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

                    // JS: if no holepunch info (server is OPEN or unreachable
                    // for holepunching), try direct connect using addresses
                    if (!hs.remote_payload.holepunch.has_value() ||
                        hs.remote_payload.holepunch->relays.empty()) {
                        // Use first address from the server's payload
                        if (!hs.remote_payload.addresses4.empty()) {
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
                            state->complete(-4);
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

                    // JS: if our firewall is OPEN, wait passively for server
                    // to probe us (via rawStream firewall callback). 10s timeout.
                    // JS: connect.js:228-231 — passive wait when our firewall is OPEN
                    if (fw == peer_connect::FIREWALL_OPEN) {
                        DHT_LOG("  [connect] Our firewall is OPEN, waiting passively (10s)\n");
                        auto* passive_timer = new uv_timer_t;
                        uv_timer_init(state->socket->loop(), passive_timer);
                        passive_timer->data = new std::shared_ptr<ConnState>(state);
                        uv_timer_start(passive_timer, [](uv_timer_t* t) {
                            auto* sp = static_cast<std::shared_ptr<ConnState>*>(t->data);
                            if (sp && *sp && !(*sp)->completed) {
                                (*sp)->complete(-6);  // Passive connect timeout
                            }
                            delete sp;
                            t->data = nullptr;
                            uv_close(reinterpret_cast<uv_handle_t*>(t),
                                     [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
                        }, 10000, 0);
                        return;
                    }

                    // --- §6: localConnection LAN shortcut ------------------
                    // JS: connect.js:234-251 — if (a) the connection went
                    // through a relay (server's address differs from the
                    // relay's), AND (b) our public IP matches the server's
                    // public IP (both behind the same NAT), AND (c) the
                    // server advertises addresses we can match against,
                    // pick the best match (fall back to addresses[0] when
                    // no octet match), ping it, and short-circuit holepunch.
                    //
                    // Differences from JS:
                    //   - JS uses `clientAddress.host === serverAddress.host`
                    //     where clientAddress is from the peerHandshake reply's
                    //     `to` field. We approximate with the NAT-sampler host
                    //     (our public IP as seen by other nodes). Close enough:
                    //     both represent "our public-facing IP".
                    //   - JS filters by `isReserved()` (loopback/multicast/etc).
                    //     We pass server addresses through as-is. Worst case
                    //     is a wasted ping to 127.0.0.1 — defensive filtering
                    //     can be a follow-up if it ever bites in production.
                    //     Tracked in docs/JS-PARITY-GAPS.md §6 polish.
                    //   - On ping failure, JS aborts the connect. We fall
                    //     through to the holepunch path instead (more robust
                    //     when the LAN link is flaky but the public path works).
                    {
                        const bool relayed = !hs.remote_payload.addresses4.empty() &&
                            (hs.remote_payload.addresses4[0] != state->relay_addr);

                        if (state->local_connection && relayed &&
                            !state->socket->nat_sampler().host().empty() &&
                            state->socket->nat_sampler().host() ==
                                hs.remote_payload.addresses4[0].host_string()) {

                            // Port=0: only the host octets matter for matching.
                            // local_addresses() walks libuv interface enumeration.
                            auto my_local = holepunch::local_addresses(0);
                            auto matched = holepunch::match_address(
                                my_local, hs.remote_payload.addresses4);

                            // JS fallback (connect.js:239):
                            //   const addr = matchAddress(...) || serverAddresses[0]
                            // Use the first server address when no octet match.
                            auto lan_addr = matched.value_or(
                                hs.remote_payload.addresses4[0]);

                            DHT_LOG("  [connect] LAN shortcut: target %s:%u "
                                    "(matched=%s)\n",
                                    lan_addr.host_string().c_str(), lan_addr.port,
                                    matched.has_value() ? "yes" : "fallback");

                            // state->dht is set unconditionally in do_connect
                            // setup, so the assert documents the invariant.
                            assert(state->dht && "ConnState::dht must be set");
                            state->dht->ping(lan_addr,
                                [state, lan_addr](bool ok) {
                                    if (state->completed) return;
                                    if (!ok) {
                                        DHT_LOG("  [connect] LAN ping failed, "
                                                "falling back to holepunch\n");
                                        return;  // holepunch path runs in parallel
                                    }
                                    DHT_LOG("  [connect] LAN ping OK — "
                                            "short-circuiting connect\n");
                                    ConnectResult result;
                                    result.success = true;
                                    result.tx_key = state->hs_result.tx_key;
                                    result.rx_key = state->hs_result.rx_key;
                                    result.handshake_hash =
                                        state->hs_result.handshake_hash;
                                    result.remote_public_key =
                                        state->hs_result.remote_public_key;
                                    result.peer_address = lan_addr;
                                    result.local_udx_id = state->our_udx_id;
                                    if (state->hs_result.remote_payload.udx
                                            .has_value()) {
                                        result.remote_udx_id =
                                            state->hs_result.remote_payload.udx->id;
                                    }
                                    state->take_raw_stream(result);
                                    state->complete(0, result);
                                });
                            // Note: we do NOT return here. The holepunch below
                            // runs in parallel so a slow LAN ping doesn't block
                            // the connect — whichever path completes first wins
                            // via `state->completed`.
                        }
                    }
                    // --- end §6 LAN shortcut ------------------------------

                    holepunch::holepunch_connect(*state->socket, hs,
                        hp_relay, hp_peer, hp_info.id, fw, addrs,
                        [state](const holepunch::HolepunchResult& hp) {
                            if (state->completed) return;  // rawStream firewall already connected
                            if (state->alive.expired() || !hp.success) {
                                state->complete(-5);
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
                            result.local_udx_id = state->our_udx_id;
                            if (state->hs_result.remote_payload.udx.has_value()) {
                                result.remote_udx_id = state->hs_result.remote_payload.udx->id;
                            }
                            state->take_raw_stream(result);
                            state->complete(0, result);
                        },
                        state->fast_open);  // §6 opts.fast_open
                });
            };
            // Fire first attempt
            (*state->try_relay_fn)();
            // Fire second attempt in parallel (JS: Semaphore(2))
            if (state->relay_idx >= 0 && !state->completed) {
                (*state->try_relay_fn)();
            }
        });
}

// ---------------------------------------------------------------------------
// create_server
// ---------------------------------------------------------------------------

server::Server* HyperDHT::create_server() {
    ensure_bound();
    auto srv = std::make_unique<server::Server>(*socket_, router_);
    auto* ptr = srv.get();
    servers_.push_back(std::move(srv));
    return ptr;
}

// ---------------------------------------------------------------------------
// DHT operations (thin wrappers)
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> HyperDHT::find_peer(
    const noise::PubKey& public_key,
    query::OnReplyCallback on_reply,
    query::OnDoneCallback on_done) {
    ensure_bound();
    return dht_ops::find_peer(*socket_, public_key,
                               std::move(on_reply), std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::lookup(
    const routing::NodeId& target,
    query::OnReplyCallback on_reply,
    query::OnDoneCallback on_done) {
    ensure_bound();
    return dht_ops::lookup(*socket_, target,
                            std::move(on_reply), std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::announce(
    const routing::NodeId& target,
    const std::vector<uint8_t>& value,
    query::OnDoneCallback on_done) {
    ensure_bound();
    return dht_ops::announce(*socket_, target, value, std::move(on_done));
}

// ---------------------------------------------------------------------------
// lookupAndUnannounce
//
// JS: .analysis/js/hyperdht/index.js:197-238 (lookupAndUnannounce — does
//     a LOOKUP query with a commit fn that signs and sends UNANNOUNCE to
//     each replying node)
//
// C++ diffs from JS:
//   - Not yet fully ported: C++ currently delegates to plain `dht_ops::lookup`
//     and the unannounce commit happens in `dht_ops` (TODO). A proper port
//     would sign an UNANNOUNCE payload per-reply via a commit callback.
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> HyperDHT::lookup_and_unannounce(
    const noise::PubKey& public_key,
    const noise::Keypair& keypair,
    query::OnReplyCallback on_reply,
    query::OnDoneCallback on_done) {
    ensure_bound();
    // JS: lookupAndUnannounce does a lookup query and sends UNANNOUNCE
    // to nodes that have our old announcement. For now, delegate to
    // a standard lookup — the unannounce commit happens in dht_ops.
    return dht_ops::lookup(*socket_,
        [&]() {
            routing::NodeId target{};
            crypto_generichash(target.data(), 32,
                               public_key.data(), 32, nullptr, 0);
            return target;
        }(),
        std::move(on_reply), std::move(on_done));
}

// ---------------------------------------------------------------------------
// ping — PING an arbitrary address and fire a bool callback.
//
// JS: .analysis/js/dht-rpc/index.js:260-299 (dht.ping — wraps io.createRequest
//     with PING cmd and returns a Promise)
// ---------------------------------------------------------------------------

void HyperDHT::ping(const compact::Ipv4Address& addr,
                     std::function<void(bool ok)> on_done) {
    ensure_bound();
    messages::Request req;
    req.command = messages::CMD_PING;
    req.internal = true;
    req.to.addr = addr;

    socket_->request(req,
        [on_done](const messages::Response&) {
            if (on_done) on_done(true);
        },
        [on_done](uint16_t) {
            if (on_done) on_done(false);
        });
}

// ---------------------------------------------------------------------------
// Mutable / Immutable storage — thin wrappers around dht_ops that surface
// JS-shaped result structs through the public HyperDHT class.
//
// JS: .analysis/js/hyperdht/index.js:266-279 (immutableGet)
//     .analysis/js/hyperdht/index.js:281-300 (immutablePut)
//     .analysis/js/hyperdht/index.js:302-353 (mutableGet)
//     .analysis/js/hyperdht/index.js:355-390 (mutablePut)
//
// These match the JS reference in `hyperdht/index.js` (immutablePut,
// immutableGet, mutablePut, mutableGet). The underlying dht_ops functions
// handle signing, target computation, query+commit. We add a small shim
// on top that (a) produces the JS-style result struct with `closest_nodes`,
// (b) forwards streaming per-result callbacks for get operations, and
// (c) tracks best-seen results for mutable_get so the caller gets the latest.
//
// C++ diffs from JS:
//   - JS `mutableGet` consumes the query as an async iterator and tracks
//     the best-seen result inline (index.js:319-328). C++ uses an
//     `on_value` reply callback that mutates a shared_ptr<MutableGetResult>.
//   - JS `immutableGet` returns the first reply whose hash matches the
//     target (index.js:272-275). C++ does the same check inside dht_ops
//     and just aggregates here.
//   - JS computes the signature inside the query commit; C++ pre-signs
//     in `dht_ops::mutable_put` so the result struct can be returned
//     immediately on completion.
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> HyperDHT::immutable_put(
    const std::vector<uint8_t>& value,
    ImmutablePutCallback on_done) {
    // JS: empty values are rejected server-side. Reject at the class layer
    // so callers get an immediate nullptr instead of a silent failed query.
    if (value.empty()) {
        DHT_LOG("  [dht] immutable_put: rejected (empty value)\n");
        return nullptr;
    }
    ensure_bound();

    // Target is BLAKE2b(value) — compute here so we can hand it to the caller.
    // `dht_ops::immutable_put` also computes the hash internally; this minor
    // double-work is acceptable to keep the wrapper layer self-contained.
    ImmutablePutResult result;
    crypto_generichash(result.hash.data(), 32,
                       value.data(), value.size(), nullptr, 0);

    DHT_LOG("  [dht] immutable_put: value=%zu bytes, "
            "hash=%02x%02x%02x%02x...\n",
            value.size(),
            result.hash[0], result.hash[1], result.hash[2], result.hash[3]);

    return dht_ops::immutable_put(*socket_, value,
        [on_done = std::move(on_done), result = std::move(result)](
                const std::vector<query::QueryReply>& closest) mutable {
            DHT_LOG("  [dht] immutable_put done: %zu closest nodes\n",
                    closest.size());
            result.closest_nodes = closest;
            if (on_done) on_done(result);
        });
}

std::shared_ptr<query::Query> HyperDHT::immutable_get(
    const std::array<uint8_t, 32>& target,
    ImmutableGetCallback on_done) {
    return immutable_get(target, /*on_value=*/nullptr, std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::immutable_get(
    const std::array<uint8_t, 32>& target,
    ImmutableValueCallback on_value,
    ImmutableGetCallback on_done) {
    ensure_bound();

    DHT_LOG("  [dht] immutable_get: target=%02x%02x%02x%02x...\n",
            target[0], target[1], target[2], target[3]);

    // Accumulate the first verified reply. `dht_ops::immutable_get` already
    // verifies BLAKE2b(value) === target, so any callback invocation is good.
    // Share state between on_result and on_done via a shared_ptr so they
    // can both safely mutate it across the async query lifetime.
    auto result = std::make_shared<ImmutableGetResult>();

    return dht_ops::immutable_get(*socket_, target,
        [result, on_value = std::move(on_value)](
                const std::vector<uint8_t>& value) {
            // Forward streaming callback (if any) on every verified reply.
            if (on_value) on_value(value);
            // Aggregate the first match for the on_done summary.
            if (!result->found) {
                DHT_LOG("  [dht] immutable_get: first verified value "
                        "(%zu bytes)\n", value.size());
                result->found = true;
                result->value = value;
            }
        },
        [on_done = std::move(on_done), result](
                const std::vector<query::QueryReply>&) {
            DHT_LOG("  [dht] immutable_get done: found=%d\n",
                    result->found ? 1 : 0);
            if (on_done) on_done(*result);
        });
}

std::shared_ptr<query::Query> HyperDHT::mutable_put(
    const noise::Keypair& keypair,
    const std::vector<uint8_t>& value,
    uint64_t seq,
    MutablePutCallback on_done) {
    if (value.empty()) {
        DHT_LOG("  [dht] mutable_put: rejected (empty value)\n");
        return nullptr;
    }
    ensure_bound();

    // Pre-compute the result we'll hand back. Signature is deterministic
    // from (seq, value, secret_key), so we can produce it locally without
    // waiting for the commit phase.
    MutablePutResult result;
    result.public_key = keypair.public_key;
    result.seq = seq;
    result.signature = announce_sig::sign_mutable(
        seq, value.data(), value.size(), keypair);

    DHT_LOG("  [dht] mutable_put: pk=%02x%02x%02x%02x... seq=%llu "
            "value=%zu bytes\n",
            keypair.public_key[0], keypair.public_key[1],
            keypair.public_key[2], keypair.public_key[3],
            static_cast<unsigned long long>(seq), value.size());

    return dht_ops::mutable_put(*socket_, keypair, value, seq,
        [on_done = std::move(on_done), result = std::move(result)](
                const std::vector<query::QueryReply>& closest) mutable {
            DHT_LOG("  [dht] mutable_put done: %zu closest nodes\n",
                    closest.size());
            result.closest_nodes = closest;
            if (on_done) on_done(result);
        });
}

std::shared_ptr<query::Query> HyperDHT::mutable_get(
    const noise::PubKey& public_key,
    uint64_t min_seq,
    bool latest,
    MutableGetCallback on_done) {
    return mutable_get(public_key, min_seq, latest,
                       /*on_value=*/nullptr, std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::mutable_get(
    const noise::PubKey& public_key,
    uint64_t min_seq,
    bool latest,
    MutableValueCallback on_value,
    MutableGetCallback on_done) {
    ensure_bound();

    DHT_LOG("  [dht] mutable_get: pk=%02x%02x%02x%02x... "
            "min_seq=%llu latest=%d\n",
            public_key[0], public_key[1], public_key[2], public_key[3],
            static_cast<unsigned long long>(min_seq), latest ? 1 : 0);

    // Track the best-seen result across all replies. `dht_ops::mutable_get`
    // already verifies signatures and filters by `min_seq`, so any result
    // arriving here is valid.
    //
    // JS semantics (hyperdht/index.js:319-328):
    //   - With `latest=true` (default): return the highest-seq valid reply.
    //   - With `latest=false`: return the FIRST valid reply. Early query
    //     termination is a §9 follow-up; until then the walk continues but
    //     the result is frozen after the first match.
    auto result = std::make_shared<MutableGetResult>();

    return dht_ops::mutable_get(*socket_, public_key, min_seq,
        [result, latest, on_value = std::move(on_value)](
                const dht_ops::MutableResult& r) {
            // Streaming callback first (if any) — receives every verified reply.
            if (on_value) on_value(r);

            if (!result->found) {
                DHT_LOG("  [dht] mutable_get: first verified reply "
                        "seq=%llu (%zu bytes)\n",
                        static_cast<unsigned long long>(r.seq),
                        r.value.size());
                result->found = true;
                result->seq = r.seq;
                result->value = r.value;
                result->signature = r.signature;
                return;
            }
            // Already have one. If `latest==false`, keep the first.
            if (!latest) return;
            // Otherwise prefer the highest seq seen so far.
            if (r.seq > result->seq) {
                DHT_LOG("  [dht] mutable_get: newer seq=%llu replaces %llu\n",
                        static_cast<unsigned long long>(r.seq),
                        static_cast<unsigned long long>(result->seq));
                result->seq = r.seq;
                result->value = r.value;
                result->signature = r.signature;
            }
        },
        [on_done = std::move(on_done), result](
                const std::vector<query::QueryReply>&) {
            DHT_LOG("  [dht] mutable_get done: found=%d seq=%llu\n",
                    result->found ? 1 : 0,
                    static_cast<unsigned long long>(result->seq));
            if (on_done) on_done(*result);
        });
}

// ---------------------------------------------------------------------------
// pool
// ---------------------------------------------------------------------------

connection_pool::ConnectionPool HyperDHT::pool() {
    return connection_pool::ConnectionPool{};
}

// ---------------------------------------------------------------------------
// suspend / resume — pause/restart RPC ticks and any servers.
//
// JS: .analysis/js/hyperdht/index.js:97 (resume re-seeds _lastRandomPunch)
//     dht-rpc's `dht.suspend()` / `dht.resume()` (suspends socket + tick)
//
// C++ diffs from JS:
//   - JS suspend rejects new connect() calls via `_connectable` flag at
//     the connect entry. We mirror that with the `suspended_` check in
//     each connect overload (connect.js:49-51).
// ---------------------------------------------------------------------------

void HyperDHT::suspend() {
    if (suspended_) return;
    suspended_ = true;

    // Suspend all servers
    for (auto& srv : servers_) {
        srv->suspend();
    }

    // Stop RPC ticks (JS: dht.suspend() stops tick timer)
    if (socket_) {
        socket_->stop_tick();
    }
}

void HyperDHT::resume() {
    if (!suspended_) return;
    suspended_ = false;

    // JS: hyperdht/index.js:97 — when `deferRandomPunch` is set, resume
    // re-seeds `_lastRandomPunch = Date.now()` so the interval restarts
    // from resume rather than carrying over the pre-suspend counter.
    if (opts_.defer_random_punch) {
        punch_stats_.last_random_punch = uv_now(loop_);
    }

    // Resume all servers
    for (auto& srv : servers_) {
        srv->resume();
    }

    // Restart RPC ticks
    if (socket_) {
        socket_->start_tick();
    }
}

// ---------------------------------------------------------------------------
// destroy
// ---------------------------------------------------------------------------

void HyperDHT::destroy(std::function<void()> on_done) {
    if (destroyed_) {
        if (on_done) on_done();
        return;
    }
    destroyed_ = true;
    *alive_ = false;

    // Close all servers (don't clear vector yet — let ~HyperDHT handle deallocation
    // after the event loop processes the close callbacks)
    for (auto& srv : servers_) {
        srv->close();
    }

    // Clear router
    router_.clear();

    // Close socket
    if (socket_) {
        socket_->close();
    }

    if (on_done) on_done();
}

}  // namespace hyperdht
