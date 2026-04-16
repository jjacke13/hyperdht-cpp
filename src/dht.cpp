// HyperDHT main class implementation — owns the RPC socket, routing
// table, announce store, query engine and connection pool. Provides
// connect(), listen(), suspend()/resume() and the tick/bootstrap loop.
//
// =========================================================================
// JS FLOW MAP — how this file maps to the JavaScript reference
// =========================================================================
//
// C++ function                       Line  JS file                   JS lines
// ─────────────────────────────────── ────  ────────────────────────  ────────
// client_raw_stream_firewall           62  connect.js               121-135
//
// HyperDHT::bind                     185  dht-rpc/index.js         157-159
// HyperDHT::start_bootstrap_walk     296  dht-rpc/index.js         379-433
// HyperDHT::refresh                  369  dht-rpc/index.js         435-438
// HyperDHT::fire_network_change      425  dht-rpc/index.js         596-599
// HyperDHT::create_raw_stream        561  hyperdht/index.js        460-462
// HyperDHT::validate_local_addresses 602  hyperdht/index.js        135-184
// HyperDHT::connect (entry)          672  hyperdht/index.js         80-82
//
// ConnState struct (file scope)     785  connect.js                57-93
// do_connect                         885  connect.js                32-115
// ├─ rawStream + firewall            923  connect.js                73, 121-135
// ├─ Step 1: findPeer                986  connect.js               341-348
// └─ Step 2: try_relay_fn           1004  connect.js               336-338, 355-368
//    └─ peer_handshake              1059  connect.js               409-449
//       └─ on_handshake_success()   (extracted, see below)
//
// on_handshake_success              1576  connect.js               405-503
// ├─ Cached firewall replay         1594  connect.js               493-496
// ├─ BLIND RELAY start              1621  connect.js               489-491, 746-795
// ├─ Direct connect (OPEN)          1651  connect.js               212-221
// ├─ No-holepunch-info fallback     1670  connect.js               212-221
// ├─ Passive wait (our fw OPEN)     1712  connect.js               228-231
// ├─ LAN shortcut (§6)             1730  connect.js               234-251
// └─ holepunch_connect              1775  connect.js               258-316
//
// start_relay_path                  1799  connect.js               746-795
// ├─ dht.connect(relay_pk)          1826  connect.js                762
// ├─ SecretStream + Protomux setup  1851  connect.js               764
// ├─ BlindRelayClient.pair          1884  connect.js               767
// └─ Wire rawStream through relay   1910  connect.js               778-784
//
// HyperDHT::suspend                 1529  hyperdht/index.js        106-120
// HyperDHT::resume                  1544  hyperdht/index.js         96-104
// HyperDHT::destroy                 1570  hyperdht/index.js        122-133
// =========================================================================

#include "hyperdht/dht.hpp"

#include <sodium.h>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <stdexcept>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/blind_relay.hpp"
#include "hyperdht/debug.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/peer_connect.hpp"

// Context stored in client rawStream->data during handshake→connection window.
// Matches JS: rawStream created at connect() time with firewall callback.
struct ClientRawStreamCtx {
    std::weak_ptr<bool> alive;
    std::function<void(udx_stream_t*, udx_socket_t*, const struct sockaddr*)> on_firewall;
};

// Firewall callback for client-side rawStream. Fires when the server's
// first UDX packet arrives with the REAL peer address.
// Matches JS: rawStream firewall → c.onsocket(socket, port, host)
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
// ConnectOptions helpers
// ---------------------------------------------------------------------------

// JS connect.js:842-848 — `selectRelay(relayThrough)`.
// Order of precedence matches JS (function first, then array, then literal).
std::optional<noise::PubKey> ConnectOptions::select_relay_through(
    uint64_t (*rand_u64)()) const {

    if (relay_through_fn) return relay_through_fn();

    if (!relay_through_array.empty()) {
        uint64_t r;
        if (rand_u64) {
            r = rand_u64();
        } else {
            randombytes_buf(&r, sizeof(r));
        }
        size_t idx = static_cast<size_t>(r % relay_through_array.size());
        return relay_through_array[idx];
    }

    return relay_through;
}

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

    // filterNode: install the JS hardcoded testnet blocklist
    // (hyperdht/index.js:585-592) plus any caller-provided filter. Both
    // must pass (AND semantics) — matches JS where the built-in filter
    // replaces opts.filterNode unless the caller opted in explicitly via
    // dht-rpc's lower-level surface. Bundling them here ensures every
    // HyperDHT instance ignores the known-bad testnet nodes without a
    // caller having to know they exist.
    //
    // Matching uses the packed 4-byte host + uint16 port directly — no
    // `host_string()` allocations — because this lambda is on the hot
    // path: every closer-nodes entry from every DHT query response, and
    // every incoming RPC that the routing table would accept.
    auto user_filter = opts_.filter_node;
    socket_->set_filter_node(
        [user_filter](const routing::NodeId& id,
                      const compact::Ipv4Address& addr) {
            // Built-in JS testnet blocklist (hyperdht/index.js:585-592).
            //   134.209.28.98:49738, 167.99.142.185:49738  (accidentally
            //   left as testnet seeds), 35.233.47.252:9400 (out-of-spec
            //   port), 150.136.142.116 (any port — misconfigured peer).
            struct Entry {
                std::array<uint8_t, 4> host;
                uint16_t port;             // 0 = "any port"
            };
            static constexpr std::array<Entry, 4> kTestnetBlocklist = {{
                {{134, 209,  28,  98}, 49738},
                {{167,  99, 142, 185}, 49738},
                {{ 35, 233,  47, 252},  9400},
                {{150, 136, 142, 116},     0},
            }};
            for (const auto& e : kTestnetBlocklist) {
                if (addr.host != e.host) continue;
                if (e.port != 0 && addr.port != e.port) continue;
                return false;
            }
            // Then the caller-supplied filter, if any.
            if (user_filter) return user_filter(id, addr);
            return true;
        });

    // §7: thread storage cache tuning into the handlers.
    // max_size governs entry count (JS: opts.maxSize); ttl_ms is the
    // storage-specific 48h default (JS: hyperdht/index.js:611,615 —
    // `opts.maxAge || 48h` for mutable/immutable); ann_ttl_ms is the
    // per-announcement TTL that JS sources from `opts.maxAge` for the
    // `persistent.records` cache (hyperdht/index.js:607, defaultMaxAge
    // = 20 min). Our `max_age_ms` option is the same knob, so plumb it
    // through here to close the §7 polish gap.
    rpc::StorageCacheConfig cache_config;
    cache_config.max_size = opts_.max_size;
    cache_config.ttl_ms = opts_.storage_ttl_ms;
    cache_config.ann_ttl_ms = opts_.max_age_ms;
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
//     .analysis/js/dht-rpc/index.js:82-84 (DHT ctor kicks off `_bootstrap`
//         immediately — C++ defers the walk to bind() since bind is
//         explicit in the C++ API rather than implicit in the ctor).
//     .analysis/js/dht-rpc/index.js:379-433 (`_bootstrap` — runs
//         `_backgroundQuery(table.id)` then flips `bootstrapped = true`).
//     .analysis/js/dht-rpc/index.js:965-979 (`_backgroundQuery`).
//
// C++ diffs from JS:
//   - JS DHT auto-bootstraps at construction against the built-in public
//     BOOTSTRAP_NODES unless the caller passes `opts.bootstrap === false`.
//     C++ instead keeps the bootstrap list empty by default (preserving
//     the contract that existing offline tests rely on) and only runs the
//     walk when `opts.bootstrap` is non-empty. Callers who want JS's
//     default behaviour pass `opts.bootstrap =
//     HyperDHT::default_bootstrap_nodes()` explicitly.
//   - JS runs up to two bootstrap passes to drive NAT detection in the
//     same flow. C++ runs exactly one; NAT detection is the separate §15
//     follow-up.
// ---------------------------------------------------------------------------

int HyperDHT::bind() {
    if (bound_) return 0;
    // §7: pass opts.host so multi-homed or specific-interface binds work.
    int rc = socket_->bind(opts_.port, opts_.host);
    if (rc != 0) return rc;
    bound_ = true;

    // §2: wire the refresh timer callback. RpcSocket decrements
    // REFRESH_TICKS on its background tick and fires this callback when
    // the counter reaches zero. Installing unconditionally mirrors JS:
    // `refresh()` is a no-op when the table is empty (the walk finds no
    // seeds and completes immediately).
    socket_->on_refresh([this]() { this->refresh(); });

    // §15: wire the health-state and persistent transitions. The
    // RpcSocket background tick fires `on_health_change_` on every
    // ONLINE/DEGRADED/OFFLINE transition; we forward it to the
    // network-update fan-out. `on_persistent_` fires once when the NAT
    // classifier flips `ephemeral_` to false — same path as JS
    // `dht-rpc/index.js:870-872`.
    socket_->on_health_change([this]() { fire_network_update(); });
    socket_->on_persistent([this]() { fire_persistent(); });

    // §15: start polling for network interface changes. libudx's
    // `udx_interface_event` wraps `uv_interface_addresses()` behind a
    // periodic timer + diff, matching JS `udx.watchNetworkInterfaces()`.
    start_interface_watcher();

    // §16: validate the machine's local interface addresses once at
    // bind time so the server-side handshake path (`share_local_address`)
    // has a cached list ready. JS runs this from `server._localAddresses`
    // on every handshake with its own per-host cache; we do the work
    // once up front and serve every subsequent handshake from the cache.
    //
    // Use the ACTUAL bound port (`socket_->port()`) — `opts_.port` may
    // be 0 for ephemeral binds, which would give peers a dead address.
    auto raw_locals = holepunch::local_addresses(socket_->port());
    validated_local_addresses_ = validate_local_addresses(raw_locals);
    DHT_LOG("  [dht] §16: %zu validated local interface(s) "
            "(from %zu enumerated)\n",
            validated_local_addresses_.size(), raw_locals.size());

    // §2: kick off the initial bootstrap walk if we have seeds. The walk
    // runs in the background; callers that need a barrier can install an
    // `on_bootstrapped()` callback.
    if (!opts_.bootstrap.empty()) {
        start_bootstrap_walk();
    }

    return 0;
}

void HyperDHT::ensure_bound() {
    if (!bound_) bind();
}

// ---------------------------------------------------------------------------
// §2: default bootstrap nodes — the 3 canonical public HyperDHT peers.
//
// JS: .analysis/js/hyperdht/lib/constants.js:16-20 (`BOOTSTRAP_NODES`).
// The `@`-prefixed IP hint is a pinning shortcut for `_resolveBootstrapNodes`
// (dht-rpc/index.js:877-898); C++ stores pre-resolved addresses so the
// fallback-host fields are flattened into the IP half of each entry.
// ---------------------------------------------------------------------------

const std::vector<compact::Ipv4Address>& HyperDHT::default_bootstrap_nodes() {
    static const std::vector<compact::Ipv4Address> nodes = {
        compact::Ipv4Address::from_string("88.99.3.86", 49737),
        compact::Ipv4Address::from_string("142.93.90.113", 49737),
        compact::Ipv4Address::from_string("138.68.147.8", 49737),
    };
    return nodes;
}

// ---------------------------------------------------------------------------
// B6: HyperDHT::hash — BLAKE2b-256 of arbitrary data
// JS: HyperDHT.hash(data) — hyperdht/index.js:448-450
// ---------------------------------------------------------------------------

std::array<uint8_t, 32> HyperDHT::hash(const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> out{};
    crypto_generichash(out.data(), 32, data, len, nullptr, 0);
    return out;
}

// JS: DHT.bootstrapper — dht-rpc/index.js:104-120.
std::unique_ptr<HyperDHT> HyperDHT::bootstrapper(
    uv_loop_t* loop,
    uint16_t port,
    const std::string& host,
    DhtOptions opts) {

    if (port == 0) throw std::invalid_argument("Port is required");
    if (host.empty()) throw std::invalid_argument("Host is required");
    if (host == "0.0.0.0" || host == "::") throw std::invalid_argument("Invalid host");
    // IPv4 sanity: uv_ip4_addr parses the dotted-quad form. Anything it
    // rejects (IPv6, hostname, garbage) trips the check.
    struct sockaddr_in probe{};
    if (uv_ip4_addr(host.c_str(), port, &probe) != 0) {
        throw std::invalid_argument("Host must be an IPv4 address");
    }

    opts.port = port;
    opts.host = host;
    opts.ephemeral = false;
    opts.bootstrap.clear();  // A bootstrap node has no upstream bootstrap.

    auto dht = std::make_unique<HyperDHT>(loop, std::move(opts));

    // JS: `firewalled: false` — advertise as OPEN. Our `firewalled_`
    // field defaults to true; force it false so the bootstrap node
    // doesn't claim to be behind a NAT.
    if (dht->socket_) dht->socket_->set_firewalled(false);

    // JS: `dht._nat.add(host, port)` — seed the NAT sampler with our
    // own public address so `remoteAddress()` returns something
    // sensible immediately (the sampler would otherwise stay UNKNOWN
    // until real peers start contacting us).
    auto self_addr = compact::Ipv4Address::from_string(host, port);
    if (dht->socket_) {
        dht->socket_->nat_sampler().add(self_addr, self_addr);
    }

    return dht;
}

// JS: HyperDHT.connectRawStream — hyperdht/index.js:452-458.
int HyperDHT::connect_raw_stream(const ConnectResult& base,
                                 udx_stream_t* raw,
                                 uint32_t remote_udx_id) {
    if (!base.success || !raw || !base.udx_socket) return -1;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (uv_ip4_addr(base.peer_address.host_string().c_str(),
                    base.peer_address.port, &addr) != 0) {
        return -2;
    }
    return udx_stream_connect(
        raw,
        static_cast<udx_socket_t*>(base.udx_socket),
        remote_udx_id,
        reinterpret_cast<const struct sockaddr*>(&addr));
}

// ---------------------------------------------------------------------------
// §2: on_bootstrapped — register the "bootstrap walk finished" callback.
//
// JS: .analysis/js/dht-rpc/index.js:404 (`this.emit('ready')`). In JS this
// fires at most once, after `_bootstrap()` flips `bootstrapped = true`.
// C++ preserves the same once-only semantic and additionally fires the
// callback synchronously if the walk has already completed by the time
// the caller installs the hook.
// ---------------------------------------------------------------------------

void HyperDHT::on_bootstrapped(BootstrappedCallback cb) {
    on_bootstrapped_ = std::move(cb);
    if (on_bootstrapped_ && socket_ && socket_->is_bootstrapped()) {
        // Walk already finished — fire immediately so callers don't
        // miss the event due to late registration.
        auto once = std::move(on_bootstrapped_);
        once();
    }
}

// ---------------------------------------------------------------------------
// §2: start_bootstrap_walk — one-shot FIND_NODE(our_id) seeded from
// `opts_.bootstrap`. On success the RpcSocket is flagged bootstrapped.
//
// JS: .analysis/js/dht-rpc/index.js:379-433 (`_bootstrap`).
//     .analysis/js/dht-rpc/index.js:965-979 (`_backgroundQuery`).
//
// C++ diffs from JS:
//   - JS uses the async-iterator `_resolveBootstrapNodes()` to DNS-resolve
//     hostnames and fall back between pinned IP / DNS lookup. C++ expects
//     pre-resolved IPs in `opts_.bootstrap`; no async resolve step.
//   - JS's `_bootstrap` also drives the quick NAT heuristic (PING_NAT on
//     the first responder) and loops up to twice if NAT sampling is
//     pending. C++ currently runs a single pass — NAT detection is a §15
//     follow-up.
// ---------------------------------------------------------------------------

void HyperDHT::start_bootstrap_walk() {
    // Target = our own id (JS `_backgroundQuery(this.table.id)`). Walking
    // toward ourselves fills the routing table with the k closest nodes
    // to us, which is what every downstream query depends on.
    auto target = socket_->table().id();

    auto q = query::Query::create(*socket_, target, messages::CMD_FIND_NODE);
    q->set_internal(true);

    // JS `_backgroundQuery:968`: `Math.min(concurrency, Math.max(2,
    // concurrency/8))`. With the default concurrency=10 that collapses to
    // `max(2, 1) = 2`. Keeping background queries narrow prevents the
    // bootstrap traffic from hogging the congestion window.
    const int background_concurrency =
        std::max(2, query::DEFAULT_CONCURRENCY / 8);
    q->set_concurrency(background_concurrency);

    // Seed the walk from the supplied bootstrap list. `add_bootstrap`
    // inserts with a zeroed id so the pop-loop always visits them even
    // though they never land in `closest_replies_`. Matches JS's
    // `_resolveBootstrapNodes → _addPending(node, null)` flow.
    for (const auto& addr : opts_.bootstrap) {
        q->add_bootstrap(addr);
    }

    DHT_LOG("  [dht] bootstrap: walking with %zu seed node(s), concurrency=%d\n",
            opts_.bootstrap.size(), background_concurrency);

    // Capture alive sentinel so the on_done lambda is a no-op if the DHT
    // has been destroyed by the time the walk finishes.
    std::weak_ptr<bool> weak_alive = alive_;
    q->on_done([this, weak_alive](const std::vector<query::QueryReply>& closest) {
        if (weak_alive.expired()) return;
        // JS `_bootstrap:402` — flip the flag, then emit `ready`.
        socket_->set_bootstrapped(true);
        DHT_LOG("  [dht] bootstrap: walk complete, %zu closest replies, "
                "routing table size=%zu\n",
                closest.size(), socket_->table().size());

        // Drop our strong ref BEFORE firing the user callback. This way,
        // if the user's `on_bootstrapped` callback re-enters HyperDHT
        // (e.g. calls `destroy()` or starts a new query), it never sees
        // a non-null `bootstrap_query_` after the walk has conceptually
        // finished. The Query itself is pinned for the duration of this
        // callback by Query's internal `shared_from_this()` self-capture,
        // so dropping our reference here is safe.
        bootstrap_query_.reset();

        if (on_bootstrapped_) {
            auto once = std::move(on_bootstrapped_);
            once();
        }
    });

    bootstrap_query_ = q;
    q->start();
}

// ---------------------------------------------------------------------------
// §2: refresh — periodic background FIND_NODE walk against a random
// routing-table entry, falling back to our own id if the table is empty.
//
// JS: .analysis/js/dht-rpc/index.js:435-438 (`refresh`).
//
// C++ diffs from JS:
//   - JS attaches a noop error handler to the stream (`.on('error', noop)`).
//     C++ Query has no error channel at this layer — failures are silent
//     by design.
//   - JS does NOT gate on bootstrapped; neither do we. An unbootstrapped
//     refresh will find zero seeds and complete immediately, which is
//     harmless.
// ---------------------------------------------------------------------------

void HyperDHT::refresh() {
    if (destroyed_ || !bound_) return;

    // JS: `const node = this.table.random();
    //       ...backgroundQuery(node ? node.id : this.table.id)`.
    routing::NodeId target;
    if (auto* rnd = socket_->table().random()) {
        target = rnd->id;
    } else {
        target = socket_->table().id();
    }

    auto q = query::Query::create(*socket_, target, messages::CMD_FIND_NODE);
    q->set_internal(true);
    const int background_concurrency =
        std::max(2, query::DEFAULT_CONCURRENCY / 8);
    q->set_concurrency(background_concurrency);

    DHT_LOG("  [dht] refresh: background query, table size=%zu\n",
            socket_->table().size());

    std::weak_ptr<bool> weak_alive = alive_;
    // Capture the query so we can locate-and-erase it from refresh_queries_
    // when it finishes. Using a raw Query* here is safe because the shared
    // ptr is owned by refresh_queries_ for the duration.
    query::Query* q_raw = q.get();
    q->on_done([this, weak_alive, q_raw](const std::vector<query::QueryReply>&) {
        // Belt-and-suspenders: both the alive sentinel and the explicit
        // destroyed_ flag must allow the erase. If the DHT has been
        // destroyed mid-refresh, `refresh_queries_` has already been
        // cleared by `destroy()` and touching it is a no-op, but we
        // skip it entirely to keep the lambda body defensively inert.
        if (weak_alive.expired() || destroyed_) return;
        // Prune the completed query from the retention list so long-lived
        // DHTs don't grow an unbounded refresh history.
        auto& rq = refresh_queries_;
        rq.erase(std::remove_if(rq.begin(), rq.end(),
                                [q_raw](const std::shared_ptr<query::Query>& p) {
                                    return p.get() == q_raw;
                                }),
                 rq.end());
    });

    refresh_queries_.push_back(q);
    q->start();
}

// ---------------------------------------------------------------------------
// §15: network-change / network-update / persistent event fan-out.
//
// JS: .analysis/js/dht-rpc/index.js:596-599 (`_onnetworkchange` emits
//     both `network-change` and `network-update`).
//     .analysis/js/hyperdht/index.js:64-75 (HyperDHT subscribes to all
//     three events to auto-refresh servers + spin up persistent store).
// ---------------------------------------------------------------------------

void HyperDHT::fire_network_change() {
    if (destroyed_) return;
    DHT_LOG("  [dht] network-change: refreshing %zu listening server(s)\n",
            servers_.size());

    // JS hyperdht/index.js:68-70 — refresh every listening server so it
    // re-announces on the new network topology.
    for (auto& srv : servers_) {
        if (srv) srv->refresh();
    }

    // Fire the user's hook.
    if (on_network_change_) {
        on_network_change_();
    }

    // JS always emits `network-update` immediately after `network-change`
    // (dht-rpc/index.js:596-599 emits both in the same call frame).
    fire_network_update();
}

void HyperDHT::fire_network_update() {
    if (destroyed_) return;

    // JS hyperdht/index.js:72-75 — only poke servers while we're online.
    if (is_online()) {
        for (auto& srv : servers_) {
            if (srv) srv->notify_online();
        }
    }

    if (on_network_update_) {
        on_network_update_();
    }
}

void HyperDHT::fire_persistent() {
    if (destroyed_) return;
    DHT_LOG("  [dht] persistent: node has transitioned ephemeral -> persistent\n");
    if (on_persistent_) {
        on_persistent_();
    }
}

// ---------------------------------------------------------------------------
// §15: libudx interface event watcher lifecycle.
//
// libudx `udx_interface_event_t` (deps/libudx/src/udx.c:2796-2905) wraps
// `uv_interface_addresses()` behind a periodic `uv_timer_t` that diffs
// the current interface list against the previous one and invokes the
// callback when the set changes. Matches JS `udx.watchNetworkInterfaces()`
// in `dht-rpc/lib/io.js:39`.
//
// Frequency: 5 seconds, same cadence as the RpcSocket background tick —
// slow enough to be free, fast enough to react to WiFi / VPN toggles.
// ---------------------------------------------------------------------------

static constexpr uint64_t INTERFACE_POLL_MS = 5000;

void HyperDHT::start_interface_watcher() {
    if (interface_watcher_ != nullptr) return;  // Already running

    interface_watcher_ = new udx_interface_event_t;
    interface_watcher_->data = this;

    int rc = udx_interface_event_init(socket_->udx_handle(),
                                      interface_watcher_,
                                      on_udx_interface_close);
    if (rc != 0) {
        DHT_LOG("  [dht] network-change: udx_interface_event_init failed: %d\n", rc);
        delete interface_watcher_;
        interface_watcher_ = nullptr;
        return;
    }

    rc = udx_interface_event_start(interface_watcher_,
                                   on_udx_interface_event,
                                   INTERFACE_POLL_MS);
    if (rc != 0) {
        DHT_LOG("  [dht] network-change: udx_interface_event_start failed: %d\n", rc);
        // Null the user data BEFORE the async close so the close callback
        // (which runs on a later loop iteration) cannot dispatch against a
        // partially-constructed HyperDHT if destroy() runs before drain.
        interface_watcher_->data = nullptr;
        // Close the handle — its close callback will free our allocation.
        udx_interface_event_close(interface_watcher_);
        interface_watcher_ = nullptr;  // Ownership transferred to the close cb
        return;
    }

    interface_watcher_active_ = true;
    DHT_LOG("  [dht] network-change: watcher started (%lu ms poll)\n",
            static_cast<unsigned long>(INTERFACE_POLL_MS));
}

void HyperDHT::stop_interface_watcher() {
    if (interface_watcher_ == nullptr) return;
    if (interface_watcher_active_) {
        udx_interface_event_stop(interface_watcher_);
        interface_watcher_active_ = false;
    }
    // Null the data pointer so any pending callback is a no-op.
    interface_watcher_->data = nullptr;
    // Do NOT call udx_interface_event_close() here — the udx_t teardown
    // (triggered by socket_->close()) will close all attached interface
    // events automatically (libudx/src/udx.c:1879). Calling close manually
    // AND letting teardown close it causes the close callback to fire after
    // the udx_t is freed → use-after-free in ref_dec(event->udx).
    //
    // Trade-off accepted: the `udx_interface_event_t` heap struct leaks
    // ~232 bytes per HyperDHT instance at process exit, because libudx
    // teardown closes its listener handles but our `on_udx_interface_close`
    // deleter never fires in that path. Fixable only by patching libudx
    // to invoke the user close callback from its teardown loop. Since
    // the leak is bounded per process lifetime (one per HyperDHT)
    // and not per-operation, we accept it.
    interface_watcher_ = nullptr;
}

void HyperDHT::on_udx_interface_event(udx_interface_event_t* handle, int status) {
    if (handle->data == nullptr) return;  // DHT is tearing down.
    if (status != 0) return;  // Error — libudx couldn't enumerate.
    auto* self = static_cast<HyperDHT*>(handle->data);
    self->fire_network_change();
}

void HyperDHT::on_udx_interface_close(udx_interface_event_t* handle) {
    // handle is heap-allocated in start_interface_watcher(). The close
    // callback fires asynchronously after udx_interface_event_close().
    // We must NOT dereference handle->data (the HyperDHT*) here —
    // the HyperDHT may already be destroyed by the time this fires.
    if (handle) delete handle;
}

// ---------------------------------------------------------------------------
// §16: createRawStream — return a UDX stream with a random ID.
//
// JS: .analysis/js/hyperdht/index.js:460-462 delegates to
//     `this.rawStreams.add(opts)` which generates a random u32 id,
//     calls `udx.createStream(id, opts)`, and tracks the stream in a
//     set for cleanup on destroy.
//
// C++ diffs from JS:
//   - No tracking set. The existing connect/holepunch paths manage raw
//     stream lifetime through their own state structs; a global tracking
//     set would duplicate that work without a clear benefit.
//   - The caller owns the returned `udx_stream_t*` and must destroy it
//     (either directly or by handing it to a `SecretStreamDuplex`).
// ---------------------------------------------------------------------------

udx_stream_t* HyperDHT::create_raw_stream() {
    ensure_bound();

    auto* stream = new udx_stream_t{};

    // `randombytes_buf` can produce 0 (probability 1/2^32). A zero
    // local_id is a legal hash key in libudx's cirbuf but some peers
    // treat 0 as a sentinel for "unassigned", and the test assertion
    // `local_id != 0` would flake at that frequency. Retry until
    // non-zero — matches JS RawStreamSet which rolls IDs starting from 1.
    uint32_t id = 0;
    do {
        randombytes_buf(&id, sizeof(id));
    } while (id == 0);

    int rc = udx_stream_init(socket_->udx_handle(), stream, id,
                             [](udx_stream_t*, int) {},
                             [](udx_stream_t* s) { delete s; });
    if (rc != 0) {
        DHT_LOG("  [dht] create_raw_stream: udx_stream_init failed: %d\n", rc);
        delete stream;
        return nullptr;
    }
    return stream;
}

// ---------------------------------------------------------------------------
// §16: validateLocalAddresses — filter to bind-able hosts only.
//
// JS: .analysis/js/hyperdht/index.js:135-184 tries to bind a probe
//     socket on each host AND then sends a 1-byte self-loopback packet
//     with a 500 ms deadline. The loopback probe is documented by JS
//     itself as "semi terrible heuristic" (line 160). C++ implements
//     only the bind half: if `udx_socket_bind(host, 0)` succeeds the
//     address is considered valid.
//
// Per-host result cache lives on the HyperDHT instance so repeated
// calls from different code paths (e.g. server _localAddresses on
// each handshake) are O(1) after the first call per host.
// ---------------------------------------------------------------------------

std::vector<compact::Ipv4Address> HyperDHT::validate_local_addresses(
    const std::vector<compact::Ipv4Address>& addresses) {

    std::vector<compact::Ipv4Address> result;
    result.reserve(addresses.size());

    for (const auto& addr : addresses) {
        const std::string host = addr.host_string();

        // Cache lookup.
        auto it = validated_host_cache_.find(host);
        if (it != validated_host_cache_.end()) {
            if (it->second) result.push_back(addr);
            continue;
        }

        // Fresh probe: try a temporary UDP bind on this host.
        //
        // The probe socket must be HEAP-allocated: `udx_socket_close()`
        // schedules an async `uv_close()` on the underlying `uv_udp_t`,
        // and the close callback runs on a later event-loop turn.
        // Stack-allocating would free the struct before the close
        // callback fires, causing a UAF inside `on_uv_close` (libudx
        // src/udx.c:137-147 dereferences `socket->udx` + `socket->on_close`).
        // We pass a self-delete close callback to libudx so ownership
        // transfers cleanly at close time.
        auto* probe = new udx_socket_t{};
        bool ok = (udx_socket_init(socket_->udx_handle(), probe,
                                   [](udx_socket_t* s) { delete s; }) == 0);
        if (ok) {
            struct sockaddr_in sin{};
            if (uv_ip4_addr(host.c_str(), 0, &sin) != 0) {
                ok = false;
            } else if (udx_socket_bind(probe,
                                       reinterpret_cast<struct sockaddr*>(&sin),
                                       0) != 0) {
                ok = false;
            }
            // Clean up: close transfers ownership to the async callback.
            udx_socket_close(probe);
        } else {
            // `udx_socket_init` failed — the handle was never registered
            // with libuv, so we must delete it ourselves.
            delete probe;
        }

        validated_host_cache_[host] = ok;
        DHT_LOG("  [dht] validate_local_addresses: %s -> %s\n",
                host.c_str(), ok ? "ok" : "rejected");
        if (ok) result.push_back(addr);
    }

    return result;
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
// Connect pipeline — findPeer → handshake → (relay | direct | LAN | holepunch)
//
// JS: .analysis/js/hyperdht/lib/connect.js:176-194 (connectAndHolepunch)
//     .analysis/js/hyperdht/lib/connect.js:318-384 (findAndConnect)
//     .analysis/js/hyperdht/lib/connect.js:386-503 (connectThroughNode)
//     .analysis/js/hyperdht/lib/connect.js:205-316 (holepunch)
//     .analysis/js/hyperdht/lib/connect.js:746-795 (relayConnection)
//
// Structure (post-refactor):
//   do_connect                 — setup, rawStream, findPeer, try_relay_fn
//   └─ on_handshake_success    — post-handshake dispatch (6 paths)
//      ├─ direct / OPEN        — no holepunch needed
//      ├─ passive wait         — our firewall is OPEN, server probes us
//      ├─ LAN shortcut (§6)    — same NAT, ping local address
//      ├─ holepunch_connect    — full 2-round relay + UDP probe
//      └─ start_relay_path     — blind relay (Phase E)
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
//   - Client rawStream + firewall callback are created eagerly at connect()
//     time (matching JS connect.js:73). Server's first UDX packet that
//     arrives before the handshake reply is cached via cached_fw_socket
//     and replayed in on_handshake_success.
//   - LAN shortcut (§6) and holepunch run in parallel — first to complete
//     wins via `state->completed`. JS aborts on LAN ping failure
//     (connect.js:243-246); we fall through to holepunch instead.
//   - Blind relay (Phase E) also runs in parallel with holepunch — matches
//     JS connect.js:489-491 (if either side has relayThrough, relay fires).
// ---------------------------------------------------------------------------
// ConnState — shared state for the async connect pipeline.
// Extracted to namespace scope so helper functions (on_handshake_success,
// start_relay_path) can reference it. Previously nested inside do_connect.
// ---------------------------------------------------------------------------
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

    // Cached early firewall event — JS: c.serverSocket / c.serverAddress.
    // If the server's first UDX packet arrives BEFORE the handshake reply,
    // cache the firewall info here and replay it after hs_result is set.
    udx_socket_t* cached_fw_socket = nullptr;
    compact::Ipv4Address cached_fw_address;
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

// ---------------------------------------------------------------------------
// do_connect — entry point for HyperDHT::connect().
//
// Orchestrates: findPeer → peer_handshake (with Semaphore(2) retry) →
// on_handshake_success (post-handshake decision tree).
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
                state->complete(ConnectError::PEER_NOT_FOUND);
                return;
            }

            // Step 2: try PEER_HANDSHAKE through relays, closest first.
            // JS: connectThroughNode for each relay, Semaphore(2).
            // Phase D: fire up to 2 initial attempts in parallel,
            // then try remaining sequentially on failure.
            state->relay_idx = static_cast<int>(state->relays.size()) - 1;
            state->try_relay_fn = std::make_shared<std::function<void()>>();
            *state->try_relay_fn = [state]() {
                if (state->completed || state->alive.expired()) return;
                if (state->relay_idx < 0) {
                    // Copy state before reset — reset destroys this lambda
                    // and its captured state, causing use-after-free
                    auto st = state;
                    st->try_relay_fn.reset();
                    st->complete(ConnectError::PEER_CONNECTION_FAILED);
                    return;
                }

                state->relay_addr = state->relays[state->relay_idx];
                state->relay_idx--;

                // Compute firewall + addresses4 for the handshake payload.
                // JS: connect.js:386-394 (connectThroughNode)
                //   const addr = c.dht.remoteAddress()
                //   const localAddrs = c.lan ? localAddresses(serverSocket) : null
                //   firewall = addr ? FIREWALL.OPEN : FIREWALL.UNKNOWN
                //
                // remoteAddress() returns non-null only when: host known,
                // port known, not firewalled, NAT port == bound port.
                uint32_t our_fw = peer_connect::FIREWALL_UNKNOWN;
                std::vector<compact::Ipv4Address> our_addrs;

                const auto& sampler = state->socket->nat_sampler();
                if (!sampler.host().empty() &&
                    sampler.port() != 0 &&
                    !state->socket->is_firewalled() &&
                    sampler.port() == state->socket->port()) {
                    // Public / 1:1 NAT — advertise our public address
                    our_fw = peer_connect::FIREWALL_OPEN;
                    our_addrs.push_back(compact::Ipv4Address::from_string(
                        sampler.host(), sampler.port()));
                }

                // Append validated LAN addresses (§6 local_connection support).
                // JS: Holepuncher.localAddresses(dht.io.serverSocket) when c.lan
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

                peer_connect::peer_handshake(*state->socket, state->relay_addr,
                    state->keypair, state->remote_pk, state->our_udx_id,
                    our_fw, our_addrs, relay_through_info,
                    [state](const peer_connect::HandshakeResult& hs) {
                        if (state->completed) return;
                        if (state->alive.expired() || !hs.success) {
                            if (state->try_relay_fn) (*state->try_relay_fn)();
                            return;
                        }
                        // Guard: only the first successful handshake proceeds.
                        // The parallel Semaphore(2) attempt fires a second
                        // handshake that may also succeed. Without this guard,
                        // it overwrites hs_result/raw_stream while holepunch #1
                        // is in flight → mixed state (keys from hs2 + address
                        // from hp1) → RTO because the server session at hp1's
                        // address expects hs1's UDX IDs.
                        if (state->hs_result.success) return;
                        state->try_relay_fn.reset();  // Break cycle
                        state->hs_result = hs;
                        on_handshake_success(state, hs);
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

std::vector<server::Server*> HyperDHT::listening() const {
    std::vector<server::Server*> out;
    out.reserve(servers_.size());
    for (const auto& srv : servers_) {
        if (srv && srv->is_listening()) out.push_back(srv.get());
    }
    return out;
}

server::Server* HyperDHT::create_server() {
    ensure_bound();
    // §16: pass `this` so the server can call back into
    // `validated_local_addresses()` when building its handshake reply
    // under `share_local_address == true`.
    auto srv = std::make_unique<server::Server>(*socket_, router_, this);
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
// ---------------------------------------------------------------------------
// B1: unannounce — standalone convenience wrapper
// JS: hyperdht/index.js:240-242
// ---------------------------------------------------------------------------

void HyperDHT::unannounce(const noise::PubKey& public_key,
                           const noise::Keypair& keypair,
                           std::function<void()> on_done) {
    lookup_and_unannounce(public_key, keypair,
        [](const query::QueryReply&) {},
        [on_done](const std::vector<query::QueryReply>&) {
            if (on_done) on_done();
        });
}

// ---------------------------------------------------------------------------
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

void HyperDHT::suspend() { suspend(nullptr); }

void HyperDHT::suspend(LogFn log) {
    if (suspended_) return;
    suspended_ = true;

    // JS: hyperdht/index.js:106-118 — phase markers match.
    if (log) log("Suspending all hyperdht servers");

    // Suspend all servers (propagate log hook to each).
    for (auto& srv : servers_) {
        srv->suspend(log);
    }

    if (log) log("Suspending dht-rpc");

    // Stop RPC ticks (JS: dht.suspend() stops tick timer)
    if (socket_) {
        socket_->stop_tick();
    }

    if (log) log("Done, hyperdht fully suspended");
}

void HyperDHT::resume() { resume(nullptr); }

void HyperDHT::resume(LogFn log) {
    if (!suspended_) return;
    suspended_ = false;

    // JS: hyperdht/index.js:97 — when `deferRandomPunch` is set, resume
    // re-seeds `_lastRandomPunch = Date.now()` so the interval restarts
    // from resume rather than carrying over the pre-suspend counter.
    if (opts_.defer_random_punch) {
        punch_stats_.last_random_punch = uv_now(loop_);
    }

    if (log) log("Resuming hyperdht servers");

    // Resume all servers
    for (auto& srv : servers_) {
        srv->resume();
    }

    // Restart RPC ticks
    if (socket_) {
        socket_->start_tick();
    }

    if (log) log("Done, hyperdht fully resumed");
}

// ---------------------------------------------------------------------------
// destroy
// ---------------------------------------------------------------------------

void HyperDHT::destroy(std::function<void()> on_done) {
    destroy(DestroyOptions{}, std::move(on_done));
}

void HyperDHT::destroy(DestroyOptions opts, std::function<void()> on_done) {
    if (destroyed_) {
        if (on_done) on_done();
        return;
    }
    destroyed_ = true;
    *alive_ = false;

    // §2: drop strong references to any outstanding background queries
    // BEFORE closing the socket. The queries hold `rpc::RpcSocket&`
    // references and the socket's inflight lambdas capture each query's
    // `self = shared_from_this()`. If we closed the socket first and then
    // let the shared_ptrs go, a pending request callback could still fire
    // against an already-`closing_` socket. Clearing first guarantees
    // each Query is destructed while the socket is still fully alive,
    // and each InflightRequest is torn down by `socket_->close()` below
    // with no dangling references.
    bootstrap_query_.reset();
    refresh_queries_.clear();

    // §15: stop the interface watcher. Its close callback (`on_udx_interface_close`)
    // deletes the heap allocation asynchronously after the timer has
    // drained. Stopping here before `socket_->close()` ensures the watcher
    // cannot fire a `network-change` against a closing DHT.
    //
    // IMPORTANT: callers MUST run `uv_run(loop, UV_RUN_DEFAULT)` after
    // `destroy()` before destructing this HyperDHT. The interface
    // watcher's close callback path reads `event->udx` (a pointer into
    // `RpcSocket::udx_` which is an embedded struct member, not heap);
    // once the RpcSocket is destructed that pointer is dangling. Draining
    // the loop lets libudx's internal `on_interface_event_close` fire
    // while the socket is still alive, so `ref_dec(event->udx)` writes
    // to a valid struct.
    stop_interface_watcher();

    // JS parity (index.js:123-127): graceful close vs force.
    //
    // In JS, `force=true` skips `await server.close()` entirely, which
    // means the announcer never emits UNANNOUNCE and peers continue to
    // consider us active until their records expire.
    //
    // In C++ our close() is synchronous, so we cannot "not-await" it —
    // but we can still honour the intent by telling the announcer to
    // stop silently (skip the unannounce emission). Closing the server
    // is still required even under force=true, otherwise libuv timers
    // and rawStream handles keep the event loop alive and the caller's
    // final `uv_run(...)` never returns.
    for (auto& srv : servers_) {
        srv->close(opts.force /* force = skip unannounce */);
    }

    // Clear router
    router_.clear();

    // Reset handlers_ BEFORE closing the socket (and therefore before
    // the caller's `uv_run()` drain). RpcHandlers owns a heap-allocated
    // `gc_timer_` whose `uv_close` + deleter lambda must be scheduled
    // while the loop is still alive — otherwise the deleter never runs,
    // leaking the timer struct. Previously `handlers_` was released
    // implicitly by ~HyperDHT, which runs AFTER the test's final
    // `uv_loop_close()` → the uv_close was posted to a dead loop.
    handlers_.reset();

    // Close socket
    if (socket_) {
        socket_->close();
    }

    if (on_done) on_done();
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
        state->fast_open);  // §6 opts.fast_open
}

// ---------------------------------------------------------------------------
// start_relay_path — blind relay connection chain.
//
// dht.connect(relay_pk) → SecretStream → Protomux → BlindRelayClient →
// pair → wire rawStream through relay.
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
