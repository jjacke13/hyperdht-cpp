// HyperDHT core lifecycle — constructor, bind, destroy, accessors.
// Connect pipeline:   src/connect.cpp
// Storage operations: src/dht_storage.cpp
// Bootstrap/network:  src/dht_network.cpp
//
// =========================================================================
// JS FLOW MAP — how this file maps to the JavaScript reference
// =========================================================================
//
// C++ function                       JS file                   JS lines
// ─────────────────────────────────── ────────────────────────  ────────
// HyperDHT::bind                     dht-rpc/index.js         157-159
// HyperDHT::cache_relay_addresses    connect.js               464-466
// HyperDHT::get_cached_relay_addrs   connect.js               323-324
// HyperDHT::create_raw_stream        hyperdht/index.js        460-462
// HyperDHT::validate_local_addrs     hyperdht/index.js        135-184
// HyperDHT::connect (entry)          hyperdht/index.js         80-82
//
// HyperDHT::suspend(LogFn)           hyperdht/index.js        106-118
// HyperDHT::resume(LogFn)            hyperdht/index.js         96-104
// HyperDHT::destroy                  hyperdht/index.js        122-133
// HyperDHT::destroy(DestroyOptions)  hyperdht/index.js  122 (force=true)
// HyperDHT::bootstrapper (static)    dht-rpc/index.js         104-120
// HyperDHT::to_array / add_node      dht-rpc/index.js         216-237
// HyperDHT::remote_address           dht-rpc/index.js         201-214
//
// See also:
//   src/connect.cpp      — ConnState, do_connect, on_handshake_success,
//                          start_relay_path, fire_handshake, pipelining
//   src/dht_storage.cpp  — find_peer, lookup, announce, unannounce,
//                          ping, immutable/mutable put/get
//   src/dht_network.cpp  — on_bootstrapped, start_bootstrap_walk, refresh,
//                          fire_network_change/update/persistent,
//                          interface watcher lifecycle
// =========================================================================

#include "hyperdht/dht.hpp"

#include <sodium.h>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <stdexcept>

#include "hyperdht/debug.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/messages.hpp"

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

    // §AUDIT-6: construct the socket pool for route caching. Peers
    // that connected successfully get stored as routes — reconnects
    // skip findPeer entirely. JS: connect.js:177 + socket-pool.js.
    socket_pool_ = std::make_unique<socket_pool::SocketPool>(
        loop_, socket_->udx_handle(), opts_.host);

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

// ---------------------------------------------------------------------------
// §AUDIT-3: Relay address cache
// JS: _relayAddressesCache — hyperdht/index.js:55 (512-entry xache, no TTL)
//     set: connect.js:464-466 (after successful connect)
//     get: connect.js:323-324 (before findPeer on reconnect)
// ---------------------------------------------------------------------------

static std::string pk_to_hex(const noise::PubKey& pk) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (uint8_t b : pk) {
        out.push_back(hex_chars[b >> 4]);
        out.push_back(hex_chars[b & 0x0f]);
    }
    return out;
}

void HyperDHT::cache_relay_addresses(
    const noise::PubKey& pk,
    const std::vector<compact::Ipv4Address>& relays) {
    if (relays.empty()) return;
    auto key = pk_to_hex(pk);
    relay_address_cache_[key] = relays;
    // Simple eviction: if over limit, erase first entry (effectively random
    // for unordered_map). JS uses xache LRU but 512 is large enough that
    // eviction policy doesn't matter in practice.
    if (relay_address_cache_.size() > kMaxRelayAddressCache) {
        relay_address_cache_.erase(relay_address_cache_.begin());
    }
}

std::vector<compact::Ipv4Address> HyperDHT::get_cached_relay_addresses(
    const noise::PubKey& pk) const {
    auto key = pk_to_hex(pk);
    auto it = relay_address_cache_.find(key);
    if (it != relay_address_cache_.end()) return it->second;
    return {};
}

// JS: DHT.bootstrapper — dht-rpc/index.js:104-120.
std::unique_ptr<HyperDHT> HyperDHT::bootstrapper(
    uv_loop_t* loop,
    uint16_t port,
    const std::string& host,
    DhtOptions opts) {

    if (port == 0 || host.empty() ||
        host == "0.0.0.0" || host == "::") {
        return nullptr;  // Invalid arguments
    }
    // IPv4 sanity: uv_ip4_addr parses the dotted-quad form. Anything it
    // rejects (IPv6, hostname, garbage) trips the check.
    struct sockaddr_in probe{};
    if (uv_ip4_addr(host.c_str(), port, &probe) != 0) {
        return nullptr;  // Host must be an IPv4 address
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
        auto* probe_sock = new udx_socket_t{};
        bool ok = (udx_socket_init(socket_->udx_handle(), probe_sock,
                                   [](udx_socket_t* s) { delete s; }) == 0);
        if (ok) {
            struct sockaddr_in sin{};
            if (uv_ip4_addr(host.c_str(), 0, &sin) != 0) {
                ok = false;
            } else if (udx_socket_bind(probe_sock,
                                       reinterpret_cast<struct sockaddr*>(&sin),
                                       0) != 0) {
                ok = false;
            }
            // Clean up: close transfers ownership to the async callback.
            udx_socket_close(probe_sock);
        } else {
            // `udx_socket_init` failed — the handle was never registered
            // with libuv, so we must delete it ourselves.
            delete probe_sock;
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

    // JS parity: hyperdht/index.js:106-118. JS emits five breadcrumbs —
    // the two "clearing raw streams" markers bracket a `rawStreams.clear()`
    // call that does not have a direct C++ counterpart (our raw streams
    // live inside individual connect/server contexts, not in a global
    // pool). We still emit the markers so log output matches the JS
    // shape an operator would see from the reference implementation.
    if (log) log("Suspending all hyperdht servers");

    // Suspend all servers (propagate log hook to each).
    for (auto& srv : servers_) {
        srv->suspend(log);
    }

    if (log) log("Done, clearing all raw streams");
    // (no-op: see comment above)

    if (log) log("Done, suspending dht-rpc");

    // Stop RPC ticks (JS: dht.suspend() stops tick timer)
    if (socket_) {
        socket_->stop_tick();
    }

    if (log) log("Done, clearing raw streams again");
    // (no-op: see comment above)

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
    // `uv_loop_close()` -> the uv_close was posted to a dead loop.
    handlers_.reset();

    // Close socket
    if (socket_) {
        socket_->close();
    }

    if (on_done) on_done();
}

}  // namespace hyperdht
