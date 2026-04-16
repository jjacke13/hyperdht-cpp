#pragma once

// HyperDHT — the main entry point for the C++ HyperDHT library.
//
// Usage:
//   uv_loop_t loop;
//   uv_loop_init(&loop);
//
//   HyperDHT dht(&loop);
//   dht.bind();
//
//   // Client: connect to a peer
//   dht.connect(remote_pk, [](int err, const ConnectionInfo& info) { ... });
//
//   // Server: listen for connections
//   auto* srv = dht.create_server();
//   srv->listen(keypair, [](const server::ConnectionInfo& info) { ... });
//
//   // Cleanup
//   dht.destroy();
//   uv_run(&loop, UV_RUN_DEFAULT);

#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <udx.h>
#include <uv.h>

#include "hyperdht/compact.hpp"
#include "hyperdht/connection_pool.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/query.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"
#include "hyperdht/secret_stream.hpp"
#include "hyperdht/server.hpp"
#include "hyperdht/socket_pool.hpp"

namespace hyperdht {

// ---------------------------------------------------------------------------
// JS-default constants exposed so tests and callers can reference the
// same values without hardcoding literals across multiple files.
// ---------------------------------------------------------------------------

// JS: `NoiseSecretStream` default keep-alive (5 s) — derived from the
// `dht.connectionKeepAlive` field in `dht-rpc/index.js:73` /
// `@hyperswarm/secret-stream/index.js` defaults. The `DhtOptions`
// default below sources from this constant so test code that bypasses
// `HyperDHT` (e.g. `test/test_live_connect.cpp` which drives
// `rpc::RpcSocket` directly) can reference the same value without
// drifting when the default changes.
inline constexpr uint64_t DEFAULT_CONNECTION_KEEP_ALIVE_MS = 5000;

// ---------------------------------------------------------------------------
// Options for HyperDHT construction
// ---------------------------------------------------------------------------

struct DhtOptions {
    // Local bind — ipv4 host + port. JS: `opts.host || '0.0.0.0'`, `opts.port || 49737`.
    // C++ differs on the port default: `0` = ephemeral (kernel picks free port).
    // Setting `port = 49737` matches JS for "known port" deployments.
    uint16_t port = 0;
    std::string host = "0.0.0.0";

    // Bootstrap node addresses (JS: opts.bootstrap). Empty = use public defaults.
    std::vector<compact::Ipv4Address> bootstrap;

    // Known-good bootstrap hints pre-seeded into the routing table.
    // JS: `opts.nodes || KNOWN_NODES`. Unlike `bootstrap` (queried during
    // bootstrap), these are added directly to the table so the DHT already
    // knows some live peers at construction time. Used by long-running
    // deployments to preserve routing state across restarts.
    std::vector<compact::Ipv4Address> nodes;

    // Default signing keypair (auto-generated from `seed` or random).
    // If `seed` is set, `default_keypair` is derived deterministically at
    // HyperDHT construction. Otherwise, if `default_keypair` is already
    // populated, it's used as-is. Otherwise, a random one is generated.
    // JS: `opts.keyPair || createKeyPair(opts.seed)`.
    noise::Keypair default_keypair;
    std::optional<noise::Seed> seed;

    // Default keep-alive ms for outgoing connections (JS: opts.connectionKeepAlive,
    // default 5000). JS applies this to every `NoiseSecretStream` at stream
    // construction time (connect.js:45).
    //
    // C++ does NOT auto-wrap the raw stream in a `SecretStreamDuplex` —
    // callers construct the Duplex themselves (see
    // `test/test_live_connect.cpp`). The canonical way to preserve JS
    // parity for keep-alive is:
    //
    //     auto duplex_opts = dht.make_duplex_options();
    //     auto* duplex = new SecretStreamDuplex(raw, hs, loop, duplex_opts);
    //
    // which populates `DuplexOptions::keep_alive_ms` from this field.
    uint64_t connection_keep_alive = DEFAULT_CONNECTION_KEEP_ALIVE_MS;

    // Optional filter applied to every node observed from the network
    // — both incoming RPCs that would be added to the routing table
    // (dht-rpc/index.js:484) and closer-nodes suggestions returned by
    // peers during a query walk (dht-rpc/lib/query.js:275).
    //
    //   Return `true`  → node is allowed.
    //   Return `false` → node is silently dropped.
    //
    // JS parity (hyperdht/index.js:585-592): HyperDHT ships with its
    // own hardcoded testnet blocklist that is ALWAYS applied on top of
    // whatever the caller supplied. When this field is empty we still
    // install the built-in JS blocklist; when set, the caller's filter
    // runs AND the blocklist runs (both must pass, matching the JS
    // single-filter semantics where the built-in filter composes).
    //
    // Signature matches `rpc::FilterNodeCallback`.
    std::function<bool(const routing::NodeId&,
                       const compact::Ipv4Address&)> filter_node;

    // Throttling for random-NAT holepunch attempts. JS defaults:
    //   randomPunchInterval: 20000ms (min gap between random punches)
    //   deferRandomPunch: false (if true, initial last_random_punch = now,
    //                            so the first random punch is gated)
    uint64_t random_punch_interval = 20000;
    bool defer_random_punch = false;

    // LRU storage cache tuning (JS: opts.maxSize, opts.maxAge).
    //
    // `max_size` (JS: opts.maxSize || 65536) is the overall cache budget.
    // Mutable + immutable caches each get `max_size/2` entries, matching
    // JS `hyperdht/index.js:610-615`.
    //
    // `max_age_ms` (JS: opts.maxAge || 20*60*1000 = 20 min) governs the
    // OTHER caches (router forwards, records, refreshes, bumps). It does
    // NOT govern mutable/immutable storage — JS uses 48h there regardless
    // of `maxAge` unless the caller explicitly overrides via `storage_ttl_ms`.
    // JS parity: `mutables: { maxAge: opts.maxAge || 48h }`.
    //
    // Currently only the storage caches are configurable in C++, so
    // `max_age_ms` is stored for forward compatibility but isn't wired
    // anywhere yet. Set `storage_ttl_ms` to tune mutable/immutable TTL.
    size_t max_size = 65536;
    uint64_t max_age_ms = 20 * 60 * 1000;
    uint64_t storage_ttl_ms = 48ULL * 60 * 60 * 1000;  // 48h (JS default)

    // Ephemeral mode (JS: opts.ephemeral). Ephemeral nodes are never
    // announced as persistent and are evicted more aggressively.
    bool ephemeral = true;
};

// ---------------------------------------------------------------------------
// Connection result (client side)
// ---------------------------------------------------------------------------

struct ConnectResult {
    bool success = false;
    noise::Key tx_key{};
    noise::Key rx_key{};
    noise::Hash handshake_hash{};
    std::array<uint8_t, 32> remote_public_key{};
    compact::Ipv4Address peer_address;
    uint32_t remote_udx_id = 0;
    uint32_t local_udx_id = 0;
    udx_stream_t* raw_stream = nullptr;   // Pre-created during handshake (like JS rawStream)
    udx_socket_t* udx_socket = nullptr;   // Socket for UDX connect (JS: ref.socket from probe)
    // Keeps the pool socket alive for the UDX stream's lifetime. Caller must
    // hold this as long as the stream is using udx_socket.
    std::shared_ptr<void> socket_keepalive;
};

// ---------------------------------------------------------------------------
// Connect error codes — matches JS hyperdht/lib/errors.js
// ---------------------------------------------------------------------------
// Passed as the `error` parameter to ConnectCallback. 0 = success.

namespace ConnectError {
    constexpr int NONE                  =  0;  // Success
    constexpr int DESTROYED             = -1;  // DHT was destroyed during connect
    constexpr int PEER_NOT_FOUND        = -2;  // JS: PEER_NOT_FOUND — findPeer returned no results
    constexpr int PEER_CONNECTION_FAILED = -3;  // JS: PEER_CONNECTION_FAILED — all relay handshakes failed
    constexpr int NO_ADDRESSES          = -4;  // Server replied but provided no connectable addresses
    constexpr int HOLEPUNCH_FAILED      = -5;  // JS: CANNOT_HOLEPUNCH — holepunch probing failed
    constexpr int HOLEPUNCH_TIMEOUT     = -6;  // JS: HOLEPUNCH_ABORTED — passive wait timed out (OPEN fw)
    constexpr int RELAY_FAILED          = -7;  // JS: RELAY_ABORTED — blind relay pairing failed
}

using ConnectCallback = std::function<void(int error, const ConnectResult& result)>;

// ---------------------------------------------------------------------------
// Connect options (matches JS connect.js opts)
// ---------------------------------------------------------------------------

struct ConnectOptions {
    // Connection pool for deduplication (JS: opts.pool)
    connection_pool::ConnectionPool* pool = nullptr;

    // Whether to attempt socket reuse from a previous connection (JS: opts.reusableSocket)
    bool reusable_socket = false;

    // Callback to veto holepunch based on firewall types (JS: opts.holepunch)
    // Return false to abort. Args: remote_fw, local_fw, remote_addrs, local_addrs
    using HolepunchVetoFn = std::function<bool(uint32_t, uint32_t,
        const std::vector<compact::Ipv4Address>&,
        const std::vector<compact::Ipv4Address>&)>;
    HolepunchVetoFn holepunch_veto;

    // Cached relay addresses for faster reconnect (JS: opts.relayAddresses)
    std::vector<compact::Ipv4Address> relay_addresses;

    // JS: opts.keyPair — override the default DHT keypair for this single
    // connection. If unset, `HyperDHT::default_keypair()` is used. Useful
    // for clients that want to rotate their identity per connection.
    std::optional<noise::Keypair> keypair;

    // JS: opts.fastOpen !== false (default true). When true, primes our
    // NAT mapping by sending a low-TTL (5) probe to the server's relay-
    // reported address BEFORE holepunch round 1. Shaves one round-trip
    // for CONSISTENT+CONSISTENT NAT combinations. Safe to leave at true;
    // set to false only for debugging.
    bool fast_open = true;

    // JS: opts.localConnection !== false (default true). When true and
    // our public IP matches the server's public IP (both nodes behind the
    // same NAT), try a LAN shortcut: find a matching local address and
    // ping it directly before falling back to holepunch. Disable to skip
    // the LAN path and go straight to the public-internet flow.
    bool local_connection = true;

    // --- Blind-relay options (Phase E) ---
    //
    // JS: opts.relayThrough — see `selectRelay()` in connect.js:842-848.
    //
    // Three forms, evaluated in this order at connect() time (first
    // non-empty wins):
    //   1. `relay_through_fn` — if set, it's called and its return value
    //       is used. Analogous to JS `typeof relayThrough === 'function'`.
    //   2. `relay_through_array` — if non-empty, one entry is picked at
    //       random. Analogous to JS `Array.isArray(relayThrough)`.
    //   3. `relay_through` — single fixed public key (the legacy single-
    //       key form; JS: `relayThrough` is a buffer).
    //
    // A `std::nullopt` result from any of the forms means "no relay".
    // When the chosen public key is non-null, the client includes
    // `relayThrough: { publicKey, token }` in the Noise payload so the
    // server can also dial the same relay.
    //
    // JS: connect.js:40,87-92,842-848
    std::optional<noise::PubKey> relay_through;
    std::vector<noise::PubKey> relay_through_array;
    std::function<std::optional<noise::PubKey>()> relay_through_fn;

    // Resolve the three forms above into a single choice. Exposed for
    // unit testing — `do_connect` calls this internally. `rand_u64` lets
    // tests inject a deterministic PRNG; production calls pass nullptr
    // to use libsodium's `randombytes_buf`.
    std::optional<noise::PubKey> select_relay_through(
        uint64_t (*rand_u64)() = nullptr) const;

    // Auto-generated relay token. If relay_through is set and relay_token
    // is all-zeros, a random token is generated at connect() time.
    // JS: connect.js:88 — relay.token()
    std::array<uint8_t, 32> relay_token{};

    // JS: opts.relayKeepAlive || 5000 — keep-alive for the relay socket
    uint64_t relay_keep_alive = 5000;

    // --- Remaining deferred JS options ---
    //
    //  - `createSecretStream`: factory hook for a custom secret-stream
    //    wrapper. LOW priority — C++ callers construct `SecretStreamDuplex`
    //    over the returned `rawStream` directly.
    //  - `createHandshake`: factory hook for a custom Noise handshake.
    //    LOW priority — `peer_connect::peer_handshake` is called directly.
    //
    // (Note: `relay_addresses` ABOVE is the cached "which relays found this
    //  peer last time" hint, distinct from `relay_through` blind-relay.)
};

// ---------------------------------------------------------------------------
// HyperDHT
// ---------------------------------------------------------------------------

class HyperDHT {
public:
    explicit HyperDHT(uv_loop_t* loop, DhtOptions opts = {});
    ~HyperDHT();

    HyperDHT(const HyperDHT&) = delete;
    HyperDHT& operator=(const HyperDHT&) = delete;

    // Bind the UDP socket (called automatically by connect/listen if needed).
    //
    // When `opts.bootstrap` is non-empty, `bind()` additionally kicks off a
    // one-shot background `FIND_NODE(our_id)` walk seeded from the supplied
    // bootstrap nodes (JS `_bootstrap()` in dht-rpc/index.js:379-433). On
    // completion the underlying `RpcSocket` is marked bootstrapped — this
    // is what enables ping-and-swap for full buckets, and it is what
    // `on_bootstrapped(cb)` fires on. When `opts.bootstrap` is empty the
    // walk is skipped and callers are responsible for populating the
    // routing table some other way (pre-seeded `opts.nodes`, manual
    // `add_bootstrap()` on individual queries, loopback test peers, etc.).
    int bind();

    // The 3 canonical public HyperDHT bootstrap nodes (JS `BOOTSTRAP_NODES`
    // in `hyperdht/lib/constants.js:16-20`). Callers that want JS's default
    // auto-bootstrap behaviour should set `opts.bootstrap =
    // HyperDHT::default_bootstrap_nodes()` before construction.
    static const std::vector<compact::Ipv4Address>& default_bootstrap_nodes();

    // Callback fired once when the initial bootstrap walk completes (the
    // RpcSocket is now marked bootstrapped and ping-and-swap is enabled).
    //
    // JS reference: `dht-rpc/index.js:404` emits `'ready'` on the DHT's
    // EventEmitter. Two deliberate divergences from JS:
    //   1. **Late install fires synchronously.** Node's EventEmitter does
    //      not replay past events, so a `.once('ready', cb)` installed
    //      *after* the emit never fires in JS. C++ instead fires the
    //      callback synchronously from inside `on_bootstrapped()` if the
    //      walk has already completed. This is a convenience extension,
    //      not JS parity. Callers that care about the ordering should
    //      install the callback BEFORE `bind()`.
    //   2. **Single slot, last-writer-wins.** `on_bootstrapped` stores
    //      exactly one callback. Installing a second callback silently
    //      replaces the first. (This matches the one-listener use case
    //      that JS `once('ready')` is typically used for; if you need
    //      a broadcast, maintain your own listener list in userspace.)
    //
    // No-op if `opts.bootstrap` is empty — without seeds there is no
    // walk to complete and the flag stays false.
    using BootstrappedCallback = std::function<void()>;
    void on_bootstrapped(BootstrappedCallback cb);
    bool is_bootstrapped() const {
        return socket_ && socket_->is_bootstrapped();
    }

    // Run a one-shot background refresh query (JS `refresh()` in
    // dht-rpc/index.js:435-438). Targets a random node from the routing
    // table, falling back to our own id if the table is empty. Called
    // automatically every REFRESH_TICKS by the RpcSocket background tick
    // once `bind()` has wired the callback. Public so callers can force
    // an extra refresh if they need one.
    void refresh();

    // --- §15: network-change / network-update / persistent event hooks ---
    //
    // JS reference: `dht-rpc/index.js:596-599` (`_onnetworkchange`),
    // `dht-rpc/index.js:982-1002` (`_online`/`_degraded`/`_offline`), and
    // `dht-rpc/index.js:870-872` (`emit('persistent')`).
    //
    // `network-change` fires when the OS reports a network interface change
    // (via the libudx interface-event watcher, polling every 5 seconds —
    // matches `udx.watchNetworkInterfaces()` in JS `dht-rpc/lib/io.js:39`).
    // The HyperDHT layer auto-refreshes every active `Server` on change
    // (`hyperdht/index.js:68-70`).
    //
    // `network-update` fires on every `network-change` AND whenever the
    // health monitor transitions between ONLINE / DEGRADED / OFFLINE.
    // HyperDHT auto-calls `Server::notify_online()` on every listening
    // server when the update fires while online
    // (`hyperdht/index.js:72-75`).
    //
    // `persistent` fires once when the node transitions from ephemeral to
    // persistent after the NAT classifier has decided we're reachable
    // (`dht-rpc/index.js:870-872`). `hyperdht/index.js:64-66` uses this
    // hook to spin up the persistent store — C++ doesn't have the
    // persistent store yet, but exposing the hook lets callers observe
    // the transition today.
    //
    // Each callback slot is single-shot replaceable (`last writer wins`),
    // matching the existing `on_bootstrapped` convention. Install BEFORE
    // `bind()` to avoid missing early events.
    using NetworkChangeCallback = std::function<void()>;
    using NetworkUpdateCallback = std::function<void()>;
    using PersistentCallback    = std::function<void()>;
    void on_network_change(NetworkChangeCallback cb) {
        on_network_change_ = std::move(cb);
    }
    void on_network_update(NetworkUpdateCallback cb) {
        on_network_update_ = std::move(cb);
    }
    void on_persistent(PersistentCallback cb) {
        on_persistent_ = std::move(cb);
    }

    // Observable health state — mirrors JS `this.online` / `this.degraded`.
    bool is_online() const {
        return socket_ && socket_->health().is_online();
    }
    bool is_degraded() const {
        return socket_ && socket_->health().is_degraded();
    }
    bool is_persistent() const {
        return socket_ && !socket_->is_ephemeral();
    }

    // Test hook: invoke the network-change fan-out directly without
    // waiting for a real interface event. Used by unit tests to
    // exercise the server-refresh + user-callback path deterministically.
    void fire_network_change_for_test() { fire_network_change(); }

    // --- §16: createRawStream + validateLocalAddresses ---
    //
    // JS references: `hyperdht/index.js:460-462` (createRawStream) and
    // `hyperdht/index.js:135-184` (validateLocalAddresses).
    //
    // `create_raw_stream()` returns a newly-allocated `udx_stream_t*`
    // with a random stream ID on the underlying RpcSocket's udx handle.
    // The caller takes ownership and is responsible for destroying the
    // stream (or handing it to a SecretStreamDuplex which takes over
    // lifetime management). Optional firewall callback can be installed
    // by the caller via `udx_stream_firewall` after construction.
    //
    // `validate_local_addresses(list)` filters the input list to only
    // those addresses whose host can be successfully bound by this
    // machine — catches addresses not owned by this host (e.g., stale
    // DHCP leases, addresses from a different network namespace). Does
    // NOT run the 500 ms self-loopback probe that JS does — JS's own
    // comment at `hyperdht/index.js:160` calls that "semi terrible
    // heuristic". Results are cached per host. Synchronous.
    udx_stream_t* create_raw_stream();

    std::vector<compact::Ipv4Address> validate_local_addresses(
        const std::vector<compact::Ipv4Address>& addresses);

    // Returns the cached list of local addresses that passed
    // `validate_local_addresses()` at bind time. The server side reads
    // this to populate `addresses4` in the Noise payload when
    // `share_local_address=true`. Matches JS `server._localAddresses()`.
    const std::vector<compact::Ipv4Address>& validated_local_addresses() const {
        return validated_local_addresses_;
    }

    // --- Static helpers (B3-B6) ---
    // JS: HyperDHT.keyPair(seed), HyperDHT.hash(data)
    // JS: HyperDHT.BOOTSTRAP, HyperDHT.FIREWALL

    // B5: Generate a keypair from an optional 32-byte seed.
    // JS: HyperDHT.keyPair(seed) — hyperdht/index.js:444-446
    static noise::Keypair key_pair(const noise::Seed& seed) {
        return noise::generate_keypair(seed);
    }
    static noise::Keypair key_pair() {
        return noise::generate_keypair();
    }

    // B6: BLAKE2b-256 hash of arbitrary data.
    // JS: HyperDHT.hash(data) — hyperdht/index.js:448-450
    static std::array<uint8_t, 32> hash(const uint8_t* data, size_t len);

    // JS: dht-rpc/index.js:104-120 `DHT.bootstrapper(port, host, opts)`.
    //
    // Convenience factory for nodes that want to RUN as a public
    // bootstrap seed (the kind of node listed in the 3-address
    // `BOOTSTRAP` set). Produces a HyperDHT that is:
    //   - non-ephemeral (participates in storage + announce)
    //   - non-firewalled (advertises itself as OPEN)
    //   - bound to the given fixed port (not auto-ephemeral)
    //   - initialised with an empty bootstrap list (it IS the bootstrap)
    //
    // Throws `std::invalid_argument` on invalid inputs (port 0,
    // empty / wildcard / non-IPv4 host).
    //
    // The caller still has to call `bind()` to actually open the
    // socket — the factory only constructs the instance so caller
    // code can inject test hooks before bind.
    static std::unique_ptr<HyperDHT> bootstrapper(
        uv_loop_t* loop,
        uint16_t port,
        const std::string& host,
        DhtOptions opts = {});

    // JS: HyperDHT.connectRawStream(encryptedStream, rawStream, remoteId)
    // — hyperdht/index.js:452-458.
    //
    // Advanced helper for piggy-backing a SECOND UDX stream onto the
    // socket that an existing connection is already using. The new
    // `raw` handle is UDX-connected to the same peer host/port as
    // `base`, but gets a fresh stream id (`remote_udx_id`). Useful
    // when a higher-level protocol wants multiple independent streams
    // between the same two peers without opening another connection.
    //
    // Preconditions: `base.success == true` and `base.udx_socket` /
    // `base.peer_address` populated (i.e. `base` came from a
    // successfully-completed `connect()`).
    //
    // Returns 0 on success, negative on error.
    static int connect_raw_stream(const ConnectResult& base,
                                  udx_stream_t* raw,
                                  uint32_t remote_udx_id);

    // B3: Firewall constants (JS: HyperDHT.FIREWALL)
    struct FIREWALL {
        static constexpr uint32_t UNKNOWN    = 0;
        static constexpr uint32_t OPEN       = 1;
        static constexpr uint32_t CONSISTENT = 2;
        static constexpr uint32_t RANDOM     = 3;
    };

    // B4: Public bootstrap nodes (JS: HyperDHT.BOOTSTRAP)
    // Alias for default_bootstrap_nodes() — static const reference.
    static const std::vector<compact::Ipv4Address>& BOOTSTRAP() {
        return default_bootstrap_nodes();
    }

    // --- Client API ---

    // Connect to a remote peer by public key.
    // Orchestrates: findPeer → handshake → holepunch → ready.
    // Callback receives error code (0 = success) and connection info.
    void connect(const noise::PubKey& remote_public_key,
                 ConnectCallback on_done);

    // Connect with options (pool, reusable socket, holepunch veto)
    void connect(const noise::PubKey& remote_public_key,
                 const ConnectOptions& opts,
                 ConnectCallback on_done);

    // Connect with a specific keypair (instead of default)
    void connect(const noise::PubKey& remote_public_key,
                 const noise::Keypair& keypair,
                 ConnectCallback on_done);

    // Shared punch stats for throttling across connections
    holepunch::PunchStats& punch_stats() { return punch_stats_; }

    // Socket pool for route caching and socket reuse
    socket_pool::SocketPool* socket_pool() { return socket_pool_.get(); }

    // --- Server API ---

    // Create a server instance. HyperDHT owns the returned pointer.
    server::Server* create_server();

    // --- DHT Operations ---

    std::shared_ptr<query::Query> find_peer(
        const noise::PubKey& public_key,
        query::OnReplyCallback on_reply,
        query::OnDoneCallback on_done);

    std::shared_ptr<query::Query> lookup(
        const routing::NodeId& target,
        query::OnReplyCallback on_reply,
        query::OnDoneCallback on_done);

    std::shared_ptr<query::Query> announce(
        const routing::NodeId& target,
        const std::vector<uint8_t>& value,
        query::OnDoneCallback on_done);

    // --- DHT Operations (continued) ---

    // Lookup and unannounce from old nodes (JS: lookupAndUnannounce)
    std::shared_ptr<query::Query> lookup_and_unannounce(
        const noise::PubKey& public_key,
        const noise::Keypair& keypair,
        query::OnReplyCallback on_reply,
        query::OnDoneCallback on_done);

    // B1: Standalone unannounce (JS: dht.unannounce — hyperdht/index.js:240-242)
    // Convenience wrapper: runs lookup_and_unannounce, ignores per-reply.
    void unannounce(const noise::PubKey& public_key,
                    const noise::Keypair& keypair,
                    std::function<void()> on_done = nullptr);

    // Ping a specific node (JS: dht.ping(addr))
    void ping(const compact::Ipv4Address& addr,
              std::function<void(bool ok)> on_done);

    // --- Mutable / Immutable storage (JS: dht.{immutable,mutable}{Put,Get}) ---

    // Immutable put: stores `value` at target = BLAKE2b(value).
    // JS: dht.immutablePut(value) → { hash, closestNodes }
    // `on_done` fires after the commit phase completes. Returns nullptr if
    // `value` is empty (matches JS: empty values are rejected server-side).
    struct ImmutablePutResult {
        std::array<uint8_t, 32> hash{};
        std::vector<query::QueryReply> closest_nodes;
    };
    using ImmutablePutCallback = std::function<void(const ImmutablePutResult&)>;
    std::shared_ptr<query::Query> immutable_put(
        const std::vector<uint8_t>& value,
        ImmutablePutCallback on_done);

    // Immutable get: retrieves the value whose content hash is `target`.
    // JS: dht.immutableGet(target) → { value } | null
    //
    // `on_value` (optional) fires once per verified reply during the walk,
    // matching the streaming semantics of JS `for await (const node of query)`.
    // Callers can use the streaming callback to act on the first match
    // without waiting for the full walk.
    //
    // `on_done` fires when the query completes. Its result struct contains
    // the FIRST verified value (if any).
    struct ImmutableGetResult {
        bool found = false;
        std::vector<uint8_t> value;
    };
    using ImmutableValueCallback = std::function<void(const std::vector<uint8_t>&)>;
    using ImmutableGetCallback = std::function<void(const ImmutableGetResult&)>;
    std::shared_ptr<query::Query> immutable_get(
        const std::array<uint8_t, 32>& target,
        ImmutableGetCallback on_done);
    std::shared_ptr<query::Query> immutable_get(
        const std::array<uint8_t, 32>& target,
        ImmutableValueCallback on_value,
        ImmutableGetCallback on_done);

    // Mutable put: signs `value` with `keypair` at seq `seq` and stores it
    // at target = BLAKE2b(keypair.public_key).
    // JS: dht.mutablePut(keyPair, value, { seq }) → { publicKey, closestNodes, seq, signature }
    // Returns nullptr if `value` is empty.
    struct MutablePutResult {
        noise::PubKey public_key{};
        uint64_t seq = 0;
        std::array<uint8_t, 64> signature{};
        std::vector<query::QueryReply> closest_nodes;
    };
    using MutablePutCallback = std::function<void(const MutablePutResult&)>;
    std::shared_ptr<query::Query> mutable_put(
        const noise::Keypair& keypair,
        const std::vector<uint8_t>& value,
        uint64_t seq,
        MutablePutCallback on_done);

    // Mutable get: retrieves the latest signed value for `public_key`.
    // JS: dht.mutableGet(publicKey, { seq, latest }) → { seq, value, signature } | null
    //
    // `min_seq` filters out results with lower seq (JS `opts.seq`).
    // `latest == true` (default): returns the highest-seq valid reply.
    // `latest == false`: returns the first valid reply. NOTE: deferred early
    // termination — the C++ version still walks the full query. Tracked as
    // a §9 query-engine follow-up in docs/JS-PARITY-GAPS.md.
    //
    // The optional `on_value` callback fires once per verified reply during
    // the walk, matching JS `for await (const node of query)`.
    struct MutableGetResult {
        bool found = false;
        uint64_t seq = 0;
        std::vector<uint8_t> value;
        std::array<uint8_t, 64> signature{};
    };
    using MutableValueCallback =
        std::function<void(const dht_ops::MutableResult&)>;
    using MutableGetCallback = std::function<void(const MutableGetResult&)>;
    std::shared_ptr<query::Query> mutable_get(
        const noise::PubKey& public_key,
        uint64_t min_seq,
        bool latest,
        MutableGetCallback on_done);
    std::shared_ptr<query::Query> mutable_get(
        const noise::PubKey& public_key,
        uint64_t min_seq,
        bool latest,
        MutableValueCallback on_value,
        MutableGetCallback on_done);

    // Overload: mutable_get with defaults (min_seq=0, latest=true).
    std::shared_ptr<query::Query> mutable_get(
        const noise::PubKey& public_key,
        MutableGetCallback on_done) {
        return mutable_get(public_key, 0, true, std::move(on_done));
    }

    // --- Stats (B2) ---
    // JS: dht.stats — hyperdht/index.js:44-48
    struct RelayingStats {
        int attempts = 0;
        int successes = 0;
        int aborts = 0;
    };
    struct Stats {
        struct { int consistent = 0; int random = 0; int open = 0; } punches;
        RelayingStats relaying;
    };
    Stats stats() const {
        Stats s;
        s.punches.consistent = punch_stats_.punches_consistent;
        s.punches.random = punch_stats_.punches_random;
        s.punches.open = punch_stats_.punches_open;
        s.relaying = relay_stats_;
        return s;
    }

    // Relay stat counters — connect/server flows increment these
    RelayingStats& relay_stats() { return relay_stats_; }

    // --- Connection Pool ---

    // Create a new connection pool (JS: dht.pool())
    connection_pool::ConnectionPool pool();

    // --- Lifecycle ---

    // Suspend: stop all servers, clear pending connects.
    //
    // JS: hyperdht/index.js:106-118 `suspend({ log })` — iterates every
    // listening server and awaits server.suspend(), then suspends the
    // base dht-rpc layer. Emits progress messages at each phase.
    //
    // Optional `log` hook mirrors JS. Pass `nullptr` for silent suspend.
    // Same signature as `Server::suspend(LogFn)`.
    using LogFn = std::function<void(const char*)>;
    void suspend(LogFn log);
    void suspend();  // convenience: suspend(nullptr)

    // Resume: resume all servers.
    //
    // JS: hyperdht/index.js:96-104 `resume({ log })` — resumes the base
    // layer then each server. `log` hook matches suspend.
    void resume(LogFn log);
    void resume();  // convenience: resume(nullptr)

    // JS parity: hyperdht/index.js:122-133 `destroy({ force = false })`.
    //
    // `force = false` (default): gracefully close every active server —
    // each announcer sends UNANNOUNCE records so peers learn we went
    // away, then pending sessions are cleared.
    //
    // `force = true`: skip the announcer graceful shutdown and tear down
    // the socket immediately. Faster but leaves stale announce records
    // in the network for `maxAge`. Use when the process is about to exit
    // anyway (SIGTERM, crash handler, etc.).
    struct DestroyOptions {
        bool force = false;
    };
    void destroy(DestroyOptions opts,
                 std::function<void()> on_done = nullptr);
    // Convenience: graceful destroy.
    void destroy(std::function<void()> on_done = nullptr);
    bool is_destroyed() const { return destroyed_; }

    // JS: hyperdht/index.js:37 — `this.listening = new Set()`. Returns
    // a snapshot view of every Server currently in the "listening"
    // state. No separate Set is maintained; `servers_` owns every
    // Server, and this helper filters on `is_listening()` at call time.
    // Returned pointers are valid until the corresponding Server is
    // destroyed (DHT destruction or its parent going out of scope).
    std::vector<server::Server*> listening() const;
    bool is_suspended() const { return suspended_; }
    bool is_connectable() const { return !suspended_ && !destroyed_; }

    // --- Accessors ---

    uv_loop_t* loop() const { return loop_; }
    rpc::RpcSocket& socket() { return *socket_; }
    router::Router& router() { return router_; }
    const noise::Keypair& default_keypair() const { return opts_.default_keypair; }
    uint16_t port() const { return socket_ ? socket_->port() : 0; }
    bool is_bound() const { return bound_; }

    // JS: dht-rpc/index.js:233-237 `toArray({limit})` — snapshot the
    // routing table as a flat list of `{host, port}` entries. Callers
    // use this to persist known peers across process restarts (feed
    // the result back into `DhtOptions::nodes` on re-bind) or to dump
    // the table for observability.
    //
    // `limit` caps the output; default (`SIZE_MAX`) returns every
    // node. Explicit 0 limit returns an empty vector, matching JS
    // `{limit: 0}` semantics.
    //
    // **Ordering difference from JS.** JS uses a time-ordered set
    // (`reverse: true` → most-recently-seen first), so a small `limit`
    // preferentially keeps the nodes most likely to still be online.
    // We iterate Kademlia buckets in ascending XOR distance (bucket 0
    // first, bucket ID_BITS-1 last), i.e. closest peers first, which
    // is orthogonal to recency. For the typical persistence use case
    // the difference is benign (closest nodes tend to be active too),
    // but callers that specifically want the "live peers for cold
    // restart" semantic should be aware.
    std::vector<compact::Ipv4Address> to_array(
        size_t limit = std::numeric_limits<size_t>::max()) const {
        std::vector<compact::Ipv4Address> out;
        if (!socket_ || limit == 0) return out;
        for (size_t i = 0; i < routing::ID_BITS; ++i) {
            for (const auto& n : socket_->table().bucket(i).nodes()) {
                out.push_back(
                    compact::Ipv4Address::from_string(n.host, n.port));
                if (out.size() >= limit) return out;
            }
        }
        return out;
    }

    // JS: dht-rpc/index.js:216-231 `addNode({host, port})` — insert a
    // node into the routing table at runtime (construction-time
    // injection is `DhtOptions::nodes`). The peer id is computed by
    // `rpc::compute_peer_id(addr)` so the table stores it under the
    // same BLAKE2b-256 hash a real network response would use.
    //
    // The node's tick fields are seeded from the current RPC tick so
    // it immediately looks "fresh" — matches JS `added: this._tick`.
    // No-op if not bound.
    void add_node(const compact::Ipv4Address& addr) {
        if (!socket_) return;
        routing::Node node;
        node.id = rpc::compute_peer_id(addr);
        node.host = addr.host_string();
        node.port = addr.port;
        // JS parity (dht-rpc/index.js:216-230): `added: this._tick,
        // pinged: 0, seen: 0`. Only `added` is stamped; `pinged` /
        // `seen` stay at zero so the node is immediately eligible
        // for the ping-and-swap eviction cycle if its bucket is
        // already full.
        node.added = socket_->tick();
        node.pinged = 0;
        node.seen = 0;
        socket_->table().add(node);
    }

    // JS: dht-rpc/index.js:201-214 `remoteAddress()` — returns our
    // public address as seen by the DHT (from NAT sampling), or
    // `std::nullopt` if:
    //   - we're firewalled (NAT unknown)
    //   - no samples yet (nat_sampler has no addresses)
    //   - our bound port doesn't match the sampled port (our socket
    //     moved underneath us — reject as stale)
    //
    // Useful for advertising our reachability to peers, or for
    // confirming we're properly bootstrapped before issuing queries.
    std::optional<compact::Ipv4Address> remote_address() const {
        if (!socket_ || !bound_) return std::nullopt;
        if (socket_->is_firewalled()) return std::nullopt;
        const auto& addrs = socket_->nat_sampler().addresses();
        if (addrs.empty()) return std::nullopt;
        const auto& top = addrs.front();
        // JS parity: drop the sample if our current bound port has
        // drifted away from what the sampler saw.
        if (top.port != socket_->port()) return std::nullopt;
        return top;
    }

    // §7 accessors — read the tuning knobs that consumer apps may need
    // to apply to stream wrappers / connection setup.
    const std::string& host() const { return opts_.host; }
    uint64_t connection_keep_alive() const { return opts_.connection_keep_alive; }
    uint64_t random_punch_interval() const { return opts_.random_punch_interval; }
    bool defer_random_punch() const { return opts_.defer_random_punch; }
    size_t max_size() const { return opts_.max_size; }
    uint64_t max_age_ms() const { return opts_.max_age_ms; }
    uint64_t storage_ttl_ms() const { return opts_.storage_ttl_ms; }

    // §7 polish: returns a `SecretStreamDuplex::DuplexOptions` populated
    // from this DHT's configuration. Callers that construct a Duplex
    // from a connect() result should use this helper instead of building
    // `DuplexOptions{}` themselves — doing so automatically applies the
    // DHT's `connection_keep_alive` setting, matching JS's
    // `NoiseSecretStream({..., keepAlive: dht.connectionKeepAlive})` in
    // `hyperdht/lib/connect.js:41-46`.
    secret_stream::DuplexOptions make_duplex_options() const {
        secret_stream::DuplexOptions opts;
        opts.keep_alive_ms = opts_.connection_keep_alive;
        return opts;
    }

private:
    uv_loop_t* loop_;
    DhtOptions opts_;
    std::unique_ptr<rpc::RpcSocket> socket_;
    std::unique_ptr<rpc::RpcHandlers> handlers_;
    router::Router router_;
    std::vector<std::unique_ptr<server::Server>> servers_;
    bool bound_ = false;
    bool destroyed_ = false;
    bool suspended_ = false;
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);  // Sentinel for async safety
    holepunch::PunchStats punch_stats_;
    RelayingStats relay_stats_;
    std::unique_ptr<socket_pool::SocketPool> socket_pool_;

    // §2 bootstrap walk state. `bootstrap_query_` holds a strong reference
    // so the shared_ptr<Query> stays alive until its on_done fires.
    // `on_bootstrapped_` is called once when the walk completes.
    // `refresh_queries_` collects the periodic refresh walks; entries are
    // pruned when their on_done fires.
    BootstrappedCallback on_bootstrapped_;
    std::shared_ptr<query::Query> bootstrap_query_;
    std::vector<std::shared_ptr<query::Query>> refresh_queries_;

    // §15 event callback slots.
    NetworkChangeCallback on_network_change_;
    NetworkUpdateCallback on_network_update_;
    PersistentCallback    on_persistent_;

    // §15 libudx interface watcher. Polls `uv_interface_addresses()` and
    // fires `on_udx_interface_event` when the set changes. Heap-allocated
    // because `udx_interface_event_close` is async — the handle must
    // outlive its owner until the close callback fires.
    udx_interface_event_t* interface_watcher_ = nullptr;
    bool interface_watcher_active_ = false;

    // §16 validation cache for local addresses. Populated by
    // `validate_local_addresses()` — the `validated_host_cache_` maps
    // host string → bind result so repeated validations are O(1). The
    // `validated_local_addresses_` list is the cached result of running
    // validation once at bind() time across all available interfaces.
    std::unordered_map<std::string, bool> validated_host_cache_;
    std::vector<compact::Ipv4Address> validated_local_addresses_;

    void ensure_bound();
    void do_connect(const noise::PubKey& remote_pk,
                    const noise::Keypair& keypair,
                    const ConnectOptions& opts,
                    ConnectCallback on_done);

    // §2: one-shot background FIND_NODE(our_id) seeded from
    // opts_.bootstrap. Caller is bind(); see JS _bootstrap()/
    // _backgroundQuery() in dht-rpc/index.js:379-433, 965-979.
    void start_bootstrap_walk();

    // §15: event-hook internals.
    //
    // `fire_network_change`: runs the JS `_onnetworkchange` fan-out
    // (hyperdht/index.js:68-70) — refreshes every active server, then
    // fires the user's `on_network_change_` callback, then falls through
    // to `fire_network_update()` (JS emits both events in sequence).
    //
    // `fire_network_update`: runs the JS `_online/_degraded/_offline`
    // fan-out (hyperdht/index.js:72-75) — if `is_online()` returns true,
    // it pokes `notify_online()` on every listening server, then fires
    // the user's `on_network_update_` callback.
    //
    // `fire_persistent`: fires the user's `on_persistent_` callback (the
    // ephemeral → persistent transition is detected inside the RpcSocket
    // background tick and wired to us via `on_persistent` callback
    // registration in `bind()`).
    //
    // `start_interface_watcher` / `stop_interface_watcher`: lifecycle
    // helpers for the libudx interface event handle. Start is called
    // from `bind()` after the socket is up; stop is called from
    // `destroy()` before the RpcSocket is torn down.
    void fire_network_change();
    void fire_network_update();
    void fire_persistent();
    void start_interface_watcher();
    void stop_interface_watcher();
    static void on_udx_interface_event(udx_interface_event_t* handle, int status);
    static void on_udx_interface_close(udx_interface_event_t* handle);
};

}  // namespace hyperdht
