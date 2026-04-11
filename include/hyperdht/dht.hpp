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
#include <memory>
#include <optional>
#include <vector>

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
#include "hyperdht/server.hpp"
#include "hyperdht/socket_pool.hpp"

namespace hyperdht {

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
    // IMPORTANT: C++ does NOT automatically wrap the connected rawStream
    // in a `SecretStreamDuplex` — callers construct the Duplex themselves
    // (see `test/test_live_connect.cpp`). To match JS keep-alive behavior,
    // callers must read `HyperDHT::connection_keep_alive()` and pass it
    // to `SecretStreamDuplex::set_keep_alive()` after construction.
    //
    // Tracked as a §7 polish follow-up: auto-wrap clients in a Duplex
    // with the DHT's default keep-alive. See docs/JS-PARITY-GAPS.md.
    uint64_t connection_keep_alive = 5000;

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
};

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

    // --- Deferred JS options NOT exposed here ---
    //
    // The following JS `connect.js` options are intentionally absent from
    // this struct. Do NOT add them without first reading the deferred
    // section in docs/JS-PARITY-GAPS.md §6:
    //
    //  - `relayThrough` / `relayToken`: blind-relay fallback. Tied to §4
    //    (`FROM_SECOND_RELAY`) which is deliberately DEFERRED.
    //  - `relayKeepAlive`: keepalive on the blind-relay socket. Only used
    //    when `relayThrough` is active, so also deferred with §4.
    //  - `createSecretStream`: factory hook for a custom secret-stream
    //    wrapper. LOW priority — the C FFI doesn't expose this and C++
    //    callers construct `SecretStreamDuplex` over the returned
    //    `rawStream` directly.
    //  - `createHandshake`: factory hook for a custom Noise handshake.
    //    LOW priority — `peer_connect::peer_handshake` is called directly
    //    instead of going through a factory.
    //
    // (Note: `relay_addresses` ABOVE is the cached "which relays found this
    //  peer last time" hint, distinct from `relayThrough` blind-relay.)
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

    // Bind the UDP socket (called automatically by connect/listen if needed)
    int bind();

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

    // --- Connection Pool ---

    // Create a new connection pool (JS: dht.pool())
    connection_pool::ConnectionPool pool();

    // --- Lifecycle ---

    // Suspend: stop all servers, clear pending connects (JS: dht.suspend())
    void suspend();

    // Resume: resume all servers (JS: dht.resume())
    void resume();

    void destroy(std::function<void()> on_done = nullptr);
    bool is_destroyed() const { return destroyed_; }
    bool is_suspended() const { return suspended_; }
    bool is_connectable() const { return !suspended_ && !destroyed_; }

    // --- Accessors ---

    uv_loop_t* loop() const { return loop_; }
    rpc::RpcSocket& socket() { return *socket_; }
    router::Router& router() { return router_; }
    const noise::Keypair& default_keypair() const { return opts_.default_keypair; }
    uint16_t port() const { return socket_ ? socket_->port() : 0; }
    bool is_bound() const { return bound_; }

    // §7 accessors — read the tuning knobs that consumer apps may need
    // to apply to stream wrappers / connection setup.
    const std::string& host() const { return opts_.host; }
    uint64_t connection_keep_alive() const { return opts_.connection_keep_alive; }
    uint64_t random_punch_interval() const { return opts_.random_punch_interval; }
    bool defer_random_punch() const { return opts_.defer_random_punch; }
    size_t max_size() const { return opts_.max_size; }
    uint64_t max_age_ms() const { return opts_.max_age_ms; }
    uint64_t storage_ttl_ms() const { return opts_.storage_ttl_ms; }

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
    std::unique_ptr<socket_pool::SocketPool> socket_pool_;

    // Relay address cache for reconnect (JS: _relayAddressesCache)
    std::unordered_map<std::string, std::vector<compact::Ipv4Address>> relay_cache_;

    void ensure_bound();
    void do_connect(const noise::PubKey& remote_pk,
                    const noise::Keypair& keypair,
                    const ConnectOptions& opts,
                    ConnectCallback on_done);
};

}  // namespace hyperdht
