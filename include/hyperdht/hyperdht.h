#pragma once

/**
 * hyperdht-cpp — Public C API
 *
 * Opaque-pointer API for FFI bindings (Python, Go, Rust, Swift, Kotlin).
 * Follows the libuv callback pattern: every async operation takes a
 * callback + void* userdata.
 *
 * Usage:
 *   uv_loop_t loop;
 *   uv_loop_init(&loop);
 *
 *   hyperdht_t* dht = hyperdht_create(&loop, NULL);
 *   hyperdht_bind(dht, 0);
 *
 *   // Connect to a peer
 *   hyperdht_connect(dht, remote_pk, my_connect_cb, userdata);
 *
 *   // Listen for connections
 *   hyperdht_server_t* srv = hyperdht_server_create(dht);
 *   hyperdht_keypair_t kp;
 *   hyperdht_keypair_generate(&kp);
 *   hyperdht_server_listen(srv, &kp, my_connection_cb, userdata);
 *
 *   // Run event loop
 *   uv_run(&loop, UV_RUN_DEFAULT);
 *
 *   // Cleanup
 *   hyperdht_destroy(dht, NULL, NULL);
 *   uv_run(&loop, UV_RUN_DEFAULT);
 *   uv_loop_close(&loop);
 *
 * THREAD SAFETY:
 *   All functions must be called from the same thread that runs the
 *   uv_loop_t event loop. This library is single-threaded by design
 *   (matching libuv's concurrency model). Do not call any hyperdht_*
 *   function from a background thread.
 */

#include <stddef.h>
#include <stdint.h>

/* Forward-declare uv_loop_t to avoid requiring uv.h in consumer code */
struct uv_loop_s;
typedef struct uv_loop_s uv_loop_t;

/* Symbol visibility for shared library builds */
#if defined(HYPERDHT_SHARED) && defined(__GNUC__)
#define HYPERDHT_API __attribute__((visibility("default")))
#elif defined(HYPERDHT_SHARED) && defined(_MSC_VER)
#define HYPERDHT_API __declspec(dllexport)
#else
#define HYPERDHT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Opaque types
 * ========================================================================= */

typedef struct hyperdht_s hyperdht_t;
typedef struct hyperdht_server_s hyperdht_server_t;

/* =========================================================================
 * Data types
 * ========================================================================= */

/** Ed25519 keypair (public + secret key) */
typedef struct {
    uint8_t public_key[32];
    uint8_t secret_key[64];
} hyperdht_keypair_t;

/** Options for creating a HyperDHT instance */
typedef struct {
    uint16_t port;          /**< Bind port (0 = ephemeral) */
    int ephemeral;          /**< 1 = ephemeral node (default), 0 = persistent */

    /**
     * §2: auto-bootstrap against the 3 canonical public HyperDHT nodes
     * (88.99.3.86, 142.93.90.113, 138.68.147.8 — all on port 49737).
     *
     * 1 = run a one-shot FIND_NODE(our_id) walk at bind() time seeded
     *     from the public nodes. Populates the routing table with real
     *     peers so subsequent lookup/announce calls have something to
     *     walk from. Matches JS `new DHT()` default behaviour.
     *
     * 0 = skip the walk. Caller is responsible for populating the
     *     routing table some other way (pre-seeded `opts.nodes`,
     *     loopback test peers, etc.). This is the existing default and
     *     preserves offline-test behaviour.
     */
    int use_public_bootstrap;
} hyperdht_opts_t;

/** Connection info — passed to connect and server callbacks */
typedef struct {
    uint8_t remote_public_key[32];
    uint8_t tx_key[32];
    uint8_t rx_key[32];
    uint8_t handshake_hash[64];  /**< BLAKE2b-512 Noise handshake hash */
    uint32_t remote_udx_id;
    uint32_t local_udx_id;
    char peer_host[46];     /**< Peer IP address as string */
    uint16_t peer_port;
    int is_initiator;       /**< 1 if we initiated, 0 if we accepted */
    void* raw_stream;       /**< Pre-created UDX stream (server side), or NULL */
    void* udx_socket;       /**< Socket for UDX connect (from holepunch probe), or NULL */
    void* _internal;        /**< Opaque — do not touch. Pool socket keepalive. */
} hyperdht_connection_t;

/* =========================================================================
 * Callback types
 * ========================================================================= */

/** Called when connect() completes. error=0 on success. */
typedef void (*hyperdht_connect_cb)(int error,
                                     const hyperdht_connection_t* conn,
                                     void* userdata);

/** Called when a server accepts a connection. */
typedef void (*hyperdht_connection_cb)(const hyperdht_connection_t* conn,
                                        void* userdata);

/** Called when an async operation completes (destroy, close, etc.). */
typedef void (*hyperdht_close_cb)(void* userdata);

/** Firewall callback — return 0 to accept, non-zero to reject. */
typedef int (*hyperdht_firewall_cb)(const uint8_t remote_pk[32],
                                     const char* peer_host,
                                     uint16_t peer_port,
                                     void* userdata);

/* =========================================================================
 * Keypair
 * ========================================================================= */

/** Generate a random Ed25519 keypair. */
HYPERDHT_API void hyperdht_keypair_generate(hyperdht_keypair_t* out);

/** Generate a keypair from a 32-byte seed (deterministic). */
HYPERDHT_API void hyperdht_keypair_from_seed(hyperdht_keypair_t* out, const uint8_t seed[32]);

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/**
 * Create a HyperDHT instance. The caller owns the uv_loop_t.
 * @param loop    libuv event loop (must outlive the DHT instance)
 * @param opts    options (NULL for defaults: ephemeral, port=0)
 * @return        new instance, or NULL on failure
 */
HYPERDHT_API hyperdht_t* hyperdht_create(uv_loop_t* loop, const hyperdht_opts_t* opts);

/**
 * Bind the UDP socket. Called automatically by connect/listen if needed.
 * @param port    bind port (0 = ephemeral)
 * @return        0 on success, negative on error
 */
HYPERDHT_API int hyperdht_bind(hyperdht_t* dht, uint16_t port);

/** Get the bound port (0 if not bound). */
HYPERDHT_API uint16_t hyperdht_port(const hyperdht_t* dht);

/** Check if the instance has been destroyed. */
HYPERDHT_API int hyperdht_is_destroyed(const hyperdht_t* dht);

/**
 * Destroy the instance. All servers and connections are closed.
 * After calling this, you MUST:
 *   1. Call uv_run() to drain pending close callbacks
 *   2. Call hyperdht_free() to release memory
 * @param cb      optional callback when destruction starts
 * @param userdata passed to cb
 */
HYPERDHT_API void hyperdht_destroy(hyperdht_t* dht, hyperdht_close_cb cb, void* userdata);

/**
 * Free the handle memory. Call ONLY after uv_run() has drained all
 * pending close callbacks (after hyperdht_destroy).
 */
HYPERDHT_API void hyperdht_free(hyperdht_t* dht);

/** Get the default keypair (auto-generated on creation). */
HYPERDHT_API void hyperdht_default_keypair(const hyperdht_t* dht, hyperdht_keypair_t* out);

/* =========================================================================
 * Client: connect
 * ========================================================================= */

/**
 * Connect to a remote peer by public key.
 * Orchestrates: findPeer → handshake → holepunch → ready.
 * @param remote_pk   32-byte public key of the target
 * @param cb          called when connection succeeds or fails
 * @param userdata    passed to cb
 * @return            0 on success (async), negative on error
 */
HYPERDHT_API int hyperdht_connect(hyperdht_t* dht,
                     const uint8_t remote_pk[32],
                     hyperdht_connect_cb cb,
                     void* userdata);

/* =========================================================================
 * Server: listen
 * ========================================================================= */

/** Create a server instance. Owned by the HyperDHT instance. */
HYPERDHT_API hyperdht_server_t* hyperdht_server_create(hyperdht_t* dht);

/**
 * Start listening for connections.
 * The server announces itself on the DHT and accepts incoming connections.
 * @param kp      keypair to listen on
 * @param cb      called for each incoming connection
 * @param userdata passed to cb
 * @return         0 on success, negative on error
 */
HYPERDHT_API int hyperdht_server_listen(hyperdht_server_t* srv,
                           const hyperdht_keypair_t* kp,
                           hyperdht_connection_cb cb,
                           void* userdata);

/**
 * Set a firewall callback to accept/reject connections.
 * Called before the Noise handshake completes.
 */
HYPERDHT_API void hyperdht_server_set_firewall(hyperdht_server_t* srv,
                                   hyperdht_firewall_cb cb,
                                   void* userdata);

/** Stop listening and unannounce. */
HYPERDHT_API void hyperdht_server_close(hyperdht_server_t* srv,
                           hyperdht_close_cb cb,
                           void* userdata);

/** Trigger a re-announcement (useful after network changes). */
HYPERDHT_API void hyperdht_server_refresh(hyperdht_server_t* srv);

/* =========================================================================
 * DHT operations: mutable/immutable storage
 * ========================================================================= */

/** Callback for immutable get — called with value or NULL if not found. */
typedef void (*hyperdht_value_cb)(const uint8_t* value, size_t len,
                                   void* userdata);

/** Callback for mutable get — called with value, seq, signature. */
typedef void (*hyperdht_mutable_cb)(uint64_t seq,
                                     const uint8_t* value, size_t len,
                                     const uint8_t signature[64],
                                     void* userdata);

/** Callback for put operations — called when complete. */
typedef void (*hyperdht_done_cb)(int error, void* userdata);

/**
 * Store an immutable value on the DHT (target = BLAKE2b(value)).
 * @return 0 on success (async), negative on error
 */
HYPERDHT_API int hyperdht_immutable_put(hyperdht_t* dht,
                           const uint8_t* value, size_t len,
                           hyperdht_done_cb cb, void* userdata);

/**
 * Retrieve an immutable value by its content hash.
 * @param target   32-byte BLAKE2b hash of the value
 * @param cb       called for each verified result
 * @param done_cb  called when query completes
 * @return 0 on success (async), negative on error
 */
HYPERDHT_API int hyperdht_immutable_get(hyperdht_t* dht,
                           const uint8_t target[32],
                           hyperdht_value_cb cb,
                           hyperdht_done_cb done_cb,
                           void* userdata);

/**
 * Store a signed mutable value on the DHT (target = BLAKE2b(publicKey)).
 * @param kp      keypair (signs the value)
 * @param value   data to store
 * @param seq     sequence number (must increase for updates)
 * @return 0 on success (async), negative on error
 */
HYPERDHT_API int hyperdht_mutable_put(hyperdht_t* dht,
                         const hyperdht_keypair_t* kp,
                         const uint8_t* value, size_t len,
                         uint64_t seq,
                         hyperdht_done_cb cb, void* userdata);

/**
 * Retrieve the latest signed mutable value for a public key.
 * @param public_key  32-byte public key
 * @param min_seq     minimum sequence number to accept (0 = any)
 * @param cb          called for each verified result
 * @param done_cb     called when query completes
 * @return 0 on success (async), negative on error
 */
HYPERDHT_API int hyperdht_mutable_get(hyperdht_t* dht,
                         const uint8_t public_key[32],
                         uint64_t min_seq,
                         hyperdht_mutable_cb cb,
                         hyperdht_done_cb done_cb,
                         void* userdata);

/* =========================================================================
 * Encrypted streams — read/write over established connections
 * ========================================================================= */

typedef struct hyperdht_stream_s hyperdht_stream_t;

/** Called when data is received on the stream. */
typedef void (*hyperdht_data_cb)(const uint8_t* data, size_t len, void* userdata);

/**
 * Create an encrypted stream from an established connection.
 * Handles UDX stream setup + SecretStream header exchange automatically.
 * The stream is ready for read/write after on_open fires.
 *
 * @param dht     the HyperDHT instance that owns the connection
 * @param conn    connection info from connect or server callback
 * @param on_open called when the stream is ready (header exchange complete)
 * @param on_data called when encrypted data is received
 * @param on_close called when the stream closes
 * @param userdata passed to all callbacks
 * @return stream handle, or NULL on failure
 */
HYPERDHT_API hyperdht_stream_t* hyperdht_stream_open(
    hyperdht_t* dht,
    const hyperdht_connection_t* conn,
    hyperdht_close_cb on_open,
    hyperdht_data_cb on_data,
    hyperdht_close_cb on_close,
    void* userdata);

/**
 * Write data to the encrypted stream. Data is encrypted with SecretStream
 * (XChaCha20-Poly1305) before sending over UDX.
 *
 * @return 0 on success, negative on error
 */
HYPERDHT_API int hyperdht_stream_write(hyperdht_stream_t* stream,
                          const uint8_t* data, size_t len);

/**
 * Close the stream. Sends end-of-stream and triggers on_close.
 */
HYPERDHT_API void hyperdht_stream_close(hyperdht_stream_t* stream);

/**
 * Check if the stream has completed the header exchange and is ready.
 */
HYPERDHT_API int hyperdht_stream_is_open(const hyperdht_stream_t* stream);

/* =========================================================================
 * Phase C: Extended API (2026-04-14)
 * ========================================================================= */

/* --- C9: Constants --- */
#define HYPERDHT_FIREWALL_UNKNOWN    0
#define HYPERDHT_FIREWALL_OPEN       1
#define HYPERDHT_FIREWALL_CONSISTENT 2
#define HYPERDHT_FIREWALL_RANDOM     3

/* Connect error codes (JS: hyperdht/lib/errors.js) */
#define HYPERDHT_OK                      0
#define HYPERDHT_ERR_DESTROYED          (-1)
#define HYPERDHT_ERR_PEER_NOT_FOUND     (-2)
#define HYPERDHT_ERR_CONNECTION_FAILED  (-3)
#define HYPERDHT_ERR_NO_ADDRESSES       (-4)
#define HYPERDHT_ERR_HOLEPUNCH_FAILED   (-5)
#define HYPERDHT_ERR_HOLEPUNCH_TIMEOUT  (-6)
#define HYPERDHT_ERR_RELAY_FAILED       (-7)

/* --- C2: DHT state --- */

HYPERDHT_API int hyperdht_is_online(const hyperdht_t* dht);
HYPERDHT_API int hyperdht_is_degraded(const hyperdht_t* dht);
HYPERDHT_API int hyperdht_is_persistent(const hyperdht_t* dht);
HYPERDHT_API int hyperdht_is_bootstrapped(const hyperdht_t* dht);
HYPERDHT_API int hyperdht_is_suspended(const hyperdht_t* dht);

/* --- C3: DHT event hooks --- */

typedef void (*hyperdht_event_cb)(void* userdata);

HYPERDHT_API void hyperdht_on_bootstrapped(hyperdht_t* dht,
                                            hyperdht_event_cb cb, void* userdata);
HYPERDHT_API void hyperdht_on_network_change(hyperdht_t* dht,
                                              hyperdht_event_cb cb, void* userdata);
HYPERDHT_API void hyperdht_on_network_update(hyperdht_t* dht,
                                              hyperdht_event_cb cb, void* userdata);
HYPERDHT_API void hyperdht_on_persistent(hyperdht_t* dht,
                                          hyperdht_event_cb cb, void* userdata);

/* --- C4: DHT query operations --- */

/** Callback for find_peer/lookup per-reply results */
typedef void (*hyperdht_peer_cb)(const uint8_t* value, size_t len,
                                  const char* from_host, uint16_t from_port,
                                  void* userdata);

HYPERDHT_API int hyperdht_find_peer(hyperdht_t* dht,
                                     const uint8_t public_key[32],
                                     hyperdht_peer_cb on_reply,
                                     hyperdht_done_cb on_done,
                                     void* userdata);

HYPERDHT_API int hyperdht_lookup(hyperdht_t* dht,
                                  const uint8_t target[32],
                                  hyperdht_peer_cb on_reply,
                                  hyperdht_done_cb on_done,
                                  void* userdata);

HYPERDHT_API int hyperdht_announce(hyperdht_t* dht,
                                    const uint8_t target[32],
                                    const uint8_t* value, size_t value_len,
                                    hyperdht_done_cb on_done,
                                    void* userdata);

HYPERDHT_API int hyperdht_unannounce(hyperdht_t* dht,
                                      const uint8_t public_key[32],
                                      const hyperdht_keypair_t* kp,
                                      hyperdht_done_cb on_done,
                                      void* userdata);

/* --- C5: DHT lifecycle --- */

HYPERDHT_API void hyperdht_suspend(hyperdht_t* dht);
HYPERDHT_API void hyperdht_resume(hyperdht_t* dht);

/* --- C6: DHT misc --- */

/** BLAKE2b-256 hash of arbitrary data */
HYPERDHT_API void hyperdht_hash(const uint8_t* data, size_t len,
                                 uint8_t out[32]);

/** Get connection keep-alive setting (ms) */
HYPERDHT_API uint64_t hyperdht_connection_keep_alive(const hyperdht_t* dht);

/* --- C7: Server state --- */

HYPERDHT_API void hyperdht_server_suspend(hyperdht_server_t* srv);
HYPERDHT_API void hyperdht_server_resume(hyperdht_server_t* srv);
HYPERDHT_API void hyperdht_server_notify_online(hyperdht_server_t* srv);
HYPERDHT_API int  hyperdht_server_is_listening(const hyperdht_server_t* srv);

/** Get server's public key. Returns 0 on success, -1 if not listening. */
HYPERDHT_API int  hyperdht_server_public_key(const hyperdht_server_t* srv,
                                              uint8_t out[32]);

/* --- C8: Server config --- */

/** Holepunch veto callback. Return 0 to allow, non-zero to reject.
 *  Args: remote_fw, local_fw, remote_addr_count, local_addr_count */
typedef int (*hyperdht_holepunch_cb)(uint32_t remote_fw, uint32_t local_fw,
                                      int remote_addr_count, int local_addr_count,
                                      void* userdata);

HYPERDHT_API void hyperdht_server_set_holepunch(hyperdht_server_t* srv,
                                                 hyperdht_holepunch_cb cb,
                                                 void* userdata);

/* ── Phase E: Blind Relay ─────────────────────────────────────────────── */

/** Set relay-through public key on a server (enables blind relay fallback).
 *  relay_pk: 32-byte public key of the relay node, or NULL to disable.
 *  keep_alive_ms: keep-alive for relay connection (default 5000). */
HYPERDHT_API void hyperdht_server_set_relay_through(hyperdht_server_t* srv,
                                                     const uint8_t* relay_pk,
                                                     uint64_t keep_alive_ms);

/** Connect with relay-through option.
 *  relay_pk: 32-byte public key of relay node, or NULL (no relay).
 *  relay_keep_alive_ms: keep-alive for relay socket (default 5000). */
HYPERDHT_API void hyperdht_connect_relay(hyperdht_t* dht,
                                          const uint8_t* remote_pk,
                                          const uint8_t* relay_pk,
                                          uint64_t relay_keep_alive_ms,
                                          hyperdht_connect_cb cb,
                                          void* userdata);

/** Get relay stats. */
HYPERDHT_API int hyperdht_relay_stats_attempts(hyperdht_t* dht);
HYPERDHT_API int hyperdht_relay_stats_successes(hyperdht_t* dht);
HYPERDHT_API int hyperdht_relay_stats_aborts(hyperdht_t* dht);

#ifdef __cplusplus
}
#endif
