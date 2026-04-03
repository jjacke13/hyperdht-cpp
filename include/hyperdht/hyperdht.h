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
void hyperdht_keypair_generate(hyperdht_keypair_t* out);

/** Generate a keypair from a 32-byte seed (deterministic). */
void hyperdht_keypair_from_seed(hyperdht_keypair_t* out, const uint8_t seed[32]);

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/**
 * Create a HyperDHT instance. The caller owns the uv_loop_t.
 * @param loop    libuv event loop (must outlive the DHT instance)
 * @param opts    options (NULL for defaults: ephemeral, port=0)
 * @return        new instance, or NULL on failure
 */
hyperdht_t* hyperdht_create(uv_loop_t* loop, const hyperdht_opts_t* opts);

/**
 * Bind the UDP socket. Called automatically by connect/listen if needed.
 * @param port    bind port (0 = ephemeral)
 * @return        0 on success, negative on error
 */
int hyperdht_bind(hyperdht_t* dht, uint16_t port);

/** Get the bound port (0 if not bound). */
uint16_t hyperdht_port(const hyperdht_t* dht);

/** Check if the instance has been destroyed. */
int hyperdht_is_destroyed(const hyperdht_t* dht);

/**
 * Destroy the instance. All servers and connections are closed.
 * Call uv_run() after this to drain pending close callbacks.
 * @param cb      optional callback when destruction is complete
 * @param userdata passed to cb
 */
void hyperdht_destroy(hyperdht_t* dht, hyperdht_close_cb cb, void* userdata);

/** Get the default keypair (auto-generated on creation). */
void hyperdht_default_keypair(const hyperdht_t* dht, hyperdht_keypair_t* out);

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
int hyperdht_connect(hyperdht_t* dht,
                     const uint8_t remote_pk[32],
                     hyperdht_connect_cb cb,
                     void* userdata);

/* =========================================================================
 * Server: listen
 * ========================================================================= */

/** Create a server instance. Owned by the HyperDHT instance. */
hyperdht_server_t* hyperdht_server_create(hyperdht_t* dht);

/**
 * Start listening for connections.
 * The server announces itself on the DHT and accepts incoming connections.
 * @param kp      keypair to listen on
 * @param cb      called for each incoming connection
 * @param userdata passed to cb
 * @return         0 on success, negative on error
 */
int hyperdht_server_listen(hyperdht_server_t* srv,
                           const hyperdht_keypair_t* kp,
                           hyperdht_connection_cb cb,
                           void* userdata);

/**
 * Set a firewall callback to accept/reject connections.
 * Called before the Noise handshake completes.
 */
void hyperdht_server_set_firewall(hyperdht_server_t* srv,
                                   hyperdht_firewall_cb cb,
                                   void* userdata);

/** Stop listening and unannounce. */
void hyperdht_server_close(hyperdht_server_t* srv,
                           hyperdht_close_cb cb,
                           void* userdata);

/** Trigger a re-announcement (useful after network changes). */
void hyperdht_server_refresh(hyperdht_server_t* srv);

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
int hyperdht_immutable_put(hyperdht_t* dht,
                           const uint8_t* value, size_t len,
                           hyperdht_done_cb cb, void* userdata);

/**
 * Retrieve an immutable value by its content hash.
 * @param target   32-byte BLAKE2b hash of the value
 * @param cb       called for each verified result
 * @param done_cb  called when query completes
 * @return 0 on success (async), negative on error
 */
int hyperdht_immutable_get(hyperdht_t* dht,
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
int hyperdht_mutable_put(hyperdht_t* dht,
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
int hyperdht_mutable_get(hyperdht_t* dht,
                         const uint8_t public_key[32],
                         uint64_t min_seq,
                         hyperdht_mutable_cb cb,
                         hyperdht_done_cb done_cb,
                         void* userdata);

#ifdef __cplusplus
}
#endif
