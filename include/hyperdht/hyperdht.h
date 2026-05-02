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
 *
 *   Exceptions: NONE. Even `hyperdht_firewall_done()` — which exists
 *   to complete a user's async policy check — must ultimately be
 *   called from the loop thread. If your ACL/DB lookup runs on a
 *   worker thread, marshal the completion back to the loop thread
 *   via `uv_async_send()` before invoking `hyperdht_firewall_done()`.
 */

/**
 * Size of an Ed25519 public key in bytes. Exposed as a #define so
 * FFI consumers (ctypes, JNI, Swift) can allocate fixed-size buffers
 * without hard-coding the magic number.
 */
#define HYPERDHT_PK_SIZE 32

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

/** Opaque query handle — see `hyperdht_query_cancel()`. */
typedef struct hyperdht_query_s hyperdht_query_t;

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

    /**
     * Default keep-alive (ms) applied to `SecretStreamDuplex` instances
     * constructed via `dht.make_duplex_options()` (and therefore to every
     * stream opened through the Python / future-binding wrappers).
     *
     * Mirrors JS `new DHT({ connectionKeepAlive })`:
     *   - any positive value (ms) → sent as keep-alive ping interval
     *   - 0                       → disabled (same as JS `false`)
     *   - UINT64_MAX              → "unset", use the C++ default (5000ms)
     *
     * NOTE: The sentinel is UINT64_MAX rather than 0 so that callers can
     * *explicitly* disable keep-alive by passing 0. `= {0}` initializers
     * would otherwise silently disable it.
     */
    uint64_t connection_keep_alive;

    /**
     * Optional 32-byte seed for deterministic default keypair derivation.
     * When non-zero (i.e. not all zeros), the DHT's default keypair is
     * derived from this seed. Useful for mobile apps that want a stable
     * identity across app launches without persisting a full secret key.
     *
     * If `seed_is_set` is 0, this field is ignored and a random keypair
     * is generated (or the caller's pre-populated one is used). Because
     * a zeroed seed is technically a valid seed, we require an explicit
     * flag rather than treating all-zeros as "unset".
     */
    uint8_t seed[32];
    int seed_is_set;

    /**
     * Explicit padding to pin struct layout under all ABIs. On 64-bit
     * platforms `int` is 4 bytes; the next field (`host*`) is 8-byte
     * aligned, so the compiler inserts 4 bytes of padding here
     * implicitly. Pinning it explicitly means Python ctypes /
     * Kotlin @CStruct / Swift struct mirrors can declare the layout
     * without platform-specific padding calculations.
     */
    uint32_t _pad0;

    /**
     * Optional bind host (interface). `NULL` or empty string → 0.0.0.0.
     * Pointer is only borrowed during `hyperdht_create()` — the caller
     * owns the string buffer.
     */
    const char* host;

    /**
     * Optional explicit bootstrap nodes. Overrides `use_public_bootstrap`
     * when set. Accepts an array of `nodes_len` {host,port} pairs, each
     * as a null-terminated string of the form "host:port".
     *
     *   const char* nodes[] = {"10.0.0.1:49737", "10.0.0.2:49737"};
     *   opts.nodes = nodes;
     *   opts.nodes_len = 2;
     *
     * Pointers are only borrowed during `hyperdht_create()`.
     *
     * Precedence: `nodes` > `use_public_bootstrap`. If BOTH are set,
     * `nodes` wins (explicit list beats canonical defaults).
     */
    const char* const* nodes;
    size_t nodes_len;
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

/** Zero the secret key material in a keypair. Call when the keypair is no
 *  longer needed to prevent secret key recovery from process memory. */
HYPERDHT_API void hyperdht_keypair_zero(hyperdht_keypair_t* kp);

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/**
 * Initialise `hyperdht_opts_t` with safe defaults (ephemeral, port=0,
 * no bootstrap, keep-alive=unset). Strongly recommended: always call
 * this before setting fields, so that new fields added in future C FFI
 * versions pick up their sentinel values rather than stack garbage.
 *
 *     hyperdht_opts_t opts;
 *     hyperdht_opts_default(&opts);
 *     opts.port = 49737;
 */
HYPERDHT_API void hyperdht_opts_default(hyperdht_opts_t* opts);

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
 *
 * BLOCKING: This function and the subsequent uv_run() drain may block
 * for several seconds while libuv close callbacks complete. On mobile
 * platforms (Android/iOS), never call this from the UI/main thread —
 * it will freeze the screen. Use a background thread or dispatch queue.
 *
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
 * Full connect options. Pass to `hyperdht_connect_ex()` for fine-grained
 * control over the outgoing connection. Mirrors C++ `ConnectOptions`.
 *
 * Always call `hyperdht_connect_opts_default()` first — new fields may
 * be added to the tail of this struct in future versions, and the
 * default helper zero-inits them to their sentinel values.
 */
typedef struct {
    /**
     * Use a specific keypair for THIS connection (identity rotation,
     * multi-account apps). NULL → use the DHT's default keypair.
     */
    const hyperdht_keypair_t* keypair;

    /**
     * Public key of a blind-relay node (32 bytes). When set, the server
     * also receives the relay hint so both sides can dial the same
     * relay as a holepunch-failure fallback. NULL → no relay.
     */
    const uint8_t* relay_through;

    /** Keep-alive interval for the relay stream (ms). 0 → library default (5000). */
    uint64_t relay_keep_alive_ms;

    /**
     * Fast-open optimization (JS parity). When enabled, the client sends
     * its first holepunch probe before the server has fully replied,
     * shaving ~1 RTT. Pass 0 to opt out, 1 to enable (default).
     */
    int fast_open;

    /**
     * Same-NAT LAN shortcut (JS parity). When enabled (default), the
     * client tries the server's advertised private addresses before
     * falling back to holepunch. Pass 0 to skip the LAN path.
     */
    int local_connection;
} hyperdht_connect_opts_t;

/** Initialise `hyperdht_connect_opts_t` with library defaults. */
HYPERDHT_API void hyperdht_connect_opts_default(hyperdht_connect_opts_t* opts);

/**
 * Connect with full options. `opts == NULL` behaves identically to
 * `hyperdht_connect()`.
 */
HYPERDHT_API int hyperdht_connect_ex(hyperdht_t* dht,
                                      const uint8_t remote_pk[32],
                                      const hyperdht_connect_opts_t* opts,
                                      hyperdht_connect_cb cb,
                                      void* userdata);

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

/** Cancelable variant of `hyperdht_immutable_get`.
 *  Returns a handle usable with `hyperdht_query_cancel()`. */
HYPERDHT_API hyperdht_query_t* hyperdht_immutable_get_ex(hyperdht_t* dht,
                                                         const uint8_t target[32],
                                                         hyperdht_value_cb cb,
                                                         hyperdht_done_cb done_cb,
                                                         void* userdata);

/** Cancelable variant of `hyperdht_mutable_get`.
 *  Returns a handle usable with `hyperdht_query_cancel()`. */
HYPERDHT_API hyperdht_query_t* hyperdht_mutable_get_ex(hyperdht_t* dht,
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
 * Callback fired when UDX acknowledges the write (drain).
 * Signals that the stream is ready for more data after backpressure.
 */
typedef void (*hyperdht_drain_cb)(hyperdht_stream_t* stream, void* userdata);

/**
 * Write data with a drain callback. Like hyperdht_stream_write but fires
 * on_drain when the underlying UDX transport acknowledges the data.
 * Use this for flow control: if write returns 0 (backpressure), wait for
 * the drain callback before writing more.
 *
 * @return 0 on success, negative on error
 */
HYPERDHT_API int hyperdht_stream_write_with_drain(
    hyperdht_stream_t* stream,
    const uint8_t* data, size_t len,
    hyperdht_drain_cb on_drain, void* userdata);

/**
 * Close the stream. Sends end-of-stream and triggers on_close.
 */
HYPERDHT_API void hyperdht_stream_close(hyperdht_stream_t* stream);

/**
 * Check if the stream has completed the header exchange and is ready.
 */
HYPERDHT_API int hyperdht_stream_is_open(const hyperdht_stream_t* stream);

/**
 * Unordered, unreliable encrypted datagrams over the same SecretStream
 * keys as the reliable stream. Mirrors `SecretStreamDuplex::send_udp`
 * and `on_udp_message` (see `secret_stream.hpp`). The transport is
 * UDX's `send`/`recv` channel — bypasses the reliable byte stream, so
 * messages may be dropped, duplicated, or arrive out of order. Each
 * call writes one secretbox-sealed envelope; payloads should fit in a
 * single UDP datagram (~1200 bytes after framing overhead).
 *
 * Receive-side ordering: `cb` may fire only after the caller has
 * installed it AND the underlying handshake is done (i.e. `on_open`
 * has fired). Datagrams that arrive before either condition is met
 * are dropped silently.
 */
typedef void (*hyperdht_udp_msg_cb)(const uint8_t* data,
                                    size_t len,
                                    void* userdata);

/**
 * Install / replace the UDP-message receive callback. Pass `cb=NULL`
 * to detach. Returns 0 on success, negative on error.
 *
 * Must be called from the loop thread (same thread that owns the DHT).
 */
HYPERDHT_API int hyperdht_stream_set_on_udp_message(
    hyperdht_stream_t* stream,
    hyperdht_udp_msg_cb cb,
    void* userdata);

/**
 * Send an unordered encrypted datagram. Returns 0 on submission
 * success, negative on error (closed stream, send-state not ready,
 * UDX backpressure). Equivalent to JS `stream.send(buf)`.
 */
HYPERDHT_API int hyperdht_stream_send_udp(
    hyperdht_stream_t* stream,
    const uint8_t* data,
    size_t len);

/**
 * Fire-and-forget variant — never blocks, drops on send-buffer
 * pressure rather than reporting it. Equivalent to JS
 * `stream.trySend(buf)`. Returns 0 on submission success.
 */
HYPERDHT_API int hyperdht_stream_try_send_udp(
    hyperdht_stream_t* stream,
    const uint8_t* data,
    size_t len);

/**
 * Connect and open a stream atomically. Combines hyperdht_connect +
 * hyperdht_stream_open so the stream is opened inside the connect
 * callback while the connection struct is still alive. Avoids the
 * dangling-pointer race that occurs when stream_open is called after
 * the connect callback returns.
 */
typedef void (*hyperdht_connect_stream_cb)(int error,
                                            hyperdht_stream_t* stream,
                                            void* userdata);

HYPERDHT_API int hyperdht_connect_and_open_stream(
    hyperdht_t* dht,
    const uint8_t remote_pk[32],
    hyperdht_connect_stream_cb on_connect,
    hyperdht_close_cb on_open,
    hyperdht_data_cb on_data,
    hyperdht_close_cb on_close,
    void* userdata);

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
#define HYPERDHT_ERR_CANCELLED          (-8)

/** Return a human-readable name for a connect error code. */
HYPERDHT_API const char* hyperdht_connect_strerror(int error);

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

/**
 * Query handle lifetime (two-call ownership):
 *
 *   1. Obtained from an `_ex` variant (find_peer_ex, lookup_ex,
 *      immutable_get_ex, mutable_get_ex).
 *   2. Valid until the user calls `hyperdht_query_free()`.
 *
 * `on_done` fires exactly once per query (natural completion OR
 * cancel). The handle REMAINS VALID after `on_done` — you still
 * need to call `hyperdht_query_free()` to release it. This is the
 * same pattern as `hyperdht_create()`/`hyperdht_free()`.
 *
 * All three operations (cancel, free, and late completion via the
 * lambda) are safe to interleave in any order:
 *
 *   - `cancel` + `free`  → callback fires with HYPERDHT_ERR_CANCELLED,
 *                          then handle is released.
 *   - `free` + natural completion → callback is detached at free time,
 *                          late completion silently no-ops.
 *   - `cancel` + `cancel` → second call is a no-op (idempotent).
 *   - `free` + `cancel`  → cancel on a freed handle is UB (you must
 *                          not use the pointer after free, same rule
 *                          as any C handle).
 */

/**
 * Cancel an in-flight query. Idempotent — safe to call any number of
 * times as long as the handle has not been freed. A cancel after the
 * query has already completed naturally is a silent no-op.
 */
HYPERDHT_API void hyperdht_query_cancel(hyperdht_query_t* q);

/**
 * Release the query handle. Must be called exactly once per `_ex`
 * call, AFTER the done callback has fired OR after `hyperdht_query_cancel()`.
 * Safe to call from inside the done callback itself.
 *
 * If free is called BEFORE the query completes, the completion
 * callback is detached — the query will still finish internally but
 * the user's `done_cb` will not fire. Useful for abandon-don't-wait
 * patterns.
 */
HYPERDHT_API void hyperdht_query_free(hyperdht_query_t* q);

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

/** Cancelable variants — return a query handle that can be passed to
 *  `hyperdht_query_cancel()`. The handle is invalidated when `on_done`
 *  fires; do not dereference it after that. Returns NULL on immediate
 *  error (bad inputs). */
HYPERDHT_API hyperdht_query_t* hyperdht_find_peer_ex(hyperdht_t* dht,
                                                      const uint8_t public_key[32],
                                                      hyperdht_peer_cb on_reply,
                                                      hyperdht_done_cb on_done,
                                                      void* userdata);

HYPERDHT_API hyperdht_query_t* hyperdht_lookup_ex(hyperdht_t* dht,
                                                   const uint8_t target[32],
                                                   hyperdht_peer_cb on_reply,
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

/**
 * Log callback for suspend/resume. Each phase transition produces a
 * `const char*` message, matching JS `dht.suspend({ log })`:
 *   "Suspending all hyperdht servers"
 *   "Done, clearing all raw streams"
 *   "Done, suspending dht-rpc"
 *   "Done, clearing raw streams again"
 *   "Done, hyperdht fully suspended"
 *
 * Mobile apps use this to show a progress UI during background
 * transitions. Passing a NULL callback is equivalent to the silent
 * `hyperdht_suspend`/`hyperdht_resume`.
 */
typedef void (*hyperdht_log_cb)(const char* msg, void* userdata);

HYPERDHT_API void hyperdht_suspend_logged(hyperdht_t* dht,
                                          hyperdht_log_cb log_cb,
                                          void* userdata);
HYPERDHT_API void hyperdht_resume_logged(hyperdht_t* dht,
                                         hyperdht_log_cb log_cb,
                                         void* userdata);

/**
 * Force-destroy — skips `UNANNOUNCE` emission on each server. Use when
 * the process is about to exit anyway (SIGTERM handler, crash path) and
 * spending a round-trip to the network isn't worth the delay. Matches
 * JS `dht.destroy({ force: true })`.
 *
 * Otherwise identical to `hyperdht_destroy` — caller still needs to
 * run the event loop to drain close callbacks, then call `hyperdht_free`.
 */
HYPERDHT_API void hyperdht_destroy_force(hyperdht_t* dht,
                                         hyperdht_close_cb cb,
                                         void* userdata);

/**
 * Force-close a server — like `hyperdht_server_close` but skips the
 * announcer's `UNANNOUNCE` emission. Timers and handles are still
 * torn down so the event loop can drain.
 */
HYPERDHT_API void hyperdht_server_close_force(hyperdht_server_t* srv,
                                              hyperdht_close_cb cb,
                                              void* userdata);

/** Server-level suspend with log (mirrors JS `server.suspend({ log })`). */
HYPERDHT_API void hyperdht_server_suspend_logged(hyperdht_server_t* srv,
                                                 hyperdht_log_cb log_cb,
                                                 void* userdata);

/* --- C6: DHT misc --- */

/** BLAKE2b-256 hash of arbitrary data */
HYPERDHT_API void hyperdht_hash(const uint8_t* data, size_t len,
                                 uint8_t out[32]);

/** Get connection keep-alive setting (ms) */
HYPERDHT_API uint64_t hyperdht_connection_keep_alive(const hyperdht_t* dht);

/**
 * Fixed stride of the `hosts_flat` buffer in `hyperdht_to_array`.
 * Each entry occupies `HYPERDHT_HOST_STRIDE` bytes, null-terminated
 * IPv4 dotted-quad string (e.g. "192.168.1.1\0...").
 */
#define HYPERDHT_HOST_STRIDE 46

/**
 * Snapshot the routing table — writes up to `cap` `{host, port}` pairs
 * into the caller-provided output buffers. Returns the number of
 * entries actually written.
 *
 * Intended use: mobile app going to background → snapshot the table,
 * persist to disk, restore via `hyperdht_add_node()` on next launch.
 * This lets the DHT skip a cold bootstrap walk.
 *
 * `hosts_flat` is a flat buffer of `cap * HYPERDHT_HOST_STRIDE` bytes.
 * Entry `i` lives at `hosts_flat + i * HYPERDHT_HOST_STRIDE`, as a
 * null-terminated string. This flat layout is FFI-friendly — maps
 * directly onto Python `ctypes.c_char * (cap * 46)`, Java/Kotlin
 * `ByteBuffer`, and Swift `UnsafeMutablePointer<CChar>`.
 *
 * @param dht         DHT instance
 * @param hosts_flat  [out] at least `cap * HYPERDHT_HOST_STRIDE` bytes
 * @param ports       [out] `cap` uint16_t entries
 * @param cap         size of both output arrays (in entries)
 * @return number of entries written (≤ cap)
 */
HYPERDHT_API size_t hyperdht_to_array(const hyperdht_t* dht,
                                       char* hosts_flat,
                                       uint16_t* ports,
                                       size_t cap);

/**
 * Add a node to the routing table at runtime. Used by persistence
 * restores (saved-table → add_node each entry on startup). Matches JS
 * `dht.addNode({host, port})`.
 *
 * @return 0 on success, negative on error (invalid host string, etc.)
 */
HYPERDHT_API int hyperdht_add_node(hyperdht_t* dht,
                                   const char* host, uint16_t port);

/**
 * Fill `out_host` (null-terminated) and `*out_port` with the DHT's
 * public address as seen by the network (via NAT sampling).
 *
 * @param out_host  receives null-terminated IPv4 host, caller-provided
 *                  buffer of at least 46 bytes
 * @param out_port  receives the port
 * @return 0 on success, -1 if the address is not yet known (firewalled,
 *         no samples, or sampled port != bound port — JS parity)
 */
HYPERDHT_API int hyperdht_remote_address(const hyperdht_t* dht,
                                          char out_host[46],
                                          uint16_t* out_port);

/* --- C7: Server state --- */

HYPERDHT_API void hyperdht_server_suspend(hyperdht_server_t* srv);
HYPERDHT_API void hyperdht_server_resume(hyperdht_server_t* srv);
HYPERDHT_API void hyperdht_server_notify_online(hyperdht_server_t* srv);
HYPERDHT_API int  hyperdht_server_is_listening(const hyperdht_server_t* srv);

/** Get server's public key. Returns 0 on success, -1 if not listening. */
HYPERDHT_API int  hyperdht_server_public_key(const hyperdht_server_t* srv,
                                              uint8_t out[32]);

/**
 * Install a 'listening' event callback — fires ONCE after the announcer
 * finishes its first cycle, when the server is fully ready to accept
 * peers. JS parity: `server.on('listening', ...)` at server.js:195.
 *
 * A later `close() + listen()` cycle re-arms the hook.
 */
HYPERDHT_API void hyperdht_server_on_listening(hyperdht_server_t* srv,
                                                hyperdht_event_cb cb,
                                                void* userdata);

/**
 * Fill `out_host` + `*out_port` with the server's listening address
 * (public address from NAT sampler). Returns 0 on success, -1 if not
 * listening or address not yet known.
 */
HYPERDHT_API int hyperdht_server_address(const hyperdht_server_t* srv,
                                          char out_host[46],
                                          uint16_t* out_port);

/* --- C8: Server config --- */

/** Holepunch veto callback. Return 0 to allow, non-zero to reject.
 *  Args: remote_fw, local_fw, remote_addr_count, local_addr_count */
typedef int (*hyperdht_holepunch_cb)(uint32_t remote_fw, uint32_t local_fw,
                                      int remote_addr_count, int local_addr_count,
                                      void* userdata);

HYPERDHT_API void hyperdht_server_set_holepunch(hyperdht_server_t* srv,
                                                 hyperdht_holepunch_cb cb,
                                                 void* userdata);

/**
 * Async firewall callback. Receives a completion handle the user must
 * invoke EXACTLY once with the accept/reject decision:
 *
 *   int accept = 0;  // reject = 0 accepts, 1 rejects
 *   hyperdht_firewall_done(done, accept);
 *
 * Mobile/server use case: the callback kicks off a DB lookup, ACL
 * check, or remote policy decision, and calls `hyperdht_firewall_done`
 * when the result arrives. The handshake response is deferred until
 * then — mirrors JS `await this.firewall(...)`.
 *
 * Sync and async setters are mutually exclusive; installing one
 * clears the other.
 */
typedef struct hyperdht_firewall_done_s hyperdht_firewall_done_t;

typedef void (*hyperdht_firewall_async_cb)(const uint8_t remote_pk[32],
                                            const char* peer_host,
                                            uint16_t peer_port,
                                            hyperdht_firewall_done_t* done,
                                            void* userdata);

/** Complete the async firewall check. `reject != 0` rejects the peer.
 *  Safe to call at most once per callback invocation. */
HYPERDHT_API void hyperdht_firewall_done(hyperdht_firewall_done_t* done,
                                          int reject);

HYPERDHT_API void hyperdht_server_set_firewall_async(hyperdht_server_t* srv,
                                                      hyperdht_firewall_async_cb cb,
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

/**
 * Holepunch stats — per-strategy connect counts (JS parity:
 * `dht.stats.punches.{consistent,random,open}`). Used for telemetry.
 *
 * - consistent: CONSISTENT+CONSISTENT NAT combo (fast punch)
 * - random:     RANDOM NAT on either side (birthday-paradox / 1750-probe)
 * - open:       OPEN on either side (direct connect, no probing)
 */
HYPERDHT_API int hyperdht_punch_stats_consistent(const hyperdht_t* dht);
HYPERDHT_API int hyperdht_punch_stats_random(const hyperdht_t* dht);
HYPERDHT_API int hyperdht_punch_stats_open(const hyperdht_t* dht);

/**
 * Ping a peer by host:port. Fires `cb(success, userdata)` when the
 * ping completes (success=1) or times out (success=0). Does NOT
 * traverse the DHT — it's a direct UDP round-trip.
 *
 * Useful as a reachability probe before attempting a full connect,
 * or for monitoring known peers.
 */
typedef void (*hyperdht_ping_cb)(int success, void* userdata);

HYPERDHT_API int hyperdht_ping(hyperdht_t* dht,
                                const char* host, uint16_t port,
                                hyperdht_ping_cb cb, void* userdata);

/* =========================================================================
 * File descriptor polling — integrate external sockets into the event loop
 * ========================================================================= */

typedef struct hyperdht_poll_s hyperdht_poll_t;

#define HYPERDHT_POLL_READABLE 1
#define HYPERDHT_POLL_WRITABLE 2

/** Called when the file descriptor is ready. `events` is a bitmask of
 *  HYPERDHT_POLL_READABLE / HYPERDHT_POLL_WRITABLE. */
typedef void (*hyperdht_poll_cb)(int fd, int events, void* userdata);

/**
 * Start watching a file descriptor on the DHT's event loop. When the fd
 * becomes readable/writable (per `events` bitmask), `cb` fires during
 * `uv_run`. This lets external sockets (e.g. TCP) participate in the
 * same event loop without polling.
 *
 * @param dht       DHT instance (provides the uv_loop)
 * @param fd        file descriptor to watch
 * @param events    bitmask: HYPERDHT_POLL_READABLE, HYPERDHT_POLL_WRITABLE
 * @param cb        called when fd is ready
 * @param userdata  passed to cb
 * @return          poll handle, or NULL on failure
 */
HYPERDHT_API hyperdht_poll_t* hyperdht_poll_start(hyperdht_t* dht,
                                                   int fd, int events,
                                                   hyperdht_poll_cb cb,
                                                   void* userdata);

/** Stop watching and free the poll handle. Safe to call from inside cb. */
HYPERDHT_API void hyperdht_poll_stop(hyperdht_poll_t* handle);

#ifdef __cplusplus
}
#endif
