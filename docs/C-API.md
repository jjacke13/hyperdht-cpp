# C API Reference

Header: `#include <hyperdht/hyperdht.h>`
Link: `-lhyperdht -lsodium -luv` (static) or `-lhyperdht -lsodium -luv` (shared)

All functions are `extern "C"` with `HYPERDHT_API` visibility. Every async callback takes `void* userdata`. Single-threaded — call all functions from the `uv_loop_t` thread.

## Types

### `hyperdht_t`
Opaque handle to a HyperDHT instance. Created with `hyperdht_create()`, freed with `hyperdht_free()`.

### `hyperdht_server_t`
Opaque handle to a listening server. Created with `hyperdht_server_create()`.

### `hyperdht_keypair_t`
```c
typedef struct {
    uint8_t public_key[32];   // Ed25519 public key
    uint8_t secret_key[64];   // Ed25519 secret key (seed + public)
} hyperdht_keypair_t;
```

### `hyperdht_opts_t`
```c
typedef struct {
    uint16_t port;      // Bind port (0 = ephemeral)
    int ephemeral;      // 1 = ephemeral (default), 0 = persistent
} hyperdht_opts_t;
```

### `hyperdht_connection_t`
```c
typedef struct {
    uint8_t remote_public_key[32];  // Peer's Ed25519 public key
    uint8_t tx_key[32];             // Our encryption key (Noise-derived)
    uint8_t rx_key[32];             // Our decryption key (Noise-derived)
    uint8_t handshake_hash[64];     // BLAKE2b-512 Noise handshake hash
    uint32_t remote_udx_id;         // Peer's UDX stream ID
    uint32_t local_udx_id;          // Our UDX stream ID
    char peer_host[46];             // Peer IP as string
    uint16_t peer_port;             // Peer port
    int is_initiator;               // 1 if we connected, 0 if we accepted
} hyperdht_connection_t;
```

## Callbacks

| Type | Signature | When |
|------|-----------|------|
| `hyperdht_connect_cb` | `void(int error, const hyperdht_connection_t* conn, void* ud)` | Connect completes |
| `hyperdht_connection_cb` | `void(const hyperdht_connection_t* conn, void* ud)` | Server accepts connection |
| `hyperdht_close_cb` | `void(void* ud)` | Async operation completes |
| `hyperdht_firewall_cb` | `int(const uint8_t pk[32], const char* host, uint16_t port, void* ud)` | Return 0 to accept |
| `hyperdht_value_cb` | `void(const uint8_t* value, size_t len, void* ud)` | Immutable get result |
| `hyperdht_mutable_cb` | `void(uint64_t seq, const uint8_t* value, size_t len, const uint8_t sig[64], void* ud)` | Mutable get result |
| `hyperdht_done_cb` | `void(int error, void* ud)` | Put operation completes |

## Functions

### Keypair

#### `hyperdht_keypair_generate(hyperdht_keypair_t* out)`
Generate a random Ed25519 keypair.

#### `hyperdht_keypair_from_seed(hyperdht_keypair_t* out, const uint8_t seed[32])`
Generate a deterministic keypair from a 32-byte seed. Same seed always produces the same keys.

### Lifecycle

#### `hyperdht_create(uv_loop_t* loop, const hyperdht_opts_t* opts) → hyperdht_t*`
Create a new HyperDHT instance. Pass `NULL` for opts to use defaults (ephemeral, random port). Returns `NULL` on failure.

#### `hyperdht_bind(hyperdht_t* dht, uint16_t port) → int`
Bind the UDP socket. Returns 0 on success. Called automatically by connect/listen if needed.

#### `hyperdht_port(const hyperdht_t* dht) → uint16_t`
Get the bound port. Returns 0 if not bound.

#### `hyperdht_is_destroyed(const hyperdht_t* dht) → int`
Returns 1 if destroyed, 0 if alive.

#### `hyperdht_destroy(hyperdht_t* dht, hyperdht_close_cb cb, void* userdata)`
Begin destruction. After calling this:
1. Call `uv_run(&loop, UV_RUN_DEFAULT)` to drain close callbacks
2. Call `hyperdht_free(dht)` to release memory

#### `hyperdht_free(hyperdht_t* dht)`
Free the handle memory. **Only call after `uv_run()` has drained all pending callbacks.**

#### `hyperdht_default_keypair(const hyperdht_t* dht, hyperdht_keypair_t* out)`
Get the auto-generated default keypair.

### Client

#### `hyperdht_connect(hyperdht_t* dht, const uint8_t remote_pk[32], hyperdht_connect_cb cb, void* userdata) → int`
Connect to a peer by public key. The full pipeline runs automatically:
1. `findPeer` — iterative DHT walk to find the target's announcement
2. `PEER_HANDSHAKE` — Noise IK handshake through a relay node
3. `PEER_HOLEPUNCH` — NAT traversal (UDP probing)
4. Encrypted channel established

Returns 0 if the async operation started successfully. The callback fires with `error=0` on success or a negative error code on failure.

### Server

#### `hyperdht_server_create(hyperdht_t* dht) → hyperdht_server_t*`
Create a server instance. Returns `NULL` on failure.

#### `hyperdht_server_listen(hyperdht_server_t* srv, const hyperdht_keypair_t* kp, hyperdht_connection_cb cb, void* userdata) → int`
Start listening. The server:
1. Announces itself to ~20 closest DHT nodes
2. Re-announces periodically (every 5 minutes)
3. Accepts incoming Noise IK handshakes
4. Calls `cb` for each established connection

#### `hyperdht_server_set_firewall(hyperdht_server_t* srv, hyperdht_firewall_cb cb, void* userdata)`
Set a firewall callback. Called before the handshake completes. Return 0 to accept, non-zero to reject. Pass `NULL` to clear.

#### `hyperdht_server_close(hyperdht_server_t* srv, hyperdht_close_cb cb, void* userdata)`
Stop listening and unannounce from the DHT.

#### `hyperdht_server_refresh(hyperdht_server_t* srv)`
Force a re-announcement. Useful after network changes.

### Immutable Storage

#### `hyperdht_immutable_put(dht, value, len, cb, userdata) → int`
Store a value on the DHT. The target key is `BLAKE2b-256(value)` — content-addressed, immutable. The value is stored on the ~20 DHT nodes closest to the target hash.

#### `hyperdht_immutable_get(dht, target, cb, done_cb, userdata) → int`
Retrieve a value by its content hash. `cb` is called for each verified result (hash matches). `done_cb` fires when the query completes.

### Mutable Storage

#### `hyperdht_mutable_put(dht, kp, value, len, seq, cb, userdata) → int`
Store a signed value. Target is `BLAKE2b-256(publicKey)`. The value is signed with Ed25519 — only the key owner can update it. `seq` must increase for updates (monotonic).

#### `hyperdht_mutable_get(dht, public_key, min_seq, cb, done_cb, userdata) → int`
Retrieve the latest signed value for a public key. `cb` is called for each verified result (valid signature, `seq >= min_seq`). `done_cb` fires when the query completes.

## Complete Example

```c
#include <hyperdht/hyperdht.h>
#include <uv.h>
#include <stdio.h>

void on_connect(int error, const hyperdht_connection_t* conn, void* ud) {
    if (error != 0) {
        printf("Connect failed: %d\n", error);
        return;
    }
    printf("Connected to %s:%d\n", conn->peer_host, conn->peer_port);
    printf("Remote key: ");
    for (int i = 0; i < 16; i++) printf("%02x", conn->remote_public_key[i]);
    printf("...\n");
}

int main() {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_t* dht = hyperdht_create(&loop, NULL);
    hyperdht_bind(dht, 0);

    // The remote peer's public key (32 bytes)
    uint8_t remote_pk[32] = { /* ... */ };

    hyperdht_connect(dht, remote_pk, on_connect, NULL);

    uv_run(&loop, UV_RUN_DEFAULT);

    hyperdht_destroy(dht, NULL, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
    return 0;
}
```

### Encrypted Streams

#### `hyperdht_stream_open(dht, conn, on_open, on_data, on_close, userdata) → hyperdht_stream_t*`
Create an encrypted read/write stream from an established connection. Handles UDX stream setup and SecretStream header exchange automatically. `on_open` fires when the stream is ready. `on_data` fires for each received (decrypted) message. Returns `NULL` on failure.

#### `hyperdht_stream_write(stream, data, len) → int`
Encrypt data with SecretStream (XChaCha20-Poly1305) and send over UDX. Returns 0 on success. Only call after `on_open` has fired.

#### `hyperdht_stream_close(stream)`
Send end-of-stream and close. Triggers the `on_close` callback.

#### `hyperdht_stream_is_open(stream) → int`
Returns 1 if the header exchange is complete and the stream is ready for read/write.

## Error Handling

All functions that return `int` use: 0 = success, negative = error. Functions that return pointers use: non-NULL = success, NULL = failure.

Error codes in `hyperdht_connection_t` callbacks: 0 = success, negative = connection failed.

Mutable storage error codes (in `hyperdht_done_cb`):
- `16` (`ERR_SEQ_REUSED`) — Same sequence number with different value
- `17` (`ERR_SEQ_TOO_LOW`) — Sequence number lower than stored value

## API Surface Summary

### Currently exposed (22 functions)

| Category | Functions |
|----------|----------|
| Keypair | `keypair_generate`, `keypair_from_seed` |
| Lifecycle | `create`, `bind`, `port`, `is_destroyed`, `destroy`, `free`, `default_keypair` |
| Client | `connect` |
| Server | `server_create`, `server_listen`, `server_set_firewall`, `server_close`, `server_refresh` |
| Storage | `immutable_put`, `immutable_get`, `mutable_put`, `mutable_get` |
| Streams | `stream_open`, `stream_write`, `stream_close`, `stream_is_open` |

### Future additions (when needed)

These C++ features exist but are not yet exposed through the C API. Each would be ~10-20 lines to add:

| Function | What it enables |
|----------|----------------|
| `hyperdht_find_peer()` | Raw DHT peer discovery |
| `hyperdht_lookup()` | Generic DHT query |
| `hyperdht_announce()` | Manual announcement (without server) |
| `hyperdht_get_public_address()` | Get our NAT-mapped public IP |
| `hyperdht_set_bootstrap()` | Custom bootstrap nodes |
| `hyperdht_stats()` | Routing table size, connections, uptime |
