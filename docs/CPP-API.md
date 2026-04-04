# C++ API Reference

Header: `#include <hyperdht/dht.hpp>`
Namespace: `hyperdht`
Link: `-lhyperdht -lsodium -luv`

The C++ API provides direct access to the HyperDHT classes. For FFI consumers (Python, Go, etc.), use the [C API](C-API.md) instead.

## Core Classes

### `hyperdht::HyperDHT`

The main entry point. Owns the RPC socket, routing table, handlers, and servers.

```cpp
#include <hyperdht/dht.hpp>

uv_loop_t loop;
uv_loop_init(&loop);

hyperdht::HyperDHT dht(&loop);
dht.bind();

// Client: connect to a peer
dht.connect(remote_public_key, [](int err, const hyperdht::ConnectResult& result) {
    if (err == 0) {
        // Encrypted connection established
        // result.tx_key, result.rx_key — Noise-derived encryption keys
        // result.remote_public_key — verified peer identity
        // result.peer_address — direct UDP address after holepunch
    }
});

// Server: listen for connections
auto* srv = dht.create_server();
srv->listen(keypair, [](const hyperdht::server::ConnectionInfo& info) {
    // info.remote_public_key, info.tx_key, info.rx_key, etc.
});

// Cleanup
dht.destroy();
uv_run(&loop, UV_RUN_DEFAULT);
uv_loop_close(&loop);
```

#### Constructor
```cpp
HyperDHT(uv_loop_t* loop, DhtOptions opts = {});
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `bind()` | `int` | Bind UDP socket (0 = success) |
| `connect(pk, callback)` | `void` | Connect to peer by public key |
| `connect(pk, keypair, callback)` | `void` | Connect with specific keypair |
| `create_server()` | `Server*` | Create a listening server |
| `find_peer(pk, on_reply, on_done)` | `shared_ptr<Query>` | Find peer's announcement |
| `lookup(target, on_reply, on_done)` | `shared_ptr<Query>` | Generic DHT lookup |
| `announce(target, value, on_done)` | `shared_ptr<Query>` | Announce + commit to k closest |
| `destroy(on_done)` | `void` | Close everything |
| `port()` | `uint16_t` | Bound port |
| `is_bound()` | `bool` | Whether socket is bound |
| `is_destroyed()` | `bool` | Whether destroy was called |
| `default_keypair()` | `const Keypair&` | Auto-generated keypair |

### `hyperdht::DhtOptions`
```cpp
struct DhtOptions {
    uint16_t port = 0;                            // 0 = ephemeral
    std::vector<compact::Ipv4Address> bootstrap;  // Empty = public bootstrap
    noise::Keypair default_keypair;               // Auto-generated if zero
    bool ephemeral = true;
};
```

### `hyperdht::ConnectResult`
```cpp
struct ConnectResult {
    bool success = false;
    noise::Key tx_key{};                          // 32-byte encryption key
    noise::Key rx_key{};                          // 32-byte decryption key
    noise::Hash handshake_hash{};                 // 64-byte Noise hash
    std::array<uint8_t, 32> remote_public_key{};
    compact::Ipv4Address peer_address;
    uint32_t remote_udx_id = 0;
    uint32_t local_udx_id = 0;
};
```

### `hyperdht::server::Server`

Created by `HyperDHT::create_server()`. Owned by the HyperDHT instance.

```cpp
auto* srv = dht.create_server();

// Listen with a keypair
srv->listen(keypair, [](const server::ConnectionInfo& info) {
    // New encrypted connection from info.remote_public_key
});

// Optional: firewall callback
srv->set_firewall([](const auto& remote_pk, const auto& payload, const auto& addr) {
    return false;  // false = accept, true = reject
});

// Stop
srv->close();
```

### `hyperdht::server::ConnectionInfo`
```cpp
struct ConnectionInfo {
    noise::Key tx_key;
    noise::Key rx_key;
    noise::Hash handshake_hash;
    std::array<uint8_t, 32> remote_public_key;
    compact::Ipv4Address peer_address;
    uint32_t remote_udx_id = 0;
    uint32_t local_udx_id = 0;
    bool is_initiator = false;
};
```

## DHT Operations

### `hyperdht::dht_ops`

Standalone functions for DHT queries. All return `shared_ptr<Query>`.

**LIFETIME:** The caller must ensure `socket` outlives the returned Query.

```cpp
#include <hyperdht/dht_ops.hpp>

// Find a peer's announcement
auto q = dht_ops::find_peer(socket, public_key,
    [](const query::QueryReply& reply) { /* each result */ },
    [](const auto&) { /* done */ });

// Immutable put (target = BLAKE2b(value))
auto q = dht_ops::immutable_put(socket, value,
    [](const auto&) { /* done */ });

// Immutable get
auto q = dht_ops::immutable_get(socket, target_hash,
    [](const std::vector<uint8_t>& value) { /* verified result */ },
    [](const auto&) { /* done */ });

// Mutable put (signed, target = BLAKE2b(publicKey))
auto q = dht_ops::mutable_put(socket, keypair, value, seq,
    [](const auto&) { /* done */ });

// Mutable get (verifies signature)
auto q = dht_ops::mutable_get(socket, public_key, min_seq,
    [](const dht_ops::MutableResult& result) {
        // result.seq, result.value, result.signature
    },
    [](const auto&) { /* done */ });
```

## Crypto Types

### `hyperdht::noise`

```cpp
#include <hyperdht/noise_wrap.hpp>

using Key = std::array<uint8_t, 32>;
using PubKey = std::array<uint8_t, 32>;
using SecKey = std::array<uint8_t, 64>;
using Seed = std::array<uint8_t, 32>;
using Hash = std::array<uint8_t, 64>;  // BLAKE2b-512

struct Keypair {
    PubKey public_key;
    SecKey secret_key;
};

// Generate random keypair
Keypair generate_keypair();

// Generate from seed (deterministic)
Keypair generate_keypair(const Seed& seed);
```

## Error Handling

The library uses error codes, not exceptions (targets embedded platforms):
- Functions returning `int`: 0 = success, negative = error
- Functions returning pointers: non-NULL = success, NULL = failure
- `std::optional` for values that may not exist
- `state.error` flag in compact encoding

## Thread Safety

All classes are single-threaded. All operations must be called from the `uv_loop_t` thread. This matches libuv's concurrency model — every JS `await` becomes a callback chain.
