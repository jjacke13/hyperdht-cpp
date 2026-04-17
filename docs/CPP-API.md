# C++ API Reference

Headers: [`include/hyperdht/*.hpp`](../include/hyperdht/) (authoritative, every method documented inline)

For FFI consumers (Python, Go, Swift, Kotlin), use the [C API](C-API.md) instead.

## Core classes

| Class | Header | Purpose |
|-------|--------|---------|
| `HyperDHT` | `dht.hpp` | Main entry point -- DHT node, connect, create_server, queries, storage |
| `Server` | `server.hpp` | Listen for connections, firewall, holepunch veto, relay |
| `SecretStreamDuplex` | `secret_stream.hpp` | Encrypted stream (XChaCha20-Poly1305) over UDX |
| `Mux` / `Channel` | `protomux.hpp` | Channel multiplexing over SecretStream |
| `BlindRelayClient/Server` | `blind_relay.hpp` | Relay fallback for double-NAT |
| `Query` | `query.hpp` | Iterative Kademlia query engine |
| `RoutingTable` | `routing_table.hpp` | k=20, 256 buckets, closest-node lookup |
| `RpcSocket` | `rpc.hpp` | DHT RPC transport, retry, congestion control |

## Conventions

- **Event loop**: single-threaded libuv. Every JS `await` becomes a callback chain.
- **Error handling**: error codes, not exceptions (targets embedded). `std::optional` for maybe-values.
- **Ownership**: RAII everywhere. `std::unique_ptr`, `std::shared_ptr`, `UvTimer` wrapper.
- **Immutability**: create new objects rather than mutating in place.
- **Naming**: `snake_case` for methods, `PascalCase` for types.

## HyperDHT (main class)

```cpp
#include <hyperdht/dht.hpp>

HyperDHT(uv_loop_t* loop, DhtOptions opts = {});
```

### Lifecycle

| Method | Description |
|--------|-------------|
| `bind()` | Bind UDP socket |
| `port()` | Bound port |
| `destroy(opts, cb)` / `destroy(cb)` | Close everything |
| `suspend(log)` / `resume(log)` | Mobile background transitions |
| `default_keypair()` | Auto-generated Ed25519 keypair |

### Connect

| Method | Description |
|--------|-------------|
| `connect(pk, cb)` | Connect to peer (full pipeline: findPeer + handshake + holepunch) |
| `connect(pk, opts, cb)` | With options (keypair, relay, fast_open, local_connection) |

### Server

| Method | Description |
|--------|-------------|
| `create_server()` | Returns `Server*` (owned by HyperDHT) |

### Queries

| Method | Description |
|--------|-------------|
| `find_peer(pk, on_reply, on_done)` | Find peer's announcement |
| `lookup(target, on_reply, on_done)` | Generic DHT lookup |
| `announce(target, value, on_done)` | Announce + commit to k closest |
| `unannounce(pk, kp, on_done)` | Remove announcement |

### Storage

| Method | Description |
|--------|-------------|
| `immutable_put(value, cb)` | Store content-addressed value |
| `immutable_get(target, on_value, on_done)` | Retrieve by BLAKE2b hash |
| `mutable_put(kp, value, seq, cb)` | Store signed value |
| `mutable_get(pk, min_seq, on_value, on_done)` | Retrieve latest signed value |

### State

| Method | Description |
|--------|-------------|
| `is_online()` / `is_degraded()` | Health monitoring |
| `is_persistent()` / `is_bootstrapped()` | Node state |
| `is_destroyed()` / `is_suspended()` | Lifecycle state |
| `remote_address()` | Public IP from NAT sampling |
| `stats()` | Punch/relay counters |

### Events

| Method | Description |
|--------|-------------|
| `on_bootstrapped(cb)` | Bootstrap walk complete |
| `on_network_change(cb)` | Network interface changed |
| `on_network_update(cb)` | Online/degraded/offline transition |
| `on_persistent(cb)` | Ephemeral -> persistent |

### Utilities

| Method | Description |
|--------|-------------|
| `hash(data, len)` | BLAKE2b-256 (static) |
| `key_pair()` / `key_pair(seed)` | Generate keypair (static) |
| `add_node(addr)` | Add to routing table |
| `to_array(limit)` | Snapshot routing table |
| `ping(addr, cb)` | Direct UDP ping |

## Server

```cpp
auto* srv = dht.create_server();
srv->listen(keypair, on_connection);
```

| Method | Description |
|--------|-------------|
| `listen(kp, cb)` | Start listening + announcing |
| `close(cb)` / `close(force, cb)` | Stop + unannounce |
| `refresh()` | Force re-announcement |
| `suspend(log)` / `resume()` | Mobile transitions |
| `set_firewall(cb)` | Sync accept/reject |
| `set_firewall_async(cb)` | Async accept/reject (DB lookup, ACL) |
| `set_holepunch(cb)` | Holepunch veto |
| `relay_through` | Blind relay public key |
| `is_listening()` / `public_key()` / `address()` | State queries |
| `on_listening(cb)` | Ready to accept peers |
| `notify_online()` | Network came back |

## DhtOptions

```cpp
struct DhtOptions {
    uint16_t port = 0;
    bool ephemeral = true;
    std::vector<compact::Ipv4Address> bootstrap;  // empty = public nodes
    noise::Keypair default_keypair;               // zero = auto-generate
    uint64_t connection_keep_alive = 5000;         // ms
    noise::Seed seed;                              // deterministic keypair
    std::string host;                              // bind interface
    // ... see dht.hpp for full list
};
```

## Thread safety

All classes are single-threaded. All operations must be called from the `uv_loop_t` thread. This matches libuv's concurrency model.
