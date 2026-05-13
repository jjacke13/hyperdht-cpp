# Rust Examples — hyperdht echo server + client

Rust port of `examples/cpp/`. Same protocol, same wire format, fully
interoperable with the C++ and JS HyperDHT echo examples.

## Build

```bash
cd examples/rust
nix develop ../../#rust -c cargo build --release
```

Binaries land in `target/release/{echo-server,echo-client}`.

## Run

### Server

```bash
# Random keypair, random ephemeral port
cargo run --release --bin echo-server

# Deterministic identity (64 hex chars = 32-byte seed)
cargo run --release --bin echo-server -- 1111111111111111111111111111111111111111111111111111111111111111

# Deterministic identity + fixed port
cargo run --release --bin echo-server -- <seed> 49737
```

The server prints its public key on startup. Share that with the client.

### Client

```bash
cargo run --release --bin echo-client -- <server-pubkey-hex>
```

## Cross-tests

These examples are wire-compatible with the C++ and JS implementations:

- Rust client → C++ server
- C++ client → Rust server
- Rust client → JS HyperDHT echo server
- JS HyperDHT client → Rust server

The Noise IK handshake, SecretStream framing, and UDX transport are all
implemented identically across language bindings.

## Notes

- First connect from a fresh DHT instance takes 1-3 seconds (DHT walk +
  holepunch). Subsequent connects to the same peer reuse cached routes
  and complete in ~50-100ms.
- Both sides must shut down their side of the stream for clean teardown
  (otherwise UDX waits for its TLP/RTO timeout, ~5-10 sec). The example
  client calls `stream.shutdown()`; the server detects EOF on read and
  exits the session loop.
