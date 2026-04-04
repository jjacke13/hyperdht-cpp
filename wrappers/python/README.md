# hyperdht — Python bindings

Python wrapper for hyperdht-cpp via ctypes. No compilation needed — just requires `libhyperdht.so`.

## Quick Start

```python
from hyperdht import HyperDHT, KeyPair

# Generate a keypair
kp = KeyPair.generate()
print(f"Public key: {kp.public_key.hex()}")

# Create a DHT node
dht = HyperDHT()
dht.bind()
print(f"Port: {dht.port}")

# Server: listen for connections
server = dht.create_server()
server.listen(kp, lambda conn: print(f"Connected: {conn.remote_key.hex()[:32]}..."))

# Client: connect to a peer
dht.connect(remote_pk_bytes, lambda err, conn: print("Connected!" if not err else f"Error: {err}"))

# Run the event loop
dht.run()

# Cleanup
dht.destroy()
```

## Requirements

- Python 3.8+
- `libhyperdht.so` (build with `nix build .#shared` or `cmake -DBUILD_SHARED_LIBS=ON`)
- `libuv.so.1` (system library)

## Installation

```bash
# Build the shared library
nix build .#shared
# or:
mkdir build && cd build
cmake .. -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release -G Ninja
ninja

# Set library path
export LD_LIBRARY_PATH=/path/to/libhyperdht.so:$LD_LIBRARY_PATH

# Use the wrapper
cd wrappers/python
python3 -c "from hyperdht import KeyPair; print(KeyPair.generate())"
```

## API

### `KeyPair`
- `KeyPair.generate() → KeyPair` — random keypair
- `KeyPair.from_seed(seed: bytes) → KeyPair` — deterministic from 32-byte seed
- `.public_key: bytes` — 32-byte Ed25519 public key
- `.secret_key: bytes` — 64-byte Ed25519 secret key

### `HyperDHT`
- `HyperDHT(port=0, ephemeral=True)` — create instance
- `.bind(port=0)` — bind UDP socket
- `.port → int` — bound port
- `.default_keypair → KeyPair` — auto-generated identity
- `.connect(remote_pk, callback)` — connect to peer
- `.create_server() → Server` — create listening server
- `.immutable_put(value, on_done)` — store content-addressed data
- `.immutable_get(hash, on_value, on_done)` — retrieve by hash
- `.mutable_put(keypair, value, seq, on_done)` — store signed data
- `.mutable_get(pubkey, min_seq, on_value, on_done)` — retrieve signed data
- `.run()` — run event loop (blocking)
- `.destroy()` — cleanup

### `Server`
- `.listen(keypair, on_connection)` — start accepting connections
- `.set_firewall(callback)` — accept/reject filter
- `.close()` — stop listening
- `.refresh()` — force re-announcement

### `Connection`
- `.remote_key: bytes` — peer's public key
- `.tx_key: bytes` — encryption key
- `.rx_key: bytes` — decryption key
- `.peer_host: str` — peer IP address
- `.peer_port: int` — peer port
- `.is_initiator: bool` — True if we connected

## Example

```bash
# Terminal 1: Server
python example.py server

# Terminal 2: Client
python example.py connect <public_key_from_server>

# Generate a keypair
python example.py keygen
```

## Testing

```bash
LD_LIBRARY_PATH=../../build-shared python3 test_wrapper.py
```
