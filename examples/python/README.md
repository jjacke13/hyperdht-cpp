# Python HyperDHT Examples

Encrypted P2P connections from Python, powered by hyperdht-cpp.

## Requirements

- Python 3.8+
- Linux (x86_64 or aarch64)
- Build tools: cmake, ninja, pkg-config
- Libraries: libsodium, libuv

### Install dependencies

```bash
# Debian / Ubuntu
sudo apt install cmake ninja-build pkg-config libsodium-dev libuv1-dev python3

# Fedora
sudo dnf install cmake ninja-build pkgconf libsodium-devel libuv-devel python3

# Arch
sudo pacman -S cmake ninja pkgconf libsodium libuv python
```

## Build

```bash
cd examples/python
./build.sh
```

This builds `libhyperdht.so` in `build-shared/` at the repo root.

## Run

```bash
# Point to the library
export HYPERDHT_LIB=../../build-shared/libhyperdht.so

# Generate a keypair
python3 example.py keygen

# Start a server (prints public key)
python3 example.py server

# Connect to a server (from another machine)
python3 example.py connect <public_key_hex>

# Holesail-compatible P2P tunnel
python3 holesail_server.py --live 8080
```

## What's here

| File | What it does |
|------|-------------|
| `example.py` | CLI: `server`, `connect`, `keygen` |
| `holesail_server.py` | P2P tunnel server (`--live <port>`, holesail-compatible `hs://` links) |
| `test_wrapper.py` | Smoke tests for the Python bindings |
| `hyperdht/` | ctypes bindings — the actual Python library |

## Important: threading and callback rules

The library uses a libuv event loop internally. Three rules you must follow:

1. **Single-threaded** — all `hyperdht` calls must happen on the same thread
   that runs `dht.run()`. Never call `stream.write()`, `dht.connect()`, or
   any other library function from a background thread. If you need to bridge
   blocking I/O (like TCP sockets), use `selectors` or `uv_async_send` to
   marshal work back to the event loop thread.

2. **Wait for `on_open`** — after `dht.open_stream()`, the SecretStream header
   exchange must complete before you can write. The `on_open` callback signals
   readiness. Writes before `on_open` return error code -1. If you're bridging
   to a TCP socket, don't start reading from TCP until `on_open` fires.

3. **Callback lifetime** — keep references to all ctypes callback objects
   (the decorated `@CFUNCTYPE` functions) for as long as they might be called.
   If Python garbage-collects a callback while the C library still holds a
   pointer to it, you get a segfault.

## How it works

The `hyperdht/` package uses ctypes to call `libhyperdht.so` (the C API).
No Python C extensions, no pip install, no compilation on the Python side.
Just `import hyperdht` and go.

The library handles:
- Ed25519 keypairs (via libsodium)
- Kademlia DHT (peer discovery across the internet)
- Noise IK handshake (mutual authentication)
- NAT holepunching (works behind most NATs and firewalls)
- SecretStream encryption (XChaCha20-Poly1305)

All of this is wire-compatible with the JavaScript [HyperDHT](https://github.com/holepunchto/hyperdht).

## Testing

```bash
export HYPERDHT_LIB=../../build-shared/libhyperdht.so
python3 test_wrapper.py
```

## Cross-language test

Start a Python server, connect from JavaScript (or vice versa):

```bash
# Python server (this machine)
python3 example.py server

# JS client (any machine with hyperdht installed)
node -e "
  const DHT = require('hyperdht')
  const d = new DHT()
  const s = d.connect(Buffer.from('<public_key>', 'hex'))
  s.on('open', () => { console.log('CONNECTED!'); d.destroy() })
"
```
