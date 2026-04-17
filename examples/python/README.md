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

## Finding the library

The Python wrapper needs `libhyperdht.so` and `libuv.so` at runtime. It searches in this order:

1. **`HYPERDHT_LIB` env var** -- explicit path to the `.so` file
2. **`LD_LIBRARY_PATH`** -- standard library search path
3. **System paths** -- `/usr/lib`, `/usr/local/lib` (via `ldconfig`)
4. **Relative to the package** -- `../../build-shared/` (for development)

Pick whichever works for your setup:

```bash
# Option 1: env var (recommended for development)
export HYPERDHT_LIB=/path/to/build-shared/libhyperdht.so

# Option 2: LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/path/to/build-shared:$LD_LIBRARY_PATH

# Option 3: system install
sudo cp build-shared/libhyperdht.so /usr/local/lib/
sudo ldconfig
```

`libuv` is usually already installed system-wide (`libuv.so.1`). If not, install it with your package manager.

## Run

### Quick demos (offline, no network needed)

```bash
python3 keypair_demo.py              # keypair generation + deterministic seeds
python3 hash_demo.py "hello world"   # BLAKE2b-256 hash
python3 state_demo.py                # DHT state inspection
```

### Network demos (connects to public HyperDHT)

```bash
python3 ping_demo.py                             # ping a bootstrap node
python3 storage_demo.py put "hello from python"   # store data on the DHT
python3 storage_demo.py get <hash>                # retrieve by content hash
```

### Server / client

```bash
# Terminal 1: start a server
python3 example.py server

# Terminal 2: connect to it
python3 example.py connect <public_key_hex>
```

### P2P tunnel (holesail-compatible)

```bash
# Start a local web server
python3 webserver.py &

# Expose it over HyperDHT
python3 holesail_server.py --live 8080

# Connect from anywhere (JS holesail or mobile app)
holesail --connect hs://0000...
```

## Examples

| File | What it does |
|------|-------------|
| `keypair_demo.py` | Random, seeded, and deterministic keypair generation |
| `hash_demo.py` | BLAKE2b-256 hash (same function the DHT uses internally) |
| `state_demo.py` | Inspect DHT state: health, routing table, stats, suspend/resume |
| `storage_demo.py` | Immutable and mutable key-value storage on the live DHT |
| `ping_demo.py` | Direct UDP ping to any DHT node |
| `example.py` | Server + client + keygen (the main demo) |
| `holesail_server.py` | P2P tunnel server with `--live`, `--seed`, `--secure` |
| `webserver.py` | Minimal HTTP server for holesail testing |
| `test_wrapper.py` | 22 automated tests for the Python wrapper |

## Important: threading and callback rules

The library uses a libuv event loop internally. Three rules you must follow:

1. **Single-threaded** -- all `hyperdht` calls must happen on the same thread
   that runs `dht.run()`. Never call `stream.write()`, `dht.connect()`, or
   any other library function from a background thread. If you need to bridge
   blocking I/O (like TCP sockets), use `selectors` or `uv_async_send` to
   marshal work back to the event loop thread.

2. **Wait for `on_open`** -- after `dht.open_stream()`, the SecretStream header
   exchange must complete before you can write. The `on_open` callback signals
   readiness. Writes before `on_open` return error code -1. If you're bridging
   to a TCP socket, don't start reading from TCP until `on_open` fires.

3. **Callback lifetime** -- keep references to all ctypes callback objects
   (the decorated `@CFUNCTYPE` functions) for as long as they might be called.
   If Python garbage-collects a callback while the C library still holds a
   pointer to it, you get a segfault.

## How it works

The `hyperdht/` package uses ctypes to call `libhyperdht.so` (the C API).
No Python C extensions, no pip install, no compilation on the Python side.
Just `import hyperdht` and go.

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
