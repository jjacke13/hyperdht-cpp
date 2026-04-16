# hyperdht-cpp

C++20 reimplementation of [HyperDHT](https://github.com/holepunchto/hyperdht),
wire-compatible with the JavaScript reference. Designed for embedded targets
and for FFI consumers (Python, Go, Rust, Swift, Kotlin) that can't pull in a
Node.js runtime.

- **Language**: C++20, exceptions disabled where practical, error codes for FFI
- **Event loop**: libuv (single-threaded, same concurrency model as the JS reference)
- **Transport**: libudx (reliable UDP with BBR congestion control)
- **Crypto**: libsodium (Ed25519, BLAKE2b, ChaCha20-Poly1305, secretstream)
- **License**: Apache-2.0

## Status

Full protocol + HyperDHT API parity with JS `hyperdht 6.29.1`. Live-tested
against a JS peer in both directions on the public network. 580+ unit tests,
ASAN-clean on the hot path. See [`docs/JS-PARITY-GAPS.md`](docs/JS-PARITY-GAPS.md)
for the detailed parity matrix.

## Build

```bash
# Using Nix (recommended — pins libudx, libsodium, libuv versions)
nix develop
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
ninja
ctest --output-on-failure

# Or use pre-packaged artefacts
nix build .#static    # libhyperdht.a
nix build .#shared    # libhyperdht.so (for FFI consumers)
```

Without Nix: install `cmake`, `ninja`, `libsodium`, `libuv`, then run the
same `cmake`/`ninja` flow from `build/`.

## Quick start (C++)

```cpp
#include <hyperdht/dht.hpp>

uv_loop_t loop;
uv_loop_init(&loop);

hyperdht::HyperDHT dht(&loop);
dht.bind();

// Client
dht.connect(remote_public_key,
    [](int err, const hyperdht::ConnectResult& r) {
        if (err == 0) {
            // r.tx_key / r.rx_key / r.peer_address — encrypted channel ready
        }
    });

// Server
auto* srv = dht.create_server();
srv->listen(keypair,
    [](const hyperdht::server::ConnectionInfo& info) {
        // info.remote_public_key / info.tx_key / info.rx_key
    });

uv_run(&loop, UV_RUN_DEFAULT);

dht.destroy();
uv_run(&loop, UV_RUN_DEFAULT);   // drain close callbacks
uv_loop_close(&loop);
```

## Quick start (Python)

```python
from hyperdht import HyperDHT, KeyPair

dht = HyperDHT()
dht.bind()

stream = dht.connect_stream(
    remote_public_key,
    on_open=lambda s: s.write(b"hello"),
    on_data=lambda data: print("got:", data),
    on_close=lambda: print("done"),
)
dht.run()
```

See [`wrappers/python/example.py`](wrappers/python/example.py) for the full example.

## Quick start (C)

```c
#include <hyperdht/hyperdht.h>

uv_loop_t loop;
uv_loop_init(&loop);

hyperdht_t* dht = hyperdht_create(&loop, NULL);
hyperdht_bind(dht, 0);
hyperdht_connect(dht, remote_pk, on_connect, NULL);

uv_run(&loop, UV_RUN_DEFAULT);
hyperdht_destroy(dht, NULL, NULL);
uv_run(&loop, UV_RUN_DEFAULT);
hyperdht_free(dht);
uv_loop_close(&loop);
```

## Documentation

| Topic | File |
|-------|------|
| Wire protocol spec (reverse-engineered from JS) | [`PROTOCOL.md`](PROTOCOL.md) |
| C API reference | [`docs/C-API.md`](docs/C-API.md) |
| C++ API reference | [`docs/CPP-API.md`](docs/CPP-API.md) |
| JS HyperDHT ↔ C/C++ side-by-side | [`docs/JS-COMPARISON.md`](docs/JS-COMPARISON.md) |
| JS source file → C++ file mapping | [`docs/JS-MAPPING.md`](docs/JS-MAPPING.md) |
| Parity gap tracker (authoritative) | [`docs/JS-PARITY-GAPS.md`](docs/JS-PARITY-GAPS.md) |
| Outstanding verification + production tasks | [`docs/REMAINING-WORK.md`](docs/REMAINING-WORK.md) |
| Internal development notes | [`CLAUDE.md`](CLAUDE.md) |

The authoritative source for every public API surface is the header comment
in `include/hyperdht/*.hpp` / `include/hyperdht/hyperdht.h` — the `docs/`
references are curated quick-starts.

## Bootstrap nodes

The public HyperDHT network's three seed nodes (same list JS uses):

```
88.99.3.86@node1.hyperdht.org:49737
142.93.90.113@node2.hyperdht.org:49737
138.68.147.8@node3.hyperdht.org:49737
```

Available programmatically via `HyperDHT::BOOTSTRAP()` or `HYPERDHT_BOOTSTRAP_*`.

## Related projects

- [nospoon](https://github.com/jjacke13/nospoon) — the P2P VPN that drove
  this implementation
- [mimiclaw](https://github.com/jjacke13/mimiclaw) — ESP32-S3 firmware
  target (pending ESP-IDF wrapper, see `docs/REMAINING-WORK.md`)

## Contributing

Work flow: `docs/JS-PARITY-GAPS.md` tracks protocol/API parity items;
`docs/REMAINING-WORK.md` tracks verification, hardening, and production
polish. Every network-behaviour change must be live-tested against a JS
peer in both directions before landing (lesson learned the hard way —
don't patch from the top of the stack).
