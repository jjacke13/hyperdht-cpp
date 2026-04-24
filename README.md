# hyperdht-cpp

A C++ implementation of [HyperDHT](https://github.com/holepunchto/hyperdht) -- wire-compatible with the JavaScript reference. Connect any device to the [Hyperswarm](https://docs.holepunch.to) P2P network without a Node.js runtime.

## What it does

Two devices on different networks, behind NATs, find each other by public key and establish an encrypted channel. No servers, no port forwarding, no configuration.

- **DHT peer discovery** -- Kademlia routing table, iterative lookups, announcements
- **NAT traversal** -- UDP holepunching with 4 strategies (consistent, random, birthday paradox, blind relay)
- **End-to-end encryption** -- Noise IK handshake (Ed25519) + SecretStream (XChaCha20-Poly1305)
- **Mutable/immutable storage** -- signed key-value records on the DHT
- **C FFI** -- 76-function `extern "C"` API for Python, Go, Rust, Swift, Kotlin
- **Python wrapper included** -- `from hyperdht import HyperDHT, KeyPair` and go

## Why C++

The JS HyperDHT requires Node.js (~30MB runtime). This implementation is a single shared library (~1-2MB stripped) that embeds anywhere: mobile apps, embedded devices, system daemons, game engines, or any language with C FFI.

## Status

Wire-compatible with JS `hyperdht@6.29.1`. Live-tested in both directions on the public network.

| | |
|---|---|
| **Tests** | 566 unit + 6 live, ASAN/UBSan clean |
| **API parity** | Full -- see [JS-PARITY-GAPS.md](docs/JS-PARITY-GAPS.md) |
| **Languages** | C++ / C / Python / Kotlin (Swift, Go, Rust planned) |
| **Platforms** | Linux, macOS, Windows, ESP32, Android |

## Build

```
nix develop && mkdir -p build && cd build && cmake .. -G Ninja && ninja && ctest -L unit
```

Without Nix: install `cmake`, `ninja`, `libsodium`, `libuv`, then the same cmake flow. Docker also works (`docker build -t hyperdht .`). See [BUILDING.md](docs/BUILDING.md) for full instructions (Linux, macOS, Docker, linking, troubleshooting).

## Documentation

| | |
|---|---|
| [Build instructions](docs/BUILDING.md) | Linux, macOS, Docker, Nix — deps, compile, link, troubleshoot |
| [C API reference](docs/C-API.md) | 76 functions, opaque-pointer pattern, callback-based async |
| [C++ API reference](docs/CPP-API.md) | RAII wrappers, error codes, single-threaded event loop |
| [Python examples](examples/python/) | Server, client, holesail tunnel, 22 wrapper tests |
| [ESP32 guide](examples/esp32/) | Build, flash, run HyperDHT on ESP32-S3 (echo server + client) |
| [Android example](examples/android/) | Kotlin/JNI wrapper with echo test app |
| [Wire protocol spec](PROTOCOL.md) | Reverse-engineered from JS, 12 sections |
| [JS name mapping](docs/JS-MAPPING.md) | Side-by-side: `createServer` -> `create_server` -> `hyperdht_server_create` |
| [Remaining work](docs/REMAINING-WORK.md) | Verification tasks, production readiness, ESP32 porting plan |

## Bootstrap nodes

The public HyperDHT network (same nodes the JS ecosystem uses):

```
node1.hyperdht.org:49737
node2.hyperdht.org:49737
node3.hyperdht.org:49737
```

## Contributing

[JS-PARITY-GAPS.md](docs/JS-PARITY-GAPS.md) tracks protocol parity. [REMAINING-WORK.md](docs/REMAINING-WORK.md) tracks hardening and production polish. Every network-behaviour change must be live-tested against a JS peer before landing.

## License

[LGPL-3.0](LICENSE) -- library changes must be shared; downstream apps can use any license.
