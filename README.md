# hyperdht-cpp

A C++ implementation of [HyperDHT](https://github.com/holepunchto/hyperdht) -- wire-compatible with the JavaScript reference. Connect any device to the [Hyperswarm](https://docs.holepunch.to) P2P network without a Node.js runtime.

## What it does

Two devices on different networks, behind NATs, find each other by public key and establish an encrypted channel. No servers, no port forwarding, no configuration.

- **DHT peer discovery** -- Kademlia routing table, iterative lookups, announcements
- **NAT traversal** -- UDP holepunching with 4 strategies (consistent, random, birthday paradox, blind relay)
- **End-to-end encryption** -- Noise IK handshake (Ed25519) + SecretStream (XChaCha20-Poly1305)
- **Mutable/immutable storage** -- signed key-value records on the DHT
- **C FFI** -- 90-function `extern "C"` API for Python, Go, Rust, Swift, Kotlin
- **Wrappers included** -- Python (`from hyperdht import HyperDHT, KeyPair`), Rust (`hyperdht` + `hyperdht-sys` crates), Kotlin/JNI for Android

## Why C++

The JS HyperDHT requires Node.js (~30MB runtime). This implementation is a single shared library (~1-2MB stripped) that embeds anywhere: mobile apps, embedded devices, system daemons, game engines, or any language with C FFI.

## Status

Wire-compatible with JS `hyperdht@6.29.1`. Live-tested in both directions on the public network.

| | |
|---|---|
| **Tests** | 731 unit + 6 live, ASAN/UBSan clean |
| **API parity** | Wire-compatible with JS `hyperdht@6.29.1`; behavioural parity ~93% and tracked openly in [docs/TODO.md](docs/TODO.md) ([original audit](docs/archive/JS-PARITY-GAPS.md)) |
| **Languages** | C++ / C / Python / Rust / Kotlin (Swift, Go via the C API) |
| **Platforms** | Linux, macOS, Windows, Android, ESP32 |

## Build

```
nix develop && mkdir -p build && cd build && cmake .. -G Ninja && ninja && ctest -L unit
```

Without Nix: install `cmake`, `ninja`, `libsodium`, `libuv`, then the same cmake flow. Docker also works (`docker build -t hyperdht .`). On Windows, use vcpkg for the dependencies and MSVC — CI builds the static and shared variants on every push (`.github/workflows/windows.yml`). See [BUILDING.md](docs/BUILDING.md) for full instructions (Linux, macOS, Windows, Docker, linking, troubleshooting).

> **⚠️ libuv 1.51.x required — do not build against libuv 1.52.0/1.52.1.**
> libuv 1.52.0 has a UDP `POLLERR` regression that silently wedges established
> connections on real NAT paths (via libudx's PMTU-probe socket). The flake
> pins `nixos-25.11` (libuv 1.51) deliberately. Building on `nixos-26.05` /
> libuv 1.52 requires the override in
> [`nix/libuv-1.52-udp-pollerr.patch`](nix/libuv-1.52-udp-pollerr.patch).
> Full write-up + upstream status + re-check checklist: [docs/LIBUV-VERSION.md](docs/LIBUV-VERSION.md).

## Documentation

| | |
|---|---|
| [Build instructions](docs/BUILDING.md) | Linux, macOS, Windows, Docker, Nix — deps, compile, link, troubleshoot |
| [C API reference](docs/C-API.md) | 90 functions, opaque-pointer pattern, callback-based async |
| [C++ API reference](docs/CPP-API.md) | RAII wrappers, error codes, single-threaded event loop |
| [Rust wrapper](docs/BUILDING-RUST.md) | `hyperdht-sys` (bindgen) + safe `hyperdht` crate, async/await API |
| [Python examples](examples/python/) | Server, client, holesail tunnel, 22 wrapper tests |
| [ESP32 guide](examples/esp32/) | Build, flash, run HyperDHT on ESP32-S3 (echo server + client) |
| [Android example](examples/android/) | Kotlin/JNI wrapper with echo test app |
| [Wire protocol spec](PROTOCOL.md) | Reverse-engineered from JS, 12 sections |
| [JS name mapping](docs/JS-MAPPING.md) | Side-by-side: `createServer` -> `create_server` -> `hyperdht_server_create` |
| [Worklist](docs/TODO.md) | Single source of truth: open parity findings, hardening, field diagnoses |

## Bootstrap nodes

The public HyperDHT network (same nodes the JS ecosystem uses):

```
node1.hyperdht.org:49737
node2.hyperdht.org:49737
node3.hyperdht.org:49737
```

## Contributing

[docs/TODO.md](docs/TODO.md) is the single source of truth for outstanding work — open JS-parity findings, hardening tasks and field diagnoses, each with the JS `file:line` it diverges from. Every network-behaviour change must be live-tested against a JS peer before landing.

## License

[LGPL-3.0](LICENSE) -- library changes must be shared; downstream apps can use any license.
