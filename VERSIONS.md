# Version Pinning — hyperdht-cpp

This document records the exact versions of all dependencies and reference
implementations used to build and verify hyperdht-cpp. Any upgrade to these
versions requires re-running the cross-tests and fuzzers.

## JS Reference Implementation (wire compatibility target)

These are the JS package versions from which the protocol was reverse-engineered
and against which all cross-tests pass. Source copies in `.analysis/js/` (gitignored).

| Package | Version | Purpose |
|---------|---------|---------|
| **hyperdht** | **6.29.1** | Main reference — all 10 commands |
| dht-rpc | 6.26.3 | DHT RPC layer (messages, routing, relay) |
| compact-encoding | 2.19.0 | Wire format (varint, buffer, arrays) |
| compact-encoding-net | 1.2.0 | IPv4 address encoding |
| noise-handshake | 4.2.0 | Noise IK state machine |
| noise-curve-ed | 2.1.0 | Ed25519 DH curve |
| @hyperswarm/secret-stream | 6.9.1 | XChaCha20-Poly1305 encrypted streams |
| sodium-secretstream | 1.2.0 | Secretstream primitive |
| udx-native | 1.19.2 | Reliable UDP (BBR congestion) |
| protomux | 3.10.1 | Channel multiplexer |
| blind-relay | 1.4.0 | Relay protocol |
| kademlia-routing-table | 1.0.6 | Routing table (k=20, 256 buckets) |
| nat-sampler | 1.0.1 | NAT type detection |

## C/C++ Dependencies

| Library | Version | How provided | Purpose |
|---------|---------|-------------|---------|
| **libudx** | v1.5.3-141-g0420f62 | Git submodule (`deps/libudx`) | Reliable UDP transport |
| **libsodium** | 1.0.20 | System (via Nix/pkg-config) | All cryptography |
| **libuv** | 1.51.0 | System (via Nix/pkg-config) | Event loop |

## Build Toolchain

| Tool | Version | How provided |
|------|---------|-------------|
| GCC | 14.3.0 | Nix devShell (`pkgs.gcc14`) |
| Clang | 21.1.7 | Nix devShell (`pkgs.llvmPackages.clang`) — for fuzzing only |
| CMake | 4.1.2 | Nix devShell |
| Ninja | (bundled with CMake) | Nix devShell |
| GoogleTest | fetched via CMake FetchContent | Build-time download |

## Nix Pin

All system dependencies are pinned via `flake.lock`:
- **nixpkgs**: `nixos-25.11` branch

To reproduce the exact build environment:
```bash
nix develop  # uses flake.lock for reproducible deps
```

## Compatibility Notes

- **hyperdht 6.x** is the target. Version 5.x and earlier use different wire formats.
- **libudx**: pinned to a specific commit via git submodule. The API is unstable — any update requires checking `udx_stream_write_t` struct layout and callback signatures.
- **libsodium**: stable API. Versions 1.0.18+ should work (we use `crypto_scalarmult_ed25519_noclamp` which was added in 1.0.18).
- **libuv**: stable API. Versions 1.40+ should work.

## How to Verify

After upgrading any dependency:
1. `ninja && ctest --output-on-failure` — all 311 tests must pass
2. Run ASan build: `cmake -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined" ..` — must be clean
3. Run fuzzers: `./build-fuzz/fuzz_* -max_total_time=60` — no crashes
4. Live cross-test: JS client → C++ server and C++ client → JS server
5. Storage cross-test: C++ mutablePut → JS mutableGet (and reverse)
