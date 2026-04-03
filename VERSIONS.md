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
| blind-relay | 1.4.0 | Relay protocol (reference only — not implemented in C++) |
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

## Nix Pin (reproducible builds)

All system dependencies are pinned via `flake.lock` to a specific nixpkgs commit:
- **nixpkgs**: `nixos-25.11` branch, commit `1073dad219cb244572b74da2b20c7fe39cb3fa9e`
- This locks: libsodium 1.0.20, libuv 1.51.0, GCC 14.3.0, Clang 21.1.7, CMake 4.1.2

To reproduce the exact build environment:
```bash
nix develop  # uses flake.lock — identical deps on any machine
```

To update nixpkgs (and potentially change dep versions):
```bash
nix flake update nixpkgs
# Then re-verify: see "How to Verify" below
```

### Without Nix (minimum versions)

| Dependency | Minimum version | Required for |
|-----------|----------------|-------------|
| libsodium | 1.0.18 | `crypto_scalarmult_ed25519_noclamp` |
| libuv | 1.40.0 | Stable UDP/timer API |
| GCC or Clang | GCC 12+ / Clang 15+ | C++20 support |
| CMake | 3.20 | FetchContent for GoogleTest |

## Compatibility Notes

- **hyperdht 6.x** is the target. Version 5.x and earlier use different wire formats.
- **libudx**: pinned to a specific commit via git submodule. The API is unstable — any update requires checking `udx_stream_write_t` struct layout and callback signatures.
- **libsodium**: stable API. Versions 1.0.18+ should work (we use `crypto_scalarmult_ed25519_noclamp` which was added in 1.0.18).
- **libuv**: stable API. Versions 1.40+ should work.

## Verification Checklist

Run this checklist after upgrading ANY dependency. The level of testing
depends on what changed.

### Level 1: Any change (libsodium, libuv, GCC, nixpkgs update)

```bash
# 1. Full test suite (311 tests)
cd build && ninja && ctest --output-on-failure

# 2. ASan + UBSan (catches memory bugs from API changes)
mkdir -p build-asan && cd build-asan
cmake .. -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
         -DCMAKE_C_FLAGS="-fsanitize=address,undefined" \
         -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" -G Ninja
ninja && ctest --output-on-failure

# 3. Fuzz for 60s each (catches parsing regressions)
cmake -S fuzz -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -G Ninja
ninja -C build-fuzz
for f in build-fuzz/fuzz_*; do $f -max_total_time=60; done
```

### Level 2: libudx update (highest risk — unstable API)

All of Level 1, plus:
```bash
# 4. Check struct sizes haven't changed
grep -r "udx_stream_write_sizeof" src/ test/  # verify all calloc sizes
grep -r "udx_socket_send" src/                # verify callback signatures

# 5. UDX-specific tests
./build/test_udx
./build/test_udx_cross    # needs Node.js + udx-native

# 6. Live connection test (UDX stream is the transport)
SERVER_KEY=<key> ./build/test_live_connect
```

### Level 3: JS HyperDHT version update (protocol change risk)

All of Level 1 + Level 2, plus:
```bash
# 7. Re-copy JS sources to .analysis/js/ from updated node_modules

# 8. Check for wire format changes
diff .analysis/js/hyperdht/lib/messages.js <old_version>
diff .analysis/js/dht-rpc/lib/io.js <old_version>

# 9. Regenerate and compare wire test vectors
node test/js/generate_wire_vectors.js > new_vectors.json

# 10. Full live cross-tests (both directions)
# Start C++ server:
./build/test_server_live
# From remote: node test/js/connect_to_cpp_server.js

# Start JS server:
# From remote: node test/js/simple_server.js
SERVER_KEY=<key> ./build/test_live_connect

# 11. Storage cross-tests
./build/test_storage_live --gtest_filter='*CppPut*'
# From remote: node test/js/storage_get.js <hash> <pubkey>
# And reverse direction
```

### Level 4: Pre-release

All of Level 1-3, plus:
```bash
# 12. Extended fuzzing (1 hour each)
for f in build-fuzz/fuzz_*; do $f -max_total_time=3600; done

# 13. Manual stress testing (A8-A9)
# Multiple concurrent JS clients connecting to C++ server
# Kill C++ node mid-connection, verify no crashes
# Let node run for hours, monitor memory with top/htop
```
