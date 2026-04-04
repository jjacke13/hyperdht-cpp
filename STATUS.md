# hyperdht-cpp — Status & Roadmap

First wire-compatible non-JS HyperDHT implementation. C++20, single-threaded libuv event loop, all crypto via libsodium. Both directions live-tested against JS HyperDHT on the public network.

## The Numbers

| Metric | Value |
|--------|-------|
| Source files | 25 `.cpp` |
| Headers | 27 `.hpp`/`.h` |
| Test files | 34 `test_*.cpp` + 1 `test_ffi.py` + 7 JS scripts |
| Total C++ lines | ~10,800 |
| Offline tests | 330 passing |
| ASan/UBSan tests | 332 passing (zero memory errors) |
| Fuzz targets | 5 (36M+ runs, zero crashes) |
| Commits | 35 |
| Bugs found/fixed | 72 found, 63 fixed, 9 deferred |
| Python FFI | Proven working (ctypes → libhyperdht.so) |

---

## What's Done

### Implementation Phases (0-7) — ALL COMPLETE

| Phase | Component | Tests | Status |
|-------|-----------|-------|--------|
| 0 | Scaffold (CMake, libudx, GoogleTest) | — | Done |
| 1 | Compact encoding | 43 | Done |
| 2 | UDX transport | 6 | Done |
| 3 | DHT RPC + all sub-components | 68+ | Done |
| 4 | Noise IK handshake | 12 | Done |
| 5 | SecretStream | 7 | Done |
| 6 | Protomux | 14 | Done |
| 7 | Full HyperDHT API (all 11 steps) | ~100 | Done |

### All 10 HyperDHT Commands — ALL COMPLETE

| Command | Client | Server | Cross-tested |
|---------|:------:|:------:|:------------:|
| PEER_HANDSHAKE | Done | Done | Yes |
| PEER_HOLEPUNCH | Done | Done | Yes |
| FIND_PEER | Done | Done | Yes |
| LOOKUP | Done | Done | Yes |
| ANNOUNCE | Done | Done + sig verify | Yes |
| UNANNOUNCE | Done | Done + sig verify | Yes |
| MUTABLE_PUT | Done | Done + sig + seq | Yes |
| MUTABLE_GET | Done | Done | Yes |
| IMMUTABLE_PUT | Done | Done + hash verify | Yes |
| IMMUTABLE_GET | Done | Done | Yes |

### NAT Holepunching

| NAT Combo | Status |
|-----------|--------|
| OPEN + anything | Done |
| CONSISTENT + CONSISTENT | Done |
| CONSISTENT + RANDOM | Done |
| RANDOM + CONSISTENT | Stub (~100 lines to implement) |
| RANDOM + RANDOM | Not started (~500 lines, blind relay) |

### Hardening (Phase A) — COMPLETE

| Task | Status |
|------|--------|
| ASan + UBSan + LeakSanitizer | Done — library clean, 332 tests pass |
| Fuzz 5 decoders (libFuzzer) | Done — 36M+ runs, 1 security bug found+fixed |
| Edge case tests (decoders, tokens, routing) | Done — 23 tests |
| Crypto review (replay, reorder, state machine) | Done — 7 tests |
| Crypto verification (entropy, tamper, keys) | Done — 15 tests |
| Wire compat (round-trip all message types) | Done — 13 tests |
| Stress/lifecycle tests | Manual — to be done as live sessions |
| Extended fuzzing (1h+ runs) | Ongoing — before releases |

### Production Bugs — ALL FIXED

| Bug | Fix | Status |
|-----|-----|--------|
| OOM on storage maps | LRU cache (32K max, 48h TTL, GC timer) | Done |
| Timer use-after-free | Heap-allocate drain_timer_ / bg_timer_ | Done |
| Socket dangling pointer | weak_ptr in commit lambdas | Done |

### Library Packaging (Phase C) — MOSTLY COMPLETE

| Task | Status |
|------|--------|
| C API header (`hyperdht.h`) | Done — all functions with HYPERDHT_API visibility |
| C API implementation (`hyperdht_api.cpp`) | Done — thin shims, reviewed |
| C API tests | Done — 9 tests |
| CMake install + pkg-config | Done — `find_package(hyperdht)` works |
| Shared library (`BUILD_SHARED_LIBS=ON`) | Done — Python FFI proven |
| Nix package (static + shared) | Done — `nix build .#static` / `nix build .#shared` |
| ESP-IDF component | Not started |

### Other Completed Items

| Item | Status |
|------|--------|
| Debug logging (DHT_LOG macro, `-DHYPERDHT_DEBUG=ON`) | Done |
| Hardcoded keys removed from live tests | Done |
| Version pinning (VERSIONS.md + 4-level checklist) | Done |

### Live Cross-Tests (all passing after every change)

| Test | Result |
|------|--------|
| C++ client → JS server (full pipeline) | Working |
| JS client → C++ server (full pipeline) | Working |
| C++ immutablePut → JS immutableGet | Working |
| JS immutablePut → C++ immutableGet | Working |
| C++ mutablePut → JS mutableGet | Working (sig verified) |
| JS mutablePut → C++ mutableGet | Working (sig verified) |
| Python ctypes → libhyperdht.so | Working (keypair, create, bind, destroy) |

---

## What's Remaining

### For Full JS Parity

| # | Item | Effort |
|---|------|--------|
| 1 | RANDOM+CONSISTENT NAT (birthday paradox — 256 sockets) | ~100 lines |
| 2 | RANDOM+RANDOM NAT (blind relay fallback) | ~500 lines |
| 3 | FROM_SECOND_RELAY fix (relayAddress routing) | ~20 lines |
| 4 | Background refresh for stored values | ~100 lines |
| 5 | Relay congestion tracking | ~10 lines |

### Packaging

| # | Item | Effort |
|---|------|--------|
| 6 | ESP-IDF component wrapper + `HYPERDHT_EMBEDDED` flag | ~50 lines |

`HYPERDHT_EMBEDDED=ON` would: reduce routing table (256→64 buckets), shrink congestion window (80→16), strip mutable/immutable storage codecs, lower buffer sizes. Targets ESP32-S3 with 8MB PSRAM.

### Documentation

| # | Item |
|---|------|
| 7 | README.md rewrite (quick start, build, examples) |
| 8 | C API reference |
| 9 | C++ API reference |
| 10 | `DEVELOPMENT.md` — journey document (phases, gotchas, bugs) |
| 11 | Nix/ESP-IDF integration guides |

### Code Quality (from reviews, non-blocking, no security impact)

1. **Holepunch callback API asymmetry** — C++ design choice. The holepunch handler callback returns a fully-encoded `HolepunchMessage`, which the router then decodes and re-encodes with a different mode. The handshake handler returns raw bytes. JS doesn't have this issue — dynamic objects pass through without decode/re-encode. Style/performance only, no protocol impact.

2. **Raw Node* from closest()** — `routing_table.closest()` returns raw pointers into internal storage. JS does the same (returns references to internal objects) but is inherently safe due to garbage collection. In our single-threaded libuv model, the table cannot mutate while we're using the pointers, so this is safe in practice. A ~40 line refactor to return by value would be more idiomatic C++.

3. **Relay sends bypass congestion window** — Identical gap in JS. The JS `router.js` has the same TODO: *"we should add a bunch of rate limits everywhere, especially including here to avoid bad users using a DHT node to relay traffic indiscriminately."* Relay sends are 1 per handshake — negligible volume. A known inherited gap, not a C++-specific issue.

---

## Architecture

```
include/hyperdht/     27 headers
├── hyperdht.h        C API (extern "C") — the FFI surface
├── dht.hpp           HyperDHT main class
├── server.hpp        Server (listen/accept)
├── peer_connect.hpp  PEER_HANDSHAKE (Noise IK via relay)
├── holepunch.hpp     PEER_HOLEPUNCH (NAT traversal)
├── rpc.hpp           DHT RPC socket
├── rpc_handlers.hpp  All 10 command handlers
├── router.hpp        Forward table for relay dispatch
├── announcer.hpp     Periodic re-announcement
├── noise_wrap.hpp    Noise_IK_Ed25519_ChaChaPoly_BLAKE2b
├── secret_stream.hpp XChaCha20-Poly1305 encrypted streams
├── protomux.hpp      Channel multiplexer
├── compact.hpp       Compact encoding (wire format)
├── messages.hpp      DHT message encode/decode
├── lru_cache.hpp     LRU cache with TTL (storage eviction)
├── debug.hpp         DHT_LOG macro (silent by default)
└── ...               routing_table, tokens, query, etc.

src/                  25 source files (~8,200 lines)
test/                 34 test files + 8 scripts (~2,600 lines)
fuzz/                 5 libFuzzer targets
```

## Build Options

```bash
# Default: static library
cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja

# Shared library (for Python/Go/Rust/Swift/Kotlin FFI)
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -G Ninja

# Debug logging enabled
cmake .. -DHYPERDHT_DEBUG=ON -G Ninja

# Tests disabled (library only, faster build)
cmake .. -DHYPERDHT_BUILD_TESTS=OFF -G Ninja

# Nix builds
nix build            # static (default)
nix build .#static   # static
nix build .#shared   # shared (.so)
nix develop          # dev shell with all tools
```

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| libudx | v1.5.3-141-g0420f62 | Reliable UDP (BBR congestion) |
| libsodium | 1.0.20 | All crypto |
| libuv | 1.51.0 | Event loop |

Pinned via `flake.lock` (nixpkgs commit `1073dad2`) and libudx flake input. See `VERSIONS.md` for full version matrix and 4-level verification checklist.

## Timeline

| Date | Milestone |
|------|-----------|
| 2026-03-30 | Project started. Phases 0-1 |
| 2026-03-31 | Phases 2-5 (UDX, RPC, Noise, SecretStream) |
| 2026-04-01 | Phase 3 complete + Phase 6 + Phase 7 Steps 1-8 |
| 2026-04-01 | C++ client → JS server: WORKING |
| 2026-04-03 | JS client → C++ server: WORKING (relay bug fixed) |
| 2026-04-03 | Hardening: ASan/UBSan, 5 fuzzers, crypto review, edge cases |
| 2026-04-03 | Steps 9-10: signature verification + mutable/immutable storage |
| 2026-04-03 | Step 11: C API + CMake install + shared lib + Python FFI |
| 2026-04-04 | Production bug fixes (LRU cache, timer UAF, socket lifetime) |
| 2026-04-04 | Nix package (static + shared), security cleanup |

## Key Protocol Discoveries

1. **Noise curve is Ed25519, not X25519** — DH via SHA512 scalar extraction + noclamp
2. **dht-rpc relay uses REQUEST not RESPONSE** — TID preserved through `req.relay()` chain
3. **has_bytes() integer overflow** — `size_t` addition wraps, bypasses bounds check
4. **Mode constants differed** — C++ `FROM_RELAY=1` vs JS `FROM_RELAY=2`
5. **Announcer must re-announce after relay discovery** — PeerRecord was empty initially

## For Consumers

**nospoon (P2P VPN):** `connect()` and `createServer()` are working. Production-ready for CONSISTENT NAT.

**Language bindings (Python/Go/Rust/Swift/Kotlin):** `nix build .#shared` → link `libhyperdht.so`, include `hyperdht.h`. Proven with Python ctypes.

**ESP32 (mimiclaw):** Needs ESP-IDF component wrapper (item 6). `HYPERDHT_EMBEDDED` flag for reduced footprint.

**Public release:** Implement items 1-2 (NAT strategies), then documentation (items 7-11).
