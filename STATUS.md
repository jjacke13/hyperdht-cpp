# hyperdht-cpp — Status & Roadmap

First wire-compatible non-JS HyperDHT implementation. C++20, single-threaded libuv event loop, all crypto via libsodium. Both directions live-tested against JS HyperDHT on the public network.

## The Numbers

| Metric | Value |
|--------|-------|
| Source files | 25 `.cpp` |
| Headers | 26 `.hpp`/`.h` |
| Test files | 33 `test_*.cpp` + 1 `test_ffi.py` + 7 JS scripts |
| Total C++ lines | ~10,600 |
| Offline tests | 321 passing |
| Fuzz targets | 5 (36M+ runs, zero crashes) |
| Sanitizer status | ASan + UBSan + LeakSanitizer clean |
| Commits | 29 |
| Bugs found/fixed | 69 found, 60 fixed, 9 deferred |
| Python FFI | Proven working (ctypes → libhyperdht.so) |

---

## What's Done

### Implementation Phases (0-7)

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

### All 10 HyperDHT Commands

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

### Hardening (Phase A)

| Task | Status |
|------|--------|
| ASan + UBSan + LeakSanitizer | Done — 6 test bugs fixed, library clean |
| Fuzz 5 decoders (libFuzzer) | Done — 36M+ runs, 1 security bug found+fixed |
| Edge case tests (decoders, tokens, routing) | Done — 23 tests |
| Crypto review (replay, reorder, state machine) | Done — 7 tests |
| Wire compat (round-trip all message types) | Done — 13 tests |
| Crypto verification (entropy, tamper, keys) | Done — 15 tests |
| Stress/lifecycle tests | Deferred to manual live sessions |
| Extended fuzzing (1h+ runs) | Ongoing — before releases |

### Library Packaging (Phase C)

| Task | Status |
|------|--------|
| C API header (`hyperdht.h`) | Done — 230 lines, all functions |
| C API implementation (`hyperdht_api.cpp`) | Done — 260 lines |
| C API tests | Done — 9 tests |
| CMake install + pkg-config | Done — `find_package(hyperdht)` works |
| Shared library (`BUILD_SHARED_LIBS=ON`) | Done — Python FFI proven |
| Nix package | Not started |
| ESP-IDF component | Not started |

### Live Cross-Tests (all passing)

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

### Must-Fix Before Production

| # | Item | Risk | Effort |
|---|------|------|--------|
| 1 | TTL + size cap on storage maps | OOM on long-running node | ~80 lines |
| 2 | drain_timer_ / punch_timer_ heap-allocate | Crash on early destruction | ~30 lines |
| 3 | announce commit raw socket pointer | Dangling pointer if socket freed | ~20 lines |

### Should-Do for Full JS Parity

| # | Item | Effort |
|---|------|--------|
| 4 | RANDOM+CONSISTENT NAT (birthday paradox) | ~100 lines |
| 5 | RANDOM+RANDOM NAT (blind relay fallback) | ~500 lines |
| 6 | FROM_SECOND_RELAY fix (relayAddress routing) | ~20 lines |
| 7 | Background refresh for stored values | ~100 lines |
| 8 | Relay congestion tracking | ~10 lines |

### Packaging & Distribution

| # | Item | Effort |
|---|------|--------|
| 9 | Nix package (`packages.default` in flake.nix) | ~50 lines |
| 10 | ESP-IDF component wrapper + `HYPERDHT_EMBEDDED` compile flag | ~50 lines |

`HYPERDHT_EMBEDDED=ON` would: reduce routing table (256→64 buckets), shrink congestion window (80→16), strip mutable/immutable storage codecs, lower buffer sizes. Targets ESP32-S3 with 8MB PSRAM.

### Documentation

| # | Item |
|---|------|
| 11 | README.md rewrite (quick start, build, examples) |
| 12 | C API reference |
| 13 | C++ API reference |
| 14 | `DEVELOPMENT.md` — journey document (phases, gotchas, bugs) |
| 15 | Nix/ESP-IDF integration guides |

### Code Quality (from reviews, non-blocking)

- Holepunch callback API asymmetry (encoded msg vs raw bytes)
- Raw Node* from closest() → return by value
- Relay sends bypass congestion window
- Remove `static int req_count` debug counter

---

## Architecture

```
include/hyperdht/     26 headers
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
├── debug.hpp         DHT_LOG macro (silent by default)
└── ...               routing_table, tokens, query, etc.

src/                  25 source files (~8,000 lines)
test/                 33 test files + 8 scripts (~2,600 lines)
fuzz/                 5 libFuzzer targets
```

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| libudx | v1.5.3-141-g0420f62 | Reliable UDP (BBR congestion) |
| libsodium | 1.0.20 | All crypto |
| libuv | 1.51.0 | Event loop |

Pinned via `flake.lock` (nixpkgs commit `1073dad2`). See `VERSIONS.md` for full version matrix and 4-level verification checklist.

## Timeline

| Date | Milestone |
|------|-----------|
| 2026-03-30 | Project started. Phases 0-1 |
| 2026-03-31 | Phases 2-5 (UDX, RPC, Noise, SecretStream) |
| 2026-04-01 | Phase 3 complete + Phase 6 + Phase 7 Steps 1-8 |
| 2026-04-01 | C++ client → JS server: WORKING |
| 2026-04-03 | JS client → C++ server: WORKING (relay bug fixed) |
| 2026-04-03 | Hardening: ASan/UBSan, 5 fuzzers, crypto review |
| 2026-04-03 | Steps 9-10: signature verification + mutable/immutable |
| 2026-04-03 | All 10 commands complete, live cross-tested |
| 2026-04-03 | Step 11: C API + CMake install + shared lib + Python FFI |

## Key Protocol Discoveries

1. **Noise curve is Ed25519, not X25519** — DH via SHA512 scalar extraction + noclamp
2. **dht-rpc relay uses REQUEST not RESPONSE** — TID preserved through `req.relay()` chain
3. **has_bytes() integer overflow** — `size_t` addition wraps, bypasses bounds check
4. **Mode constants differed** — C++ `FROM_RELAY=1` vs JS `FROM_RELAY=2`
5. **Announcer must re-announce after relay discovery** — PeerRecord was empty initially

## For Consumers

**nospoon (P2P VPN):** Items 1-3 from must-fix. `connect()` and `createServer()` are working.

**Language bindings (Python/Go/Rust/Swift/Kotlin):** Link `libhyperdht.so`, include `hyperdht.h`. Proven with Python ctypes.

**ESP32 (mimiclaw):** Items 1-3, then items 9-10. `HYPERDHT_EMBEDDED` flag for reduced footprint.

**Public release:** Items 1-8, then documentation (items 11-15).
