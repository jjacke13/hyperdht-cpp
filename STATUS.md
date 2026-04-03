# hyperdht-cpp — Full Status Report (2026-04-03)

## Overview

First wire-compatible non-JS HyperDHT implementation. C++20, single-threaded libuv event loop, all crypto via libsodium. Both directions live-tested against JS HyperDHT on the public network.

## The Numbers

| Metric | Value |
|--------|-------|
| Source files | 24 `.cpp` |
| Headers | 25 `.hpp`/`.h` |
| Test files | 32 `test_*.cpp` + 6 JS helper scripts |
| Total C++ lines | ~10,000 |
| Offline tests | 257 passing |
| Fuzz targets | 5 (36M+ runs, zero crashes) |
| Sanitizer status | ASan + UBSan + LeakSanitizer clean |
| Commits | 16 |
| Bugs found/fixed | 69 found, 60 fixed, 9 deferred |

## Phase Completion

### Phases 0-6 (Foundation) — ALL DONE

| Phase | Component | Status |
|-------|-----------|--------|
| 0 | Scaffold (CMake, libudx, GoogleTest) | Done |
| 1 | Compact encoding (43 tests) | Done |
| 2 | UDX transport (6 tests) | Done |
| 3 | DHT RPC + all sub-components (68+ tests) | Done |
| 4 | Noise IK handshake (12 tests) | Done |
| 5 | SecretStream (7 tests) | Done |
| 6 | Protomux (14 tests) | Done |

### Phase 7 (Full API — 11 Steps) — 10 of 11 DONE

| Step | Component | Status |
|------|-----------|--------|
| 1 | Announce message encoding + constants | Done |
| 2 | Announce signature scheme (Ed25519) | Done |
| 3 | Router (forward table) | Done |
| 4 | Server-side PEER_HANDSHAKE handler | Done |
| 5 | Server-side PEER_HOLEPUNCH handler | Done |
| 6 | Announcer (periodic re-announcement) | Done |
| 7 | Server class + listen() | Done |
| 8 | HyperDHT class + connect() | Done |
| 9 | Enhanced ANNOUNCE/UNANNOUNCE (signature verification) | Done |
| 10 | Mutable/Immutable Put/Get (client + server) | Done |
| 11 | C API (extern "C") | Not started |

### Hardening (Phase A) — PARTIALLY DONE

| Task | Status |
|------|--------|
| A1-A2: ASan + UBSan + LeakSanitizer | Done — 6 test bugs fixed, library clean |
| A3-A5: Fuzz 5 decoders (compact, messages, handshake, holepunch, noise payload) | Done — 1 security bug found and fixed (has_bytes integer overflow) |
| A6-A7: Edge case tests (truncated messages, expired tokens, full table) | Not done |
| A8: Stress test (concurrent connections, rapid connect/disconnect) | Not done |
| A9: Lifecycle tests (destroy mid-operation) | Not done |
| A10: Crypto review (replay/reorder, nonce uniqueness) | Not done |
| A11: Wire compat cross-tests for every message type | Not done |

## All 10 HyperDHT Commands

| Command | Client (send) | Server (handle) | Live cross-tested |
|---------|:---:|:---:|:---:|
| PEER_HANDSHAKE | Yes | Yes | Yes |
| PEER_HOLEPUNCH | Yes | Yes | Yes |
| FIND_PEER | Yes | Yes | Yes |
| LOOKUP | Yes | Yes | Yes |
| ANNOUNCE | Yes | Yes + Ed25519 sig verify | Yes |
| UNANNOUNCE | Yes | Yes + Ed25519 sig verify | Yes |
| MUTABLE_PUT | Yes | Yes + sig verify + seq ordering | Yes |
| MUTABLE_GET | Yes | Yes | Yes |
| IMMUTABLE_PUT | Yes | Yes + content hash verify | Yes |
| IMMUTABLE_GET | Yes | Yes | Yes |

## Live Cross-Tests (all passing)

| Test | Result |
|------|--------|
| C++ client → JS server (full connect pipeline) | Working (~12s) |
| JS client → C++ server (full connect pipeline) | Working |
| C++ immutablePut("hello from C++") → JS immutableGet | Working |
| JS immutablePut("hello from JS") → C++ immutableGet | Working |
| C++ mutablePut(seq=1) → JS mutableGet | Working (signature verified) |
| JS mutablePut(seq=1) → C++ mutableGet | Working (signature verified) |

## What's NOT Done

### MUST-FIX for production

| # | Item | Risk | Effort |
|---|------|------|--------|
| 1 | TTL + size cap on mutable/immutable storage maps | OOM on long-running node — storage grows without limit | ~80 lines (LRU cache) |
| 2 | Heap-allocate drain_timer_ / punch_timer_ | Use-after-free crash if DHT destroyed during active holepunch | ~30 lines |
| 3 | announce commit lambda captures raw socket pointer | Dangling pointer crash if socket destroyed before commit completes | ~20 lines (weak_ptr) |

### SHOULD-DO for production

| # | Item | Why | Effort |
|---|------|-----|--------|
| 4 | C API (hyperdht.h + hyperdht_api.cpp) | Enables Python/Go/Rust/Swift/Kotlin bindings, ESP32 use | ~450 lines |
| 5 | CMake install rules + pkg-config | Lets other CMake/Nix/system projects consume the library | ~100 lines |
| 6 | Edge case + stress tests (A6-A9) | Stress testing, lifecycle teardown tests, boundary conditions | ~300 lines |
| 7 | Background refresh for stored values | Client-side put is one-shot; data disappears after ~48h without refresh | ~100 lines |
| 8 | FROM_SECOND_RELAY fix | Double-relayed connections send reply to wrong node | ~20 lines |
| 9 | Relay congestion tracking | Relay sends bypass congestion window; abuse vector | ~10 lines |

### NICE-TO-HAVE

| # | Item | Why | Effort |
|---|------|-----|--------|
| 10 | Nix package (packages.default in flake.nix) | nix build produces a usable library artifact | ~50 lines |
| 11 | ESP-IDF component wrapper | ESP32 integration with HYPERDHT_EMBEDDED flag | ~50 lines |
| 12 | Documentation (README, C API ref, C++ API ref, journey doc) | Usability for anyone else | ~500 lines |
| 13 | Remove debug fprintf statements | Clean output for production | ~30 min |
| 14 | Holepunch callback API cleanup (encoded msg vs raw bytes) | Consistency with handshake path | ~50 lines |
| 15 | Raw Node* → vector<Node> in closest() | Eliminates fragile pointer if table mutates | ~40 lines |

## Deferred Code Review Items (9 total)

From 7 review rounds (69 bugs found, 60 fixed):

| # | File | Issue | Why Deferred |
|---|------|-------|-------------|
| R3-D1 | rpc.cpp | drain_timer_ UAF on early destruction | Needs heap-allocated timer |
| R3-D2 | holepunch.cpp | punch_timer_ UAF on early destruction | Same pattern |
| R3-D3 | dht_ops.cpp | announce commit captures raw socket pointer | Needs shared_ptr or lifetime contract |
| R4-D1 | routing_table.cpp | closest() returns raw Node* | Safe in single-thread but fragile |
| R7-D1 | router.cpp | FROM_SECOND_RELAY sends to wrong node | Rare edge case |
| R7-D2 | router.cpp | Holepunch callback API asymmetry | Functionally correct |
| R7-D3 | rpc_handlers.cpp | Relay sends bypass congestion window | Low volume |
| LOW-1 | rpc.hpp | Raw owning pointers (libuv async close) | libuv lifetime pattern |
| LOW-2 | compact.cpp | char buf[4] misleading name | Safe, cosmetic |

## Architecture

```
hyperdht-cpp/
├── include/hyperdht/     25 headers (public API)
│   ├── hyperdht.h        C API stub (Step 11)
│   ├── dht.hpp           HyperDHT main class
│   ├── server.hpp        Server (listen/accept)
│   ├── peer_connect.hpp  PEER_HANDSHAKE (Noise IK via relay)
│   ├── holepunch.hpp     PEER_HOLEPUNCH (NAT traversal)
│   ├── rpc.hpp           DHT RPC socket
│   ├── rpc_handlers.hpp  All 10 command handlers
│   ├── router.hpp        Forward table for relay dispatch
│   ├── announcer.hpp     Periodic re-announcement
│   ├── noise_wrap.hpp    Noise_IK_Ed25519_ChaChaPoly_BLAKE2b
│   ├── secret_stream.hpp XChaCha20-Poly1305 streams
│   ├── protomux.hpp      Channel multiplexer
│   ├── compact.hpp       Compact encoding (wire format)
│   ├── messages.hpp      DHT message encode/decode
│   └── ...               (routing_table, tokens, query, etc.)
├── src/                  24 implementation files (~7,500 lines)
├── test/                 32 test files + 6 JS scripts (~2,500 lines)
├── fuzz/                 5 libFuzzer targets
├── deps/libudx/          Git submodule (reliable UDP)
├── PROTOCOL.md           Protocol specification
├── ROADMAP.md            Remaining work plan
└── STATUS.md             This file
```

## Dependencies

| Library | Purpose | License |
|---------|---------|---------|
| libudx | Reliable UDP (BBR congestion) | Apache-2.0 |
| libsodium | All crypto (Ed25519, BLAKE2b, XChaCha20-Poly1305) | ISC |
| libuv | Event loop (required by libudx) | MIT |

## Key Protocol Discoveries

1. **Noise curve is Ed25519, not X25519** — DH via SHA512 scalar extraction + noclamp
2. **dht-rpc relay uses REQUEST not RESPONSE** — TID preserved through req.relay() chain. The critical bug that blocked JS→C++ for days.
3. **has_bytes() integer overflow** — size_t addition wraps around, passing bounds check. Found by fuzzing.
4. **Mode constants differed between C++ and JS** — FROM_RELAY=1 vs FROM_RELAY=2. Silent wire incompatibility.
5. **Announcer must re-announce after relay discovery** — PeerRecord was empty until relays were learned.

## Timeline

| Date | Milestone |
|------|-----------|
| 2026-03-30 | Project started. Phases 0-1 (scaffold + compact encoding) |
| 2026-03-31 | Phases 2-5 (UDX, DHT RPC, Noise IK, SecretStream) |
| 2026-04-01 | Phase 3 completion + Phase 6 (Protomux) + Phase 7 Steps 1-8 |
| 2026-04-01 | C++ client → JS server: WORKING (full pipeline) |
| 2026-04-03 | JS client → C++ server: WORKING (relay bug fixed) |
| 2026-04-03 | Hardening: ASan/UBSan clean, 5 fuzzers (36M runs) |
| 2026-04-03 | Steps 9-10: signature verification + mutable/immutable storage |
| 2026-04-03 | All 10 commands complete, cross-tested both directions |

## For nospoon (P2P VPN)

Items 1-3 from MUST-FIX (~130 lines) are needed. The `connect()` and `createServer()` APIs are fully working. nospoon can use the C++ headers directly — no C API needed for a C++ consumer.

## For public release

Items 1-9 from SHOULD-DO plus item 12 (documentation). The C API (item 4) is essential for language bindings.

## For ESP32 (mimiclaw)

Items 1-5 plus item 11 (ESP-IDF component). The `HYPERDHT_EMBEDDED` compile flag will strip mutable/immutable storage and reduce buffer sizes.
