# hyperdht-cpp Roadmap

## Current State (2026-04-03)

- 24 source files, 25 headers, ~9,400 lines C++
- 246 offline tests passing
- Both directions live-tested: C++ client <-> JS server, JS client <-> C++ server
- Phase 7 Steps 1-8 complete (connect + createServer)

## Remaining Work

### Phase A: Hardening & Security Testing

| # | Task | Purpose |
|---|------|---------|
| A1 | Run full suite under ASan + UBSan | Catch use-after-free, buffer overflows, undefined behavior |
| A2 | Run full suite under LeakSanitizer / Valgrind | libuv/libudx async close patterns are leak-prone |
| A3 | Fuzz compact decoders with libFuzzer | Compact encoding parses untrusted network input |
| A4 | Fuzz message decoders (Request, Response) | Message parsing is attack surface |
| A5 | Fuzz Noise recv + handshake msg decoder | Cryptographic input parsing |
| A6 | Edge case tests: zero-length buffers, max varints, truncated messages | Protocol boundary conditions |
| A7 | Edge case tests: duplicate TIDs, expired tokens, full routing table | State machine edge cases |
| A8 | Stress test: rapid connect/disconnect, 100 concurrent connections | Real-world load patterns |
| A9 | Lifecycle tests: destroy mid-handshake, mid-holepunch, mid-announce | Verify no crashes/leaks on teardown |
| A10 | Crypto review: replay/reorder rejection, nonce uniqueness | Cryptographic correctness |
| A11 | Wire compat cross-tests: C++ encode -> JS decode for every message type | Regression guard |

### Phase B: Complete DHT Features (Plan Steps 9-10)

| # | Task | Lines est. |
|---|------|------------|
| B1 | Enhanced ANNOUNCE handlers — verify Ed25519 signatures on announce/unannounce | ~150 |
| B2 | Mutable Put/Get — signed key-value storage with seq ordering | ~150 |
| B3 | Immutable Put/Get — content-addressed storage (BLAKE2b-256(value) == target) | ~100 |
| B4 | Tests for B1-B3 + cross-tests with JS | ~200 |

### Phase C: Library Packaging (Plan Step 11-13)

| # | Task | Lines est. |
|---|------|------------|
| C1 | C API header (`hyperdht.h`) — opaque pointers, callbacks, void* userdata | ~150 |
| C2 | C API implementation (`hyperdht_api.cpp`) — thin shim to C++ objects | ~300 |
| C3 | C API tests (`test_c_api.cpp`) — create/destroy, connect, server through C | ~150 |
| C4 | CMake install rules — targets, headers, pkg-config, cmake package | ~100 |
| C5 | Nix package — `packages.default` in flake.nix (build + install + test) | ~50 |
| C6 | ESP-IDF component wrapper + `HYPERDHT_EMBEDDED` compile flag | ~50 |

### Phase D: Documentation

| # | Document | Content |
|---|----------|---------|
| D1 | `README.md` rewrite | Quick start, build, link, hello-world connect/listen |
| D2 | C API reference | Every function, type, callback documented |
| D3 | C++ API reference | For direct C++ consumers |
| D4 | Examples | Connect to JS server, create server, bidirectional |
| D5 | `DEVELOPMENT.md` | Journey document: phase-by-phase narrative, protocol gotchas, bug archaeology, timeline |
| D6 | Nix/ESP-IDF integration guides | flake input, component setup |

## Library Design Decisions

### Single library, single C header

One `libhyperdht.a` (+ optional `.so`) with `hyperdht.h` as the stable ABI surface.

- C++ consumers: use C++ headers directly
- C/FFI consumers: use `hyperdht.h` only
- ESP32: same library with `HYPERDHT_EMBEDDED=1` compile flag
- Link: `-lhyperdht -ludx -lsodium -luv`

### C API pattern (libuv-style)

```c
hyperdht_t* hyperdht_create(uv_loop_t* loop, const hyperdht_opts_t* opts);
int         hyperdht_connect(hyperdht_t* dht, const uint8_t pk[32], hyperdht_connect_cb cb, void* ud);
int         hyperdht_server_listen(hyperdht_server_t* srv, const hyperdht_keypair_t* kp, ...);
void        hyperdht_destroy(hyperdht_t* dht, hyperdht_close_cb cb);
```

### Static + Shared

Default: static (`libhyperdht.a`). Optional: shared (`libhyperdht.so`) via `BUILD_SHARED_LIBS=ON`.

### Embedded flags

```cmake
option(HYPERDHT_EMBEDDED "Smaller buffers, no mutable/immutable storage" OFF)
```

When ON: reduced routing table (64 buckets), smaller congestion window (16), no mutable/immutable codecs.

## Deferred Items (from code reviews)

- FROM_SECOND_RELAY sends to wrong node (needs relayAddress routing)
- Holepunch callback API asymmetry (encoded msg vs raw bytes)
- Relay sends bypass congestion window
- Raw Node* from closest() (structural refactor of routing_table.hpp)
- drain_timer_ / punch_timer_ UAF on early destruction (heap-allocate timers)
- announce commit lambda captures raw socket pointer

## Suggested Order

1. **Phase A** (hardening) — find bugs in what we have before adding more
2. **Phase B** (features) — complete the DHT storage API
3. **Phase C** (packaging) — C API, CMake install, Nix, ESP-IDF
4. **Phase D** (docs) — last, when API is stable
