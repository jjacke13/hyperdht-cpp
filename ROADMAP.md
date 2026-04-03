# hyperdht-cpp Roadmap

## Current State (2026-04-03)

- 24 source files, 25 headers, ~9,400 lines C++
- 246 offline tests passing
- Both directions live-tested: C++ client <-> JS server, JS client <-> C++ server
- Phase 7 Steps 1-8 complete (connect + createServer)

## Remaining Work

### Phase A: Hardening & Security Testing

| # | Task | Status |
|---|------|--------|
| A1 | Run full suite under ASan + UBSan | **Done** — 6 test bugs fixed, library clean |
| A2 | Run full suite under LeakSanitizer / Valgrind | **Done** — bundled with ASan |
| A3 | Fuzz compact decoders with libFuzzer | **Done** — 9.8M runs, 0 crashes |
| A4 | Fuzz message decoders (Request, Response) | **Done** — 7.2M runs, 1 bug found+fixed (has_bytes overflow) |
| A5 | Fuzz Noise recv + handshake/holepunch/noise payload decoders | **Done** — 19.6M runs, 2 crashes (same root cause) |
| A6 | Edge case tests: zero-length buffers, max varints, truncated messages | **Done** — 15 tests |
| A7 | Edge case tests: expired tokens, full routing table, duplicate nodes | **Done** — 8 tests |
| A8 | Stress test: rapid connect/disconnect, concurrent connections | **Manual** — to be done as live testing sessions |
| A9 | Lifecycle tests: destroy mid-handshake, mid-holepunch, mid-announce | **Manual** — to be done as live testing sessions |
| A10 | Crypto review: replay/reorder rejection, nonce uniqueness, state machine | **Done** — 7 tests |
| A11 | Wire compat cross-tests: round-trip for all message types | **Done** — 13 tests |
| A12 | Extended fuzzing: longer runs (hours), new targets as code evolves | **Ongoing** — run periodically before releases |

**A12 (Extended fuzzing):** The initial fuzz runs were 30 seconds each (~36M total iterations). Longer runs find deeper bugs. Before any release or major change, run each fuzzer for at least 1 hour:
```bash
cmake -S fuzz -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -G Ninja
ninja -C build-fuzz
./build-fuzz/fuzz_compact -max_total_time=3600
./build-fuzz/fuzz_messages -max_total_time=3600
./build-fuzz/fuzz_handshake_msg -max_total_time=3600
./build-fuzz/fuzz_holepunch_msg -max_total_time=3600
./build-fuzz/fuzz_noise_payload -max_total_time=3600
```
Add new fuzz targets when new decoders are added (e.g., for the C API input validation).

### Phase B: Complete DHT Features (Plan Steps 9-10)

| # | Task | Status |
|---|------|--------|
| B1 | Enhanced ANNOUNCE handlers — verify Ed25519 signatures | **Done** |
| B2 | Mutable Put/Get — signed key-value storage with seq ordering | **Done** |
| B3 | Immutable Put/Get — content-addressed storage | **Done** |
| B4 | Tests for B1-B3 + cross-tests with JS | **Done** — live cross-tested both directions |

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

## Storage Hardening (must-fix before production)

1. **TTL + size cap on mutable/immutable storage maps** (PRIORITY)
   - JS uses xache: 32K max entries, 48h TTL, LRU eviction
   - Our `unordered_map` has no limit — a long-running node will OOM
   - Fix: add a simple LRU cache with max entries (e.g. 32K) and TTL eviction on a background timer
   - Affects: `mutables_` and `immutables_` in `rpc_handlers.hpp`

2. **Background refresh for stored values**
   - JS peers re-PUT periodically to keep data alive across the network
   - Our client-side put is one-shot — data disappears when the storing nodes evict it
   - Fix: add a refresh timer that re-announces/re-puts values we care about
   - Lower priority than #1 (only matters for long-lived data)

## Missing NAT Strategy

- **RANDOM+CONSISTENT (birthday paradox)**: Open 256 UDP sockets, each with a random port. High probability one matches the remote's consistent mapping. JS does this with `udx.createSocket()` in a loop. ~100 lines using existing UDX wrapper. This completes 4/4 punchable NAT combos (RANDOM+RANDOM is not punchable and requires blind relay, which JS also doesn't fully support).

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
