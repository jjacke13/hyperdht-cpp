# Remaining Work

Tasks to verify / harden the implementation, organized by category and estimated effort.

**Last updated: 2026-04-26** (after merging PRs #1-#3 from lukeburns)

---

## Verification tasks (not done yet)

### Low effort (~30 min each)

- **Memory leak check under valgrind/ASAN full suite**
  - Run `ctest` under valgrind with leak detection
  - Already have ASAN build in `build-asan/`. Known: 10600 bytes leaked
    in `test_server` teardown (pre-existing libuv/libudx internals, not
    our code). Verify no leaks in hot path.

- **Documentation pass on `CLAUDE.md`**
  - Update phase status table (phases A-E all done)
  - Document new architecture: ConnState file-scope, on_handshake_success,
    start_relay_path split
  - Note the UvTimer RAII pattern
  - Note the multi-listener probe callback pattern

### Medium effort (~1 hour each)

- **Fuzzing run**
  - `fuzz/` directory has 5 harnesses (compact, handshake_msg,
    holepunch_msg, messages, noise_payload)
  - Run each for 30 minutes under libFuzzer, report coverage
  - Fix any crashes found

- **Stress test — concurrent connects**
  - Spawn 100 JS clients simultaneously against one C++ server
  - Verify probe listener fix actually prevents collision (pre-fix would silently drop)
  - Measure memory growth over the run
  - Measure successful-connect rate

- **Final live test on a clean (non-nospoon) NAT machine**
  - Outstanding item: C++ → C++ NAT-to-NAT from the list in memory
  - Only failure mode we have is environmental (nospoon interference)

### Higher effort (~2+ hours)

- **Soak test — long-running connection**
  - Open a connection, exchange data every 5 minutes, run for 12+ hours
  - Verify NAT pinhole keepalive, SecretStream keepalive, no drift

- **Read-side backpressure (udx_stream_read_stop)**
  - We never pause reading from UDX — every byte is consumed immediately.
    JS does `rawStream.pause()` when the Readable buffer exceeds
    `highWaterMark` (16KB), which calls `udx_stream_read_stop`.
    Without this, a fast sender can grow our internal buffers.
    The pre-connect message queue has a 64-message cap as defense-in-depth,
    but the general data path has no read-side flow control.
    Need: expose pause/resume on SecretStreamDuplex, wire to UDX read stop.

- **Nospoon coexistence**
  - Running nospoon (JS HyperDHT VPN) on the same machine as holesail-py
    prevents remote clients from connecting. Likely socket/port conflict
    or NAT mapping collision when two DHT instances share the same public
    IP. Needs a side-by-side comparison of JS `dht-rpc` socket binding
    (SO_REUSEPORT, port selection) vs our `rpc.cpp`.

- **Holesail connection latency vs JS**
  - Our holesail-py connects noticeably slower than JS holesail to the
    same server. uv_poll integration eliminated polling overhead but the
    gap remains. Needs profiling to identify where the extra latency is:
    bootstrap walk speed, findPeer iterations, handshake relay selection,
    Python ctypes callback overhead, or something else entirely.

---

## Going one step up: "app-level" production readiness

Everything above is "does the systems code work correctly". A real product
shipping this library needs more:

### 1. Observability

Currently: `DHT_LOG` macros at compile time, no runtime control.

- **Structured logging hook** — let the caller inject a logger (syslog, JSON, etc.)
- **Metrics hook** — expose counters for: connects attempted/succeeded/failed per
  path (direct/holepunch/relay), NAT state transitions, probe volume, pool
  socket count, routing table size
- **Tracing hook** — span IDs flowing through async chains for distributed tracing

### 2. Runtime configurability

Currently: most constants are compile-time (`HOLEPUNCH_TIMEOUT_MS`,
`RELAY_TIMEOUT_MS`, etc.)

- Make timeouts, retry counts, concurrency limits runtime-settable via `DhtOptions`
- Environment variable overrides for common tuning knobs
- Runtime config reload (change relay list without restart)

### 3. API stability + versioning

- Declare C FFI ABI stable (or explicitly not-stable) in hyperdht.h
- Add `HYPERDHT_VERSION_MAJOR/MINOR/PATCH` macros
- Semver + CHANGELOG.md
- Deprecation path for API changes

### 4. Error recovery / graceful degradation

- **Reconnect-on-failure** — client policy: exponential backoff, max attempts
- **Circuit breaker** — stop hammering a relay that keeps failing
- **Bootstrap fallback** — if all 3 public bootstrap nodes are down, try cached
  `opts.nodes`
- **Announce retry** — if re-announce fails, back off + retry instead of silently
  losing the record

### 5. Rate limiting / DoS protection

Currently: no inbound connection rate limit. A malicious peer could hammer
PEER_HANDSHAKE and exhaust memory (each handshake allocates session state).

- Per-source rate limit on PEER_HANDSHAKE
- Max pending handshakes globally
- Reject handshakes from IPs in a blocklist
- Connection age-out under memory pressure

### 6. Security hardening

- **Fuzz the wire formats** with sanitizers enabled — AFL++ or libFuzzer
- **Static analysis CI** — clang-tidy, cppcheck, a few rounds of warning triage
- **Audit the Noise implementation** — our custom Noise IK with Ed25519 DH is
  ~300 lines; a cryptographer should eyeball it
- **Constant-time comparisons** — verify all secret-sensitive comparisons use
  `sodium_memcmp` (grep for `memcmp` where both sides are secrets)
- **Input validation at C FFI boundary** — currently permissive; add explicit
  checks for null pointers, size limits, valid UTF-8, etc.

### 7. Packaging + distribution

- **Stable public headers** — move the consumer-facing subset of `include/hyperdht/`
  to `include/hyperdht/public/` with ABI guarantees
- **NixOS module** — ship a `module.nix` so downstream can `imports = [ hyperdht ];`
- **Docker image** — Alpine-based, statically linked, ~5MB
- **Debian/RPM packages** — via nix2deb or fpm

### 8. C FFI remaining exposures

The C FFI surface (84 fns as of 2026-04-26) is production-ready for
mobile/cross-language consumers. Recent additions:

- **PR #3** (lukeburns): `hyperdht_stream_send_udp`,
  `hyperdht_stream_try_send_udp`, `hyperdht_stream_set_on_udp_message`
  — unordered encrypted datagrams. Also fixed `NS_SEND` namespace
  constant (was wrong, broke C++ ↔ JS datagram interop).

Still not exposed:

| C++ method | Priority | Why it matters |
|------------|----------|----------------|
| `HyperDHT::pool()` → connection pool | MEDIUM | Multi-peer apps want connection dedup. Currently every `connect()` is independent. |
| `HyperDHT::listening()` snapshot | LOW | Enumerate active servers. Wrappers can track their own list. |
| `HyperDHT::lookup_and_unannounce()` | LOW | Caller can do lookup + unannounce separately today. |

Explicitly **NOT** planned for the C FFI:

| C++ method | Why excluded |
|------------|--------------|
| `HyperDHT::bootstrapper()` | Niche server-side use case. |
| `HyperDHT::connect_raw_stream()` | Leaks libudx primitives into the C FFI. |
| `HyperDHT::validate_local_addresses()` | JS itself comments this is "semi terrible". |
| `HyperDHT::create_raw_stream()` | Exposes libudx through the boundary. |
| `rpc::Session` | `hyperdht_query_cancel()` covers the common case. |

### 9. Language bindings

- **Python** — Done (commit f6cc594). 84 FFI functions, 4 modules, 22
  tests, holesail live-tested. Remaining: async/await support, PEP 517.
- **Kotlin/Android** — Done. JNI wrapper (`wrappers/kotlin/`), example
  app (`examples/android/`), CI builds arm64 .so. Fixed: JNI global ref
  leaks, threading, lifecycle (commit e821a7c).
- **Go** — cgo wrapper with goroutine-friendly callbacks (no consumer yet)
- **Rust** — `hyperdht-sys` crate + safe `hyperdht` wrapper (no consumer yet)
- **Swift** — for iOS targets; C FFI was designed with Swift C-interop in mind

### 10. Documentation

- **User guide** — getting started, common patterns, common pitfalls
- **API reference** — Doxygen for C++ + public C headers
- **Protocol spec** — already have PROTOCOL.md; cross-link from code
- **Migration guide** — for existing JS HyperDHT users

### 11. Real-world deployment validation

- **Run a public node** — announce on the public DHT, serve real nospoon traffic
- **Multi-region test** — clients in US, EU, Asia connecting through each other
- **Mobile network test** — 4G/5G NAT behavior, esp. carrier-grade NAT
- **IPv6 validation** — protocol has IPv6 fields (`addresses6`); we don't exercise them

---

## Release plan

The low-level systems code is solid. The work in this doc is about
making the library *shippable*, not making it correct.

### Phase 1 — v0.1 beta to nospoon (~3 hours total)

Goal: a known consumer exercising the library in production.

**Active consumer:** Luke Burns (nospoon) is already using the library
and contributing back fixes:
- PR #1: server UAF in blind-relay callback chain
- PR #2: LRU cache gc() leaked entries after get() promotion
- PR #3: datagram C FFI + NS_SEND constant fix

**Must have:**
- 30-min soak test (open a connection, exchange data every 5min,
  verify keepalive + no drift)
- CLAUDE.md documentation pass (update phase table, note the new
  RAII patterns added since)

**Tag v0.1.0.**

### Phase 2 — v1.0 public release

**Must have before tagging:**
- Address whatever v0.1 consumer finds in production
- Observability hooks (structured logger + metrics)
- Runtime-configurable timeouts
- API stability declaration (C FFI ABI guarantees, semver)
- CHANGELOG.md

**Strong should-have:**
- Fuzzing CI (runs on every push, not ad-hoc)
- Clean-machine NAT-to-NAT live test (rules out nospoon interference)
- Full ASAN test suite pass (no hot-path leaks; pre-existing libudx
  teardown leaks documented as acceptable)

**Nice to have:**
- Rate limiting / DoS protection (section 5)
- Static analysis CI (clang-tidy, cppcheck)
- Noise implementation crypto audit (section 6)
- IPv6 validation (section 11)

### Phase 3 — language + platform expansion

Parallel to v1.0, driven by downstream consumer needs:

- **Swift wrapper** for iOS targets — the C FFI was designed for
  Swift C-interop, but no wrapper exists yet.
- **Go / Rust wrappers** (lower priority — no active consumer).
- **Public bootstrap node deployment** (section 11 real-world validation).

### What it takes to NOT ship

- Don't ship if ASAN reports a hot-path leak (every test run, not
  just teardown).
- Don't ship if the fuzzer finds a new decoder crash.
- Don't ship if the soak test shows memory growth over 30 min.
- Don't ship if a live test against JS regresses.

None of these are true today — the tree is in a shippable state
modulo the Phase 1 items above.
