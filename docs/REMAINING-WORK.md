# Remaining Work

Tasks to verify / harden the implementation, organized by category and estimated effort.

**Last updated: 2026-04-16** (after Phase E + reviewer-fix round 2)

---

## Verification tasks (not done yet)

### Low effort (~30 min each)

- **Memory leak check under valgrind/ASAN full suite**
  - Run `ctest` under valgrind with leak detection
  - Already have ASAN build in `build-asan/`. Known: teardown leaks in
    libuv loop internals (not our code). Verify no leaks in hot path.

- **Documentation pass on `CLAUDE.md`**
  - Update phase status table (phases A-E all done)
  - Document new architecture: ConnState file-scope, on_handshake_success,
    start_relay_path split
  - Note the UvTimer RAII pattern
  - Note the multi-listener probe callback pattern

- **Python FFI smoke test**
  - `wrappers/python/` exists; verify the C FFI actually works end-to-end
  - Import, create DHT, connect, echo round-trip — same as test_echo_fixture
    but through Python

### Medium effort (~1 hour each)

- **Fuzzing run**
  - `fuzz/` directory has fuzz harnesses for compact, handshake_msg,
    holepunch_msg, noise_payload
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

- **aarch64 CI**
  - We've built on aarch64 NixOS manually. Add to CI when repo is pushed.

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
- **pkg-config** — already have `hyperdht.pc.in`; verify install path
- **NixOS module** — ship a `module.nix` so downstream can `imports = [ hyperdht ];`
- **Docker image** — Alpine-based, statically linked, ~5MB
- **Debian/RPM packages** — via nix2deb or fpm

### 8. Language bindings (beyond C FFI)

- **Python** — existing `wrappers/python` via ctypes; add async/await support,
  context managers, type hints, PEP 517 packaging
- **Go** — cgo wrapper with goroutine-friendly callbacks
- **Rust** — `hyperdht-sys` crate + safe `hyperdht` wrapper
- **Swift/Kotlin** — for mobile use (the target use case for mimiclaw eventually)

### 9. Documentation

- **User guide** — getting started, common patterns, common pitfalls
- **API reference** — Doxygen for C++ + public C headers
- **Protocol spec** — already have PROTOCOL.md; cross-link from code
- **Migration guide** — for existing JS HyperDHT users

### 10. Real-world deployment validation

- **Run a public node** — announce on the public DHT, serve real nospoon traffic
- **Multi-region test** — clients in US, EU, Asia connecting through each other
- **Mobile network test** — 4G/5G NAT behavior, esp. carrier-grade NAT
- **IPv6 validation** — protocol has IPv6 fields (`addresses6`); we don't exercise them

---

## Prioritization

If shipping to nospoon as the first real consumer:

**Must have:**
- Python FFI smoke (confirms bindings work)
- CLAUDE.md documentation pass
- A real soak test (even just 30 minutes of continuous connects)

**Should have before v1.0:**
- Observability hooks (structured logger + metrics)
- Runtime-configurable timeouts
- API stability declaration + semver

**Nice to have:**
- Fuzzing CI
- Rate limiting
- Additional language bindings

The low-level systems code is solid. The work above is all about making it
*shippable as a library* — operational concerns, not correctness concerns.
