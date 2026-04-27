# Remaining Work

Tasks to verify / harden the implementation, organized by category and estimated effort.

**Last updated: 2026-04-27** (v0.3.0 release)

---

## Verification tasks (not done yet)

### Low effort (~30 min each)

- **Memory leak check under valgrind/ASAN full suite**
  - Run `ctest` under valgrind with leak detection
  - Already have ASAN build in `build-asan/`. Known: 10600 bytes leaked
    in `test_server` teardown (pre-existing libuv/libudx internals, not
    our code). Verify no leaks in hot path.

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

### Higher effort (~2+ hours)

- **Soak test — long-running connection**
  - Open a connection, exchange data every 5 minutes, run for 12+ hours
  - Verify NAT pinhole keepalive, SecretStream keepalive, no drift

- **Read-side backpressure (udx_stream_read_stop)**
  - We never pause reading from UDX — every byte is consumed immediately.
    JS does `rawStream.pause()` when the Readable buffer exceeds
    `highWaterMark` (16KB), which calls `udx_stream_read_stop`.
    Without this, a fast sender can grow our internal buffers.
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
On Android, `DHT_LOG` routes to logcat via `__android_log_print` when
`HYPERDHT_DEBUG` is defined (added v0.3.0).

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
- **NixOS module** — already ships `module.nix` for holesail + echo-server
- **Docker image** — Alpine-based, statically linked, ~5MB
- **Debian/RPM packages** — via nix2deb or fpm

### 8. C FFI remaining exposures

The C FFI surface (84 fns as of v0.3.0) is production-ready for
mobile/cross-language consumers.

Still not exposed:

| C++ method | Priority | Why it matters |
|------------|----------|----------------|
| `HyperDHT::pool()` → connection pool | MEDIUM | Multi-peer apps want connection dedup. Currently every `connect()` is independent. |
| `HyperDHT::listening()` snapshot | LOW | Enumerate active servers. Wrappers can track their own list. |
| `HyperDHT::lookup_and_unannounce()` | LOW | Caller can do lookup + unannounce separately today. |

### 9. Language bindings

- **Python** — Done (commit f6cc594). 84 FFI functions, 4 modules, 22
  tests, holesail live-tested.
- **Kotlin/Android** — Done. JNI wrapper (`wrappers/kotlin/`), example
  app (`examples/android/`), CI builds arm64 debug+release .so.
  All bugs fixed including post-persistent echo (v0.3.0).
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
- **Mobile network test** — 4G/5G NAT behavior verified (v0.3.0: Android echo
  works over carrier NAT, both ephemeral and persistent server states)
- **IPv6 validation** — protocol has IPv6 fields (`addresses6`); we don't exercise them

---

## Release plan

### v0.1.0 (2026-04-21) — Initial release

- Full protocol implementation (phases 0-7)
- C FFI (76 fns), Python wrapper, live-tested against JS HyperDHT
- 560+ tests, ASAN clean

### v0.2.0 (2026-04-22) — Android + polish

- Kotlin/Android wrapper with JNI bridge
- PoolSocket UAF fix (GrapheneOS hardened_malloc caught it)
- Thread-safe stream ops, connect_and_open_stream C FFI
- CI builds arm64 debug+release JNI .so

### v0.3.0 (2026-04-27) — JS parity + hardening

- **Dual-socket architecture** — client_socket_ (ephemeral) + server_socket_
  (persistent), matching JS dht-rpc io.js. Firewall probe sends PING_NAT
  from client asking remote to reply to server; port-preservation check.
- **ESP32-S3 port** — libuv-esp32 shim, cross-compile, echo test on real hardware
- **External contributions** — 3 PRs from Luke Burns (nospoon):
  server UAF, LRU cache gc leak, datagram FFI + NS_SEND fix
- **Android fixes** — post-persistent echo (loopRunNowait flush),
  UI freeze (close on background thread), debug instrumentation
  (DHT_LOG → logcat on Android)
- **Routing ID parity** — BLAKE2b(host,port) matching JS dht-rpc
- **Server session lifecycle** — prevent resource leak on long-running servers
- C FFI now at 84 functions

### v1.0 — public release (planned)

**Must have:**
- Observability hooks (structured logger + metrics)
- Runtime-configurable timeouts
- API stability declaration (C FFI ABI guarantees, semver)
- CHANGELOG.md

**Strong should-have:**
- Fuzzing CI (runs on every push, not ad-hoc)
- Full ASAN test suite pass
- Stress test (100 concurrent connects)

**Nice to have:**
- Rate limiting / DoS protection
- Static analysis CI (clang-tidy, cppcheck)
- Noise implementation crypto audit
- IPv6 validation
