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
- **pkg-config** — already have `hyperdht.pc.in`; verify install path
- **NixOS module** — ship a `module.nix` so downstream can `imports = [ hyperdht ];`
- **Docker image** — Alpine-based, statically linked, ~5MB
- **Debian/RPM packages** — via nix2deb or fpm

### 8. Language bindings (beyond C FFI)

The C FFI surface (76 fns as of commit 41ff514) is now considered
production-ready for mobile/cross-language consumers: no known UAFs,
explicit `_free` contracts on owned handles, idempotent cancel,
ABI-pinned struct layouts, async firewall completion that survives
the callback frame.

#### 8.0. C FFI — remaining exposures

Audit 2026-04-17 against the C++ public surface found a handful of
C++ methods still not exposed through the C FFI. None block any
current consumer (Python wrapper works end-to-end with what's
available today), but a true feature-parity C FFI would cover them.

| C++ method | Priority | Why it matters |
|------------|----------|----------------|
| `HyperDHT::pool()` → connection pool | MEDIUM | Multi-peer apps (nospoon swarm, mobile messaging) want connection dedup. Currently every `connect()` is independent — repeated connects to the same peer build repeated sessions. |
| `HyperDHT::listening()` snapshot | LOW | Enumerate active servers. Wrappers can track their own list instead, but an accessor is cheap. |
| `HyperDHT::lookup_and_unannounce()` combined op | LOW | JS `dht.lookupAndUnannounce()`. Caller can do lookup + unannounce separately today. |
| `HyperDHT::BOOTSTRAP()` getter | TRIVIAL | Returns the 3 canonical seed nodes as a const list. Currently `HYPERDHT_BOOTSTRAP_*` is a constant-based workaround — a proper getter would be ~5 lines. |

Explicitly **NOT** planned for the C FFI (implementation details or
documented non-goals):

| C++ method | Why excluded |
|------------|--------------|
| `HyperDHT::bootstrapper()` static factory | For running a public bootstrap node — niche server-side use case; not a mobile/app concern. |
| `HyperDHT::connect_raw_stream()` static | Advanced multi-stream piggyback — leaks libudx primitives into the C FFI. |
| `HyperDHT::validate_local_addresses()` | JS itself comments this is "semi terrible"; a 500ms echo probe per interface. Rarely needed. |
| `HyperDHT::create_raw_stream()` | Returns a raw `udx_stream_t*` — exposes libudx through the boundary; wrappers should stay above that layer. |
| `rpc::Session` | Batched request cancellation. `hyperdht_query_cancel()` covers the common case (one query at a time); Session is for query-heavy internal code paths. |

What remains is building idiomatic wrappers on top of the current
surface.

- **Python** — ✅ DONE (commit f6cc594). Full parity: 76 FFI
  functions exposed, 4 modules (_ffi, _bindings, _server, __init__),
  22 tests, holesail server live-tested. Remaining: async/await
  support, PEP 517 packaging.
- **Go** — cgo wrapper with goroutine-friendly callbacks
- **Rust** — `hyperdht-sys` crate + safe `hyperdht` wrapper
- **Swift/Kotlin** — for mobile use (mimiclaw, future iOS/Android
  apps). The C FFI was explicitly designed with these consumers in
  mind: `HYPERDHT_PK_SIZE` / `HYPERDHT_HOST_STRIDE` constants, flat
  `char*` out-buffers, explicit struct padding (`_pad0`), completion-
  callback-style async firewall, and `_ex` query cancellation all
  target Swift C-interop / JNI idioms directly.
- **ESP-IDF component wrapper** — wrap the library as a reusable
  ESP-IDF component with a CMakeLists.txt registering the component
  against the IDF build system. Pair with an `HYPERDHT_EMBEDDED=ON`
  CMake option that trims memory-heavy features for the ESP32-S3
  target (8MB PSRAM): shrink the routing table (256 → 64 buckets),
  shrink the congestion window (80 → 16 inflight), strip the
  mutable/immutable storage codecs (device is client-only), and
  lower default buffer sizes. Estimated ~50 lines.

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

### 11. ESP32 / embedded porting

**Goal:** run hyperdht-cpp on ESP32-S3 (and any FreeRTOS + lwIP device)
so that $5 microcontrollers become first-class peers on the HyperDHT
network — no cloud broker, no relay server.

**The one blocker: libuv doesn't run on FreeRTOS.** No existing port
exists. The libuv maintainers rejected an ESP-IDF PR ([#4132](https://github.com/libuv/libuv/discussions/4132))
to avoid ifdef soup. Everything else (libsodium, our C++ code, libudx)
is portable.

**Approach: `libuv-esp32` shim component (~500 lines)**

A standalone ESP-IDF component implementing only the libuv subset that
libudx calls. libudx and hyperdht-cpp compile unmodified.

| libuv function | ESP-IDF equivalent |
|---|---|
| `uv_loop_init` / `uv_run` / `uv_loop_close` | `select()` loop in a FreeRTOS task |
| `uv_udp_init` / `uv_udp_bind` / `uv_udp_send` / `uv_udp_recv_start` | `lwip_socket`, `lwip_sendto`, `lwip_recvfrom` |
| `uv_timer_init` / `uv_timer_start` / `uv_timer_stop` | `xTimerCreate` or `esp_timer` |
| `uv_hrtime` | `esp_timer_get_time() * 1000` (us → ns) |
| `uv_async_send` | self-pipe or `xTaskNotify` to wake the select loop |
| `uv_interface_addresses` | `esp_netif_get_ip_info()` |

NOT needed: filesystem, processes, pipes, TTY, signals, thread pool.

libuv already has a `posix-poll.c` backend (used by QNX, Haiku) that
uses `poll()` instead of `epoll` — this is the template for the FreeRTOS
backend since lwIP's `poll()` works via `select()` internally.

**Memory budget (ESP32-S3, 8MB PSRAM):**

| Component | Full node | Client-only |
|---|---|---|
| Routing table (k=20, 256 buckets) | ~400KB | ~100KB (k=5) |
| Crypto state per connection | ~2KB | ~2KB |
| UDX buffers per stream | ~64KB | ~16KB |
| Code (.text) + libsodium | ~300KB | ~250KB |
| **Total** | **~800KB** | **~400KB** |

A stripped connect-only profile fits in ~400KB — well within the
8MB PSRAM budget. Even 2MB PSRAM devices are viable.

**Compile-time trim knob (`HYPERDHT_EMBEDDED=ON`):**
- Routing table: 256 → 64 buckets, k=20 → k=5
- Congestion window: 80 → 16 inflight
- Strip mutable/immutable storage codecs (client-only)
- Lower default UDX buffer sizes

**Integration pattern (mimiclaw-tested):**

mimiclaw already uses FreeRTOS tasks + queues + lwIP (via
`esp_http_client`). HyperDHT would run as one more task:

```c
xTaskCreatePinnedToCore(hyperdht_task, "dht", 8192, NULL, 5, NULL, 1);

void hyperdht_task(void* arg) {
    uv_loop_t loop;
    uv_loop_init(&loop);
    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    hyperdht_bind(dht, 0);
    uv_run(&loop, UV_RUN_DEFAULT);  // blocks on this core
}
```

Messages flow through the existing message bus (`xQueue`) — same
pattern as the telegram/feishu bot tasks.

**What this enables:**
- **Device-to-device P2P** — two ESP32s find each other on the
  internet via DHT, holepunch through NAT, encrypted channel.
  No server, no MQTT broker.
- **Phone → ESP32 direct** — mobile app (Kotlin/Swift wrapper)
  connects to ESP32 from anywhere. No port forwarding.
- **ESP32 as holesail server** — plug into any network, expose a
  local service (serial, camera, GPIO) over HyperDHT.
- **P2P firmware updates** — one device announces new firmware on
  DHT, others discover and download. No OTA server.
- **Mesh of cheap sensors** — self-organizing, no infrastructure
  beyond the 3 public bootstrap nodes.

**Effort estimate:** ~1 week for the libuv-esp32 shim + build
integration + basic testing on real hardware. The protocol code,
crypto, and C FFI layer are untouched.

---

## Release plan

The low-level systems code is solid. The work in this doc is about
making the library *shippable*, not making it correct.

### Phase 1 — v0.1 beta to nospoon (~3 hours total)

Goal: a known consumer exercising the library in production.

**Blocking:** nothing — Python wrapper is done (commit f6cc594),
holesail live-tested end-to-end with JS client (2026-04-17).

**Must have:**
- 30-min soak test (open a connection, exchange data every 5min,
  verify keepalive + no drift)
- CLAUDE.md documentation pass (update phase table, note the new
  RAII patterns added since)

**Tag v0.1.0.** nospoon integrates, reports real-world issues.

### Phase 2 — v1.0 public release

**Must have before tagging:**
- Address whatever v0.1 consumer finds in production
- Observability hooks (structured logger + metrics)
- Runtime-configurable timeouts
- API stability declaration (C FFI ABI guarantees, semver)
- CHANGELOG.md

**Strong should-have:**
- Fuzzing CI (runs on every push, not ad-hoc)
- aarch64 CI (we build on aarch64 NixOS manually today)
- Clean-machine NAT-to-NAT live test (rules out nospoon interference)
- Full ASAN test suite pass (no hot-path leaks; pre-existing libudx
  teardown leaks documented as acceptable)

**Nice to have:**
- Rate limiting / DoS protection (§5)
- Static analysis CI (clang-tidy, cppcheck)
- Noise implementation crypto audit (§6)
- IPv6 validation (§10)

### Phase 3 — language + platform expansion

Parallel to v1.0, driven by downstream consumer needs:

- **Kotlin / Swift wrappers** for mimiclaw / iOS / Android targets —
  the C FFI was designed for these consumers specifically, but no
  wrappers exist yet.
- **ESP32 porting** via `libuv-esp32` shim + `HYPERDHT_EMBEDDED=ON`
  trim — see §11 for full technical plan.
- **Go / Rust wrappers** (lower priority — no active consumer).
- **Public bootstrap node deployment** (§10 real-world validation).

### What it takes to NOT ship

- ❌ Don't ship if ASAN reports a hot-path leak (every test run, not
  just teardown).
- ❌ Don't ship if the fuzzer finds a new decoder crash.
- ❌ Don't ship if the soak test shows memory growth over 30 min.
- ❌ Don't ship if a live test against JS regresses.

None of these are true today — the tree is in a shippable state
modulo the Phase 1 items above.
