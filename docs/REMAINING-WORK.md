# Remaining Work

Tasks to verify / harden the implementation, organized by category and estimated effort.

**Last updated: 2026-05-08** (v0.4.0 — Windows port + CGNAT holepunch + ESP32 single-socket)

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

- ~~**Nospoon coexistence**~~ — **RESOLVED** (v0.3.1). C++ and JS DHT
  instances coexist on the same machine without conflict.

- ~~**Holesail connection latency vs JS**~~ — **RESOLVED** (v0.3.1).
  Root cause was `reusableSocket: false` in handshake payload — JS clients
  couldn't cache UDX routes, so every connection did full holepunch.
  Fixed by enabling `reusableSocket` and wiring it through FFI.

---

## Missing JS parity features

### `changeRemote` — UDX stream remote address migration

JS uses `rawStream.changeRemote(socket, remoteId, port, host)` to
update an existing UDX stream's locked remote address without tearing
down the encrypted channel. The mechanism: udx's `firewall` callback
fires for any traffic arriving from an unrecognized (host, port) on
a stream's ID. JS's `onsocket` handler responds:
- If stream not yet connected → `connect()` (initial path lock)
- If stream already connected → `changeRemote()` (switch to new path)

This handles both:

1. **Path upgrade during initial setup** — connection establishes via
   blind relay first, then holepunch arrives → upgrade to direct path
2. **NAT remap mid-connection** — peer's external (host, port) changes,
   new packets with valid stream ID trigger firewall callback →
   switch to the new address without dropping the connection

libudx has `udx_stream_change_remote()` natively. Work needed:
- Wrap `udx_stream_change_remote()` in our SecretStreamDuplex (~10 lines)
- Add to C FFI (~15 lines)
- Wire the firewall callback to detect new remotes and call it (~30 lines)
- Python wrapper (~5 lines)

Impact: meaningful for long-lived connections (VPN, persistent streams)
that need to survive NAT mapping changes (router reboot, mobile network
roaming, idle timeout). For short-lived web requests, less critical
since reusableSocket already handles fast reconnect.

JS: `udx-native/lib/stream.js:184`, called from `connect.js:457` and
`server.js:323` (both inside `onsocket` which fires from the rawStream
firewall callback when a new remote sends valid traffic).

### `_relayAddressesCache` — client-side relay address cache

After the first successful connection, JS caches the server's relay
addresses (the 3 DHT nodes that store the announcement) keyed by server
public key. On reconnect, `dht.connect()` skips the full findPeer walk
and sends PEER_HANDSHAKE directly to the cached relays — saves 2-3
seconds per connection.

JS: `hyperdht/index.js:55` (512-entry xache, no TTL), used in
`connect.js:323` (read) and `connect.js:464` (write).

---

## ESP32 (`HYPERDHT_EMBEDDED`) — known issues

### Birthday-paradox 256-socket OOM risk

The `RANDOM+CONSISTENT` holepunch strategy spawns up to **256
ephemeral `PoolSocket`s** on the CONSISTENT side to brute-force the
RANDOM peer's NAT mapping (`include/hyperdht/holepunch.hpp:130-220`,
`src/holepunch.cpp:745+`). On ESP32-S3 with ~150KB free RAM after
lwIP/wifi, allocating 256 UDP sockets will OOM and crash the device.

**Trigger condition:** ESP32 (CONSISTENT — typical home WiFi) is
asked to punch to a peer on RANDOM/symmetric NAT (CGNAT, some
mobile carriers). Hasn't been hit yet in testing because all ESP32
field tests so far have been:
- same-LAN (LAN shortcut bypasses holepunch entirely), or
- home-WiFi-to-home-WiFi (CONSISTENT+CONSISTENT, no PoolSockets needed).

**Mitigation options** (pick one before shipping ESP32-on-CGNAT
deployments):
- `#ifdef HYPERDHT_EMBEDDED` cap birthday-paradox count at e.g. 16,
  trade success rate for memory safety
- `#ifdef HYPERDHT_EMBEDDED` skip birthday-paradox entirely → fall
  through to `BlindRelayClient` (still compiled in on EMBEDDED, only
  the relay-server side was excluded in v0.4.0)
- Make `MAX_PUNCH_SOCKETS` runtime-configurable via `DhtOptions` and
  let the ESP32 example set it to a small value

Recommendation: skip birthday-paradox on EMBEDDED, fall through to
BlindRelay. Same memory footprint as steady-state, and BlindRelay
already works for the RANDOM+RANDOM case anyway.

### Max-concurrent-clients cap (TODO — required before multi-client deployments)

Each active **cross-NAT** client connection consumes one fresh
`PoolSocket` (ephemeral UDP socket) on the ESP32 side, on top of the
single main socket. See memory note
`holepunch_uses_fresh_poolsocket.md` for the architecture detail.

ESP32-S3 has **two** stacked ceilings on concurrent clients:

1. **lwIP UDP socket ceiling** — `MEMP_NUM_UDP_PCB` in sdkconfig
   (default 8-16 depending on ESP-IDF version). Hits first if RAM
   budget is generous. Each PoolSocket consumes one PCB.
2. **RAM ceiling** — ~5-10 KB per connection (UDX state +
   SecretStream + Noise + buffers). With ~150 KB free heap, that's
   roughly 10-15 concurrent streams before fragmentation/allocation
   failures dominate.

**Practical cap:**
`max_clients = min(MEMP_NUM_UDP_PCB - reserved_pcbs,
                   free_heap_at_idle / per_conn_RAM_estimate) - safety_margin`
where `reserved_pcbs` covers the ESP32's own single_socket + lwIP
internals (~3-4) and `safety_margin` is a 1-2 connection cushion for
holepunch races. With ESP-IDF defaults that lands around **5-8 max
concurrent cross-NAT clients** before things start failing.

**Implementation TODO:**
- Add a `Server::max_connections` option (default `unlimited` on
  desktop, default `8` or runtime-configurable on EMBEDDED).
- Reject incoming PEER_HANDSHAKE with `OVER_CAPACITY` error when
  `connections_.size() >= max_connections` — fires *before* the
  holepunch path tries to acquire a PoolSocket, avoiding the lwIP
  PCB exhaustion that would manifest as cryptic ENOMEM later.
- Expose via C FFI: `hyperdht_server_set_max_connections(srv, int)`.
- Document in `examples/esp32/README.md` how to bump
  `MEMP_NUM_UDP_PCB` in sdkconfig if the user needs more.
- LAN-shortcut connections do NOT consume a PoolSocket (they ride on
  single_socket). The cap should only count cross-NAT connections.
  Distinguishing requires checking `c.lan` at accept time.

**Why this matters:** without a cap, the 9th simultaneous cross-NAT
client triggers a silent failure mode — `udx_socket_init()` returns
ENOMEM, the holepunch path partially completes, then leaves orphaned
state. Capping at the application layer surfaces a clean
`OVER_CAPACITY` to the connecting peer instead.

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

Implemented in v0.3.1 security audit:
- ~~Max pending handshakes globally~~ — **DONE** (256 cap)
- ~~FIND_NODE per-IP rate limit~~ — **DONE** (1/sec/IP)
- ~~DOWN_HINT per-IP rate limit~~ — **DONE** (1/sec/IP)
- ~~Unbounded collection caps~~ — **DONE** (pending_, seen_, store_, etc.)

Remaining:
- Per-source rate limit on PEER_HANDSHAKE
- Reject handshakes from IPs in a blocklist
- Connection age-out under memory pressure

### 6. Security hardening

Security audit completed v0.3.1 — 62/64 findings fixed:
- ~~Noise crypto~~ — low-order point rejection, key zeroing, nonce guard
- ~~Input validation~~ — varint range checks, safe pointer arithmetic, caps
- ~~UAF/lifecycle~~ — alive_ sentinels, null guards, closed_flag
- ~~FFI boundary~~ — keypair zeroing, double-call protection, return checks
- ~~JNI~~ — global ref tracking, null handle guard, fail-closed firewall

Remaining:
- **Fuzz the wire formats** with sanitizers enabled — AFL++ or libFuzzer
- **Static analysis CI** — clang-tidy, cppcheck
- **Constant-time comparisons** — verify `sodium_memcmp` where needed

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
- **Mobile network test** — 4G/5G NAT behavior verified. v0.3.0 fixed the
  post-persistent echo bug; CGNAT holepunch landed post-v0.3.1 via
  `HandshakeResult::server_address` propagation (relay's fresh observation
  triggers JS server fast-mode punch — see CLAUDE.md gotcha #19).
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
