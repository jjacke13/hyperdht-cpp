# JS Parity Gaps & Remaining Work

Actionable audit of what's still missing in `hyperdht-cpp` versus the JavaScript reference stack:

- `hyperdht` 6.29.1
- `dht-rpc` 6.26.3
- `protomux` 3.10.1
- `@hyperswarm/secret-stream` 6.9.1

---

## Pending manual live tests

### §7 DhtOptions — pre-commit validation

- **`seed` → deterministic keypair** — not strictly a live test; unit test
  `SeedDerivesDeterministicKeypair` covers it. But worth running at least
  one live connect where the C++ side uses `DhtOptions::seed` (via
  `CLIENT_SEED=<hex>` env) and verifying the JS server logs the expected
  pubkey.

- **`host = "127.0.0.1"`** — `HostLoopbackBind` test covers this locally.
  No network cross-test required.

- **`nodes` pre-seeding** — needs a live run where `opts.nodes` contains
  a real bootstrap node address. After `bind()`, verify the routing table
  is non-empty before any query kicks in.

- **`random_punch_interval` / `defer_random_punch`** — hard to verify
  without a RANDOM-NAT peer. Debug log (`[hp] random-punch: throttled`)
  should fire when the interval is short enough to trigger during a
  holepunch round. Low priority.

### §6 `local_connection` LAN shortcut — still pending

Requires both ends on the same NAT / public IP (same home network):
  1. `./test_server_live` on machine A
  2. `SERVER_KEY=<hex> LOCAL_CONNECTION=1 ./test_hyperdht --gtest_filter='*LiveConnect*'`
     on machine B (debug build so `[connect] LAN shortcut: target ...`
     is visible)
  3. Confirm either `LAN ping OK` (success) or `LAN ping failed, falling
     back to holepunch` (wiring verified)

---

## Progress by layer

| Layer | Status |
|---|---|
| compact-encoding / noise / udx / crypto primitives | ✓ COMPLETE |
| dht-rpc (messages, routing, tokens, rpc socket, handlers, query, filter, DELAYED_PING, DOWN_HINT gossip, ping-and-swap, adaptive timeout) | ✓ COMPLETE |
| `@hyperswarm/secret-stream` crypto primitive + user-facing `SecretStreamDuplex` | ✓ COMPLETE |
| protomux (channel mux, cork/uncork batching, aliases, destroy, opened, get_last_channel, for_each_channel) | ✓ COMPLETE |
| server / router / announcer / server_connection | ✓ COMPLETE |
| `HyperDHT` class (public API) | ⚠️ partial — §13, §15, §16 (§6, §7 DONE) |
| C FFI (`hyperdht.h`) | ⚠️ partial — §10 refactor follow-up |

**The bottom five layers are done.** Remaining work is strictly at the `HyperDHT` class layer and above.

---

## What blocks a real production DHT client

Nothing functional. All storage methods are now on the public class (§5 done). Remaining items are ergonomics/options (§6, §7), performance (§13), and event hooks (§15, §16).

---

## Remaining work

### HIGH — functional, user-visible

Listed bottom-up by layer.

#### §6 — `ConnectOptions` remaining items   *(HyperDHT-class layer)*

**Present:** `pool`, `reusable_socket`, `holepunch_veto`, `relay_addresses`,
`keypair`, `fast_open`, `local_connection`.

**Not added by design (see header comment in `include/hyperdht/dht.hpp`):**

| Option | JS line | Why skipped |
|---|---|---|
| `relayThrough` / `relayToken` | 40, 87-92, 489-490 | Blind-relay path — tied to §4 which is DEFERRED |
| `relayKeepAlive` | 92 | Only used with `relayThrough`, deferred with it |
| `createSecretStream` | 41, 827-829 | LOW priority factory hook; C FFI doesn't expose |
| `createHandshake` | 68, 823-825 | LOW priority factory hook; direct call is clearer |

**§6 polish follow-ups: verified non-impactful, not implementing** — see
"Deferred as non-impactful" below.

#### §7 — `DhtOptions` DONE

**Present:** `port`, `host`, `bootstrap`, `nodes`, `default_keypair`,
`seed`, `ephemeral`, `connection_keep_alive`, `random_punch_interval`,
`defer_random_punch`, `max_size`, `max_age_ms`, `storage_ttl_ms`.

**Both §7 polish follow-ups are complete** — see "Completed" section.

---

### MEDIUM — behavior divergence

Listed bottom-up by layer.

#### §13 — Sequential connect across relays   *(HyperDHT-class layer)*

- **JS:** `connect.js:336` uses `Semaphore(2)` to try multiple relays in parallel.
- **C++:** retries relays one at a time. Slower when the first relay is slow. Performance gap, not a bug.

#### §15 — network-change / network-update / persistent event hooks — **DONE**

See "Completed" section below.

#### §16 — `validateLocalAddresses()` and `createRawStream()` on `HyperDHT` — **DONE**

See "Completed" section below.

---

### LOW — polish / follow-ups

- **`mutable_get(latest=false)` early termination (§5 follow-up):** JS `mutableGet` returns from the async for-loop on the first valid reply when `opts.latest === false`. C++ still walks the full query and freezes the first result — functionally correct but higher latency. Proper fix requires query-engine early-termination support (tracked as the broader §9 follow-up below).
- **Bootstrap two-pass NAT detection (§2 follow-up):** JS `_bootstrap` runs `_backgroundQuery` up to twice to drive the NAT classification. The second pass is gated on `testNat` being set by the `ondata` PING_NAT echo during the first walk. C++ currently runs exactly one pass — the NAT sampling loop is tied to §15 (`network-change` hooks) which is deferred. Functional consequence: firewalled/random-NAT nodes finish bind with a slightly less-populated routing table than JS peers would at the same point.
- **`_backgroundQuery` dynamic concurrency bump (§2 follow-up):** JS bumps the background query's concurrency back to full when the inflight window is nearly empty (dht-rpc/index.js:973-976). C++ fixes it at `max(2, DEFAULT_CONCURRENCY/8)=2` for the entire walk. Latency only, no correctness impact.
- **Query engine `_slow` oncycle counter (§1 follow-up):** JS `_slow` is bumped every time a request's timeout fires and it's about to retry, and is added to the effective concurrency so slow retries are compensated by extra new sends. Also drives JS's secondary `_readMore` flush path (`_slow === inflight && closestReplies.length >= k`), which lets queries finish without waiting for every retry to exhaust. C++ `RpcSocket::InflightRequest` does not expose a per-retry hook yet — adding `OnCycleCallback` to `request()` overloads + plumbing through `on_request_timeout` would unblock the port. Behavior gap: retry-heavy queries have slightly lower concurrency bandwidth and wait longer before flushing than JS peers. Latency only, correctness unaffected. `read_more()` has an inline comment at `src/query.cpp` pointing at this note.
- **Query engine `_open` bootstrap top-up (§1 follow-up):** JS `_open` tops the frontier up from `dht._resolveBootstrapNodes()` when `seed_from_table()` leaves pending under k. C++ requires callers with a sparse routing table to prime the query by calling `add_bootstrap()` before `start()`. Ergonomics only, no wire gap.
- **`validate_local_addresses` 500 ms self-loopback probe (§16 follow-up):** JS runs a bind-and-echo probe per host (`hyperdht/index.js:135-184`): bind a socket on the candidate host, send a 1-byte UDP packet to itself, wait 500 ms for the echo. C++ does only the bind check — if `udx_socket_bind(host, 0)` succeeds, the address is kept. JS's own comment at `index.js:160` calls the echo "semi terrible heuristic". Consequence: on a machine with a docker bridge that accepts binds but can't route packets, C++ will keep the dead address; a client trying the LAN shortcut will time out on the first probe and fall through to holepunch. Latency-only gap for an uncommon edge case.
- No static helpers: `HyperDHT::key_pair()`, `HyperDHT::hash()`, `BOOTSTRAP` / `FIREWALL` public constants.
- No `Session` class for batched request cancellation.
- `HANDSHAKE_INITIAL_TIMEOUT` (10s prepunch timeout in JS `server.js:16`) — verify `server_connection.cpp` has an equivalent.
- `HyperDHT::pool()` may be a stub — verify.
- No `relaying` stats (`stats.relaying.{attempts, successes, aborts}`) — only `punch_stats` tracked.

---

## Deferred by design (do NOT fix)

- **Blind relay** (`relayThrough`, `relayToken`, `blind-relay/index.js`, `compact-encoding-bitfield`). ~500 lines. ~5% of connections. Note: server sends `relayAddresses` in noisePayload (flag bit 6). For NAT pairs where holepunch fails, blind relay is the fallback JS uses. Promoting this from "deferred" may be needed for certain NAT combinations.
- **§4 `FROM_SECOND_RELAY`** — rare two-hop relay edge case. `src/router.cpp:110-116` comments "NOT yet implemented". Never observed in any real test.
- **`refresh-chain.js`** — unused in hyperdht 6.29.1.

## Deferred as non-impactful (verified safe to skip)

- **§6 LAN shortcut `isReserved` filter** — JS uses `bogon.isReserved` to
  drop multicast / TEST-NET / broadcast entries from the server's advertised
  addresses before `match_address`. C++ doesn't filter. Verified safe:
  (a) `holepunch::local_addresses()` already skips `is_internal` interfaces
  so the client never has loopback in its local list, and
  (b) `match_address` is best-octet-prefix matching — reserved ranges can't
  match real client interfaces anyway. Worst case is a wasted PING to a
  malicious/buggy server's garbage address, which then times out and falls
  through to holepunch. Zero observable bug.
- **§6 LAN shortcut `clientAddress.host` vs NAT sampler** — JS reads
  `clientAddress.host` from THIS peerHandshake response's `to` field
  (`connect.js:234`); C++ reads the NAT sampler's top-voted host instead
  (`dht.cpp:732-735`). Verified functionally equivalent in practice:
  `RpcSocket::handle_message` feeds every response's wire `to` field into
  `NatSampler::add` BEFORE firing `on_response` (`src/rpc.cpp:558-579`),
  and `NatSampler::add` updates `host_` on the very first sample
  (`src/nat_sampler.cpp:115-118`). So by the time the LAN shortcut check
  runs, the sampler has already absorbed the current peer's observation.
  The only divergence is a rare multi-peer edge case where previous
  samples from OTHER peers voted for a different top IP — which falls
  through to holepunch with no correctness impact.

---

## Architectural differences that are FINE (not gaps)

- **`suspend`/`resume`/`destroy` are callback-based, not `async`.** C++ vs JS paradigm. Just finish what JS's async versions finish.
- **No `EventEmitter`.** Fine — explicit callback registration is idiomatic C++. The individual hooks still need to exist (§15).
- **C FFI (`hyperdht.h`) is a deliberate simplification** — some omitted features are intentional.

---

## Recommended order of remaining work

1. **§13** — parallel relay attempts (`Semaphore(2)` in connect.js:336). Performance only, not correctness.
2. **LOW polish** — static helpers (`key_pair()`, `hash()`, `BOOTSTRAP`/`FIREWALL` constants), `Session` class, `HANDSHAKE_INITIAL_TIMEOUT` verify, `relaying` stats.
3. **C FFI follow-ups** — expose `on_network_change`/`on_network_update`/`on_persistent` user callbacks, `create_raw_stream`/`validate_local_addresses` public methods, additional `hyperdht_opts_t` fields (`host`, `seed`, `connection_keep_alive`, `max_age_ms`).

## Future: thorough JS API surface audit

Before declaring "full JS parity", run a systematic top-to-bottom audit of
the **entire public JS API** — every method, property, option, and event
on `HyperDHT`, `Server`, `NoiseSecretStream`, and `dht-rpc/DHT` — and map
each to its C++ / C FFI equivalent. The per-§ approach we've followed so
far was driven by the JS-PARITY-GAPS doc (which was itself an audit from
2026-04-10), but as features land the doc can drift. A fresh pass should:

1. Read `hyperdht/index.js` top-to-bottom, list every `this.xxx` property
   and every `xxx()` method on the prototype.
2. Do the same for `hyperdht/lib/server.js`, `hyperdht/lib/connect.js`,
   `dht-rpc/index.js`, `@hyperswarm/secret-stream/index.js`.
3. For each: mark PRESENT / MISSING / DEFERRED in a table, with the C++
   file:line and a short rationale if deferred.
4. Produce a single-page "API parity matrix" that replaces or supplements
   this doc.

This audit should happen AFTER the manual remote-machine tests confirm
everything works end-to-end, so it's informed by real-world usage rather
than purely spec-driven.

---

## Completed

- **§1 query engine minor gaps** — `closest_nodes()` convenience getter + cold-start slowdown (`_slowdown` + `_fromTable`) + `<K/4`-success table-retry + `add_seed_node()` API for `opts.nodes` / `opts.closestReplies` parity. Fixed a latent `std::optional<uint32_t> == 0` bug that counted every successful reply as an error, and fixed a `push_closest` duplicate-erase bug that removed the wrong element when the duplicate wasn't at the tail. Deferred: the additive `_slow` oncycle counter (requires new RpcSocket hook) and `_open` bootstrap top-up (callers must use `add_bootstrap()`). 5 new GoogleTests + live bootstrap walk against real HyperDHT public nodes (49 replies, 980 closer nodes, 20 final). JS refs: `dht-rpc/lib/query.js:32-36, 47-67, 72-80, 111-120, 122-131, 179, 189-191, 200-205, 259-296, 283-285, 334-351`.
- **§2 bootstrap walk activation** — `HyperDHT::bind()` now kicks off a one-shot `FIND_NODE(our_id)` background walk seeded from `opts.bootstrap` (empty ⇒ no walk, preserving existing offline-test contract). On completion the underlying `RpcSocket` is marked bootstrapped, enabling ping-and-swap, and an optional `on_bootstrapped(cb)` fires. `HyperDHT::refresh()` is wired to `RpcSocket::on_refresh_` so the background tick drives a periodic background query. New `HyperDHT::default_bootstrap_nodes()` returns the 3 public peers. Live smoke test against the real public HyperDHT returns 20 closest replies and populates the routing table with 53 real peers in ~5 seconds. 5 new offline GoogleTests + 1 new live smoke test. JS refs: `dht-rpc/lib/index.js:379-433, 435-438, 965-979`, `hyperdht/lib/constants.js:16-20`.
- **§7 polish (both items)** — (1) `connection_keep_alive` auto-apply: new `HyperDHT::make_duplex_options()` helper returns `DuplexOptions{ keep_alive_ms = connection_keep_alive() }` so callers constructing a `SecretStreamDuplex` from a connect result get the configured value automatically. New `DEFAULT_CONNECTION_KEEP_ALIVE_MS = 5000` constant shared between `DhtOptions::connection_keep_alive` default and `test_live_connect.cpp`. New `SecretStreamDuplex::keep_alive_ms()` / `timeout_ms()` const getters for introspection. (2) `max_age_ms` for announce store: `StorageCacheConfig` gains an `ann_ttl_ms` field (default `announce::DEFAULT_TTL_MS`), `RpcHandlers` stores it in `ann_ttl_ms_` and applies it when populating `PeerAnnouncement.ttl` in `handle_announce`. `HyperDHT` constructor plumbs `opts_.max_age_ms → cache_config.ann_ttl_ms`. Dead `HyperDHT::relay_cache_` member deleted. 3 new GoogleTests (helper round-trip, max_age accessor round-trip, end-to-end announce→stored TTL via real signed ANNOUNCE over loopback). JS refs: `hyperdht/lib/connect.js:41-46`, `hyperdht/index.js:594-620`.
- **§15 network event hooks** — `HyperDHT` gains three single-slot callbacks: `on_network_change`, `on_network_update`, `on_persistent`, plus observables `is_online()`, `is_degraded()`, `is_persistent()`. libudx `udx_interface_event_t` drives network-change detection by polling `uv_interface_addresses` every 5 s, matching JS `udx.watchNetworkInterfaces()`. Health-state transitions (ONLINE/DEGRADED/OFFLINE) are detected by pre/post comparison in `RpcSocket::background_tick` and fire a new `RpcSocket::on_health_change` callback that HyperDHT wires to `fire_network_update()`. `check_persistent()` gained an `if (!ephemeral_) return;` idempotency guard so `force_check_persistent()` is safe to call repeatedly. HyperDHT `fire_network_change` auto-refreshes all listening servers and cascades into `fire_network_update` (JS parity: `dht-rpc/index.js:596-599` emits both events together). `fire_network_update` pokes `notify_online()` on every server if `is_online()`. 4 new GoogleTests + 2 new RpcSocket test hooks (`force_check_persistent`, `force_fire_health_change_for_test`). JS refs: `dht-rpc/index.js:596-599, 870-872, 982-1002`, `hyperdht/index.js:64-75`.
- **§16 `createRawStream()` + `validateLocalAddresses()` + LAN-address advertisement** — `HyperDHT::create_raw_stream()` returns a heap-allocated UDX stream with a random non-zero ID (self-delete close callback, no tracking set). `HyperDHT::validate_local_addresses(list)` filters to bindable hosts only (JS's 500 ms echo probe deferred — tracked in LOW polish). Per-host result cached in `validated_host_cache_`. `HyperDHT::bind()` runs validation once across `holepunch::local_addresses(socket_->port())` using the ACTUAL bound port (not `opts_.port` which may be 0 for ephemeral). `HyperDHT::validated_local_addresses()` exposes the cache. `Server` gains a 3-arg constructor with a non-owning `HyperDHT*` back-pointer; `handle_handshake` now appends `dht_->validated_local_addresses()` to the Noise `addresses4` field when `share_local_address == true`. **This is the functional payoff**: C++ servers now advertise their LAN interfaces, so same-NAT clients can activate the LAN shortcut in `connect.js:234-251` and skip holepunch. Dead `HyperDHT::relay_cache_` already removed in §7 polish; §16's `Server::share_local_address` option finally has an effect. 4 new GoogleTests. JS refs: `hyperdht/index.js:135-184, 460-462`, `hyperdht/lib/server.js:206-208, 270-277`.
- **Holepunch connect flow parity (2026-04-13)** — Major rework of `holepunch_connect` and `do_connect` to match JS connect.js architecture. (1) PEER_HANDSHAKE now sends `firewall` + `addresses4` (validated LAN addresses) matching connect.js:386-394. (2) Holepunch rounds 1+2 sent via pool socket (`pool->request()`) instead of main RPC socket, matching JS updateHolepunch which uses `c.puncher.socket`. (3) Probes sent from pool socket only (not both main+pool), matching holepuncher.js:225. (4) Puncher created before fast-open probe (matching connect.js:258) so probe echoes can be caught. (5) Post-Round1 full-TTL probe to server's pool address (matching probeRound:582-591) — server's puncher echoes it, connecting without holepunch rounds when NAT allows. (6) rawStream created before findPeer (matching connect.js:73) with firewall callback passing `udx_socket_t*`. (7) Pool socket keepalive (`shared_ptr<void>`) flows through `HolepunchResult → ConnectResult → hyperdht_stream_s` to prevent premature socket destruction. (8) Server's `peer_addr` added to `discover_pool_addresses` PING targets to create direct NAT mapping with server. (9) 500ms analyze-equivalent delay before Round 2. (10) Parallel handshake guard (`hs_result.success` check) prevents state overwrite from Semaphore(2) race. (11) Callback copy-before-invoke in PoolSocket probe handler prevents UB. (12) Puncher `destroy()` clears `send_fn/send_ttl_fn/on_connect/on_abort` callbacks after firing abort to break PunchState circular refs. Live-tested: VPS fixture echo round-trip passes. NAT-to-NAT with nospoon VPN running on server fails (environmental, not code — need clean test without nospoon). Known issue: pool keepalive prevents clean process exit on teardown. JS refs: `connect.js:73, 258, 386-394, 505-516, 557, 582-591`, `holepuncher.js:124-128, 225`, `server.js:437`.
- **§2 FFI exposure + §10 hyperdht_api.cpp Duplex refactor** — `hyperdht_opts_t` gains a `use_public_bootstrap` flag (default 0 to preserve offline-test contract). When set, `hyperdht_create()` populates `cpp_opts.bootstrap` from `HyperDHT::default_bootstrap_nodes()` so Python/C FFI users automatically run the §2 bootstrap walk against the public DHT. Plus the entire `hyperdht_stream_s` was refactored from the hand-rolled `SecretStream` + UDX read/write glue (~240 lines) to a thin `SecretStreamDuplex` wrapper (~150 lines, net -30 lines after both changes). The Duplex applies `DhtOptions::connection_keep_alive` automatically via `dht->make_duplex_options()` — **continuous P2P data streams over NAT now stay alive indefinitely instead of dying after ~30 seconds of idle when the NAT pinhole expires**. Per-frame encryption, header exchange, idle timeout, and keep-alive frames all come from the Duplex layer that `test_live_connect.cpp` has been dogfooding. cpp-reviewer flagged 2 false-alarm HIGH issues (close_cb confused with on_ack; double-`udx_stream_connect` that doesn't exist) and 2 real MEDIUM items (dead `owns_raw` field, OOM-leaks-reused-raw — both fixed). 9/9 existing C API tests + 528/528 offline suite pass. JS refs: `hyperdht/lib/connect.js:41-46`.

---

## How to verify progress

Each item has a JS file:line citation and a C++ location. When implementing:

1. Read the JS reference (`.analysis/js/...`) top-to-bottom.
2. Map every field / method / constant to C++.
3. Live-test both directions (C++ ↔ JS) where applicable.
4. Run `cpp-reviewer` after each non-trivial batch.
5. Move completed items out of this file — the goal is to keep it shrinking.
