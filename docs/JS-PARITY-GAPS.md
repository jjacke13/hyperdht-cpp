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

**§6 polish follow-ups:**
- LAN shortcut: apply `isReserved`-style filter to server addresses before
  matching (currently passes addresses through as-is — worst case is a
  wasted ping to a reserved address).
- LAN shortcut: C++ uses NAT-sampler host vs JS `clientAddress.host` (from
  peerHandshake reply's `to` field). Close enough but not identical.

#### §7 — `DhtOptions` DONE (polish follow-ups remain)

**Present:** `port`, `host`, `bootstrap`, `nodes`, `default_keypair`,
`seed`, `ephemeral`, `connection_keep_alive`, `random_punch_interval`,
`defer_random_punch`, `max_size`, `max_age_ms`, `storage_ttl_ms`.

**§7 polish follow-ups:**
- `connection_keep_alive` is stored + exposed via accessor but NOT
  auto-applied to any `SecretStreamDuplex` — C++ callers wrap streams
  themselves. Follow-up: auto-wrap client streams in a Duplex and pass
  the DHT's default keep-alive at construction.
- `max_age_ms` governs non-storage caches (router forwards, records,
  refreshes, bumps). None of those exist in C++ yet — the field is stored
  for forward compatibility. When those caches land, they should read
  `opts_.max_age_ms`. Storage TTL is controlled independently via
  `storage_ttl_ms` (default 48h, matching JS parity).

---

### MEDIUM — behavior divergence

Listed bottom-up by layer.

#### §13 — Sequential connect across relays   *(HyperDHT-class layer)*

- **JS:** `connect.js:336` uses `Semaphore(2)` to try multiple relays in parallel.
- **C++:** retries relays one at a time. Slower when the first relay is slow. Performance gap, not a bug.

#### §15 — No event-style callbacks for `network-change` / `network-update` / `persistent`   *(HyperDHT-class layer)*

- **JS:** fires three events the app can listen for; servers use `network-change` to refresh their announce.
- **C++:** No hooks. Needs simple callback registration (`on_network_change(cb)`) + detection logic.

#### §16 — `validateLocalAddresses()` and `createRawStream()` not on `HyperDHT`   *(HyperDHT-class layer)*

- Both exposed on JS. `createRawStream` is for advanced users; `validateLocalAddresses` matters for multi-homed servers.

---

### LOW — polish / follow-ups

- **`mutable_get(latest=false)` early termination (§5 follow-up):** JS `mutableGet` returns from the async for-loop on the first valid reply when `opts.latest === false`. C++ still walks the full query and freezes the first result — functionally correct but higher latency. Proper fix requires query-engine early-termination support (tracked as the broader §9 follow-up below).
- **Bootstrap-walk activation (§2 follow-up):** `RpcSocket::bootstrapped_` starts false and ping-and-swap is a no-op until `set_bootstrapped(true)`. Infrastructure is tested in isolation. `HyperDHT::bind()` needs a one-shot `FIND_NODE(our_id)` that flips the flag on success. Until then, full-bucket events silently reject (same as before §2 was added — strictly additive).
- **`hyperdht_api.cpp` refactor (§10 follow-up):** `hyperdht_stream_s` still uses the low-level `SecretStream` primitive with inline glue. `test_live_connect.cpp` already uses `SecretStreamDuplex` — the C FFI can be refactored to match.
- **Query engine minor gaps:** JS `SLOWDOWN_CONCURRENCY = 3` until the first response arrives (cold-cache optimization). C++ has the constant but always uses `DEFAULT_CONCURRENCY = 10`. Also missing: `closest_nodes()` convenience getter, `_addFromTable` retry when > 3/4 of cached nodes fail.
- No static helpers: `HyperDHT::key_pair()`, `HyperDHT::hash()`, `BOOTSTRAP` / `FIREWALL` public constants.
- No `Session` class for batched request cancellation.
- `HANDSHAKE_INITIAL_TIMEOUT` (10s prepunch timeout in JS `server.js:16`) — verify `server_connection.cpp` has an equivalent.
- `HyperDHT::pool()` may be a stub — verify.
- No `relaying` stats (`stats.relaying.{attempts, successes, aborts}`) — only `punch_stats` tracked.

---

## Deferred by design (do NOT fix)

- **Blind relay** (`relayThrough`, `relayToken`, `blind-relay/index.js`, `compact-encoding-bitfield`). ~500 lines. ~5% of connections.
- **§4 `FROM_SECOND_RELAY`** — rare two-hop relay edge case. `src/router.cpp:110-116` comments "NOT yet implemented". Never observed in any real test.
- **`refresh-chain.js`** — unused in hyperdht 6.29.1.

---

## Architectural differences that are FINE (not gaps)

- **`suspend`/`resume`/`destroy` are callback-based, not `async`.** C++ vs JS paradigm. Just finish what JS's async versions finish.
- **No `EventEmitter`.** Fine — explicit callback registration is idiomatic C++. The individual hooks still need to exist (§15).
- **C FFI (`hyperdht.h`) is a deliberate simplification** — some omitted features are intentional.

---

## Recommended order of remaining work

Bottom-up through the stack:

1. **§6 / §7** — Missing option fields. `fastOpen` and `localConnection` first.
2. **§15** — `network-change` callback hooks.
3. **§16** — `createRawStream` / `validateLocalAddresses`.
4. **§13** — parallel relay attempts (performance).
5. **LOW polish** — bootstrap walk, `hyperdht_api.cpp` refactor, query slowdown, static helpers, etc.

---

## How to verify progress

Each item has a JS file:line citation and a C++ location. When implementing:

1. Read the JS reference (`.analysis/js/...`) top-to-bottom.
2. Map every field / method / constant to C++.
3. Live-test both directions (C++ ↔ JS) where applicable.
4. Run `cpp-reviewer` after each non-trivial batch.
5. Move completed items out of this file — the goal is to keep it shrinking.
