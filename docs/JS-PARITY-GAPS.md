# JS Parity Gaps & Remaining Work

Actionable audit of what's still missing in `hyperdht-cpp` versus the JavaScript reference stack:

- `hyperdht` 6.29.1
- `dht-rpc` 6.26.3
- `protomux` 3.10.1
- `@hyperswarm/secret-stream` 6.9.1

---

## Progress by layer

| Layer | Status |
|---|---|
| compact-encoding / noise / udx / crypto primitives | ✓ COMPLETE |
| dht-rpc (messages, routing, tokens, rpc socket, handlers, query, filter, DELAYED_PING, DOWN_HINT gossip, ping-and-swap, adaptive timeout) | ✓ COMPLETE |
| `@hyperswarm/secret-stream` crypto primitive + user-facing `SecretStreamDuplex` | ✓ COMPLETE |
| protomux (channel mux, cork/uncork batching, aliases, destroy, opened, get_last_channel, for_each_channel) | ✓ COMPLETE |
| server / router / announcer / server_connection | ✓ COMPLETE |
| `HyperDHT` class (public API) | ⚠️ partial — §5, §6, §7, §13, §15, §16 |
| C FFI (`hyperdht.h`) | ⚠️ partial — follow-ups on §5, §10 refactor |

**The bottom five layers are done.** Remaining work is strictly at the `HyperDHT` class layer and above.

---

## What blocks a real production DHT client

1. **§5** *(HyperDHT-class layer)* — `mutablePut/Get`, `immutablePut/Get` not exposed on `HyperDHT` (wire + `dht_ops` exist, just not wired to the public class). Biggest functional gap by impact.

Everything else is performance / polish / options.

---

## Remaining work

### HIGH — functional, user-visible

Listed bottom-up by layer.

#### §5 — `mutablePut` / `mutableGet` / `immutablePut` / `immutableGet` not on `HyperDHT`   *(HyperDHT-class layer)*

- **JS:** `hyperdht/index.js:266-390` — 4 public methods.
- **C++:** `include/hyperdht/dht.hpp` public API has `connect`, `create_server`, `find_peer`, `lookup`, `announce`, `lookup_and_unannounce`, `ping`, `pool`, `suspend`, `resume`, `destroy` — but **not** the 4 storage methods.
- **Note:** `CMD_MUTABLE_PUT/GET`, `CMD_IMMUTABLE_PUT/GET` are defined in `messages.hpp` and `dht_ops` has the lower-level implementations. Just needs plumbing to the public class + C FFI.
- **Impact:** biggest user-visible functional gap.

#### §6 — `ConnectOptions` missing JS `connect.js` features   *(HyperDHT-class layer)*

**Currently present:** `pool`, `reusable_socket`, `holepunch_veto`, `cached_relay_addresses`, `udx_socket`.

**Missing:**

| Option | JS line | Purpose | Priority |
|---|---|---|---|
| `relayThrough` / `relayToken` | 40, 87-92, 489-490 | Blind relay fallback | **DEFERRED** |
| `fastOpen` | 269 | Skip probe round for CONSISTENT+CONSISTENT | HIGH |
| `localConnection` | 71 | LAN shortcut toggle | HIGH |
| `relayKeepAlive` | 92 | Keepalive on relay socket | MEDIUM |
| `createSecretStream` | 41, 827-829 | Factory hook for custom stream wrapper | LOW |
| `createHandshake` | 68, 823-825 | Factory hook for custom Noise | LOW |
| Per-connect `keyPair` | 39 | Override default keypair per connect | MEDIUM |

#### §7 — `DhtOptions` missing JS constructor options   *(HyperDHT-class layer)*

**Currently present:** `port`, `bootstrap`, `default_keypair`, `ephemeral`.

**Missing:**

| Option | JS line | Purpose |
|---|---|---|
| `host` | 52 | Bind host |
| `seed` | 36 | Derive keypair from 32-byte seed |
| `nodes` | 30 | Known-good bootstrap hints |
| `connectionKeepAlive` | 38-41 | Per-connection default keepalive |
| `randomPunchInterval` | 60 | Override 20s random-punch throttle |
| `deferRandomPunch` | 57 | Defer random punches |
| `maxSize` / `maxAge` | 598-599 | Storage cache tuning |

The random-punch tuning knobs matter — currently hardcoded in `holepunch.hpp:202-203`.

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

1. **§5** — Expose storage API on `HyperDHT` + C FFI. **Biggest user-visible win.**
2. **§6 / §7** — Missing option fields. `fastOpen` and `localConnection` first.
3. **§15** — `network-change` callback hooks.
4. **§16** — `createRawStream` / `validateLocalAddresses`.
5. **§13** — parallel relay attempts (performance).
6. **LOW polish** — bootstrap walk, `hyperdht_api.cpp` refactor, query slowdown, static helpers, etc.

---

## How to verify progress

Each item has a JS file:line citation and a C++ location. When implementing:

1. Read the JS reference (`.analysis/js/...`) top-to-bottom.
2. Map every field / method / constant to C++.
3. Live-test both directions (C++ ↔ JS) where applicable.
4. Run `cpp-reviewer` after each non-trivial batch.
5. Move completed items out of this file — the goal is to keep it shrinking.
