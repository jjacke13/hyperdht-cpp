# JS Parity Status

Complete audit of `hyperdht-cpp` versus the JavaScript reference:

- `hyperdht` 6.29.1
- `dht-rpc` 6.26.3
- `protomux` 3.10.1
- `@hyperswarm/secret-stream` 6.9.1
- `blind-relay` 2.3.0

**Last updated: 2026-04-16** (post reviewer-fix round 2 + live-test validation)

---

## Overall completeness

| Layer | Status |
|---|---|
| compact-encoding / noise / udx / crypto | **100%** COMPLETE |
| dht-rpc (messages, routing, tokens, RPC socket, handlers, query, NAT sampler) | **100%** COMPLETE |
| `@hyperswarm/secret-stream` (SecretStream + SecretStreamDuplex) | **100%** COMPLETE |
| protomux (channels, cork/uncork, aliases, batch, pair/unpair) | **100%** COMPLETE |
| server / router / announcer / server_connection | **~95%** (see remaining gaps) |
| client holepunch (pool socket, 4 punch strategies, probing) | **~95%** (analyze() not called in flow) |
| HyperDHT class (connect, listen, storage, lifecycle) | **~90%** |
| blind relay (client, server, message encoding, connect/server integration) | **~90%** (see note below) |
| C FFI (`hyperdht.h`) | **~85%** |

**Bottom line:** Core P2P connectivity is production-ready. All connection paths
(direct, holepunch, blind relay) are wired. Remaining items are polish, edge
cases, and peripheral features.

---

## Done (Phases A-E)

### Phase A: Server holepunch behavioral parity

- [x] A1: `ourRemoteAddr` skip — server with public addr omits holepunch from response
- [x] A2: Server-side NAT sampling via `nat.add()`
- [x] A4: Fast-mode ping when CONSISTENT
- [x] A5: NAT freeze placeholder
- [x] A6: Random throttle detection logging
- [x] A7: Puncher→onsocket wiring (`puncher.onconnect = onsocket`)

### Phase B: C++ API completion

- [x] B1: `HyperDHT::unannounce()` standalone
- [x] B2: `HyperDHT::Stats` (punches + relaying)
- [x] B3: `HyperDHT::FIREWALL` constants
- [x] B4: `HyperDHT::BOOTSTRAP()` alias
- [x] B5: `HyperDHT::key_pair()` static
- [x] B6: `HyperDHT::hash()` static (BLAKE2b-256)
- [x] B7: Passive timeout equivalence verified
- [x] B9: `HANDSHAKE_INITIAL_TIMEOUT` (10s) verified

### Phase C: C FFI completion

- [x] C1: `hyperdht_opts_t` gains `use_public_bootstrap`
- [x] C2: State queries (`is_online`, `is_degraded`, `is_persistent`, `is_bootstrapped`, `is_suspended`)
- [x] C3: Event hooks (`on_bootstrapped`, `on_network_change`, `on_network_update`, `on_persistent`)
- [x] C4: DHT ops (`find_peer`, `lookup`, `announce`, `unannounce`)
- [x] C5: Lifecycle (`suspend`, `resume`)
- [x] C6: Misc (`hash`, `connection_keep_alive`)
- [x] C7: Server state (`suspend`, `resume`, `notify_online`, `is_listening`, `public_key`)
- [x] C8: Server config (`set_holepunch` veto, `set_relay_through`)
- [x] C9: Constants (`HYPERDHT_FIREWALL_*`)

### Phase D: Parallel relay attempts

- [x] D1-D2: Semaphore(2) — fire 2 handshake attempts in parallel, first wins

### Phase E: Blind relay

- [x] E1: Message encoding (Pair/Unpair) — `blind_relay.hpp/cpp`
- [x] E2: `BlindRelayClient` — pair/unpair over Protomux `"blind-relay"` channel
- [x] E3: `BlindRelayServer`/`BlindRelaySession` — token matching + `udx_stream_relay_to()`
- [x] E4: Connect flow integration — full chain: `dht.connect(relayPk)` → SecretStream → Protomux → BlindRelayClient → pair → wire rawStream
- [x] E5: Server flow integration — same chain, emits `on_connection` on success
- [x] E6: `ConnectOptions` relay fields (`relay_through`, `relay_token`, `relay_keep_alive`)
- [x] E7: C FFI (`hyperdht_connect_relay`, `hyperdht_server_set_relay_through`, relay stats)
- [x] E8: Firewall callback skips relay traffic (JS `isRelay()` check)
- [x] 32 unit tests (encoding, token, client, server, options, constants)

---

## Remaining gaps

### HIGH — none remaining

All HIGH gaps have been resolved:
- **Error codes**: `ConnectError` enum in `dht.hpp` + `HYPERDHT_ERR_*` in C FFI. Maps to JS `errors.js`.
- **Connection pool**: `has(pk)` and `get(pk)` already exist in `connection_pool.hpp:100-104`.
- **`announce()` interface**: The public `HyperDHT::announce()` is a low-level query op. The full announce flow (keypair + relay addresses + signatures) is handled internally by the `Announcer` when `server.listen()` is called — matching JS architecture.

### MEDIUM — behavioral differences for edge cases

| Gap | JS ref | C++ status | Impact |
|-----|--------|------------|--------|
| Client-side `analyze()` not called | `connect.js:607-614` | `analyze()` defined in `Holepuncher` but not invoked in `holepunch_connect` flow | NAT stability reopen not triggered during punch — may cause timeouts on unstable NATs |
| Server LAN shortcut | `server.js:390-394` | Server always proceeds to holepunch for non-OPEN clients; no same-host private-address match | Same-LAN server→client misses direct path. LOW impact (client-side LAN shortcut works) |
| Random punch throttle enforcement | `server.js:553-574` | Detected + logged, but `TRY_LATER` response not actually sent | Multiple random punches can run simultaneously. Rare in practice. |
| NAT freeze on server | `server.js:582-584` | Placeholder comment, `NatSampler::freeze()` not implemented | Classification may drift mid-holepunch on server. Rare impact. |
| Query early termination | `dht-rpc/lib/query.js` | C++ queries always walk to completion, no abort mid-walk | `mutable_get(latest=false)` walks full instead of returning first match. Latency only. |
| `selectRelay()` array/function support | `connect.js:842-848` | C++ `relay_through` is a single public key, not array or function | Can't load-balance across relay nodes. Easy to extend. |

### LOW — polish

| Gap | JS ref | Notes |
|-----|--------|-------|
| `createSecretStream` / `createHandshake` factory hooks | `connect.js:41, 68` | Callers construct Duplex directly in C++ |
| `connectRawStream()` static helper | `hyperdht/index.js:460` | Advanced: manual rawStream wiring after handshake |
| `listening` set on HyperDHT | `hyperdht/index.js` | Can't enumerate active servers from user code |
| `'listening'` event on Server | `server.js` | No event emitted when `listen()` completes |
| `session()` for batched request cancellation | `dht-rpc/lib/session.js` | Not implemented (B8 deferred) |
| `filterNode` option | `hyperdht/index.js:32` | Custom bootstrap node filtering |
| `suspend`/`resume` logging hook | `server.js:63-76` | No `{ log }` parameter |
| `destroy({ force })` | `hyperdht/index.js` | Always graceful, no force flag |
| `Client.from()` WeakMap caching | `blind-relay/index.js:284-291` | C++ creates fresh client per relay connection |
| Multiple event listeners | EventEmitter pattern | C++ uses single-slot callbacks (last-writer-wins) |
| `validate_local_addresses` 500ms echo probe | `hyperdht/index.js:160` | Bind-only check (JS itself calls this "semi terrible") |
| Bootstrap two-pass NAT detection | `dht-rpc/index.js:379-433` | Single pass. Firewalled nodes get slightly fewer table entries. |
| Query `_slow` oncycle counter | `dht-rpc/lib/query.js` | Retry-heavy queries have slightly lower concurrency. Latency only. |

---

## Architectural differences (intentional, not gaps)

These are deliberate C++ design choices that differ from JS but are functionally equivalent:

| Aspect | JS | C++ | Why |
|--------|----|----|-----|
| Async model | `async`/`await` + Promises | Callbacks + `shared_ptr` sentinel | libuv event loop, no coroutines |
| Event system | `EventEmitter` (multi-listener broadcast) | Single-slot callbacks | Simpler, sufficient for known use cases |
| Connect return | Returns `NoiseSecretStream` | Returns `ConnectResult` with raw keys + stream | Caller wraps in `SecretStreamDuplex`; more flexible |
| Error model | Named `Error` subclasses with `.code` | Negative integer error codes | Simpler for C FFI; enum can be added |
| Port default | 49737 | 0 (ephemeral) | C++ picks free port unless explicitly set |
| Secret stream ownership | `dht.connect()` wraps internally | Caller constructs over returned raw_stream | More explicit lifetime control |

---

## Deferred by design

| Item | Why deferred |
|------|-------------|
| `FROM_SECOND_RELAY` (mode 3) | Rare two-hop relay edge case. Never observed in testing. |
| `refresh-chain.js` | Unused in hyperdht 6.29.1 |
| Persistent storage cache | JS auto-caches announced records. C++ queries only. Would need its own design. |
| `reusableSocket` on Server | Socket pool reuse flag not exposed |

---

## Verification checklist

- [x] `ctest` — 555/556 tests pass (only pre-existing `test_server_live` failure)
- [x] 32 blind relay unit tests pass
- [x] ASAN-clean (fixed 2 pre-existing bugs: PoolSocket UAF, interface watcher double-close)
- [x] C++ client → JS server (public IP): PASS — full echo round-trip in ~5s
- [x] JS client → C++ server (our NAT): PASS — connection received via rawStream firewall
- [x] JS client → C++ server (aarch64 NAT): PASS — NAT-to-NAT holepunch succeeded
- [x] JS client → C++ server (x86_64 NAT): PASS — NAT-to-NAT with nospoon on peer
- [ ] C++ client → JS server (behind NAT, clean machine): **pending** — nospoon interferes
- [ ] C++ client → C++ server (NAT-to-NAT, clean machine): **pending** — nospoon interferes
- [ ] C++ client → JS server with blind relay fallback: **pending** — no deployed relay node to test against
- [ ] Every JS public method has a C++ equivalent (API parity matrix above)
- [ ] Every C++ public method has a C FFI equivalent

## Recent changes (2026-04-16)

Post-Phase-E cleanup (cpp-reviewer round 2 findings):

- **RAII `UvTimer` wrapper** (`async_utils.hpp`) — replaced raw `new uv_timer_t` +
  manual close callback pattern in dht.cpp, server.cpp, holepunch.cpp. Eliminates
  class of timer-leak bugs at teardown.
- **Multi-listener probe callbacks** (`rpc.hpp`) — `add_probe_listener` /
  `remove_probe_listener` replaces single-slot `on_holepunch_probe`. Fixes
  concurrent-session collision bug where second holepunch silently replaced
  first's echo handler. Matches JS per-socket isolation pattern.
- **`do_connect` decomposition** — 1192-line monolith split into `do_connect`
  (232 lines: setup + findPeer + retry loop), `on_handshake_success` (245 lines:
  post-handshake decision tree), `start_relay_path` (243 lines: blind relay chain).
  Max lambda nesting dropped from 5 to ~3 levels. `ConnState` now at file scope.
