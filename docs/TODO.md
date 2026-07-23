# hyperdht-cpp — Master TODO / Worklist

**Single source of truth for outstanding work.** Everything to do lives here:
the rest of the JS-parity sweep, missing parity features, hardening tasks,
un-audited blind spots, and space for future sweeps. Update this file as work
lands; keep the one-line status snapshot in `CLAUDE.md` pointing here.

Last updated: 2026-07-22.

---

## Status snapshot

- **JS-parity sweep 2026-07-09**: 91 confirmed findings (12 HIGH / 45 MED / 34 LOW).
  **All 12 HIGH closed.** ~86/91 addressed (fixed or accepted-divergence).
  **6 MED/LOW still open** (Section A).
- **2026-07-22 batch** (on main): server-1 (firewall-reject now SILENT — presence
  leak closed), server-2 (holepunch reply deferred past veto+punch(), encrypted
  ABORTED on failure), server-3 (synchronous handshake dedup + duplicate
  queueing), connect-3 (reusableSocket client wiring), connect-4 (route-shortcut
  payload), connect-5 (bogon filter + serverAddress fallback), connect-6 (LAN
  shortcut exclusive, JS trigger via client_address), connect-7 (client
  holepunch veto), announce-4 (record signs empty relayAddresses — client
  independence proven both sides), announce-6 (router FROM_RELAY-only handler
  gate). Suite 702/702; cpp-reviewer SHIP, ASAN/UBSAN clean.
- **2026-07-21 batch** (on main): announce-5, announce-7, server-8, connect-8
  (SECURITY: handshake reply validation + new `Response::remote_addr` source
  check — RPC matched responses by tid only), connect-10 (client relay-chain
  teardown; also broke a shared_ptr cycle that leaked ConnState on dead
  pairings), birthday-win SocketRef keepalive pin (holepunch.cpp:1450
  residual). Suite 684/684 (excl. live); cpp-reviewer SHIP, ASAN/UBSAN clean.
- Prior sweep commits (merged to main 2026-07-11): `f266b35` deps bump,
  `88b8022` compact/routing, `5460cfa` core sweep + relay→direct upgrade,
  `f37ef1d` wrappers, `86353db` docs.
- Detail docs: `docs/PARITY-SWEEP-2026-07-09.md` (FREEZE table + per-subsystem
  notes + REMAINING OPEN), `docs/.parity-sweep-appendix.md` (all 91 with
  JS/C++ file:line), `docs/RELAY-UPGRADE-PORT.md` (#266 port design).

Freeze-ready (fully swept): noise, compact, routing, tokens-nat, messages,
blind-relay, dhtrpc-io, protomux, query, dhtrpc-tick, dht-top. Partial
(HIGHs only): connect, server, router-announce, secret-stream.

---

## A. Open JS-parity findings (6) — the resume worklist

Remaining: connect-9, server-4 (ACCEPT candidate — likely just document),
server-6/9/11, secret-stream connect-1 (deferred, needs live JS cross-test).
Full text + JS/C++ file:line for each is in `docs/.parity-sweep-appendix.md`.

### connect (1 open; done: connect-1..8/10/11)
- [x] **connect-8** — DONE 2026-07-21. Handshake reply now validated
  (mode==REPLY, source-address match via `Response::remote_addr`, version/
  error/udx checks); JS-terminal failures fail the connect with
  `ConnectError::SERVER_ERROR` instead of retrying relays.
- [x] connect-10 — DONE 2026-07-21. 15s timer now tears down the relay chain
  (`abort_relay_chain`), breaking the pair-callback↔ConnState shared_ptr
  cycle; deferred teardown from client-callback frames via 0ms re-arm.
- [x] connect-3 — DONE 2026-07-22. reusableSocket threaded: ConnState + UdxInfo
  advertise flag + route-cache read/write gated on both-sides opt-in.
- [x] connect-4 — DONE 2026-07-22. `build_local_handshake_info` shared by
  fire_handshake and the route shortcut (one payload for all attempts).
- [x] connect-5 — DONE 2026-07-22. `is_bogon`/`is_reserved` (npm bogon port);
  direct paths use first-non-bogon + serverAddress fallback.
- [x] connect-6 — DONE 2026-07-22. LAN shortcut EXCLUSIVE of holepunch, JS
  trigger (`client_address.host == server_address.host`, onlyNonReserved
  filter, ping-fail aborts). NEEDS LIVE LAN VALIDATION (Section C).
- [x] connect-7 — DONE 2026-07-22. `opts.holepunch` veto invoked after probe
  round, before punching; abort maps to HOLEPUNCH_TIMEOUT. Deviation: abort
  is local-only (no ABORTED round to the relay — see Section G).
- [ ] connect-9 — findPeer query not seeded with closestNodes/onlyClosestNodes/retries.

### server (4 open; done: server-1/2/3/5/8)
- [x] server-1 — DONE 2026-07-22. Firewall-rejected handshake now sends NOTHING
  (presence leak closed); rejected session stored only for dedup-silence,
  reaped by the clear-wait timer.
- [x] server-2 — DONE 2026-07-22. Holepunch reply committed only after veto +
  punch()-started; failures send encrypted ABORTED (`encode_abort_reply`).
  Deviation kept: immediate clear_session vs JS ~10s defer (Section G).
- [x] server-3 — DONE 2026-07-22. Dedup entry written same-tick before the
  async firewall dispatch; duplicates queue on `pending_handshakes_` and all
  get the same reply (or silence) on resolve.
- [ ] server-4 — `MAX_PENDING_HANDSHAKES=256` cap silently drops. **ACCEPT
  candidate** (anti-DoS, like the other caps we kept) — likely just document.
- [ ] server-6 — `neverPunch` (`opts.holepunch === false`) not implemented.
- [x] server-8 — DONE 2026-07-21. 15s pairing watchdog (`relay_pending_` +
  `abort_relay`): tears down the relay chain only, session + puncher keep
  running (JS onabort parity); pair-error no longer clears the session.
- [ ] server-9 — server-side same-host LAN match (server.js:414-426) not implemented.
- [ ] server-11 — OPEN-client shortcut targets self-reported `addresses4[0]` with a null socket.

### router-announce (0 open; done: announce-1..7)
- [x] announce-4 — DONE 2026-07-22. Announcer signs/stores empty relayAddresses
  (JS parity); proven no client (JS or C++) reads relays from the record —
  they come from the responding DHT node + the handshake payload. Dead
  re-announce-once machinery removed.
- [x] announce-5 — DONE 2026-07-21. Server-host FROM_SECOND_RELAY reply now
  routed to the embedded relayAddress (first relay), dropped when absent.
- [x] announce-6 — DONE 2026-07-22. Holepunch handler now FROM_RELAY-only with
  the `!peerAddress` drop (router.js:221); FROM_CLIENT/FROM_SERVER route
  through the pure-relay path (self-hosting server reaches its own handler
  via one self-hop, like JS).
- [x] announce-7 — DONE 2026-07-21. `handle_refresh` ports persistent.js
  `_onrefresh`: refresh hashes stored on full announce, preimage verified,
  record re-added, chain rotated. (Latent feature — current JS always sends
  refresh:null.)

### nat-sampler / punch payload (from the 2026-07-22 field diagnosis; see
### docs/FIELD-DIAGNOSIS-2026-07-22.md "Finding B" + "Finding E")
- [x] **Finding E** — DONE 2026-07-22 (uncommitted): announcer `updating_`
  latch → server stopped reannouncing. Root leak: `Query::visit()` didn't
  settle a tid==0 (congestion/closing) request-drop → walk never completed →
  cycle wedged. Fixed the walk drop-settle + added a 60s stuck-cycle watchdog
  on the ping timer. Test `RecoversFromWedgedCycleViaWatchdog` (red-checked).
- [ ] **B1 (NEXT — confirmed field -5 cause)** — NatSampler classifies at
  `sampled_ >= 3` (nat_sampler.cpp:111); `MIN_SAMPLES=4` feeds an `ok` flag
  nobody reads. Three agreeing samples latch CONSISTENT and cannot be demoted.
  Finding D both-ends capture confirmed this is the field `-5` (client ports
  moved within a run yet latched fw=2). Gate verdict on >=4 + let disagreeing
  samples demote. Flips port-varying peers into the wired birthday strategy.
- [ ] **B2** — Round-2 holepunch payload sends ONE address (`our_addr`,
  holepunch.cpp:1880-1885) instead of `nat_sampler().addresses()`; JS sends
  the full set in both rounds (connect.js:567,654,684).
- [ ] **D-secondary** — server NatSampler never evicts stale external
  addresses after a NAT remap (`:62622` lingered next to live `:48008`). Real
  but not a connect blocker; wants an eviction/aging pass.

### secret-stream (1 open)
- [ ] connect-1 (MED) — `connected`/on_connect gated on the REMOTE header +
  local write-ack, not on the LOCAL handshake as in JS (+½–1 RTT to first byte).
  DEFERRED — needs a live JS cross-test, not a batch edit. Design in memory
  `parity_audit_2026_07_08.md` (split is_ready → can_encrypt/can_decrypt).

---

## B. Accepted divergences (do NOT re-flag as bugs)

Kept where C++ is safer/more correct than JS. Documented so the next sweep
doesn't re-report them:
- compact array-length cap 4096 (JS 0x100000) — anti-DoS.
- routing exact-k-closest sort (JS bucket-order early-stop) — strictly more correct.
- blind-relay 30s unpaired-pairing TTL + 1024-pairing cap (JS unbounded) — anti-DoS.
- SocketPool routes cap + GC (JS no cap) — anti-DoS + leak prevention.
- FIND_NODE/DOWN_HINT 1/sec/IP rate limits (JS unbounded).
- ConnectionPool: local Server router entry refreshed, not clobbered (JS
  last-writer-wins would kill our own listener).
- No auto-bootstrap of the public network by default (embedded/library targets
  must not auto-join) — opt in via `default_bootstrap_nodes()`.
- filterNode composes built-in + caller filter (JS discards the caller's).
- C API can't express JS's explicit-ephemeral=true→non-adaptive state.
- Announcer keepalive DRIFT DETECTION (`08e2f47`): pong `to`-field vs stored
  peer_addr triggers an early refresh (rate-limited 10s). JS discards the
  pong body (announcer.js:114-121) and waits out the 5-min reannounce.

---

## C. Needs LIVE validation (user's nospoon / CGNAT phone)

Loopback can't prove these; validate against a real NAT'd JS peer:
- [ ] **Finding A fix (`08e2f47`, 2026-07-22)**: announcer publish-after-settle
  + keepalive drift detection + closestNodes reuse. Retest checklist in
  `docs/FIELD-DIAGNOSIS-2026-07-22.md` — key test: disconnect → IMMEDIATE
  reconnect repeatedly across >10 min, expect success at every point in the
  announce cycle; watch for `DRIFTED` log lines healing within ~5-10s.
- [ ] Relay→direct upgrade: C++ client rides relay → punch lands → migrates with
  no ETIMEDOUT/-110; relay closed only after provable direct arrival.
- [ ] Server-side migration when a JS client is on relay and the C++ server punches.
- [ ] Holepuncher birthday **win** end-to-end (the pinning residual at
  holepunch.cpp:1450 is FIXED 2026-07-21 — winning `SocketRef` now rides in
  `HolepunchResult.socket_keepalive`); still needs live validation, plus
  server-side birthday stream *completion* (accepts via main-socket firewall,
  not birthday SocketRefs) — THE symmetric-CGNAT-server path.
- [ ] Outgoing request id accepted by JS `validateId` → C++ node appears in JS
  routing tables; bootstrapper works as a real DHT id-holder.
- [ ] TRY_LATER end-to-end (throttled server → client waits 10-20s → completes).
- [ ] LAN same-NAT shortcut (connect-6, 2026-07-22): now EXCLUSIVE of holepunch
  — verify a real same-LAN connect still succeeds and a failed LAN ping
  aborts cleanly instead of hanging.
- [ ] Empty relayAddresses announce record (announce-4, 2026-07-22): one live
  nospoon round-trip to confirm relay discovery is unaffected end-to-end.

---

## D. Missing JS parity features

- [x] **`changeRemote`** — DONE this session (relay→direct upgrade port: libudx
  `udx_stream_change_remote` wrapped in `relay_upgrade::try_change_remote` +
  Duplex firewall tap + FFI). Covers the path-upgrade case; mid-connection NAT
  remap is out of scope (JS doesn't handle it either — onsocket is one-shot).
- [ ] **`_relayAddressesCache`** — client-side cache of the server's relay
  addresses keyed by server pubkey; skips the findPeer walk on reconnect (saves
  2-3s). JS `hyperdht/index.js:55` (512-entry xache), `connect.js:323,464`.
- [ ] **Read-side backpressure** — we consume every UDX byte immediately; JS
  `rawStream.pause()` (→ `udx_stream_read_stop`) when the read buffer exceeds
  highWaterMark (16KB). Expose pause/resume on SecretStreamDuplex, wire to UDX.
  (Also surfaced in protomux-2: no true read-side pause; buffer+teardown substituted.)
- [ ] **Sleeping-interval wake detection** — VERIFY: the tick rewrite added
  `_onwakeup`/`do_wakeup` + `last_tick_ms_`, but confirm `background_tick`
  actually compares wall-clock gap vs `SLEEPING_INTERVAL` (15s) and triggers the
  wake path (JS `dht-rpc/index.js:764-799`). If the gap comparison isn't wired,
  finish it. See memory `sleeping_interval_gap.md`.
- [ ] **Bootstrap DNS / `ip@host` form** — `_resolveBootstrapNodes` DNS + `@`-host
  fallback absent (IP-only). Callers passing hostnames get nothing.

---

## E. Hardening / verification tasks

- [ ] Full ASAN/valgrind leak sweep of the hot path (known pre-existing teardown
  leaks in libuv/libudx internals — confirm no hot-path leaks; re-verify after
  this session's large diff).
- [ ] Fuzzing: run each `fuzz/` harness (compact, handshake_msg, holepunch_msg,
  messages, noise_payload) ≥30 min under libFuzzer; fix crashes.
- [ ] Stress: 100 concurrent JS clients vs one C++ server; measure success rate +
  memory growth; confirm the probe-listener multi-slot fix holds.
- [ ] Soak: 12h+ connection, data every 5 min; verify NAT pinhole + SecretStream
  keepalive, no drift.

---

## F. Round-2 blind spots (never audited line-by-line)

The 2026-07-09 sweep did NOT run a finder on these. Seed a round-2 sweep here
before any full "core frozen" sign-off:
- [ ] `health.cpp` vs `dht-rpc/lib/health.js` (only checked at the tick call-site).
- [ ] HyperDHT `suspend()`/`resume()` socket rebind + inbound-drop (io.js
  `suspend`/`_rebind`) — rpc-level `stop_tick`/`start_tick` alone don't match.
- [ ] `raw-stream-set.js`, `semaphore.js`, `refresh-chain.js`, `commands.js`,
  the udx wrapper.
- [ ] The entire `ffi_*` layer (the natural freeze boundary — audit last, once
  the core below it is frozen).

---

## G. Small follow-ups

- [ ] `immutable_put`/`mutable_put` result callbacks still swallow the commit
  error (their callback signatures lack an error field — unlike announce/put
  which now report failure via OnDoneCallback).
- [ ] Wrapper build CI: Python/Kotlin/Rust announce-ABI change (`f37ef1d`) is
  UNVERIFIED — no wrapper build in the C++ gate. Add a wrapper-build check.
- [ ] Tighten connect-3 wording in the sweep docs so it's not read as
  "reusableSocket unimplemented" (server + wire are done; client option +
  cache gating are the gap).
- [ ] tick-7: full 2-pass bootstrap + `testNat`-gated second `_updateNetworkState`
  (only the quick-firewall PING_NAT first-responder heuristic landed).
- [ ] holepuncher-4: fresh-socket reopen (currently same-socket resample — recovers
  lossy-UNKNOWN, not the new-NAT-mapping case). Blocked on the upgrade-port
  socket-handle invariant; revisit if a real CGNAT case needs it.
- [ ] Announcer synchronous-cycle-completion parks a stale `current_query_`
  (cpp-reviewer, Finding E batch): if a full-congestion walk completes
  synchronously inside `dht_ops::find_peer()` before the
  `current_query_ = find_peer(...)` assignment, on_done's reset() runs on the
  old (null) value and the finished Query is parked until the next update().
  Benign (destroy() idempotent, self-heals, no leak/UAF), pre-existing pattern
  now reachable via a 2nd trigger. Real fix = defer Query's first dispatch via
  uv_idle; not warranted yet.
- Documented deviations from the 2026-07-22 batch (deliberate, revisit only if
  live behavior warrants):
  - [ ] connect-7 veto abort is local-only; JS also sends an ERROR_ABORTED
    round to the relay. Skipped: PunchState::complete closes the pool socket
    immediately (send race). Add with a deferred close if needed.
  - [ ] `HOLEPUNCH_TIMEOUT` (-6) now covers veto + LAN-ping-fail + passive
    timeout (all JS HOLEPUNCH_ABORTED). Rename would touch FFI/wrappers.
  - [ ] server veto/punch-fail clear_session immediately; JS defers ~10s via
    puncher teardown (pre-existing semantics, kept).
  - [ ] direct branch lacks JS's `relayed && !remoteHolepunchable` gate —
    pre-existing structural divergence; gating would break direct-to-server
    connects (loopback fixtures rely on it).

---

## H. Future work

- [ ] **Round-2 adversarial JS-parity sweep** — re-run `jsparity-adversarial-sweep`
  over the round-1 blind spots (Section F) + a re-diff of the subsystems changed
  heavily this session (rpc, connect, server, holepunch, protomux) to catch
  regressions the per-bucket reviews might have missed. Append new findings to
  Section A.
