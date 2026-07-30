# hyperdht-cpp — Master TODO / Worklist

**Single source of truth for outstanding work.** Everything to do lives here:
the rest of the JS-parity sweep, missing parity features, hardening tasks,
un-audited blind spots, and space for future sweeps. Update this file as work
lands; keep the one-line status snapshot in `CLAUDE.md` pointing here.

Last updated: 2026-07-30.

---

## Status snapshot

- **2026-07-30 (later)**: field **Finding M FIXED** — Round 1 now fails over to
  the remaining announce relays instead of treating one dead relay as terminal.
  Deliberately beyond-JS (it is the fix JS's own TODO asks for), capped at
  `PICK_BEST - 1` legs after cpp-reviewer flagged the 128-entry wire cap as a
  retry-amplification stall. 722/722, ASAN clean, SHIP. Round-2 failover (JS's
  second TODO) still open — needs field evidence.
- **2026-07-30**: field **Finding M** logged as the new P0 (Section A) — one
  unreachable relay in the announce is a permanent unrecoverable `-5` because
  neither implementation fails over to `relays[1..n]`. 81/81 repro, reproduced
  on nospoon-JS too, and upstream JS carries the TODO asking for the fix in two
  places. NOT a parity bug — the fix is a deliberate beyond-JS improvement.
- **2026-07-29 (later)**: field Finding J FIXED — `udx_stream_destroy` has no
  `UDX_STREAM_DESTROYING` guard, so a second destroy inside the deferred-close
  window ran `close_stream_internal()` twice and aborted in libuv. Now guarded
  by `udx::destroy_stream_once()`. Reproduced standalone and fixed; 719/719.
  Surfaced a separate pre-existing UAF in `protomux.cpp:242` (logged below).
- **2026-07-29**: field Finding I FIXED — the advertised local-address list was
  a bind-time snapshot, permanently breaking same-LAN connects (`-6`) after any
  interface change; now re-enumerated live per advertisement
  (`HyperDHT::local_addresses_now()`), matching JS `_localAddresses()`. Also
  recorded new field Findings J (HIGH, `uv_close` double-close crash) and K
  (sampling gate), and DEMOTED B1 — Finding L exonerates it as the `-5` cause,
  promoting B2. Suite 718/718.

- **2026-07-28**: C-API SECURITY fix — `hyperdht_server_set_firewall` polarity
  was inverted, so every C-API server with a firewall admitted exactly the
  peers it should reject (`0203820`, found via holesail-cpp; regression tests
  `ServerFfiFirewall.*` red-checked). Raises the priority of the un-audited
  `ffi_*` layer (Section F). Also landed read-side backpressure
  (`hyperdht_stream_pause/resume`) + the `reusable_socket` connect option
  (`a08cade`, Section D). Suite 716/716 unit.
- **Adversarial re-verification 2026-07-26** (16-subsystem Opus workflow):
  claimed status CONFIRMED accurate — zero FALSE_DONE, all 12 HIGH genuinely
  closed, all 6 claimed-open genuinely open, ~93% behavioral parity. Added 1
  HIGH new hazard (server/divergence-1 UAF, NOT fixed), 3 LOW divergences +
  io-6 DONE→PARTIAL, re-tagged 6 stale-OPEN appendix entries as DONE, reframed
  B1 as beyond-JS (not a parity bug). Detail in Section A. messages + protomux
  were UNVERIFIED this pass (finder output-cap failures).
- **JS-parity sweep 2026-07-09**: 91 confirmed findings (12 HIGH / 45 MED / 34 LOW).
  **All 12 HIGH closed.** ~86/91 addressed (fixed or accepted-divergence)
  (io-6 demoted to PARTIAL 2026-07-26 → ~85/91).
  **6 MED/LOW still open** (Section A) + 4 new 2026-07-26 findings.
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

## A. Open JS-parity findings (6 prior + 4 new 2026-07-26) — the resume worklist

Remaining: connect-9, server-4 (ACCEPT candidate — likely just document),
server-6/9/11, secret-stream connect-1 (deferred, needs live JS cross-test).
Full text + JS/C++ file:line for each is in `docs/.parity-sweep-appendix.md`.

### 2026-07-26 adversarial re-verification (workflow) — NEW findings
Full run: 14/16 subsystems (messages + protomux finders failed on output-cap,
UNVERIFIED this pass), 11 material findings, ALL skeptic-confirmed (high conf).
The 12 HIGH and all 6 claimed-open items above survived independently — zero
FALSE_DONE. Behavioral parity estimate ~93%. Net-new, none previously ledgered:
- [ ] **server/divergence-1 (HIGH — potential UAF)** — blind relay starts
  (server.cpp:754) BEFORE the OPEN/direct shortcut returns (JS server.js:394
  returns first). In relayThrough + OPEN-client + pairing-within-15s: the OPEN
  on_socket transfers+nulls conn.raw_stream and returns at server.cpp:1099
  WITHOUT storing the session; the pending relay continuation then
  `udx_stream_connect()`+`emit_connection()` a 2nd time on that now user-owned
  stream (the `connections_.find` guard is empty — session never stored). Fix:
  return before starting relay for OPEN clients, OR cancel the pending relay on
  the OPEN path. Add a relayThrough+OPEN regression test. **NOT YET FIXED.**
- [ ] **connect/divergence-1 (LOW)** — reusableSocket route-shortcut callback
  (connect.cpp:580-591) ignores `hs.terminal`, running a full findPeer walk
  where JS terminates SERVER_ERROR (can return PEER_NOT_FOUND instead). Fix:
  apply the `fire_handshake` terminal check (connect.cpp:315-318). One line.
- [ ] **connect/divergence-2 (LOW)** — step-4 no-holepunch direct-connect
  (connect.cpp:732-753) missing JS's `(relayed && !remoteHolepunchable)` gate
  (connect.js:212) and ordered ahead of passive-wait/LAN; a NON-relayed
  !remoteHolepunchable connect dials server_addr instead of passive-wait /
  CANNOT_HOLEPUNCH. Likely pre-existing. Gate on `relayed` + reorder, or ledger
  as a deliberate divergence.
- [ ] **compact/buffer64k (LOW — doc-only)** — `Buffer::decode` 64KB cap
  (compact.cpp:239-249) vs JS uncapped; fails SAFE (rejects a superset), H12
  anti-DoS. Add a ledger line like compact-2's array cap. No code change.
- [ ] **dhtrpc-io-6 (correction: DONE → PARTIAL)** — a node first seen via an
  external inbound request is never NAT-sampled; JS `_addNode` samples every
  new node once regardless of the `sample` gate (index.js:533-536). Low impact
  (new nodes usually arrive on the active socket). Fix: carry a `sampled` flag
  + sample new nodes once; or accept + downgrade the ledger entry.

**Docs caught up (code was AHEAD):** 6 appendix entries were labeled OPEN but
are FIXED + skeptic-confirmed — now tagged `[DONE — verified 2026-07-26]` in
`docs/.parity-sweep-appendix.md`: holepuncher-1 (birthday wired; symmetric-CGNAT
stream *completion* still live-unvalidated), query-2, dhttop-1, dhttop-2,
dhttop-6, dhttop-8. Headline 86/91 unaffected (already excluded them).

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

### 2026-07-27 field findings (handoff Findings I/J/K/L)

- [x] **Finding I — server advertised a BIND-TIME local-address snapshot.**
  DONE 2026-07-29. `validated_local_addresses_` was assigned only in `bind()`
  (dht.cpp) and never recomputed, so an interface appearing later (DHCP
  completing after an early bind, interface flap) was never advertised for the
  process lifetime → same-LAN clients failed **permanently** with `-6`. Fatal
  rather than degraded because the LAN shortcut is EXCLUSIVE: a bad
  `addresses4` removes the holepunch fallback too (that exclusivity is correct
  parity — connect-6 — so the fix is the address list, NOT the fallback).
  Genuine JS divergence: `_localAddresses()` (server.js:206-208) re-enumerates
  per handshake (server.js:272).
  Fix: new `HyperDHT::local_addresses_now()` — live enumerate →
  `validate_local_addresses()` → refresh snapshot; used by the server handshake
  reply and the client's `build_local_handshake_info` (memoized per `connect()`
  on `ConnState`, matching JS's one-payload-per-connect latch, connect.js:386).
  VERIFIED with a netns repro (interface brought up after bind: before the fix
  the advertised list stayed `127.0.0.1` even after the interface watcher
  polled; after, it tracks the live address). Tests
  `LocalAddressesNowMatchesLiveEnumeration` +
  `LocalAddressesNowRespectsExcludeLocalAddress` (the latter red-checked
  against a naive bypass — live re-enumeration MUST stay routed through
  `validate_local_addresses()` or it resurrects `exclude_local_address()`'d
  hosts, which nospoon relies on to hide its TUN address). 718/718,
  cpp-reviewer SHIP, ASAN clean.
- [x] **Finding J (HIGH — hard crash)** — DONE 2026-07-29. `uv_close`
  double-close abort in `~ConnState` teardown. ROOT CAUSE: `udx_stream_destroy`
  (deps/libudx/src/udx.c:2709) guards on `UDX_STREAM_CLOSED` but NEVER on
  `UDX_STREAM_DESTROYING`. On the slow send path (`uv_udp_try_send` →
  `UV_EAGAIN`, which happens whenever ANY other send is queued on that socket —
  common on the busy shared DHT-RPC socket) `close_stream_internal()` is
  deferred to the send completion, leaving the stream DESTROYING-but-not-CLOSED
  and still CONNECTED for a loop turn. A second destroy in that window queues a
  second destroy packet and runs `close_stream_internal()` TWICE, which
  `uv_close()`s the stream's 5 timers twice → libuv
  `assert(!uv__is_closing(handle))`. libudx's own `assert(CLOSED == 0)` is
  compiled out in Release — exactly where the field crash was seen.
  Fix: `hyperdht::udx::destroy_stream_once()` (include/hyperdht/udx.hpp) skips
  when `DESTROYING|CLOSED`; applied to `~ConnState` and `ServerConnection`'s
  dtor + `operator=`. Skipping is always correct — such a stream already
  finalizes itself. INDEPENDENTLY REPRODUCED by cpp-reviewer with a standalone
  program against the vendored libudx (forced `UV_EAGAIN`, double destroy →
  assert in Debug, SIGSEGV in Release; guarded → clean, `finalize_count == 1`).
  Test `DestroyStreamOnceSkipsStreamAlreadyBeingDestroyed` (red-checked).
  719/719, cpp-reviewer SHIP.
  NOTE: `blind_relay.cpp`'s destroy sites are NOT exposed — for a `relayed`
  stream `udx_stream_destroy` calls `close_stream_internal` synchronously in
  one call (upstream `fa576bd` made it so deliberately), so there is no window.
- [ ] **Finding J follow-up** — convert `SecretStreamDuplex::destroy()`
  (src/secret_stream.cpp:666) to the same guard. It owns the live,
  post-handshake application stream — the one most likely to have traffic
  queued at teardown, so the `UV_EAGAIN` window is most plausible there. NOT
  done with the main fix because that call is load-bearing for control flow
  (the destroy is what triggers `on_udx_close` → `fire_close`), so skipping it
  needs a deliberate decision about who fires the close notification and when;
  a careless change hangs the duplex. No second owner is currently reachable
  (`relay_upgrade` never destroys; `ffi_stream.cpp:56,125` run before a Duplex
  exists), so this is hardening, not a known live bug.
- [ ] **protomux UAF (NEW, found 2026-07-29 by cpp-reviewer under ASAN)** —
  heap-use-after-free at `src/protomux.cpp:242` in `Channel::open()`, hit by
  `Protomux.PairNotifyPerProtocol`, `Protomux.UnpairStopsNotify`,
  `Protomux.PairFallsBackToGlobal`, `ProtomuxParity.AsymmetricIdDataRoundTrip`.
  Pre-existing (file last touched in `5460cfa`), unrelated to the Finding J
  diff. Likely synchronous loopback reentrancy: `Mux::write_frame` → `on_data`
  → `dispatch_frame` frees/replaces the `Channel` while `open()` still uses
  `this`. Note protomux was also one of the two subsystems left UNVERIFIED by
  the 2026-07-26 parity re-verification — worth pairing the two.
- [ ] **Finding K** — the pool-NAT sampling gate does not hold: `pool_fw` is
  read mid-flight at holepunch.cpp:1758, while the comment at
  holepunch.cpp:1777-1779 asserts sampling has completed by then. Field log
  shows `Sampling settled` firing 1 ms BEFORE `sampling done`, with disagreeing
  values (read fw=3, settled fw=2); ordering varies run to run. Effect on
  connect outcome NOT established (n=1 each way — do not assume a direction).
  Minimum: enforce the invariant or correct the comment.
- [x] **Finding M — DONE 2026-07-30** (round 1 only; round 2 deliberately left
  alone, see below). `holepunch::pick_fallback_relays()` hands the announce
  record minus the chosen relay to `holepunch_connect(..., fallback_relays)`;
  `fail_round1()` pops the next leg and re-runs `run_round1` on the SAME pool
  socket, puncher and NAT samples — only the relay changes. Terminal only once
  the list empties, so the single-relay path is unchanged.
  Scope matched to JS: the six Round-1 sites that JS reaches by *throwing* out
  of `probeRound` into the retry catch now fail over (request timeout, bad
  reply, empty payload, decrypt failure, remote error, no server address);
  everything JS reaches via `abort()` (double-random NATs, unstable NAT, probe
  exhaustion) stays terminal.
  Round 1's two addresses had to be split: the message's `peer_address` is the
  relay's forward destination (router.js:214 uses it verbatim) and moves with
  the relay, while the payload's `remote_address` stays the fresh observation
  the server matches for its fast-mode punch (server.js:530-538). Attempt 0
  seeds both from the same value, so it is byte-identical to before.
  SECURITY (cpp-reviewer): the failover list is capped at
  `announcer::PICK_BEST - 1`, NOT the wire cap of 128 relays
  (peer_connect.cpp:175) — that bound was sized for parse safety back when
  extra entries were ignored, and each entry now costs a multi-second RPC, so
  uncapped it let a hostile connect() target stall its caller for ~6 minutes
  with garbage address bytes. Honest servers announce ≤3 (pickBest), so the cap
  costs no real connectivity.
  Tests: `ConnectRelayFailover.{DeadRelayFallsOverToTheNextRelay,
  NoFallbackRelaysStaysSingleAttempt, FallbackListSkipsTheChosenRelayAndIsCapped}`
  (first one red-checked). 722/722 unit; ASAN/UBSAN clean; cpp-reviewer SHIP.
  STILL OPEN: JS's second TODO (connect.js:312, round-2 failure). C++ already
  treats a round-2 relay timeout as non-fatal because probing is under way by
  then, so the remaining gap is only a round-2 *error reply*; failing that over
  means re-running round 1 for a fresh token. Needs field evidence first.
  Original report follows.
- [ ] ~~**Finding M (2026-07-30, P0 — best-evidenced item in the handoff)**~~ — ONE
  unreachable relay in the announce = permanent `-5`, with no failover to the
  other two. 81/81 deterministic field repro (81 × round-1 TIMEOUT to the same
  relay, 0 successes) while six other pool nodes queried in the same
  millisecond all replied — so not a network block.
  ROOT CAUSE: the chosen relay sits behind an endpoint-dependent (symmetric)
  NAT, so the *server's* mapping for it (`:58044`, in the announce record) is
  useless to a third party; the client's own observation of the same host is a
  different port (`:45262`). The server's 5 s keepalives ride the server's own
  mapping, so the entry looks healthy from the server — **the announcer cannot
  detect this**; no server-side liveness check helps.
  **NOT a C++ bug and NOT a parity divergence** — cross-implementation control:
  nospoon-JS on the same machine/network/seed fails identically
  (`HOLEPUNCH_ABORTED` ×6). VERIFIED IN BOTH SOURCES 2026-07-30: selection is
  faithful parity (`connect.cpp:781-790` vs `pickServerRelay`
  connect.js:812-817 — host+port match else `relays[0]`), and the bail-out is
  terminal on both (`holepunch.cpp:2059-2062` `state->complete({})`).
  **Upstream JS asks for this fix in its own source, twice** (verified
  verbatim): connect.js:271 `// TODO: we should retry here with some of the
  other relays, bail for now` and connect.js:312 `// TODO: retry with another
  relay?`.
  FIX: on round-1 (and round-2) failure, fail over to `relays[1..n]` instead of
  completing terminally. Deliberately BEYOND-JS, but it is the fix JS itself
  requests.
  **REJECTED alternative — do NOT substitute the client's own observation of
  the same host** (`:45262`). `relays[i]` is not an address, it is a live
  server↔relay UDP session, and `probeRound` sends `(peerAddress,
  relayAddress)` as a unit (connect.js:561). JS documents why at
  connect.js:280-285: *"If the relays were different, then the server would not
  have a UDP session open on this address to the client relay, which round2
  uses."* Port-swapping trades a round-1 timeout for a round-2 failure.
  Failover is safe precisely because each `relays[i]` carries its own
  `peer_address` and its own server-maintained session.
  Operational note: nothing client-side recovers; the server must re-announce
  (restart) to draw a fresh relay set.

### nat-sampler / punch payload (from the 2026-07-22 field diagnosis; see
### docs/FIELD-DIAGNOSIS-2026-07-22.md "Finding B" + "Finding E")
- [x] **Finding E** — DONE 2026-07-22 (uncommitted): announcer `updating_`
  latch → server stopped reannouncing. Root leak: `Query::visit()` didn't
  settle a tid==0 (congestion/closing) request-drop → walk never completed →
  cycle wedged. Fixed the walk drop-settle + added a 60s stuck-cycle watchdog
  on the ping timer. Test `RecoversFromWedgedCycleViaWatchdog` (red-checked).
- [x] **Finding H (pickBest)** — DONE 2026-07-26 (announcer.cpp `update()`;
  see handoff Finding H, both-ends field capture + code-confirmed). The
  announce record was committed to EVERY walked node (~41) instead of JS
  `pickBest(q.closestReplies)` = closest 3 (announcer.js:170,298-301). The
  ~38 extra record-holders had EXPIRED server-forward NAT mappings (only the
  3 kept-alive `active_relays_` forward), so a client hunted dead relays
  ~28s before hitting a live one. Fix: commit only the closest `PICK_BEST`(3)
  replies in `on_done` (full closest set still saved for reseed). Pure JS-
  parity restoration. Test `CommitsToPickBestThreeNotAllClosest`; 709/709
  unit + cpp-reviewer SHIP + ASAN clean. **NEEDS LIVE VALIDATION (Section C):
  mobile connect ~28s → ~1s.** Upstream of the punch; independent of B1/B2.
- [ ] **B1 (BEYOND-JS field-hardening — NOT a parity bug)** — NatSampler
  classifies at `sampled_ >= 3` (nat_sampler.cpp:111); `MIN_SAMPLES=4` feeds an
  `ok` flag nobody reads. Three agreeing samples latch CONSISTENT and cannot be
  demoted. **2026-07-26 re-verification CORRECTION:** this latch is
  JS-IDENTICAL — `nat.js _updateFirewall` max-hits only ever grow, never
  decrement — so stock JS fails the same CGNAT case. B1 is therefore a
  DELIBERATE divergence, not a parity gap. Fix = gate the verdict on >=4 + let
  disagreeing samples demote a stale CONSISTENT, to engage the wired birthday
  strategy on port-varying CGNAT.
  **2026-07-27 DEMOTED — field Finding L EXONERATES B1 as the `-5` cause.**
  The "reasonable candidate for the live `-5`" reading is WITHDRAWN. Mobile
  capture: all 6 SUCCESSES logged `pool_fw=2` — B1's exact misdeclaration,
  with the client mapping equally unstable — so B1's precondition is present
  in the successes; and the one attempt that classified CORRECTLY (`pool_fw=3`
  RANDOM, i.e. what fixing B1 produces) still failed `-5`. B1 discriminates in
  neither direction. Keep it as a remedy (a client whose mapping moves
  mid-handshake wants the birthday fallback), NOT as the cause. **B2 is now
  the priority of the pair.**
- [ ] **B2 (NOW THE PRIORITY OF THE PAIR — see Finding L)** — Round-2 holepunch payload sends ONE
  address (`our_addr`, holepunch.cpp:1880-1885) instead of
  `nat_sampler().addresses()`; JS sends the full set in both rounds
  (connect.js:567,654,684). Field Finding F (2026-07-23, SUCCESS) shows B2 is
  load-bearing, not a nicety: a port-varying SERVER (announce `:45747` ≠
  holepunch egress `:2707`) mislabeled `fw=2 CONSISTENT` (B1 latch) connected
  ONLY because it reported BOTH ports and the client probed both. B2's
  multi-address reporting is the mechanism that compensates for B1's
  mislabel — so B1 (correct classification) + B2 (full address set) are
  complementary; land both. Also note: Finding F shows B1 mislabels the
  SERVER's own self-classification too, not just clients.
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
- [x] **Finding H fix (pickBest, 2026-07-26)** — **FIELD-VALIDATED 2026-07-26**:
  phone (mobile CGNAT) now connects **every time, fast**. The mobile
  connect-latency stall (~28s hunting dead record-holders) is gone, and the
  one robustness risk — findPeer converging to a 3-node record set — did NOT
  materialize (Kademlia converges, as JS proves in prod). Committed `12c4af6`.
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
- [x] **Read-side backpressure** — DONE 2026-07-28 (`a08cade`).
  `SecretStreamDuplex::pause_read/resume_read` wrap
  `udx_stream_read_stop/read_start`, exposed as `hyperdht_stream_pause/resume`
  on the C API (idempotent, NULL/closed-safe; unordered datagrams unaffected).
  Test `test_stream_pause.cpp`. RESIDUAL: the *automatic* highWaterMark (16KB)
  trigger is NOT implemented — pause/resume is caller-driven, where JS pauses
  itself when the read buffer exceeds highWaterMark. protomux-2 (no true
  read-side pause; buffer+teardown substituted) is likewise still open.
- [ ] **Sleeping-interval wake detection** — VERIFY: the tick rewrite added
  `_onwakeup`/`do_wakeup` + `last_tick_ms_`, but confirm `background_tick`
  actually compares wall-clock gap vs `SLEEPING_INTERVAL` (15s) and triggers the
  wake path (JS `dht-rpc/index.js:764-799`). If the gap comparison isn't wired,
  finish it. See memory `sleeping_interval_gap.md`.
- [ ] **Bootstrap DNS / `ip@host` form** — `_resolveBootstrapNodes` DNS + `@`-host
  fallback absent (IP-only). Callers passing hostnames get nothing.

---

## E. Hardening / verification tasks

- [ ] Full ASAN/valgrind leak sweep of the hot path (confirm no hot-path leaks;
  re-verify after this session's large diff). The teardown leaks previously
  logged here as "pre-existing, in libuv/libudx internals" were pinned down
  2026-07-28 — see TD1-TD3 below. **Two of the three are ours, not libuv's.**
- [ ] Fuzzing: run each `fuzz/` harness (compact, handshake_msg, holepunch_msg,
  messages, noise_payload) ≥30 min under libFuzzer; fix crashes.
- [ ] Stress: 100 concurrent JS clients vs one C++ server; measure success rate +
  memory growth; confirm the probe-listener multi-slot fix holds.
- [ ] Soak: 12h+ connection, data every 5 min; verify NAT pinhole + SecretStream
  keepalive, no drift.

### E.1 Teardown defects (found 2026-07-28 while building holesail-cpp)

All three are shutdown-only, so a long-running server pays them once at exit and
the OS reclaims. **They matter for embedders that create and destroy many DHT
instances in one process** (test harnesses, apps that rebuild the DHT on a
network change) — there they accumulate. holesail-cpp scopes them in its
`test/lsan.supp`, which doubles as the reproduction recipe.

- [ ] **TD1 — a cancelled query leaks its state (~1.3 KB). The `on_done`
  contract is NOT violated.** *Corrected 2026-07-29 — the original entry claimed
  "`hyperdht_query_cancel()` never fires `on_done`, a contract violation". That
  half is REFUTED by standalone repro; the leak half stands, at a much smaller
  magnitude than first reported.*
  - **Contract HOLDS.** `hyperdht_query_cancel()` DOES fire `on_done` with
    `HYPERDHT_ERR_CANCELLED` (-8), on all four cancelable paths
    (`immutable_get_ex`, `mutable_get_ex`, `find_peer_ex`, `lookup_ex`), in both
    orderings (cancel→pump→free and cancel→free→pump). Chain verified in code:
    `ffi_core.cpp:28` `st.q->destroy()` → `Query::destroy()` →
    `fire_done_once(QUERY_OK)` → the FFI done lambda, which maps
    `state->cancelled` to -8. Matches `hyperdht.h:751`.
  - The one case where the callback does NOT run is `hyperdht_query_free()`
    **without** a preceding cancel — free deliberately detaches by nulling
    `done_cb` (`ffi_core.cpp:31-40`). That is documented behaviour
    (`hyperdht.h:759`), not a defect. Most likely what the original repro hit.
  - **The leak is real but ~1.3 KB, not ~34 KB.** A/B under ASAN, same binary:
    baseline create/bind/destroy = 15623 B / 18 allocs; identical run with one
    `immutable_get_ex` cancelled mid-flight = 16895 B / 35 allocs. Delta =
    **1272 B / 17 allocations** for the cancelled query, with `on_done` observed
    firing. So `QueryState` / `query::Query` still outlive teardown even though
    the completion lambda ran — the ownership problem in `query_free`'s
    "`state` may still be alive via lambda ref, which is fine" comment is
    genuine; the reasoning about *why* was not.
  - Fix: give `query_free` real ownership (or drop the query's self-reference
    once done). Do NOT "fix" it by firing `on_done` on cancel — that already
    happens, and adding a second fire would break the fires-exactly-once
    contract. Re-run the full 716-test lane after.
  - Repro note: measure with stdout UNBUFFERED. `DHT_LOG` writes to stderr
    unbuffered while `printf` is block-buffered when piped, which interleaves
    the transcript misleadingly and can make a callback look like it never ran.

- [ ] **TD2 — every DHT orphans a stopped-but-unclosed `uv_timer_t`.** The
  interface-watcher timer (`HyperDHT::start_interface_watcher`) is stopped but
  never `uv_close`d: `active=0 closing=0 ref=1`. The knock-on effect is the
  bigger problem — **`uv_loop_close()` then returns `EBUSY` permanently**, so
  libuv cannot free the loop's own internals either and embedders cannot cleanly
  close or reuse a loop. ~1237 bytes + 4 allocations per DHT, plus the loop.
  VERIFIED with a zero-holesail program following `hyperdht.h`'s own
  create → listen → destroy → `uv_run` → free recipe verbatim. holesail-cpp
  works around it by `uv_walk`-closing the orphan before `uv_loop_close()`
  (`drain_and_close()` in its `src/cli.cpp`); that workaround should become
  unnecessary.
  **INDEPENDENTLY RE-CONFIRMED 2026-07-29** (separate repro, hyperdht-cpp only):
  after `hyperdht_destroy` + full drain, `uv_walk` reports exactly one leftover
  handle — `type=timer active=0 closing=0 has_ref=1`, matching the description
  verbatim — and `uv_loop_close()` returns `-16 (EBUSY)`. This one is solid.

- [ ] **TD3 — in-flight connect/stream state dropped when `hyperdht_destroy`
  beats a graceful close round-trip.** Frames: `HyperDHT::do_connect`,
  `server::Server::on_handshake_result`, `udx__cirbuf_init` / `_set`. ~11 KB per
  integration run, and it **scales with connection count** — consistent with
  per-connection state being abandoned rather than reaped. Lower confidence than
  TD1/TD2: established by tracing frame `#1` of every unsuppressed allocation to
  a dependency frame, not by a standalone repro. Reproduce before fixing.

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
  the core below it is frozen). **RAISED IN PRIORITY 2026-07-28:** the first
  real bug found here was a SECURITY inversion — `hyperdht_server_set_firewall`
  returned `cb(...) == 0` where `FirewallCb` means true=REJECT, so every C-API
  server with a firewall admitted exactly the peers it should refuse and
  refused the authorised one (`0203820`, found via holesail-cpp, regression
  tests `ServerFfiFirewall.*`). Polarity conversions are the smell: the sibling
  `set_holepunch` (`== 0`) and async `firewall_done` (`!= 0`) were each
  re-checked and ARE correct — the two callbacks legitimately have opposite
  polarities (`FirewallCb` true=reject vs `HolepunchCb` false=abort). Audit the
  rest of `ffi_*` for the same class: bool/int contract mismatches at the
  boundary, which compile fine and fail silently.

---

## G. Small follow-ups

- [ ] **F1 (field Finding F, 2026-07-23)** — after a direct probe wins
  (rawStream firewall fires, connected), the client keeps the round-2 BLIND
  RELAY request alive and retries it 3× to timeout (`Round 2: TIMEOUT
  (relay)`). Cancel the round-2 relay once the direct probe connects — wasted
  relay traffic + a scary-but-harmless timeout in field logs. Not a bug.
- [ ] **F2 (field Finding F, 2026-07-23)** — server logs
  `on_peer_holepunch: unknown session id=0` for the client's round-2 that
  arrives AFTER the session connected+cleaned on round 1. Benign; downgrade
  the log level or match it against a recently-completed session so it doesn't
  read as an error in field captures.
- [ ] `immutable_put`/`mutable_put` result callbacks still swallow the commit
  error (their callback signatures lack an error field — unlike announce/put
  which now report failure via OnDoneCallback).
- [ ] Wrapper build CI: Python/Kotlin/Rust announce-ABI change (`f37ef1d`) is
  UNVERIFIED — no wrapper build in the C++ gate. Add a wrapper-build check.
- [x] Tighten connect-3 wording in the sweep docs so it's not read as
  "reusableSocket unimplemented" — RESOLVED 2026-07-28 (`a08cade`): the C-API
  client option landed as `hyperdht_connect_opts_t.reusable_socket` (tail-
  appended; Python ctypes mirror updated in the same commit per the CLAUDE.md
  ABI gotcha). Server + wire + client option are all done; only the route-cache
  gating nuance remains, tracked as connect/divergence-1 in Section A.
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

## H2. Dependency watch — libuv 1.52 regression (recurring)

hyperdht-cpp is pinned to **libuv 1.51.x** (flake on nixos-25.11) because libuv
1.52.0 has a UDP `POLLERR` regression that wedges libudx streams on real NAT
paths — full write-up in `docs/LIBUV-VERSION.md`; unwired fallback patch in
`nix/libuv-1.52-udp-pollerr.patch`. **Re-check whenever bumping nixpkgs/libuv:**
- [ ] Has **libudx** bumped its libuv pin past 1.51 or shipped a 1.52-compat
  fix? (`deps/libudx/CMakeLists.txt:~7`; watch holepunchto/libudx `main`.)
- [ ] Has libuv shipped **>= 1.52.2** with PR #3250? If yes → drop the 25.11
  pin, delete the patch, remove the CMakeLists version guard, use stock libuv.

## H. Future work

- [ ] **Extract `run_round1()` into named phases** (`src/holepunch.cpp`) — the
  single worst readability hot spot: **457 lines**, 9× the 50-line guideline.
  Split into `probe_round` → `await_sampling` → `analyze_and_maybe_reopen` →
  `round2`, each taking `PunchState`. **Do it WITH the Finding K fix, not as
  separate churn** — the `proceed` lambda, the sampling gate and the reopen
  path all live in one function body today, which is precisely why K (a
  mid-flight `pool_fw` read that contradicts its own comment) is subtle
  instead of obvious.
  Scope discipline — a 2026-07-29 measurement says the library is NOT spaghetti
  otherwise, so do NOT generalise this into a broad refactor: coupling is low
  (most `src/*.cpp` include 3-5 hyperdht headers; only `dht.hpp` at 12, the
  facade), code density is ~340 lines/file across 36 files (the ~20.4k raw
  `src/` total is 27% comments, and those JS `file:line` parity refs are what
  made Findings H/I/J root-causable by reading). `holepunch.cpp` carries 36
  lambdas (server 23, connect 19, rpc 17) — the cost of "every JS `await`
  becomes a callback chain". Coroutines would flatten it but are a large change
  and hostile to the ESP32 target: rejected. NOTE: raw indentation hits 56
  columns in holepunch.cpp but that is WRAPPED ARGUMENTS, not nesting — true
  control-flow nesting at depth >=5 is 19 lines there, 8 in connect.
- [ ] **Round-2 adversarial JS-parity sweep** — re-run `jsparity-adversarial-sweep`
  over the round-1 blind spots (Section F) + a re-diff of the subsystems changed
  heavily this session (rpc, connect, server, holepunch, protomux) to catch
  regressions the per-bucket reviews might have missed. Append new findings to
  Section A.

---

## I. peeroxide cross-reference (second independent Rust oracle)

**Context (2026-07-23):** `Rightbracket/peeroxide` — independent Rust port of the
FULL Hyperswarm stack (pure-Rust libudx + HyperDHT + Hyperswarm topic layer + CLI),
wire-compatible with JS, v0.3.1, published (crates.io/homebrew). Local Nix build at
`~/Desktop/repos/peeroxide-nix` (`nix build .#peeroxide`). Source clone was in
scratchpad; re-clone `https://github.com/Rightbracket/peeroxide` to act on these.
It hit the SAME announce/staleness class we did — useful as a borrow source AND a
second parity oracle. Two workstreams:

### I.1 Announce/staleness — borrow ideas (check ours against theirs)
- [ ] **Refresh-token cheap-refresh.** Their `peeroxide-dht/src/persistent.rs:462` —
  announce carries optional `refresh` token; a re-announce with NO peer body but a
  refresh token restores the full record from a token-keyed cache → keepalives are
  tiny (token only), not full peer+sig+relays. **Check: do WE send refresh tokens on
  re-announce + handle the no-peer+refresh restore node-side?** (Jul-21 note: field
  exists in our messages, may be unused.) Parity gap + efficiency.
- [ ] **Parallel dual-announce + relay feedback.** Their `peeroxide/src/peer_discovery.rs`
  `do_refresh`: each refresh fires topic-announce (on `topic`) AND self-announce (on
  `hash(pk)` → FE-holders for PEER_HANDSHAKE Phase 2) in parallel; relay addresses
  harvested from prior hash(pk) acker set feed the next topic record ("mirrors Node's
  `Announcer.relayAddresses`"). **Check our Announcer does the same dual-target +
  relay feedback** — this is the Finding A/D forward-state area.
- [ ] **Constants sanity-check:** their `REFRESH_INTERVAL=600s` (+≤120s jitter),
  record `TTL=20min` ("matches Node.js"). Confirm our re-announce cadence (~10min,
  not 5) + TTL match.
- Note: they PUNT unannounce (`swarm.rs` `// leave/unannounce (future)`) → their
  server-restart staleness window = full 20-min TTL. If we have clean
  unannounce-on-shutdown, we're AHEAD there — do NOT copy their omission.

### I.2 JS-parity hunt — their golden fixtures as a parity oracle
- [ ] Their committed byte-exact fixtures: `tests/interop/*-fixtures.json` (noise,
  noise-ik, dht-rpc, hyperdht, protomux, secure-payload, blind-relay), generated by
  `tests/node/generate-*-golden.js` from the JS reference. **Feed their fixture inputs
  through our C++ encoders, assert output == their bytes.** Both claim JS-parity →
  any mismatch localizes a bug to a specific message/field. Highest-value targets:
  `noise-ik-fixtures.json` (Ed25519 DH, our #1 gotcha) + `hyperdht-fixtures.json`
  (announce/lookup, current pain).
- [ ] Mine their interop `.rs` assertions for edges we may skip (empty relays,
  refresh-only announce, `bump` handling, `MAX_RELAY_ADDRESSES` truncation).
