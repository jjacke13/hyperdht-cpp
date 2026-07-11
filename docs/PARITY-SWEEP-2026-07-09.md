# Core-Ossification Readiness — Adversarial JS-Parity Sweep (2026-07-09)

## FREEZE STATUS (updated 2026-07-09 — easy / near-freeze pass)

Subsystems cleared to freeze after this pass (working tree, 584/584 green):

| Subsystem | Status | Notes |
|---|---|---|
| **noise** | ✅ FROZEN-READY | 0 findings. Crypto core untouched. |
| **compact** | ✅ FROZEN-READY | compact-1 fixed (`Bool::decode == 1`); compact-2 (4096 array cap) kept as **accepted** anti-DoS hardening, stale comment corrected. |
| **routing** | ✅ FROZEN-READY | routing-2 fixed (re-add no longer fires spurious ping-and-swap; +regression test); routing-1 (exact-k-closest sort) kept as **accepted** — C++ is strictly more correct than JS's bucket-order early-stop, and it's not a wire field. |
| **secret-stream** | ⏳ near-freeze | 3 of 4 LOW fixed (timers-1 uv_unref both; end-1 stops keepalive; timeout-1 refresh on raw chunk). enablesend-1 = **inert** (default true, no consumer sets false) — documented, no change. connect-1 (MED, connect-gated-on-both-headers RTT) **deferred** — relaxing the header-exchange gate needs a live JS cross-test, not a batch edit. |
| **messages** | ✅ FROZEN-READY (2026-07-10) | messages-1 fixed: `encode_lookup_reply`/`decode_lookup_reply` now JS `rawPeers = c.array(c.raw)` + trailing bump (messages.js:315-334) — no per-element length prefix; `handle_lookup` uses the shared encoder. messages-2: AnnounceMessage bump field confirmed already correct (flags bit3), byte-exact test added. **Cross-checked: real JS messages.js decoded a C++-encoded 74-byte reply exactly** (2 peers + bump=42). Old-C++ peers wire-incompatible for lookup — intended. |
| **router-announce** | ✅ 3 of 3 HIGH fixed (2026-07-10); 1 MED + 3 LOW remain | announce-1+announce-2 fixed: announce stores bare `m.peer` record (relays≤3, trimmed AFTER signature verify per persistent.js:106/121 — trim-before-verify bug caught in review); announceSelf populates router entry `{relay: req.from, record}` + `records.remove` (persistent.js:131-138); bump gate with wall-clock drift window; FIND_PEER is router-only (store fallback removed, JS returns null); LOOKUP pushes router fwd.record under the 20 cap + bump, null when empty; unannounce cleans relay-only router entries (never a local Server's). Accepted divergence: a local listening Server's router entry is refreshed, not clobbered (JS last-writer-wins would kill our own listener). announce-3 fixed: router relay else-branches ported (router.js:128-171, 212-247) — FROM_CLIENT→FROM_RELAY to relayAddress‖entry.relay (closerNodes reply when neither), FROM_RELAY→FROM_SECOND_RELAY, FROM_SERVER→REPLY bounced to peerAddress; `make_relay_request` mirrors io.js Request.relay (same tid/command/target, token/id absent, fire-and-forget). +4 relay tests, suite 613/613 unit-green. C++ nodes no longer black-hole third-party connect traffic. |
| **dhtrpc-tick** | ✅ all findings closed (2026-07-11); tick-7 partial | tick-2/4/6 verified already-fixed this session (flat-1000ms timeout; persistent id = BLAKE2b(server host:port) via probe_ring_ swap; request-path NAT feed). tick-1: eviction PINGs retries 0→3 (JS 4 transmissions) + 2 false comments fixed. tick-3 (**was: seed/isolated node dead forever**): bootstrap walk now runs unconditionally — empty frontier → `seed_from_table` sets from_table_ → `read_more`→`maybe_finish` fires on_done synchronously in `start()` → flips bootstrapped_ (traced sound, no hang/UAF; `bootstrap_query_` set before start, Query self-pins). tick-5: `adaptive_` = `!ephemeral.has_value() && opts.adaptive` (DhtOptions.ephemeral now optional<bool>); stable-ticks countdown + wakeup ephemeral-revert gated on adaptive_ (C++ && short-circuits — non-adaptive never decrements); opts.ephemeral applied at construction; bootstrapper forced-persistent + id finalized. tick-8: tick_/refresh_ticks_ seeded with JS randomOffset (`n - randombytes_uniform(n/2)` → [51,100]/[31,60]) — de-syncs fleet. **sweep-miss-b**: outgoing requests now carry our id when `!ephemeral_ && !firewalled_` (= JS `ephemeral===false && socket===serverSocket`; wire-safe — JS validateId benignly ignores a mismatch). +10 tests. **tick-7 REDUCED**: quick-firewall PING_NAT to first bootstrap responder (early firewalled_ clear, ~20min win) done; full 2-pass + testNat second _updateNetworkState DEFERRED (ephemeral→persistent still via the untouched stable-ticks→RingSampler probe). **Accepted gap: C API can't express JS's explicit-ephemeral=true→non-adaptive state (only adaptive or forced-persistent).** LIVE: JS validateId accepts our outgoing id; bootstrapper appears in JS routing tables; quick-firewall clears against real bootstrap nodes. |
| **holepuncher** | ⏳ findings fixed; 2 residuals need LIVE CGNAT (2026-07-11) | holepuncher-1 (HIGH) **egress fixed + loopback-proven**: both Holepuncher ctors now take pool+stats (DHT-owned, shared → real cross-puncher serialization); birthday `open_birthday_sockets`/`keep_alive_random_nat` egress per-holder via `send_probe_from_socket(ref->socket())` (was all-from-one-socket → no birthday effect); non-initiator echo leaves the recv socket. Test `BirthdayEgressPerSocket` asserts ≥3 distinct source ports (old code = 1). **RESIDUAL (live-only): birthday-WIN stream keepalive still pins `state->pool`, not the winning SocketRef (holepunch.cpp:1450) — winning socket can be released under the stream; fix documented in-code, needs live CGNAT.** holepuncher-2: TRY_LATER = bounded 3× jittered 10-20s retry (was fatal); safe (state held by sleeper, self-cancels on completed, cycle broken by complete()/abort); divergence: retries unconditionally vs JS relayToken-gate (C++ server keeps session alive on TRY_LATER — documented). holepuncher-3: coerce leaves UNKNOWN unmatched → punch() false (was blind-punch); server analyze-abort correctly NOT added (JS's is nested under `!remoteHolepunching` — unreachable from C++'s punch path; verified against server.js:520-524). holepuncher-5: verified-remote gate now on BOTH random branches. holepuncher-6: route GC on socket close (auto, tested); `on_stream_error` gc implemented+tested but not auto-wired (stale route = 1 failed handshake, not UAF — documented). **RESIDUAL: holepuncher-4 wires on_reset_ but resamples the SAME socket (preserves upgrade-port socket-handle invariant) — recovers lossy-UNKNOWN, NOT the new-NAT-mapping case JS's fresh-socket _reset handles.** +5 tests. **LIVE list: server-side birthday stream completion (accepts via main-socket firewall, not birthday SocketRefs — THE symmetric-CGNAT-server path), client birthday-win keepalive, TRY_LATER end-to-end, h-4 fresh-NAT case.** |
| **query** | ✅ FROZEN-READY (2026-07-11) | commit-1 fixed: `OnDoneCallback(int error, replies)` — empty closest → QUERY_ERR_TOO_FEW_NODES; every closest reply mapped through commit (tokenless = failed, JS autoCommit reject); success iff ANY commit succeeded (exact `_endAfterCommit` semantics — agent corrected the session's sketch against real JS). **Announce client REWRITTEN** (sweep miss a): walk = value-less CMD_LOOKUP; per-node signing over (target, reply.token, reply.from.id) in the commit — proven by a two-node test the old code cannot pass; ABI change `hyperdht_announce(keypair, relays, bump)`, Python/Kotlin/Rust wrappers updated (builds UNVERIFIED — flag for wrapper CI). query-1: walk retries 5 (6 sends). query-2: error replies filtered from on_reply (closer-nodes still merged). query-3: _slow oncycle → widened concurrency + early flush (test: ~1s vs 6s). query-4: onlyClosestNodes flag. downhint-1: DOWN_HINT emission on visit timeout (refs threading, retries 3, 50/tick rate limit). +10 tests, suite 662/663. NOTE: immutable/mutable_put result callbacks still swallow commit errors (their cb signatures lack an error field — follow-up). |
| **connect/server (relay→direct)** | ✅ PORT COMPLETE (2026-07-11) — needs LIVE validation | Stage 1: libudx bump 759bf76; connect-2 `complete_error` guards (+latent relay-failure hang fix); `try_change_remote` state machine (hazards 4/5/6, 5 tests); connect-11 verified both-correct; keepalive verified. Stage 2: `SecretStreamDuplex::attach_upgrade` taps (raw-activity/firewall/close, zero behavior unset — also killed a latent firewall type-confusion by installing the Duplex firewall unconditionally at start()); `RelayOwner` + `UpgradeContext` (hazard 2 — explicit relay ownership replacing the accidental ref cycle; hazard 3 — punched-socket keepalive transfers into ctx; hazard 7 — ctx via stream->data→Duplex; hazard 8 — Duplex stays sole raw-stream owner, close tap fires first so all late hops no-op); client punch-after-relay → onsocket → changeRemote → #266 confirm choreography (zero-length raw nudge, validUpgrade straggler rule, graceful relay close ONLY after provable direct arrival); server relay-emit no longer clears session (puncher survives; 2dfa977 10s grace + relay_token gate + 45s backstop preserved verbatim); FFI consumers get it free via ConnectResult/ConnectionInfo upgrade handle, raw C++-API adds one `attach_to_duplex` line. 9/9 module tests incl. DEFERRED-path + mid-window destroy race, ASAN-clean; cpp-reviewer 1 HIGH (server double-emit) fixed. **Review catch (mine): stage-2's ASAN sweep exposed a heap-UAF in BlindRelaySession — server-side session never nulled `channel_` on close and had no on_destroy handler; fixed, ASAN 44/44 clean.** Suite 652/653. **LIVE list for nospoon run: JS-peer migration (no -110), server-side migration vs JS client, relay straggler under RTT skew, hours-long relay steady state, backstop-mid-upgrade on slow CGNAT.** |
| **protomux** | ✅ FROZEN-READY (2026-07-11) | All 10 findings closed. protomux-1 (the data-loss one): `send()` encodes `local_id_` per JS index.js:270-278 — asymmetric-id routing proven by test. Pre-pair buffering via JS-style remote slots created at OPEN, drained on pair. REJECT emitted ([0,2,remoteId], byte-asserted) for control-session + declined opens. Grow-by-one open validation + live-slot reuse → safe_destroy. Batch entry cap removed (frame length bounds work; truncation = teardown not silence). uncork splits at MAX_BATCH 8MB. Multi-message batch replies coalesce (cork/uncork, byte-asserted). Queued pending opens per key. ondrain fires on open-but-unpaired. Stray/late REJECT = fatal. Local-id assignment moved to open() (JS :71-79, needed for sequence check). **Documented divergences**: (a) opens with NO notify handler are PARKED not rejected — C++ notify is synchronous so JS's async pre-open pattern would otherwise break (blind-relay depends on it; bounded by cap); (b) no read-side pause exists → MAX_BUFFERED 32KB overflow = teardown, never silent drop; (c) remote backlog cap 1<<20 vs JS Infinity (anti-DoS). +12 tests, protomux 48/48, blind-relay 44/44, suite 643/644. |
| **dhtrpc-io** | ✅ FROZEN-READY (2026-07-10) | io-1 INVALID_TOKEN fixed earlier (tokens-nat pass, verified). io-2: UNKNOWN_COMMAND error replies at all 3 silent sites (internal default / external default / ephemeral storage gate — JS index.js:679,684-687; ephemeral node now signals instead of timing out the querier). io-3: retransmit timeout = flat 1000ms default matching deployed JS (io.js:78,457-459 — hyperdht never enables AdaptiveTimeout); C++ 2×EMA adaptive kept behind opt-in `adaptive_timeout_`; false parity comment rewritten. io-4: PING/FIND_NODE replies token-less (sendReply token=false, index.js:641,660). io-5: congestion-queued requests now in BOTH inflight_+pending_ (io.js:337) — cancellable, no post-destroy callback UAF; 2× congestion recv() accounting matched. io-6: request-path NAT feed (req.to → both samplers, gate `from_server != firewalled_` = JS !external). io-7: alloc_tid never returns the 0 sentinel. +5 tests, 631/632. **NEW (sweep miss #2, confirmed in review): C++ never sets the id on OUTGOING requests — JS `_encodeRequest` includes it when `!ephemeral && socket===serverSocket` (io.js:521). Persistent C++ node can't enter JS routing tables via its own requests. Fix with the tick-4 persistent-identity cluster.** |
| **dht-top** | ⏳ 4 fixed + 2 accepted; 1 NEW finding | dhttop-1 fixed: real `lookup_and_unannounce` port (LOOKUP walk, per-reply signed UNANNOUNCE via Tracker mirroring `await Promise.all(unannounces)`, all settle paths guarded incl. tid==0) + local self-unlink. dhttop-6 fixed: `announce(clear)` routes through it with announce commit folded in. dhttop-2 fixed: `pool()` returns DHT-owned pointer, `attach_server` chains via `Server::add_connection_listener` (never steals user cb). dhttop-8 fixed: keep-new swap deferred to old stream's close (connection-pool.js:37-55). dhttop-3 ACCEPTED (no auto-bootstrap = deliberate, embedded targets; comments corrected). dhttop-4 ACCEPTED (C++ composes filters; JS discards user filter — false comment fixed). +7 tests, 626/627. **NEW (sweep miss, found in review): plain `dht_ops::announce` walks with token-less CMD_ANNOUNCE + one fixed pre-signed value — JS walks CMD_LOOKUP and signs per-node at commit (announce signable covers the per-node token, so the fixed value can't verify). JS persistent nodes silently drop the walk requests. Masked because the live announce path is the server-side Announcer. Fix with the query/commit-1 bucket: walk CMD_LOOKUP value-less, commit = the (already-correct) `make_announce_commit`.** |
| **blind-relay** | ✅ FROZEN-READY (2026-07-10) | All 6 findings fixed, 1 accepted. blind-relay-1: `CreateStreamFn(close_cb, user_data)` + per-link `relay_firewall_cb` → `udx_stream_connect(stream, socket, remote_id, from)` on first unknown-remote packet then accept (index.js:268-280); **proven by new end-to-end test relaying real bytes through firewall-connected streams**. blind-relay-2: pass 3 = send→endMaybe→emit per link (index.js:174-185). blind-relay-3: graceful Server::close drains via pending_close_ + zombie reaping, on_closed when last session gone. blind-relay-4: per-stream close cb erases streams_ entry (udx folds error into close status). blind-relay-5: client inbound unpair now ignored (empty handler preserves wire index 1). blind-relay-6: decode_pair/unpair → optional, nullopt → channel close (JS decode-throw teardown); required a protomux `Channel::dispatch` stack-copy fix so handlers may tear down their own channel. blind-relay-7 ACCEPTED (30s TTL + 1024 cap = C++ anti-DoS hardening, comment corrected). +6 tests, suite 620/620 unit-green. |
| **tokens-nat** | ✅ FROZEN-READY (2026-07-10) | tokens-1 fixed: central INVALID_TOKEN validation at `RpcSocket::handle_message` choke point (io.js:94-101), error=2 reply with fresh token; per-handler checks kept as backstops. nat-1+nat-2 fixed: new `nat::RingSampler` = line-faithful port of the `nat-sampler` package (32-ring, no dedup, threshold gating, host-null/port-0 states); RpcSocket's dht-rpc-role reads switched to it, firewall probe uses fresh sampler + swap (index.js:818-845); existing `NatSampler` (hyperdht nat.js semantics) untouched for holepunch/server/connect. +7 RingSampler tests +1 InvalidToken test, suite 606/606 unit-green. |

Accepted-divergence policy: where C++ intentionally differs and is safer or
more correct than JS (compact array cap, routing exact-sort), we document and
keep it rather than regress to JS — "as close to JS as possible" means matching
behavior that matters (wire bytes, connectivity, correctness), not copying a
weaker algorithm.

## REMAINING OPEN — honest tally (updated 2026-07-11)

Of the **91 confirmed findings**: **all 12 HIGH closed**; ~70/91 addressed
(fixed or accepted-divergence); **~21 MED/LOW still OPEN**, concentrated in the
three subsystems that were only touched for their HIGH relay-upgrade/wire
findings. This is the resume worklist — NOT "the sweep is done."

- **connect — 8 open** (done: connect-1/2/11): connect-3 reusableSocket ignored;
  connect-4 route-shortcut handshake omits firewall+addresses; connect-5
  direct-connect bogon filter + serverAddress fallback; connect-6 LAN same-NAT
  runs parallel (JS exclusive); connect-7 opts.holepunch veto callback unused;
  **connect-8 handshake reply under-validated (no mode===REPLY / from-match) —
  SECURITY**; connect-9 findPeer not seeded closestNodes/onlyClosestNodes/retries;
  connect-10 relay 15s timeout is a no-op.
- **server — 8 open** (done: server-5): **server-1 ERROR_ABORTED Noise reply on
  firewall reject (JS sends nothing)**; **server-2 holepunch reply committed
  before veto/punch-start**; **server-3 handshake dedup not synchronous on
  async-firewall path** (all three correctness); server-4 MAX_PENDING_HANDSHAKES
  256 cap silent drop (ACCEPT candidate — anti-DoS); server-6 neverPunch
  (opts.holepunch===false) unimplemented; server-8 relay pairing no 15s abort;
  server-9 server-side same-host LAN match; server-11 OPEN-client shortcut
  targets self-reported addr[0] with null socket.
- **router-announce — 4 open** (done: announce-1/2/3): announce-4 announcer
  embeds relay addresses in the SIGNED record (JS announces empty list);
  announce-5 FROM_SECOND_RELAY reply sent to req.from not the embedded
  relayAddress; announce-6 holepunch server handler invoked for all modes;
  announce-7 refresh-chain announce not honored (refresh token never stored).
- **secret-stream — 1 open**: connect-1 (connect gated on BOTH headers) —
  deferred, needs a live JS cross-test not a batch edit.

Do connect-8 + server-1/2/3 first (correctness/security). server-4 and a few
others are likely ACCEPT-as-divergence (anti-DoS), decide per-finding.

Committed 2026-07-11 (branch fix/relay-direct-upgrade, NOT pushed): f266b35
deps, 88b8022 compact/routing, 5460cfa core sweep + relay upgrade, f37ef1d
wrappers, 86353db docs.

---

Everything below is the original sweep report.

---


16 subsystem finders diffed every C++ file against its JS reference fresh (no
priming with prior conclusions), each finding was then refuted-or-confirmed by
an independent Fable adversarial verifier (default: not-real). **91 findings
survived** (118 agents, 0 errors on the final pass). Raw data:
`.parity-sweep-2026-07-09.raw.json`; full finding text: appendix below.

Purpose: decide which core subsystems are JS-faithful enough to **freeze**, and
what must close first. The freeze line is drawn at the FFI/wrapper boundary —
core below it must come back clean before we can say "future bugs are in the
wrappers."

## Verdict at a glance

| Severity | Count (none already-fixed) |
|---|---|
| HIGH | 12 |
| MED | 45 |
| LOW | 34 |
| Comment "JS-parity" claims that are FALSE | 8 |

**Tonight's six fixes survived adversarial review — zero contradictions.** No
confirmed finding shows the abort-grace/relay_token gate, `UvTimer` one-shot
release, `punch()` idempotence, commit-timeout settlement, or tick-wakeup work
to be wrong. One finding (`commit-1`) sits on top of tonight's C1 fix: it
confirms C1 removed the hang but the deferred C2 (false-success) is real and
HIGH — my `commit_success_` field is present but not yet consumed.

## Freeze / Hold readiness by subsystem

| Subsystem | H | M | L | Verdict |
|---|---|---|---|---|
| **noise** (Ed25519 IK, BLAKE2b, HKDF) | 0 | 0 | 0 | **FREEZE** — crypto core clean, zero divergences |
| **compact** (wire varint/buffer/ipv4) | 0 | 0 | 2 | **FREEZE** after 2 cosmetic LOWs |
| **routing** (kademlia table) | 0 | 1 | 1 | **FREEZE-soon** — 1 MED (row-traversal order, behaviourally equivalent set) |
| **tokens-nat** | 0 | 3 | 0 | HOLD-minor — NAT-sampler feed + consensus threshold |
| **secret-stream** | 0 | 1 | 4 | HOLD-minor — connect-gated-on-both-headers + timer unref |
| **dhtrpc-io** | 0 | 5 | 2 | HOLD — INVALID_TOKEN/UNKNOWN_COMMAND replies, adaptive-timeout, NAT feed |
| **protomux** | 0 | 5 | 5 | HOLD — channel-id/batch edges (no HIGH) |
| **blind-relay** | 0 | 2 | 5 | HOLD — pairing TTL / close ordering |
| **dht-top** (index API, pool, caches) | 0 | 3 | 3 | HOLD — dedup, hashing, keepalive |
| **dhtrpc-tick** | 1 | 6 | 1 | **HOLD** — persistent-id-from-wrong-socket + eviction aggressiveness |
| **holepuncher** | 1 | 4 | 1 | **HOLD** — birthday punch dead (symmetric CGNAT) |
| **query** | 1 | 2 | 3 | **HOLD** — commit false-success |
| **server** | 1 | 6 | 2 | **HOLD** — relay→direct upgrade |
| **connect** | 3 | 6 | 2 | **HOLD** — relay→direct upgrade cluster |
| **messages** | 2 | 0 | 0 | **HOLD** — LOOKUP wire format |
| **router-announce** | 3 | 1 | 3 | **HOLD** — LOOKUP/FIND_PEER wire format + relay black-hole |

Freeze-ready today: **noise, compact** (crypto + wire encoding — the two most
important things to ossify, and both clean). Everything else holds on at least
one real divergence.

## The headline discovery: LOOKUP / FIND_PEER wire format is broken vs JS

The single most important new finding — because it's a **silent cross-impl wire
break masked in C++↔C++ (nospoon) but broken against JS peers / the public
DHT**, exactly the class that invalidates a freeze:

- **messages-1 / announce-1**: C++ `LOOKUP` reply length-prefixes each peer
  record (`compact::Buffer`) and omits the trailing `bump`. JS `lookupRawReply`
  is `uint(count) + concat(raw self-delimiting records) + uint(bump)`. JS
  `mapLookup` reads the extra length varint as record bytes → misaligned
  `publicKey`. The header comment claims `array(raw)` — the code does not.
- **messages-2 / announce-2**: C++ stores and returns the **entire announce
  message** (flags + peer + 64-byte signature) as each peer entry; JS stores and
  returns only the bare `m.peer` record (pubkey + relayAddresses). JS decodes
  the announce flags byte as the first byte of `publicKey`.
- **announce-2**: same for `FIND_PEER` served from the store fallback (the
  Server's own-key router path is correct).
- **announce-3**: C++ nodes that are only a **relay/storage** node (not the
  target's server host) silently drop third-party `PEER_HANDSHAKE`/
  `PEER_HOLEPUNCH` — `router.cpp` returns false and the caller ignores it. JS
  relays them (FROM_CLIENT→FROM_RELAY→FROM_SECOND_RELAY→REPLY). A C++ node in
  the DHT path is a black hole for other peers' connect traffic.

Net: a C++ node cannot serve topic discovery or act as a DHT relay for JS
clients. nospoon hasn't felt it because both ends run the same C++ (they agree
on the wrong format), but it fails the "wire-compatible with the reference"
promise and must close before ossifying the storage/router core.

## Top priorities to close before freeze (ranked)

1. **Wire-format cluster** (messages-1/2, announce-1/2/3) — restore JS
   `lookupRawReply`/`m.peer` encoding, store the bare peer record not the
   announce envelope, add `bump`, implement the router relay else-branch.
   Small, high-value, unblocks JS interop + public-DHT participation.
2. **Relay→direct upgrade** (connect-1, server-5, connect-2) — the branch's
   namesake and the nospoon "connected-no-data-then-drop" killer. Design ready
   in `RELAY-UPGRADE-PORT.md`. connect-2 (abort guards) is a cheap partial win
   independent of the full `changeRemote` port.
3. **commit-1 false-success** (query) — consume the `commit_success_` field I
   staged tonight; give `OnDoneCallback` an error path so a failed announce/put
   reports failure instead of lying. Directly affects nospoon re-announce.
4. **holepuncher-1 birthday punch** — wire the pool + per-holder egress so
   symmetric-CGNAT (Cosmote phone) can punch.
5. **tick-4 persistent id from client socket** — a persistent C++ node
   advertises an id/port from the client socket, not the server socket it
   transmits from; peers key on the wrong address.
6. **tick-1/tick-2 eviction aggressiveness** — eviction PING uses retries=0
   (JS 3) and an always-on adaptive timeout (JS flat 1000ms). My new
   `_pingSome` calls `check_node` every 8th tick, so this now churns live-but-
   lossy nodes harder than JS. Comments here are among the 8 false JS-parity
   claims.

## The 8 false "JS-parity" comments

Comments asserting JS behavior that the verifier proved wrong (a distinct
hazard — they mislead the next reader): tick-1, tick-2 (rpc.cpp eviction/
timeout), plus 6 more across the confirmed set (grep `comment_claim_false` in
the raw JSON). Fix the code or the comment in each.

## Coverage / blind spots (no finder ran on these)

The completeness critic didn't run (removed to save the session-limit budget),
but the finder coverage notes name what was NOT audited line-by-line and should
seed a round 2 before a full freeze sign-off:

- `health.cpp` vs `dht-rpc/lib/health.js` (only checked at the tick call-site).
- HyperDHT-level `suspend()`/`resume()` socket rebind + inbound-drop (io.js
  `suspend`/`_rebind`) — rpc-level `stop_tick`/`start_tick` alone don't match.
- `raw-stream-set.js`, `semaphore.js`, `refresh-chain.js`, `commands.js`,
  the udx wrapper, and the entire `ffi_*` layer had no dedicated finder.
- `_resolveBootstrapNodes` DNS/`@`-host fallback — absent in C++ by design,
  but callers passing hostnames get nothing.

The `ffi_*` layer is the natural freeze boundary: it's the wrapper surface, so
it's audited last / separately once the core below it is frozen.

---

See `docs/.parity-sweep-appendix.md` for all 91 findings with JS/C++ file:line,
divergence, and consequence, and `.parity-sweep-2026-07-09.raw.json` for the
machine-readable set (per-finding verify_reasoning included).
