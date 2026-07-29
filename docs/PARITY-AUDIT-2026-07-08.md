# JS-Parity Audit — 2026-07-08

Systematic sweep of hyperdht-cpp against the JS reference (hyperdht 6.29.1,
dht-rpc 6.26.3, udx-native 1.19.2 in `.analysis/js/`) plus upstream drift
(6.29.1 → main). Five parallel audit passes over module pairs; every HIGH
finding below was re-verified by hand against source before inclusion.
Severity = user-visible impact for nospoon-style workloads.

Master fix-order proposal at the bottom.

---

## A. Root cause #1 (previously established): relay-vs-punch race

cpp races blind-relay against holepunch, first winner takes all
(`connect.cpp:582`, discard at `:772`); JS emits on relay and upgrades the
same stream to direct via `changeRemote`. Kills connections against JS peers
when the punch lands after the relay (peer migrates unilaterally, cpp closed
the punched socket). Full design: `docs/RELAY-UPGRADE-PORT.md`. Server mirror:
`clear_session` at relay-emit destroys the puncher (JS `_clearLater` keeps the
session until upgrade/close).

## B. Symmetric-NAT batch (client-side punch is effectively dead) — VERIFIED

The residual "phone on Cosmote CGNAT still flaky" now has mechanics:

1. **Client Holepuncher built with no SocketPool and no PunchStats**
   (`holepunch.cpp:1353` two-arg ctor → `pool_`/`stats_` null). The
   RANDOM+CONSISTENT strategy needs `pool_` to open birthday sockets
   (`holepunch.cpp:358-361` → returns false when null) → a client behind
   symmetric NAT never runs the birthday attack; JS succeeds. Random-punch
   throttling (`stats_`) silently skipped too.
2. **Birthday probes all egress from ONE socket** — the 256 holders only
   recv (`holepunch.cpp:661-665`); every send goes through `send_ttl_fn_` →
   the single PunchState pool socket (`holepunch.cpp:669-671, 715-720,
   1358-1360`). JS sends from each acquired socket (`holepuncher.js:264,
   271-276`) — source-port diversity IS the birthday paradox. Success
   collapses from birthday-odds to ~1/64000. (EMBEDDED compounding:
   BIRTHDAY_SOCKETS=8 there.)
3. **Server TRY_LATER treated as fatal** (`holepunch.cpp:1738-1741`
   completes `{}` on any round-2 error). JS waits 10-20s and retries round 2
   (`connect.js:527-533, 698-701`). Server-side random-punch throttle
   (1 per 20s) therefore converts into client hard-fail `-5`.
4. **Random-punch throttle fails instead of waiting, after announcing
   punching** — JS blocks/retries BEFORE sending round 2 `punching:true`
   (`connect.js:638-664`); cpp checks inside `punch()` AFTER round 2 is on
   the wire and returns false (`holepunch.cpp:345-368`), and
   `holepunch.cpp:1764` ignores `punch()`'s return → silent stall to
   timeout instead of queueing (or fast REMOTE_NOT_HOLEPUNCHABLE).
5. **NAT reopen recovery unwired** — JS `analyze(true)` → `_reopen()` loop:
   fresh socket + re-sample up to 3×, then restart round 1
   (`holepuncher.js:85-93, 152-159`, `connect.js:605-609`). cpp: `on_reset_`
   never set, always reports false (`holepunch.cpp:581-593`), and the
   round-1 restart is a TODO (`holepunch.cpp:1623-1628`). Flaky/mobile NATs
   abort where JS recovers.
6. Smaller, same area: UNKNOWN local firewall punched as CONSISTENT
   (`holepunch.cpp:330`; JS declines); CONSISTENT+RANDOM skips the
   verified-remote gate (`holepunch.cpp:342-356` vs `holepuncher.js:194`);
   `update_remote` loses sticky verification for secondary addresses
   (`holepunch.hpp:294-301` clears before checking); client doesn't feed
   holepunch replies into its NAT sampler (`connect.js:578` missing);
   cpp-only ~0.5-2.5s extra latency before round 2 (`holepunch.cpp:1774+`).

## C. Reliability batch (dht-rpc/query) — VERIFIED

1. **HIGH: announce/put can hang forever.** Commit requests are sent with no
   timeout callback (`dht_ops.cpp:128, :167, :281` — 2-arg `request()`);
   only responses decrement `commit_inflight_` (`query.cpp:535-541`). One
   commit target dropping 4 packets → `on_done` never fires + Query leaks.
   JS commits reject on timeout and always complete (`query.js:236-247,
   392-402`). Affects every announce on a lossy link — nospoon servers
   re-announce continuously.
2. **MED: all-tokenless/empty commit set = silent SUCCESS**
   (`query.cpp:524-531`); JS destroys with "Too few nodes responded"
   (`query.js:225-229`). Caller believes record stored when it's nowhere.
3. **MED: `request()` return value ignored in query visits**
   (`query.cpp:242, 257-265`) — under congestion (pending_ cap 640) the
   visit is dropped, `inflight_` never decrements → wedged query. Also
   visit retries 3 (DEFAULT_RETRIES) vs JS 5 (`query.js:28-29`).
4. **HIGH (scoped): `opts.ephemeral=false` / `bootstrapper()` never applied**
   — `dht.cpp:379` sets the flag, nothing consumes it; storage commands are
   dropped while ephemeral (`rpc_handlers.cpp:167`). Private testnets /
   bootstrap nodes built on cpp can't serve storage. Public-net nospoon
   unaffected.
5. **MED: DOWN_HINT never sent** (handled only, `rpc_handlers.cpp:282`);
   JS gossips dead nodes (`query.js:298-332`). Slower network self-healing.
6. **MED: no UNKNOWN_COMMAND / INVALID_TOKEN error replies** — bad token or
   unknown command just times out (`rpc_handlers.cpp:124,158,178,526-529`);
   JS replies typed errors immediately (`io.js:94-101`, `index.js:679-686`).
   Slows peers; blocks fast plugin-command negotiation (upstream cmd 10).
7. **MED: bootstrap is IP-only, single pass** — no DNS resolution, no
   `ip@host` fallback form (`dht_network.cpp:53-109`, hardcoded IPs in
   `dht_ops.cpp:31-38`); JS resolves hostnames + runs a 2-pass bootstrap
   with a quick NAT probe (`index.js:389-432, 877-908`). Hardcoded bootstrap
   IPs rot silently.
8. **MED: NAT sampler fed only by responses** (`rpc.cpp:711-718`); JS also
   samples inbound requests (`index.js:632-635`). A server-heavy node (Pi5)
   starves its sampler → slower/never persistent transition.
9. **MED (topology-specific): cpp-only per-IP rate limits** — FIND_NODE and
   DOWN_HINT 1/sec/IP (`rpc_handlers.cpp:257-269, 300-313`). Several peers
   behind one CGNAT IP querying a cpp node get silently dropped. JS has no
   such limit — consider keying by (ip,port) or raising the cap.
10. LOW: query surfaces error responses to `on_reply` (JS filters,
    `query.js:287-296`); nat-sampler host/port from single sample (JS wants
    consensus, nat-sampler `index.js:18-47`); adaptive timeout ignores
    attempt count; refresh timer not reset on query start.

## D. Streams batch (secret-stream / protomux / blind-relay)

1. **HIGH (latent): protomux data frames encode the WRONG channel id** —
   cpp sends `remote_id_` (`protomux.cpp:251-260`), JS sends the sender's
   OWN `_localId` (`protomux/index.js:275`), and both receivers index by the
   sender's localId. Works today only because blind-relay opens one channel
   per mux (ids collide at 1). Any multi-channel or order-skewed peer →
   misrouted/dropped frames. Fix: encode `local_id_`.
2. **MED: connect gated on both headers** (`secret_stream.cpp:733-737`,
   write refuses `-2` before that); JS is writable as soon as the LOCAL
   handshake completes (`index.js:436-438`) — cpp adds ~½-1 RTT to first
   byte.
3. **MED: keepalive/timeout uv timers never unref'd** (JS unrefs both,
   `index.js:102,115`) — any live duplex pins `uv_run` open; embedders that
   drain the loop to exit hang until explicit destroy. Related LOW:
   `end()` doesn't stop keepalive (JS `_final` clears it).
4. **MED: `enable_send=false` kills outbound `send/trySend`**
   (`secret_stream.cpp:354-356, 817`); in JS the flag only suppresses the
   inbound message listener — send always works.
5. **MED: premature raw close reported as clean** — no `_ended`-style
   dual-counter (`index.js:71, 215-217, 279-282, 505`); reconnect logic
   can't distinguish abrupt vs graceful teardown.
6. **MED: batching divergences** — corked batch never split at 8MiB
   MAX_BATCH (oversize frame → whole batch lost via `-4`); cpp-only
   MAX_BATCH_ENTRIES=1024 silently truncates inbound batch tails
   (`protomux.cpp:669-677`); cpp-only 32KiB pending-message cap DROPS
   messages JS would buffer-and-pause (`protomux.cpp:728-730`).
7. **MED: blind-relay lifecycle** — pair confirmation can be sent on an
   already-closed channel during graceful shutdown (`blind_relay.cpp:545-563`
   pass order; JS sends confirmation first, `index.js:174-182`); cpp-only
   30s pairing TTL evicts slow second peers (JS keeps pairs indefinitely,
   `blind_relay.cpp:353-362`) → both sides wait forever; `Server::close()`
   destroys sessions synchronously vs JS awaiting graceful end
   (`blind_relay.cpp:344-350`); `on_unpair` clears only the receiving
   session's tokens (`blind_relay.cpp:585-592`).
8. LOW: timeout refresh per-decrypted-frame vs per-raw-chunk; malformed
   protomux/blind-relay messages decode to partial structs instead of
   destroying (JS compact-encoding throws → stream destroyed); nested
   batches ignored; open-message duplicate/sequence validation missing;
   `raw_bytes_read` counts framing (metrics only).

## E. Connect/server batch (beyond the relay-upgrade area)

1. **MED: handshake dedup registered after async processing**
   (`server.cpp:879`); JS stores the in-flight promise synchronously
   before any await (`server.js:467-473`, explicit anti-flood comment).
   Duplicate Noise msg1 replays each get fully processed (extra streams,
   double msg2) until the first completes.
2. **MED: reusableSocket** — client hardcodes `false` in its handshake
   payload (`peer_connect.cpp:336, :431`) so JS/cpp servers never cache a
   route toward us mid-protocol (server-side advertise + FFI opt exist);
   meanwhile the cpp client caches + tries routes unconditionally
   (`connect.cpp:138-142, 474`) where JS gates both on the option
   (`connect.js:177, 473`); cpp server never stores routes at all
   (`server.js:315-317` has no counterpart). Route cache also has no GC on
   socket close / error demotion (JS socket-pool `index.js:79-100`).
3. **MED: ConnectionPool dedup dead** — `connect()` with a pooled duplicate
   returns error `-7` instead of the existing stream (`dht.cpp:569-574`),
   and in-flight connects are never attached (`attach_stream`/`mark_opened`
   defined, never called) → concurrent dials to one key duplicate.
4. **MED: direct-connect address selection** — no bogon filtering, no
   serverAddress fallback (`connect.cpp:629-650`, `holepunch.cpp:244-250`
   vs `connect.js:196-219`): a peer listing a private address first breaks
   cpp direct connect.
5. LOW: error-code granularity collapsed (single `-5` for six JS codes);
   version-mismatch/server-error retried against other relays instead of
   fast-fail (`peer_connect.cpp:389`); `opts.relay_addresses` ignored
   (JS closestNodes/onlyClosestNodes/retries shaping, `connect.js:320-347`);
   persistent-node router shortcut missing (`connect.js:327-333`);
   server `holepunch === false` never-punch mode inexpressible (veto ABORTS
   instead, `server.cpp:1047-1051`).

## F2. 2dfa977 regression — CONFIRMED + FIXED tonight (uncommitted)

Reported by a second agent, verified against JS, both claims true plus one
more:

- `on_peer_holepunch` silently drops rounds for unknown sessions
  (`server.cpp:926-928`). `2dfa977` wired the server puncher's `on_abort`
  to clear the session at **+1ms** after the server's probe schedule ends.
  A symmetric-CGNAT client is still punching then (late rounds, retries;
  findPeer alone can take 20s+) → its rounds hit a cleared session → drop →
  connect only succeeds after a fresh handshake cycle.
- JS truth (`server.js:401-412, 439-448`): `onabort` never erases the
  session directly — it destroys the raw stream and the session GCs via
  stream close → `_clearLater` → **handshakeClearWait = 10s** grace.
- Additional regression surface the report missed: JS `onabort` skips the
  teardown entirely while a relay is engaged (`hs.relayToken !== null`) —
  the blind-relay pairing may complete after the puncher gives up. `2dfa977`
  cleared unconditionally → could kill in-flight relay pairings too.

Fix (working tree, `server.cpp` on_abort): defer clear by
`handshake_clear_wait` (10s) instead of 1ms, and skip fast-clear when
`relay_token` is set (45s backstop owns that case). Storm protection
preserved: sessions die at schedule-end + 10s, not 45s. 48/48 server unit
tests pass. Interim mitigation if deploying before this lands: re-pin
nospoon to `a35cb2a` (drops only 2dfa977 — but that restores the 45s
reconnect-storm window; the tree fix supersedes both).

## IMPLEMENTED tonight (working tree, branch fix/relay-direct-upgrade, UNCOMMITTED)

All landed with the full unit suite green (583/583, +2 new tests) and ASAN
showing no new leaks/UAF (the 99 ASAN failures are pre-existing teardown
leaks, confirmed identical with the changes stashed).

1. **Background-tick parity** (§F) — `_onwakeup` sleep detection, `_pingSome`,
   thin-table refresh, same-NAT-host guard. `test/test_tick.cpp` (10 tests).
2. **2dfa977 regression** (§F2) — abort clear deferred to `handshake_clear_wait`
   (10s) + `relay_token` gate. `server.cpp` on_abort.
3. **Finding #1 (relay stream destroyed by plain session timer)** — the plain
   session timer now defers to the relay backstop while a relay pairing is in
   flight (`session_relay_engaged` helper, shared with the abort path). No
   change to *who* destroys the stream, only *when*. This closes the second
   manifestation of the a35cb2a class (abort/timer racing the relay callback).
   Latent for nospoon (no relay_through) but live for relay/RustDesk work.
4. **punch() idempotence** — `if (punching_) return true;` guard
   (`holepunch.cpp`), matching JS `holepuncher.js:161-164`. A JS client or an
   RPC retransmit sending multiple punching rounds no longer resets the
   server puncher's schedule, so on_abort fires at schedule end as intended.
5. **Finding #3 (connect leak on reconnect)** — `UvTimer` now releases its
   callback after a one-shot fires (`async_utils.hpp`), breaking the
   `ConnState → UvTimer → cb → ConnState` cycle that leaked a udx_stream +
   raw DHT/socket pointers on every nospoon network-switch restart.
   Reentrancy-safe (move-out-before-invoke). Not a JS-parity item — pure C++
   lifetime bug (JS has GC). nospoon should still lengthen its 5s post-restart
   DHT-delete defer to >15s (relay timeout); that's the consumer-side half.
6. **Finding C1 (announce/put hang forever)** — commit requests now wire both
   response AND timeout (+ congestion-drop) settlement so a single lost store
   packet can't wedge the query (`query.cpp` do_commit, `dht_ops.cpp` ×3,
   `OnCommitCallback` signature). Counter fully set before dispatch so a
   synchronous drop can't complete the query early.
   `test/test_query.cpp::CommitTimeoutStillCompletes`. Matches JS
   `query.js:236-247`.

Still OPEN from the audit (descending nospoon impact): Finding #2 (256-cap
silent drop → reply TRY_LATER; touches wire path), the symmetric-NAT client
batch (§B), the relay→direct upgrade port (§A / task #2), protomux channel-id
(§D1), read backpressure, Finding C2 (all-tokenless commit = silent success;
needs an on_done error channel).

## F. Background tick — FIXED tonight (branch fix/relay-direct-upgrade)

`_onwakeup` sleep detection, `_pingSome` every 8th tick, thin-table refresh,
same-NAT-host skip guard, bootstrapped gate, JS execution order, resume =
wakeup+refresh. `test/test_tick.cpp` (10 tests) + full suite 582/582.

## G. Upstream drift (6.29.1 → main; full sweep in agent report)

- **Verified SAFE**: #240 refresh-only-announce crash — cpp already checks
  `peer.has_value()` first (`rpc_handlers.cpp:537`); UNANNOUNCE same.
- **libudx pin 8 commits behind** udx-native 1.20.7's (`0420f62` →
  `759bf76`): UAF-on-RTO fix, immediate close-packet cancel, SACK
  validation, relayed-packet forwarding fix (#291 — likely load-bearing for
  the relay-upgrade port). Bump before/with the #266 port.
- **Port with the #266 work**: #251 (relay teardown; superseded by #266
  confirm-based flow), #268/#266 (in design doc), invalid-port firewall
  guards #243 + udx#77 (client+server, port 0/65536), #248 client abort
  actually transmitting ABORTED (verify our path), #259+#272 LAN
  prepunch/shortcut races (read together).
- **Later**: #237 hyperdht-address + pre-connect (pairs with relay-cache
  full-walk change), plugin cmd 10 graceful UNKNOWN_COMMAND (needs C6),
  dht-rpc health OFFLINE_THRESHOLD=2.

## H. Status corrections

- WAF `Query::push_closest` crash: LIKELY FIXED May 20 (`0f8b3b3` +
  nospoon `2763b2b`) — doc annotated, reopen only on post-fix repro.
- `_relayAddressesCache`: implemented since April (`c196205`) —
  REMAINING-WORK.md entry stale.
- Reconnect storm + relay-emit destroyed stream: fixed `2dfa977`/`a35cb2a`,
  deployed (nospoon pin `9aa515a`).

---

## Proposed fix order

1. **Relay→direct upgrade port** (A) + libudx bump + #243/udx#77 guards —
   the nospoon connected-no-data killer. `docs/RELAY-UPGRADE-PORT.md`.
2. **Symmetric-NAT batch** (B1-B5) — wire pool+stats into the client
   puncher, per-holder birthday sends, TRY_LATER wait/retry, throttle
   before round 2 + honor `punch()` result, reopen loop + round-1 restart.
   This is the Cosmote-phone fix.
3. **Commit-path reliability** (C1-C3) — timeout callbacks on commits,
   too-few-nodes error, request() return handling. Small, high value.
4. **Protomux channel-id fix** (D1) + invalid-port guards — small patches,
   interop insurance.
5. **Tick parity** (F) — done.
6. Backpressure (existing task), dedup timing (E1), reusableSocket
   plumbing (E2), pool dedup (E3), stream lifecycle items (D2-D7),
   remaining C/E/G items in descending severity.
