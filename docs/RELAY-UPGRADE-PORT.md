# Relay→Direct Upgrade Port (JS PR #266 family)

Design doc for porting the JS relay→direct upgrade handoff + relayed keepalive
into hyperdht-cpp. Distilled 2026-07-08 from two research passes: a mechanical
spec of upstream PR #266 and a full flow map of the 6.29.1 reference in
`.analysis/js/`.

## The root cause this fixes

cpp runs blind-relay and holepunch as a **race** — first `complete()` wins
(`connect.cpp:582`), the loser is discarded. A successful punch after a relay
win is dropped at `connect.cpp:772`; its `socket_keepalive` is released, so the
punched PoolSocket **closes**.

JS instead emits the connection on the relay fast path and keeps punching; when
the punch lands, `onsocket` migrates the *same live stream* onto the direct
socket via `rawStream.changeRemote(...)` (`connect.js:453-487`,
`server.js:305-342`, branch on `rawStream.connected`).

Kill-chain vs a JS peer: cpp client rides relay → punch succeeds → cpp discards
result and closes the punched socket → JS peer (6.29.1 migrates unilaterally,
no confirmation step) switches its end to the direct path → its packets land on
the closed socket → stream starves → ETIMEDOUT (-110) → "reconnecting".

Server-side mirror: cpp `clear_session` at relay-emit destroys the puncher, so
a cpp server can never complete its punch after emitting a relayed connection.
JS keeps the handshake session alive until upgrade or stream close
(`_clearLater`, `server.js:308`). `a35cb2a` fixed the emitted-stream UAF
symptom of this divergence; this port fixes the session-lifetime root.

## Target semantics: post-#266, not 6.29.1

Upstream history of the upgrade teardown:

1. **6.29.1**: after upgrade, the relay control connection is *never* closed —
   it idles with keepalive until the app stream closes. Punch failure → stay on
   relay forever (that's a supported steady state, kept alive by keepalives).
2. **Intermediate main**: closed the relay on local `remote-changed`. Wrong —
   local completion only proves *our* side switched; the peer may still be
   acking over the relay (upstream PR #268 analysis: peer left stranded).
3. **PR #266 final (merged 2026-06-30, unreleased, post-6.32)**: close the
   relay only after receiving traffic that **provably arrived on the direct
   path**. This is our port target. Interop-safe with 6.29.1 peers: against a
   peer that never closes its relay end, we still confirm and close ours; a
   pure-relay connection (punch failed) never closes it — matching 6.29.1.

## #266 mechanics (what we port)

State per connection/handshake: `validUpgrade = true`.

**Firewall callback** (fires per packet whose source socket != stream's current
socket; udx `streams_by_id` is shared on `udx_t` so relay stragglers still
resolve — `deps/libudx/src/udx.c:1458-1473`):

```
if from relay path (isRelay: socket+port+host match relay rawStream):
    validUpgrade = false; accept packet; return
validUpgrade = true
onsocket(socket, port, host)         // upgrade trigger
```

**onsocket** (one-shot; both sides identical shape):

```
if rawStream == null: return                    // already upgraded
if rawStream.connected:                         // relay won earlier
    ret = changeRemote(direct socket, remote_udx_id, port, host)
    confirmDirectUpgrade(ret)
else:                                           // no relay path yet
    connect(direct socket, ...); create/start secret stream; emit
cache reusable route if both sides reusableSocket
destroy puncher (onabort = noop first)
rawStream = null                                // one-shot
```

**confirmDirectUpgrade**:

```
when remote-changed complete (ret==1: immediately; ret==0: on callback):
    hook data + message + close on the raw stream
    send ONE zero-length udx message (nudge: peer's firewall sees a
        direct-source packet; with keepalive on, empty secret-stream frames
        are eaten, so the nudge must be raw udx)
    ondirect (any data/message received):
        if !validUpgrade: validUpgrade = true; return   // relay straggler
        unhook; closeRelayConnection()                  // graceful end
```

**closeRelayConnection** = null relay refs (so isRelay stops matching), clear
relay timeout, `.end()` the relay control stream. `destroyRelayConnection`
(same + `.destroy()`) stays wired to: raw stream close, pair error, 15s relay
timeout.

**Relayed keepalive** (the second half of #266): the emitted app stream on the
server relay path must inherit `connectionKeepAlive` (JS had `keepAlive: 0`
there; client side always had it). cpp note: our FFI consumer applies
`make_duplex_options()` → `keep_alive_ms = connection_keep_alive` (default
5000) on both paths already — verify all consumers (C++ API examples included)
get keepalive on relayed streams, and that empty-frame swallowing is gated on
`keepAlive != 0` like JS secret-stream (`plain.byteLength === 0 && keepAlive
!== 0 → swallow`).

## libudx contract (verified in deps/libudx)

- `udx_stream_change_remote(stream, socket, remote_id, addr, cb)` (udx.h:638):
  applies socket/remote switch immediately; **returns 1** = no unacked
  in-flight → callback will NEVER fire (treat as confirmed now); **0** =
  deferred → callback fires when the peer acks packets sent post-switch;
  **negative** = error → stay on relay, do not treat as fatal.
- Preconditions: stream CONNECTED, not DEAD, port != 0, same `udx_t`
  (`assert` aborts on different udx — all our sockets live on one
  `udx_handle()` per DHT, but validate anyway).
- Retransmits of packets queued pre-switch still go to the old remote
  (udx.h:417-419) — the drain the deferred callback waits for.
- `change_remote` resets the MTU state machine (`reset_mtu_state_machine`,
  udx.c:2445) — also re-probes path MTU on the new path. (Bonus: mid-connection
  path-MTU shrink is a suspected cause of the bulk-transfer -110; migration
  re-probes.)
- Firewall return: nonzero = drop, 0 = accept (udx.c:1471). JS always accepts
  and uses the callback purely as the wire-up signal.
- Zero-length nudge: `udx_stream_send` (already used, secret_stream.cpp:827);
  message receive already wired (`udx_stream_recv_start`,
  secret_stream.cpp:453).

## Lifetime hazards (catalogued 2026-07-08, ownership-map pass)

1. ~~Server emits a stream its own `clear_session` destroys~~ — fixed
   `a35cb2a` (stream detached from session before clear).
2. Nothing owns the client relay control connection after completion — it
   survives via an accidental ref cycle `state → relay(unique_ptr) → client →
   pair-callback → state` (`connect.cpp:97-114,918`). Server: relay duplex
   lives only in the pair-success lambda. Port must introduce an **explicit
   relay owner** released by confirmDirectUpgrade / stream close.
3. Two sockets must stay alive during the upgrade window (relay socket + direct
   pool socket). The consumer's `socket_keepalive` (ffi_stream.cpp:136-143) is
   captured once at open and pins only the relay socket. Manage relay-vs-direct
   socket lifetime inside the DHT layer; on upgrade, take over
   `hp.socket_keepalive` (currently dropped at connect.cpp:772-776).
4. `change_remote` ret==1 → callback never fires. State machine must not wait
   unconditionally.
5. Same-`udx_t` assert is a hard abort — validate before calling.
6. Preconditions can fail benignly (port 0, stream dead from racing teardown)
   → treat as "stay on relay".
7. The emitted stream's firewall ctx is currently nulled at completion
   (`take_raw_stream`, connect.cpp:153; ffi_stream.cpp:48) — the upgrade
   needs a live ctx for the whole stream lifetime, freed on stream finalize.
8. Duplex vs stream teardown ordering: `SecretStreamDuplex::destroy()`
   destroys the raw stream (secret_stream.cpp:612-614). One owner must be
   unambiguous post-port (double-destroy risk when the relay finally closes).

Also: JS `onsocket` is one-shot (`rawStream = null`) — mid-connection NAT
remaps after the upgrade are NOT handled by JS either. Parity means one
upgrade, not a general migration engine.

## Port structure

- New module `include/hyperdht/relay_upgrade.hpp` + `src/relay_upgrade.cpp`:
  `RelayOwner` (duplex + mux + blind-relay client + socket keepalive + timeout)
  and the `confirmDirectUpgrade` state machine, shared by client and server.
- `SecretStreamDuplex`: optional raw-activity tap (data/message arrival), no
  behavior change when unset.
- Client (`connect.cpp`): keep firewall ctx alive on the emitted stream;
  `onsocket`-equivalent; punch-success-after-relay triggers upgrade instead of
  early return; take over pool socket keepalive; destroy puncher on upgrade.
- Server (`server.cpp`): on relay-emit, stop clearing the whole session —
  strip the timer, transfer the stream (a35cb2a), keep puncher + handshake
  state until upgrade / abort / backstop (JS `_clearLater` parity). Punch
  success after emit → onsocket-equivalent → changeRemote. Respect
  `67e05a3`/`2dfa977` timer semantics for the punch-fail path.

## Upstream tracking

- #266 merged 2026-06-30 (`120364a7`), NOT in any release (latest v6.32.0
  predates it). Included test coverage: relayed keepalive inheritance +
  3-config upgrade test (default keepalive / no keepalive + app-data confirm /
  idle without keepalive).
- #272 "Fix server lan prepunch" (`69bfcf0b`, 2026-07-07) touches server
  holepunch setup (`setupHolepuncher`, `replyFromPuncher`, `to: serverAddress`)
  — separate parity item, not part of this port.
