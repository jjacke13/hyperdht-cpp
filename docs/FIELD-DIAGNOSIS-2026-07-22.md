# Field diagnosis: nospoon connect failures, 2026-07-22

Answer to `HANDOFF-NOSPOON-FIELD-2026-07-22.md`. Root-caused from three parallel
code traces (announcer lifecycle, NAT-sampler classification, punch abort/retry)
plus the operator's follow-up field data. All file:line refs at HEAD `2d54afb`.

## TL;DR

**One root cause explains every observed failure: Finding A.** The server is
reliably reachable only in the window right after a full announce cycle, on any
client network. Finding B (NAT misclassification) turned out to be real code
debt but NOT implicated in the observed failures — the operator's phone succeeds
from BOTH mobile data and CGNAT wifi when the attempt lands in the fresh window
(same fast-mode-ping path, confirmed by server logs from both networks). The
failure variable is *when in the announce cycle the attempt lands*, not the
client's network.

## Finding A — root cause chain

The relay that forwards client handshakes to the server uses the forward state
it stored **at announce time**: `relay: req.from` (JS persistent.js:131-138) —
the server's external UDP address as observed when the ANNOUNCE arrived. The
punch coordination additionally relies on the relay's fresh observation of the
client's punch socket (`peer_address` in the holepunch payload).

Death mode: the server's ~5s relay keepalive (`ping_relays()`,
src/announcer.cpp:190-226) only proves "the relay's DHT node answers PING". It
never exercises the client→relay→server forward path and never rewrites the
relay's stored forward address. When the server's NAT mapping drifts, the relay
keeps forwarding handshakes to a dead port; the server sees NOTHING; the health
check stays green (it only counts PING responders). Heal happens only at the
next full reannounce (REANNOUNCE_MS = 5 min). Decay (NAT UDP idle 30-120s or a
remap event) ≪ heal (5 min) ⇒ multi-minute black window at the tail of every
cycle. JS shares the same structural blind spot; three things made C++ worse:

- **D1 — `relays_` publishes one cycle stale.** `build_relays()` runs in the
  find_peer COMPLETION callback (announcer.cpp:252-257) but `active_relays_` is
  filled by ANNOUNCE-response callbacks that land later (:308-336). JS awaits
  all ANNOUNCE responses before publishing (announcer.js:154-189).
- **D-A — regression in `2d54afb` (announce-4).** The removed "re-announce
  ONCE" second `update()` was a bandaid that masked D1 at startup and at the
  persistent transition. Removing it stretched the warmup from seconds to a
  full 5-min cycle — the operator's "fresh server works; after that, wait 1-2
  reannounce cycles" observation.
- **D-B — no closestNodes reuse.** C++ re-walks find_peer from bootstrap every
  cycle (dht_ops.cpp:46-60); JS seeds with the previous cycle's closest nodes
  (announcer.js:156,187) so the SAME relays get their forward state refreshed
  every cycle. C++ relay churn leaves dropped relays' forward state to rot.
- **D-C — the one cheap signal was discarded.** Every keepalive pong carries
  the relay's live observation of our external address (wire `to` field);
  C++ read it and threw it away (announcer.cpp:206-215). Comparing it against
  the stored `peer_addr` detects forward-state staleness in ~5s instead of
  5 min.

### Fixes (this repo, post-`2d54afb`)

1. Publish-after-settle: `build_relays()` runs only after the query completes
   AND every ANNOUNCE commit resolves — proper D1 fix, replaces the D-A bandaid.
2. Drift detection: keepalive pong `to`-field vs stored `peer_addr`; mismatch →
   `refresh()` (rate-limited). Deliberate beyond-JS improvement.
3. closestNodes reuse across announce cycles (JS parity).
4. Field-grade DHT_LOG on all of the above.

## Finding B — demoted to code debt (not field-implicated)

The operator's phone connects from BOTH networks via the identical path:
handshake → holepunch payload carries the relay's fresh `peer_address`
observation of the client's punch socket → server fast-mode pings it → punch
lands from exactly that port. Confirmed in server logs for mobile data
(`5.203.174.17:3789`) and CGNAT wifi (`46.177.170.175:56067`). Neither network
is behaving symmetric; the "every punch fails" wifi session was a stale-window
artifact of Finding A.

Real bugs found by the trace, queued as parity debt (fix later, not blocking):

- **B1 — classification latches at 3 samples.** `NatSampler::add` classifies at
  `sampled_ >= 3` (src/nat_sampler.cpp:111); `MIN_SAMPLES = 4`
  (src/holepunch.cpp:1197) only feeds an `ok` flag nobody reads — downstream
  reads `firewall()` live. Three agreeing low-RTT samples latch CONSISTENT.
  Once latched, later samples cannot undo it.
- **B2 — Round-2 payload hardcodes ONE address** (src/holepunch.cpp:1880-1885,
  `our_addr = resp.from.addr`), ignoring `nat_sampler().addresses()`. JS sends
  the full nat.addresses set in both rounds (connect.js:567,654,684).
- False-CONSISTENT is never re-examined: `is_unstable()` only fires on
  UNKNOWN/double-RANDOM (both impls), and the C++ reopen path re-samples the
  SAME pool socket (upgrade-port pin), so it cannot reveal per-socket
  randomization the way JS's fresh-socket `_reset` can.
- Ruled out: connect-5 bogon filtering CANNOT eat punch targets — the holepunch
  probe path (fast-open `hs.server_address`, round-1 `server_addrs`) is
  entirely unfiltered. `2d54afb` introduced no probe-targeting regression.
- Also ruled out: serving a connection does NOT disturb announcer/relay state
  (no code path writes announcer state from connection handling) — the
  "disconnect then immediate retry fails" pattern is stale-window timing.

## Finding C — parked

`-110` under bulk traffic: untested MTU hypothesis vs relay-migration; needs a
field load test on a stable connection, which is blocked on Finding A being
fixed first.

## Retest checklist (after the Finding A fixes deploy)

1. Fresh server → connect from wifi AND 4G: expect success (baseline).
2. Disconnect → IMMEDIATE reconnect, repeatedly, across >10 min: expect success
   at every point in the announce cycle (the fix's central claim).
3. Watch server log for `drift` lines: NAT remap events should trigger a
   refresh within ~5-10s instead of a silent black window.
4. Only if a failure survives all that: revisit Finding B (enable debug JNI,
   capture client-side sampler counts).
