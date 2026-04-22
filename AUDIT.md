# JS Parity Audit — 2026-04-19

Short-term tracking for findings from the JS vs C++ comparison audit.
This file is gitignored.

## 1. Dual socket architecture (DOWNGRADED — was CRITICAL)

JS dht-rpc splits at the RPC layer: `serverSocket` (stable identity) +
`clientSocket` (ephemeral outgoing) in io.js.

C++ splits at the holepunch layer instead: main socket (RPC relay) +
pool socket (ephemeral probes) via SocketPool (commit 054ad8c). The
functional separation is equivalent — probes go through pool, identity
through main.

**Remaining narrow gaps:**
- PING_NAT firewall probing: JS uses server/client socket split to verify
  port consistency (`_checkIfFirewalled`). Affects NAT classification
  accuracy, not connectivity.

**Status:** Mostly done (054ad8c). Remaining gap is LOW priority.

## 1b. Nospoon coexistence — DISMISSED

Initially suspected dual-node interference. Disproved: JS holesail server
+ holesail-py coexist fine on the same Pi5. The interference is
nospoon-specific (likely its VPN routing), not a hyperdht-cpp issue.

## 2. findPeer pipelined with handshake (HIGH — latency)

JS starts handshakes as findPeer results stream in (`for await (const data of c.query)`).
We wait for findPeer to complete, then start handshakes.

**Impact:** First connect is 2-4 RTTs slower than JS.

**Where:** `connect.js:350` vs `dht.cpp:1181`

**Status:** FIXED — `fire_handshake()` now fires from `on_reply` callback with
Semaphore(2) concurrency limit. `check_exhaustion()` shared helper prevents
termination gaps between `try_next_relay` and `on_done`.

## 3. Relay address cache (HIGH — reconnect speed)

JS caches relay addresses (512-entry LRU `_relayAddressesCache`).
Reconnects skip the full Kademlia walk.

**Where:** `connect.js:323-324, 464-466`

**Status:** FIXED — 512-entry `relay_address_cache_` on HyperDHT class.
Cached relays pre-populate handshake pipeline before findPeer starts.

## 4. Puncher not destroyed in on_socket (MEDIUM)

JS destroys the Holepuncher inside `onsocket` (`server.js:336-338`).
We weren't doing this — puncher kept probing after connection.

**Status:** FIXED — commit 829f875

## 5. OPEN shortcut doesn't cancel session timer (LOW)

`on_socket` called from the OPEN path (line 741) doesn't cancel the
session timer or erase from connections_. Timer fires 10s later, harmless
but wasteful.

**Where:** `server.cpp:741` vs `server.js` _clearLater pattern

**Status:** Non-issue. Verified: OPEN path returns at line 741 before the
timer setup at line 765-769. Timer is never created.

## 6. Router forward table shortcut (LOW)

JS checks `_socketPool.routes` for previously-connected peers — zero
findPeer RTTs on reconnect.

**Where:** `connect.js:177-183`

**Status:** FIXED — `do_connect()` checks `SocketPool::get_route()` before
findPeer. Routes stored after successful connect via `add_route()`.
SocketPool constructed in `bind()`.

## 7. Stream drain callback (LOW)

`hyperdht_stream_write` returns 0 on backpressure but no drain callback
to signal readiness. JS has `socket.on('drain', ...)`.

**Where:** ref holesail-nix commit 4563f71

**Status:** FIXED — `hyperdht_stream_write_with_drain()` added to C FFI.
Bridges existing `WriteDoneCb` through. Guards against use-after-close.
