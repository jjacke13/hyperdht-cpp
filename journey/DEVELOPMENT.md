# Development Journey -- hyperdht-cpp

The story of building the first wire-compatible non-JS HyperDHT implementation.

## Why

[nospoon](https://github.com/jjacke13/nospoon) is a P2P VPN built on HyperDHT. It works, but it requires Node.js -- a 50MB runtime dependency. The goal: eliminate that dependency entirely by reimplementing HyperDHT in C++. This also enables:

- Single static binary for the VPN (no runtime)
- ESP32 firmware (mimiclaw) joining the DHT natively
- Language bindings for Python, Go, Rust, Swift, Kotlin via C API
- Mobile apps without BareKit/JS worklets

## The Challenge

No HyperDHT protocol specification exists. The "spec" is the JavaScript source code across 15+ npm packages. Previous attempts to port HyperDHT (Go in 2021, Rust in 2024) all failed -- none achieved wire compatibility with the JS network.

We reverse-engineered the protocol from the JS source and documented it in [PROTOCOL.md](../PROTOCOL.md) -- now the most comprehensive HyperDHT protocol document in existence.

## Phase 1: First Connection (5 days)

### Day 1 (2026-03-30): Foundation

**Phases 0-1**: Project scaffold + compact encoding.

Set up CMake, libudx as a git submodule, GoogleTest, Nix devShell. Implemented the compact encoding library -- HyperDHT's wire format (varint, buffer, IPv4 arrays). 43 tests including 7 cross-verified against JS output.

**Key discovery**: The protocol docs we'd written had two bugs -- varint example was wrong, and IPv4 port encoding was LE not BE. Found by cross-testing against JS.

### Day 2 (2026-03-31): The Stack

**Phases 2-5**: UDX transport, DHT RPC, Noise IK handshake, SecretStream. Plus the first half of Phase 3 (messages, routing table, tokens).

The biggest surprise: HyperDHT uses Ed25519 for Noise IK, not X25519. The DH operation uses `crypto_scalarmult_ed25519_noclamp` with SHA-512 scalar extraction. The existing `noise-c` library can't do this -- we had to implement the Noise IK state machine ourselves (~300 lines).

**Cross-test milestone**: C++ Noise handshake byte-for-byte matches JS output. The real HyperDHT prologue (`hypercore-crypto.namespace`) computed correctly.

### Day 3 (2026-04-01): Connection Pipeline

**Phase 3 completion + Phase 6 + Phase 7 Steps 1-8**: All DHT RPC sub-components, Protomux, and the full connect/server pipeline.

**THE MOMENT**: C++ client connects to a live JS HyperDHT server over the public internet. Full pipeline: findPeer -> PEER_HANDSHAKE (Noise IK) -> PEER_HOLEPUNCH (NAT traversal) -> UDX stream -> SecretStream header exchange -> encrypted channel. ~4 seconds total.

But the reverse direction (JS client -> C++ server) didn't work. The handshake completed on our side, but the reply never reached the JS client. Three bugs fixed, still broken.

### Day 4 (2026-04-03): The Relay Bug

The most satisfying debugging session.

**Root cause**: When our server received a relayed PEER_HANDSHAKE, it sent a RESPONSE (type byte `0x13`) back to the relay. But dht-rpc's relay mechanism uses `req.relay()`, which sends a REQUEST (type byte `0x03`). The relay node expected to receive a REQUEST, process it in its `onpeerhandshake` handler (non-server path, `FROM_SERVER` mode), and convert it to a RESPONSE for the client. Our RESPONSE was silently dropped because the relay had no matching TID in its pending requests.

**One byte difference**: `0x03` vs `0x13`. Four days of debugging.

After the fix: JS client -> C++ server: **CONNECTED**.

Also on Day 4: All 10 HyperDHT commands implemented (client + server). Ed25519 signature verification on ANNOUNCE/UNANNOUNCE. Mutable/immutable storage (both directions cross-tested with JS). Hardening -- ASan/UBSan clean, 5 fuzz targets (36M runs), crypto review.

### Day 5 (2026-04-04)

C API (`hyperdht.h`) for FFI consumers. Python ctypes wrapper. CMake install rules + pkg-config. Nix package (static + shared). Three production bugs fixed (LRU cache for storage, timer UAF, socket lifetime). Python holesail tunnel serving a web page to a phone over the public DHT.

## Phase 2: JS Parity (2 weeks)

We thought we were done. We weren't.

Live testing against more JS peers revealed dozens of behavioral gaps -- things that worked in our unit tests but diverged from JS in edge cases. The lesson: **verify each layer against JS BEFORE building the next. Don't patch from the top.**

### Weeks 2-3 (2026-04-05 to 2026-04-14)

Systematic audit of every C++ file against the JS source. Added JS flow maps (exact C++ line -> JS file:line citations) to 16 source files. Tracked gaps in [JS-PARITY-GAPS.md](../docs/JS-PARITY-GAPS.md).

**What we found and fixed:**

- Server holepunch parity (NAT sampling, fast-mode ping, puncher->onsocket wiring)
- Pool socket for holepunch (dual-socket probing, JS uses a different socket per punch)
- Birthday paradox NAT strategy (256 sockets for RANDOM+CONSISTENT)
- Blind relay (Protomux channel over SecretStream, pair/unpair, udx_stream_relay_to)
- Connection pool (dedup connections by remote public key)
- Announcer re-announce cycle, router forward table
- Suspend/resume for mobile background transitions
- Health monitoring (4-tick sliding window, ONLINE/DEGRADED/OFFLINE)
- Ephemeral/persistent toggle (240-tick stability timer)
- Adaptive per-peer RTT timeout

**7 cpp-reviewer rounds** caught 68 bugs total:
- Memory safety (UAF, leaks, overflow): 12
- Protocol correctness (wrong constants, missing fields): 8
- Crypto (nonce handling, state machine): 5
- Logic errors (inverted checks, missing guards): 15
- API/design (callback asymmetry, raw pointers): 9
- Others: 19

The most impactful single bug: `has_bytes()` integer overflow -- a security vulnerability found by fuzzing that could cause OOM via crafted varint input. One-line fix.

### C FFI Expansion (2026-04-15 to 2026-04-16)

Expanded the C API from 22 to 76 functions targeting mobile/cross-language consumers. Added opaque query handles with two-layer shared_ptr ownership for UAF-safe cancel/done/free in any order. Explicit struct padding, stride constants, completion-callback patterns -- all designed for Swift C-interop and Kotlin JNI.

cpp-reviewer caught 2 CRITICAL UAFs in this expansion:
1. Async firewall callback storing pointers to stack-local variables
2. Query handle deleted in on_done lambda while user still holds it

Both fixed with ownership transfer patterns.

## Phase 3: Python Wrapper + Live Testing (2026-04-17)

### Python Wrapper Parity

Rewrote the Python wrapper to expose all 76 C FFI functions. Split into 4 modules (_ffi, _bindings, _server, __init__). Added Query, PunchStats, RelayStats, Address classes. 22 tests.

### Holesail Live Test

Rewrote the holesail tunnel server and tested it live -- a JS holesail client on a phone connecting through the public HyperDHT to a Python server running our C++ library. **Three bugs found in production:**

1. **Thread safety crash** -- the TCP bridge thread was calling `stream.write()` off the libuv event loop thread, corrupting libudx's packet reference counts. Manifested as `assert(pkt->ref_count == 2)` after ~9 connections. Fix: single-threaded event loop with `selectors`.

2. **Write before connected** -- the SecretStream header exchange hadn't completed when we tried to write the HTTP response back. The remote peer's data arrived (and was decryptable) before our own header send was ACKed, so `on_data` fired before `on_open`. Fix: defer TCP reads until `on_open`.

3. **Missing metadata** -- JS holesail clients do `mutableGet` before connecting to fetch port/protocol info. Without it: "cannot read property string of undefined". Fix: `mutablePut` at startup with `{host, port, udp}` JSON.

After fixes: web page served through the P2P tunnel, stable across 13+ connections, zero crashes.

## Protocol Gotchas

Non-obvious details that caused surprises:

1. **Noise curve is Ed25519, not X25519** -- `crypto_scalarmult_ed25519_noclamp` with SHA-512 scalar extraction. `noise-c` can't do this.

2. **BLAKE2b is 512-bit (64 bytes)** for the Noise hash, not 256-bit.

3. **HKDF uses HMAC-BLAKE2b** with 128-byte block length, not 64.

4. **dht-rpc relay sends REQUEST, not RESPONSE** -- TID preserved through `req.relay()`. The relay chain: CLIENT->REQUEST->RELAY->REQUEST->SERVER->REQUEST->RELAY->RESPONSE->CLIENT.

5. **Holepunch payload encryption**: XSalsa20-Poly1305 (`crypto_secretbox`), key = `BLAKE2b(NS_PEER_HOLEPUNCH, noise_handshake_hash)`.

6. **SecretStream first message**: `uint24_le(56) + 32-byte stream_id + 24-byte header`. Without this exact framing, decryption fails silently.

7. **on_data fires before on_open** -- SecretStream can decrypt incoming data before the local header send is ACKed. Writes fail until both headers are exchanged.

8. **libudx is single-threaded** -- calling any UDX function from a non-event-loop thread corrupts internal state silently. No error, no warning, just eventual crash.

## Previous Attempts

| Project | Language | Year | What Went Wrong |
|---------|----------|------|-----------------|
| tigerbot/hyperdht | Go | 2021 | Targets old v4 protocol, uses protobuf (wrong wire format) |
| datrs/hyperswarm-rs | Rust | 2024 | Partial implementation, doesn't interop with JS nodes |
| fsteff/libudx-rs | Rust | 2022 | FFI bindings only, no HyperDHT protocol |

## What Made It Work

1. **JS source as the spec**: Every line of C++ was written by reading the JS implementation. No guessing.

2. **Cross-testing at every phase**: C++ encode -> JS decode (and reverse) for every data type. Live tests against the public HyperDHT network.

3. **Incremental verification**: Each phase tested in isolation before building on top.

4. **Sanitizers + fuzzing early**: ASan/UBSan on every test run. Fuzz targets for all wire format decoders.

5. **Code reviews on every commit**: cpp-reviewer agent caught 68 bugs across 7 rounds. Most caught before they reached live testing.

6. **Live testing is non-negotiable**: Unit tests prove code correctness. Live tests prove protocol correctness. Several bugs only appeared against real JS peers.

## Stats

| Metric | Value |
|--------|-------|
| Source files | 35+ `.cpp` + 30+ headers |
| Lines of C++ | ~23,000 |
| C FFI functions | 76 |
| Tests | 569 unit + 6 live, ASAN/UBSan clean |
| Fuzz iterations | 36M+ |
| JS packages reverse-engineered | 15 |
| Commits | 112 |
| Bugs found by reviewer | 68 |
| Python wrapper | 76 functions, 22 tests, holesail live-tested |
