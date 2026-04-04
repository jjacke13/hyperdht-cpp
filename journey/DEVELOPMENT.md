# Development Journey — hyperdht-cpp

The story of building the first wire-compatible non-JS HyperDHT implementation, from zero to 10,800 lines of working C++ in 5 days.

## Why

[nospoon](https://github.com/jjacke13/nospoon) is a P2P VPN built on HyperDHT. It works, but it requires Node.js — a 50MB runtime dependency. The goal: eliminate that dependency entirely by reimplementing HyperDHT in C++. This also enables:

- Single static binary for the VPN (no runtime)
- ESP32 firmware (mimiclaw) joining the DHT natively
- Language bindings for Python, Go, Rust, Swift, Kotlin via C API
- Mobile apps without BareKit/JS worklets

## The Challenge

No HyperDHT protocol specification exists. The "spec" is the JavaScript source code across 15+ npm packages. Previous attempts to port HyperDHT (Go in 2021, Rust in 2024) all failed — none achieved wire compatibility with the JS network.

We reverse-engineered the protocol from the JS source and documented it in [PROTOCOL.md](../docs/PROTOCOL.md) — now the most comprehensive HyperDHT protocol document in existence.

## Timeline

### Day 1 (2026-03-30): Foundation

**Phases 0-1**: Project scaffold + compact encoding.

Set up CMake, libudx as a git submodule, GoogleTest, Nix devShell. Implemented the compact encoding library — HyperDHT's wire format (varint, buffer, IPv4 arrays). 43 tests including 7 cross-verified against JS output.

**Key discovery**: The protocol docs we'd written had two bugs — varint example was wrong, and IPv4 port encoding was LE not BE. Found by cross-testing against JS.

### Day 2 (2026-03-31): The Stack

**Phases 2-5**: UDX transport, DHT RPC, Noise IK handshake, SecretStream. Plus the first half of Phase 3 (messages, routing table, tokens).

The biggest surprise: HyperDHT uses Ed25519 for Noise IK, not X25519. The DH operation uses `crypto_scalarmult_ed25519_noclamp` with SHA-512 scalar extraction. The existing `noise-c` library can't do this — we had to implement the Noise IK state machine ourselves (~300 lines).

**Cross-test milestone**: C++ Noise handshake byte-for-byte matches JS output. The real HyperDHT prologue (`hypercore-crypto.namespace`) computed correctly.

### Day 3 (2026-04-01): Connection Pipeline

**Phase 3 completion + Phase 6 + Phase 7 Steps 1-8**: All DHT RPC sub-components, Protomux, and the full connect/server pipeline.

**THE MOMENT**: C++ client connects to a live JS HyperDHT server over the public internet. Full pipeline: findPeer → PEER_HANDSHAKE (Noise IK) → PEER_HOLEPUNCH (NAT traversal) → UDX stream → SecretStream header exchange → encrypted channel. ~4 seconds total.

But the reverse direction (JS client → C++ server) didn't work. The handshake completed on our side, but the reply never reached the JS client. Three bugs fixed, still broken.

### Day 4 (2026-04-03): The Relay Bug

The most satisfying debugging session.

**Root cause**: When our server received a relayed PEER_HANDSHAKE, it sent a RESPONSE (type byte `0x13`) back to the relay. But dht-rpc's relay mechanism uses `req.relay()`, which sends a REQUEST (type byte `0x03`). The relay node expected to receive a REQUEST, process it in its `onpeerhandshake` handler (non-server path, `FROM_SERVER` mode), and convert it to a RESPONSE for the client. Our RESPONSE was silently dropped because the relay had no matching TID in its pending requests.

**One byte difference**: `0x03` vs `0x13`. Four days of debugging.

After the fix: JS client → C++ server: **CONNECTED**.

Also on Day 4: All 10 HyperDHT commands implemented (client + server). Ed25519 signature verification on ANNOUNCE/UNANNOUNCE. Mutable/immutable storage (both directions cross-tested with JS). Hardening — ASan/UBSan clean, 5 fuzz targets (36M runs), crypto review.

### Day 5 (2026-04-04): Production Readiness

C API (`hyperdht.h`) for FFI consumers. Python ctypes test proving it works. CMake install rules + pkg-config. Nix package (static + shared). Three production bugs fixed (LRU cache for storage, timer UAF, socket lifetime). Documentation.

## Protocol Gotchas

Non-obvious details that caused surprises:

1. **Noise curve is Ed25519, not X25519** — `crypto_scalarmult_ed25519_noclamp` with SHA-512 scalar extraction. `noise-c` can't do this.

2. **BLAKE2b is 512-bit (64 bytes)** for the Noise hash, not 256-bit.

3. **HKDF uses HMAC-BLAKE2b** with 128-byte block length, not 64.

4. **dht-rpc relay sends REQUEST, not RESPONSE** — TID preserved through `req.relay()` → `_encodeRequest()` → `this.tid`. The relay chain is: CLIENT→REQUEST→RELAY→REQUEST→SERVER→REQUEST→RELAY→RESPONSE→CLIENT.

5. **Mode constants**: `FROM_CLIENT=0, FROM_SERVER=1, FROM_RELAY=2, FROM_SECOND_RELAY=3, REPLY=4`. We initially had `FROM_RELAY=1, FROM_SERVER=5` — silent wire incompatibility.

6. **Holepunch payload encryption**: XSalsa20-Poly1305 (`crypto_secretbox`), key = `BLAKE2b(NS_PEER_HOLEPUNCH, noise_handshake_hash)`.

7. **SecretStream first message**: `uint24_le(56) + 32-byte stream_id + 24-byte header`. Without this exact framing, decryption fails silently.

8. **Namespace hashes**: `BLAKE2b-256(BLAKE2b-256("hyperswarm/dht") || cmd_byte)`. Matches `hypercore-crypto.namespace()`. Verified by live Noise handshake with JS.

9. **has_bytes() integer overflow**: `s.start + n` wraps around on `size_t` when `n` is near `UINT64_MAX`, bypassing the bounds check. Found by fuzzing. Fixed with subtraction: `n <= s.end - s.start`.

10. **Announcer must re-announce after relay discovery**: First announce cycle has no relay addresses (they come from ANNOUNCE responses). Must re-announce with updated PeerRecord.

## Bug Archaeology

72 bugs found across 7 code review rounds + ASan + fuzzing:
- 63 fixed
- 9 deferred (structural, non-blocking)

Categories:
- Memory safety (UAF, leaks, overflow): 12
- Protocol correctness (wrong constants, missing fields): 8
- Crypto (nonce handling, state machine): 5
- Test bugs (libuv lifecycle): 6
- Logic errors (inverted checks, missing guards): 15
- API/design (callback asymmetry, raw pointers): 9

The most impactful single bug: `has_bytes()` integer overflow — a security vulnerability found by fuzzing that could cause OOM via crafted varint input. One-line fix.

## What Made It Work

1. **JS source as the spec**: Every line of C++ was written by reading the JS implementation. No guessing.

2. **Cross-testing at every phase**: C++ encode → JS decode (and reverse) for every data type. Live tests against the public HyperDHT network.

3. **Incremental verification**: Each phase was tested in isolation before building on top. Phase 1 (compact encoding) was byte-for-byte verified before Phase 2 (UDX) started.

4. **Sanitizers + fuzzing early**: ASan found 6 bugs in test code. Fuzzing found 1 security bug in library code. Both were run before adding more features.

5. **Code reviews on every step**: cpp-reviewer agent caught 72 bugs across 7 rounds. Most were caught before they reached live testing.

## Previous Attempts (all failed)

| Project | Language | Year | What Went Wrong |
|---------|----------|------|-----------------|
| tigerbot/hyperdht | Go | 2021 | Targets old v4 protocol, uses protobuf (wrong wire format) |
| datrs/hyperswarm-rs | Rust | 2024 | Partial implementation, doesn't interop with JS nodes |
| fsteff/libudx-rs | Rust | 2022 | FFI bindings only, no HyperDHT protocol |

## The Result

5 days ago, HyperDHT was JavaScript-only. If you wanted P2P encrypted connections, you needed Node.js.

Now:

```python
# Python — 4 lines to accept encrypted P2P connections
from hyperdht import HyperDHT, KeyPair
dht = HyperDHT()
server = dht.create_server()
server.listen(KeyPair.generate(), lambda c: print(f"Peer: {c.remote_key.hex()[:16]}..."))
```

And this Python server can talk to any JS HyperDHT client on the public network. And vice versa. Full Noise IK encryption, NAT holepunching, DHT routing — all happening underneath those 4 lines.

The same library can power a Go service, a Rust daemon, a Swift iOS app, an ESP32 sensor. All talking to each other and to existing JS nodes. One network.

## Stats

| Metric | Value |
|--------|-------|
| Calendar days | 5 |
| Source files | 25 `.cpp` + 27 headers |
| Lines of C++ | ~10,800 |
| Tests | 330 offline + 332 ASan |
| Fuzz iterations | 36M+ |
| JS packages reverse-engineered | 15 |
| Commits | 35 |
| Live cross-tests | 7 (connect, storage, FFI) |
