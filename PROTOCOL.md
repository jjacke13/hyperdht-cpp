# HyperDHT Protocol Specification

Reverse-engineered from the JavaScript/C reference implementations.
No formal spec exists — this document IS the spec.

## Overview

HyperDHT is a peer-to-peer networking stack that provides NAT-traversing encrypted connections over a Kademlia-like DHT. The stack has 6 layers:

```
+-------------------------------------------+
|  HyperDHT API                             |  connect(), createServer(), keyPair()
+-------------------------------------------+
|  Protomux                                 |  Stream multiplexing (channels)
+-------------------------------------------+
|  SecretStream (@hyperswarm/secret-stream)  |  Noise IK → libsodium secretstream
+-------------------------------------------+
|  DHT RPC (dht-rpc)                         |  Kademlia routing, request/response
+-------------------------------------------+
|  UDX (libudx)                              |  Reliable UDP transport (BBR)
+-------------------------------------------+
|  UDP                                       |  Raw datagrams
+-------------------------------------------+
```

---

## Layer 1: UDX Transport

**Source**: `libudx` (C library), `udx-native` (Node.js bindings)
**Wireshark dissector**: `libudx/docs/wireshark/udx.lua`

Reliable, ordered, congestion-controlled UDP transport. Similar to QUIC but simpler.

### Packet Header (20 bytes)

```
Offset  Size  Field        Notes
──────  ────  ─────        ─────
0       1     Magic        Always 0xFF
1       1     Version      Currently 1
2       1     Type flags   Bitmask (see below)
3       1     Data offset  Offset from byte 20 to payload start
4       4     Stream ID    LE uint32
8       4     Window       LE uint32 (receive window)
12      4     Seq          LE uint32 (sequence number)
16      4     Ack          LE uint32 (acknowledgement number)
```

### Type Flags (byte 2)

```
Bit  Value  Name
───  ─────  ────
0    0x01   DATA
1    0x02   END
2    0x04   SACK
3    0x08   MESSAGE
4    0x10   DESTROY
5    0x20   HEARTBEAT
```

### SACK Ranges

If SACK flag is set, SACK entries follow the header as pairs of LE uint32 `(from, to)`. Number of pairs = `data_offset / 8`. Payload starts at offset `20 + data_offset`.

### Constants

- MTU base: 1200 bytes
- MTU max: 1500 bytes
- Congestion control: BBR

---

## Layer 2: DHT RPC

**Source**: `dht-rpc/lib/io.js`

Request/response RPC over raw UDP datagrams. NOT over UDX — these are plain UDP packets for DHT queries.

### Message Format

First byte encodes type + version:
- `0x03` = Request (type=0, version=3)
- `0x13` = Response (type=1, version=3)

### Flags Byte (byte 1)

**Request flags:**
```
Bit  Value  Field
───  ─────  ─────
0    0x01   id (routing ID present)
1    0x02   token (roundtrip token present)
2    0x04   internal (DHT-internal command)
3    0x08   target (32-byte target key present)
4    0x10   value (payload buffer present)
```

**Response flags:**
```
Bit  Value  Field
───  ─────  ─────
0    0x01   id
1    0x02   token
2    0x04   closerNodes (array of peers)
3    0x08   error (error code present)
4    0x10   value (payload buffer present)
```

### Request Fields (compact-encoded, in order)

1. `tid` — uint16 (transaction ID)
2. `to` — 6 bytes (4 IP + 2 port, compact-encoded IPv4)
3. `id` — fixed 32 bytes (if flag set). Routing ID = `blake2b(publicIP + publicPort)`
4. `token` — fixed 32 bytes (if flag set). Anti-spoofing roundtrip token
5. `command` — varint (command number, see below)
6. `target` — fixed 32 bytes (if flag set). DHT key being queried
7. `value` — length-prefixed buffer (if flag set). Command-specific payload

### Response Fields (compact-encoded, in order)

1. `tid` — uint16
2. `to` — 6 bytes
3. `id` — fixed 32 bytes (if flag set)
4. `token` — fixed 32 bytes (if flag set)
5. `closerNodes` — array of 6-byte IPv4 entries (if flag set)
6. `error` — varint (if flag set)
7. `value` — length-prefixed buffer (if flag set)

### Internal Commands (dht-rpc layer)

```
0 = PING
1 = PING_NAT
2 = FIND_NODE
3 = DOWN_HINT
4 = DELAYED_PING
```

### Routing ID

Each node's routing ID is `blake2b(publicIP_bytes + publicPort_LE16)`, 32 bytes.

### Routing Table

Standard Kademlia k-bucket routing table. Bucket size k=20. XOR distance metric on 32-byte routing IDs.

---

## Layer 3: HyperDHT Commands

**Source**: `hyperdht/lib/constants.js`, `hyperdht/lib/messages.js`

Built on top of dht-rpc. These commands use the `command` field in DHT RPC messages.

### Command Numbers

```
0 = PEER_HANDSHAKE
1 = PEER_HOLEPUNCH
2 = FIND_PEER
3 = LOOKUP
4 = ANNOUNCE
5 = UNANNOUNCE
6 = MUTABLE_PUT
7 = MUTABLE_GET
8 = IMMUTABLE_PUT
9 = IMMUTABLE_GET
```

### Key Message Schemas (compact-encoded)

**Handshake** (`PEER_HANDSHAKE` value):
```
flags:         varint
mode:          varint
noise:         length-prefixed buffer (Noise IK handshake bytes)
peerAddress:   6 bytes (if flag 0x01 set)
relayAddress:  6 bytes (if flag 0x02 set)
```

**Holepunch** (`PEER_HOLEPUNCH` value):
```
flags:         varint
mode:          varint
id:            fixed 32 bytes
payload:       length-prefixed buffer (encrypted holepunch payload)
peerAddress:   6 bytes (if flag 0x01 set)
```

**Noise Payload** (encrypted inside Noise handshake):
```
version:        varint
flags:          varint
error:          varint
firewall:       varint
holepunch:      { id(fixed32), payload(buffer) }  (if flag set)
addresses4:     array of 6-byte IPv4                (if flag set)
addresses6:     array of 18-byte IPv6               (if flag set)
udx:            { id(uint32), seq(uint32) }         (if flag set)
secretStream:   length-prefixed buffer               (if flag set)
relayThrough:   6 bytes                              (if flag set)
relayAddresses: array of 6-byte IPv4                 (if flag set)
```

**Holepunch Payload** (encrypted):
```
flags:          varint
error:          varint
firewall:       varint
round:          varint
connected:      bool (varint)
punching:       bool (varint)
addresses:      array of 6-byte IPv4  (if flag set)
remoteAddress:  6 bytes               (if flag set)
token:          fixed 32 bytes        (if flag set)
remoteToken:    fixed 32 bytes        (if flag set)
```

**Peer** (used in ANNOUNCE, FIND_PEER):
```
publicKey:      fixed 32 bytes
relayAddresses: array of 6-byte IPv4
```

**Announce** (`ANNOUNCE` value):
```
flags:     varint
peer:      Peer struct     (if flag 0x01 set)
refresh:   length-prefixed (if flag 0x02 set)
signature: fixed 64 bytes  (if flag 0x04 set)
bump:      length-prefixed (if flag 0x08 set)
```

---

## Layer 4: Noise Handshake

**Source**: `noise-handshake`, `noise-curve-ed`, `hyperdht/lib/noise-wrap.js`

### Pattern: Noise IK

The IK pattern means the initiator knows the responder's static public key beforehand.

```
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

### Curve: Ed25519

Using `noise-curve-ed` which converts Ed25519 keys to X25519 for Diffie-Hellman, using `sodium.crypto_sign_ed25519_pk_to_curve25519`.

### Prologue

```javascript
crypto.namespace('hyperswarm/dht', [COMMANDS.PEER_HANDSHAKE])
```

This produces a 32-byte prologue via BLAKE2b that binds the Noise handshake to the HyperDHT context.

### Handshake Flow

1. Initiator sends `-> e, es, s, ss` (64-byte ephemeral key + encrypted static key + payload)
2. Responder sends `<- e, ee, se` (encrypted response with payload)
3. Both derive transport keys from the handshake

After handshake, the session transitions to libsodium secretstream for ongoing encryption.

---

## Layer 5: SecretStream

**Source**: `@hyperswarm/secret-stream`, `sodium-secretstream`

After the Noise IK handshake produces shared secrets, data is encrypted using **libsodium's secretstream** (`crypto_secretstream_xchacha20poly1305`).

This provides:
- AEAD encryption (XChaCha20-Poly1305)
- Message ordering (internal counter)
- 17-byte overhead per message (1 tag + 16 MAC)

The SecretStream runs over a UDX stream (reliable, ordered).

---

## Layer 6: Protomux

**Source**: `protomux`

Stream multiplexer that runs on top of SecretStream. Allows multiple "protocols" (channels) over a single encrypted connection.

### Framing

Each protomux message has:
- Channel ID (varint)
- Message type (varint)
- Payload (length-prefixed)

Channels are opened by protocol name + ID. Both sides must agree on the protocol name for a channel to be established.

---

## Compact Encoding Reference

**Source**: `compact-encoding` README

### Varint (ULEB128)

```
Value          Encoding
─────          ────────
0-252          1 byte (value as-is)
253-0xFFFF     3 bytes: 0xFD + LE uint16
0x10000-MAX    5 bytes: 0xFE + LE uint32
```

### Common Types

```
uint         varint (ULEB128)
int          ZigZag encoded, then varint
fixed32      raw 32 bytes
fixed64      raw 64 bytes
buffer       varint(length) + raw bytes
string       varint(length) + UTF-8 bytes
array(type)  varint(count) + count * type
bool         varint (0 or 1)
ipv4addr     4 bytes IP + 2 bytes port (LE) = 6 bytes
```

---

## Connection Establishment Flow

**Source**: `hyperdht/docs/handshake.md`, `hyperdht/docs/holepunch.md`

### Phase 1: Find Peer (DHT lookup)

```
Client → DHT → FIND_PEER(serverPublicKey) → closest nodes
Closest node that knows the server → returns relay info
```

### Phase 2: Relay Handshake

```
Client → clientRelay → PEER_HANDSHAKE(noise1) → serverRelay → Server
Server → serverRelay → PEER_HANDSHAKE(noise2) → clientRelay → Client
```

The Noise IK payloads contain endpoint addresses for direct connection.

### Phase 3: Holepunch

```
Client → clientRelay → PEER_HOLEPUNCH(round1) → serverRelay → Server
Server → serverRelay → PEER_HOLEPUNCH(round2) → clientRelay → Client
Both: Send UDP probes to each other's addresses
```

### Phase 4: Direct Connection

```
Client ←→ Server (UDX stream over UDP, encrypted with SecretStream)
```

If holepunching fails, traffic relays through `blind-relay` nodes.

---

## Existing Non-JS Implementations (all incomplete)

| Project | Language | Status | Compatible? |
|---------|----------|--------|-------------|
| tigerbot/hyperdht | Go | Stale (2021) | No (targets old v4, uses protobuf) |
| datrs/hyperswarm-rs | Rust | Stale (2024) | No (doesn't interop with JS nodes) |
| fsteff/libudx-rs | Rust | Stale (2022) | FFI bindings only (not reimplementation) |

**No complete wire-compatible non-JS implementation exists.**

---

## What Already Exists in C (reuse, don't reimplement)

Several critical components of the HyperDHT stack are already implemented in C. These can be linked directly from C++ with zero overhead — no porting needed.

### Direct reuse (link the C library)

| Component | C Library | What it provides | Effort |
|-----------|-----------|-----------------|--------|
| **libsodium** | `libsodium` | ALL crypto: Ed25519, X25519, BLAKE2b, XChaCha20-Poly1305, secretstream, key exchange, random | **Zero** — just `#include <sodium.h>` |
| **UDX transport** | `libudx` | Reliable UDP, congestion control (BBR), SACK, stream abstraction, holepunching | **Zero** — C library with clean API, already used by `udx-native` via N-API bindings |
| **Noise protocol** | `noise-c` | Full Noise framework: IK pattern, key DH, symmetric crypto, handshake state machine | **Zero** — mature C library |

### What this means for the implementation plan

```
Layer              JS Package              C Library         Need to write?
─────              ──────────              ─────────         ──────────────
UDP transport      udx-native (bindings)   libudx            NO — use libudx directly
Crypto             sodium-native           libsodium         NO — use libsodium directly
Noise handshake    noise-handshake         noise-c           MINIMAL — glue code only
SecretStream       sodium-secretstream     libsodium         MINIMAL — thin wrapper around crypto_secretstream_*
Compact encoding   compact-encoding        (none)            YES — ~200 lines C++
DHT RPC            dht-rpc                 (none)            YES — message parsing, routing table
Protomux           protomux                (none)            YES — channel multiplexing
HyperDHT logic     hyperdht                (none)            YES — handshake flow, commands, holepunch orchestration
```

### Key insight

The **hard systems-level stuff** (reliable UDP, congestion control, crypto, Noise state machine) is already in C. What we need to write in C++ is the **protocol logic** (message encoding, DHT routing, connection orchestration) — which is the easier part.

### libudx API surface (what we get for free)

```c
// Create and bind
udx_t *udx = udx_init(loop);
udx_socket_t *sock = udx_socket_init(udx, loop);
udx_socket_bind(sock, &addr, 0);

// Streams (reliable ordered data)
udx_stream_t *stream = udx_stream_init(udx, loop);
udx_stream_connect(stream, sock, remote_id, remote_port, &remote_addr);
udx_stream_write(stream, buf, len, cb);
udx_stream_read_start(stream, alloc_cb, read_cb);

// Messages (unreliable datagrams — used for DHT RPC)
udx_socket_send(sock, buf, len, &dest_addr, cb);
udx_socket_recv_start(sock, alloc_cb, recv_cb);
```

This gives us Phase 2 (UDX transport) essentially for free.

### libsodium API surface (what we get for free)

```c
// Key generation (Ed25519)
crypto_sign_keypair(pk, sk);
crypto_sign_seed_keypair(pk, sk, seed);

// Ed25519 → X25519 conversion (for Noise DH)
crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk);
crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_sk);

// BLAKE2b hashing (routing IDs, discovery keys)
crypto_generichash(out, outlen, in, inlen, key, keylen);

// SecretStream (post-handshake encryption)
crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
crypto_secretstream_xchacha20poly1305_push(&state, c, &clen, m, mlen, NULL, 0, tag);
crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key);
crypto_secretstream_xchacha20poly1305_pull(&state, m, &mlen, &tag, c, clen, NULL, 0);
```

This gives us Phase 4 (Noise) and Phase 5 (SecretStream) with minimal glue code.

---

## Implementation Plan

### Phase 0: Protocol Analysis
Deep-read JS/C source for each layer. Document exact byte layouts, edge cases, error handling. Produce test vectors by capturing real traffic between JS nodes.
**Effort**: Research only, no code.

### Phase 1: Compact Encoding
Implement the serialization library. Foundation for everything above.
**Effort**: ~200-300 lines C++. Must write from scratch (no C lib exists).
**Test**: encode/decode round-trip against JS `compact-encoding`.

### Phase 2: UDX Transport
Link `libudx` C library. Write thin C++ wrapper class.
**Effort**: MINIMAL — libudx does the heavy lifting. ~100 lines of C++ wrapper.
**Test**: UDX stream between C++ and JS `udx-native`.

### Phase 3: DHT RPC
Implement request/response message encoding over raw UDP, Kademlia routing table, node discovery.
**Effort**: SIGNIFICANT — core protocol logic, ~1000-1500 lines C++. No C lib exists.
**Test**: C++ node responds to PING from JS `dht-rpc`. C++ node joins the DHT and discovers peers.

### Phase 4: Noise Handshake
Use `noise-c` library for Noise IK state machine + `libsodium` for Ed25519→X25519. Write glue code for HyperDHT-specific prologue and payload encoding.
**Effort**: MINIMAL — libraries handle crypto. ~200 lines of glue code.
**Test**: C++ initiator connects to JS HyperDHT server (handshake completes).

### Phase 5: SecretStream
Thin wrapper around `libsodium` `crypto_secretstream_xchacha20poly1305_*` over UDX stream.
**Effort**: MINIMAL — ~100-150 lines C++.
**Test**: Encrypted data exchange between C++ and JS peers.

### Phase 6: Protomux
Implement channel multiplexing (varint-framed messages with channel IDs).
**Effort**: MODERATE — ~400-600 lines C++. No C lib exists.
**Test**: Open a protocol channel between C++ and JS peers.

### Phase 7: Full HyperDHT API
`connect()`, `createServer()`, `keyPair()`, `lookup()`, `announce()`. Orchestrate handshake → holepunch → direct connection flow.
**Effort**: SIGNIFICANT — ~1000-2000 lines C++. The integration layer.
**Test**: C++ nospoon client connects to JS nospoon server. Full tunnel works.

### Effort Summary

```
Phase  Layer              Effort       Lines (est.)  Why
─────  ─────              ──────       ────────────  ───
  0    Protocol analysis  Research     0             Reading JS/C source
  1    Compact encoding   Write        200-300       No C lib exists
  2    UDX transport      Wrap libudx  100           C lib does the work
  3    DHT RPC            Write        1000-1500     Core protocol logic
  4    Noise handshake    Glue code    200           noise-c + libsodium
  5    SecretStream       Wrap libsodium  100-150    C lib does the work
  6    Protomux           Write        400-600       Protocol logic
  7    HyperDHT API       Write        1000-2000     Integration + orchestration
                                       ───────────
                          TOTAL        ~3000-4850 lines C++
```

Roughly half the stack is free (libudx, libsodium, noise-c). The other half is protocol logic that must be written.

---

## C++ vs JS: Where the Pain Is

Things that are trivial in JS but require careful attention in C++.

### 1. Async concurrency model (HIGH effort)

JS has a single-threaded event loop with `async/await`. The entire HyperDHT codebase assumes this — no locks, no races, no thread safety concerns. Callbacks and promises just work.

In C++ you must choose and manage your own concurrency:
- **libuv** (what libudx already uses internally) — callback-based, single-threaded event loop, closest to JS model
- **asio** — more C++ idiomatic, supports coroutines (C++20)
- **std::thread** + mutexes — most error-prone

**Recommendation**: Use libuv since libudx already depends on it. Keeps everything single-threaded like JS. But every "await" in the JS source becomes a callback chain or coroutine in C++.

**Watch out for**: The JS code freely creates `Promise` chains, uses `async for` loops, and relies on microtask ordering. Translating this to callbacks without introducing subtle ordering bugs is the #1 source of pain.

### 2. Memory management (MEDIUM effort)

JS has garbage collection. The HyperDHT code freely creates objects, closures, Buffers, and lets the GC clean up. In C++:

- **Buffers**: JS `Buffer` is reference-counted and resizable. In C++ you need `std::vector<uint8_t>` or `std::shared_ptr<uint8_t[]>`, and must think about ownership at every handoff (who frees this buffer? when?).
- **Closures/callbacks**: JS closures capture variables by reference and the GC keeps them alive. In C++ lambdas, captured references can dangle if the original object is destroyed. Use `std::shared_ptr` or ensure lifetime correctness.
- **Connection objects**: JS HyperDHT creates connection/stream objects and lets them float around with event listeners. In C++ you need clear ownership: who owns the connection? When is it destroyed? What happens to pending callbacks?

**Recommendation**: Use RAII and `std::unique_ptr`/`std::shared_ptr` consistently. Define ownership rules early and stick to them.

### 3. Streams and backpressure (MEDIUM effort)

JS `streamx` handles backpressure automatically — if a consumer is slow, the producer pauses. The HyperDHT code relies on this implicitly everywhere (piping TUN data through framing through encryption through UDX).

In C++ with libudx:
- libudx has its own flow control (congestion window), but the layers above it need manual backpressure
- If TUN produces data faster than UDX can send, you need to buffer or pause the TUN read
- If UDX receives data faster than the TUN can write, same problem

**Watch out for**: Unbounded buffer growth if backpressure is not implemented. JS streams handle this transparently; C++ does not.

### 4. Error propagation (MEDIUM effort)

JS uses `try/catch` with async functions, and errors bubble up through promise chains. HyperDHT code `throw`s errors that propagate to the caller automatically.

In C++ you must choose:
- Exceptions (similar to JS `throw`, but expensive and not always available on embedded)
- Error codes / `std::expected` (C++23) (explicit, verbose, but no overhead)
- Callbacks with error parameter (Node.js style — `cb(err, result)`)

**Recommendation**: Since libudx uses C-style error codes, and this targets embedded too, avoid exceptions. Use error codes consistently.

### 5. Timer and timeout management (LOW-MEDIUM effort)

JS HyperDHT uses `setTimeout`, `setInterval`, and `clearTimeout` freely — for DHT refresh, keepalives, NAT sampling, connection timeouts, adaptive timeouts, etc. There are dozens of timers active simultaneously.

In C++ with libuv: `uv_timer_t` works similarly, but each timer is a heap-allocated handle that must be explicitly stopped and closed. Forgetting to stop a timer → use-after-free. Forgetting to close a handle → memory leak.

**Watch out for**: Timer cleanup on connection teardown. The JS code just lets timers get GC'd when the connection object is gone. In C++ you must explicitly cancel every timer when cleaning up.

### 6. Dynamic typing → static typing (LOW-MEDIUM effort)

JS HyperDHT passes around plain objects (`{ id, token, target, value, ... }`) and checks for field existence with `if (msg.token)`. The compact-encoding schemas use flag bits to indicate which fields are present.

In C++ you need explicit structs with `std::optional<>` fields:
```cpp
struct DhtRequest {
    uint16_t tid;
    std::array<uint8_t, 6> to;
    std::optional<std::array<uint8_t, 32>> id;
    std::optional<std::array<uint8_t, 32>> token;
    uint32_t command;
    std::optional<std::array<uint8_t, 32>> target;
    std::optional<std::vector<uint8_t>> value;
};
```

This is actually cleaner than JS — the type system enforces correctness. But it's more verbose and you must define every struct upfront rather than ad-hoc.

### 7. EventEmitter pattern (LOW effort)

Nearly every JS HyperDHT object is an EventEmitter: `dht.on('connection', ...)`, `stream.on('data', ...)`, `stream.on('close', ...)`.

In C++ this maps to either:
- Callback function pointers / `std::function`
- A simple observer pattern class (~50 lines)
- libuv handles (already event-based)

Not hard, just needs a consistent pattern decided early.

### 8. The holepunch state machine (HIGH effort, regardless of language)

The NAT traversal / holepunching logic in `hyperdht/lib/connect.js` is the most complex part of the entire stack. It's complex in JS too — multi-round relay-mediated address exchange with timeouts, retries, fallback to blind relay, and multiple concurrent probe strategies.

This is equally hard in any language. The challenge is correctness of the state machine, not the language.

### Summary: Where to spend extra time

```
Area                    Extra C++ effort vs JS    Why
────                    ──────────────────────    ───
Async/callback model    HIGH                      No await, manual callback chains
Memory/lifetime mgmt    MEDIUM                    No GC, must track ownership
Stream backpressure     MEDIUM                    Not automatic like JS streamx
Error handling          MEDIUM                    Must choose and be consistent
Timers/cleanup          LOW-MEDIUM                Must manually cancel all timers
Type definitions        LOW-MEDIUM                More verbose but actually safer
Events/listeners        LOW                       Simple pattern, decide once
Holepunch state machine HIGH (but same in JS)     Inherently complex logic
```

---

## Bootstrap Nodes

Hardcoded in `hyperdht/lib/constants.js`. These are the entry points to the public HyperDHT network:

```
88.99.3.86@node1.hyperdht.org:49737
142.93.90.113@node2.hyperdht.org:49737
138.68.147.8@node3.hyperdht.org:49737
```

Format: `IP@hostname:port`. The hostname is for human reference; the IP is what's used for the initial UDP packet.

A new node joins by sending a `FIND_NODE` request (dht-rpc internal command 2) to one or more bootstrap nodes, which respond with closer nodes. The node then populates its routing table by iteratively querying closer and closer nodes.

### Other Constants

```
Firewall types: UNKNOWN=0, OPEN=1, CONSISTENT=2, RANDOM=3
Error codes:    NONE=0, ABORTED=1, VERSION_MISMATCH=2, TRY_LATER=3,
                SEQ_REUSED=16, SEQ_TOO_LOW=17
```

### Namespace Derivation

HyperDHT derives per-command Noise prologues via:
```javascript
crypto.namespace('hyperswarm/dht', [ANNOUNCE, UNANNOUNCE, MUTABLE_PUT, PEER_HANDSHAKE, PEER_HOLEPUNCH])
```
This produces 5 x 32-byte keys via BLAKE2b, used as Noise prologues to bind each handshake to its specific command context.

---

## Testing Strategy

### Principle: Test against JS at every phase

Do NOT rely only on unit tests. After each phase, verify wire compatibility by talking to a real JS HyperDHT node.

### Test Harness Setup

```
┌──────────────┐     UDP      ┌──────────────┐
│  C++ node    │ ◄──────────► │  JS node     │
│  (under test)│              │  (reference)  │
└──────────────┘              └──────────────┘
```

Run a JS HyperDHT node (or testnet) as the reference implementation. The C++ test sends messages and verifies the JS node responds correctly, and vice versa.

### Per-Phase Tests

| Phase | Test |
|-------|------|
| 1. Compact encoding | Encode in C++, decode in JS (and reverse). Compare byte-for-byte output. Use a small JS script that reads stdin, decodes, re-encodes, writes stdout. |
| 2. UDX | Open UDX stream from C++ to JS `udx-native`. Send data back and forth. Verify ordering and reliability. |
| 3. DHT RPC | C++ node sends PING to JS `dht-rpc` node. C++ node sends FIND_NODE to bootstrap. Verify response parsing. |
| 4. Noise | C++ initiator performs Noise IK handshake with JS HyperDHT server. Verify handshake completes and both sides derive the same session keys. |
| 5. SecretStream | After Noise handshake, send encrypted data from C++ to JS and back. Verify decryption works on both sides. |
| 6. Protomux | Open a named protocol channel between C++ and JS. Send messages on the channel. |
| 7. Full API | C++ `connect()` to JS `createServer()`. Verify the full flow: DHT lookup → relay handshake → holepunch → encrypted stream. |

### Packet Capture

Use the UDX Wireshark dissector (`libudx/docs/wireshark/udx.lua`) to capture traffic between two JS nodes. Save as `.pcap` files for reference when debugging C++ implementation.

For DHT RPC messages (plain UDP, not UDX), capture with Wireshark and write a small JS script to decode the compact-encoded payload for inspection.

### Testnet

HyperDHT provides `testnet.js` — creates isolated DHT networks with their own bootstrap nodes. Use this for testing so we don't pollute the public DHT:

```javascript
const testnet = require('hyperdht/testnet')
const { bootstrap } = await testnet.createTestnet(3)
// bootstrap = [{ host: '127.0.0.1', port: ... }, ...]
```

Point the C++ node at these local bootstrap nodes during development.

---

## Project Structure

```
hyperdht-cpp/
├── PROTOCOL.md              ← this file
├── CMakeLists.txt           ← top-level build
├── include/
│   └── hyperdht/
│       ├── hyperdht.h       ← public C API (extern "C")
│       ├── dht.hpp          ← C++ API
│       ├── compact.hpp      ← compact encoding
│       ├── rpc.hpp          ← DHT RPC
│       ├── noise_wrap.hpp   ← Noise IK glue
│       ├── secret_stream.hpp
│       └── protomux.hpp
├── src/
│   ├── compact.cpp
│   ├── rpc.cpp
│   ├── routing_table.cpp
│   ├── noise_wrap.cpp
│   ├── secret_stream.cpp
│   ├── protomux.cpp
│   ├── dht.cpp              ← main HyperDHT logic
│   └── hyperdht_c.cpp       ← C API wrapper
├── deps/
│   ├── libudx/              ← git submodule
│   ├── libsodium/           ← git submodule or system lib
│   └── noise-c/             ← git submodule
├── test/
│   ├── test_compact.cpp
│   ├── test_rpc.cpp
│   ├── test_noise.cpp
│   ├── test_stream.cpp
│   ├── test_protomux.cpp
│   ├── test_integration.cpp ← full connect/server test against JS
│   └── js/                  ← JS reference scripts for cross-testing
│       ├── testnet.js
│       ├── echo_server.js
│       └── compact_check.js
└── examples/
    ├── ping.cpp             ← minimal DHT ping example
    └── connect.cpp          ← connect to a JS HyperDHT server
```

### Build Dependencies

```cmake
# CMakeLists.txt sketch
cmake_minimum_required(VERSION 3.20)
project(hyperdht-cpp LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)

# libuv (required by libudx)
find_package(libuv REQUIRED)

# libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# libudx (git submodule)
add_subdirectory(deps/libudx)

# noise-c (git submodule)
add_subdirectory(deps/noise-c)

# Our library
add_library(hyperdht
    src/compact.cpp
    src/rpc.cpp
    src/routing_table.cpp
    src/noise_wrap.cpp
    src/secret_stream.cpp
    src/protomux.cpp
    src/dht.cpp
    src/hyperdht_c.cpp
)
target_link_libraries(hyperdht PUBLIC udx sodium noise-protocol noise-handshakestate uv)
target_include_directories(hyperdht PUBLIC include/)
```

---

## Platform Priority

1. **Linux x86_64** — primary development target, easiest toolchain
2. **Linux aarch64** — RPi, NanoPi (nospoon's NixOS targets)
3. **macOS arm64** — development machines
4. **Windows x64** — nospoon already supports Windows
5. **ESP32** (ESP-IDF) — mimiclaw integration, the ultimate goal
6. **iOS/Android** — native library, replaces BareKit worklet

All C dependencies (libudx, libsodium, noise-c) already build on all these platforms.

---

## Public C API (extern "C")

For other languages to bind to. Keep it minimal and opaque-pointer based:

```c
/* hyperdht.h — public C API */

typedef struct hdht_t hdht_t;
typedef struct hdht_server_t hdht_server_t;
typedef struct hdht_stream_t hdht_stream_t;
typedef struct hdht_keypair_t hdht_keypair_t;

/* Lifecycle */
hdht_t *hdht_create(uv_loop_t *loop, const hdht_opts_t *opts);
void hdht_destroy(hdht_t *dht);

/* Key generation */
hdht_keypair_t *hdht_keypair_create(const uint8_t *seed /* 32 bytes, or NULL */);
void hdht_keypair_destroy(hdht_keypair_t *kp);
const uint8_t *hdht_keypair_public_key(const hdht_keypair_t *kp);  /* 32 bytes */

/* Server */
hdht_server_t *hdht_listen(hdht_t *dht, const hdht_keypair_t *kp);
void hdht_server_on_connection(hdht_server_t *srv, hdht_connection_cb cb, void *userdata);
void hdht_server_close(hdht_server_t *srv);

/* Client */
hdht_stream_t *hdht_connect(hdht_t *dht, const uint8_t *server_pk,
                             const hdht_keypair_t *kp /* optional */);
void hdht_stream_on_open(hdht_stream_t *s, hdht_open_cb cb, void *userdata);
void hdht_stream_on_data(hdht_stream_t *s, hdht_data_cb cb, void *userdata);
void hdht_stream_on_close(hdht_stream_t *s, hdht_close_cb cb, void *userdata);
int hdht_stream_write(hdht_stream_t *s, const uint8_t *buf, size_t len);
void hdht_stream_destroy(hdht_stream_t *s);

/* DHT operations */
void hdht_lookup(hdht_t *dht, const uint8_t *topic, hdht_lookup_cb cb, void *userdata);
void hdht_announce(hdht_t *dht, const uint8_t *topic, const hdht_keypair_t *kp);
void hdht_unannounce(hdht_t *dht, const uint8_t *topic, const hdht_keypair_t *kp);
```

This mirrors the JS HyperDHT API almost 1:1. Any language with C FFI (Python, Go, Rust, Swift, Kotlin) can call this.

---

## Licensing

All dependencies are permissive — no copyleft issues:

| Library | License | Obligations |
|---------|---------|-------------|
| libudx | Apache-2.0 | Include LICENSE, preserve NOTICE if present |
| libsodium | ISC | Include copyright notice |
| noise-c | MIT | Include copyright notice |
| libuv | MIT | Include copyright notice |

All compatible with releasing `hyperdht-cpp` under MIT or Apache-2.0.

**Recommendation**: Apache-2.0 (matches libudx, includes patent grant).

---

## C++ Dependencies

| Need | Library | License | Notes |
|------|---------|---------|-------|
| Reliable UDP | `libudx` | Apache-2.0 | C library, git submodule |
| Crypto | `libsodium` | ISC | System lib or submodule |
| Noise IK | `noise-c` | MIT | C library, git submodule |
| Event loop | `libuv` | MIT | Required by libudx, system lib |
| Build system | CMake 3.20+ | — | Standard |
| C++ standard | C++20 | — | For `std::optional`, coroutines (optional) |
| Testing | Catch2 or doctest | — | Header-only, lightweight |
