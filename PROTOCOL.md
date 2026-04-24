# HyperDHT Protocol Specification

Reverse-engineered from the JavaScript/C reference implementations.
No formal spec exists — this document IS the spec.

---

## Overview

HyperDHT is a peer-to-peer networking stack that provides NAT-traversing encrypted
connections over a Kademlia-like DHT. The stack has 6 layers:

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

**Key insight**: The bottom 3 layers (UDP, UDX, crypto primitives) already exist as C
libraries. What we write in C++ is the protocol logic on top.

---

## 1. Compact Encoding

**Source**: `compact-encoding/index.js`

Foundation for all wire formats. Little-endian byte order throughout.

### 1.1 State Object

```
{ start: number, end: number, buffer: Uint8Array }
```

- `start` — current read/write position (advances during encode/decode)
- `end` — end position / required size
- `buffer` — the byte array

Usage: preencode (calculate size) → allocate buffer → encode → send.

### 1.2 Varint (unsigned integer)

```
Value Range          Bytes  Format
──────────────       ─────  ──────
0 to 0xFC (252)      1     [value]
0xFD to 0xFFFF       3     [0xFD] [uint16 LE]
0x10000 to 0xFFFFFFFF  5   [0xFE] [uint32 LE]
> 0xFFFFFFFF         9     [0xFF] [uint64 LE]
```

Examples:
- 42 → `[0x2A]`
- 4200 → `[0xFD, 0x68, 0x10]`
- 300000 (0x493E0) → `[0xFE, 0xE0, 0x93, 0x04, 0x00]`

### 1.3 Signed Integer (Zig-Zag)

Signed ints use zig-zag encoding before varint:
```
 0 →  0       -1 →  1        1 →  2       -2 →  3
n >= 0: 2*n   n < 0: 2*(-n) - 1
```

Decode: `(n & 1) == 0 ? n/2 : -(n+1)/2`

### 1.4 Fixed-Size Types

```
Type       Size    Format
────       ────    ──────
uint8      1       raw byte
uint16     2       LE
uint24     3       LE
uint32     4       LE
uint64     8       two uint32 LE (low + high)
float32    4       IEEE 754 LE
float64    8       IEEE 754 LE
fixed32    32      raw 32 bytes (no length prefix)
fixed64    64      raw 64 bytes (no length prefix)
bool       1       0x00 or 0x01
```

### 1.5 Length-Prefixed Types

```
buffer     varint(length) + raw bytes.  NULL encoded as [0x00].
string     varint(byte_length) + UTF-8 bytes
raw        no prefix — consumes remaining bytes up to state.end
```

### 1.6 Combinators

**array(enc)**: `varint(count) + count * enc.encode(element)`
- Decode caps at 0x100000 (1M) elements to prevent DoS.

**frame(enc)**: `varint(inner_length) + enc.encode(value)`
- Allows skipping unknown data for forward compatibility.

### 1.7 IPv4 Address (compact-encoding-net)

```
Bytes 0-3: IPv4 address octets (sequential, e.g. 10.0.0.1 → [10, 0, 0, 1])
Bytes 4-5: Port (little-endian uint16, same as compact-encoding uint16)
Total: 6 bytes
```

### 1.8 Types Used by HyperDHT

From `hyperdht/lib/messages.js`, the minimum encoder set:

| Type | Used for |
|------|----------|
| uint (varint) | flags, version, mode, error, firewall, command, seq |
| buffer | noise payloads, values, refresh tokens |
| fixed32 | publicKey, token, id (32 bytes) |
| fixed64 | signature (64 bytes) |
| bool | connected, punching |
| array(ipv4addr) | addresses, relayAddresses, closerNodes |
| array(peer) | peer lists |
| raw | generic peer data |

---

## 2. UDX Transport

**Source**: `libudx` (C library), `udx-native` (Node.js bindings)

Reliable, ordered, congestion-controlled UDP transport. Similar to QUIC but simpler.

### 2.1 Packet Header (20 bytes)

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

### 2.2 Type Flags (byte 2)

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

### 2.3 SACK Ranges

If SACK flag set, SACK entries follow header as pairs of LE uint32 `(from, to)`.
Number of pairs = `data_offset / 8`. Payload starts at `20 + data_offset`.

### 2.4 Dual API

- **Streams** (reliable): ordered, congestion-controlled (BBR), ACK-based. Used for
  application data after connection established.
- **Messages** (unreliable): raw UDP datagrams. Used for DHT RPC queries.

### 2.5 Stream Lifecycle

```
init(id) → connect(socket, remoteId, port, host) → write/read → end/destroy
```

Stream IDs are uint32, assigned by the application. Both sides exchange IDs during
the Noise handshake (in the `udx` field of NoisePayload).

### 2.6 Firewall Callback

Incoming packets trigger a firewall callback BEFORE acceptance:
```c
int on_firewall(udx_stream_t *stream, udx_socket_t *socket, const struct sockaddr *from)
```
Returns 1 (deny) or 0 (allow). **Can call `udx_stream_connect()` inside** — this is
how incoming connections are accepted.

### 2.7 Relay

```c
udx_stream_relay_to(udx_stream_t *self, udx_stream_t *destination)
```
Bidirectional relay between two streams. Used by blind-relay.

### 2.8 Constants

```
MTU base: 1200 bytes
MTU max:  1500 bytes
Congestion control: BBR
Default port: 49737
```

### 2.9 libudx C API (what we link to)

```c
/* Lifecycle */
int udx_init(uv_loop_t *loop, udx_t *udx, udx_idle_cb on_idle);

/* Socket */
int udx_socket_init(udx_t *udx, udx_socket_t *sock, udx_socket_close_cb on_close);
int udx_socket_bind(udx_socket_t *sock, const struct sockaddr *addr, int flags);
int udx_socket_recv_start(udx_socket_t *sock, udx_socket_message_cb on_message);
int udx_socket_send_ttl(udx_socket_send_t *req, udx_socket_t *sock,
                        const uv_buf_t bufs[], int nbufs,
                        const struct sockaddr *to, int ttl, udx_socket_send_cb cb);
int udx_socket_close(udx_socket_t *sock);

/* Stream */
int udx_stream_init(udx_t *udx, udx_stream_t *stream, uint32_t id,
                    udx_stream_close_cb on_close, udx_stream_finalize_cb on_finalize);
int udx_stream_connect(udx_stream_t *stream, udx_socket_t *sock,
                       uint32_t remote_id, const struct sockaddr *remote_addr);
int udx_stream_change_remote(udx_stream_t *stream, udx_socket_t *sock,
                             uint32_t remote_id, const struct sockaddr *remote_addr,
                             udx_stream_remote_changed_cb cb);
int udx_stream_relay_to(udx_stream_t *self, udx_stream_t *dest);
int udx_stream_read_start(udx_stream_t *stream, udx_stream_read_cb on_read);
int udx_stream_write(udx_stream_write_t *req, udx_stream_t *stream,
                     const uv_buf_t bufs[], int nbufs, udx_stream_ack_cb on_ack);
int udx_stream_write_end(udx_stream_write_t *req, udx_stream_t *stream,
                         const uv_buf_t bufs[], int nbufs, udx_stream_ack_cb on_ack);
int udx_stream_destroy(udx_stream_t *stream);
void udx_stream_firewall(udx_stream_t *stream, udx_stream_firewall_cb on_firewall);
int udx_stream_set_seq(udx_stream_t *stream, uint32_t seq);
int udx_stream_set_ack(udx_stream_t *stream, uint32_t ack);
```

---

## 3. DHT RPC

**Source**: `dht-rpc/lib/io.js`, `dht-rpc/index.js`

Request/response RPC over raw UDP datagrams. NOT over UDX streams — these are plain
UDP packets for DHT queries.

### 3.1 Message Header

First byte encodes type + version:

```
Byte 0: (type << 4) | version
  REQUEST  = 0x03  (type=0, version=3)
  RESPONSE = 0x13  (type=1, version=3)
```

### 3.2 Flags Byte (byte 1)

**Request flags:**
```
Bit  Value  Field
───  ─────  ─────
0    0x01   id (32-byte routing ID present)
1    0x02   token (32-byte roundtrip token present)
2    0x04   internal (DHT-internal command, not application)
3    0x08   target (32-byte target key present)
4    0x10   value (payload buffer present)
```

**Response flags:**
```
Bit  Value  Field
───  ─────  ─────
0    0x01   id (32-byte routing ID present)
1    0x02   token (32-byte roundtrip token present)
2    0x04   closerNodes (array of 6-byte peers)
3    0x08   error (error code present)
4    0x10   value (payload buffer present)
```

### 3.3 Request Layout

```
[0x03]                              type|version
[flags]                             uint8
[tid]                               uint16 LE (transaction ID)
[to]                                6 bytes (IPv4 address, target node)
[id]        (if flag 0x01)          fixed 32 bytes (routing ID)
[token]     (if flag 0x02)          fixed 32 bytes (anti-spoofing)
[command]                           varint
[target]    (if flag 0x08)          fixed 32 bytes (DHT key)
[value]     (if flag 0x10)          varint(len) + bytes
```

### 3.4 Response Layout

```
[0x13]                              type|version
[flags]                             uint8
[tid]                               uint16 LE (matching request)
[to]                                6 bytes (IPv4 address, source)
[id]        (if flag 0x01)          fixed 32 bytes
[token]     (if flag 0x02)          fixed 32 bytes
[closerNodes] (if flag 0x04)        varint(count) + count * 6-byte IPv4
[error]     (if flag 0x08)          varint
[value]     (if flag 0x10)          varint(len) + bytes
```

### 3.5 Internal Commands

```
0 = PING
1 = PING_NAT
2 = FIND_NODE
3 = DOWN_HINT
4 = DELAYED_PING
```

### 3.6 Routing ID

The routing ID determines a node's position in the Kademlia keyspace.

**Derivation** (address-based, used when persistent):
```
id = BLAKE2b-256(host_4bytes + port_2bytes_LE)  → 32 bytes
```
Where `host_4bytes` is the IPv4 octets (e.g. `[88, 99, 3, 86]`) and `port_2bytes_LE`
is the port in little-endian. This is the compact IPv4 encoding (§1.7), hashed.

**Initial ID** (ephemeral phase): `randomBytes(32)`. Never sent on the wire — used
only for internal XOR distance calculations in the routing table.

**ID in messages**: Only included when `ephemeral === false`. The flag bit (bit 0) in
the request/response flags byte controls presence. When ephemeral, the flag is unset
and the 32-byte ID field is omitted entirely.

**Validation on receive** (`validateId`): When a message includes an ID, the receiver
recomputes `BLAKE2b(from_host:from_port)` from the UDP source address and compares it
to the wire ID. If they don't match, the ID is discarded (`from.id = null`). This
prevents a node from claiming an arbitrary position in the keyspace.

**Source**: `dht-rpc/lib/peer.js:20-25` (derivation), `dht-rpc/lib/io.js:627-630`
(validation), `dht-rpc/lib/io.js:488,521` (suppression)

### 3.7 Token System

Anti-spoofing tokens prove a node knew our address at query time.

**Generation**: `token = BLAKE2b(host_string, secret)` → 32 bytes

**Dual secrets**: Two 32-byte secrets maintained simultaneously.
- On startup: both initialized with `randombytes_buf(32)`
- Rotation every 7.5 seconds (10 × 750ms drain cycles):
  ```
  secret[0] = secret[1]           // old ← current
  secret[1] = BLAKE2b(secret[1])  // current ← hash(current)
  ```
- Validation: token must match either `token(addr, 0)` or `token(addr, 1)`
- Invalid token → INVALID_TOKEN error (code 2)

### 3.8 Routing Table (Kademlia)

**Source**: `kademlia-routing-table/index.js`

- **k** (bucket size): 20 nodes per bucket
- **Buckets**: 256 (one per bit position in 32-byte ID)
- **No bucket splitting** — fixed 256 buckets

**XOR distance**:
```
for each byte i in id:
  if id[i] != self.id[i]:
    bucket = i * 8 + clz8(id[i] ^ self.id[i])
    break
```

**Closest node lookup**: Search from target bucket outward (closer first, then further)
until k nodes found.

**Node eviction** (when bucket full):
- `full` event fires
- DHT pings the oldest node in the bucket
- If oldest responds → keep it, discard new node
- If oldest times out → remove it, insert new node

**Node record**:
```
{ id, host, port, token, to, sampled, added, pinged, seen, downHints }
```

### 3.9 Iterative Query Flow

**Source**: `dht-rpc/lib/query.js`

1. **Init**: Load k closest nodes from routing table + bootstrap nodes
2. **Iterate**: Send queries to pending nodes (concurrency α=10, default)
3. **Process responses**: Insert closer nodes into pending queue, track k-closest replies
4. **Terminate**: When no more pending nodes and inflight complete (or all slow)
5. **Commit** (for updates): Send update to all k-closest nodes in parallel

**Distance comparison**: `(target[i] ^ a[i]) - (target[i] ^ b[i])` per byte

**Slowdown**: Concurrency reduced to 3 during initial cache warmup.

**Retries**: Default 5 per request. DOWN_HINT commands get 3.

### 3.10 Congestion Control

4-slot circular buffer, drained every 750ms:

```
window = [0, 0, 0, 0]
maxWindow = 80 per slot

full = (total >= 2 * maxWindow) || (current_slot >= maxWindow)
```

On drain: rotate to next slot, subtract oldest.

### 3.11 NAT Detection

**Source**: `nat-sampler/index.js`

Maintains up to 32 address samples in a circular buffer.

**Classification** (after ≥3 samples):
```
max_hits ≥ 3:  CONSISTENT  (same external addr every time)
max_hits = 1:  RANDOM      (different addr each time)
max_hits = 2:  heuristic based on unique hosts and sample count
```

**Threshold** (adaptive):
```
samples < 4:   threshold = 0
samples < 8:   threshold = samples - 1
samples < 12:  threshold = samples - 2
else:           threshold = samples - 3
```

Result: `{ firewall: OPEN|CONSISTENT|RANDOM|UNKNOWN, host, port }`

### 3.12 Persistent vs Ephemeral Mode

Nodes start **ephemeral** and may transition to **persistent** once their
external address is verified as stable. The transition is one-way under normal
operation (persistent → ephemeral only on suspension in adaptive mode).

**Ephemeral** (default):
- Routing table ID: random 32 bytes (placeholder for XOR distance calculations)
- ID NOT included in any request or response message (flag bit 0 unset)
- Remote nodes with `from.id === null` are sampled for NAT but NOT added to
  routing tables (JS: `_addNodeFromNetwork`, line 488)
- **Storage commands blocked**: FIND_PEER, LOOKUP, ANNOUNCE, UNANNOUNCE,
  MUTABLE/IMMUTABLE_GET/PUT are silently dropped. Only internal commands (PING,
  PING_NAT, FIND_NODE, DOWN_HINT, DELAYED_PING) and connection-layer commands
  (PEER_HANDSHAKE, PEER_HOLEPUNCH) are processed.
  JS: `if (this._persistent === null) return false` (hyperdht/index.js:404)

**Persistent transition** (`_updateNetworkState`, dht-rpc/index.js:801-875):
1. After `STABLE_TICKS` (240 × 5s = ~20 min) of stable network, or immediately
   if `opts.ephemeral === false`
2. Check firewall probe: if firewalled, remain ephemeral
3. Set `firewalled = false`, `ephemeral = false`
4. Compute address-based ID: `id = BLAKE2b(compact_ipv4(host, port))`
5. **Rebuild routing table**: create new table with the address-based ID,
   copy all existing nodes (skip self, drop those that don't fit in new
   bucket layout). Suppress bucket-full callbacks during migration.
6. Re-install `on('row', ...)` listener for ping-and-swap eviction
7. If already bootstrapped: trigger `refresh()` (re-bootstrap walk with
   new ID so the table fills with nodes close to our new position)
8. Emit `'persistent'` event

**Persistent**:
- Routing table ID: `BLAKE2b(publicHost:publicPort)` — address-based
- ID included in all messages (flag bit 0 set, 32-byte field present)
- Storage commands accepted and processed
- Announce signatures bind to this ID: `signable = NS + BLAKE2b(target || nodeId || token || peer || refresh)`
  — the `nodeId` in the signature is the receiving node's routing ID. Client
  obtains it from the response, server uses its own `table.id`. Both must
  match for the signature to verify.

**Why storage commands are gated**: Announce signatures include the server's
node ID. If the server accepted announces while ephemeral (with a random ID),
those signatures would become invalid when the ID changes at the persistent
transition. By blocking storage commands until the ID is finalized, the
signature binding is always consistent.

### 3.13 Timing Constants

```
TICK_INTERVAL       = 5000 ms     (background maintenance tick)
STABLE_TICKS        = 240         (~20 min of stable network)
REFRESH_TICKS       = 60          (refresh every ~5 min idle)
RECENT_NODE         = 12 ticks    (~1 min)
OLD_NODE            = 360 ticks   (~30 min)
DRAIN_INTERVAL      = 750 ms     (congestion window rotation)
SECRET_ROTATION     = 10 drains   (~7.5 seconds)
DEFAULT_TIMEOUT     = 1000 ms    (per-request, adaptive)
DEFAULT_RETRIES     = 5
PING_EVERY          = 8 ticks    (~40 seconds)
```

### 3.14 Error Codes

```
UNKNOWN_COMMAND = 1
INVALID_TOKEN   = 2
```

---

## 4. HyperDHT Commands

**Source**: `hyperdht/lib/constants.js`, `hyperdht/lib/messages.js`

Built on top of dht-rpc. These use the `command` field in DHT RPC messages.

### 4.1 Command Numbers

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

### 4.2 Firewall Types

```
UNKNOWN    = 0
OPEN       = 1
CONSISTENT = 2
RANDOM     = 3
```

### 4.3 Error Codes (in Noise payloads)

```
NONE             = 0
ABORTED          = 1
VERSION_MISMATCH = 2
TRY_LATER        = 3
SEQ_REUSED       = 16
SEQ_TOO_LOW      = 17
```

### 4.4 Handshake Message (PEER_HANDSHAKE value)

```
[flags]         varint    bit0=peerAddress, bit1=relayAddress
[mode]          varint    0=FROM_CLIENT, 1=FROM_SERVER, 2=FROM_RELAY,
                          3=FROM_SECOND_RELAY, 4=REPLY
[noise]         buffer    Noise IK handshake bytes
[peerAddress]   6 bytes   (if flag 0x01) IPv4 address
[relayAddress]  6 bytes   (if flag 0x02) IPv4 address
```

### 4.5 Noise Payload (encrypted in handshake.noise)

```
[version]       varint    protocol version (1)
[flags]         varint    presence flags (7 bits)
[error]         varint    ERROR.* constant
[firewall]      varint    FIREWALL.* constant

Flag bits:
  0 - holepunch info present
  1 - addresses4 array present
  2 - addresses6 array present
  3 - udx info present
  4 - secretStream info present
  5 - relayThrough info present
  6 - relayAddresses array present

[holepunch]       (if flag 0):
  [id]            varint (session ID)
  [relays]        array of:
    [relayAddress]  6 bytes IPv4
    [peerAddress]   6 bytes IPv4

[addresses4]      (if flag 1): array of 6-byte IPv4
[addresses6]      (if flag 2): array of 18-byte IPv6

[udx]             (if flag 3):
  [version]       varint (1)
  [features]      varint (bit0=reusableSocket)
  [id]            varint (UDX stream ID)
  [seq]           varint (sequence number)

[secretStream]    (if flag 4):
  [version]       varint (1)

[relayThrough]    (if flag 5):
  [version]       varint (1)
  [flags]         varint (0, reserved)
  [publicKey]     fixed32
  [token]         fixed32

[relayAddresses]  (if flag 6): array of 6-byte IPv4
```

### 4.6 Holepunch Message (PEER_HOLEPUNCH value)

```
[flags]         varint    bit0=peerAddress present
[mode]          varint    FROM_CLIENT/FROM_RELAY/FROM_SERVER/REPLY
[id]            varint    holepunch session ID
[payload]       buffer    encrypted holepunch payload
[peerAddress]   6 bytes   (if flag 0x01) IPv4
```

### 4.7 Holepunch Payload (encrypted)

Encrypted with XSalsa20-Poly1305 (`crypto_secretbox`).
Key = `BLAKE2b(NS_PEER_HOLEPUNCH, noise_handshake_hash)`.

Wire format: `[nonce 24 bytes][ciphertext + MAC 16 bytes]`

Plaintext structure:
```
[flags]         varint    presence flags (6 bits)
[error]         varint    ERROR.* constant
[firewall]      varint    FIREWALL.* constant
[round]         varint    holepunch round number (0+)

Flag bits:
  0 - connected (bool)
  1 - punching (bool)
  2 - addresses array present
  3 - remoteAddress present
  4 - token (32 bytes) present
  5 - remoteToken (32 bytes) present

[connected]     varint    (if flag 0) bool
[punching]      varint    (if flag 1) bool
[addresses]     (if flag 2): array of 6-byte IPv4
[remoteAddress] (if flag 3): 6 bytes IPv4
[token]         (if flag 4): fixed 32 bytes
[remoteToken]   (if flag 5): fixed 32 bytes
```

### 4.8 Peer (used in ANNOUNCE, FIND_PEER)

```
[publicKey]      fixed 32 bytes
[relayAddresses] array of 6-byte IPv4
```

### 4.9 Announce (ANNOUNCE value)

```
[flags]     varint    bit0=peer, bit1=refresh, bit2=signature, bit3=bump
[peer]      Peer struct     (if flag 0x01)
[refresh]   buffer          (if flag 0x02)
[signature] fixed 64 bytes  (if flag 0x04)
[bump]      buffer          (if flag 0x08)
```

### 4.10 Namespace Derivation

Per-command Noise prologues via BLAKE2b:
```
crypto.namespace('hyperswarm/dht', [ANNOUNCE, UNANNOUNCE, MUTABLE_PUT,
                                    PEER_HANDSHAKE, PEER_HOLEPUNCH])
```
Produces 5 × 32-byte keys. `NS_PEER_HANDSHAKE` is the Noise prologue.
`NS_PEER_HOLEPUNCH` is used to derive the holepunch encryption key.

---

## 5. Noise IK Handshake

**Source**: `noise-handshake/`, `noise-curve-ed/`, `hyperdht/lib/noise-wrap.js`

### 5.1 Protocol

```
Noise_IK_Ed25519_ChaChaPoly_BLAKE2b
```

Constructed from: `"Noise" + "_" + pattern + "_" + DH_ALG + "_" + CIPHER_ALG + "_" + "BLAKE2b"`.
`DH_ALG` is `"Ed25519"` (from `noise-curve-ed/index.js:10`), NOT `"25519"`.

- **Pattern**: IK (initiator knows responder's static public key)
- **DH**: Ed25519 (NOT standard X25519 — see 5.5)
- **Cipher**: ChaCha20-Poly1305 (IETF)
- **Hash**: BLAKE2b-512 (64 bytes, NOT 256)

### 5.2 IK Pattern

```
IK:
  <- s                    (responder's static key is pre-known)
  ...
  -> e, es, s, ss         (message 1: initiator → responder)
  <- e, ee, se            (message 2: responder → initiator)
```

### 5.3 Prologue

```
prologue = NS_PEER_HANDSHAKE  (32 bytes, from namespace derivation)
```

Mixed into initial hash state before any handshake tokens.

### 5.4 State Machine

**Initialization** (noise-handshake/noise.js:126-132):
```
protocol = "Noise_IK_Ed25519_ChaChaPoly_BLAKE2b"  (37 bytes)

// Standard Noise: if len(protocol) <= HASHLEN, zero-pad; else hash.
// 37 <= 64, so zero-pad:
digest = protocol || 0x00 × (64 - 37)             → 64 bytes (zero-padded)
chainingKey = copy(digest)                         → 64 bytes (same value)
digest = BLAKE2b-512(digest || prologue)           → 64 bytes (via mixHash)
key = null, nonce = 0
```

Note: the protocol string is NOT hashed — it is zero-padded to HASHLEN (64 bytes)
and used directly as the initial digest. This follows the standard Noise Framework
specification for protocol strings shorter than the hash output length.

**Message 1 (initiator → responder)**:
```
1. Generate ephemeral keypair (e)
2. Write e.publicKey (32 bytes plaintext)
3. mixHash(e.publicKey)
4. ES: mixKey(DH(responderStaticPK, e.secretKey))
5. Encrypt initiator's static key (32 bytes) → 48 bytes ciphertext
6. mixHash(ciphertext)
7. SS: mixKey(DH(responderStaticPK, initiator.staticSK))
8. Encrypt payload → ciphertext
9. mixHash(ciphertext)
```

**Message 1 byte layout**:
```
[e.publicKey: 32 bytes]
[encrypted static key: 32 + 16 = 48 bytes]
[encrypted payload: N + 16 bytes]
Total: 80 + N + 16 bytes
```

**Message 2 (responder → initiator)**:
```
1. Generate ephemeral keypair (e)
2. Write e.publicKey (32 bytes plaintext)
3. mixHash(e.publicKey)
4. EE: mixKey(DH(initiator_e_PK, responder_e_SK))
5. SE: mixKey(DH(initiator_static_PK, responder_e_SK))
6. Encrypt payload → ciphertext
7. mixHash(ciphertext)
```

**Message 2 byte layout**:
```
[e.publicKey: 32 bytes]
[encrypted payload: N + 16 bytes]
Total: 32 + N + 16 bytes
```

**split()** — after handshake completes:
```
[tx_key, rx_key] = HKDF(chainingKey, empty)  → 2 × 32 bytes
handshakeHash = digest  → 64 bytes
```

Initiator: tx encrypts outgoing, rx decrypts incoming.
Responder: roles reversed (tx = initiator's rx, rx = initiator's tx).

### 5.5 Ed25519 DH (NOT X25519)

**Source**: `noise-curve-ed/index.js`

HyperDHT uses Ed25519 keys for Noise DH, NOT the standard X25519. The DH operation:

```c
// 1. Extract scalar from Ed25519 secret key (first 32 bytes = seed)
uint8_t hash[64];
crypto_hash_sha512(hash, secretKey, 32);

uint8_t scalar[32];
memcpy(scalar, hash, 32);
scalar[0] &= 248;
scalar[31] &= 127;
scalar[31] |= 64;

// 2. Perform scalar multiplication on Ed25519 curve
uint8_t output[32];
crypto_scalarmult_ed25519_noclamp(output, scalar, remotePublicKey);
```

**Key generation**:
```c
// From seed (deterministic):
crypto_sign_seed_keypair(publicKey, secretKey, seed);  // pk=32, sk=64

// Random:
crypto_sign_keypair(publicKey, secretKey);
```

**Constants**: PKLEN=32, SKLEN=64, DHLEN=32, SCALARLEN=32

### 5.6 CipherState (ChaCha20-Poly1305 IETF)

```
Key:   32 bytes
Nonce: 12 bytes (counter at bytes 4-7 LE, rest zero)
MAC:   16 bytes
```

```c
// Construct nonce
uint8_t nonce[12] = {0};
uint32_t counter = /* ... */;
memcpy(&nonce[4], &counter, 4);  // LE at offset 4

// Encrypt
crypto_aead_chacha20poly1305_ietf_encrypt(
    ciphertext, &ciphertext_len,
    plaintext, plaintext_len,
    ad, ad_len,          // AD = current digest (64 bytes)
    NULL, nonce, key);

// Counter increments after each operation. Resets to 0 on rekey.
```

### 5.7 SymmetricState (BLAKE2b-512)

```
mixHash(data):
  digest = BLAKE2b-512(digest || data)

mixKey(dh_output):
  [ck, tempK] = HKDF(chainingKey, dh_output)  → 2 × 64 bytes
  chainingKey = ck
  key = tempK[0:32]
  nonce = 0

encryptAndHash(plaintext):
  if key == null: return plaintext (no encryption yet)
  ciphertext = encrypt(key, nonce, plaintext, AD=digest)
  mixHash(ciphertext)
  nonce++
  return ciphertext

decryptAndHash(ciphertext):
  if key == null: return ciphertext
  plaintext = decrypt(key, nonce, ciphertext, AD=digest)
  mixHash(ciphertext)
  nonce++
  return plaintext
```

### 5.8 HKDF (HMAC-BLAKE2b)

```
HMAC-BLAKE2b(key, message):
  block_size = 128  (NOT 64 — BLAKE2b uses 128-byte blocks)
  if len(key) > 128: key = BLAKE2b-512(key)
  key = pad_to_128_bytes(key)
  ipad = key XOR [0x36 × 128]
  opad = key XOR [0x5c × 128]
  return BLAKE2b-512(opad || BLAKE2b-512(ipad || message))

HKDF-Extract(salt, ikm):
  return HMAC-BLAKE2b(salt, ikm)  → 64 bytes

HKDF-Expand(prk, info, length):
  T(1) = HMAC-BLAKE2b(prk, info || 0x01)
  T(2) = HMAC-BLAKE2b(prk, T(1) || info || 0x02)
  return T(1) || T(2) truncated to length

For 2 outputs: HKDF(ck, input) → 128 bytes → split into 2 × 64
For 3 outputs: HKDF(ck, input) → 192 bytes → split into 3 × 64
```

### 5.9 NoiseWrap (HyperDHT integration)

```javascript
new NoiseWrap(keyPair, remotePublicKey):
  noise = new Noise('IK', isInitiator, keyPair, { curve: ed25519 })
  noise.initialise(NS_PEER_HANDSHAKE, remotePublicKey)

send(noisePayload):
  encoded = compact_encode(noisePayload)  // See 4.5
  return noise.send(encoded)

recv(buf):
  plaintext = noise.recv(buf)
  return compact_decode(noisePayload, plaintext)

final():
  { tx, rx } = noise.split()
  return {
    isInitiator,
    publicKey, remotePublicKey,
    remoteId: derivedStreamId(hash, !isInitiator),
    holepunchSecret: BLAKE2b(NS_PEER_HOLEPUNCH, handshakeHash),
    hash: handshakeHash,
    tx: tx[0:32],
    rx: rx[0:32]
  }
```

---

## 6. SecretStream

**Source**: `@hyperswarm/secret-stream`, `sodium-secretstream`

After Noise IK handshake produces `tx`, `rx`, and `hash`, data is encrypted using
libsodium's secretstream (`crypto_secretstream_xchacha20poly1305`).

### 6.1 Constants

```
KEYBYTES    = 32      (symmetric key)
HEADERBYTES = 24      (init state for receiver)
ABYTES      = 17      (1 tag byte + 16 MAC bytes per message)
STATEBYTES  = 52      (internal state)
TAG_MESSAGE = 0x00
TAG_FINAL   = 0x01
```

### 6.2 Initialization

```
Push side (sender):
  crypto_secretstream_xchacha20poly1305_init_push(state, header, tx_key)
  // Generates 24-byte header that receiver needs

Pull side (receiver):
  // Wait for header from remote
  crypto_secretstream_xchacha20poly1305_init_pull(state, header, rx_key)
```

### 6.3 Header Exchange

The first message after handshake contains the secretstream header:

```
[uint24_le(32 + 24)]     3 bytes: length = 56
[stream_id]              32 bytes: BLAKE2b(NS_{role}, handshakeHash)
[header]                 24 bytes: from init_push()
```

`stream_id` computation:
```
initiator_id = BLAKE2b(NS_INITIATOR, handshakeHash)  → 32 bytes
responder_id = BLAKE2b(NS_RESPONDER, handshakeHash)  → 32 bytes
```

Both sides send their stream_id + header. On receipt, verify stream_id matches
expected value, then call `init_pull(header)`.

### 6.4 Message Framing

After header exchange, each message:

```
Outgoing:
  [uint24_le(ciphertext_len)]   3 bytes
  [ciphertext]                  plaintext_len + 17 bytes

  crypto_secretstream_xchacha20poly1305_push(state, ciphertext,
      plaintext, plaintext_len, NULL, 0, TAG_MESSAGE)

Incoming:
  Read uint24_le → length
  Read length bytes → ciphertext
  crypto_secretstream_xchacha20poly1305_pull(state, plaintext, &tag,
      ciphertext, ciphertext_len, NULL, 0)
  Check tag: TAG_MESSAGE (0x00) or TAG_FINAL (0x01)
```

**Overhead**: 3 bytes framing + 17 bytes AEAD = 20 bytes per message.

### 6.5 Unordered Messages

Separate from secretstream. Use `crypto_secretbox` for each message:

```
Key derivation:
  send_key = BLAKE2b(NS_role || NS_SEND, handshakeHash)  → 32 bytes

Nonce: [8-byte counter][16 zero bytes]
  counter incremented with sodium_increment() after each message

Wire: [counter 8 bytes][MAC 16 bytes][ciphertext]
```

---

## 7. Protomux

**Source**: `protomux/index.js`

Stream multiplexer on top of SecretStream. Multiple protocols (channels) over a
single encrypted connection.

### 7.1 Wire Format

**User message** (remoteId > 0):
```
[varint: remoteId]      channel ID
[varint: messageType]   type index within channel
[payload]               encoding-specific
```

**Control message** (remoteId = 0):
```
[0x00]                  reserved (always 0)
[type]                  uint8: 0=batch, 1=open, 2=reject, 3=close
[type-specific data]
```

### 7.2 Control Messages

**Open (type 1)**:
```
[0x00][0x01]
[varint: localId]       sender's local channel ID (≥ 1)
[string: protocol]      varint(len) + UTF-8 bytes
[buffer: id]            varint(len) + bytes (binary channel ID, optional)
[handshake data]        optional, encoding-specific
```

**Close (type 3)**:
```
[0x00][0x03]
[varint: localId]       channel being closed
```

**Reject (type 2)**:
```
[0x00][0x02]
[varint: remoteId]      remote channel ID being rejected
```

**Batch (type 0)** — multiple messages in one frame:
```
[0x00][0x00]
[varint: initialRemoteId]
repeating:
  [varint: messageLength]    if 0, next varint is new remoteId (channel switch)
  [message bytes]            [varint: type][payload]
```

### 7.3 Channel Lifecycle

1. Local calls `createChannel({ protocol, id })` → allocates localId (≥ 1)
2. Local sends OPEN message with localId, protocol name, id
3. Remote receives OPEN, matches by `protocol##hex(id)` key
4. Remote creates matching channel, sends OPEN back
5. Both sides: `_fullyOpen()` → can send/receive user messages
6. Either side sends CLOSE → channel destroyed, ID recycled

**Buffering**: Messages received before channel fully opened are buffered
(up to 32KB, then stream pauses).

### 7.4 Protocol Matching

Channels matched by composite key: `protocol_name + "##" + hex(id)`.
Wildcard: `protocol_name + "##"` matches any id.

### 7.5 Cork/Uncork

Reference-counted batching. During cork, messages buffered and sent as batch.
Max batch size: 8MB.

### 7.6 HyperDHT Usage

HyperDHT does NOT use protomux directly for DHT messages. It's used via
`blind-relay` protocol for relay connections. Protocol name: `"blind-relay"`.

---

## 8. Connection Establishment Flow

### 8.1 Phase 1: DHT Lookup

```
Client → DHT → FIND_PEER(hash(serverPublicKey)) → closest nodes
Closest node that knows server → returns relay info
```

Optimizations (implementation, not wire-level):
- **Pipelining:** handshakes start as findPeer results stream in (not after
  query completes). Up to 2 concurrent handshakes via Semaphore(2).
- **Relay cache:** 512-entry session cache of relay addresses per remote key.
  Reconnects skip the Kademlia walk.
- **Route shortcut:** if a prior connection established a socket route,
  try handshake through cached route before findPeer.

### 8.2 Phase 2: Relay Handshake (Noise IK)

```
Client builds NoisePayload with:
  - version: 1
  - firewall: OPEN (if has external addr) or UNKNOWN
  - addresses4: [externalAddr, ...localAddrs]
  - udx: { id: streamId, seq: 0 }
  - secretStream: { version: 1 }
  - relayThrough: (if using relay) { publicKey, token }

Client → Noise IK message 1 → PEER_HANDSHAKE → relay → Server
Server → Noise IK message 2 → PEER_HANDSHAKE → relay → Client

Both sides now have:
  - Remote's public key, firewall type, addresses
  - UDX stream IDs for direct connection
  - Shared secrets (tx, rx, holepunchSecret)
```

### 8.3 Phase 3: Holepunch

Only needed when neither side is FIREWALL.OPEN and connection was relayed.

**Source**: `hyperdht/lib/connect.js`, `hyperdht/lib/holepuncher.js`, `hyperdht/lib/nat.js`

#### 8.3.1 Architecture: Pool Socket and NAT Sampler

Each holepunch session uses a **dedicated UDP socket** ("pool socket") acquired from
`dht._socketPool`. This socket has its own NAT mapping, separate from the main DHT
socket. All probe traffic and holepunch relay messages flow through the pool socket
so that NAT classification and probe addresses are consistent.

```
Main DHT socket (port A)         Pool socket (port B)
├─ RPC traffic (PING, FIND_NODE) ├─ Holepunch relay messages (PEER_HOLEPUNCH)
├─ Handshake (PEER_HANDSHAKE)    ├─ NAT sampling PINGs
└─ rawStream firewall detection  ├─ openSession (TTL=5 probes)
                                 └─ Probe send/recv (1-byte [0x00])
```

**NAT Sampler** (`Nat` class): Determines the pool socket's firewall type by sending
PINGs to 4+ known DHT nodes. Each PING response includes a `to` field showing our
external address as seen by the remote node. The sampler classifies based on hit
counts:

| Hits on top address | Classification |
|---------------------|----------------|
| ≥ 3 same host:port  | CONSISTENT     |
| All different        | RANDOM         |
| < 3 samples          | UNKNOWN        |
| Not firewalled       | OPEN           |

Node selection: skip the first 5 nodes in the routing table (load balancing), then
ping up to `_minSamples` (4) unique nodes. Retry once if fewer than 4 responses.

The `analyzing` promise resolves when classification reaches CONSISTENT/OPEN, or
when `_minSamples` responses arrive.

#### 8.3.2 Connection Paths (Pre-Holepunch)

Before holepunch probing starts, several fast paths are checked:

```
Server firewall OPEN?          → client connects directly (onsocket)
  OR relayed && !holepunchable?

Client firewall OPEN?          → passive wait (10s timeout for server to reach us)

Same-NAT LAN shortcut?        → ping server's LAN address, connect if reachable
  (client.host == server.host
   AND server has private addresses
   AND matchAddress succeeds)

Server not holepunchable?      → abort (CANNOT_HOLEPUNCH)
  (!payload.holepunch.relays)
```

`coerceFirewall(fw)`: OPEN is treated as CONSISTENT for strategy selection.

#### 8.3.3 rawStream Firewall Detection (Zero-Punch Path)

Both client and server create a **rawStream** (UDX stream with firewall callback)
during the handshake phase, before holepunch starts.

```
Client: rawStream created at connect() init (before findPeer)
Server: rawStream created during _addHandshake (after Noise exchange)
```

The rawStream is registered on the UDX instance with a unique `local_id` (the UDX
stream ID exchanged in the Noise payload). When a UDX packet arrives matching this
`local_id` from an unknown address, the firewall callback fires.

**Client firewall callback**:
```
if (traffic from relay socket)  → ignore (relay traffic, not direct)
else if (onsocket is set)       → call onsocket(socket, port, host)
else                            → cache in serverSocket/serverAddress for later
```

**Server firewall callback**:
```
if (traffic from relay socket)  → ignore
else                            → call onsocket(socket, port, host)
```

When `onsocket` fires:
1. `rawStream.connect(socket, remoteUdxId, port, host)` — bind to the real address
2. Start SecretStream encryption
3. Destroy holepuncher (if running)
4. Set `rawStream = null` (signal: connection complete)

This path allows connections without any holepunch probes when one side can reach
the other directly (e.g., server with public IP, or NAT mapping already open from
relay traffic).

#### 8.3.4 Probe Round (Round 0)

Purpose: exchange NAT info, classify both sides, establish tokens.

```
1. Client opens low-TTL (5) session to guessed server address
   └─ openSession(serverAddress) → sends [0x00] with TTL=5 from pool socket
   └─ Primes client's NAT mapping for server's address without reaching server

2. Client sends PEER_HOLEPUNCH round=0 via relay (from pool socket):
   - firewall: puncher.nat.firewall (pool socket classification)
   - addresses: puncher.nat.addresses
   - remoteAddress: serverAddress (where we think server is)
   - punching: false
   - token: null (no token yet)

3. Server decrypts, creates its own Holepuncher (non-initiator)
   - Feeds NAT sample: nat.add(req.to, req.from) (if req.socket === puncher.socket)
   - Updates remote state: updateRemote({ punching, firewall, addresses, verified })
   - Token echo: if request came from server's relay AND client echoed token → verified

4. Server responds with its NAT info:
   - firewall, addresses, token
   - If server NAT is CONSISTENT and client opened session to matching address:
     → server sends fast-mode ping back (shortcut probe)

5. Client receives response:
   - nat.add(reply.to, reply.from) — feeds pool socket's NAT sampler
   - If server reported different address → openSession(newAddress)
   - If server firewall is UNKNOWN → wait 1000ms (give server time to classify)

6. Client analyzes NAT stability:
   - analyze(false) — passive check
   - If unstable: analyze(true) — reopen socket (up to MAX_REOPENS=3)
   - If stable after reopen: re-run probeRound
   - If server UNKNOWN and retry flag: re-run probeRound(retry=false)

7. Abort conditions:
   - Either side still UNKNOWN after retry → HOLEPUNCH_PROBE_TIMEOUT
   - Both sides RANDOM → HOLEPUNCH_DOUBLE_RANDOMIZED_NATS
```

#### 8.3.5 Token Verification

Proves NAT address ownership, controls which addresses are used for aggressive
punching strategies.

```
Generation: token = BLAKE2b-256(peerAddress.host, localSecret)
  where localSecret is a random 32-byte secret per SecurePayload

Echo flow:
  Round 0: Client sends token=null, server generates token from client's peerAddress
  Round 1: Server echoes its token in response
  Round 1: Client generates token from server's address, sends it
  Round 2: Client echoes server's token as remoteToken

Verification:
  Server checks: isServerRelay && remoteToken === BLAKE2b(peerAddress.host, localSecret)
  If match: echoed=true → verified=peerAddress.host in updateRemote

Effect: addresses from verified hosts are probed every round.
         Unverified addresses only probed every 4th round (tries & 3 === 0).
```

#### 8.3.6 Punch Round (Round 1+)

```
1. Freeze NAT classification: nat.freeze()
   └─ Prevents further updates during the gossip exchange

2. Random NAT throttle check (if either side RANDOM):
   - If dht._randomPunches >= limit OR interval not elapsed:
     → send non-punching round with token (to maintain relay session)
     → wait 10-20s (tryLater)
     → retry roundPunch(delayed=true)
   - If throttled and delayed: use server's chosen relay instead of client's

3. Send PEER_HOLEPUNCH round=1 via relay:
   - punching: true  ← tells server to start probing
   - addresses: puncher.nat.addresses (pool socket's external addresses)
   - token: BLAKE2b(serverAddress.host, localSecret)
   - remoteToken: server's token from round 0 (echo)

4. Server receives, checks remoteHolepunching:
   - Calls holepunch hook (user callback to allow/reject)
   - Checks random throttle (TRY_LATER if exceeded)
   - Calls puncher.punch() → starts probing client's addresses

5. Client receives response:
   - If tryLater → wait and retry
   - Check remoteHolepunching flag (server is actively punching)
   - If not punching: throw REMOTE_NOT_HOLEPUNCHING

6. Client calls puncher.punch() → start probing
```

#### 8.3.7 Punch Strategies

Based on `coerceFirewall()` of both sides (OPEN treated as CONSISTENT):

| Client | Server | Strategy | Details |
|--------|--------|----------|---------|
| CONSISTENT | CONSISTENT | `_consistentProbe` | 10 rounds, 1s apart |
| CONSISTENT | RANDOM | `_randomProbes` | 1750 probes, random ports, 20ms apart |
| RANDOM | CONSISTENT | Birthday sockets | 256 sockets + `_keepAliveRandomNat` |
| RANDOM | RANDOM | Fail | Cannot punch |

**CONSISTENT + CONSISTENT** (`_consistentProbe`):
```
Non-initiator (server): wait 1000ms before first round
  └─ Gives initiator's openSession time to prime NAT

Initiator (client): start immediately

Loop (max 10 rounds):
  For each remote address:
    if (!addr.verified && (tries & 3) !== 0) → skip (filter unverified)
    send [0x00] probe via pool socket (TTL=64)
  Wait 1000ms

Probe message: single byte [0x00]
Probe detection (non-initiator): echo probe back, do NOT set connected
Probe detection (initiator): set connected=true, fire onconnect(socket, port, host)
```

**CONSISTENT + RANDOM** (`_randomProbes`):
```
Requires verified remote address
1750 iterations (~35 seconds):
  Generate random port (1000-65535)
  Send [0x00] to remoteAddr.host:randomPort via pool socket
  Wait 20ms
```

**RANDOM + CONSISTENT** (Birthday sockets):
```
Requires verified remote address

Phase 1: _openBirthdaySockets
  Open 256 UDP sockets from pool (BIRTHDAY_SOCKETS)
  Each socket sends [0x00] to remoteAddr with TTL=5

Phase 2: _keepAliveRandomNat
  Initial pause: 100ms
  1750 iterations (~35 seconds):
    Cycle through all 256 sockets (i++ mod 256)
    First pass (round 0): send with TTL=5
    Subsequent passes: send with TTL=64
    Wait 20ms
```

#### 8.3.8 NAT Stability Analysis

The `analyze(allowReopen)` flow checks if the NAT classification is usable:

```
1. await nat.analyzing (wait for classification to complete)

2. _unstable() check:
   - Both local AND remote >= RANDOM → unstable
   - Local is UNKNOWN → unstable

3. If stable → return true

4. If unstable AND !allowReopen → return false (caller handles)

5. If unstable AND allowReopen → _reopen():
   Loop up to MAX_REOPENS (3) times:
     _reset() → acquire new pool socket, destroy old NAT, create new NAT
     await nat.analyzing → re-classify with new socket
   Return: coerceFirewall(nat.firewall) === CONSISTENT

6. If reopen succeeded → caller re-runs probeRound
```

#### 8.3.9 NAT Freeze

Before Round 1+ (punch round), both sides freeze their NAT classification:
```
nat.freeze()
  → Prevents add() from triggering _updateFirewall/_updateAddresses
  → Ensures consistent addresses during the gossip exchange
  → Unfrozen by nat.unfreeze() (re-runs classification)
```

#### 8.3.10 Random NAT Throttling

Global rate limiting for random-NAT strategies to prevent port exhaustion:
```
dht._randomPunches: current concurrent random punches
dht._randomPunchLimit: max concurrent (default 1)
dht._lastRandomPunch: timestamp of last completed random punch
dht._randomPunchInterval: min interval between punches (default 20s)

_incrementRandomized(): dht._randomPunches++, set randomized=true
_decrementRandomized(): dht._randomPunches--, set _lastRandomPunch=now

If throttled:
  Server: send TRY_LATER error in holepunch response
  Client: wait 10-20s, then retry with delayed=true
  Delayed: use server's chosen relay instead of client's
```

#### 8.3.11 Holepuncher Lifecycle

```
Created:   punching=false, connected=false, destroyed=false
           Pool socket acquired, NAT autoSample started

Punching:  punch() called → punching=true
           Strategy dispatched (_consistentProbe / _randomProbes / birthday)

Connected: _onholepunchmessage fires (initiator only)
           connected=true, punching=false
           Release all pool sockets except winner
           Fire onconnect(socket, port, host)

Aborted:   Probe rounds exhausted → _autoDestroy() → destroy()
           Or explicit destroy() from timeout/error

Destroyed: destroyed=true, punching=false
           Release all pool sockets
           Destroy NAT object
           If !connected: _decrementRandomized(), fire onabort()
```

#### 8.3.12 Constants

```
BIRTHDAY_SOCKETS     = 256    Max sockets for RANDOM+CONSISTENT
HOLEPUNCH            = [0x00] Probe payload (1 byte)
HOLEPUNCH_TTL        = 5      Low TTL for NAT priming / birthday
DEFAULT_TTL          = 64     Normal probe TTL
MAX_REOPENS          = 3      Socket reopen attempts for unstable NAT
HANDSHAKE_INITIAL_TIMEOUT = 10000  Prepunching abort timeout (ms)
```

### 8.4 Phase 4: Direct Connection

```
Client ←→ Server (UDX stream over UDP)
  Stream encrypted with SecretStream
  Protomux channels available for application protocols
```

When holepunch succeeds (or rawStream firewall fires), both sides call `onsocket()`:

```
onsocket(socket, port, host):
  1. rawStream.connect(socket, remoteUdxId, port, host)
  2. Start SecretStream encryption with Noise-derived keys (tx, rx, handshakeHash)
  3. Cache relay addresses for future reconnections:
     - Prefer remote's relayAddresses (from Noise payload)
     - Fallback to locally discovered relay addresses
  4. Add to socket pool routes (if reusableSocket enabled)
  5. Destroy holepuncher (if running)
  6. Clear passive connect timeout (if set)
  7. Set rawStream = null (signal: connection complete)
```

### 8.5 Phase 5: Relay Fallback (Blind Relay)

When holepunching fails or either side requests relay-through.

```
1. Client connects to relay node via normal HyperDHT
2. Both peers create blind-relay Client over the connection
3. Client.pair(isInitiator=true, token, localStream)
4. Server.pair(isInitiator=false, token, localStream)
5. Relay matches by token, creates relay streams
6. Relay calls stream.relayTo() for bidirectional forwarding
7. Both peers receive remoteId, connect their UDX streams
8. Traffic flows: Peer A → Relay → Peer B (encrypted end-to-end)
```

**Timeout**: 15 seconds to pair, else abort.

---

## 9. Blind Relay Protocol

**Source**: `blind-relay/index.js`

### 9.1 Protocol Name

```
protocol: "blind-relay"  (over protomux)
```

### 9.2 Messages

**Pair (message type 0)**:
```
[isInitiator]   1-bit flag (compact bitfield)
[token]         fixed 32 bytes (pre-exchanged)
[id]            varint (local UDX stream ID)
[seq]           varint (initial sequence number)
```

**Unpair (message type 1)**:
```
[token]         fixed 32 bytes
```

### 9.3 Pairing Flow

```
Peer A sends:  pair(isInitiator=true, token=T, id=1, seq=0)
Peer B sends:  pair(isInitiator=false, token=T, id=2, seq=0)

Relay matches by token T:
  1. Creates stream for A: firewall callback → stream.connect(socket, remoteId=1, ...)
  2. Creates stream for B: firewall callback → stream.connect(socket, remoteId=2, ...)
  3. Calls stream_A.relayTo(stream_B) — bidirectional forwarding
  4. Sends pair response to A with relay's stream.id
  5. Sends pair response to B with relay's stream.id

Data now flows: A → relay_stream_A → relay_stream_B → B
All encrypted end-to-end (relay sees ciphertext only)
```

### 9.4 Cleanup

- Explicit `unpair(token)` → destroy streams
- Peer disconnect → close all pairings for that session
- Idle timeout → relay cleans up

---

## 10. Server-Side Flow

**Source**: `hyperdht/lib/server.js`

### 10.1 Listening

```javascript
server.listen(keyPair)
  → target = hash(publicKey)
  → register in router: { onpeerhandshake, onpeerholepunch }
  → start announcer (periodic ANNOUNCE to DHT)
```

### 10.2 Incoming Handshake (_addHandshake)

```
 1. Receive PEER_HANDSHAKE with noise bytes
 2. Deduplicate by hash(noise) — same client via multiple relays = one session
 3. Decrypt Noise IK message → get client's payload
 4. Call firewall hook: firewall(remotePublicKey, payload, clientAddress)
    → if true: reject (set firewalled=true, respond with ERROR_ABORTED)
 5. Check version (must be 1), check udx field exists
 6. Create rawStream with firewall callback (see §8.3.3)
 7. Define onsocket callback (connects rawStream, starts SecretStream)
 8. Build server's NoisePayload response:
    - firewall type, addresses (including LAN addresses if shareLocalAddress)
    - holepunch: { id, relays } — ONLY if server creates a Holepuncher
    - relayThrough if configured
    - udx: { id, seq }
 9. Send Noise IK message 2 back through relay
10. Connection path decision:
    a. Client FIREWALL.OPEN or direct (non-relayed):
       → call onsocket() immediately (server sends first UDX)
    b. Same-NAT LAN shortcut:
       → if client and server on same host AND private addresses match
       → set prepunching timeout (10s), wait for LAN ping from client
    c. Server has ourRemoteAddr (knows its public address) OR _neverPunch:
       → set prepunching timeout (10s), do NOT create Holepuncher
       → wait for client's rawStream UDX (firewall detection path)
       → holepunch field in response is NULL (no relays reported)
    d. Else (server behind NAT, no public address):
       → create Holepuncher(dht, session, false, remoteFirewall)
       → puncher.onconnect = onsocket
       → set prepunching timeout (10s → destroy puncher)
       → holepunch field includes { id, relays } from announcer
```

### 10.3 Incoming Holepunch (_onpeerholepunch)

```
 1. Look up session by holepunch ID
    → if no puncher exists (server skipped creation) → abort
 2. Decrypt payload with holepunchSecret (XSalsa20-Poly1305)
 3. Token echo verification:
    - Server generates: token = BLAKE2b(peerAddress.host, localSecret)
    - If request from server's relay AND client echoed token → verified=true
 4. NAT sampling: nat.add(req.to, req.from)
    → only if req.socket === puncher.socket (same pool socket)
 5. Update remote state: updateRemote({ punching, firewall, addresses, verified })
    → verified host: peerAddress.host if token echoed, else null
 6. Analyze NAT stability:
    a. analyze(false) — passive check of current samples
    b. If !remoteHolepunching && !stable → analyze(true) — allow reopen
    c. If still not stable → abort
 7. Fast-mode ping:
    → if server is CONSISTENT AND client opened session to matching address
    → send ping back immediately (shortcut before full probe rounds)
 8. NAT freeze:
    → if nat.firewall !== UNKNOWN → nat.freeze()
    → locks classification during the gossip exchange
 9. If remote is punching (punching=true in payload):
    a. Call holepunch hook: this.holepunch(remoteFw, localFw, remoteAddrs, localAddrs)
       → if returns false: abort
    b. Random punch throttle:
       → if either side RANDOM: check _randomPunches >= limit or interval
       → if throttled: respond with ERROR.TRY_LATER (client retries after 10-20s)
    c. Execute punch: puncher.punch()
       → non-initiator → _consistentProbe with 1s initial delay
       → sends 10 rounds of probes, echoes received probes back
10. Send encrypted response:
    - firewall, addresses, token (if from relay), remoteToken echo
    - punching flag reflects server's punch state
11. On connection:
    → puncher.onconnect fires (from probe echo or rawStream detection)
    → onsocket(socket, port, host)
    → rawStream.connect → SecretStream → emit 'connection'
```

---

## 11. Constants Reference

### Crypto Sizes

```
Ed25519 public key:     32 bytes
Ed25519 secret key:     64 bytes (seed + derived)
DH scalar:              32 bytes
DH output:              32 bytes
BLAKE2b-512 hash:       64 bytes
BLAKE2b-256 hash:       32 bytes (for routing IDs, tokens)
ChaCha20-Poly1305 key:  32 bytes
ChaCha20-Poly1305 nonce: 12 bytes
ChaCha20-Poly1305 MAC:  16 bytes
Secretstream key:       32 bytes
Secretstream header:    24 bytes
Secretstream ABYTES:    17 bytes (1 tag + 16 MAC)
Secretbox nonce:        24 bytes
Secretbox MAC:          16 bytes
```

### Network

```
Default port:           49737
IPv4 address encoding:  6 bytes (4 IP + 2 port)
Bootstrap nodes:
  88.99.3.86@node1.hyperdht.org:49737
  142.93.90.113@node2.hyperdht.org:49737
  138.68.147.8@node3.hyperdht.org:49737
```

### DHT Parameters

```
k (bucket size):        20
Buckets:                256
Query concurrency (α):  10
Default retries:        5
Default timeout:        1000 ms
Tick interval:          5000 ms
Drain interval:         750 ms
Congestion max window:  80 per slot (4 slots)
Token rotation:         7.5 seconds
```

### Holepunch

```
Firewall: UNKNOWN=0, OPEN=1, CONSISTENT=2, RANDOM=3
Max random punches:     1 concurrent
Random punch interval:  20 seconds minimum
Consistent probe rounds: 10 (1s apart)
Random probes:          1750 (20ms apart)
Birthday sockets:       256
Passive timeout:        10 seconds
Relay pairing timeout:  15 seconds
TRY_LATER wait:         10-20 seconds (jitter)
```

---

## 12. What Already Exists in C (reuse, don't reimplement)

```
Layer              JS Package              C Library         Write?
─────              ──────────              ─────────         ──────
UDP transport      udx-native              libudx            NO
Crypto             sodium-native           libsodium         NO
Noise handshake    noise-handshake         (custom C++)      YES (~300 lines)
SecretStream       sodium-secretstream     libsodium         MINIMAL wrapper
Compact encoding   compact-encoding        (none)            YES (~250 lines)
DHT RPC            dht-rpc                 (none)            YES (~1500 lines)
Protomux           protomux                (none)            YES (~500 lines)
HyperDHT logic     hyperdht                (none)            YES (~2000 lines)
```

**IMPORTANT**: noise-c cannot be used because HyperDHT's Noise implementation uses
Ed25519 DH (`crypto_scalarmult_ed25519_noclamp`) with BLAKE2b-512, not the standard
X25519 with SHA-256. We implement the Noise IK state machine ourselves using libsodium.

---

## 13. Implementation Plan

### Phase 0: Protocol Analysis (this document)
Deep-read JS/C source. Document byte layouts, edge cases, state machines.

### Phase 1: Compact Encoding (~250 lines)
Varint, zig-zag, buffer, fixed32/64, array, ipv4addr. Test: round-trip against JS.

### Phase 2: UDX Transport (~100 lines)
Thin C++ wrapper around libudx C API. Test: stream between C++ and JS udx-native.

### Phase 3: DHT RPC (~1500 lines)
Message encoding/decoding, routing table, token system, iterative queries,
NAT sampling, congestion control. Test: PING/FIND_NODE against JS dht-rpc.

### Phase 4: Noise IK Handshake (~300 lines)
Custom Noise IK state machine using libsodium. Ed25519 DH, BLAKE2b-512, HKDF.
Test: handshake with JS HyperDHT server.

### Phase 5: SecretStream (~150 lines)
Wrapper around libsodium secretstream. Header exchange, uint24 framing.
Test: encrypted data exchange with JS peer.

### Phase 6: Protomux (~500 lines)
Channel multiplexing, open/close/batch, cork/uncork.
Test: open protocol channel with JS peer.

### Phase 7: Full HyperDHT API (~2000 lines)
connect(), createServer(), lookup(), announce(). Holepunch state machine.
Blind relay fallback. Test: C++ client → JS server full tunnel.

### Effort Summary

```
Phase  Component            Lines (est.)   Difficulty
─────  ─────────            ────────────   ──────────
  1    Compact encoding     250            Low
  2    UDX wrapper          100            Low
  3    DHT RPC              1500           High
  4    Noise IK             300            Medium
  5    SecretStream         150            Low
  6    Protomux             500            Medium
  7    HyperDHT API         2000           High
                            ─────
                            ~4800 lines C++
```

---

## 14. Testing Strategy

### Principle: Test against JS at every phase

```
┌──────────────┐     UDP      ┌──────────────┐
│  C++ node    │ ◄──────────► │  JS node     │
│  (under test)│              │  (reference)  │
└──────────────┘              └──────────────┘
```

### Per-Phase Tests

| Phase | Test |
|-------|------|
| 1 | Encode in C++, decode in JS (and reverse). Byte-for-byte match. |
| 2 | UDX stream between C++ and JS. Send data, verify ordering. |
| 3 | C++ sends PING to JS dht-rpc. C++ joins DHT via FIND_NODE. |
| 4 | C++ Noise IK handshake with JS HyperDHT server. |
| 5 | Encrypted data exchange between C++ and JS peers. |
| 6 | Open protomux channel between C++ and JS peers. |
| 7 | C++ connect() to JS createServer(). Full tunnel works. |

### Testnet

```javascript
const testnet = require('hyperdht/testnet')
const { bootstrap } = await testnet.createTestnet(3)
// Point C++ node at these local bootstrap addresses
```

### Packet Capture

Use UDX Wireshark dissector (`libudx/docs/wireshark/udx.lua`) for debugging.

---

## 15. Project Structure

```
hyperdht-cpp/
├── PROTOCOL.md              ← this file
├── CLAUDE.md                ← project context
├── CMakeLists.txt           ← top-level build
├── include/hyperdht/
│   ├── hyperdht.h           ← public C API (extern "C")
│   ├── dht.hpp              ← C++ API
│   ├── compact.hpp          ← compact encoding
│   ├── rpc.hpp              ← DHT RPC
│   ├── noise_wrap.hpp       ← Noise IK (custom, using libsodium)
│   ├── secret_stream.hpp
│   └── protomux.hpp
├── src/
│   ├── compact.cpp
│   ├── rpc.cpp
│   ├── routing_table.cpp
│   ├── noise.cpp            ← Noise IK state machine
│   ├── secret_stream.cpp
│   ├── protomux.cpp
│   ├── dht.cpp              ← main HyperDHT logic
│   └── hyperdht_c.cpp       ← C API wrapper
├── deps/
│   ├── libudx/              ← git submodule
│   └── (libsodium)          ← system lib or submodule
├── test/
│   ├── test_compact.cpp
│   ├── test_rpc.cpp
│   ├── test_noise.cpp
│   ├── test_stream.cpp
│   ├── test_protomux.cpp
│   ├── test_integration.cpp
│   └── js/                  ← JS reference scripts
└── examples/
    ├── ping.cpp
    └── connect.cpp
```

---

## 16. Platform Priority

1. **Linux x86_64** — primary development
2. **Linux aarch64** — RPi, NanoPi (nospoon targets)
3. **macOS arm64** — development machines
4. **Windows x64** — nospoon supports Windows
5. **ESP32** (ESP-IDF) — mimiclaw integration
6. **iOS/Android** — native library

---

## 17. Public C API

Opaque-pointer based for FFI:

```c
typedef struct hdht_t hdht_t;
typedef struct hdht_server_t hdht_server_t;
typedef struct hdht_stream_t hdht_stream_t;
typedef struct hdht_keypair_t hdht_keypair_t;

hdht_t *hdht_create(uv_loop_t *loop, const hdht_opts_t *opts);
void hdht_destroy(hdht_t *dht);

hdht_keypair_t *hdht_keypair_create(const uint8_t *seed);
void hdht_keypair_destroy(hdht_keypair_t *kp);
const uint8_t *hdht_keypair_public_key(const hdht_keypair_t *kp);

hdht_server_t *hdht_listen(hdht_t *dht, const hdht_keypair_t *kp);
void hdht_server_on_connection(hdht_server_t *srv, hdht_connection_cb cb, void *ud);
void hdht_server_close(hdht_server_t *srv);

hdht_stream_t *hdht_connect(hdht_t *dht, const uint8_t *server_pk,
                             const hdht_keypair_t *kp);
void hdht_stream_on_open(hdht_stream_t *s, hdht_open_cb cb, void *ud);
void hdht_stream_on_data(hdht_stream_t *s, hdht_data_cb cb, void *ud);
void hdht_stream_on_close(hdht_stream_t *s, hdht_close_cb cb, void *ud);
int hdht_stream_write(hdht_stream_t *s, const uint8_t *buf, size_t len);
void hdht_stream_destroy(hdht_stream_t *s);

void hdht_lookup(hdht_t *dht, const uint8_t *topic, hdht_lookup_cb cb, void *ud);
void hdht_announce(hdht_t *dht, const uint8_t *topic, const hdht_keypair_t *kp);
void hdht_unannounce(hdht_t *dht, const uint8_t *topic, const hdht_keypair_t *kp);
```

---

## 18. Licensing

All dependencies permissive:

| Library | License |
|---------|---------|
| libudx | Apache-2.0 |
| libsodium | ISC |
| libuv | MIT |

**Recommendation**: Apache-2.0 (matches libudx, includes patent grant).
