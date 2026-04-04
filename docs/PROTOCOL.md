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

```
id = BLAKE2b(publicIP_4bytes + publicPort_2bytes_LE)  → 32 bytes
```

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

**Ephemeral** (default): Node ID not included in messages. Used by clients and
nodes behind NAT.

**Persistent**: Node ID included in all messages. Stable long-term identity.
Entered explicitly (`ephemeral: false`) or adaptively after ~20 minutes of
stable external address.

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
Noise_IK_25519_ChaChaPoly_BLAKE2b
```

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

**Initialization**:
```
chainingKey = BLAKE2b-512("Noise_IK_25519_ChaChaPoly_BLAKE2b")  → 64 bytes
digest = BLAKE2b-512(chainingKey || prologue)
key = null, nonce = 0
```

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

Up to 2 parallel queries via semaphore.

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

#### 8.3.1 Probe Round (round 0)

Purpose: classify both NATs before attempting to punch.

```
1. Client opens low-TTL (5) session to guessed server address
2. Client sends PEER_HOLEPUNCH round=0 (punching=false) via relay
3. Server responds with its NAT info
4. Both classify: OPEN / CONSISTENT / RANDOM / UNKNOWN
5. If UNKNOWN after retry → abort
6. If both RANDOM → abort (DOUBLE_RANDOMIZED_NATS)
```

#### 8.3.2 Token Verification

Proves NAT address ownership:
```
Client: token = BLAKE2b(serverAddress.host, localSecret)
Client sends token in holepunch payload
Server echoes token back in response
Client verifies: echoed token matches → address is verified
Only verified addresses used for aggressive punching
```

#### 8.3.3 Punch Strategies (rounds 1+)

Based on firewall combination:

| Client | Server | Strategy |
|--------|--------|----------|
| CONSISTENT | CONSISTENT | 10 probe rounds, 1s apart |
| CONSISTENT | RANDOM | 1750 probes to random ports, 20ms apart (~35s) |
| RANDOM | CONSISTENT | 256 birthday-paradox sockets + cycling probes |
| RANDOM | RANDOM | **Fail** — cannot punch |

**Birthday paradox**: Open 256 UDP sockets. Probability that one gets a matching
NAT mapping: 1 - (1 - 1/65536)^256 ≈ ~0.4% per socket, but combined with
probe cycling the success rate is much higher.

#### 8.3.4 Random NAT Throttling

```
Max concurrent random punches: 1
Min interval between random punches: 20 seconds
If throttled: send TRY_LATER error, wait 10-20s (with jitter)
```

### 8.4 Phase 4: Direct Connection

```
Client ←→ Server (UDX stream over UDP)
  Stream encrypted with SecretStream
  Protomux channels available for application protocols
```

If holepunch succeeds, both sides call `onsocket()`:
- Connect rawStream to peer's address with exchanged UDX stream IDs
- Start SecretStream encryption with Noise-derived keys
- Cache relay addresses for future connections

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

### 10.2 Incoming Handshake (_onpeerhandshake)

```
1. Receive PEER_HANDSHAKE with noise bytes
2. Deduplicate by hash(noise)
3. Decrypt Noise IK message → get client's payload
4. Call firewall hook: firewall(remotePublicKey, payload, clientAddress)
   → if true: reject
5. Check version (must be 1), check udx field exists
6. Build server's NoisePayload response:
   - firewall type, addresses, udx info
   - holepunch: { id, relays } if not OPEN
   - relayThrough if configured
7. Send Noise IK message 2 back through relay
8. If client is OPEN → connect directly (onsocket)
9. If relay-through → setup relay connection
10. Else → create Holepuncher, wait for holepunch rounds
```

### 10.3 Incoming Holepunch (_onpeerholepunch)

```
1. Look up session by holepunch ID
2. Decrypt payload with holepunchSecret
3. Update NAT samples, verify token echo
4. Analyze NAT stability
5. If remote is punching:
   - Call holepunch hook
   - Check random punch throttle
   - Execute punch strategy
6. Send encrypted response with our NAT info
7. On success → onsocket() → emit 'connection'
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
