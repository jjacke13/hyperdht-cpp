# Security Audit Report — hyperdht-cpp

**Date:** 2026-05-02
**Re-verified:** 2026-05-02
**Scope:** 24k lines C++, 66 files (35 src + 31 headers + JNI wrapper)
**Version:** v0.3.0

---

## Summary

Original scan found 64 issues. **44 fixed, 2 false positives, 18 remain open.**

| Severity | Remaining |
|----------|-----------|
| **CRITICAL** | 2 |
| **HIGH** | 6 |
| **MEDIUM** | 10 |
| **LOW** | 5 |

---

## CRITICAL (2)

### ~~C5 — FALSE POSITIVE~~

**Status:** False positive. The guard already exists at `connect.cpp:595-596`:
```cpp
if (!hs.remote_payload.holepunch.has_value() ||
    hs.remote_payload.holepunch->relays.empty()) {
```
This early return ensures `relays[0]` at line 623 is only reachable when
`relays` is NOT empty.

---

### C9 — `hyperdht_destroy` Fires Callback Before libuv Drain

**File:** `src/ffi_core.cpp:149-166`

```cpp
void hyperdht_destroy(hyperdht_t* dht, hyperdht_close_cb cb, void* userdata) {
    ...
    dht->dht->destroy();
    if (cb) cb(userdata);   // fires synchronously, BEFORE uv_run drains
}
```

**Attack vector:** FFI callers treating the callback as "destruction complete" will call `hyperdht_free()`, which calls `delete dht` while the underlying `HyperDHT` object still has live libuv handles. Close callbacks fire into a destroyed object.

**Fix:** Fire `cb` only after all libuv close callbacks complete (inside the last `on_close` of the HyperDHT internals), matching the `hyperdht_server_close` pattern.

---

### C10+C11 — Secret Key Material on Stack Never Zeroed + `connect_relay` No PK Length Validation

**C10 — File:** `src/ffi_core.cpp:192`, `src/ffi_storage.cpp:50-51,349-351`, `src/ffi_server.cpp:32-33`, `wrappers/kotlin/src/main/cpp/hyperdht_jni.cpp:145-148,902-904,1056-1059`

```cpp
memcpy(out->public_key, kp.public_key.data(), 32);
memcpy(out->secret_key, kp.secret_key.data(), 64);   // secret key on stack
// Stack frame never zeroed on return
```

64-byte Ed25519 secret keys are copied into `hyperdht_keypair_t` on the stack and never `sodium_memzero`'d. Recoverable from crash dumps. Also applies to JNI `keypairGenerate`, `keypairFromSeed` (seed not zeroed), `mutablePut`, `unannounce`.

**Fix:** Add `sodium_memzero(&cpp_kp, sizeof(cpp_kp))` before each function's return. Provide a `hyperdht_keypair_zero(kp)` helper. In JNI, also zero `seed[32]` in `keypairFromSeed`.

**C11 — File:** `src/ffi_server.cpp:271-297`

```cpp
void hyperdht_connect_relay(hyperdht_t* dht,
                             const uint8_t* remote_pk, ...)
{
    memcpy(pk.data(), remote_pk, 32);  // reads 32 bytes from bare pointer
}
```

`remote_pk` is `const uint8_t*` with no length parameter. A caller passing a buffer shorter than 32 bytes produces an out-of-bounds read. Same issue for `relay_pk`. Function is `void` — no error return.

**Fix:** Add `size_t pk_len` parameter with early-return guard, or change return type to `int`.

---

## HIGH (6)

### H1 — Nonce Counter Truncated to 32 Bits — MITIGATED

**File:** `src/noise_wrap.cpp:163-172, 233`
**Status:** Mitigated. `encrypt_with_ad` now returns empty at `nonce_ >= UINT32_MAX`.
The 32-bit truncation in `build_nonce` is kept for JS wire compatibility (JS
`cipher.js` uses `setUint32(4, counter, true)`). In practice, Noise IK
handshakes only use 2 encryptions per session — nonce exhaustion is unreachable.

**Residual:** Parameter type remains `uint64_t`; could be narrowed to `uint32_t`
for clarity.

---

### H9 — `SocketRef::on_socket_close` Dereferences `pool_` After `SocketPool` Destruction

**File:** `src/socket_pool.cpp:125-128`

```cpp
void SocketRef::on_socket_close(udx_socket_t* socket) {
    auto* self = static_cast<SocketRef*>(socket->data);
    self->pool_.remove(self);   // pool_ is a reference to destroyed SocketPool
}
```

`SocketPool::~SocketPool()` calls `destroy()` which closes sockets asynchronously via `udx_socket_close`. The destructor returns, `SocketPool` is freed, then `on_socket_close` fires against the dangling `pool_` reference.

**Fix:** In `SocketPool::destroy()`, null out `socket_.data` on each `SocketRef` before closing, so `on_socket_close` gets null `self` and returns early.

---

### H13 — Port 0 Accepted in `Ipv4Addr::decode` — MITIGATED

**File:** `src/compact.cpp:361`, `src/query.cpp:326`
**Status:** Mitigated. Port 0 filtering added at `query.cpp:326` where
`closer_nodes` entries are processed — port 0 addresses are skipped before
reaching `add_pending` or the routing table. The decoder itself does NOT
reject port 0 because relay `peer_address` fields legitimately use port 0
as a placeholder (e.g., in `decode_noise_payload`).

**Residual:** Port 0 addresses could still reach the routing table via
`reping_and_swap` if a node's port changes to 0 after insertion.

---

### H16 — JNI Event Callback Global Refs Never Freed

**File:** `wrappers/kotlin/src/main/cpp/hyperdht_jni.cpp:307-348`

`onBootstrapped`, `onNetworkChange`, `onNetworkUpdate`, `onPersistent`, and `serverOnListening` all allocate `new jobject(env->NewGlobalRef(...))`. There is no cleanup path — `Java_com_hyperdht_Native_destroy` has no access to the stored ref pointers. ART's 16384 global ref limit is eventually exhausted.

**Fix:** Track event callback global refs in a data structure keyed on the DHT handle. Free them in `Java_com_hyperdht_Native_free`. For one-shot callbacks (bootstrapped, persistent), delete the global ref immediately after the callback fires.

---

### H17 — `serverCreate` Stores `ServerCtx` for Null Handle

**File:** `wrappers/kotlin/src/main/cpp/hyperdht_jni.cpp:608-617`

```cpp
auto sh = (jlong)hyperdht_server_create((hyperdht_t*)h);
auto* ctx = new ServerCtx;
g_server_ctx[sh] = ctx;   // sh may be 0 (null)
return sh;
```

If `hyperdht_server_create` returns null, `g_server_ctx[0]` is inserted. Subsequent `serverListen(0, ...)` passes null to `hyperdht_server_listen`, crashing on `srv->server` dereference.

**Fix:** Check `sh == 0` before inserting into `g_server_ctx`. Free the leaked `ServerCtx`.

---

### H20 — JNI Global Ref Double-`DeleteGlobalRef` on Stream Open Failure

**File:** `wrappers/kotlin/src/main/cpp/hyperdht_jni.cpp:479-503`

```cpp
auto* sctx = new StreamCtx;
sctx->onOpen  = ctx->onOpen;   // same global ref as ctx->onOpen
sctx->onData  = ctx->onData;
sctx->onClose = ctx->onClose;
```

On the failure path (`stream == nullptr`), `sctx->on*` are `DeleteGlobalRef`'d, then `ctx->on*` (same refs) are also `DeleteGlobalRef`'d — double-free.

**Fix:** After assigning `sctx->on* = ctx->on*`, immediately null `ctx->on*` to make ownership transfer explicit.

---

### H25 — Blind Relay `pairings_` — Size Cap Added, No TTL

**File:** `src/blind_relay.cpp:447-472`
**Status:** Partially fixed. Size cap of 1024 added via `server_.pairing_count()`.

**Residual:** Unpaired entries hold their slot indefinitely — no timeout. An
attacker controlling one side can hold all 1024 slots. Add per-pairing TTL
(e.g. 30s) and evict stale entries on timer or new pair attempts.

---

## MEDIUM (10)

### M1 — IPv6 `from_string` Silent Non-Hex Corruption

**File:** `src/compact.cpp:422-437`

Non-hex characters in IPv6 groups are silently skipped, producing wrong address values (e.g., `"gg::1"` parses as `0::1`). Loop termination was fixed but validation is still missing.

**Fix:** Add hex-char validation; return error on non-hex input.

---

### M2 — `uv_buf_t::len` `size_t` to `unsigned int` Truncation

**File:** `src/rpc.cpp:280`, `src/holepunch.cpp:830`

```cpp
static_cast<unsigned int>(ctx->buf.size())  // silent truncation if > UINT_MAX
```

**Fix:** Assert `ctx->buf.size() <= UINT_MAX` before the cast.

---

### M4 — `hash_state` Not Zeroed in `announce_sig.cpp`

**File:** `src/announce_sig.cpp:51-66, 177-188`

`crypto_generichash_state` left on stack after `crypto_generichash_final`. Contains intermediate digest state including token and peer data.

**Fix:** Add `sodium_memzero(&hash_state, sizeof(hash_state))` after final.

---

### M8 — `UdxSocket` Has No RAII Destructor

**File:** `include/hyperdht/udx.hpp:48-71`

Destructor is implicit and does nothing. Leaked handles on error paths. This is by design due to libuv's async close pattern, but a scope-exit-without-close silently leaks.

**Fix:** Add destructor that calls `udx_socket_close()` if bound, or add `assert(!bound_)`.

---

### M10 — Birthday Socket `on_holepunch_message` Raw `this` During Linger

**File:** `src/holepunch.cpp:619-628`

```cpp
ref->on_holepunch_message =
    [this](const uint8_t*, size_t, const compact::Ipv4Address& from,
           socket_pool::SocketRef* r) {
        on_message(from, r->socket(), r);
    };
```

The winning birthday socket's callback holds raw `this` (Holepuncher). During the pool's linger period after the puncher is destroyed, incoming probes dereference freed memory.

**Fix:** Clear `on_holepunch_message` on all holders (including the winner) after connect completes.

---

### M13 — `peer_rtt_` Evicts by `begin()` Not LRU

**File:** `src/rpc.cpp:1099-1102`

```cpp
peer_rtt_.erase(peer_rtt_.begin());  // unordered_map::begin() is arbitrary
```

Eviction is non-deterministic. An attacker controlling which IPs appear in responses can cause targeted evictions of legitimate peer RTT data.

---

### M14 — `handshake_dedup_` Map Uncapped

**File:** `src/server.cpp:370-371`

`handshake_dedup_` uses 96-char hex string keys with no size cap or eviction. Under a handshake flood, entries accumulate (separate from the `connections_` cap at H23).

---

### M15 — GC-Only Eviction — No On-Put Cap for Storage

**File:** `src/rpc_handlers.cpp:88-95`

GC runs every 60s. Between sweeps, expired announce entries accumulate. The `mutables_` and `immutables_` LRU stores have a max entry count but no per-value size enforcement at the store level (handled at the handler level by C15/C16 fixes, but the store itself accepts anything).

---

### M19 — JNI Firewall Callback Exception Causes Fail-Open

**File:** `wrappers/kotlin/src/main/cpp/hyperdht_jni.cpp:709-726`

```cpp
jboolean reject = env->CallBooleanMethod(*ref, mid, jpk, jhost, (jint)port);
return reject ? 1 : 0;
// No ExceptionCheck() — exception yields JNI_FALSE = accept
```

If the Kotlin firewall callback throws, the connection is silently accepted (fail-open).

**Fix:** Call `env->ExceptionCheck()` after `CallBooleanMethod`; if thrown, return 1 (reject) to fail closed.

---

### M20 — `connectionKeepAlive` `int` to `uint32_t` Truncation

**File:** `wrappers/kotlin/src/main/cpp/hyperdht_jni.cpp:178`

```cpp
opts.connection_keep_alive = (uint32_t)connectionKeepAlive;  // jint is signed 32-bit
```

A value of `-1` (Kotlin sentinel) becomes `0xFFFFFFFF` (~49-day keepalive). The C API's `UINT64_MAX` sentinel can never be conveyed.

**Fix:** Change JNI `connectionKeepAlive` to `jlong`. Update Kotlin `DhtOptions.connectionKeepAlive` from `Int` to `Long`.

---

## LOW (5)

| # | File | Issue |
|---|------|-------|
| ~~L1~~ | ~~`noise_wrap.hpp/cpp`~~ | ~~FIXED: CipherState destructor added; `initialise_key` now zeros old key before overwrite~~ |
| L2 | `holepunch.cpp:1484-1489` | Token replay theoretical — mitigated by per-session `holepunchSecret` |
| L3 | `rpc_handlers.cpp:104` | `static int req_count` overflows at `INT_MAX` — signed integer overflow is UB |
| L4 | `socket_pool.cpp:168` | `SocketPool::acquire()` has no fd/count limit |
| L5 | `hyperdht_jni.cpp:307-323` | One-shot event global refs leaked (bootstrapped, persistent) |
| L6 | `ffi_stream.cpp:293-298` | `hyperdht_poll_stop` async close with no drain callback — fd reuse race |
