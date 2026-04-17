# JavaScript → C++ Mapping

API naming and file mapping for JS developers migrating to the C++ / C FFI layer.

## API Name Translation

Convention: JS uses `camelCase`, C++ uses `snake_case`, C FFI uses `hyperdht_` prefix + `snake_case`.

### DHT Lifecycle

| JS | C++ | C FFI |
|----|-----|-------|
| `new HyperDHT(opts)` | `HyperDHT(loop, opts)` | `hyperdht_create(loop, opts)` |
| `dht.destroy({ force })` | `dht.destroy(opts, cb)` | `hyperdht_destroy()` / `hyperdht_destroy_force()` |
| `dht.suspend({ log })` | `dht.suspend(log)` | `hyperdht_suspend()` / `hyperdht_suspend_logged()` |
| `dht.resume({ log })` | `dht.resume(log)` | `hyperdht_resume()` / `hyperdht_resume_logged()` |
| `dht.port` | `dht.port()` | `hyperdht_port(dht)` |

### Server

| JS | C++ | C FFI |
|----|-----|-------|
| `dht.createServer(opts, onconn)` | `dht.create_server()` | `hyperdht_server_create(dht)` |
| `server.listen(keyPair)` | `server.listen(kp, cb)` | `hyperdht_server_listen(srv, kp, cb, ud)` |
| `server.close()` | `server.close(cb)` | `hyperdht_server_close(srv, cb, ud)` |
| `server.close({ force: true })` | `server.close(true, cb)` | `hyperdht_server_close_force(srv, cb, ud)` |
| `server.address()` | `server.address()` | `hyperdht_server_address(srv, ...)` |
| `server.publicKey` | `server.public_key()` | `hyperdht_server_public_key(srv)` |
| `server.listening` | `server.is_listening()` | `hyperdht_server_is_listening(srv)` |
| `server.suspend()` | `server.suspend()` | `hyperdht_server_suspend(srv)` |
| `server.resume()` | `server.resume()` | `hyperdht_server_resume(srv)` |
| `server.refresh()` | `server.refresh()` | `hyperdht_server_refresh(srv)` |
| `opts.firewall(pk, addr)` | `server.set_firewall(cb)` | `hyperdht_server_set_firewall(srv, cb, ud)` |
| `opts.firewall` (async) | `server.set_firewall_async(cb)` | `hyperdht_server_set_firewall_async(srv, cb, ud)` |
| `opts.holepunch(pk, addr)` | `server.set_holepunch(cb)` | `hyperdht_server_set_holepunch(srv, cb, ud)` |
| `opts.relayThrough` | `server.relay_through` | `hyperdht_server_set_relay_through(srv, pk)` |
| `server.on('listening')` | `server.on_listening(cb)` | `hyperdht_server_on_listening(srv, cb, ud)` |
| `server.notifyOnline()` | `server.notify_online()` | `hyperdht_server_notify_online(srv)` |

### Client: Connect

| JS | C++ | C FFI |
|----|-----|-------|
| `dht.connect(remotePk)` | `dht.connect(pk, cb)` | `hyperdht_connect(dht, pk, cb, ud)` |
| `dht.connect(remotePk, opts)` | `dht.connect(pk, opts, cb)` | `hyperdht_connect_ex(dht, pk, opts, cb, ud)` |

### Queries

| JS | C++ | C FFI |
|----|-----|-------|
| `dht.findPeer(pk, opts)` | `dht.find_peer(pk, on_reply, on_done)` | `hyperdht_find_peer()` / `hyperdht_find_peer_ex()` |
| `dht.lookup(target, opts)` | `dht.lookup(target, on_reply, on_done)` | `hyperdht_lookup()` / `hyperdht_lookup_ex()` |
| `dht.announce(target, kp)` | `dht.announce(target, value, cb)` | `hyperdht_announce(dht, ...)` |
| `dht.unannounce(target, kp)` | `dht.unannounce(pk, kp, cb)` | `hyperdht_unannounce(dht, ...)` |
| `dht.lookupAndUnannounce(...)` | `dht.lookup_and_unannounce(...)` | — |
| `query.destroy()` | — | `hyperdht_query_cancel()` + `hyperdht_query_free()` |

### Mutable / Immutable Storage

| JS | C++ | C FFI |
|----|-----|-------|
| `dht.immutablePut(value)` | `dht.immutable_put(value, cb)` | `hyperdht_immutable_put(dht, ...)` |
| `dht.immutableGet(hash)` | `dht.immutable_get(hash, cb)` | `hyperdht_immutable_get()` / `hyperdht_immutable_get_ex()` |
| `dht.mutablePut(kp, value)` | `dht.mutable_put(kp, val, seq, cb)` | `hyperdht_mutable_put(dht, ...)` |
| `dht.mutableGet(pk, opts)` | `dht.mutable_get(pk, seq, latest, cb)` | `hyperdht_mutable_get()` / `hyperdht_mutable_get_ex()` |

### State Queries

| JS | C++ | C FFI |
|----|-----|-------|
| `dht.online` | `dht.is_online()` | `hyperdht_is_online(dht)` |
| `dht.degraded` | `dht.is_degraded()` | `hyperdht_is_degraded(dht)` |
| `dht.destroyed` | `dht.is_destroyed()` | `hyperdht_is_destroyed(dht)` |
| `dht.bootstrapped` | `dht.is_bootstrapped()` | `hyperdht_is_bootstrapped(dht)` |
| — | `dht.is_persistent()` | `hyperdht_is_persistent(dht)` |
| — | `dht.is_suspended()` | `hyperdht_is_suspended(dht)` |

### Events

| JS | C++ | C FFI |
|----|-----|-------|
| `dht.on('ready', cb)` | `dht.on_bootstrapped(cb)` | `hyperdht_on_bootstrapped(dht, cb, ud)` |
| `dht.on('network-change', cb)` | `dht.on_network_change(cb)` | `hyperdht_on_network_change(dht, cb, ud)` |
| `dht.on('network-update', cb)` | `dht.on_network_update(cb)` | `hyperdht_on_network_update(dht, cb, ud)` |
| `dht.on('persistent', cb)` | `dht.on_persistent(cb)` | `hyperdht_on_persistent(dht, cb, ud)` |

### Utilities

| JS | C++ | C FFI |
|----|-----|-------|
| `HyperDHT.keyPair()` | `HyperDHT::key_pair()` | `hyperdht_keypair_generate(pk, sk)` |
| `HyperDHT.keyPair(seed)` | `HyperDHT::key_pair(seed)` | `hyperdht_keypair_from_seed(pk, sk, seed)` |
| `HyperDHT.hash(data)` | `HyperDHT::hash(data, len)` | `hyperdht_hash(out, data, len)` |
| `dht.defaultKeyPair` | `dht.default_keypair()` | `hyperdht_default_keypair(dht)` |
| `dht.remoteAddress()` | `dht.remote_address()` | `hyperdht_remote_address(dht, ...)` |
| `dht.addNode(addr)` | `dht.add_node(addr)` | `hyperdht_add_node(dht, host, port)` |
| `dht.toArray(limit)` | `dht.to_array(limit)` | `hyperdht_to_array(dht, buf, cap)` |
| `dht.connectionKeepAlive` | `dht.connection_keep_alive()` | `hyperdht_connection_keep_alive(dht)` |

### Constants

| JS | C++ | C FFI |
|----|-----|-------|
| `HyperDHT.FIREWALL.UNKNOWN` | `HyperDHT::FIREWALL::UNKNOWN` | `HYPERDHT_FIREWALL_UNKNOWN` |
| `HyperDHT.FIREWALL.OPEN` | `HyperDHT::FIREWALL::OPEN` | `HYPERDHT_FIREWALL_OPEN` |
| `HyperDHT.FIREWALL.CONSISTENT` | `HyperDHT::FIREWALL::CONSISTENT` | `HYPERDHT_FIREWALL_CONSISTENT` |
| `HyperDHT.FIREWALL.RANDOM` | `HyperDHT::FIREWALL::RANDOM` | `HYPERDHT_FIREWALL_RANDOM` |

### C FFI Only (no JS equivalent)

| C FFI | Purpose |
|-------|---------|
| `hyperdht_opts_default()` | Sentinel-filled options struct |
| `hyperdht_connect_opts_default()` | Sentinel-filled connect options |
| `hyperdht_query_free(q)` | Release query handle (prevent leak) |
| `hyperdht_firewall_done(done)` | Complete async firewall decision |
| `hyperdht_set_log_callback(dht, cb)` | Debug logging hook |
| `hyperdht_ping(dht, host, port, cb)` | Direct ping (dht-rpc level) |
| `hyperdht_stream_open/write/close` | Encrypted stream over connection |

---

## File Mapping

Every JS source file in the HyperDHT stack and its C++ equivalent.

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Fully implemented |
| ⚠️ | Partially implemented |
| ⬜ | Not needed (handled by C lib or inlined) |
| ❌ | Not implemented (deferred) |
| 🚫 | Unused in hyperdht 6.29.1 |

---

## hyperdht (6.29.1)

```
hyperdht/
├── index.js                    ✅ dht.hpp / dht.cpp
├── lib/
│   ├── announcer.js            ✅ announcer.hpp / announcer.cpp
│   ├── connect.js              ✅ dht.cpp (do_connect) + peer_connect.hpp/cpp
│   ├── connection-pool.js      ✅ connection_pool.hpp / connection_pool.cpp
│   ├── constants.js            ⬜ inline in headers (FIREWALL_*, MODE_*, ERROR_*)
│   ├── crypto.js               ⬜ libsodium direct calls
│   ├── encode.js               ⬜ inline (trivial helper)
│   ├── errors.js               ⬜ error codes in headers
│   ├── holepuncher.js          ✅ holepunch.hpp / holepunch.cpp
│   ├── messages.js             ✅ dht_messages.hpp/cpp + peer_connect.cpp
│   ├── nat.js                  ✅ nat_sampler.hpp / nat_sampler.cpp
│   ├── noise-wrap.js           ✅ noise_wrap.hpp / noise_wrap.cpp
│   ├── persistent.js           ✅ rpc_handlers.hpp/cpp — all server-side
│                                 storage handlers (find_peer / lookup /
│                                 announce / unannounce / mutable_{put,get}
│                                 / immutable_{put,get}) + LRU + GC timer.
│                                 Separately, rpc.cpp owns the
│                                 ephemeral↔persistent node-state toggle.
│                                 JS `bumps` cache for refresh-chain is
│                                 intentionally deferred (see JS-PARITY-GAPS).
│   ├── raw-stream-set.js       ⬜ not needed (no raw stream tracking in C++)
│   ├── refresh-chain.js        🚫 unused in hyperdht 6.29.1
│   ├── router.js               ✅ router.hpp / router.cpp
│   ├── secure-payload.js       ✅ holepunch.cpp (SecurePayload class)
│   ├── semaphore.js            ✅ async_utils.hpp / async_utils.cpp
│   ├── server.js               ✅ server.hpp / server.cpp + server_connection.hpp/cpp
│   ├── sleeper.js              ✅ async_utils.hpp / async_utils.cpp
│   └── socket-pool.js          ✅ socket_pool.hpp / socket_pool.cpp
├── bin.js                      ⬜ CLI tool — not needed
├── browser.js                  ⬜ browser shim — not needed
└── testnet.js                  ⬜ test harness — not needed
```

## dht-rpc (6.26.3)

```
dht-rpc/
├── index.js                    ✅ rpc.hpp / rpc.cpp + dht.hpp / dht.cpp
└── lib/
    ├── commands.js             ⬜ inline in messages.hpp (CMD_*)
    ├── errors.js               ⬜ inline in headers
    ├── health.js               ✅ health.hpp / health.cpp
    ├── io.js                   ✅ rpc.hpp / rpc.cpp + messages.hpp / messages.cpp
    ├── peer.js                 ⬜ inline in routing_table.hpp
    ├── query.js                ✅ query.hpp / query.cpp
    └── session.js              ✅ rpc.hpp (rpc::Session) + RpcSocket::cancel_request
```

## protomux (3.10.1)

```
protomux/
└── index.js                    ✅ protomux.hpp / protomux.cpp
```

## @hyperswarm/secret-stream (6.9.1)

```
@hyperswarm/secret-stream/
├── index.js                    ✅ secret_stream.hpp / secret_stream.cpp
└── lib/
    ├── bridge.js               ⬜ virtual stream for testing — not needed
    └── handshake.js            ✅ secret_stream.cpp (header exchange)
```

## blind-relay (2.3.0)

```
blind-relay/
├── index.js                    ✅ blind_relay.hpp / blind_relay.cpp
│                                 (BlindRelayClient/Server/Session +
│                                  Pair/Unpair messages + udx_stream_relay_to)
└── lib/
    └── errors.js               ⬜ inline in blind_relay.hpp (RelayError namespace)
```

## compact-encoding-bitfield (2.0.0)

```
compact-encoding-bitfield/
└── index.js                    ⬜ inline in blind_relay.cpp — the only usage is
                                   a single 1-byte `bitfield(7)` on the Pair
                                   message (bit 0 = isInitiator). A general
                                   bitfield codec would be over-engineering.
```

## compact-encoding (2.19.0)

```
compact-encoding/
├── index.js                    ✅ compact.hpp / compact.cpp
├── raw.js                      ✅ compact.cpp (Raw codec)
├── endian.js                   ✅ compact.cpp (LE read/write helpers)
├── lexint.js                   ⬜ not used by HyperDHT
└── test.js                     ⬜ test file
```

## compact-encoding-net (1.2.0)

```
compact-encoding-net/
└── index.js                    ✅ compact.hpp / compact.cpp (Ipv4Addr + Ipv6Addr)
```

## noise-handshake (4.2.0)

```
noise-handshake/
├── noise.js                    ✅ noise_wrap.hpp / noise_wrap.cpp
├── symmetric-state.js          ✅ noise_wrap.cpp
├── dh.js                       ⬜ libsodium (crypto_scalarmult_ed25519)
├── cipher.js                   ⬜ libsodium (ChaCha20-Poly1305)
├── hkdf.js                     ⬜ libsodium (HMAC-BLAKE2b)
└── hmac.js                     ⬜ libsodium (BLAKE2b keyed)
```

## noise-curve-ed (2.1.0)

```
noise-curve-ed/
└── index.js                    ⬜ libsodium (Ed25519 DH via noclamp)
```

## sodium-secretstream (1.2.0)

```
sodium-secretstream/
└── index.js                    ⬜ libsodium (crypto_secretstream_xchacha20poly1305)
```

## kademlia-routing-table (1.0.6)

```
kademlia-routing-table/
└── index.js                    ✅ routing_table.hpp / routing_table.cpp
```

## nat-sampler (1.0.1)

```
nat-sampler/
└── index.js                    ✅ nat_sampler.hpp / nat_sampler.cpp
```

## udx-native (1.19.2)

```
udx-native/
├── lib/
│   ├── udx.js                  ⬜ libudx C library (deps/libudx)
│   ├── socket.js               ⬜ libudx (udx_socket_t)
│   ├── stream.js               ⬜ libudx (udx_stream_t)
│   ├── network-interfaces.js   ⬜ libuv (uv_interface_addresses)
│   └── ip.js                   ⬜ inline helpers
└── binding.js                  ⬜ N/A (native binding)
```

---

## C++ Files Without JS Equivalent

These are C++-specific files with no direct JS counterpart:

```
include/hyperdht/
├── hyperdht.h          C API (extern "C") for FFI — JS doesn't need this
├── debug.hpp           DHT_LOG macro — JS uses console.log
├── lru_cache.hpp       LRU cache for storage — JS uses xache npm package
├── announce_sig.hpp    Signature verification — inline in JS
├── rpc_handlers.hpp    Command dispatch — inline in JS dht-rpc
├── udx.hpp             RAII wrappers for libudx — JS uses udx-native bindings
└── tokens.hpp          Token rotation — inline in JS dht-rpc
```
