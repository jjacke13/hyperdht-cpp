# JavaScript → C++ File Mapping

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
│   ├── persistent.js           ⚠️ rpc.cpp (ephemeral/persistent toggle)
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
    └── session.js              ⚠️ internal in rpc.cpp (no public Session API)
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

## blind-relay (1.4.0)

```
blind-relay/
├── index.js                    ❌ DEFERRED — relay fallback (~5% of connections)
└── lib/
    └── errors.js               ❌ DEFERRED
```

## compact-encoding-bitfield (2.0.0)

```
compact-encoding-bitfield/
└── index.js                    ❌ DEFERRED — only used by blind-relay (flags field)
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
