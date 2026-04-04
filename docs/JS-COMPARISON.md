# API Comparison: C++ vs JavaScript HyperDHT

This document maps between the JS HyperDHT API and our C/C++ equivalents.

## Creating an Instance

**JavaScript:**
```js
const dht = new HyperDHT({ port: 0, bootstrap: [...] })
await dht.ready()
```

**C++:**
```cpp
hyperdht::HyperDHT dht(&loop, { .port = 0 });
dht.bind();
```

**C:**
```c
hyperdht_t* dht = hyperdht_create(&loop, NULL);
hyperdht_bind(dht, 0);
```

## Connecting to a Peer

**JavaScript:**
```js
const socket = dht.connect(remotePublicKey)
socket.on('open', () => {
    socket.write('hello')
})
```

**C++:**
```cpp
dht.connect(remote_pk, [](int err, const ConnectResult& result) {
    // result.tx_key, result.rx_key for encrypted stream
});
```

**C:**
```c
hyperdht_connect(dht, remote_pk, on_connect, userdata);
```

## Creating a Server

**JavaScript:**
```js
const server = dht.createServer()
server.on('connection', (socket) => {
    socket.on('data', (buf) => console.log(buf))
})
await server.listen(keyPair)
```

**C++:**
```cpp
auto* srv = dht.create_server();
srv->listen(keypair, [](const server::ConnectionInfo& info) {
    // info.remote_public_key, info.tx_key, etc.
});
```

**C:**
```c
hyperdht_server_t* srv = hyperdht_server_create(dht);
hyperdht_server_listen(srv, &kp, on_connection, userdata);
```

## Firewall

**JavaScript:**
```js
const server = dht.createServer({
    firewall(remotePublicKey, remoteHandshakePayload) {
        return false  // false = accept
    }
})
```

**C++:**
```cpp
srv->set_firewall([](const auto& pk, const auto& payload, const auto& addr) {
    return false;  // false = accept, true = reject
});
```

**C:**
```c
int my_firewall(const uint8_t pk[32], const char* host, uint16_t port, void* ud) {
    return 0;  // 0 = accept, non-zero = reject
}
hyperdht_server_set_firewall(srv, my_firewall, userdata);
```

## Immutable Storage

**JavaScript:**
```js
// Put
const { hash } = await dht.immutablePut(Buffer.from('hello'))

// Get
const result = await dht.immutableGet(hash)
console.log(result.value.toString())  // 'hello'
```

**C++:**
```cpp
// Put
dht_ops::immutable_put(socket, value, [](const auto&) { /* done */ });

// Get
dht_ops::immutable_get(socket, hash,
    [](const std::vector<uint8_t>& val) { /* got it */ },
    [](const auto&) { /* done */ });
```

**C:**
```c
// Put
hyperdht_immutable_put(dht, value, len, on_done, userdata);

// Get
hyperdht_immutable_get(dht, hash, on_value, on_done, userdata);
```

## Mutable Storage

**JavaScript:**
```js
// Put
const keyPair = HyperDHT.keyPair()
await dht.mutablePut(keyPair, Buffer.from('hello'), { seq: 1 })

// Get
const result = await dht.mutableGet(keyPair.publicKey)
console.log(result.value.toString(), result.seq)
```

**C++:**
```cpp
// Put
dht_ops::mutable_put(socket, keypair, value, seq, [](const auto&) {});

// Get
dht_ops::mutable_get(socket, public_key, min_seq,
    [](const dht_ops::MutableResult& r) { /* r.value, r.seq */ },
    [](const auto&) {});
```

**C:**
```c
// Put
hyperdht_mutable_put(dht, &kp, value, len, seq, on_done, userdata);

// Get
hyperdht_mutable_get(dht, public_key, min_seq, on_mutable, on_done, userdata);
```

## Keypair Generation

**JavaScript:**
```js
const keyPair = HyperDHT.keyPair()           // random
const keyPair = HyperDHT.keyPair(seed)       // from 32-byte seed
```

**C++:**
```cpp
auto kp = noise::generate_keypair();          // random
auto kp = noise::generate_keypair(seed);      // from seed
```

**C:**
```c
hyperdht_keypair_t kp;
hyperdht_keypair_generate(&kp);              // random
hyperdht_keypair_from_seed(&kp, seed);       // from seed
```

## Cleanup / Destroy

**JavaScript:**
```js
await dht.destroy()
```

**C++:**
```cpp
dht.destroy();
uv_run(&loop, UV_RUN_DEFAULT);  // drain callbacks
```

**C:**
```c
hyperdht_destroy(dht, NULL, NULL);
uv_run(&loop, UV_RUN_DEFAULT);
hyperdht_free(dht);
```

## Key Differences

| Aspect | JavaScript | C/C++ |
|--------|-----------|-------|
| Async model | `async/await` + event emitters | Callbacks + `uv_run()` event loop |
| Memory | Garbage collected | Manual: `create` → `destroy` → `uv_run` → `free` |
| Streams | `socket.write()` / `socket.on('data')` | Raw keys provided; build stream layer on top |
| Error handling | Exceptions + error events | Return codes (0 = success, negative = error) |
| Thread safety | Single-threaded (Node.js) | Single-threaded (libuv) — same model |
| Protomux | Built-in channel multiplexing | Available but separate (`protomux.hpp`) |

## What's NOT in the C/C++ API (yet)

- **Readable/Writable streams**: JS gives you a `socket` object with `.write()` and `.on('data')`. Our API gives you the encryption keys and peer address — you build the UDX stream + SecretStream on top. The building blocks are there (`udx.hpp`, `secret_stream.hpp`), but there's no convenience wrapper yet.
- **`dht.lookup()` as async iterator**: JS uses `for await (const node of query)`. C++ uses callbacks on the `Query` object.
- **`dht.findPeer()` as async iterator**: Same — callbacks instead of iterator.
