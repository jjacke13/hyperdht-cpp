# JavaScript Examples

Persistent server and client using the JS HyperDHT package. Use these to cross-test against the C++ examples.

## Setup

```bash
cd examples/js
npm install
```

## Run

```bash
# Server — runs forever, echoes data
node server.js                              # random identity
node server.js <64-hex-seed>                # stable identity

# Client — connects and sends "hello from JS"
node client.js <64-hex-public-key>
```

## Cross-test with C++

```bash
# JS server + C++ client
node server.js
# (copy the public key)
../cpp/client <public-key>

# C++ server + JS client
../cpp/server
# (copy the public key)
node client.js <public-key>
```
