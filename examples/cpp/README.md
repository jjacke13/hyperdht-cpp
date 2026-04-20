# C++ Examples

Persistent server and client using the C FFI (`hyperdht.h`).

## Build

```bash
# From the repo root — build the library first
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
ninja
cd ..

# Build examples
cd examples/cpp
g++ -std=c++20 -O2 server.cpp -I../../include -L../../build -lhyperdht -lsodium -luv -o server
g++ -std=c++20 -O2 client.cpp -I../../include -L../../build -lhyperdht -lsodium -luv -o client
```

## Run

```bash
export LD_LIBRARY_PATH=../../build

# Server — runs forever, echoes data
./server                                    # random identity
./server <64-hex-seed>                      # stable identity

# Client — connects and sends "hello from C++"
./client <64-hex-public-key>
```

## Cross-test with JS

```bash
# C++ server + JS client
./server
# (copy the public key)
node ../js/client.js <public-key>

# JS server + C++ client
node ../js/server.js
# (copy the public key)
./client <public-key>
```

## Live servers

These servers are running 24/7 for testing:

| Machine | Public key |
|---------|-----------|
| 1 | b7c5c4e909ad28e2071c48a09f330ec2735248a4e4d8759032a9b57b0f2e7aec |
| 2 |                      TBD                                         |