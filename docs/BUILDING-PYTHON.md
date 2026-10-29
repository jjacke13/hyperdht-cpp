# Building the Python wrapper

ctypes-based bindings for `libhyperdht.so`. Pure Python — no extension
module to compile, but the C library (`libhyperdht.so` + `libuv.so.1`)
must be reachable at runtime.

## 1. Dependencies

Install Python 3 and follow the
[non-Nix dependency build instructions](BUILDING.md#linux-and-macos-without-nix)
to build libuv **1.51.0** and libsodium **1.0.22** from the pinned submodules.
Keep `PKG_CONFIG_PATH` and the runtime library variables from that guide in
the same shell. Distro development packages may provide different versions.

## 2. Build `libhyperdht.so`

Linux shortcut:

```bash
cd examples/python
./build.sh
```

This produces `build-shared/libhyperdht.so` at the repo root. On macOS,
use the manual CMake command below; the output is `libhyperdht.dylib`.

Equivalent manual invocation:

```bash
cmake -B build-shared -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DHYPERDHT_BUILD_TESTS=OFF
ninja -C build-shared
```

## 3. Install the Python wrapper

```bash
pip install wrappers/python/
```

Or, for development (editable install):

```bash
pip install -e wrappers/python/
```

The package is `hyperdht`. Verify:

```bash
python3 -c "from hyperdht import HyperDHT, KeyPair; print(KeyPair.generate())"
```

## 4. Library discovery at runtime

`hyperdht/_ffi.py` searches for the `.so` in this order:

1. `HYPERDHT_LIB` env var (explicit path to `libhyperdht.so`)
2. `LD_LIBRARY_PATH`
3. System paths (`/usr/lib`, `/usr/local/lib`) via `ldconfig`
4. Package-relative `../../build-shared/` (for in-tree development)

Pick whichever matches your setup:

```bash
# Development: point at build dir
export HYPERDHT_LIB=$PWD/build-shared/libhyperdht.so

# Or: LD_LIBRARY_PATH
export LD_LIBRARY_PATH=$PWD/build-shared:$LD_LIBRARY_PATH

# Or: system install
sudo cp build-shared/libhyperdht.so /usr/local/lib/
sudo ldconfig
```

## 5. Run examples

Offline (no network):

```bash
python3 examples/python/keypair_demo.py
python3 examples/python/hash_demo.py "hello"
python3 examples/python/state_demo.py
```

Network (joins public DHT):

```bash
python3 examples/python/ping_demo.py
python3 examples/python/storage_demo.py put "hello"
python3 examples/python/storage_demo.py get <hash>
```

Server / client demo:

```bash
# Terminal 1
python3 examples/python/example.py server

# Terminal 2 (uses pubkey printed by server)
python3 examples/python/example.py client <pubkey>
```

## CI

No dedicated Python CI job. The wrapper is plain Python — `pip install`
of the package only ships `.py` files. The C library it depends on is
built by the `build-linux-x86_64` + `build-linux-aarch64` jobs in
`.github/workflows/build.yml`.
