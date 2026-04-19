# Building hyperdht-cpp

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| CMake | 3.20+ | Build system |
| Ninja | any | Build backend (optional, can use Make) |
| libsodium | 1.0.18+ | All cryptography |
| libuv | 1.44+ | Event loop (required by libudx) |
| libudx | pinned | Reliable UDP (git submodule) |
| C++ compiler | C++20 | GCC 12+ or Clang 15+ |

## Quick start

### Nix (recommended)

```bash
nix develop
mkdir -p build && cd build
cmake .. -G Ninja
ninja
ctest -L unit --output-on-failure
```

### Docker (no local deps needed)

```bash
docker build -t hyperdht .
docker run --rm -it hyperdht bash          # dev shell
docker run --rm hyperdht tar cf - -C /out . | tar xf -  # extract libraries
```

Output in `/out/`:

| File | Size | Use |
|------|------|-----|
| `lib/libhyperdht.a` | ~1.8MB | Static library with symbol table |
| `lib/libhyperdht.so` | ~1.1MB | Shared library with symbol table |
| `lib/libhyperdht-stripped.a` | ~1.5MB | Static, symbols removed (production) |
| `lib/libhyperdht-stripped.so` | ~776KB | Shared, symbols removed (production) |
| `include/hyperdht/` | | Public headers |

All are Release builds (-O2, no debug info). Stripped variants are smallest;
non-stripped keep function names for readable stack traces and profiling.

---

## Linux

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install cmake ninja-build pkg-config g++ git libsodium-dev libuv1-dev
```

### Fedora

```bash
sudo dnf install cmake ninja-build pkgconf gcc-c++ git libsodium-devel libuv-devel
```

### Arch

```bash
sudo pacman -S cmake ninja pkgconf gcc git libsodium libuv
```

### Build

```bash
git clone --recurse-submodules https://github.com/jjacke13/hyperdht-cpp.git
cd hyperdht-cpp

# Static library
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
ninja
sudo ninja install   # installs to /usr/local
cd ..

# Shared library
mkdir -p build-shared && cd build-shared
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -G Ninja
ninja
sudo cp libhyperdht.so /usr/local/lib/
sudo ldconfig
cd ..
```

### Run tests

```bash
mkdir -p build-test && cd build-test
cmake .. -DCMAKE_BUILD_TYPE=Debug -DHYPERDHT_BUILD_TESTS=ON -G Ninja
ninja
ctest -L unit --output-on-failure -j$(nproc)
```

---

## macOS

### Install dependencies

```bash
brew install cmake ninja libsodium libuv pkg-config
```

### Build

```bash
git clone --recurse-submodules https://github.com/jjacke13/hyperdht-cpp.git
cd hyperdht-cpp

mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
ninja
cd ..

# Shared library
mkdir -p build-shared && cd build-shared
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -G Ninja
ninja
cd ..
```

On macOS the shared library is `libhyperdht.dylib` instead of `.so`.

### Run tests

```bash
mkdir -p build-test && cd build-test
cmake .. -DCMAKE_BUILD_TYPE=Debug -DHYPERDHT_BUILD_TESTS=ON -G Ninja
ninja
ctest -L unit --output-on-failure -j$(sysctl -n hw.ncpu)
```

---

## Using the library

### Link against static library

```bash
g++ -std=c++20 my_app.cpp -I/usr/local/include -lhyperdht -lsodium -luv -o my_app
```

### Link against shared library

```bash
g++ -std=c++20 my_app.cpp -I/usr/local/include -lhyperdht -lsodium -luv -o my_app
export LD_LIBRARY_PATH=/usr/local/lib  # if not in system path
```

### Use from CMake

```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(HYPERDHT REQUIRED hyperdht)

add_executable(my_app main.cpp)
target_link_libraries(my_app ${HYPERDHT_LIBRARIES})
target_include_directories(my_app PRIVATE ${HYPERDHT_INCLUDE_DIRS})
```

### Use from Python

```bash
export HYPERDHT_LIB=/usr/local/lib/libhyperdht.so  # or .dylib on macOS
cd examples/python
python3 -c "from hyperdht import HyperDHT, KeyPair; print(KeyPair.generate())"
```

---

## Build options

| CMake flag | Default | Description |
|------------|---------|-------------|
| `CMAKE_BUILD_TYPE` | | `Release` for production, `Debug` for development |
| `BUILD_SHARED_LIBS` | `OFF` | Build shared library instead of static |
| `HYPERDHT_BUILD_TESTS` | `OFF` | Build test executables |
| `HYPERDHT_DEBUG` | `OFF` | Enable debug logging macros |

---

## Troubleshooting

**`libudx` not found**: Make sure you cloned with `--recurse-submodules`, or run:
```bash
git submodule update --init deps/libudx
```

**`libsodium` not found**: Install the `-dev` / `-devel` package, not just the runtime.

**macOS linker errors**: Make sure Homebrew's pkg-config can find libsodium:
```bash
export PKG_CONFIG_PATH="$(brew --prefix libsodium)/lib/pkgconfig:$PKG_CONFIG_PATH"
```
