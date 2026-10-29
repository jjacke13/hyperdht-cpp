# Building hyperdht-cpp

This page covers the **core C++ library**. For language wrappers
and embedded targets:

| Target | Doc |
|--------|-----|
| Python (ctypes) | [BUILDING-PYTHON.md](BUILDING-PYTHON.md) |
| Android (Kotlin + JNI) | [BUILDING-ANDROID.md](BUILDING-ANDROID.md) |
| Rust (`hyperdht-sys` + `hyperdht`) | [BUILDING-RUST.md](BUILDING-RUST.md) |
| ESP32-S3 (ESP-IDF component) | [BUILDING-ESP32.md](BUILDING-ESP32.md) |

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| CMake | 3.20+ | Build system |
| Ninja | any | Build backend (optional, can use Make) |
| libsodium | **1.0.22** (pinned source) | All cryptography |
| libuv | **1.51.0** (pinned source) | Event loop (required by libudx) — see note below |
| libudx | pinned | Reliable UDP (git submodule) |
| C++ compiler | C++20 | GCC 12+ or Clang 15+ |

> **libuv version:** build against **libuv 1.51.x**, not 1.52.0/1.52.1. libuv
> 1.52.0 introduced a UDP `POLLERR` regression that silently wedges libudx
> streams on real NAT paths (established connections stall with no self-heal).
> Both the Nix flake and native CI use the pinned sources. Ordinary CMake
> builds still use the dependencies you supply; cloning submodules does not
> automatically select them. Follow the source-build steps below instead of
> relying on whichever versions your package manager currently provides.
> Details: [LIBUV-VERSION.md](LIBUV-VERSION.md).

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
git submodule update --init --recursive
docker build -t hyperdht .
docker run --rm -it hyperdht bash          # dev shell
docker run --rm hyperdht tar cf - -C /out . | tar xf -  # extract libraries
```

Run these commands from the repository root after cloning it. The Dockerfile
builds the checked-out libuv and libsodium sources, verifies their versions,
and runs the libsodium self-tests. It also builds the HyperDHT test executable;
run the unit suite explicitly:

```bash
docker run --rm hyperdht ctest -L unit --test-dir /src/build-test \
  --output-on-failure -j2 --timeout 30 \
  -E "LiveBootstrap|LiveConnect|FindPeerRandomKey|Cross|CrossTest|TableRetryAfterExternalSeedFlood"
```

Output in `/out/`:

| File | Use |
|------|-----|
| `lib/libhyperdht.a` | Static library with symbol table |
| `lib/libhyperdht.so` | Shared library with symbol table |
| `lib/libhyperdht-stripped.a` | Static, symbols removed (production) |
| `lib/libhyperdht-stripped.so` | Shared, symbols removed (production) |
| `include/hyperdht/` | Public headers |

Matching libuv/libsodium shared runtimes, static libraries, headers, notices,
and `libudx.a` are included too. Keep the shared libraries together in `lib/`.

All are Release builds without debug info. Stripped variants are smallest;
non-stripped keep function names for readable stack traces and profiling.

---

## Linux and macOS (without Nix)

### Install build tools

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install cmake ninja-build pkg-config g++ make git

# Fedora
sudo dnf install cmake ninja-build pkgconf gcc-c++ make git

# Arch
sudo pacman -S cmake ninja pkgconf gcc make git

# macOS (Xcode Command Line Tools must also be installed)
brew install cmake ninja pkg-config
```

Use the command for your OS. libuv and libsodium will be built from the
submodules, rather than installed with the package manager.

### Build the pinned dependencies

```bash
git clone --recurse-submodules https://github.com/jjacke13/hyperdht-cpp.git
cd hyperdht-cpp
# For an existing checkout:
git submodule update --init --recursive

export HYPERDHT_SOURCE="$PWD"
export DEPS_PREFIX="$PWD/build-deps/install"

# libuv 1.51.0: static and shared libraries, with PIC for shared consumers.
cmake -S deps/libuv -B build-deps/libuv -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DLIBUV_BUILD_TESTS=OFF -DLIBUV_BUILD_BENCH=OFF \
  -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_PREFIX="$DEPS_PREFIX"
cmake --build build-deps/libuv --target install --parallel 2

# libsodium 1.0.22: the pinned source already contains configure.
mkdir -p build-deps/sodium
cd build-deps/sodium
"$HYPERDHT_SOURCE/deps/libsodium/configure" --prefix="$DEPS_PREFIX"
make
make check
make install
cd "$HYPERDHT_SOURCE"

# Keep these variables in the shell used to build and run the library.
export PKG_CONFIG_PATH="$DEPS_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LIBRARY_PATH="$DEPS_PREFIX/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$DEPS_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export DYLD_LIBRARY_PATH="$DEPS_PREFIX/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
test "$(pkg-config --modversion libuv)" = 1.51.0
test "$(pkg-config --modversion libsodium)" = 1.0.22
```

The exact source commits are `5152db2cbfeb5582e9c27c5ea1dba2cd9e10759b`
(libuv) and `77e1ce5d6dee871c49ef211222ba18ef0c486bda` (libsodium).
`git submodule status` shows the checked-out commits. Do not use
`git submodule update --remote`, which would move away from the recorded pins.

### Build the library

From the repository root, in the same shell:

```bash
# Static library (libhyperdht.a and libudx.a)
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DHYPERDHT_BUILD_TESTS=OFF
cmake --build build --parallel 2

# Shared library (.so on Linux, .dylib on macOS)
cmake -S . -B build-shared -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON -DHYPERDHT_BUILD_TESTS=OFF
cmake --build build-shared --parallel 2
```

Use fresh build directories if they previously found different dependencies;
CMake caches their paths. The shared build keeps references to the local
installed dependencies. For relocatable distribution, follow the native
[CI build and packaging steps](../.github/workflows/build.yml), including
platform-specific runtime paths, the packaging smoke test and license notices.

Optional system installation of the static library and headers:

```bash
sudo cmake --install build --prefix /usr/local
```

This does not install libuv or libsodium into the system. Keep the dependency
prefix and environment above, or package the matching dependencies with your app.

### Run tests

```bash
cmake -S . -B build-test -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DHYPERDHT_BUILD_TESTS=ON
cmake --build build-test --parallel 2
ctest -L unit --test-dir build-test --output-on-failure -j2 --timeout 30 \
  -E "LiveBootstrap|LiveConnect|FindPeerRandomKey|Cross|CrossTest|TableRetryAfterExternalSeedFlood"
```

The exclusions match native CI. Live/public-network tests require their own
setup and are not part of this command.

## Windows (MSVC)

Use Visual Studio's x64 developer environment, CMake, Ninja, Git and vcpkg.
The complete tested recipe is in the [Windows workflow](../.github/workflows/windows.yml):

1. Initialize all submodules with `git submodule update --init --recursive`.
2. Use `.github/vcpkg/vcpkg.json` for libsodium **1.0.22**, rather than an
   unversioned `vcpkg install libsodium`. Fetch its `builtin-baseline` commit
   into the vcpkg checkout first. Use that same checkout for installation and
   `CMAKE_TOOLCHAIN_FILE`.
3. Build `deps/libuv` using the CMake options in the
   [setup-libuv action](../.github/actions/setup-libuv/action.yml).
4. Apply the two libudx MSVC compatibility substitutions shown in the workflow.
5. Configure with `VCPKG_TARGET_TRIPLET=x64-windows-static-md`, the manifest's
   `VCPKG_INSTALLED_DIR`, and `libuv_DIR=<libuv-prefix>/lib/cmake/libuv`.
   Build static and shared variants as shown there.

This uses the submodule for libuv and the locked vcpkg package for libsodium.
The Windows CI artifact already contains both dependency archives, headers
and notices if you do not need to compile from source.

---

## Using the library

### Link against static library

With the source-build environment above (core static, dependencies selected
from the matching prefix):

```bash
g++ -std=c++20 my_app.cpp -I"$HYPERDHT_SOURCE/include" \
  -I"$HYPERDHT_SOURCE/deps/libudx/include" -I"$DEPS_PREFIX/include" \
  -L"$HYPERDHT_SOURCE/build" -L"$DEPS_PREFIX/lib" \
  -lhyperdht -ludx -lsodium -luv -o my_app
```

### Link against shared library

The default Release shared build exports the C API. C++ API consumers also
need `-DHYPERDHT_EXPORT_CXX=ON` when configuring the shared library.

```bash
g++ -std=c++20 my_app.cpp -I"$HYPERDHT_SOURCE/include" \
  -I"$DEPS_PREFIX/include" -L"$HYPERDHT_SOURCE/build-shared" \
  -L"$DEPS_PREFIX/lib" -lhyperdht -lsodium -luv -o my_app
# Linux:
export LD_LIBRARY_PATH="$HYPERDHT_SOURCE/build-shared:$LD_LIBRARY_PATH"
# macOS:
export DYLD_LIBRARY_PATH="$HYPERDHT_SOURCE/build-shared:$DYLD_LIBRARY_PATH"
```

### Use from CMake

```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(HYPERDHT REQUIRED IMPORTED_TARGET hyperdht)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE PkgConfig::HYPERDHT)
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
| `HYPERDHT_BUILD_TESTS` | `ON` | Build test executables |
| `HYPERDHT_DEBUG` | `OFF` | Enable debug logging macros |

---

## Troubleshooting

**Missing dependency sources**: Make sure you cloned with `--recurse-submodules`, or run:
```bash
git submodule update --init --recursive
```

**`libsodium` or `libuv` not found / wrong version**: Build the pinned
sources above and export `PKG_CONFIG_PATH` in the same shell before configuring.
Verify both `pkg-config --modversion` results and use a fresh CMake build directory.

**Runtime library not found**: Keep `LD_LIBRARY_PATH` (Linux) or
`DYLD_LIBRARY_PATH` (macOS) pointing to the dependency prefix. A packaged build
must include the matching runtime libraries, not just `libhyperdht`.
