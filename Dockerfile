# Build environment for hyperdht-cpp.
#
# Compile:
#   docker build -t hyperdht .
#
# Extract libraries:
#   docker run --rm hyperdht tar cf - -C /out . | tar xf -
#
# Dev shell:
#   docker run --rm -it hyperdht bash
#
# Run tests:
#   docker run --rm hyperdht ctest -L unit --test-dir /src/build-test --output-on-failure
#
# Output directory (/out/):
#   lib/libhyperdht.a               static, Release, with symbol table
#   lib/libhyperdht.so              shared, Release, with symbol table
#   lib/libhyperdht-stripped.a      static, Release, symbols removed
#   lib/libhyperdht-stripped.so     shared, Release, symbols removed
#   include/hyperdht/              public headers
#
# All four libraries are Release builds (-O2, no debug info, no assertions).
# The non-stripped variants keep the symbol table for readable stack traces
# and profiling. The stripped variants are the smallest possible binaries.
# Both are production-ready — use stripped for distribution, non-stripped
# for development/debugging.

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build pkg-config g++ make git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# .git is excluded from the context; initialize submodules before docker build.
RUN test -f deps/libudx/CMakeLists.txt \
    && test -f deps/libuv/CMakeLists.txt \
    && test -f deps/libsodium/configure

ENV CMAKE_BUILD_PARALLEL_LEVEL=2 \
    PKG_CONFIG_PATH=/opt/hyperdht-deps/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/hyperdht-deps/lib

RUN cmake -S deps/libuv -B /tmp/libuv-build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DLIBUV_BUILD_TESTS=OFF -DLIBUV_BUILD_BENCH=OFF \
    -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_PREFIX=/opt/hyperdht-deps \
    && cmake --build /tmp/libuv-build --target install

RUN mkdir -p /tmp/sodium-build && cd /tmp/sodium-build \
    && /src/deps/libsodium/configure --prefix=/opt/hyperdht-deps \
    && make && make check && make install \
    && test "$(pkg-config --modversion libuv)" = 1.51.0 \
    && test "$(pkg-config --modversion libsodium)" = 1.0.22

# Static library
RUN cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DHYPERDHT_BUILD_TESTS=OFF \
    && cmake --build build

# Shared library
RUN cmake -B build-shared -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DHYPERDHT_BUILD_TESTS=OFF \
    -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INSTALL_RPATH='$ORIGIN' \
    && cmake --build build-shared

# Install to /usr/local
RUN cmake --install build --prefix /usr/local \
    && cp build-shared/libhyperdht.so /usr/local/lib/ \
    && strip --strip-unneeded -o /usr/local/lib/libhyperdht-stripped.so /usr/local/lib/libhyperdht.so \
    && strip --strip-unneeded -o /usr/local/lib/libhyperdht-stripped.a /usr/local/lib/libhyperdht.a \
    && ldconfig

# Tests (built but not run — user can run with the command above)
RUN cmake -B build-test -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DHYPERDHT_BUILD_TESTS=ON \
    && cmake --build build-test

# Clean output directory with everything in one place
RUN mkdir -p dist/lib dist/include \
    && cp /usr/local/lib/libhyperdht*.a /usr/local/lib/libhyperdht*.so \
          /usr/local/lib/libudx.a dist/lib/ \
    && cp -r /usr/local/include/. dist/include/ \
    && RUNNER_OS=Linux RUNNER_TEMP=/tmp \
       LIBUV_PREFIX=/opt/hyperdht-deps SODIUM_PREFIX=/opt/hyperdht-deps \
       bash .github/scripts/package-dependencies.sh \
    && mkdir -p /out && cp -a dist/. /out/
