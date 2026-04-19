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
    cmake ninja-build pkg-config g++ git ca-certificates \
    libsodium-dev libuv1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN if [ ! -f deps/libudx/CMakeLists.txt ]; then \
      git submodule update --init deps/libudx; \
    fi

# Static library
RUN cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DHYPERDHT_BUILD_TESTS=OFF \
    && ninja -C build

# Shared library
RUN cmake -B build-shared -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DHYPERDHT_BUILD_TESTS=OFF \
    && ninja -C build-shared

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
    && ninja -C build-test

# Clean output directory with everything in one place
RUN mkdir -p /out/lib /out/include \
    && cp /usr/local/lib/libhyperdht.a /out/lib/ \
    && cp /usr/local/lib/libhyperdht.so /out/lib/ \
    && cp /usr/local/lib/libhyperdht-stripped.a /out/lib/ \
    && cp /usr/local/lib/libhyperdht-stripped.so /out/lib/ \
    && cp -r /usr/local/include/hyperdht /out/include/
