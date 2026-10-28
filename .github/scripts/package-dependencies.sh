#!/usr/bin/env bash
set -euo pipefail

cp -r "$LIBUV_PREFIX/include/." "$SODIUM_PREFIX/include/." dist/include/
cp "$LIBUV_PREFIX/lib/libuv.a" "$SODIUM_PREFIX/lib/libsodium.a" dist/lib/
mkdir -p dist/licenses/libuv dist/licenses/libsodium
cp deps/libuv/LICENSE deps/libuv/LICENSE-extra dist/licenses/libuv/
cp deps/libsodium/LICENSE .github/licenses/libsodium-source-notices.txt dist/licenses/libsodium/

if [[ "$RUNNER_OS" == macOS ]]; then
  cp -P "$LIBUV_PREFIX"/lib/libuv*.dylib "$SODIUM_PREFIX"/lib/libsodium*.dylib dist/lib/
  otool -L dist/lib/libhyperdht.dylib > "$RUNNER_TEMP/hyperdht-links.txt"
  grep -F '@rpath/libuv' "$RUNNER_TEMP/hyperdht-links.txt"
  grep -F '@rpath/libsodium' "$RUNNER_TEMP/hyperdht-links.txt"
else
  cp -P "$LIBUV_PREFIX"/lib/libuv.so* "$SODIUM_PREFIX"/lib/libsodium.so* dist/lib/
  readelf -d dist/lib/libhyperdht.so > "$RUNNER_TEMP/hyperdht-links.txt"
  grep -F '$ORIGIN' "$RUNNER_TEMP/hyperdht-links.txt"
fi
if grep -E '/nix/store|/hyperdht-libuv|/hyperdht-sodium' "$RUNNER_TEMP/hyperdht-links.txt"; then
  echo 'release library contains a build-only dependency path' >&2
  exit 1
fi

# Load the relocated package and check its actual runtime dependencies.
cat > "$RUNNER_TEMP/package-smoke.c" <<'EOF'
#include <string.h>
#include <uv.h>
#include <sodium.h>
#include <hyperdht/hyperdht.h>
int main(void) {
    hyperdht_opts_t opts;
    hyperdht_opts_default(&opts);
    return strcmp(uv_version_string(), "1.51.0") ||
           strcmp(sodium_version_string(), "1.0.22");
}
EOF
cc "$RUNNER_TEMP/package-smoke.c" -I dist/include -L dist/lib \
  -lhyperdht -luv -lsodium -o "$RUNNER_TEMP/package-smoke"
LD_LIBRARY_PATH="$PWD/dist/lib" DYLD_LIBRARY_PATH="$PWD/dist/lib" \
  "$RUNNER_TEMP/package-smoke"
