#!/usr/bin/env bash
# Build libhyperdht.so from the repository root.
# Run from examples/python/ — the script finds the repo root automatically.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/build-shared"

echo "=== Building libhyperdht.so ==="
echo "  Repo:  $REPO_ROOT"
echo "  Build: $BUILD_DIR"
echo ""

# Check dependencies
for cmd in cmake ninja pkg-config; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found. Install it first:"
        echo ""
        echo "  Debian/Ubuntu: sudo apt install cmake ninja-build pkg-config libsodium-dev libuv1-dev"
        echo "  Fedora:        sudo dnf install cmake ninja-build pkgconf libsodium-devel libuv-devel"
        echo "  Arch:          sudo pacman -S cmake ninja pkgconf libsodium libuv"
        echo ""
        exit 1
    fi
done

# Check libraries
missing=""
pkg-config --exists libsodium 2>/dev/null || missing="$missing libsodium"
pkg-config --exists libuv 2>/dev/null || missing="$missing libuv"
if [ -n "$missing" ]; then
    echo "ERROR: Missing libraries:$missing"
    echo ""
    echo "  Debian/Ubuntu: sudo apt install libsodium-dev libuv1-dev"
    echo "  Fedora:        sudo dnf install libsodium-devel libuv-devel"
    echo "  Arch:          sudo pacman -S libsodium libuv"
    echo ""
    exit 1
fi

# Init libudx submodule if needed
if [ ! -f "$REPO_ROOT/deps/libudx/CMakeLists.txt" ]; then
    echo "  Fetching libudx submodule..."
    git -C "$REPO_ROOT" submodule update --init deps/libudx
fi

# Build
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake "$REPO_ROOT" \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DHYPERDHT_BUILD_TESTS=OFF \
    -G Ninja
ninja

SO_PATH="$BUILD_DIR/libhyperdht.so"
if [ ! -f "$SO_PATH" ]; then
    echo "ERROR: Build succeeded but libhyperdht.so not found at $SO_PATH"
    exit 1
fi

echo ""
echo "=== Build complete ==="
echo "  Library: $SO_PATH"
echo ""
echo "  Run the examples:"
echo "    export HYPERDHT_LIB=$SO_PATH"
echo "    cd $SCRIPT_DIR"
echo "    python3 example.py keygen"
echo "    python3 example.py server"
echo "    python3 holesail_server.py --live 8080"
echo ""
