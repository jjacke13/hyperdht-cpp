#!/usr/bin/env python3
"""
Quick FFI test — proves the C API works from Python via ctypes.
Usage: python3 test/test_ffi.py build-shared/libhyperdht.so
"""

import ctypes
import sys
import os

if len(sys.argv) < 2:
    print("Usage: python3 test_ffi.py <path-to-libhyperdht.so>")
    sys.exit(1)

lib_path = sys.argv[1]
print(f"Loading {lib_path}...")
lib = ctypes.CDLL(lib_path)

# --- Keypair ---

class Keypair(ctypes.Structure):
    _fields_ = [
        ("public_key", ctypes.c_uint8 * 32),
        ("secret_key", ctypes.c_uint8 * 64),
    ]

print("\n1. Keypair generation")
kp = Keypair()
lib.hyperdht_keypair_generate(ctypes.byref(kp))
pk_hex = bytes(kp.public_key).hex()
print(f"   Public key: {pk_hex[:32]}...")
assert pk_hex != "00" * 32, "Public key should not be all zeros"
print("   PASS")

print("\n2. Keypair from seed (deterministic)")
seed = (ctypes.c_uint8 * 32)(*([0x42] * 32))
kp1 = Keypair()
kp2 = Keypair()
lib.hyperdht_keypair_from_seed(ctypes.byref(kp1), seed)
lib.hyperdht_keypair_from_seed(ctypes.byref(kp2), seed)
assert bytes(kp1.public_key) == bytes(kp2.public_key), "Same seed should give same key"
print(f"   Public key: {bytes(kp1.public_key).hex()[:32]}...")
print("   PASS")

# --- Lifecycle ---

print("\n3. Create + bind + destroy")

# We need libuv for the event loop
# Try to find it
for uv_path in [
    "libuv.so.1", "libuv.so",
    # Nix store paths
    *[f"{p}/lib/libuv.so.1" for p in os.environ.get("LD_LIBRARY_PATH", "").split(":") if p],
]:
    try:
        libuv = ctypes.CDLL(uv_path)
        break
    except OSError:
        continue
else:
    print("   SKIP — libuv not found (need uv_loop for lifecycle tests)")
    print("\nAll available tests passed!")
    sys.exit(0)

# uv_loop_t is ~1KB on Linux
UV_LOOP_SIZE = 1024  # generous
loop_buf = (ctypes.c_uint8 * UV_LOOP_SIZE)()
loop_ptr = ctypes.cast(loop_buf, ctypes.c_void_p)

libuv.uv_loop_init(loop_ptr)

# Set function signatures
lib.hyperdht_create.restype = ctypes.c_void_p
lib.hyperdht_create.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
lib.hyperdht_bind.restype = ctypes.c_int
lib.hyperdht_bind.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
lib.hyperdht_port.restype = ctypes.c_uint16
lib.hyperdht_port.argtypes = [ctypes.c_void_p]
lib.hyperdht_is_destroyed.restype = ctypes.c_int
lib.hyperdht_is_destroyed.argtypes = [ctypes.c_void_p]
lib.hyperdht_destroy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

dht = lib.hyperdht_create(loop_ptr, None)
assert dht is not None and dht != 0, "Create should return non-NULL"
print(f"   Created: handle={dht:#x}")

rc = lib.hyperdht_bind(dht, 0)
assert rc == 0, f"Bind failed: {rc}"
port = lib.hyperdht_port(dht)
assert port > 0, "Port should be non-zero after bind"
print(f"   Bound to port {port}")

assert lib.hyperdht_is_destroyed(dht) == 0
lib.hyperdht_destroy(dht, None, None)

libuv.uv_run(loop_ptr, 0)  # UV_RUN_DEFAULT = 0
libuv.uv_loop_close(loop_ptr)
print("   Destroyed cleanly")
print("   PASS")

print("\n=== All Python FFI tests passed! ===")
