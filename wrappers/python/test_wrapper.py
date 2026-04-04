#!/usr/bin/env python3
"""
Test the Python wrapper — verifies all basic operations work.

Usage:
    LD_LIBRARY_PATH=../../build-shared python3 test_wrapper.py
"""

import sys
sys.path.insert(0, ".")

from hyperdht import HyperDHT, KeyPair

passed = 0
failed = 0


def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS  {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        failed += 1


# --- KeyPair tests ---

def test_keygen():
    kp = KeyPair.generate()
    assert len(kp.public_key) == 32
    assert len(kp.secret_key) == 64
    assert kp.public_key != b"\x00" * 32

test("KeyPair.generate", test_keygen)


def test_keygen_seed():
    seed = b"\x42" * 32
    kp1 = KeyPair.from_seed(seed)
    kp2 = KeyPair.from_seed(seed)
    assert kp1.public_key == kp2.public_key
    assert kp1.secret_key == kp2.secret_key

test("KeyPair.from_seed (deterministic)", test_keygen_seed)


def test_keygen_different():
    kp1 = KeyPair.generate()
    kp2 = KeyPair.generate()
    assert kp1.public_key != kp2.public_key

test("KeyPair.generate (different each time)", test_keygen_different)


# --- HyperDHT lifecycle tests ---

def test_create_destroy():
    dht = HyperDHT()
    dht.bind()
    assert dht.port > 0
    dht.destroy()

test("HyperDHT create/bind/destroy", test_create_destroy)


def test_default_keypair():
    dht = HyperDHT()
    kp = dht.default_keypair
    assert len(kp.public_key) == 32
    assert kp.public_key != b"\x00" * 32
    dht.destroy()

test("HyperDHT.default_keypair", test_default_keypair)


def test_create_server():
    dht = HyperDHT()
    dht.bind()
    server = dht.create_server()
    assert server is not None
    dht.destroy()

test("HyperDHT.create_server", test_create_server)


def test_repr():
    kp = KeyPair.generate()
    s = repr(kp)
    assert "KeyPair" in s
    assert kp.public_key[:8].hex() in s

test("KeyPair repr", test_repr)


# --- Summary ---

print(f"\n{'=' * 40}")
print(f"  {passed} passed, {failed} failed")
if failed:
    sys.exit(1)
else:
    print("  All tests passed!")
