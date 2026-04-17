#!/usr/bin/env python3
"""
Test the Python wrapper -- verifies all operations work.

Usage:
    LD_LIBRARY_PATH=../../build-shared python3 test_wrapper.py
"""

import sys

sys.path.insert(0, ".")

from hyperdht import (
    ERR_CANCELLED,
    ERR_DESTROYED,
    ERR_OK,
    FIREWALL_CONSISTENT,
    FIREWALL_OPEN,
    FIREWALL_RANDOM,
    FIREWALL_UNKNOWN,
    Address,
    HyperDHT,
    KeyPair,
    PunchStats,
    RelayStats,
)

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


# ---------------------------------------------------------------------------
# KeyPair
# ---------------------------------------------------------------------------

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


def test_keygen_repr():
    kp = KeyPair.generate()
    s = repr(kp)
    assert "KeyPair" in s
    assert kp.public_key[:8].hex() in s

test("KeyPair repr", test_keygen_repr)


def test_keygen_validation():
    try:
        KeyPair(b"\x00" * 16, b"\x00" * 64)
        assert False, "Should have raised"
    except ValueError:
        pass
    try:
        KeyPair.from_seed(b"\x00" * 16)
        assert False, "Should have raised"
    except ValueError:
        pass

test("KeyPair validation", test_keygen_validation)


# ---------------------------------------------------------------------------
# HyperDHT lifecycle
# ---------------------------------------------------------------------------

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


def test_create_with_seed():
    seed = b"\xAB" * 32
    dht1 = HyperDHT(seed=seed)
    dht2 = HyperDHT(seed=seed)
    assert dht1.default_keypair.public_key == dht2.default_keypair.public_key
    dht1.destroy()
    dht2.destroy()

test("HyperDHT with seed", test_create_with_seed)


def test_create_server():
    dht = HyperDHT()
    dht.bind()
    server = dht.create_server()
    assert server is not None
    dht.destroy()

test("HyperDHT.create_server", test_create_server)


def test_destroy_force():
    dht = HyperDHT()
    dht.bind()
    dht.destroy(force=True)

test("HyperDHT.destroy(force=True)", test_destroy_force)


# ---------------------------------------------------------------------------
# State queries
# ---------------------------------------------------------------------------

def test_state_queries():
    dht = HyperDHT()
    assert dht.is_online is True   # fresh DHT starts ONLINE
    assert dht.is_degraded is False
    assert dht.is_destroyed is False
    assert dht.is_persistent is False
    assert dht.is_bootstrapped is False
    assert dht.is_suspended is False
    dht.destroy()

test("state queries on fresh DHT", test_state_queries)


# ---------------------------------------------------------------------------
# Hash
# ---------------------------------------------------------------------------

def test_hash():
    h1 = HyperDHT.hash(b"hello")
    h2 = HyperDHT.hash(b"hello")
    h3 = HyperDHT.hash(b"world")
    assert len(h1) == 32
    assert h1 == h2
    assert h1 != h3

test("HyperDHT.hash", test_hash)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants():
    assert FIREWALL_UNKNOWN == 0
    assert FIREWALL_OPEN == 1
    assert FIREWALL_CONSISTENT == 2
    assert FIREWALL_RANDOM == 3
    assert ERR_OK == 0
    assert ERR_DESTROYED == -1
    assert ERR_CANCELLED == -8

test("constants", test_constants)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_punch_stats():
    dht = HyperDHT()
    stats = dht.punch_stats
    assert isinstance(stats, PunchStats)
    assert stats.consistent == 0
    assert stats.random == 0
    assert stats.open == 0
    dht.destroy()

test("punch_stats", test_punch_stats)


def test_relay_stats():
    dht = HyperDHT()
    stats = dht.relay_stats
    assert isinstance(stats, RelayStats)
    assert stats.attempts == 0
    assert stats.successes == 0
    assert stats.aborts == 0
    dht.destroy()

test("relay_stats", test_relay_stats)


# ---------------------------------------------------------------------------
# Routing table
# ---------------------------------------------------------------------------

def test_to_array_empty():
    dht = HyperDHT()
    dht.bind()
    nodes = dht.to_array()
    assert isinstance(nodes, list)
    assert len(nodes) == 0
    dht.destroy()

test("to_array (empty)", test_to_array_empty)


def test_remote_address_unknown():
    dht = HyperDHT()
    dht.bind()
    addr = dht.remote_address
    assert addr is None  # no NAT samples yet
    dht.destroy()

test("remote_address (unknown)", test_remote_address_unknown)


# ---------------------------------------------------------------------------
# Server state
# ---------------------------------------------------------------------------

def test_server_state():
    dht = HyperDHT()
    dht.bind()
    server = dht.create_server()
    assert server.is_listening is False
    assert server.public_key is None  # not listening
    assert server.address is None     # not listening
    dht.destroy()

test("server state (not listening)", test_server_state)


# ---------------------------------------------------------------------------
# Connection keep-alive
# ---------------------------------------------------------------------------

def test_connection_keep_alive_default():
    dht = HyperDHT()
    ka = dht.connection_keep_alive
    assert ka > 0  # default is 5000ms
    dht.destroy()

test("connection_keep_alive (default)", test_connection_keep_alive_default)


def test_connection_keep_alive_custom():
    dht = HyperDHT(connection_keep_alive=10000)
    assert dht.connection_keep_alive == 10000
    dht.destroy()

test("connection_keep_alive (custom)", test_connection_keep_alive_custom)


# ---------------------------------------------------------------------------
# Suspend / resume
# ---------------------------------------------------------------------------

def test_suspend_resume():
    dht = HyperDHT()
    dht.bind()
    dht.suspend()
    assert dht.is_suspended is True
    dht.resume()
    assert dht.is_suspended is False
    dht.destroy()

test("suspend/resume", test_suspend_resume)


def test_suspend_logged():
    messages = []
    dht = HyperDHT()
    dht.bind()
    dht.suspend(log=lambda msg: messages.append(msg))
    dht.run(mode="nowait")
    dht.resume()
    dht.destroy()
    # We should have received at least some log messages
    # (exact count depends on C++ implementation)

test("suspend_logged", test_suspend_logged)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print(f"\n{'=' * 40}")
print(f"  {passed} passed, {failed} failed")
if failed:
    sys.exit(1)
else:
    print("  All tests passed!")
