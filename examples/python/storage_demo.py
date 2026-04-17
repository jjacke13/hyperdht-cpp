#!/usr/bin/env python3
"""
DHT storage — immutable and mutable key-value records.

Requires a live DHT connection (use_public_bootstrap=True).

Usage:
    python storage_demo.py put <text>
    python storage_demo.py get <hash_hex>
    python storage_demo.py mput <text>
    python storage_demo.py mget <public_key_hex>
"""

import sys
sys.path.insert(0, ".")

from hyperdht import HyperDHT, KeyPair


def cmd_put(text):
    """Store immutable data. Target = BLAKE2b(value)."""
    dht = HyperDHT(use_public_bootstrap=True)
    dht.bind()

    value = text.encode()
    target = HyperDHT.hash(value)
    print(f"Storing: {text!r}")
    print(f"Target:  {target.hex()}")

    def on_done(err):
        if err:
            print(f"Error: {err}")
        else:
            print(f"Stored! Retrieve with:")
            print(f"  python storage_demo.py get {target.hex()}")
        dht.destroy()

    dht.on_bootstrapped(
        lambda: dht.immutable_put(value, on_done=on_done))
    dht.run()


def cmd_get(hash_hex):
    """Retrieve immutable data by content hash."""
    dht = HyperDHT(use_public_bootstrap=True)
    dht.bind()

    target = bytes.fromhex(hash_hex)
    found = []

    def on_value(data):
        found.append(data)
        print(f"Found: {data!r}")

    def on_done(err):
        if not found:
            print("Not found on the DHT")
        dht.destroy()

    dht.on_bootstrapped(
        lambda: dht.immutable_get(target, on_value=on_value, on_done=on_done))
    dht.run()


def cmd_mput(text):
    """Store signed mutable data. Target = BLAKE2b(publicKey)."""
    dht = HyperDHT(use_public_bootstrap=True)
    dht.bind()

    kp = KeyPair.generate()
    value = text.encode()
    print(f"Storing: {text!r}")
    print(f"Signed by: {kp.public_key.hex()[:32]}...")

    def on_done(err):
        if err:
            print(f"Error: {err}")
        else:
            print(f"Stored! Retrieve with:")
            print(f"  python storage_demo.py mget {kp.public_key.hex()}")
        dht.destroy()

    dht.on_bootstrapped(
        lambda: dht.mutable_put(kp, value, seq=1, on_done=on_done))
    dht.run()


def cmd_mget(pk_hex):
    """Retrieve latest signed mutable value for a public key."""
    dht = HyperDHT(use_public_bootstrap=True)
    dht.bind()

    pk = bytes.fromhex(pk_hex)
    found = []

    def on_value(seq, data, sig):
        found.append(data)
        print(f"Found (seq={seq}): {data!r}")

    def on_done(err):
        if not found:
            print("Not found on the DHT")
        dht.destroy()

    dht.on_bootstrapped(
        lambda: dht.mutable_get(pk, on_value=on_value, on_done=on_done))
    dht.run()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    arg = " ".join(sys.argv[2:])

    if cmd == "put":
        cmd_put(arg)
    elif cmd == "get":
        cmd_get(arg)
    elif cmd == "mput":
        cmd_mput(arg)
    elif cmd == "mget":
        cmd_mget(arg)
    else:
        print(__doc__)
        sys.exit(1)
