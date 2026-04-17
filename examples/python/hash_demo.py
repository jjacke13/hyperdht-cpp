#!/usr/bin/env python3
"""
BLAKE2b-256 hashing — the same hash function used by the DHT.

Usage:
    python hash_demo.py [text]
"""

import sys
sys.path.insert(0, ".")

from hyperdht import HyperDHT

text = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "hello world"
data = text.encode()

h = HyperDHT.hash(data)
print(f"Input:  {text!r}")
print(f"Hash:   {h.hex()}")
print(f"Length: {len(h)} bytes (256-bit)")

# Same input always gives same hash
h2 = HyperDHT.hash(data)
print(f"Stable: {h == h2}")

# Different input gives different hash
h3 = HyperDHT.hash(b"different")
print(f"Unique: {h != h3}")
