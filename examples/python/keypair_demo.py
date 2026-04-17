#!/usr/bin/env python3
"""
Keypair generation — random, deterministic, and from seed.

Usage:
    python keypair_demo.py
"""

import sys
sys.path.insert(0, ".")

from hyperdht import HyperDHT, KeyPair

# Random keypair — different every time
kp1 = KeyPair.generate()
kp2 = KeyPair.generate()
print(f"Random keypair 1: {kp1.public_key.hex()[:32]}...")
print(f"Random keypair 2: {kp2.public_key.hex()[:32]}...")
print(f"Different: {kp1.public_key != kp2.public_key}")

# Deterministic keypair — same seed always gives same keys
seed = b"my-secret-seed-must-be-32-bytes!"
kp3 = KeyPair.from_seed(seed)
kp4 = KeyPair.from_seed(seed)
print(f"\nFrom seed:        {kp3.public_key.hex()[:32]}...")
print(f"Same seed again:  {kp4.public_key.hex()[:32]}...")
print(f"Identical: {kp3.public_key == kp4.public_key}")

# DHT default keypair — auto-generated on creation
dht = HyperDHT()
print(f"\nDHT default key:  {dht.default_keypair.public_key.hex()[:32]}...")

# DHT with seed — stable identity across restarts
dht2 = HyperDHT(seed=seed)
print(f"DHT seeded key:   {dht2.default_keypair.public_key.hex()[:32]}...")
print(f"Matches from_seed: {dht2.default_keypair.public_key == kp3.public_key}")

dht.destroy()
dht2.destroy()
