#!/usr/bin/env python3
"""
Ping a HyperDHT node — direct UDP round-trip.

Usage:
    python ping_demo.py [host] [port]
    python ping_demo.py                          # pings bootstrap node 1
    python ping_demo.py 142.93.90.113 49737      # pings bootstrap node 2
"""

import sys
import time
sys.path.insert(0, ".")

from hyperdht import HyperDHT

host = sys.argv[1] if len(sys.argv) > 1 else "88.99.3.86"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 49737

dht = HyperDHT()
dht.bind()

start = time.monotonic()

def on_result(success):
    elapsed = (time.monotonic() - start) * 1000
    if success:
        print(f"Pong from {host}:{port} -- {elapsed:.0f}ms")
    else:
        print(f"No response from {host}:{port} (timeout)")
    dht.destroy()

print(f"Pinging {host}:{port}...")
dht.ping(host, port, on_done=on_result)
dht.run()
