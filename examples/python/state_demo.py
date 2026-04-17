#!/usr/bin/env python3
"""
DHT state inspection — lifecycle, health, and events.

Usage:
    python state_demo.py
"""

import sys
sys.path.insert(0, ".")

from hyperdht import HyperDHT, FIREWALL_UNKNOWN, FIREWALL_OPEN, FIREWALL_CONSISTENT

FIREWALL_NAMES = {
    FIREWALL_UNKNOWN: "UNKNOWN",
    FIREWALL_OPEN: "OPEN",
    FIREWALL_CONSISTENT: "CONSISTENT",
}

dht = HyperDHT()
dht.bind()

print(f"Port:          {dht.port}")
print(f"Online:        {dht.is_online}")
print(f"Bootstrapped:  {dht.is_bootstrapped}")
print(f"Persistent:    {dht.is_persistent}")
print(f"Suspended:     {dht.is_suspended}")
print(f"Destroyed:     {dht.is_destroyed}")
print(f"Keep-alive:    {dht.connection_keep_alive}ms")

# Remote address (requires bootstrap + NAT sampling)
addr = dht.remote_address
print(f"Public addr:   {addr if addr else 'unknown (not bootstrapped)'}")

# Routing table snapshot
nodes = dht.to_array()
print(f"Routing table: {len(nodes)} nodes")

# Punch stats
stats = dht.punch_stats
print(f"Punch stats:   consistent={stats.consistent} random={stats.random} open={stats.open}")

# Relay stats
relay = dht.relay_stats
print(f"Relay stats:   attempts={relay.attempts} successes={relay.successes} aborts={relay.aborts}")

# Suspend / resume cycle
print(f"\nSuspending...")
dht.suspend()
print(f"Suspended:     {dht.is_suspended}")
dht.resume()
print(f"Resumed:       {not dht.is_suspended}")

dht.destroy()
print(f"Destroyed:     True")
