#!/usr/bin/env python3
"""
holesail-py — Expose a local port over HyperDHT.

A minimal Python reimplementation of holesail's server functionality,
powered by hyperdht-cpp. Proves that the C++ HyperDHT library can be
used from Python to accept encrypted P2P connections.

Usage:
    python holesail_server.py [port]

    port: local TCP port to expose (default: 8080)

What it does:
    1. Creates a HyperDHT node with a random keypair
    2. Announces on the DHT network
    3. Accepts encrypted connections from any HyperDHT client
    4. Prints a connection string that JS holesail clients can use

Example:
    # Terminal 1: Start a local web server
    python -m http.server 8080

    # Terminal 2: Expose it over HyperDHT
    python holesail_server.py 8080

    # Terminal 3 (JS client, any machine):
    holesail --connect <connection_string>

Note: Full TCP bridging requires stream-level integration (UDX + SecretStream).
This demo shows the HyperDHT connection establishment — the hardest part.
The actual data forwarding would be ~50 more lines using the stream APIs.
"""

import sys
import signal
sys.path.insert(0, ".")

from hyperdht import HyperDHT, KeyPair


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

    # Create DHT node
    dht = HyperDHT()
    dht.bind()

    # Generate identity
    kp = KeyPair.generate()

    # Create server
    server = dht.create_server()

    connections = []

    def on_connection(conn):
        connections.append(conn)
        print(f"\n  Peer connected!")
        print(f"    Remote key: {conn.remote_key.hex()[:32]}...")
        print(f"    From: {conn.peer_host}:{conn.peer_port}")
        print(f"    Encrypted: yes (Noise IK + SecretStream)")
        print(f"    Would bridge to: localhost:{port}")
        print(f"    Total connections: {len(connections)}")

    server.listen(kp, on_connection)

    # Print connection info (like holesail does)
    pk_hex = kp.public_key.hex()
    print(f"""
  ╔══════════════════════════════════════════════════════════╗
  ║  holesail-py — P2P tunnel powered by hyperdht-cpp       ║
  ╠══════════════════════════════════════════════════════════╣
  ║                                                          ║
  ║  Local port:  {port:<42} ║
  ║  DHT port:    {dht.port:<42} ║
  ║                                                          ║
  ║  Connection string:                                      ║
  ║  {pk_hex[:55]} ║
  ║  {pk_hex[55:]:<55} ║
  ║                                                          ║
  ║  Share this key with peers. They can connect with:       ║
  ║    holesail --connect {pk_hex[:32]}...    ║
  ║                                                          ║
  ║  Or from Python:                                         ║
  ║    dht.connect(bytes.fromhex("{pk_hex[:24]}..."))  ║
  ║                                                          ║
  ║  Or from C++:                                            ║
  ║    dht.connect(pk, callback);                            ║
  ║                                                          ║
  ║  Or from ANY language with our C API.                    ║
  ║                                                          ║
  ║  Ctrl+C to stop                                          ║
  ╚══════════════════════════════════════════════════════════╝
""")

    # Handle Ctrl+C
    def shutdown(sig, frame):
        print(f"\n  Shutting down... ({len(connections)} connections served)")
        server.close()
        dht.destroy()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    # Run the event loop
    try:
        dht.run()
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
