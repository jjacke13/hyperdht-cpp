#!/usr/bin/env python3
"""
Example: HyperDHT from Python.

Usage:
    # Server
    python example.py server

    # Client (pass the server's public key)
    python example.py connect <public_key_hex>

    # Keypair
    python example.py keygen
"""

import sys
sys.path.insert(0, ".")

from hyperdht import HyperDHT, KeyPair


def cmd_keygen():
    kp = KeyPair.generate()
    print(f"Public key:  {kp.public_key.hex()}")
    print(f"Secret key:  {kp.secret_key.hex()}")


def cmd_server():
    dht = HyperDHT()
    dht.bind()

    kp = KeyPair.generate()
    server = dht.create_server()

    def on_connection(conn):
        print(f"Client connected: {conn.remote_key[:16].hex()}...")
        print(f"  From: {conn.peer_host}:{conn.peer_port}")

    server.listen(kp, on_connection)

    print(f"Server listening")
    print(f"Public key: {kp.public_key.hex()}")
    print(f"Port: {dht.port}")
    print(f"Ctrl+C to stop")

    try:
        dht.run()
    except KeyboardInterrupt:
        pass
    finally:
        dht.destroy()


def cmd_connect(pk_hex):
    remote_pk = bytes.fromhex(pk_hex)

    dht = HyperDHT()
    dht.bind()

    connected = False

    def on_done(error, conn):
        nonlocal connected
        if error:
            print(f"Connection failed: {error}")
        else:
            connected = True
            print(f"Connected!")
            print(f"  Remote key: {conn.remote_key[:16].hex()}...")
            print(f"  Peer: {conn.peer_host}:{conn.peer_port}")

    print(f"Connecting to {pk_hex[:32]}...")
    dht.connect(remote_pk, on_done)
    dht.run()

    if connected:
        print("Success!")

    dht.destroy()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "keygen":
        cmd_keygen()
    elif cmd == "server":
        cmd_server()
    elif cmd == "connect" and len(sys.argv) >= 3:
        cmd_connect(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)
