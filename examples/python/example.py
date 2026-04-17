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
    """JS-style: one call returns a ready-to-use stream."""
    remote_pk = bytes.fromhex(pk_hex)

    dht = HyperDHT()
    dht.bind()

    connected = False

    def on_open(stream):
        nonlocal connected
        connected = True
        print("Connected! Sending hello...")
        stream.write(b"hello from python")

    def on_data(data):
        print(f"Received: {data!r}")

    def on_close():
        print("Stream closed")
        dht.destroy()

    def on_error(code):
        print(f"Connection failed: {code}")
        dht.destroy()

    print(f"Connecting to {pk_hex[:32]}...")
    stream = dht.connect_stream(
        remote_pk,
        on_open=on_open,
        on_data=on_data,
        on_close=on_close,
        on_error=on_error,
    )
    # You can even queue a write before on_open fires:
    # stream.write(b"queued before open")

    dht.run()

    if connected:
        print("Success!")


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
