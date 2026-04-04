#!/usr/bin/env python3
"""
holesail-py — Expose a local port over HyperDHT.

A minimal Python reimplementation of holesail's server functionality,
powered by hyperdht-cpp. Accepts encrypted P2P connections and bridges
them to a local TCP port.

Usage:
    python holesail_server.py [port] [--secure]

    port:     local TCP port to expose (default: 8080)
    --secure: use hs://s000 mode (firewall rejects unknown peers)

Example:
    # Terminal 1: Start a local web server
    python3 webserver.py

    # Terminal 2: Expose it over HyperDHT
    python3 holesail_server.py 8080

    # Terminal 3 (JS client, any machine):
    holesail --connect <connection_string>
"""

import base64
import hashlib
import os
import socket
import sys
import threading

sys.path.insert(0, ".")

from hyperdht import HyperDHT, KeyPair

# z32 encoding (same alphabet as holesail's z32 module)
_Z32 = 'ybndrfg8ejkmcpqxot1uwisza345h769'
_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'


def _to_z32(data: bytes) -> str:
    b32 = base64.b32encode(data).decode().rstrip('=')
    return b32.translate(str.maketrans(_STD, _Z32.upper())).lower()


def _bridge_tcp_to_stream(tcp_sock: socket.socket, stream) -> None:
    """Read from TCP socket, write to encrypted stream. Runs in a thread."""
    try:
        while True:
            data = tcp_sock.recv(4096)
            if not data:
                break
            stream.write(data)
    except (OSError, RuntimeError):
        pass
    finally:
        stream.close()


def main():
    secure = "--secure" in sys.argv or "-s" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    port = int(args[0]) if args else 8080

    # Create DHT node
    dht = HyperDHT()
    dht.bind()

    # Generate holesail-compatible connection key
    if secure:
        raw_key = os.urandom(32)
        connection_key = _to_z32(raw_key)
        seed = hashlib.sha256(connection_key.encode()).digest()
        kp = KeyPair.from_seed(seed)
    else:
        kp = KeyPair.generate()
        connection_key = _to_z32(kp.public_key)

    # Create server
    server = dht.create_server()

    if secure:
        server.set_firewall(
            lambda remote_pk, host, port: remote_pk != kp.public_key)

    connections = []

    def on_connection(conn):
        connections.append(conn)
        print(f"\n  Peer connected!")
        print(f"    Remote key: {conn.remote_key.hex()[:32]}...")
        print(f"    From: {conn.peer_host}:{conn.peer_port}")
        print(f"    Encrypted: yes (Noise IK + SecretStream)")
        print(f"    Bridging to: localhost:{port}")
        print(f"    Total connections: {len(connections)}")

        # Connect to local TCP server
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tcp_sock.connect(('127.0.0.1', port))
        except OSError as e:
            print(f"    ERROR: can't connect to localhost:{port} — {e}")
            return

        # Open encrypted stream over the P2P connection
        def on_open():
            print(f"    Stream open — bridging data")
            # TCP→stream runs in a thread (reads are blocking)
            threading.Thread(
                target=_bridge_tcp_to_stream,
                args=(tcp_sock, stream),
                daemon=True,
            ).start()

        def on_data(data: bytes):
            # Stream→TCP: forward decrypted data to local server
            try:
                tcp_sock.sendall(data)
            except OSError:
                stream.close()

        def on_close():
            print(f"    Stream closed")
            try:
                tcp_sock.close()
            except OSError:
                pass

        stream = dht.open_stream(conn, on_open=on_open, on_data=on_data,
                                 on_close=on_close)

    server.listen(kp, on_connection)

    # Print connection info
    prefix = "s000" if secure else "0000"
    hs_link = f"hs://{prefix}{connection_key}"
    pk_hex = kp.public_key.hex()

    print(f"\n  Full public key: {pk_hex}")
    print(f"  Key length: {len(kp.public_key)} bytes")

    # Debug: show which library is loaded
    import hyperdht._bindings as _b
    print(f"  Library: {_b._lib._name}")
    print(f"  LD_LIBRARY_PATH: {os.environ.get('LD_LIBRARY_PATH', 'not set')}")
    print(f"""
  holesail-py — P2P tunnel powered by hyperdht-cpp
  -------------------------------------------------

  Local port:  {port}
  DHT port:    {dht.port}
  Public key:  {pk_hex}

  Connection string (holesail-compatible):
    {hs_link}

  Connect with JS holesail:
    holesail --connect {hs_link}

  Connect with raw HyperDHT (JS/Python/C++):
    dht.connect(bytes.fromhex("{pk_hex}"))

  Ctrl+C to stop
""")

    # Run event loop in background thread so Ctrl+C works
    thread = threading.Thread(target=dht.run, daemon=True)
    thread.start()

    try:
        thread.join()
    except KeyboardInterrupt:
        pass
    print(f"\n  Shutting down... ({len(connections)} connections served)")
    dht.destroy()


if __name__ == "__main__":
    main()
