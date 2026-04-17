#!/usr/bin/env python3
"""
holesail-py -- Expose a local TCP port over HyperDHT.

A Python reimplementation of holesail's server functionality,
powered by hyperdht-cpp. Accepts encrypted P2P connections and
bridges them to a local TCP port.

Usage:
    python holesail_server.py --live <port> [options]

Options:
    --live <port>     Local TCP port to expose (required)
    --host <addr>     Local bind address (default: 127.0.0.1)
    --seed <hex>      64-char hex seed for deterministic identity
    --secure          Firewall rejects peers that don't know the seed

Examples:
    # Expose a local web server
    python holesail_server.py --live 8080

    # Deterministic identity (survives restarts)
    python holesail_server.py --live 3000 --seed $(head -c32 /dev/urandom | xxd -p -c64)

    # Secure mode (only seed-holders can connect)
    python holesail_server.py --live 8080 --seed abc123...def --secure

Connect with JS holesail:
    holesail --connect <connection_string>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import selectors
import socket
import sys
import time

sys.path.insert(0, ".")

from hyperdht import HyperDHT, KeyPair

# z32 encoding (same alphabet as holesail's z32 module)
_Z32 = "ybndrfg8ejkmcpqxot1uwisza345h769"
_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _to_z32(data: bytes) -> str:
    b32 = base64.b32encode(data).decode().rstrip("=")
    return b32.translate(str.maketrans(_STD, _Z32.upper())).lower()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="holesail-py",
        description="Expose a local TCP port over HyperDHT (P2P)",
    )
    parser.add_argument(
        "--live", type=int, required=True, metavar="PORT",
        help="Local TCP port to expose",
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Local bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--seed", metavar="HEX",
        help="64-char hex seed for deterministic keypair",
    )
    parser.add_argument(
        "--secure", action="store_true",
        help="Reject peers that don't know the seed",
    )
    return parser.parse_args()


def _make_keypair(
    seed_hex: str | None, secure: bool,
) -> tuple[KeyPair, str]:
    """Create keypair and connection string."""
    if seed_hex:
        if len(seed_hex) != 64:
            print("Error: --seed must be 64 hex characters (32 bytes)")
            sys.exit(1)
        seed = bytes.fromhex(seed_hex)
        kp = KeyPair.from_seed(seed)
        connection_key = _to_z32(seed if secure else kp.public_key)
    elif secure:
        raw_seed = os.urandom(32)
        kp = KeyPair.from_seed(raw_seed)
        connection_key = _to_z32(raw_seed)
    else:
        kp = KeyPair.generate()
        connection_key = _to_z32(kp.public_key)

    return kp, connection_key


class Bridge:
    """Bidirectional bridge between a TCP socket and an encrypted stream.

    All I/O happens on the main thread via a selectors poll loop.
    The stream→TCP direction is handled by the stream's on_data callback.
    The TCP→stream direction is polled via the selector.
    """

    def __init__(
        self, tcp_sock: socket.socket, stream, selector: selectors.BaseSelector,
    ) -> None:
        self._tcp = tcp_sock
        self._stream = stream
        self._selector = selector
        self._closed = False
        self._active = False
        # Don't register with selector yet — wait for on_open so the
        # SecretStream header exchange completes before we try to write.

    def activate(self) -> None:
        """Start polling TCP for data. Call from on_open."""
        if self._active or self._closed:
            return
        self._active = True
        self._selector.register(
            self._tcp, selectors.EVENT_READ, self._on_tcp_readable)

    def _on_tcp_readable(self) -> None:
        """Called when the TCP socket has data (or EOF)."""
        if not self._stream:
            return
        try:
            data = self._tcp.recv(4096)
        except BlockingIOError:
            return
        except OSError:
            self.close()
            return

        if not data:
            self.close()
            return

        try:
            self._stream.write(data)
        except RuntimeError:
            self.close()

    def write_to_tcp(self, data: bytes) -> None:
        """Called from stream's on_data — forward to TCP."""
        try:
            self._tcp.sendall(data)
        except OSError:
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._active:
            try:
                self._selector.unregister(self._tcp)
            except (KeyError, ValueError):
                pass
        try:
            self._tcp.close()
        except OSError:
            pass
        try:
            self._stream.close()
        except RuntimeError:
            pass


def main() -> None:
    args = _parse_args()
    local_port = args.live
    local_host = args.host

    # Verify the local port is reachable before joining the DHT
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        test_sock.connect((local_host, local_port))
        test_sock.close()
    except OSError:
        print(f"Warning: nothing listening on {local_host}:{local_port} yet")

    # Keypair + connection string
    kp, connection_key = _make_keypair(args.seed, args.secure)

    # Build the DHT node
    dht = HyperDHT(use_public_bootstrap=True)
    dht.bind()

    # Selector for polling TCP sockets alongside the libuv event loop
    sel = selectors.DefaultSelector()
    bridges: list[Bridge] = []

    # Create server with optional firewall
    server = dht.create_server()

    if args.secure:
        server.set_firewall(
            lambda remote_pk, host, port: remote_pk != kp.public_key
        )

    connection_count = 0

    def on_connection(conn) -> None:
        nonlocal connection_count
        connection_count += 1
        print(f"  Peer connected from {conn.peer_host}:{conn.peer_port}"
              f"  [{connection_count} total]")

        # Connect to local TCP server
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tcp_sock.connect((local_host, local_port))
        except OSError as e:
            print(f"  Error: can't reach {local_host}:{local_port} -- {e}")
            return

        bridge = Bridge(tcp_sock, None, sel)
        bridges.append(bridge)

        def on_open() -> None:
            bridge.activate()

        def on_data(data: bytes) -> None:
            bridge.write_to_tcp(data)

        def on_close() -> None:
            bridge.close()

        stream = dht.open_stream(
            conn, on_open=on_open, on_data=on_data, on_close=on_close,
        )
        bridge._stream = stream

    server.listen(kp, on_connection)

    # Publish metadata so holesail clients can discover port/protocol.
    # JS holesail does: dht.mutablePut(keyPair, JSON({host, port, udp}))
    import json
    metadata = json.dumps({
        "host": local_host,
        "port": local_port,
        "udp": False,
    }).encode()
    dht.mutable_put(kp, metadata, seq=1)

    # Connection string
    prefix = "s000" if args.secure else "0000"
    hs_link = f"hs://{prefix}{connection_key}"

    print(f"""
  holesail-py -- P2P tunnel powered by hyperdht-cpp
  --------------------------------------------------

  Exposing:    {local_host}:{local_port}
  DHT port:    {dht.port}
  Mode:        {"secure" if args.secure else "open"}
  Public key:  {kp.public_key.hex()}

  Connection string:
    {hs_link}

  Connect with:
    holesail --connect {hs_link}

  Ctrl+C to stop
""")

    # Single-threaded event loop: poll both libuv and TCP sockets
    last_put = time.monotonic()
    put_seq = 2
    try:
        while True:
            # Tick the libuv event loop (non-blocking)
            dht.run(mode="nowait")

            # Poll TCP sockets for readable data (short timeout)
            events = sel.select(timeout=0.005)
            for key, _ in events:
                callback = key.data
                callback()

            # Re-announce metadata every 50 minutes (JS parity)
            now = time.monotonic()
            if now - last_put >= 50 * 60:
                dht.mutable_put(kp, metadata, seq=put_seq)
                put_seq += 1
                last_put = now

    except KeyboardInterrupt:
        pass

    print(f"\n  Shutting down ({connection_count} connections served)")
    sel.close()
    dht.destroy()


if __name__ == "__main__":
    main()
