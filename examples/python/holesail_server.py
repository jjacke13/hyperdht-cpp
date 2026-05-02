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
import os
import socket
import sys
import weakref

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

    All I/O runs on the libuv event loop — TCP sockets are registered
    via uv_poll (hyperdht_poll_start), so there's zero polling latency.
    The stream->TCP direction is handled by the stream's on_data callback.
    The TCP->stream direction fires when libuv detects the fd is readable.
    """

    def __init__(
        self, tcp_sock: socket.socket, stream, dht,
        bridges: set[Bridge],
    ) -> None:
        self._tcp = tcp_sock
        self._stream = stream
        self._dht = dht
        self._bridges = bridges
        self._poll_handle = None
        self._write_buf = bytearray()
        self._watching_writable = False
        self._closed = False
        self._tcp.setblocking(False)

    def activate(self) -> None:
        """Start watching TCP for data. Call from on_open."""
        if self._poll_handle or self._closed:
            return
        # Single poll handle — libuv forbids multiple polls on same fd.
        # Start with readable only; add writable when backpressured.
        self._poll_handle = self._dht.poll_start(
            self._tcp.fileno(), self._on_poll)

    def _on_poll(self, fd: int, events: int) -> None:
        """Single callback for both readable and writable events."""
        if events & 1:  # POLL_READABLE
            self._handle_readable()
        if events & 2:  # POLL_WRITABLE
            self._handle_writable()

    def _handle_readable(self) -> None:
        if not self._stream:
            return
        try:
            data = self._tcp.recv(65536)
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

    def _handle_writable(self) -> None:
        if not self._write_buf:
            self._set_writable(False)
            return

        try:
            sent = self._tcp.send(self._write_buf)
        except BlockingIOError:
            return
        except OSError:
            self.close()
            return

        del self._write_buf[:sent]

        if not self._write_buf:
            self._set_writable(False)

    def write_to_tcp(self, data: bytes) -> None:
        """Called from stream's on_data — forward to TCP."""
        if self._closed:
            return

        # If we already have buffered data, append and let the
        # writable poll flush it in order.
        if self._write_buf:
            self._write_buf.extend(data)
            return

        # Try to send directly first (fast path).
        try:
            sent = self._tcp.send(data)
        except BlockingIOError:
            sent = 0
        except OSError:
            self.close()
            return

        if sent == len(data):
            return  # All sent, no buffering needed

        # Partial send — buffer the rest and watch for writable.
        self._write_buf.extend(data[sent:])
        self._set_writable(True)

    def _set_writable(self, enable: bool) -> None:
        """Toggle writable event on the single poll handle."""
        if enable == self._watching_writable:
            return
        self._watching_writable = enable
        if not self._poll_handle:
            return
        # Recreate poll with updated event flags — libuv doesn't
        # support modifying events on an active poll, so stop+restart.
        self._dht.poll_stop(self._poll_handle)
        self._poll_handle = self._dht.poll_start(
            self._tcp.fileno(), self._on_poll,
            readable=True, writable=enable)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._bridges.discard(self)
        if self._poll_handle:
            self._dht.poll_stop(self._poll_handle)
            self._poll_handle = None
        self._write_buf.clear()
        try:
            self._tcp.close()
        except OSError:
            pass
        if self._stream:
            try:
                self._stream.close()
            except RuntimeError:
                pass
            self._stream = None


def main() -> None:
    args = _parse_args()
    local_port = args.live
    local_host = args.host

    # Verify the local port is reachable before joining the DHT
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        test_sock.connect((local_host, local_port))
    except OSError:
        print(f"Warning: nothing listening on {local_host}:{local_port} yet")
    finally:
        test_sock.close()

    # Keypair + connection string
    kp, connection_key = _make_keypair(args.seed, args.secure)

    # Build the DHT node
    dht = HyperDHT(use_public_bootstrap=True)
    dht.bind()

    bridges: set[Bridge] = set()

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
            tcp_sock.close()
            return

        # Create bridge with stream=None initially, set after open_stream
        bridge = Bridge(tcp_sock, None, dht, bridges)
        bridges.add(bridge)

        conn_id = connection_count

        def on_open() -> None:
            bridge.activate()

        def on_data(data: bytes) -> None:
            bridge.write_to_tcp(data)

        def on_close() -> None:
            print(f"  Stream closed  [{conn_id}]")
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

    # Diagnostic heartbeat — print DHT state every 30s
    import time
    last_heartbeat = [time.monotonic()]

    orig_run = dht.run

    def run_with_heartbeat():
        while True:
            dht.run(mode="once")
            now = time.monotonic()
            if now - last_heartbeat[0] >= 30:
                last_heartbeat[0] = now
                addr = dht.remote_address
                addr_str = f"{addr.host}:{addr.port}" if addr else "unknown"
                print(f"  [heartbeat] online={dht.is_online} "
                      f"persistent={dht.is_persistent} "
                      f"listening={server.is_listening} "
                      f"addr={addr_str} "
                      f"bridges={len(bridges)} "
                      f"conns={connection_count}")

    # Event-driven: TCP sockets are registered with libuv via poll_start,
    # so dht.run() handles everything — DHT, streams, and TCP bridging.
    try:
        run_with_heartbeat()
    except KeyboardInterrupt:
        pass

    print(f"\n  Shutting down ({connection_count} connections served)")
    for bridge in list(bridges):
        bridge.close()
    server.close_force()  # skip UNANNOUNCE — exit fast
    dht.destroy(force=True)


if __name__ == "__main__":
    main()
