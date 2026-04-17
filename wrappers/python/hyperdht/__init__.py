"""
hyperdht -- Python bindings for hyperdht-cpp via ctypes.

Usage::

    from hyperdht import HyperDHT, KeyPair

    kp = KeyPair.generate()
    print(f"Public key: {kp.public_key.hex()}")

    dht = HyperDHT(use_public_bootstrap=True)
    dht.bind()
    print(f"Listening on port {dht.port}")

    # Server
    server = dht.create_server()
    server.listen(kp, lambda conn: print(f"Connected: {conn}"))

    # Client
    dht.connect(remote_pk, lambda err, conn: print("OK" if not err else err))

    dht.run()
    dht.destroy()

Requires: libhyperdht.so and libuv.so
"""

from hyperdht._bindings import (
    Address,
    Connection,
    HyperDHT,
    KeyPair,
    PendingStream,
    PunchStats,
    Query,
    RelayStats,
    Stream,
)
from hyperdht._ffi import (
    ERR_CANCELLED,
    ERR_CONNECTION_FAILED,
    ERR_DESTROYED,
    ERR_HOLEPUNCH_FAILED,
    ERR_HOLEPUNCH_TIMEOUT,
    ERR_NO_ADDRESSES,
    ERR_OK,
    ERR_PEER_NOT_FOUND,
    ERR_RELAY_FAILED,
    FIREWALL_CONSISTENT,
    FIREWALL_OPEN,
    FIREWALL_RANDOM,
    FIREWALL_UNKNOWN,
)
from hyperdht._server import Server

__all__ = [
    # Classes
    "HyperDHT",
    "KeyPair",
    "Server",
    "Connection",
    "Stream",
    "PendingStream",
    "Query",
    "PunchStats",
    "RelayStats",
    "Address",
    # Firewall constants
    "FIREWALL_UNKNOWN",
    "FIREWALL_OPEN",
    "FIREWALL_CONSISTENT",
    "FIREWALL_RANDOM",
    # Error codes
    "ERR_OK",
    "ERR_DESTROYED",
    "ERR_PEER_NOT_FOUND",
    "ERR_CONNECTION_FAILED",
    "ERR_NO_ADDRESSES",
    "ERR_HOLEPUNCH_FAILED",
    "ERR_HOLEPUNCH_TIMEOUT",
    "ERR_RELAY_FAILED",
    "ERR_CANCELLED",
]

__version__ = "0.1.0"
