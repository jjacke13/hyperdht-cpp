"""
hyperdht — Python bindings for hyperdht-cpp via ctypes.

Usage:
    from hyperdht import HyperDHT, KeyPair

    kp = KeyPair.generate()
    print(f"Public key: {kp.public_key.hex()}")

    dht = HyperDHT()
    dht.bind()
    print(f"Listening on port {dht.port}")

    # Server
    server = dht.create_server()
    server.listen(kp, lambda conn: print(f"Connected: {conn.remote_key.hex()}"))

    # Client
    dht.connect(remote_pk, lambda err, conn: print("Connected!" if not err else f"Error: {err}"))

    dht.run()  # Run the event loop
    dht.destroy()

Requires: libhyperdht.so and libuv.so
"""

from hyperdht._bindings import (
    HyperDHT,
    KeyPair,
    Server,
    Connection,
)

__all__ = ["HyperDHT", "KeyPair", "Server", "Connection"]
__version__ = "0.1.0"
