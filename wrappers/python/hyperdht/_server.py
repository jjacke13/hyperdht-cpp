"""
HyperDHT Server -- listens for incoming encrypted connections.
"""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, Callable

from hyperdht._ffi import (
    CLOSE_CB,
    CONNECTION_CB,
    EVENT_CB,
    FIREWALL_ASYNC_CB,
    FIREWALL_CB,
    HOLEPUNCH_CB,
    LOG_CB,
    Keypair as _Keypair,
    lib as _lib,
)

if TYPE_CHECKING:
    from hyperdht._bindings import Address, Connection, HyperDHT, KeyPair


class Server:
    """HyperDHT server -- listens for incoming connections."""

    def __init__(self, handle: ctypes.c_void_p, dht: HyperDHT) -> None:
        self._handle = handle
        self._dht = dht
        self._callbacks: list = []

    def listen(self, keypair: KeyPair, on_connection: Callable) -> None:
        """Start listening for connections."""
        from hyperdht._bindings import Connection

        c_kp = keypair._to_c()

        @CONNECTION_CB
        def cb(conn_ptr, ud):
            if conn_ptr:
                on_connection(Connection(conn_ptr.contents))

        self._callbacks.extend([cb, c_kp])
        rc = _lib.hyperdht_server_listen(
            self._handle, ctypes.byref(c_kp), cb, None)
        _lib.hyperdht_keypair_zero(ctypes.byref(c_kp))
        if rc != 0:
            raise RuntimeError(f"server_listen failed: {rc}")

    def close(self, on_done: Callable | None = None) -> None:
        """Stop listening and unannounce."""
        @CLOSE_CB
        def cb(ud):
            if on_done:
                on_done()

        self._callbacks.append(cb)
        _lib.hyperdht_server_close(self._handle, cb, None)

    def close_force(self, on_done: Callable | None = None) -> None:
        """Force-close, skipping unannounce."""
        @CLOSE_CB
        def cb(ud):
            if on_done:
                on_done()

        self._callbacks.append(cb)
        _lib.hyperdht_server_close_force(self._handle, cb, None)

    def refresh(self) -> None:
        """Force re-announcement."""
        if self._handle:
            _lib.hyperdht_server_refresh(self._handle)

    # -- Firewall --

    def set_firewall(self, callback: Callable) -> None:
        """Set sync firewall. ``callback(pk, host, port) -> bool``.
        Return True to reject, False to accept."""
        @FIREWALL_CB
        def cb(pk_ptr, host, port, ud):
            remote_pk = bytes(pk_ptr[:32])
            reject = callback(remote_pk, host.decode(), port)
            return 1 if reject else 0

        self._callbacks.append(cb)
        _lib.hyperdht_server_set_firewall(self._handle, cb, None)

    def set_firewall_async(self, callback: Callable) -> None:
        """Set async firewall. ``callback(pk, host, port, done_fn)``.
        Call ``done_fn(reject=True)`` when your decision is ready."""
        @FIREWALL_ASYNC_CB
        def cb(pk_ptr, host, port, done_handle, ud):
            remote_pk = bytes(pk_ptr[:32])
            host_str = host.decode() if host else ""

            def done_fn(reject: bool = False) -> None:
                _lib.hyperdht_firewall_done(done_handle, 1 if reject else 0)

            callback(remote_pk, host_str, port, done_fn)

        self._callbacks.append(cb)
        _lib.hyperdht_server_set_firewall_async(self._handle, cb, None)

    def set_holepunch(self, callback: Callable) -> None:
        """Set holepunch veto. Return True to reject, False to allow.
        ``callback(remote_fw, local_fw, remote_addr_count, local_addr_count) -> bool``"""
        @HOLEPUNCH_CB
        def cb(remote_fw, local_fw, remote_n, local_n, ud):
            reject = callback(remote_fw, local_fw, remote_n, local_n)
            return 1 if reject else 0

        self._callbacks.append(cb)
        _lib.hyperdht_server_set_holepunch(self._handle, cb, None)

    # -- Relay --

    def set_relay_through(
        self, relay_pk: bytes | None, keep_alive_ms: int = 5000,
    ) -> None:
        """Enable blind relay fallback. Pass None to disable."""
        if relay_pk is not None:
            if len(relay_pk) != 32:
                raise ValueError("relay_pk must be 32 bytes")
            pk = (ctypes.c_uint8 * 32)(*relay_pk)
            _lib.hyperdht_server_set_relay_through(
                self._handle, pk, keep_alive_ms)
        else:
            _lib.hyperdht_server_set_relay_through(self._handle, None, 0)

    # -- Lifecycle --

    def suspend(self, log: Callable | None = None) -> None:
        """Suspend the server."""
        if log:
            @LOG_CB
            def cb(msg, ud):
                log(msg.decode() if msg else "")

            self._callbacks.append(cb)
            _lib.hyperdht_server_suspend_logged(self._handle, cb, None)
        else:
            _lib.hyperdht_server_suspend(self._handle)

    def resume(self) -> None:
        """Resume the server."""
        _lib.hyperdht_server_resume(self._handle)

    def notify_online(self) -> None:
        """Notify after network comes back online."""
        _lib.hyperdht_server_notify_online(self._handle)

    def on_listening(self, callback: Callable) -> None:
        """Register callback for when server is ready to accept peers."""
        @EVENT_CB
        def cb(ud):
            callback()

        self._callbacks.append(cb)
        _lib.hyperdht_server_on_listening(self._handle, cb, None)

    # -- State --

    @property
    def is_listening(self) -> bool:
        return bool(_lib.hyperdht_server_is_listening(self._handle))

    @property
    def public_key(self) -> bytes | None:
        """Server's public key, or None if not listening."""
        out = (ctypes.c_uint8 * 32)()
        rc = _lib.hyperdht_server_public_key(self._handle, out)
        if rc != 0:
            return None
        return bytes(out)

    @property
    def address(self) -> Address | None:
        """Server's public address, or None if not known."""
        from hyperdht._bindings import Address

        host_buf = ctypes.create_string_buffer(46)
        port = ctypes.c_uint16()
        rc = _lib.hyperdht_server_address(
            self._handle, host_buf, ctypes.byref(port))
        if rc != 0:
            return None
        return Address(host_buf.value.decode(), port.value)
