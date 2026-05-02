"""
Python-friendly wrappers for the hyperdht-cpp C FFI.

Low-level ctypes declarations live in ``_ffi.py``.
"""

from __future__ import annotations

import ctypes
from typing import Callable, NamedTuple

from hyperdht._ffi import (
    CLOSE_CB,
    CONNECT_CB,
    DATA_CB,
    DONE_CB,
    DRAIN_CB,
    EVENT_CB,
    HOST_STRIDE,
    LOG_CB,
    MUTABLE_CB,
    PEER_CB,
    PING_CB,
    POLL_CB,
    POLL_READABLE,
    POLL_WRITABLE,
    UV_RUN_DEFAULT,
    UV_RUN_NOWAIT,
    UV_RUN_ONCE,
    VALUE_CB,
    ConnectOpts as _ConnectOpts,
    Connection as _Connection,
    Keypair as _Keypair,
    Opts as _Opts,
    lib as _lib,
    uv as _uv,
)
from hyperdht._server import Server


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class PunchStats(NamedTuple):
    """Holepunch connect counts by strategy."""
    consistent: int
    random: int
    open: int


class RelayStats(NamedTuple):
    """Blind-relay counters."""
    attempts: int
    successes: int
    aborts: int


class Address(NamedTuple):
    """A host:port pair."""
    host: str
    port: int


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

class Connection:
    """Represents an established encrypted connection."""

    __slots__ = (
        "_c_conn", "remote_key", "tx_key", "rx_key", "handshake_hash",
        "remote_udx_id", "local_udx_id", "peer_host", "peer_port",
        "is_initiator",
    )

    def __init__(self, c_conn: _Connection) -> None:
        self._c_conn = _Connection()
        ctypes.memmove(
            ctypes.byref(self._c_conn), ctypes.byref(c_conn),
            ctypes.sizeof(_Connection))
        self.remote_key = bytes(c_conn.remote_public_key)
        self.tx_key = bytes(c_conn.tx_key)
        self.rx_key = bytes(c_conn.rx_key)
        self.handshake_hash = bytes(c_conn.handshake_hash)
        self.remote_udx_id = c_conn.remote_udx_id
        self.local_udx_id = c_conn.local_udx_id
        self.peer_host = c_conn.peer_host.decode("utf-8")
        self.peer_port = c_conn.peer_port
        self.is_initiator = bool(c_conn.is_initiator)

    def __repr__(self) -> str:
        return (f"Connection(peer={self.peer_host}:{self.peer_port}, "
                f"key={self.remote_key[:8].hex()}...)")


# ---------------------------------------------------------------------------
# KeyPair
# ---------------------------------------------------------------------------

class KeyPair:
    """Ed25519 keypair for HyperDHT identity."""

    __slots__ = ("public_key", "secret_key")

    def __init__(self, public_key: bytes, secret_key: bytes) -> None:
        if len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        if len(secret_key) != 64:
            raise ValueError("secret_key must be 64 bytes")
        self.public_key = public_key
        self.secret_key = secret_key

    @classmethod
    def generate(cls) -> KeyPair:
        """Generate a random keypair."""
        kp = _Keypair()
        _lib.hyperdht_keypair_generate(ctypes.byref(kp))
        result = cls(bytes(kp.public_key), bytes(kp.secret_key))
        _lib.hyperdht_keypair_zero(ctypes.byref(kp))
        return result

    @classmethod
    def from_seed(cls, seed: bytes) -> KeyPair:
        """Generate a deterministic keypair from a 32-byte seed."""
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        kp = _Keypair()
        seed_arr = (ctypes.c_uint8 * 32)(*seed)
        _lib.hyperdht_keypair_from_seed(ctypes.byref(kp), seed_arr)
        result = cls(bytes(kp.public_key), bytes(kp.secret_key))
        _lib.hyperdht_keypair_zero(ctypes.byref(kp))
        return result

    def _to_c(self) -> _Keypair:
        kp = _Keypair()
        ctypes.memmove(kp.public_key, self.public_key, 32)
        ctypes.memmove(kp.secret_key, self.secret_key, 64)
        return kp

    def __repr__(self) -> str:
        return f"KeyPair(pk={self.public_key[:8].hex()}...)"


# ---------------------------------------------------------------------------
# Stream
# ---------------------------------------------------------------------------

class Stream:
    """Encrypted read/write stream over an established connection."""

    def __init__(self, handle: ctypes.c_void_p, dht: HyperDHT) -> None:
        self._handle = handle
        self._dht = dht
        self._callbacks: list = []
        self._on_data = None
        self._on_close = None
        self._on_open = None

    @property
    def is_open(self) -> bool:
        if not self._handle:
            return False
        return bool(_lib.hyperdht_stream_is_open(self._handle))

    def write(self, data: bytes) -> None:
        """Write data to the encrypted stream."""
        if not self._handle:
            raise RuntimeError("Stream is closed")
        rc = _lib.hyperdht_stream_write(self._handle, data, len(data))
        if rc < 0:
            raise RuntimeError(f"stream_write failed: {rc}")

    def write_with_drain(
        self, data: bytes, on_drain: Callable | None = None,
    ) -> int:
        """Write with drain callback for flow control.
        Returns 0 on success (may be backpressured), negative on error.
        on_drain fires when the transport is ready for more data."""
        if not self._handle:
            raise RuntimeError("Stream is closed")
        if on_drain is None:
            return _lib.hyperdht_stream_write(self._handle, data, len(data))

        @DRAIN_CB
        def cb(stream_ptr, ud):
            on_drain()

        self._callbacks.append(cb)
        return _lib.hyperdht_stream_write_with_drain(
            self._handle, data, len(data), cb, None)

    def close(self) -> None:
        """Close the stream."""
        if self._handle:
            _lib.hyperdht_stream_close(self._handle)
            self._handle = None


# ---------------------------------------------------------------------------
# PendingStream
# ---------------------------------------------------------------------------

class PendingStream:
    """Handle returned by ``HyperDHT.connect_stream()`` before the
    encrypted channel is established.

    Writes before ``on_open`` are buffered and flushed automatically.
    """

    def __init__(self) -> None:
        self.stream: Stream | None = None
        self._pending_writes: list[bytes] = []
        self._pending_close = False

    def write(self, data: bytes) -> None:
        """Write to the stream. Buffered if not yet open."""
        if self.stream and self.stream.is_open:
            self.stream.write(data)
        else:
            self._pending_writes.append(data)

    def close(self) -> None:
        """Close the stream (or cancel if not yet opened)."""
        if self.stream:
            self.stream.close()
        else:
            self._pending_close = True

    @property
    def is_open(self) -> bool:
        return self.stream is not None and self.stream.is_open

    def _flush_pending(self) -> None:
        if not self.stream:
            return
        for buf in self._pending_writes:
            self.stream.write(buf)
        self._pending_writes.clear()
        if self._pending_close:
            self.stream.close()


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

class Query:
    """Handle for an in-flight DHT query (find_peer, lookup, etc.).

    Obtained from ``_ex`` methods. Must be freed after use::

        query = dht.find_peer_ex(pk, on_reply=..., on_done=...)
        query.cancel()   # optional
        query.free()     # required

    Or as a context manager::

        with dht.find_peer_ex(pk, on_reply=...) as q:
            dht.run()
        # auto-freed on exit
    """

    def __init__(self, handle: ctypes.c_void_p) -> None:
        self._handle = handle

    def cancel(self) -> None:
        """Cancel the query. Idempotent."""
        if self._handle:
            _lib.hyperdht_query_cancel(self._handle)

    def free(self) -> None:
        """Release the query handle. Must be called exactly once."""
        if self._handle:
            _lib.hyperdht_query_free(self._handle)
            self._handle = None

    def __enter__(self) -> Query:
        return self

    def __exit__(self, *_: object) -> None:
        self.free()

    def __del__(self) -> None:
        self.free()


# ---------------------------------------------------------------------------
# HyperDHT
# ---------------------------------------------------------------------------

class HyperDHT:
    """HyperDHT node -- connect to peers, listen for connections, store data.

    Usage::

        dht = HyperDHT(use_public_bootstrap=True)
        dht.bind()
        dht.on_bootstrapped(lambda: print("Ready!"))
        dht.run()
        dht.destroy()
    """

    def __init__(
        self,
        port: int = 0,
        ephemeral: bool = True,
        *,
        use_public_bootstrap: bool = False,
        connection_keep_alive: int | None = None,
        seed: bytes | None = None,
        host: str | None = None,
        nodes: list[str] | None = None,
    ) -> None:
        # Allocate uv_loop
        loop_size = _uv.uv_loop_size()
        self._loop_buf = (ctypes.c_uint8 * loop_size)()
        self._loop = ctypes.cast(self._loop_buf, ctypes.c_void_p)
        _uv.uv_loop_init(self._loop)

        # Build opts via the C default helper for forward compatibility
        opts = _Opts()
        _lib.hyperdht_opts_default(ctypes.byref(opts))
        opts.port = port
        opts.ephemeral = 1 if ephemeral else 0
        opts.use_public_bootstrap = 1 if use_public_bootstrap else 0

        if connection_keep_alive is not None:
            opts.connection_keep_alive = connection_keep_alive

        if seed is not None:
            if len(seed) != 32:
                raise ValueError("seed must be 32 bytes")
            ctypes.memmove(opts.seed, seed, 32)
            opts.seed_is_set = 1

        # Keep borrowed-pointer references alive for the create() call
        self._host_buf: bytes | None = None
        if host is not None:
            self._host_buf = host.encode()
            opts.host = self._host_buf

        self._node_bufs: list[bytes] | None = None
        self._nodes_arr = None
        if nodes is not None:
            self._node_bufs = [n.encode() for n in nodes]
            arr = (ctypes.c_char_p * len(nodes))(*self._node_bufs)
            self._nodes_arr = arr
            opts.nodes = arr
            opts.nodes_len = len(nodes)

        self._handle = _lib.hyperdht_create(self._loop, ctypes.byref(opts))
        if not self._handle:
            raise RuntimeError("Failed to create HyperDHT instance")

        self._callbacks: list = []

    # -- Lifecycle --

    def bind(self, port: int = 0) -> None:
        """Bind the UDP socket."""
        rc = _lib.hyperdht_bind(self._handle, port)
        if rc != 0:
            raise RuntimeError(f"bind failed: {rc}")

    @property
    def port(self) -> int:
        return _lib.hyperdht_port(self._handle)

    @property
    def default_keypair(self) -> KeyPair:
        kp = _Keypair()
        _lib.hyperdht_default_keypair(self._handle, ctypes.byref(kp))
        result = KeyPair(bytes(kp.public_key), bytes(kp.secret_key))
        _lib.hyperdht_keypair_zero(ctypes.byref(kp))
        return result

    @property
    def connection_keep_alive(self) -> int:
        """Keep-alive setting (ms)."""
        return _lib.hyperdht_connection_keep_alive(self._handle)

    def destroy(self, force: bool = False) -> None:
        """Destroy the instance and free all resources."""
        if self._handle:
            fn = _lib.hyperdht_destroy_force if force else _lib.hyperdht_destroy
            fn(self._handle, CLOSE_CB(0), None)
            # Drain with UV_RUN_ONCE so Python signals (Ctrl+C) are
            # processed between iterations instead of blocking in C.
            try:
                while _uv.uv_run(self._loop, UV_RUN_ONCE):
                    pass
            except KeyboardInterrupt:
                pass  # second Ctrl+C skips drain — exit immediately
            _lib.hyperdht_free(self._handle)
            self._handle = None
        _uv.uv_loop_close(self._loop)

    def run(self, mode: str = "default") -> None:
        """Run the libuv event loop.

        The default mode uses UV_RUN_ONCE in a Python loop so that
        signals (Ctrl+C) are processed between iterations. Use
        mode="blocking" for the old UV_RUN_DEFAULT behavior.
        """
        if mode == "blocking":
            _uv.uv_run(self._loop, UV_RUN_DEFAULT)
        elif mode == "once":
            _uv.uv_run(self._loop, UV_RUN_ONCE)
        elif mode == "nowait":
            _uv.uv_run(self._loop, UV_RUN_NOWAIT)
        else:
            # Default: UV_RUN_ONCE loop — returns to Python between
            # iterations so KeyboardInterrupt can be raised.
            while _uv.uv_run(self._loop, UV_RUN_ONCE):
                pass

    def suspend(self, log: Callable | None = None) -> None:
        """Suspend the DHT."""
        if log:
            @LOG_CB
            def cb(msg, ud):
                log(msg.decode() if msg else "")

            self._callbacks.append(cb)
            _lib.hyperdht_suspend_logged(self._handle, cb, None)
        else:
            _lib.hyperdht_suspend(self._handle)

    def resume(self, log: Callable | None = None) -> None:
        """Resume the DHT."""
        if log:
            @LOG_CB
            def cb(msg, ud):
                log(msg.decode() if msg else "")

            self._callbacks.append(cb)
            _lib.hyperdht_resume_logged(self._handle, cb, None)
        else:
            _lib.hyperdht_resume(self._handle)

    # -- State --

    @property
    def is_online(self) -> bool:
        return bool(_lib.hyperdht_is_online(self._handle))

    @property
    def is_degraded(self) -> bool:
        return bool(_lib.hyperdht_is_degraded(self._handle))

    @property
    def is_destroyed(self) -> bool:
        return bool(_lib.hyperdht_is_destroyed(self._handle))

    @property
    def is_persistent(self) -> bool:
        return bool(_lib.hyperdht_is_persistent(self._handle))

    @property
    def is_bootstrapped(self) -> bool:
        return bool(_lib.hyperdht_is_bootstrapped(self._handle))

    @property
    def is_suspended(self) -> bool:
        return bool(_lib.hyperdht_is_suspended(self._handle))

    @property
    def remote_address(self) -> Address | None:
        """Public address from NAT sampling, or None if unknown."""
        host_buf = ctypes.create_string_buffer(46)
        port = ctypes.c_uint16()
        rc = _lib.hyperdht_remote_address(
            self._handle, host_buf, ctypes.byref(port))
        if rc != 0:
            return None
        return Address(host_buf.value.decode(), port.value)

    @property
    def punch_stats(self) -> PunchStats:
        return PunchStats(
            consistent=_lib.hyperdht_punch_stats_consistent(self._handle),
            random=_lib.hyperdht_punch_stats_random(self._handle),
            open=_lib.hyperdht_punch_stats_open(self._handle),
        )

    @property
    def relay_stats(self) -> RelayStats:
        return RelayStats(
            attempts=_lib.hyperdht_relay_stats_attempts(self._handle),
            successes=_lib.hyperdht_relay_stats_successes(self._handle),
            aborts=_lib.hyperdht_relay_stats_aborts(self._handle),
        )

    # -- Events --

    def on_bootstrapped(self, callback: Callable) -> None:
        """Register callback for bootstrap completion."""
        @EVENT_CB
        def cb(ud):
            callback()

        self._callbacks.append(cb)
        _lib.hyperdht_on_bootstrapped(self._handle, cb, None)

    def on_network_change(self, callback: Callable) -> None:
        @EVENT_CB
        def cb(ud):
            callback()

        self._callbacks.append(cb)
        _lib.hyperdht_on_network_change(self._handle, cb, None)

    def on_network_update(self, callback: Callable) -> None:
        @EVENT_CB
        def cb(ud):
            callback()

        self._callbacks.append(cb)
        _lib.hyperdht_on_network_update(self._handle, cb, None)

    def on_persistent(self, callback: Callable) -> None:
        @EVENT_CB
        def cb(ud):
            callback()

        self._callbacks.append(cb)
        _lib.hyperdht_on_persistent(self._handle, cb, None)

    # -- Connect --

    def connect(
        self,
        remote_public_key: bytes,
        on_done: Callable,
        *,
        keypair: KeyPair | None = None,
        relay_through: bytes | None = None,
        relay_keep_alive_ms: int = 0,
        fast_open: bool = True,
        local_connection: bool = True,
    ) -> None:
        """Connect to a peer by public key."""
        if len(remote_public_key) != 32:
            raise ValueError("remote_public_key must be 32 bytes")

        pk = (ctypes.c_uint8 * 32)(*remote_public_key)

        @CONNECT_CB
        def cb(error, conn_ptr, ud):
            if error != 0:
                on_done(error, None)
            else:
                on_done(0, Connection(conn_ptr.contents))

        self._callbacks.append(cb)

        has_opts = (
            keypair is not None
            or relay_through is not None
            or relay_keep_alive_ms != 0
            or not fast_open
            or not local_connection
        )

        if has_opts:
            c_opts = _ConnectOpts()
            _lib.hyperdht_connect_opts_default(ctypes.byref(c_opts))

            c_kp = None
            if keypair is not None:
                c_kp = keypair._to_c()
                c_opts.keypair = ctypes.pointer(c_kp)

            relay_arr = None
            if relay_through is not None:
                if len(relay_through) != 32:
                    raise ValueError("relay_through must be 32 bytes")
                relay_arr = (ctypes.c_uint8 * 32)(*relay_through)
                c_opts.relay_through = relay_arr

            c_opts.relay_keep_alive_ms = relay_keep_alive_ms
            c_opts.fast_open = 1 if fast_open else 0
            c_opts.local_connection = 1 if local_connection else 0

            self._callbacks.extend([c_kp, relay_arr])
            rc = _lib.hyperdht_connect_ex(
                self._handle, pk, ctypes.byref(c_opts), cb, None)
        else:
            rc = _lib.hyperdht_connect(self._handle, pk, cb, None)

        if rc != 0:
            raise RuntimeError(f"connect failed: {rc}")

    def connect_stream(
        self,
        remote_public_key: bytes,
        on_open: Callable | None = None,
        on_data: Callable | None = None,
        on_close: Callable | None = None,
        on_error: Callable | None = None,
        **connect_kwargs,
    ) -> PendingStream:
        """Connect and open encrypted stream in one call."""
        pending = PendingStream()

        def _on_connect(error, conn):
            if error != 0:
                if on_error:
                    on_error(error)
                return

            def _on_stream_open():
                pending._flush_pending()
                if on_open:
                    on_open(pending.stream)

            stream = self.open_stream(
                conn,
                on_open=_on_stream_open,
                on_data=on_data,
                on_close=on_close,
            )
            pending.stream = stream

        self.connect(remote_public_key, _on_connect, **connect_kwargs)
        return pending

    # -- Server --

    def create_server(self) -> Server:
        """Create a server instance."""
        handle = _lib.hyperdht_server_create(self._handle)
        if not handle:
            raise RuntimeError("Failed to create server")
        return Server(handle, self)

    # -- Stream --

    def open_stream(
        self,
        connection: Connection,
        on_open: Callable | None = None,
        on_data: Callable | None = None,
        on_close: Callable | None = None,
    ) -> Stream:
        """Open encrypted stream over a connection."""
        @CLOSE_CB
        def open_cb(ud):
            if on_open:
                on_open()

        @DATA_CB
        def data_cb(data_ptr, length, ud):
            if on_data and data_ptr and length > 0:
                on_data(bytes(data_ptr[:length]))

        @CLOSE_CB
        def close_cb(ud):
            if on_close:
                on_close()

        # Store callbacks on the DHT instance, not the Stream — the C
        # library fires close_cb asynchronously after stream.close(), and
        # the Stream object may be GC'd before that callback fires.
        cbs = [open_cb, data_cb, close_cb]
        self._callbacks.extend(cbs)

        handle = _lib.hyperdht_stream_open(
            self._handle, ctypes.byref(connection._c_conn),
            open_cb, data_cb, close_cb, None)
        if not handle:
            raise RuntimeError("Failed to open stream")

        stream = Stream(handle, self)
        stream._on_open = open_cb
        stream._on_data = data_cb
        stream._on_close = close_cb
        return stream

    # -- DHT queries --

    def find_peer(
        self,
        public_key: bytes,
        on_reply: Callable | None = None,
        on_done: Callable | None = None,
    ) -> None:
        """Find a peer by public key."""
        if len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        pk = (ctypes.c_uint8 * 32)(*public_key)
        reply_cb, done_cb = self._make_query_cbs(on_reply, on_done)
        rc = _lib.hyperdht_find_peer(
            self._handle, pk, reply_cb, done_cb, None)
        if rc != 0:
            raise RuntimeError(f"find_peer failed: {rc}")

    def find_peer_ex(
        self,
        public_key: bytes,
        on_reply: Callable | None = None,
        on_done: Callable | None = None,
    ) -> Query:
        """Find a peer, returning a cancelable Query handle."""
        if len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        pk = (ctypes.c_uint8 * 32)(*public_key)
        reply_cb, done_cb = self._make_query_cbs(on_reply, on_done)
        handle = _lib.hyperdht_find_peer_ex(
            self._handle, pk, reply_cb, done_cb, None)
        if not handle:
            raise RuntimeError("find_peer_ex failed")
        return Query(handle)

    def lookup(
        self,
        target: bytes,
        on_reply: Callable | None = None,
        on_done: Callable | None = None,
    ) -> None:
        """Look up a target hash on the DHT."""
        if len(target) != 32:
            raise ValueError("target must be 32 bytes")
        t = (ctypes.c_uint8 * 32)(*target)
        reply_cb, done_cb = self._make_query_cbs(on_reply, on_done)
        rc = _lib.hyperdht_lookup(
            self._handle, t, reply_cb, done_cb, None)
        if rc != 0:
            raise RuntimeError(f"lookup failed: {rc}")

    def lookup_ex(
        self,
        target: bytes,
        on_reply: Callable | None = None,
        on_done: Callable | None = None,
    ) -> Query:
        """Look up, returning a cancelable Query handle."""
        if len(target) != 32:
            raise ValueError("target must be 32 bytes")
        t = (ctypes.c_uint8 * 32)(*target)
        reply_cb, done_cb = self._make_query_cbs(on_reply, on_done)
        handle = _lib.hyperdht_lookup_ex(
            self._handle, t, reply_cb, done_cb, None)
        if not handle:
            raise RuntimeError("lookup_ex failed")
        return Query(handle)

    def announce(
        self,
        target: bytes,
        value: bytes,
        on_done: Callable | None = None,
    ) -> None:
        """Announce on the DHT."""
        if len(target) != 32:
            raise ValueError("target must be 32 bytes")
        t = (ctypes.c_uint8 * 32)(*target)
        buf = (ctypes.c_uint8 * len(value))(*value)

        @DONE_CB
        def cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.append(cb)
        rc = _lib.hyperdht_announce(
            self._handle, t, buf, len(value), cb, None)
        if rc != 0:
            raise RuntimeError(f"announce failed: {rc}")

    def unannounce(
        self,
        public_key: bytes,
        keypair: KeyPair,
        on_done: Callable | None = None,
    ) -> None:
        """Remove announcement from the DHT."""
        if len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        pk = (ctypes.c_uint8 * 32)(*public_key)
        c_kp = keypair._to_c()

        @DONE_CB
        def cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.append(cb)
        rc = _lib.hyperdht_unannounce(
            self._handle, pk, ctypes.byref(c_kp), cb, None)
        _lib.hyperdht_keypair_zero(ctypes.byref(c_kp))
        if rc != 0:
            raise RuntimeError(f"unannounce failed: {rc}")

    # -- Storage --

    def immutable_put(
        self, value: bytes, on_done: Callable | None = None,
    ) -> None:
        """Store an immutable value (target = BLAKE2b(value))."""
        buf = (ctypes.c_uint8 * len(value))(*value)

        @DONE_CB
        def cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.append(cb)
        rc = _lib.hyperdht_immutable_put(
            self._handle, buf, len(value), cb, None)
        if rc != 0:
            raise RuntimeError(f"immutable_put failed: {rc}")

    def immutable_get(
        self,
        target: bytes,
        on_value: Callable | None = None,
        on_done: Callable | None = None,
    ) -> None:
        """Retrieve an immutable value by hash."""
        if len(target) != 32:
            raise ValueError("target must be 32 bytes")
        t = (ctypes.c_uint8 * 32)(*target)

        @VALUE_CB
        def val_cb(value_ptr, length, ud):
            if on_value and value_ptr and length > 0:
                on_value(bytes(value_ptr[:length]))

        @DONE_CB
        def done_cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.extend([val_cb, done_cb])
        rc = _lib.hyperdht_immutable_get(
            self._handle, t, val_cb, done_cb, None)
        if rc != 0:
            raise RuntimeError(f"immutable_get failed: {rc}")

    def immutable_get_ex(
        self,
        target: bytes,
        on_value: Callable | None = None,
        on_done: Callable | None = None,
    ) -> Query:
        """Cancelable immutable_get."""
        if len(target) != 32:
            raise ValueError("target must be 32 bytes")
        t = (ctypes.c_uint8 * 32)(*target)

        @VALUE_CB
        def val_cb(value_ptr, length, ud):
            if on_value and value_ptr and length > 0:
                on_value(bytes(value_ptr[:length]))

        @DONE_CB
        def done_cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.extend([val_cb, done_cb])
        handle = _lib.hyperdht_immutable_get_ex(
            self._handle, t, val_cb, done_cb, None)
        if not handle:
            raise RuntimeError("immutable_get_ex failed")
        return Query(handle)

    def mutable_put(
        self,
        keypair: KeyPair,
        value: bytes,
        seq: int,
        on_done: Callable | None = None,
    ) -> None:
        """Store a signed mutable value."""
        c_kp = keypair._to_c()
        buf = (ctypes.c_uint8 * len(value))(*value)

        @DONE_CB
        def cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.append(cb)
        rc = _lib.hyperdht_mutable_put(
            self._handle, ctypes.byref(c_kp),
            buf, len(value), seq, cb, None)
        _lib.hyperdht_keypair_zero(ctypes.byref(c_kp))
        if rc != 0:
            raise RuntimeError(f"mutable_put failed: {rc}")

    def mutable_get(
        self,
        public_key: bytes,
        min_seq: int = 0,
        on_value: Callable | None = None,
        on_done: Callable | None = None,
    ) -> None:
        """Retrieve a signed mutable value."""
        if len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        pk = (ctypes.c_uint8 * 32)(*public_key)

        @MUTABLE_CB
        def val_cb(seq, value_ptr, length, sig_ptr, ud):
            if on_value and value_ptr and length > 0:
                on_value(seq, bytes(value_ptr[:length]), bytes(sig_ptr[:64]))

        @DONE_CB
        def done_cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.extend([val_cb, done_cb])
        rc = _lib.hyperdht_mutable_get(
            self._handle, pk, min_seq, val_cb, done_cb, None)
        if rc != 0:
            raise RuntimeError(f"mutable_get failed: {rc}")

    def mutable_get_ex(
        self,
        public_key: bytes,
        min_seq: int = 0,
        on_value: Callable | None = None,
        on_done: Callable | None = None,
    ) -> Query:
        """Cancelable mutable_get."""
        if len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        pk = (ctypes.c_uint8 * 32)(*public_key)

        @MUTABLE_CB
        def val_cb(seq, value_ptr, length, sig_ptr, ud):
            if on_value and value_ptr and length > 0:
                on_value(seq, bytes(value_ptr[:length]), bytes(sig_ptr[:64]))

        @DONE_CB
        def done_cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.extend([val_cb, done_cb])
        handle = _lib.hyperdht_mutable_get_ex(
            self._handle, pk, min_seq, val_cb, done_cb, None)
        if not handle:
            raise RuntimeError("mutable_get_ex failed")
        return Query(handle)

    # -- Utilities --

    @staticmethod
    def hash(data: bytes) -> bytes:
        """BLAKE2b-256 hash."""
        out = (ctypes.c_uint8 * 32)()
        buf = (ctypes.c_uint8 * len(data))(*data)
        _lib.hyperdht_hash(buf, len(data), out)
        return bytes(out)

    def add_node(self, host: str, port: int) -> None:
        """Add a node to the routing table."""
        rc = _lib.hyperdht_add_node(self._handle, host.encode(), port)
        if rc != 0:
            raise RuntimeError(f"add_node failed: {rc}")

    def to_array(self, cap: int = 256) -> list[Address]:
        """Snapshot the routing table as (host, port) pairs."""
        hosts = ctypes.create_string_buffer(cap * HOST_STRIDE)
        ports = (ctypes.c_uint16 * cap)()
        n = _lib.hyperdht_to_array(self._handle, hosts, ports, cap)
        result: list[Address] = []
        for i in range(n):
            offset = i * HOST_STRIDE
            host = hosts[offset:offset + HOST_STRIDE]
            host = host.split(b"\x00")[0].decode()
            result.append(Address(host, ports[i]))
        return result

    def ping(
        self, host: str, port: int, on_done: Callable | None = None,
    ) -> None:
        """Ping a peer directly (UDP round-trip)."""
        @PING_CB
        def cb(success, ud):
            if on_done:
                on_done(bool(success))

        self._callbacks.append(cb)
        rc = _lib.hyperdht_ping(self._handle, host.encode(), port, cb, None)
        if rc != 0:
            raise RuntimeError(f"ping failed: {rc}")

    # -- FD polling (integrate external sockets into libuv) --

    def poll_start(
        self, fd: int, callback: Callable, readable: bool = True,
        writable: bool = False,
    ) -> ctypes.c_void_p:
        """Watch a file descriptor on the event loop. Returns a poll handle.
        Call poll_stop(handle) when done. The callback receives (fd, events)."""
        events = 0
        if readable:
            events |= POLL_READABLE
        if writable:
            events |= POLL_WRITABLE

        @POLL_CB
        def cb(fd_val, ev, ud):
            callback(fd_val, ev)

        self._callbacks.append(cb)
        handle = _lib.hyperdht_poll_start(self._handle, fd, events, cb, None)
        if not handle:
            raise RuntimeError("poll_start failed")
        return handle

    @staticmethod
    def poll_stop(handle: ctypes.c_void_p) -> None:
        """Stop watching a file descriptor."""
        if handle:
            _lib.hyperdht_poll_stop(handle)

    # -- Private helpers --

    def _make_query_cbs(self, on_reply, on_done):
        """Build and retain PEER_CB + DONE_CB for query methods."""
        @PEER_CB
        def reply_cb(value_ptr, length, host, port, ud):
            if on_reply and value_ptr and length > 0:
                on_reply(bytes(value_ptr[:length]), host.decode(), port)

        @DONE_CB
        def done_cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.extend([reply_cb, done_cb])
        return reply_cb, done_cb
