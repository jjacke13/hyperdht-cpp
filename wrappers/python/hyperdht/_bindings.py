"""
Low-level ctypes bindings to libhyperdht.so + libuv.so.
"""

import ctypes
import ctypes.util
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

def _find_lib(name, so_name):
    """Find a shared library by searching common locations."""
    # 1. Environment variable
    env_path = os.environ.get(f"{name.upper()}_LIB")
    if env_path and os.path.exists(env_path):
        return env_path

    # 2. LD_LIBRARY_PATH
    for d in os.environ.get("LD_LIBRARY_PATH", "").split(":"):
        p = os.path.join(d, so_name)
        if os.path.exists(p):
            return p

    # 3. System
    found = ctypes.util.find_library(name)
    if found:
        return found

    # 4. Relative to this file (for development)
    for rel in ["../../../build-shared", "../../../build"]:
        p = Path(__file__).parent / rel / so_name
        if p.exists():
            return str(p)

    return so_name  # Let ctypes try


_lib = ctypes.CDLL(_find_lib("hyperdht", "libhyperdht.so"))
_uv = ctypes.CDLL(_find_lib("uv", "libuv.so.1"))


# ---------------------------------------------------------------------------
# C types
# ---------------------------------------------------------------------------

class _Keypair(ctypes.Structure):
    _fields_ = [
        ("public_key", ctypes.c_uint8 * 32),
        ("secret_key", ctypes.c_uint8 * 64),
    ]


class _Opts(ctypes.Structure):
    _fields_ = [
        ("port", ctypes.c_uint16),
        ("ephemeral", ctypes.c_int),
    ]


class _Connection(ctypes.Structure):
    _fields_ = [
        ("remote_public_key", ctypes.c_uint8 * 32),
        ("tx_key", ctypes.c_uint8 * 32),
        ("rx_key", ctypes.c_uint8 * 32),
        ("handshake_hash", ctypes.c_uint8 * 64),
        ("remote_udx_id", ctypes.c_uint32),
        ("local_udx_id", ctypes.c_uint32),
        ("peer_host", ctypes.c_char * 46),
        ("peer_port", ctypes.c_uint16),
        ("is_initiator", ctypes.c_int),
    ]


# Callback types
_CONNECT_CB = ctypes.CFUNCTYPE(
    None, ctypes.c_int, ctypes.POINTER(_Connection), ctypes.c_void_p)
_CONNECTION_CB = ctypes.CFUNCTYPE(
    None, ctypes.POINTER(_Connection), ctypes.c_void_p)
_CLOSE_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
_FIREWALL_CB = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_char_p,
    ctypes.c_uint16, ctypes.c_void_p)
_VALUE_CB = ctypes.CFUNCTYPE(
    None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_void_p)
_MUTABLE_CB = ctypes.CFUNCTYPE(
    None, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_void_p)
_DONE_CB = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p)


# ---------------------------------------------------------------------------
# Function signatures
# ---------------------------------------------------------------------------

# Keypair
_lib.hyperdht_keypair_generate.argtypes = [ctypes.POINTER(_Keypair)]
_lib.hyperdht_keypair_generate.restype = None

_lib.hyperdht_keypair_from_seed.argtypes = [
    ctypes.POINTER(_Keypair), ctypes.POINTER(ctypes.c_uint8)]
_lib.hyperdht_keypair_from_seed.restype = None

# Lifecycle
_lib.hyperdht_create.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Opts)]
_lib.hyperdht_create.restype = ctypes.c_void_p

_lib.hyperdht_bind.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
_lib.hyperdht_bind.restype = ctypes.c_int

_lib.hyperdht_port.argtypes = [ctypes.c_void_p]
_lib.hyperdht_port.restype = ctypes.c_uint16

_lib.hyperdht_is_destroyed.argtypes = [ctypes.c_void_p]
_lib.hyperdht_is_destroyed.restype = ctypes.c_int

_lib.hyperdht_destroy.argtypes = [ctypes.c_void_p, _CLOSE_CB, ctypes.c_void_p]
_lib.hyperdht_destroy.restype = None

_lib.hyperdht_free.argtypes = [ctypes.c_void_p]
_lib.hyperdht_free.restype = None

_lib.hyperdht_default_keypair.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(_Keypair)]
_lib.hyperdht_default_keypair.restype = None

# Connect
_lib.hyperdht_connect.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), _CONNECT_CB, ctypes.c_void_p]
_lib.hyperdht_connect.restype = ctypes.c_int

# Server
_lib.hyperdht_server_create.argtypes = [ctypes.c_void_p]
_lib.hyperdht_server_create.restype = ctypes.c_void_p

_lib.hyperdht_server_listen.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(_Keypair), _CONNECTION_CB, ctypes.c_void_p]
_lib.hyperdht_server_listen.restype = ctypes.c_int

_lib.hyperdht_server_close.argtypes = [ctypes.c_void_p, _CLOSE_CB, ctypes.c_void_p]
_lib.hyperdht_server_close.restype = None

_lib.hyperdht_server_refresh.argtypes = [ctypes.c_void_p]
_lib.hyperdht_server_refresh.restype = None

_lib.hyperdht_server_set_firewall.argtypes = [
    ctypes.c_void_p, _FIREWALL_CB, ctypes.c_void_p]
_lib.hyperdht_server_set_firewall.restype = None

# Storage
_lib.hyperdht_immutable_put.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    _DONE_CB, ctypes.c_void_p]
_lib.hyperdht_immutable_put.restype = ctypes.c_int

_lib.hyperdht_immutable_get.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    _VALUE_CB, _DONE_CB, ctypes.c_void_p]
_lib.hyperdht_immutable_get.restype = ctypes.c_int

_lib.hyperdht_mutable_put.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(_Keypair),
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint64,
    _DONE_CB, ctypes.c_void_p]
_lib.hyperdht_mutable_put.restype = ctypes.c_int

_lib.hyperdht_mutable_get.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64,
    _MUTABLE_CB, _DONE_CB, ctypes.c_void_p]
_lib.hyperdht_mutable_get.restype = ctypes.c_int

# Stream
_DATA_CB = ctypes.CFUNCTYPE(
    None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_void_p)

_lib.hyperdht_stream_open.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(_Connection),
    _CLOSE_CB, _DATA_CB, _CLOSE_CB, ctypes.c_void_p]
_lib.hyperdht_stream_open.restype = ctypes.c_void_p

_lib.hyperdht_stream_write.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
_lib.hyperdht_stream_write.restype = ctypes.c_int

_lib.hyperdht_stream_close.argtypes = [ctypes.c_void_p]
_lib.hyperdht_stream_close.restype = None

_lib.hyperdht_stream_is_open.argtypes = [ctypes.c_void_p]
_lib.hyperdht_stream_is_open.restype = ctypes.c_int

# libuv
_uv.uv_loop_init.argtypes = [ctypes.c_void_p]
_uv.uv_loop_init.restype = ctypes.c_int

_uv.uv_run.argtypes = [ctypes.c_void_p, ctypes.c_int]
_uv.uv_run.restype = ctypes.c_int

_uv.uv_loop_close.argtypes = [ctypes.c_void_p]
_uv.uv_loop_close.restype = ctypes.c_int

_uv.uv_loop_size.argtypes = []
_uv.uv_loop_size.restype = ctypes.c_size_t

UV_RUN_DEFAULT = 0
UV_RUN_ONCE = 1
UV_RUN_NOWAIT = 2


# ---------------------------------------------------------------------------
# Python-friendly classes
# ---------------------------------------------------------------------------

class Connection:
    """Represents an established encrypted connection."""

    def __init__(self, c_conn):
        self._c_conn = _Connection()
        ctypes.memmove(ctypes.byref(self._c_conn), ctypes.byref(c_conn),
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

    def __repr__(self):
        return (f"Connection(peer={self.peer_host}:{self.peer_port}, "
                f"key={self.remote_key[:8].hex()}...)")


class Stream:
    """Encrypted read/write stream over an established connection."""

    def __init__(self, handle, dht):
        self._handle = handle
        self._dht = dht
        self._callbacks = []
        self._on_data = None
        self._on_close = None
        self._on_open = None

    @property
    def is_open(self):
        if not self._handle:
            return False
        return bool(_lib.hyperdht_stream_is_open(self._handle))

    def write(self, data: bytes):
        """Write data to the encrypted stream."""
        if not self._handle:
            raise RuntimeError("Stream is closed")
        buf = (ctypes.c_uint8 * len(data))(*data)
        rc = _lib.hyperdht_stream_write(self._handle, buf, len(data))
        if rc != 0:
            raise RuntimeError(f"stream_write failed: {rc}")

    def close(self):
        """Close the stream."""
        if self._handle:
            _lib.hyperdht_stream_close(self._handle)
            self._handle = None


class KeyPair:
    """Ed25519 keypair for HyperDHT identity."""

    def __init__(self, public_key: bytes, secret_key: bytes):
        if len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        if len(secret_key) != 64:
            raise ValueError("secret_key must be 64 bytes")
        self.public_key = public_key
        self.secret_key = secret_key

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generate a random keypair."""
        kp = _Keypair()
        _lib.hyperdht_keypair_generate(ctypes.byref(kp))
        return cls(bytes(kp.public_key), bytes(kp.secret_key))

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        """Generate a deterministic keypair from a 32-byte seed."""
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        kp = _Keypair()
        seed_arr = (ctypes.c_uint8 * 32)(*seed)
        _lib.hyperdht_keypair_from_seed(ctypes.byref(kp), seed_arr)
        return cls(bytes(kp.public_key), bytes(kp.secret_key))

    def _to_c(self):
        kp = _Keypair()
        ctypes.memmove(kp.public_key, self.public_key, 32)
        ctypes.memmove(kp.secret_key, self.secret_key, 64)
        return kp

    def __repr__(self):
        return f"KeyPair(pk={self.public_key[:8].hex()}...)"


class Server:
    """HyperDHT server — listens for incoming connections."""

    def __init__(self, handle, dht):
        self._handle = handle
        self._dht = dht  # prevent GC
        self._cb = None  # prevent GC of callback

    def listen(self, keypair: KeyPair, on_connection):
        """
        Start listening for connections.

        Args:
            keypair: KeyPair to listen on (determines the server's public key)
            on_connection: callable(Connection) — called for each connection
        """
        c_kp = keypair._to_c()

        @_CONNECTION_CB
        def cb(conn_ptr, ud):
            if conn_ptr:
                conn = Connection(conn_ptr.contents)
                on_connection(conn)

        self._cb = cb  # prevent GC
        rc = _lib.hyperdht_server_listen(self._handle, ctypes.byref(c_kp), cb, None)
        if rc != 0:
            raise RuntimeError(f"server_listen failed: {rc}")

    def set_firewall(self, callback):
        """
        Set firewall callback. Return True to reject, False to accept.

        Args:
            callback: callable(remote_pk: bytes, host: str, port: int) → bool
        """
        @_FIREWALL_CB
        def cb(pk_ptr, host, port, ud):
            remote_pk = bytes(pk_ptr[:32])
            reject = callback(remote_pk, host.decode(), port)
            return 1 if reject else 0

        self._firewall_cb = cb
        _lib.hyperdht_server_set_firewall(self._handle, cb, None)

    def close(self):
        """Stop listening and unannounce."""
        _lib.hyperdht_server_close(self._handle, _CLOSE_CB(0), None)
        self._handle = None

    def refresh(self):
        """Force re-announcement."""
        if self._handle:
            _lib.hyperdht_server_refresh(self._handle)


class HyperDHT:
    """
    HyperDHT node — connect to peers, listen for connections, store data.

    Usage:
        dht = HyperDHT()
        dht.bind()
        print(f"Port: {dht.port}")

        # ... set up connect/listen callbacks ...

        dht.run()      # Blocks until all operations complete
        dht.destroy()
    """

    def __init__(self, port=0, ephemeral=True):
        # Allocate uv_loop
        loop_size = _uv.uv_loop_size()
        self._loop_buf = (ctypes.c_uint8 * loop_size)()
        self._loop = ctypes.cast(self._loop_buf, ctypes.c_void_p)
        _uv.uv_loop_init(self._loop)

        # Create DHT
        opts = _Opts(port=port, ephemeral=1 if ephemeral else 0)
        self._handle = _lib.hyperdht_create(self._loop, ctypes.byref(opts))
        if not self._handle:
            raise RuntimeError("Failed to create HyperDHT instance")

        self._callbacks = []  # prevent GC

    def bind(self, port=0):
        """Bind the UDP socket."""
        rc = _lib.hyperdht_bind(self._handle, port)
        if rc != 0:
            raise RuntimeError(f"bind failed: {rc}")

    @property
    def port(self) -> int:
        """Get the bound port."""
        return _lib.hyperdht_port(self._handle)

    @property
    def default_keypair(self) -> KeyPair:
        """Get the auto-generated default keypair."""
        kp = _Keypair()
        _lib.hyperdht_default_keypair(self._handle, ctypes.byref(kp))
        return KeyPair(bytes(kp.public_key), bytes(kp.secret_key))

    def connect(self, remote_public_key: bytes, on_done):
        """
        Connect to a peer by public key.

        Args:
            remote_public_key: 32-byte Ed25519 public key
            on_done: callable(error: int, connection: Connection or None)
        """
        if len(remote_public_key) != 32:
            raise ValueError("remote_public_key must be 32 bytes")

        pk = (ctypes.c_uint8 * 32)(*remote_public_key)

        @_CONNECT_CB
        def cb(error, conn_ptr, ud):
            if error != 0:
                on_done(error, None)
            else:
                conn = Connection(conn_ptr.contents)
                on_done(0, conn)

        self._callbacks.append(cb)
        rc = _lib.hyperdht_connect(self._handle, pk, cb, None)
        if rc != 0:
            raise RuntimeError(f"connect failed: {rc}")

    def create_server(self) -> Server:
        """Create a server instance."""
        handle = _lib.hyperdht_server_create(self._handle)
        if not handle:
            raise RuntimeError("Failed to create server")
        return Server(handle, self)

    def open_stream(self, connection: Connection, on_open=None,
                    on_data=None, on_close=None) -> Stream:
        """
        Open an encrypted read/write stream over a connection.

        Args:
            connection: Connection from connect() or server listen callback
            on_open: callable() — stream is ready for read/write
            on_data: callable(data: bytes) — received decrypted data
            on_close: callable() — stream closed
        """
        @_CLOSE_CB
        def open_cb(ud):
            if on_open:
                on_open()

        @_DATA_CB
        def data_cb(data_ptr, length, ud):
            if on_data and data_ptr and length > 0:
                on_data(bytes(data_ptr[:length]))

        @_CLOSE_CB
        def close_cb(ud):
            if on_close:
                on_close()

        handle = _lib.hyperdht_stream_open(
            self._handle, ctypes.byref(connection._c_conn),
            open_cb, data_cb, close_cb, None)

        if not handle:
            raise RuntimeError("Failed to open stream")

        stream = Stream(handle, self)
        stream._on_open = open_cb      # prevent GC
        stream._on_data = data_cb
        stream._on_close = close_cb
        return stream

    def immutable_put(self, value: bytes, on_done=None):
        """Store an immutable value (target = BLAKE2b(value))."""
        buf = (ctypes.c_uint8 * len(value))(*value)

        @_DONE_CB
        def cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.append(cb)
        rc = _lib.hyperdht_immutable_put(self._handle, buf, len(value), cb, None)
        if rc != 0:
            raise RuntimeError(f"immutable_put failed: {rc}")

    def immutable_get(self, target: bytes, on_value=None, on_done=None):
        """Retrieve an immutable value by hash."""
        if len(target) != 32:
            raise ValueError("target must be 32 bytes")
        t = (ctypes.c_uint8 * 32)(*target)

        @_VALUE_CB
        def val_cb(value_ptr, length, ud):
            if on_value and value_ptr and length > 0:
                on_value(bytes(value_ptr[:length]))

        @_DONE_CB
        def done_cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.extend([val_cb, done_cb])
        rc = _lib.hyperdht_immutable_get(self._handle, t, val_cb, done_cb, None)
        if rc != 0:
            raise RuntimeError(f"immutable_get failed: {rc}")

    def mutable_put(self, keypair: KeyPair, value: bytes, seq: int, on_done=None):
        """Store a signed mutable value."""
        c_kp = keypair._to_c()
        buf = (ctypes.c_uint8 * len(value))(*value)

        @_DONE_CB
        def cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.append(cb)
        rc = _lib.hyperdht_mutable_put(
            self._handle, ctypes.byref(c_kp), buf, len(value), seq, cb, None)
        if rc != 0:
            raise RuntimeError(f"mutable_put failed: {rc}")

    def mutable_get(self, public_key: bytes, min_seq=0, on_value=None, on_done=None):
        """Retrieve a signed mutable value."""
        if len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        pk = (ctypes.c_uint8 * 32)(*public_key)

        @_MUTABLE_CB
        def val_cb(seq, value_ptr, length, sig_ptr, ud):
            if on_value and value_ptr and length > 0:
                on_value(seq, bytes(value_ptr[:length]), bytes(sig_ptr[:64]))

        @_DONE_CB
        def done_cb(error, ud):
            if on_done:
                on_done(error)

        self._callbacks.extend([val_cb, done_cb])
        rc = _lib.hyperdht_mutable_get(
            self._handle, pk, min_seq, val_cb, done_cb, None)
        if rc != 0:
            raise RuntimeError(f"mutable_get failed: {rc}")

    def run(self, mode="default"):
        """Run the libuv event loop. Blocks until all operations complete."""
        modes = {"default": UV_RUN_DEFAULT, "once": UV_RUN_ONCE, "nowait": UV_RUN_NOWAIT}
        _uv.uv_run(self._loop, modes.get(mode, UV_RUN_DEFAULT))

    def destroy(self):
        """Destroy the instance and free all resources."""
        if self._handle:
            _lib.hyperdht_destroy(self._handle, _CLOSE_CB(0), None)
            _uv.uv_run(self._loop, UV_RUN_DEFAULT)
            _lib.hyperdht_free(self._handle)
            self._handle = None
        _uv.uv_loop_close(self._loop)
