"""
Low-level ctypes declarations for libhyperdht + libuv.

This module contains ONLY C-level plumbing:
  - Library loading
  - C struct mirrors
  - Callback type definitions
  - Function signature declarations
  - Constants

Python-friendly wrappers live in ``_bindings.py``.
"""

import ctypes
import ctypes.util
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

def _find_lib(name: str, so_name: str) -> str:
    """Find a shared library by searching common locations."""
    env_path = os.environ.get(f"{name.upper()}_LIB")
    if env_path and os.path.exists(env_path):
        return env_path

    for d in os.environ.get("LD_LIBRARY_PATH", "").split(":"):
        p = os.path.join(d, so_name)
        if os.path.exists(p):
            return p

    found = ctypes.util.find_library(name)
    if found:
        return found

    for rel in ["../../../build-shared", "../../../build"]:
        p = Path(__file__).parent / rel / so_name
        if p.exists():
            return str(p)

    return so_name


lib = ctypes.CDLL(_find_lib("hyperdht", "libhyperdht.so"))
uv = ctypes.CDLL(_find_lib("uv", "libuv.so.1"))


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PK_SIZE = 32
HOST_STRIDE = 46

FIREWALL_UNKNOWN = 0
FIREWALL_OPEN = 1
FIREWALL_CONSISTENT = 2
FIREWALL_RANDOM = 3

ERR_OK = 0
ERR_DESTROYED = -1
ERR_PEER_NOT_FOUND = -2
ERR_CONNECTION_FAILED = -3
ERR_NO_ADDRESSES = -4
ERR_HOLEPUNCH_FAILED = -5
ERR_HOLEPUNCH_TIMEOUT = -6
ERR_RELAY_FAILED = -7
ERR_CANCELLED = -8


# ---------------------------------------------------------------------------
# C struct types
# ---------------------------------------------------------------------------

class Keypair(ctypes.Structure):
    _fields_ = [
        ("public_key", ctypes.c_uint8 * 32),
        ("secret_key", ctypes.c_uint8 * 64),
    ]


class Opts(ctypes.Structure):
    """Mirror of hyperdht_opts_t — layout must match the C header exactly."""
    _fields_ = [
        ("port", ctypes.c_uint16),
        ("ephemeral", ctypes.c_int),
        ("use_public_bootstrap", ctypes.c_int),
        ("connection_keep_alive", ctypes.c_uint64),
        ("seed", ctypes.c_uint8 * 32),
        ("seed_is_set", ctypes.c_int),
        ("_pad0", ctypes.c_uint32),
        ("host", ctypes.c_char_p),
        ("nodes", ctypes.POINTER(ctypes.c_char_p)),
        ("nodes_len", ctypes.c_size_t),
    ]


class ConnectOpts(ctypes.Structure):
    """Mirror of hyperdht_connect_opts_t."""
    _fields_ = [
        ("keypair", ctypes.POINTER(Keypair)),
        ("relay_through", ctypes.POINTER(ctypes.c_uint8)),
        ("relay_keep_alive_ms", ctypes.c_uint64),
        ("fast_open", ctypes.c_int),
        ("local_connection", ctypes.c_int),
    ]


class Connection(ctypes.Structure):
    """Mirror of hyperdht_connection_t."""
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
        ("raw_stream", ctypes.c_void_p),
        ("udx_socket", ctypes.c_void_p),
        ("_internal", ctypes.c_void_p),
    ]


# ---------------------------------------------------------------------------
# Callback types
# ---------------------------------------------------------------------------

CONNECT_CB = ctypes.CFUNCTYPE(
    None, ctypes.c_int, ctypes.POINTER(Connection), ctypes.c_void_p)
CONNECTION_CB = ctypes.CFUNCTYPE(
    None, ctypes.POINTER(Connection), ctypes.c_void_p)
CLOSE_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
FIREWALL_CB = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_char_p,
    ctypes.c_uint16, ctypes.c_void_p)
VALUE_CB = ctypes.CFUNCTYPE(
    None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_void_p)
MUTABLE_CB = ctypes.CFUNCTYPE(
    None, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_void_p)
DONE_CB = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p)
DATA_CB = ctypes.CFUNCTYPE(
    None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_void_p)
EVENT_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
PEER_CB = ctypes.CFUNCTYPE(
    None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_uint16, ctypes.c_void_p)
LOG_CB = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_void_p)
HOLEPUNCH_CB = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32,
    ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
FIREWALL_ASYNC_CB = ctypes.CFUNCTYPE(
    None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_char_p,
    ctypes.c_uint16, ctypes.c_void_p, ctypes.c_void_p)
PING_CB = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p)


# ---------------------------------------------------------------------------
# Function signatures — Keypair
# ---------------------------------------------------------------------------

lib.hyperdht_keypair_generate.argtypes = [ctypes.POINTER(Keypair)]
lib.hyperdht_keypair_generate.restype = None

lib.hyperdht_keypair_from_seed.argtypes = [
    ctypes.POINTER(Keypair), ctypes.POINTER(ctypes.c_uint8)]
lib.hyperdht_keypair_from_seed.restype = None

# ---------------------------------------------------------------------------
# Function signatures — Lifecycle
# ---------------------------------------------------------------------------

lib.hyperdht_opts_default.argtypes = [ctypes.POINTER(Opts)]
lib.hyperdht_opts_default.restype = None

lib.hyperdht_create.argtypes = [ctypes.c_void_p, ctypes.POINTER(Opts)]
lib.hyperdht_create.restype = ctypes.c_void_p

lib.hyperdht_bind.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
lib.hyperdht_bind.restype = ctypes.c_int

lib.hyperdht_port.argtypes = [ctypes.c_void_p]
lib.hyperdht_port.restype = ctypes.c_uint16

lib.hyperdht_is_destroyed.argtypes = [ctypes.c_void_p]
lib.hyperdht_is_destroyed.restype = ctypes.c_int

lib.hyperdht_destroy.argtypes = [ctypes.c_void_p, CLOSE_CB, ctypes.c_void_p]
lib.hyperdht_destroy.restype = None

lib.hyperdht_destroy_force.argtypes = [ctypes.c_void_p, CLOSE_CB, ctypes.c_void_p]
lib.hyperdht_destroy_force.restype = None

lib.hyperdht_free.argtypes = [ctypes.c_void_p]
lib.hyperdht_free.restype = None

lib.hyperdht_default_keypair.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(Keypair)]
lib.hyperdht_default_keypair.restype = None

# ---------------------------------------------------------------------------
# Function signatures — State
# ---------------------------------------------------------------------------

lib.hyperdht_is_online.argtypes = [ctypes.c_void_p]
lib.hyperdht_is_online.restype = ctypes.c_int

lib.hyperdht_is_degraded.argtypes = [ctypes.c_void_p]
lib.hyperdht_is_degraded.restype = ctypes.c_int

lib.hyperdht_is_persistent.argtypes = [ctypes.c_void_p]
lib.hyperdht_is_persistent.restype = ctypes.c_int

lib.hyperdht_is_bootstrapped.argtypes = [ctypes.c_void_p]
lib.hyperdht_is_bootstrapped.restype = ctypes.c_int

lib.hyperdht_is_suspended.argtypes = [ctypes.c_void_p]
lib.hyperdht_is_suspended.restype = ctypes.c_int

# ---------------------------------------------------------------------------
# Function signatures — Events
# ---------------------------------------------------------------------------

lib.hyperdht_on_bootstrapped.argtypes = [
    ctypes.c_void_p, EVENT_CB, ctypes.c_void_p]
lib.hyperdht_on_bootstrapped.restype = None

lib.hyperdht_on_network_change.argtypes = [
    ctypes.c_void_p, EVENT_CB, ctypes.c_void_p]
lib.hyperdht_on_network_change.restype = None

lib.hyperdht_on_network_update.argtypes = [
    ctypes.c_void_p, EVENT_CB, ctypes.c_void_p]
lib.hyperdht_on_network_update.restype = None

lib.hyperdht_on_persistent.argtypes = [
    ctypes.c_void_p, EVENT_CB, ctypes.c_void_p]
lib.hyperdht_on_persistent.restype = None

# ---------------------------------------------------------------------------
# Function signatures — Connect
# ---------------------------------------------------------------------------

lib.hyperdht_connect.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    CONNECT_CB, ctypes.c_void_p]
lib.hyperdht_connect.restype = ctypes.c_int

lib.hyperdht_connect_opts_default.argtypes = [ctypes.POINTER(ConnectOpts)]
lib.hyperdht_connect_opts_default.restype = None

lib.hyperdht_connect_ex.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ConnectOpts), CONNECT_CB, ctypes.c_void_p]
lib.hyperdht_connect_ex.restype = ctypes.c_int

lib.hyperdht_connect_relay.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64,
    CONNECT_CB, ctypes.c_void_p]
lib.hyperdht_connect_relay.restype = None

# ---------------------------------------------------------------------------
# Function signatures — Server
# ---------------------------------------------------------------------------

lib.hyperdht_server_create.argtypes = [ctypes.c_void_p]
lib.hyperdht_server_create.restype = ctypes.c_void_p

lib.hyperdht_server_listen.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(Keypair),
    CONNECTION_CB, ctypes.c_void_p]
lib.hyperdht_server_listen.restype = ctypes.c_int

lib.hyperdht_server_close.argtypes = [
    ctypes.c_void_p, CLOSE_CB, ctypes.c_void_p]
lib.hyperdht_server_close.restype = None

lib.hyperdht_server_close_force.argtypes = [
    ctypes.c_void_p, CLOSE_CB, ctypes.c_void_p]
lib.hyperdht_server_close_force.restype = None

lib.hyperdht_server_refresh.argtypes = [ctypes.c_void_p]
lib.hyperdht_server_refresh.restype = None

lib.hyperdht_server_set_firewall.argtypes = [
    ctypes.c_void_p, FIREWALL_CB, ctypes.c_void_p]
lib.hyperdht_server_set_firewall.restype = None

lib.hyperdht_server_set_firewall_async.argtypes = [
    ctypes.c_void_p, FIREWALL_ASYNC_CB, ctypes.c_void_p]
lib.hyperdht_server_set_firewall_async.restype = None

lib.hyperdht_firewall_done.argtypes = [ctypes.c_void_p, ctypes.c_int]
lib.hyperdht_firewall_done.restype = None

lib.hyperdht_server_set_holepunch.argtypes = [
    ctypes.c_void_p, HOLEPUNCH_CB, ctypes.c_void_p]
lib.hyperdht_server_set_holepunch.restype = None

lib.hyperdht_server_suspend.argtypes = [ctypes.c_void_p]
lib.hyperdht_server_suspend.restype = None

lib.hyperdht_server_resume.argtypes = [ctypes.c_void_p]
lib.hyperdht_server_resume.restype = None

lib.hyperdht_server_suspend_logged.argtypes = [
    ctypes.c_void_p, LOG_CB, ctypes.c_void_p]
lib.hyperdht_server_suspend_logged.restype = None

lib.hyperdht_server_notify_online.argtypes = [ctypes.c_void_p]
lib.hyperdht_server_notify_online.restype = None

lib.hyperdht_server_is_listening.argtypes = [ctypes.c_void_p]
lib.hyperdht_server_is_listening.restype = ctypes.c_int

lib.hyperdht_server_public_key.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8)]
lib.hyperdht_server_public_key.restype = ctypes.c_int

lib.hyperdht_server_on_listening.argtypes = [
    ctypes.c_void_p, EVENT_CB, ctypes.c_void_p]
lib.hyperdht_server_on_listening.restype = None

lib.hyperdht_server_address.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint16)]
lib.hyperdht_server_address.restype = ctypes.c_int

lib.hyperdht_server_set_relay_through.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64]
lib.hyperdht_server_set_relay_through.restype = None

# ---------------------------------------------------------------------------
# Function signatures — DHT queries
# ---------------------------------------------------------------------------

lib.hyperdht_find_peer.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    PEER_CB, DONE_CB, ctypes.c_void_p]
lib.hyperdht_find_peer.restype = ctypes.c_int

lib.hyperdht_lookup.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    PEER_CB, DONE_CB, ctypes.c_void_p]
lib.hyperdht_lookup.restype = ctypes.c_int

lib.hyperdht_announce.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    DONE_CB, ctypes.c_void_p]
lib.hyperdht_announce.restype = ctypes.c_int

lib.hyperdht_unannounce.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(Keypair), DONE_CB, ctypes.c_void_p]
lib.hyperdht_unannounce.restype = ctypes.c_int

lib.hyperdht_find_peer_ex.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    PEER_CB, DONE_CB, ctypes.c_void_p]
lib.hyperdht_find_peer_ex.restype = ctypes.c_void_p

lib.hyperdht_lookup_ex.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    PEER_CB, DONE_CB, ctypes.c_void_p]
lib.hyperdht_lookup_ex.restype = ctypes.c_void_p

# ---------------------------------------------------------------------------
# Function signatures — Storage
# ---------------------------------------------------------------------------

lib.hyperdht_immutable_put.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    DONE_CB, ctypes.c_void_p]
lib.hyperdht_immutable_put.restype = ctypes.c_int

lib.hyperdht_immutable_get.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    VALUE_CB, DONE_CB, ctypes.c_void_p]
lib.hyperdht_immutable_get.restype = ctypes.c_int

lib.hyperdht_mutable_put.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(Keypair),
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint64,
    DONE_CB, ctypes.c_void_p]
lib.hyperdht_mutable_put.restype = ctypes.c_int

lib.hyperdht_mutable_get.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64,
    MUTABLE_CB, DONE_CB, ctypes.c_void_p]
lib.hyperdht_mutable_get.restype = ctypes.c_int

lib.hyperdht_immutable_get_ex.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
    VALUE_CB, DONE_CB, ctypes.c_void_p]
lib.hyperdht_immutable_get_ex.restype = ctypes.c_void_p

lib.hyperdht_mutable_get_ex.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64,
    MUTABLE_CB, DONE_CB, ctypes.c_void_p]
lib.hyperdht_mutable_get_ex.restype = ctypes.c_void_p

# ---------------------------------------------------------------------------
# Function signatures — Query handle
# ---------------------------------------------------------------------------

lib.hyperdht_query_cancel.argtypes = [ctypes.c_void_p]
lib.hyperdht_query_cancel.restype = None

lib.hyperdht_query_free.argtypes = [ctypes.c_void_p]
lib.hyperdht_query_free.restype = None

# ---------------------------------------------------------------------------
# Function signatures — Stream
# ---------------------------------------------------------------------------

lib.hyperdht_stream_open.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(Connection),
    CLOSE_CB, DATA_CB, CLOSE_CB, ctypes.c_void_p]
lib.hyperdht_stream_open.restype = ctypes.c_void_p

lib.hyperdht_stream_write.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
lib.hyperdht_stream_write.restype = ctypes.c_int

lib.hyperdht_stream_close.argtypes = [ctypes.c_void_p]
lib.hyperdht_stream_close.restype = None

lib.hyperdht_stream_is_open.argtypes = [ctypes.c_void_p]
lib.hyperdht_stream_is_open.restype = ctypes.c_int

# ---------------------------------------------------------------------------
# Function signatures — DHT lifecycle (suspend / resume)
# ---------------------------------------------------------------------------

lib.hyperdht_suspend.argtypes = [ctypes.c_void_p]
lib.hyperdht_suspend.restype = None

lib.hyperdht_resume.argtypes = [ctypes.c_void_p]
lib.hyperdht_resume.restype = None

lib.hyperdht_suspend_logged.argtypes = [
    ctypes.c_void_p, LOG_CB, ctypes.c_void_p]
lib.hyperdht_suspend_logged.restype = None

lib.hyperdht_resume_logged.argtypes = [
    ctypes.c_void_p, LOG_CB, ctypes.c_void_p]
lib.hyperdht_resume_logged.restype = None

# ---------------------------------------------------------------------------
# Function signatures — DHT misc
# ---------------------------------------------------------------------------

lib.hyperdht_hash.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8)]
lib.hyperdht_hash.restype = None

lib.hyperdht_connection_keep_alive.argtypes = [ctypes.c_void_p]
lib.hyperdht_connection_keep_alive.restype = ctypes.c_uint64

lib.hyperdht_to_array.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint16), ctypes.c_size_t]
lib.hyperdht_to_array.restype = ctypes.c_size_t

lib.hyperdht_add_node.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint16]
lib.hyperdht_add_node.restype = ctypes.c_int

lib.hyperdht_remote_address.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint16)]
lib.hyperdht_remote_address.restype = ctypes.c_int

# ---------------------------------------------------------------------------
# Function signatures — Stats
# ---------------------------------------------------------------------------

lib.hyperdht_punch_stats_consistent.argtypes = [ctypes.c_void_p]
lib.hyperdht_punch_stats_consistent.restype = ctypes.c_int

lib.hyperdht_punch_stats_random.argtypes = [ctypes.c_void_p]
lib.hyperdht_punch_stats_random.restype = ctypes.c_int

lib.hyperdht_punch_stats_open.argtypes = [ctypes.c_void_p]
lib.hyperdht_punch_stats_open.restype = ctypes.c_int

lib.hyperdht_relay_stats_attempts.argtypes = [ctypes.c_void_p]
lib.hyperdht_relay_stats_attempts.restype = ctypes.c_int

lib.hyperdht_relay_stats_successes.argtypes = [ctypes.c_void_p]
lib.hyperdht_relay_stats_successes.restype = ctypes.c_int

lib.hyperdht_relay_stats_aborts.argtypes = [ctypes.c_void_p]
lib.hyperdht_relay_stats_aborts.restype = ctypes.c_int

# ---------------------------------------------------------------------------
# Function signatures — Ping
# ---------------------------------------------------------------------------

lib.hyperdht_ping.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint16,
    PING_CB, ctypes.c_void_p]
lib.hyperdht_ping.restype = ctypes.c_int

# ---------------------------------------------------------------------------
# libuv
# ---------------------------------------------------------------------------

uv.uv_loop_init.argtypes = [ctypes.c_void_p]
uv.uv_loop_init.restype = ctypes.c_int

uv.uv_run.argtypes = [ctypes.c_void_p, ctypes.c_int]
uv.uv_run.restype = ctypes.c_int

uv.uv_loop_close.argtypes = [ctypes.c_void_p]
uv.uv_loop_close.restype = ctypes.c_int

uv.uv_loop_size.argtypes = []
uv.uv_loop_size.restype = ctypes.c_size_t

UV_RUN_DEFAULT = 0
UV_RUN_ONCE = 1
UV_RUN_NOWAIT = 2
