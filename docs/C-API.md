# C API Reference

Header: [`include/hyperdht/hyperdht.h`](../include/hyperdht/hyperdht.h) (76 functions, heavily commented)

The header is the authoritative reference. This page covers the patterns and conventions.

## Conventions

- All functions are `extern "C"` with `HYPERDHT_API` visibility
- Every async callback takes `void* userdata`
- Single-threaded: call all functions from the `uv_loop_t` thread
- Error codes: 0 = success, negative = error
- Pointers: non-NULL = success, NULL = failure
- Ownership: `_create` / `_free` pairs for owned handles

## Opaque types

| Type | Created by | Freed by |
|------|-----------|----------|
| `hyperdht_t` | `hyperdht_create()` | `hyperdht_destroy()` + `uv_run()` + `hyperdht_free()` |
| `hyperdht_server_t` | `hyperdht_server_create()` | Owned by `hyperdht_t`, closed via `hyperdht_server_close()` |
| `hyperdht_stream_t` | `hyperdht_stream_open()` | `hyperdht_stream_close()` |
| `hyperdht_query_t` | `*_ex()` variants | `hyperdht_query_free()` |
| `hyperdht_firewall_done_t` | Passed to async firewall cb | `hyperdht_firewall_done()` |

## API surface (76 functions)

| Category | Functions |
|----------|----------|
| **Keypair** (2) | `keypair_generate`, `keypair_from_seed` |
| **Lifecycle** (8) | `opts_default`, `create`, `bind`, `port`, `is_destroyed`, `destroy`, `destroy_force`, `free`, `default_keypair` |
| **State** (5) | `is_online`, `is_degraded`, `is_persistent`, `is_bootstrapped`, `is_suspended` |
| **Events** (4) | `on_bootstrapped`, `on_network_change`, `on_network_update`, `on_persistent` |
| **Connect** (4) | `connect`, `connect_opts_default`, `connect_ex`, `connect_relay` |
| **Server** (15) | `server_create`, `server_listen`, `server_close`, `server_close_force`, `server_refresh`, `server_set_firewall`, `server_set_firewall_async`, `firewall_done`, `server_set_holepunch`, `server_suspend`, `server_resume`, `server_suspend_logged`, `server_notify_online`, `server_is_listening`, `server_public_key`, `server_on_listening`, `server_address`, `server_set_relay_through` |
| **Queries** (8) | `find_peer`, `find_peer_ex`, `lookup`, `lookup_ex`, `announce`, `unannounce`, `query_cancel`, `query_free` |
| **Storage** (8) | `immutable_put`, `immutable_get`, `immutable_get_ex`, `mutable_put`, `mutable_get`, `mutable_get_ex` |
| **Streams** (4) | `stream_open`, `stream_write`, `stream_close`, `stream_is_open` |
| **Lifecycle ext** (4) | `suspend`, `resume`, `suspend_logged`, `resume_logged` |
| **Misc** (6) | `hash`, `connection_keep_alive`, `to_array`, `add_node`, `remote_address`, `ping` |
| **Stats** (6) | `punch_stats_consistent`, `punch_stats_random`, `punch_stats_open`, `relay_stats_attempts`, `relay_stats_successes`, `relay_stats_aborts` |

## Constants

```c
HYPERDHT_PK_SIZE           32
HYPERDHT_HOST_STRIDE       46
HYPERDHT_FIREWALL_UNKNOWN   0
HYPERDHT_FIREWALL_OPEN      1
HYPERDHT_FIREWALL_CONSISTENT 2
HYPERDHT_FIREWALL_RANDOM    3
HYPERDHT_ERR_DESTROYED     -1
HYPERDHT_ERR_PEER_NOT_FOUND -2
HYPERDHT_ERR_CANCELLED     -8
```

## Threading rules

All calls must happen on the `uv_loop_t` thread. No exceptions -- even `hyperdht_firewall_done()` must be marshaled back via `uv_async_send()` if your policy check runs on a worker thread.

## Query handle lifecycle

Handles from `_ex` variants (`find_peer_ex`, `lookup_ex`, `immutable_get_ex`, `mutable_get_ex`):

1. `on_done` fires exactly once (completion or cancel)
2. Handle remains valid after `on_done` -- you still need `hyperdht_query_free()`
3. `cancel` + `free` in any order is safe
4. `free` before completion detaches the callback (silent no-op on late completion)

## Language bindings

The C FFI is designed for cross-language use:

- **Python**: `wrappers/python/` -- ctypes bindings, 76 functions exposed
- **Kotlin/Swift**: explicit struct padding (`_pad0`), stride constants, completion callbacks
- **Any language with C FFI**: opaque pointers + callbacks, no C++ symbols exposed

See [JS-MAPPING.md](JS-MAPPING.md) for the full name translation table.
