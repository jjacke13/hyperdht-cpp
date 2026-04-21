# ESP32 Implementation Plan

**Goal:** Run hyperdht-cpp on ESP32-S3 (FreeRTOS + lwIP) as a full peer —
connect, listen, announce, store, holepunch. No cloud broker, no relay
server.

**Last updated:** 2026-04-21

---

## 1. Architecture

```
┌─────────────────────────────────────────────────┐
│  User application (FreeRTOS task)               │
│    xTaskCreatePinnedToCore(dht_task, ...)        │
├─────────────────────────────────────────────────┤
│  hyperdht C FFI  (hyperdht.h — UNCHANGED)       │
├─────────────────────────────────────────────────┤
│  hyperdht-cpp    (src/*.cpp — UNCHANGED)         │
├─────────────────────────────────────────────────┤
│  libudx          (deps/libudx — UNCHANGED)       │
├─────────────────────────────────────────────────┤
│  libuv-esp32 shim  ← NEW (~600 lines C)         │
│    implements libuv subset on FreeRTOS + lwIP    │
├─────────────────────────────────────────────────┤
│  libsodium       (ESP-IDF component, upstream)   │
├─────────────────────────────────────────────────┤
│  FreeRTOS + lwIP + esp_timer  (ESP-IDF v5.5+)   │
└─────────────────────────────────────────────────┘
```

**Key principle: nothing above the shim changes.** libudx, hyperdht-cpp,
and the C FFI compile unmodified. The shim is a drop-in replacement for
libuv that implements only the ~40 functions libudx + hyperdht-cpp call.

The only addition to hyperdht-cpp is a `HYPERDHT_EMBEDDED` compile flag
that reduces sizing constants (routing table, congestion window, buffers).
It does NOT remove features or add `#ifdef` to protocol logic.

---

## 2. libuv API Surface — Complete Audit

Combined audit of libudx + hyperdht-cpp. Every function the shim must
implement.

### Critical path (must be correct and fast)

| Function | Called by | Notes |
|---|---|---|
| `uv_now` | libudx (28×), hyperdht | Returns `loop->time` (cached ms). HOT PATH — BBR, RTT, pacing |
| `uv_timer_init` | libudx, hyperdht | ~5 timers per stream + RPC timers |
| `uv_timer_start` | libudx, hyperdht | Min-heap insert. HOT PATH |
| `uv_timer_stop` | libudx, hyperdht | Min-heap remove. HOT PATH |
| `uv_timer_get_due_in` | libudx | TLP/RTO scheduling |
| `uv_timer_again` | hyperdht | SecretStream keepalive refresh |
| `uv_udp_init` | libudx | Create lwIP UDP socket |
| `uv_udp_bind` | libudx | Bind socket |
| `uv_udp_send` | libudx | Async send (queued, callback on completion) |
| `uv_udp_try_send` | libudx | Sync sendto() — fast path, no queue |
| `uv_udp_recv_start` | libudx | Register alloc_cb + recv_cb, add to select() |
| `uv_buf_init` | libudx, hyperdht | Trivial: `{base, len}` |
| `uv_close` | libudx, hyperdht | Set CLOSING, queue for next iteration |
| `uv_is_active` | libudx, hyperdht | Check flags |
| `uv_is_closing` | hyperdht | Check flags |
| `uv_prepare_init` | libudx | Packet assembly batching |
| `uv_prepare_start` | libudx | Register prepare callback |
| `uv_prepare_stop` | libudx | Unregister |
| `uv_run` | caller | Main loop: timers → prepare → select() → I/O → closing |
| `uv_stop` | caller/tests | Set `stop_flag` |

### Init / config (called once or rarely)

| Function | Called by | Notes |
|---|---|---|
| `uv_loop_init` | caller | Init queues, heap, eventfd |
| `uv_loop_close` | caller | Cleanup |
| `uv_udp_getsockname` | libudx, hyperdht | Get bound port after bind(0) |
| `uv_udp_set_ttl` | libudx | `setsockopt(IP_TTL)` |
| `uv_send_buffer_size` | libudx | `setsockopt(SO_SNDBUF)` |
| `uv_recv_buffer_size` | libudx | `setsockopt(SO_RCVBUF)` |
| `uv_fileno` | libudx | Return fd from UDP handle |
| `uv_unref` | hyperdht | GC timer shouldn't keep loop alive |
| `uv_ip4_addr` | libudx | `inet_pton` wrapper |
| `uv_ip6_addr` | libudx | `inet_pton` wrapper |
| `uv_ip4_name` | libudx | `inet_ntop` wrapper |
| `uv_strerror` | libudx | Error string table |
| `uv_hrtime` | libudx (debug) | `esp_timer_get_time() * 1000` |

### Optional (can stub initially)

| Function | Called by | Stub behavior |
|---|---|---|
| `uv_getaddrinfo` | libudx | `lwip_getaddrinfo` or return `UV_ENOSYS` |
| `uv_freeaddrinfo` | libudx | `lwip_freeaddrinfo` or no-op |
| `uv_interface_addresses` | hyperdht | Enumerate via `esp_netif` |
| `uv_free_interface_addresses` | hyperdht | `free()` |
| `uv_udp_recv_stop` | libudx | Remove from select() set |
| `uv_udp_set_membership` | libudx | Return `UV_ENOSYS` (no multicast needed) |
| `uv_udp_set_source_membership` | libudx | Return `UV_ENOSYS` |
| `uv_udp_set_multicast_loop` | libudx | Return `UV_ENOSYS` |
| `uv_udp_set_multicast_interface` | libudx | Return `UV_ENOSYS` |
| `uv_poll_init` | hyperdht (ffi_stream) | Return `UV_ENOSYS` — ESP32 uses C API directly |
| `uv_poll_start` | hyperdht (ffi_stream) | Return `UV_ENOSYS` |
| `uv_poll_stop` | hyperdht (ffi_stream) | No-op |
| `uv_inet_ntop` | libudx (debug) | `inet_ntop` |

**Total: ~40 functions + ~13 type definitions.**

### CRITICAL: struct layout compatibility

libudx reads `uv_udp_t.send_queue_count` directly (udx.c:2130). The shim's
`uv_udp_t` struct **must** place `send_queue_size` and `send_queue_count`
at the same offsets as real libuv. Strategy: copy libuv's public struct
definitions verbatim from `uv.h`, replacing private fields with our own.

libudx does NOT use libuv's internal QUEUE macros — all access is through
the public API. However, `uv_handle_t` contains a `struct uv__queue
handle_queue` field that the internal lifecycle functions manipulate. The
shim must provide this type.

---

## 3. Shim Internal Design

### Event loop (`uv_run`)

```
uv_run(loop, mode):
    loop->time = esp_timer_get_time() / 1000

    while alive && !stop_flag:
        run_pending_callbacks(loop)
        run_prepare_handles(loop)

        timeout = next_timer_deadline(loop)
        build_fd_set(loop, &readfds, &writefds)
        FD_SET(loop->wakeup_fd, &readfds)       ← eventfd

        select(maxfd+1, &readfds, &writefds, NULL, timeout)

        loop->time = esp_timer_get_time() / 1000
        if FD_ISSET(wakeup_fd): drain_eventfd()
        dispatch_udp_io(loop, &readfds, &writefds)

        run_timers(loop)                          ← min-heap
        run_closing_handles(loop)

        if mode == UV_RUN_ONCE or UV_RUN_NOWAIT: break
```

### Timer heap

Binary min-heap (same as libuv). Each `uv_timer_t` has:
- `timeout` — absolute ms when it fires
- `repeat` — 0 = one-shot, >0 = recurring interval
- `start_id` — tie-breaker from `loop->timer_counter++`

Comparison: `a.timeout < b.timeout`, then `a.start_id < b.start_id`.

libudx creates ~5 timers per stream (RTO, TLP, keepalive, ZWP, pacing)
plus RACK loss detection. With 10 concurrent streams, the heap holds ~60
entries — trivial for a min-heap.

### UDP I/O

- `uv_udp_init`: `socket(AF_INET, SOCK_DGRAM, 0)` + `fcntl(O_NONBLOCK)`
- `uv_udp_bind`: `bind()` + `setsockopt(SO_REUSEADDR)` (needs `CONFIG_LWIP_SO_REUSE=y`)
- `uv_udp_try_send`: `sendto()` — returns bytes sent or `UV_EAGAIN`
- `uv_udp_send`: queue the request, register fd for POLLOUT in next select()
- `uv_udp_recv_start`: store alloc_cb + recv_cb, register fd for POLLIN
- Recv dispatch: `alloc_cb(handle, 65536, &buf)` → `recvfrom()` → `recv_cb(handle, nread, &buf, &addr, 0)`

### Cross-thread wakeup (`uv_async`)

ESP-IDF supports `eventfd` via VFS (since v4.4+). One eventfd per loop,
shared by all async handles:

```c
// Init:
esp_vfs_eventfd_config_t cfg = ESP_VFS_EVENTFD_CONFIG_DEFAULT();
cfg.max_fds = 2;
esp_vfs_eventfd_register(&cfg);
loop->wakeup_fd = eventfd(0, 0);

// Send (from any task — thread-safe):
uint64_t val = 1;
write(async->loop->wakeup_fd, &val, sizeof(val));

// Drain (in event loop after select returns):
uint64_t val;
read(loop->wakeup_fd, &val, sizeof(val));
```

### Network interfaces

```c
int uv_interface_addresses(uv_interface_address_t** addrs, int* count) {
    esp_netif_t* netif = NULL;
    // count interfaces
    while ((netif = esp_netif_next(netif))) n++;
    // allocate + fill from esp_netif_get_ip_info()
}
```

---

## 4. HYPERDHT_EMBEDDED Sizing Constants

A single config header that overrides defaults when `HYPERDHT_EMBEDDED` is
defined. No `#ifdef` in protocol logic — only in constant definitions.

### Constants to override

| Constant | Location | Desktop | Embedded | Rationale |
|---|---|---|---|---|
| `K` (bucket size) | `routing_table.hpp:20` | 20 | 10 | Half the routing entries, still good lookup resolution |
| `DEFAULT_MAX_WINDOW` | `rpc.hpp:33` | 80 | 16 | Smaller congestion window for limited bandwidth |
| `BIRTHDAY_SOCKETS` | `holepunch.hpp:222` | 256 | 8 | lwIP max 10 sockets total; see §5 |

### Implementation approach

```cpp
// include/hyperdht/embedded_config.hpp (NEW file)
#pragma once

#ifdef HYPERDHT_EMBEDDED
  constexpr size_t EMBEDDED_K = 10;
  constexpr size_t EMBEDDED_BUCKETS = 64;
  constexpr int    EMBEDDED_MAX_WINDOW = 16;
  constexpr int    EMBEDDED_BIRTHDAY_SOCKETS = 8;
#endif
```

Each header uses the override if defined:

```cpp
// routing_table.hpp
#ifdef HYPERDHT_EMBEDDED
  constexpr size_t K = 10;
  // ... bucket array uses 64 instead of ID_BITS
#else
  constexpr size_t K = 20;
#endif
```

**Risk to existing builds:** ZERO — `HYPERDHT_EMBEDDED` is only defined
via CMake when targeting ESP32. Desktop builds never see it.

---

## 5. Known ESP32 Constraints

### Birthday-paradox holepunch is limited

Desktop opens 256 UDP sockets for RANDOM+CONSISTENT NAT traversal. ESP-IDF
lwIP defaults to 10 sockets total (`CONFIG_LWIP_MAX_SOCKETS`). Even raised
to 16, we can't do 256.

**Impact:** RANDOM+CONSISTENT holepunch will be weaker (8 sockets instead
of 256). This only matters when the ESP32 is behind a RANDOM NAT and the
remote peer is behind a CONSISTENT NAT — uncommon for home WiFi routers
(usually CONSISTENT). CONSISTENT+CONSISTENT (the common case) works fine
with a single socket.

**Mitigation:** Set `BIRTHDAY_SOCKETS = 8` under `HYPERDHT_EMBEDDED`.
The blind-relay fallback still works for cases where holepunch fails.

### Memory

| Component | Embedded size |
|---|---|
| Routing table (k=10, 64 buckets) | ~50KB |
| Crypto state per connection | ~2KB |
| UDX buffers per stream | ~16KB |
| Code (.text) + libsodium | ~300KB |
| **Total** | **~400KB** |

ESP32-S3 with 8MB PSRAM has ~8000KB free after WiFi init. No concern.

Task stack: 16KB recommended (networking + libsodium crypto). Allocate
from PSRAM via `heap_caps_malloc(MALLOC_CAP_SPIRAM)`.

### No uv_poll (FFI stream layer)

`ffi_stream.cpp` uses `uv_poll_t` for external fd monitoring. On ESP32,
applications use the C/C++ API directly — not the FFI-over-fd pattern.
These functions return `UV_ENOSYS`. No protocol impact.

### select() overhead

lwIP's `select()` goes through the VFS layer, adding ~133μs per call.
Fine for a DHT ticking at 1ms+ granularity.

---

## 6. File Structure

```
components/
  libuv-esp32/                      ← NEW: ESP-IDF component
    CMakeLists.txt                  ← idf_component_register(...)
    include/
      uv.h                         ← Public API (libuv-compatible signatures)
      uv/                           
        errno.h                    ← UV_E* error codes
        unix.h                     ← Platform types (uv__queue, etc.)
    src/
      uv_loop.c                    ← uv_loop_init, uv_run, uv_loop_close (~120 lines)
      uv_udp.c                     ← UDP socket operations (~150 lines)
      uv_timer.c                   ← Min-heap timer implementation (~100 lines)
      uv_async.c                   ← eventfd-based wakeup (~40 lines)
      uv_prepare.c                 ← Prepare handles (~30 lines)
      uv_handle.c                  ← Handle lifecycle (init/close/ref) (~60 lines)
      uv_misc.c                    ← buf_init, strerror, hrtime, ip4_addr (~80 lines)
      uv_interface.c               ← esp_netif enumeration (~60 lines)
      uv_getaddrinfo.c             ← lwip_getaddrinfo wrapper (~40 lines)
    Kconfig                        ← ESP-IDF menuconfig options (optional)

  hyperdht/                         ← NEW: ESP-IDF component wrapper
    CMakeLists.txt                  ← Links pre-built .a or builds from source
    include/ → ../../include/       ← Symlink to main headers
    Kconfig                         ← HYPERDHT_EMBEDDED toggle
```

**Estimated total: ~680 lines of C** for the libuv shim.

---

## 7. Build System

### CMake: HYPERDHT_EMBEDDED option

Added to the main `CMakeLists.txt`:

```cmake
option(HYPERDHT_EMBEDDED "Reduce sizing constants for embedded targets" OFF)
if(HYPERDHT_EMBEDDED)
    target_compile_definitions(hyperdht PUBLIC HYPERDHT_EMBEDDED=1)
endif()
```

Desktop builds are unaffected. ESP-IDF component sets this flag.

### ESP-IDF component CMakeLists.txt

```cmake
# components/hyperdht/CMakeLists.txt
idf_component_register(
    SRCS "stub.c"            # empty — we link pre-built .a
    INCLUDE_DIRS "include"
    PRIV_REQUIRES libuv-esp32 lwip esp_netif
)

# Option A: pre-built static library (cross-compiled separately)
set(LIB_DIR "${CMAKE_CURRENT_LIST_DIR}/lib/${IDF_TARGET}")
add_prebuilt_library(hyperdht_core "${LIB_DIR}/libhyperdht.a")
add_prebuilt_library(libudx_core "${LIB_DIR}/libudx.a")
target_link_libraries(${COMPONENT_LIB} INTERFACE hyperdht_core libudx_core)

# Option B: build from source (requires C++20)
# add_subdirectory(${HYPERDHT_SRC_DIR} hyperdht_build)
```

### Cross-compilation

Two approaches:

**A. Pre-build with NDK-style toolchain file:**
```bash
cmake -B build-esp32 \
  -DCMAKE_TOOLCHAIN_FILE=toolchains/esp32s3.cmake \
  -DHYPERDHT_EMBEDDED=ON \
  -DHYPERDHT_BUILD_TESTS=OFF \
  -DSODIUM_INCLUDE_DIR=... \
  -DUV_INCLUDE_DIR=components/libuv-esp32/include \
  -DUV_LIBRARY=""  # header-only at compile time, linked by ESP-IDF
```

**B. Build as ESP-IDF component from source:**
The component's CMakeLists.txt adds the hyperdht-cpp sources directly,
with `HYPERDHT_EMBEDDED=ON`. Preferred for development — single build.

---

## 8. Nix Integration

Use `mirrexagon/nixpkgs-esp-dev` (v5.5.2, ESP32-S3 fully supported):

```nix
# flake.nix additions
inputs.nixpkgs-esp-dev.url = "github:mirrexagon/nixpkgs-esp-dev";

devShells.x86_64-linux.esp32 = let
  pkgs = import nixpkgs {
    system = "x86_64-linux";
    overlays = [ nixpkgs-esp-dev.overlays.default ];
    config.permittedInsecurePackages = [ "python3.13-ecdsa-0.19.1" ];
  };
in pkgs.mkShell {
  buildInputs = [ pkgs.esp-idf-xtensa ];  # ESP32-S3 = Xtensa
};
```

Then: `nix develop .#esp32`, `idf.py set-target esp32s3`, `idf.py build`.

### sdkconfig.defaults

```ini
CONFIG_LWIP_SO_REUSE=y
CONFIG_LWIP_MAX_SOCKETS=16
CONFIG_SPIRAM=y
CONFIG_SPIRAM_MODE_OCT=y
CONFIG_SPIRAM_SPEED_80M=y
CONFIG_SPIRAM_USE_MALLOC=y
CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=4096
CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=32768
CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY=y
CONFIG_ESP_MAIN_TASK_STACK_SIZE=4096
```

---

## 9. Existing Work / References

| Project | What we learn |
|---|---|
| **esp32-event** (alxvasilev, ~600 lines) | Validates shim pattern: select() + sorted timers + loopback UDP wakeup. Only covers loop/timer/poll/async — we add UDP, prepare, full handle lifecycle. |
| **Crouton** (couchbaselabs, snej) | Replaced libuv with FreeRTOS+lwIP raw API on ESP32. Confirms the platform works. We stay at the POSIX socket layer (simpler, libudx expects it). |
| **NuttX libuv port** (Apache/Xiaomi, 3986-line patch) | Full libuv on NuttX RTOS. Works because NuttX is POSIX-compliant. FreeRTOS is not — confirms we need a shim, not a port. |
| **libuv discussion #4132** | Maintainers rejected in-tree ESP-IDF support to avoid `#ifdef` soup. Our approach (separate component, not a libuv fork) avoids this entirely. |

---

## 10. Implementation Phases

### Phase 1: libuv-esp32 shim — core (~2 days)

**Files:** `uv_loop.c`, `uv_handle.c`, `uv_timer.c`, `uv_udp.c`, `uv.h`

Implement the critical-path functions:
- Loop: init, run (UV_RUN_DEFAULT + UV_RUN_ONCE), close, stop, now
- Handle: init, close, is_active, is_closing, ref/unref
- Timer: init, start, stop, get_due_in, again (min-heap)
- UDP: init, bind, send, try_send, recv_start, getsockname
- Types: uv_loop_t, uv_handle_t, uv_udp_t, uv_timer_t, uv_buf_t

**Validation:** Compile libudx against the shim headers (type check only —
no hardware needed). Verify struct layout with `static_assert` on
`offsetof(uv_udp_t, send_queue_count)`.

### Phase 2: Prepare + async + misc (~1 day)

**Files:** `uv_prepare.c`, `uv_async.c`, `uv_misc.c`

- Prepare: init, start, stop (libudx packet assembly)
- Async: init, send, close (eventfd-based wakeup)
- Misc: buf_init, strerror, hrtime, ip4_addr, ip6_addr, ip4_name,
  fileno, send/recv_buffer_size, udp_set_ttl

**Validation:** Full libudx + hyperdht-cpp compile against shim (still
host cross-compile, not on device).

### Phase 3: HYPERDHT_EMBEDDED constants (~0.5 day)

**Files:** Modified headers (routing_table.hpp, rpc.hpp, holepunch.hpp),
new `embedded_config.hpp`, CMakeLists.txt option.

- Add `HYPERDHT_EMBEDDED` guards around sizing constants
- Verify desktop build is unaffected (`ctest` passes unchanged)

**Validation:** Build twice — with and without `HYPERDHT_EMBEDDED`. Run
full desktop test suite on the without build. Compile-only on the with
build.

### Phase 4: ESP-IDF integration (~1 day)

**Files:** `components/libuv-esp32/CMakeLists.txt`,
`components/hyperdht/CMakeLists.txt`, `sdkconfig.defaults`,
`main/dht_task.c` (example)

- Register components with ESP-IDF build system
- Cross-compile libhyperdht.a + libudx.a for ESP32-S3
- Link against libsodium (ESP-IDF component from upstream)
- Write minimal `dht_task.c` that creates a DHT node and bootstraps

**Validation:** `idf.py build` succeeds. Flash to device, check serial
output for "bootstrapped" log.

### Phase 5: Interface + DNS (~0.5 day)

**Files:** `uv_interface.c`, `uv_getaddrinfo.c`

- `uv_interface_addresses` via `esp_netif_next()` + `esp_netif_get_ip_info()`
- `uv_getaddrinfo` via `lwip_getaddrinfo()`

**Validation:** Holepunch local address detection works (needed for LAN
connections).

### Phase 6: Live test (~1 day)

- Connect ESP32-S3 to WiFi
- Bootstrap against public DHT nodes
- Connect to a JS HyperDHT echo server
- Send data, verify echo
- Test server mode: listen on ESP32, connect from phone (Kotlin wrapper)

**Validation:** Full echo round-trip ESP32 ↔ JS. Full echo round-trip
phone → ESP32.

### Phase 7: Nix + CI (~0.5 day)

- Add `esp32` devShell to flake.nix
- Add ESP32 build job to CI (compile-only, no hardware)
- Document setup in README

---

## 11. Testing Strategy

### Desktop (no hardware needed)

1. **Struct layout verification** — `static_assert(offsetof(...))` for
   every field libudx accesses directly (send_queue_count, etc.)
2. **Shim unit tests** — timer heap operations, fd_set building, handle
   lifecycle state machine. Run on host with a mock select().
3. **HYPERDHT_EMBEDDED regression** — full `ctest` suite must pass on
   desktop without `HYPERDHT_EMBEDDED`. Compile-only with it.

### On device (ESP32-S3)

4. **Bootstrap test** — create DHT, connect to public bootstrap nodes,
   verify routing table fills
5. **Echo test** — connect to JS echo server, send/receive data
6. **Server test** — listen on ESP32, connect from Kotlin app on phone
7. **Soak test** — keep connection alive for 1+ hour, exchange data
   periodically
8. **Memory monitoring** — `heap_caps_get_free_size()` before/after,
   check for growth over time

---

## 12. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Struct layout mismatch → libudx reads garbage | Medium | CRASH | `static_assert` on field offsets at compile time |
| lwIP select() too slow for BBR pacing | Low | PERF | BBR adapts; 133μs overhead is small vs 1ms+ tick |
| libsodium stack overflow in Noise handshake | Medium | CRASH | 16KB stack from PSRAM; monitor with `uxTaskGetStackHighWaterMark` |
| HYPERDHT_EMBEDDED breaks desktop tests | Low | REGRESSION | CI runs full test suite without the flag |
| WiFi reconnect drops DHT state | Medium | DISCONNECT | Existing suspend/resume API handles this |
| Birthday holepunch too weak with 8 sockets | Medium | CONN FAIL | Blind-relay fallback; most home NATs are CONSISTENT anyway |
| ESP-IDF lwIP bug in UDP | Low | CRASH | lwIP is battle-tested; ESP-IDF v5.5 is stable |

---

## 13. Estimated Effort

| Phase | Effort | Output |
|---|---|---|
| 1. Shim core | 2 days | Loop, timer, UDP, handle lifecycle |
| 2. Prepare + async + misc | 1 day | Full API surface |
| 3. HYPERDHT_EMBEDDED | 0.5 day | Sizing constants |
| 4. ESP-IDF integration | 1 day | Builds + flashes |
| 5. Interface + DNS | 0.5 day | Holepunch support |
| 6. Live test | 1 day | Verified on hardware |
| 7. Nix + CI | 0.5 day | Reproducible build |
| **Total** | **~6.5 days** | |

---

## 14. What Does NOT Change

To be absolutely clear — these files are **not modified**:

- `deps/libudx/` — untouched, compiles against shim headers
- `src/*.cpp` — all protocol logic untouched
- `include/hyperdht/hyperdht.h` — C FFI API unchanged
- `test/` — all tests run unchanged on desktop
- `wrappers/python/` — unchanged
- `wrappers/kotlin/` — unchanged (uses JNI, not ESP-IDF)
- `.github/workflows/build.yml` — desktop/Android CI unchanged

**Modified files** (minimal, guarded):

- `include/hyperdht/routing_table.hpp` — `K` and bucket count behind `#ifdef HYPERDHT_EMBEDDED`
- `include/hyperdht/rpc.hpp` — `DEFAULT_MAX_WINDOW` behind `#ifdef`
- `include/hyperdht/holepunch.hpp` — `BIRTHDAY_SOCKETS` behind `#ifdef`
- `CMakeLists.txt` — add `HYPERDHT_EMBEDDED` option (OFF by default)

**New files:**

- `components/libuv-esp32/` — the shim (~680 lines)
- `components/hyperdht/` — ESP-IDF component wrapper (~50 lines)
- `examples/esp32/` — example app
- `docs/ESP32-IMPLEMENTATION-PLAN.md` — this document
