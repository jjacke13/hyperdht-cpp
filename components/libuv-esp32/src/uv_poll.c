/* libuv-esp32 shim — poll handle stubs.
 * uv_poll_t is used by hyperdht-cpp's ffi_stream.cpp for external fd
 * monitoring. On ESP32, applications use the C/C++ API directly — not
 * the FFI-over-fd pattern. These return UV_ENOSYS. */

#include "internal.h"

int uv_poll_init(uv_loop_t* loop, uv_poll_t* handle, int fd) {
  (void)loop; (void)handle; (void)fd;
  return UV_ENOSYS;
}

int uv_poll_start(uv_poll_t* handle, int events, uv_poll_cb cb) {
  (void)handle; (void)events; (void)cb;
  return UV_ENOSYS;
}

int uv_poll_stop(uv_poll_t* handle) {
  (void)handle;
  return 0;  /* No-op — nothing to stop */
}
