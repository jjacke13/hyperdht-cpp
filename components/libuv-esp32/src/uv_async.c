/* libuv-esp32 shim — async handle (cross-thread wakeup).
 *
 * Uses eventfd on ESP-IDF (via VFS), or on Linux (for host testing).
 * uv_async_send() is the one function safe to call from any thread/task.
 */

#include "internal.h"

#if defined(ESP_PLATFORM)
#include <esp_vfs_eventfd.h>
#elif defined(__linux__)
#include <sys/eventfd.h>
#endif

/* Initialize the loop's wakeup mechanism (called once per loop).
 * Lazily called on first uv_async_init(). */
static int uv__async_init_loop(uv_loop_t* loop) {
  if (loop->wakeup_fd >= 0)
    return 0;  /* Already initialized */

#if defined(ESP_PLATFORM)
  loop->wakeup_fd = eventfd(0, 0);
#elif defined(__linux__)
  loop->wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
#else
  return UV_ENOSYS;
#endif

  if (loop->wakeup_fd < 0)
    return uv__translate_errno(errno);

  return 0;
}

int uv_async_init(uv_loop_t* loop, uv_async_t* handle, uv_async_cb cb) {
  int rc = uv__async_init_loop(loop);
  if (rc != 0) return rc;

  uv__handle_init(loop, (uv_handle_t*)handle, UV_ASYNC);
  handle->async_cb = cb;
  handle->pending = 0;
  uv__queue_init(&handle->queue);
  uv__queue_insert_tail(&loop->async_handles, &handle->queue);
  uv__handle_start((uv_handle_t*)handle);
  return 0;
}

/* Thread-safe: can be called from any FreeRTOS task or ISR. */
int uv_async_send(uv_async_t* handle) {
  /* Atomically set pending flag */
  handle->pending = 1;

  /* Wake the select() loop */
  if (handle->loop->wakeup_fd >= 0) {
    uint64_t val = 1;
    ssize_t r = write(handle->loop->wakeup_fd, &val, sizeof(val));
    (void)r;
  }

  return 0;
}
