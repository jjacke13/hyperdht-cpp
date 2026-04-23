/* libuv-esp32 shim — handle lifecycle (close, ref, active checks). */

#include "internal.h"

int uv_is_active(const uv_handle_t* handle) {
  return uv__is_active(handle);
}

int uv_is_closing(const uv_handle_t* handle) {
  return uv__is_closing(handle);
}

void uv_ref(uv_handle_t* handle) {
  if (!(handle->flags & UV_HANDLE_REF)) {
    handle->flags |= UV_HANDLE_REF;
    if (handle->flags & UV_HANDLE_ACTIVE)
      handle->loop->active_handles++;
  }
}

void uv_unref(uv_handle_t* handle) {
  if (handle->flags & UV_HANDLE_REF) {
    handle->flags &= ~UV_HANDLE_REF;
    if (handle->flags & UV_HANDLE_ACTIVE)
      handle->loop->active_handles--;
  }
}

int uv_has_ref(const uv_handle_t* handle) {
  return (handle->flags & UV_HANDLE_REF) != 0;
}

/* Type-specific close dispatch. Sets CLOSING, queues for callback. */
void uv_close(uv_handle_t* handle, uv_close_cb close_cb) {
  if (handle->flags & (UV_HANDLE_CLOSING | UV_HANDLE_CLOSED))
    return;

  handle->close_cb = close_cb;
  handle->flags |= UV_HANDLE_CLOSING;

  /* Type-specific cleanup */
  switch (handle->type) {
    case UV_TIMER:
      uv_timer_stop((uv_timer_t*)handle);
      break;
    case UV_PREPARE:
      uv_prepare_stop((uv_prepare_t*)handle);
      break;
    case UV_UDP: {
      uv_udp_t* udp = (uv_udp_t*)handle;
      uv_udp_recv_stop(udp);
      /* Do NOT close the fd here — defer to the close callback.
       * libudx may still have pending send/recv operations referencing
       * this fd. Real libuv also defers fd close to uv__finish_close. */
      break;
    }
    case UV_ASYNC:
    case UV_POLL:
    case UV_CHECK:
    case UV_IDLE:
      break;
    default:
      break;
  }

  /* Deactivate */
  if (handle->flags & UV_HANDLE_ACTIVE) {
    handle->flags &= ~UV_HANDLE_ACTIVE;
    if (handle->flags & UV_HANDLE_REF)
      handle->loop->active_handles--;
  }
  handle->flags &= ~UV_HANDLE_REF;

  /* Queue for close callback on next loop iteration */
  handle->next_closing = handle->loop->closing_handles;
  handle->loop->closing_handles = handle;
}

int uv_fileno(const uv_handle_t* handle, uv_os_fd_t* fd) {
  if (uv__is_closing(handle))
    return UV_EBADF;

  switch (handle->type) {
    case UV_UDP:
      *fd = ((const uv_udp_t*)handle)->io_watcher.fd;
      return *fd >= 0 ? 0 : UV_EBADF;
    default:
      return UV_EINVAL;
  }
}

int uv_send_buffer_size(uv_handle_t* handle, int* value) {
  uv_os_fd_t os_fd;
  if (uv_fileno(handle, &os_fd) != 0)
    return UV_EBADF;
  int fd = (int)os_fd;

  if (*value == 0) {
    /* Query: try getsockopt, fall back to a reasonable default */
    socklen_t len = sizeof(*value);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, value, &len) != 0)
      *value = 65536;  /* lwIP doesn't always support SO_SNDBUF query */
  } else {
    /* Set: try setsockopt, ignore failure (lwIP manages its own buffers) */
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, value, sizeof(*value));
  }
  return 0;
}

int uv_recv_buffer_size(uv_handle_t* handle, int* value) {
  uv_os_fd_t os_fd;
  if (uv_fileno(handle, &os_fd) != 0)
    return UV_EBADF;
  int fd = (int)os_fd;

  if (*value == 0) {
    socklen_t len = sizeof(*value);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, value, &len) != 0)
      *value = 65536;
  } else {
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, value, sizeof(*value));
  }
  return 0;
}

size_t uv_handle_size(uv_handle_type type) {
  switch (type) {
    case UV_ASYNC:   return sizeof(uv_async_t);
    case UV_CHECK:   return sizeof(uv_check_t);
    case UV_IDLE:    return sizeof(uv_idle_t);
    case UV_POLL:    return sizeof(uv_poll_t);
    case UV_PREPARE: return sizeof(uv_prepare_t);
    case UV_TIMER:   return sizeof(uv_timer_t);
    case UV_UDP:     return sizeof(uv_udp_t);
    default:         return 0;
  }
}

const char* uv_handle_type_name(uv_handle_type type) {
  switch (type) {
    case UV_ASYNC:   return "async";
    case UV_CHECK:   return "check";
    case UV_IDLE:    return "idle";
    case UV_POLL:    return "poll";
    case UV_PREPARE: return "prepare";
    case UV_TIMER:   return "timer";
    case UV_UDP:     return "udp";
    default:         return "unknown";
  }
}
