/* libuv-esp32 shim — internal shared definitions. */

#ifndef UV_ESP32_INTERNAL_H
#define UV_ESP32_INTERNAL_H

#include "uv.h"
#include "queue-inl.h"
#include "heap-inl.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* --- Handle lifecycle helpers --- */

static inline void uv__handle_init(uv_loop_t* loop,
                                   uv_handle_t* h,
                                   uv_handle_type type) {
  h->loop = loop;
  h->type = type;
  h->flags = UV_HANDLE_REF;
  h->close_cb = NULL;
  h->next_closing = NULL;
  h->data = NULL;
  uv__queue_insert_tail(&loop->handle_queue, &h->handle_queue);
  loop->active_handles++;  /* REF'd by default */
}

static inline void uv__handle_start(uv_handle_t* h) {
  if (!(h->flags & UV_HANDLE_ACTIVE)) {
    h->flags |= UV_HANDLE_ACTIVE;
    if (h->flags & UV_HANDLE_REF) {
      /* already counted in active_handles from init */
    }
  }
}

static inline void uv__handle_stop(uv_handle_t* h) {
  if (h->flags & UV_HANDLE_ACTIVE) {
    h->flags &= ~UV_HANDLE_ACTIVE;
  }
}

static inline int uv__is_active(const uv_handle_t* h) {
  return (h->flags & UV_HANDLE_ACTIVE) != 0;
}

static inline int uv__is_closing(const uv_handle_t* h) {
  return (h->flags & (UV_HANDLE_CLOSING | UV_HANDLE_CLOSED)) != 0;
}

/* --- Timer heap comparison --- */

static inline int timer_less_than(const struct heap_node* a,
                                  const struct heap_node* b) {
  const uv_timer_t* ta = HEAP_NODE_DATA(uv_timer_t, node.heap[0], a);
  const uv_timer_t* tb = HEAP_NODE_DATA(uv_timer_t, node.heap[0], b);

  if (ta->timeout < tb->timeout) return 1;
  if (ta->timeout > tb->timeout) return 0;
  return ta->start_id < tb->start_id;
}

/* --- Translate system errno to UV error --- */

static inline int uv__translate_errno(int sys_errno) {
  if (sys_errno == 0) return 0;
  return -sys_errno;
}

/* --- Max fd tracking for select() --- */

/* Maximum number of UDP handles we track for select().
 * ESP-IDF lwIP defaults to 10 sockets; we allow up to 32
 * for safety (raised CONFIG_LWIP_MAX_SOCKETS). */
#define UV_ESP32_MAX_FDS 32

/* Per-loop I/O watcher state — tracks which fds to select() on. */
typedef struct {
  int fd;
  uv_udp_t* handle;
  int events;  /* POLLIN, POLLOUT */
} uv__fd_entry_t;

#endif /* UV_ESP32_INTERNAL_H */
