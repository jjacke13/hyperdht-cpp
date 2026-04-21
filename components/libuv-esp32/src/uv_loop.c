/* libuv-esp32 shim — event loop implementation.
 *
 * select()-based I/O multiplexing with min-heap timers.
 * Single-threaded, runs in one FreeRTOS task.
 *
 * Loop phases (matching real libuv):
 *   update_time → run_timers → run_pending → run_prepare
 *   → io_poll (select) → run_timers → run_closing → check alive
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime */

#include "internal.h"

#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

/* --- Platform time --- */

/* On ESP-IDF: esp_timer_get_time() returns microseconds.
 * On Linux (for host testing): clock_gettime(). */
static uint64_t uv__get_time_ms(void) {
#ifdef ESP_PLATFORM
  /* esp_timer_get_time() returns int64_t microseconds, monotonic */
  extern int64_t esp_timer_get_time(void);
  return (uint64_t)(esp_timer_get_time() / 1000);
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

/* --- Loop init/close --- */

int uv_loop_init(uv_loop_t* loop) {
  memset(loop, 0, sizeof(*loop));
  uv__queue_init(&loop->handle_queue);
  uv__queue_init(&loop->pending_queue);
  uv__queue_init(&loop->watcher_queue);
  uv__queue_init(&loop->prepare_handles);
  uv__queue_init(&loop->check_handles);
  uv__queue_init(&loop->idle_handles);
  uv__queue_init(&loop->async_handles);
  heap_init((struct heap*)&loop->timer_heap);
  loop->closing_handles = NULL;
  loop->active_handles = 0;
  loop->stop_flag = 0;
  loop->timer_counter = 0;
  loop->time = uv__get_time_ms();
  loop->wakeup_fd = -1;
  loop->watchers = NULL;
  loop->nwatchers = 0;
  loop->nfds = 0;
  loop->backend_fd = -1;
  loop->flags = 0;
  return 0;
}

int uv_loop_close(uv_loop_t* loop) {
  if (loop->wakeup_fd >= 0) {
    close(loop->wakeup_fd);
    loop->wakeup_fd = -1;
  }
  free(loop->watchers);
  loop->watchers = NULL;
  return 0;
}

void uv_update_time(uv_loop_t* loop) {
  loop->time = uv__get_time_ms();
}

uint64_t uv_now(const uv_loop_t* loop) {
  return loop->time;
}

void uv_stop(uv_loop_t* loop) {
  loop->stop_flag = 1;
}

/* --- Internal: run expired timers --- */

static void uv__run_timers(uv_loop_t* loop) {
  struct heap* timer_heap = (struct heap*)&loop->timer_heap;

  for (;;) {
    struct heap_node* node = heap_min(timer_heap);
    if (node == NULL) break;

    uv_timer_t* handle = HEAP_NODE_DATA(uv_timer_t, node.heap[0], node);
    if (handle->timeout > loop->time) break;

    uv_timer_stop(handle);

    if (handle->repeat != 0)
      uv_timer_start(handle, handle->timer_cb, handle->repeat, handle->repeat);

    handle->timer_cb(handle);
  }
}

/* --- Internal: run prepare handles --- */

static void uv__run_prepare(uv_loop_t* loop) {
  struct uv__queue* q;
  struct uv__queue queue;

  uv__queue_move(&loop->prepare_handles, &queue);
  while (!uv__queue_empty(&queue)) {
    q = uv__queue_head(&queue);
    uv__queue_remove(q);
    uv__queue_insert_tail(&loop->prepare_handles, q);

    uv_prepare_t* h = uv__queue_data(q, uv_prepare_t, queue);
    if (h->prepare_cb)
      h->prepare_cb(h);
  }
}

/* --- Internal: process queued UDP sends --- */

static void uv__flush_udp_sends(uv_udp_t* handle) {
  while (!uv__queue_empty(&handle->write_queue)) {
    struct uv__queue* q = uv__queue_head(&handle->write_queue);
    uv_udp_send_t* req = uv__queue_data(q, uv_udp_send_t, queue);

    struct msghdr msg;
    struct iovec iov[16];
    unsigned int n = req->nbufs < 16 ? req->nbufs : 16;

    for (unsigned int i = 0; i < n; i++) {
      iov[i].iov_base = req->bufs[i].base;
      iov[i].iov_len = req->bufs[i].len;
    }

    socklen_t addrlen = req->u.addr.sa_family == AF_INET
                            ? sizeof(struct sockaddr_in)
                            : sizeof(struct sockaddr_in6);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &req->u.storage;
    msg.msg_namelen = addrlen;
    msg.msg_iov = iov;
    msg.msg_iovlen = (int)n;

    ssize_t sent = sendmsg(handle->io_watcher.fd, &msg, 0);
    int status = 0;
    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;  /* Try again next iteration */
      status = uv__translate_errno(errno);
    }

    uv__queue_remove(q);
    handle->send_queue_size -= (size_t)req->status;
    handle->send_queue_count--;

    if (req->bufs != req->bufsml)
      free(req->bufs);

    if (req->cb)
      req->cb(req, status);
  }

  /* Clear POLLOUT if queue is empty */
  if (uv__queue_empty(&handle->write_queue))
    handle->io_watcher.pevents &= ~0x04;
}

/* --- Internal: dispatch UDP recv --- */

static void uv__udp_recv(uv_udp_t* handle) {
  if (!handle->recv_cb || !handle->alloc_cb)
    return;

  /* Read up to 8 datagrams per iteration (avoid starving timers) */
  for (int i = 0; i < 8; i++) {
    uv_buf_t buf;
    handle->alloc_cb((uv_handle_t*)handle, 65536, &buf);
    if (buf.base == NULL || buf.len == 0)
      break;

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    ssize_t nread = recvfrom(handle->io_watcher.fd, buf.base, buf.len, 0,
                             (struct sockaddr*)&addr, &addrlen);
    if (nread < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        /* No more data — deliver empty read to free the buffer */
        handle->recv_cb(handle, 0, &buf, NULL, 0);
        break;
      }
      handle->recv_cb(handle, uv__translate_errno(errno), &buf, NULL, 0);
      break;
    }

    if (nread == 0) {
      handle->recv_cb(handle, 0, &buf, NULL, 0);
      break;
    }

    buf.len = (size_t)nread;
    handle->recv_cb(handle, nread, &buf, (struct sockaddr*)&addr, 0);
  }
}

/* --- Internal: I/O poll via select() --- */

static void uv__io_poll(uv_loop_t* loop, uint64_t timeout_ms) {
  fd_set readfds, writefds;
  int maxfd = -1;

  FD_ZERO(&readfds);
  FD_ZERO(&writefds);

  /* Add wakeup fd */
  if (loop->wakeup_fd >= 0) {
    FD_SET(loop->wakeup_fd, &readfds);
    if (loop->wakeup_fd > maxfd)
      maxfd = loop->wakeup_fd;
  }

  /* Walk all UDP handles and add their fds */
  struct uv__queue* q;
  for (q = uv__queue_head(&loop->handle_queue);
       q != &loop->handle_queue;
       q = uv__queue_next(q)) {
    uv_handle_t* h = uv__queue_data(q, uv_handle_t, handle_queue);
    if (h->type != UV_UDP) continue;
    if (h->flags & (UV_HANDLE_CLOSING | UV_HANDLE_CLOSED)) continue;

    uv_udp_t* udp = (uv_udp_t*)h;
    int fd = udp->io_watcher.fd;
    if (fd < 0) continue;

    if (udp->io_watcher.pevents & 0x01) {  /* POLLIN */
      FD_SET(fd, &readfds);
      if (fd > maxfd) maxfd = fd;
    }
    if (udp->io_watcher.pevents & 0x04) {  /* POLLOUT */
      FD_SET(fd, &writefds);
      if (fd > maxfd) maxfd = fd;
    }
  }

  if (maxfd < 0 && timeout_ms == 0)
    return;  /* Nothing to wait on and no timeout */

  struct timeval tv;
  struct timeval* tvp = NULL;
  if (timeout_ms != (uint64_t)-1) {
    tv.tv_sec = (long)(timeout_ms / 1000);
    tv.tv_usec = (long)((timeout_ms % 1000) * 1000);
    tvp = &tv;
  }

  int n = select(maxfd + 1, &readfds, &writefds, NULL, tvp);

  /* Update time after blocking */
  loop->time = uv__get_time_ms();

  if (n <= 0) return;

  /* Drain wakeup fd */
  if (loop->wakeup_fd >= 0 && FD_ISSET(loop->wakeup_fd, &readfds)) {
    uint64_t val;
    ssize_t r = read(loop->wakeup_fd, &val, sizeof(val));
    (void)r;
  }

  /* Dispatch UDP I/O */
  for (q = uv__queue_head(&loop->handle_queue);
       q != &loop->handle_queue;
       q = uv__queue_next(q)) {
    uv_handle_t* h = uv__queue_data(q, uv_handle_t, handle_queue);
    if (h->type != UV_UDP) continue;
    if (h->flags & (UV_HANDLE_CLOSING | UV_HANDLE_CLOSED)) continue;

    uv_udp_t* udp = (uv_udp_t*)h;
    int fd = udp->io_watcher.fd;
    if (fd < 0) continue;

    if (FD_ISSET(fd, &readfds))
      uv__udp_recv(udp);
    if (FD_ISSET(fd, &writefds))
      uv__flush_udp_sends(udp);
  }
}

/* --- Internal: run close callbacks --- */

static void uv__run_closing(uv_loop_t* loop) {
  while (loop->closing_handles != NULL) {
    uv_handle_t* h = loop->closing_handles;
    loop->closing_handles = h->next_closing;

    h->flags |= UV_HANDLE_CLOSED;
    h->flags &= ~UV_HANDLE_CLOSING;
    uv__queue_remove(&h->handle_queue);
    uv__queue_init(&h->handle_queue);

    if (h->close_cb)
      h->close_cb(h);
  }
}

/* --- Loop alive check --- */

int uv_loop_alive(const uv_loop_t* loop) {
  return loop->active_handles > 0 ||
         loop->closing_handles != NULL;
}

int uv_backend_fd(const uv_loop_t* loop) {
  return loop->wakeup_fd;
}

/* --- Next timer timeout (ms until next fire, or -1 if none) --- */

static uint64_t uv__next_timeout(const uv_loop_t* loop) {
  const struct heap* timer_heap = (const struct heap*)&loop->timer_heap;
  const struct heap_node* node = heap_min(timer_heap);

  if (node == NULL)
    return (uint64_t)-1;

  const uv_timer_t* handle = HEAP_NODE_DATA(uv_timer_t, node.heap[0], node);
  if (handle->timeout <= loop->time)
    return 0;

  return handle->timeout - loop->time;
}

/* --- Main event loop --- */

int uv_run(uv_loop_t* loop, uv_run_mode mode) {
  loop->time = uv__get_time_ms();

  while (uv_loop_alive(loop) && !loop->stop_flag) {
    loop->time = uv__get_time_ms();
    uv__run_timers(loop);

    uv__run_prepare(loop);

    /* Calculate select() timeout from next timer */
    uint64_t timeout;
    if (mode == UV_RUN_NOWAIT)
      timeout = 0;
    else
      timeout = uv__next_timeout(loop);

    uv__io_poll(loop, timeout);

    uv__run_timers(loop);
    uv__run_closing(loop);

    if (mode == UV_RUN_ONCE || mode == UV_RUN_NOWAIT)
      break;
  }

  loop->stop_flag = 0;

  return uv_loop_alive(loop);
}
