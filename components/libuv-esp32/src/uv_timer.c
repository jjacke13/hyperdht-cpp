/* libuv-esp32 shim — timer implementation (binary min-heap). */

#include "internal.h"

int uv_timer_init(uv_loop_t* loop, uv_timer_t* handle) {
  uv__handle_init(loop, (uv_handle_t*)handle, UV_TIMER);
  handle->timer_cb = NULL;
  handle->timeout = 0;
  handle->repeat = 0;
  handle->start_id = 0;
  memset(&handle->node, 0, sizeof(handle->node));
  return 0;
}

int uv_timer_start(uv_timer_t* handle, uv_timer_cb cb,
                   uint64_t timeout, uint64_t repeat) {
  uint64_t clamped_timeout;

  if (uv__is_closing((uv_handle_t*)handle) || cb == NULL)
    return UV_EINVAL;

  /* If already active, remove from heap first */
  if (uv__is_active((uv_handle_t*)handle))
    uv_timer_stop(handle);

  clamped_timeout = handle->loop->time + timeout;

  handle->timer_cb = cb;
  handle->timeout = clamped_timeout;
  handle->repeat = repeat;
  handle->start_id = handle->loop->timer_counter++;

  heap_insert((struct heap*)&handle->loop->timer_heap,
              (struct heap_node*)&handle->node.heap[0],
              timer_less_than);

  uv__handle_start((uv_handle_t*)handle);
  return 0;
}

int uv_timer_stop(uv_timer_t* handle) {
  if (!uv__is_active((uv_handle_t*)handle))
    return 0;

  heap_remove((struct heap*)&handle->loop->timer_heap,
              (struct heap_node*)&handle->node.heap[0],
              timer_less_than);

  uv__handle_stop((uv_handle_t*)handle);
  return 0;
}

int uv_timer_again(uv_timer_t* handle) {
  if (handle->timer_cb == NULL)
    return UV_EINVAL;

  if (handle->repeat == 0)
    return 0;

  uv_timer_stop(handle);
  uv_timer_start(handle, handle->timer_cb, handle->repeat, handle->repeat);
  return 0;
}

void uv_timer_set_repeat(uv_timer_t* handle, uint64_t repeat) {
  handle->repeat = repeat;
}

uint64_t uv_timer_get_repeat(const uv_timer_t* handle) {
  return handle->repeat;
}

uint64_t uv_timer_get_due_in(const uv_timer_t* handle) {
  if (!uv__is_active((const uv_handle_t*)handle))
    return 0;

  if (handle->timeout <= handle->loop->time)
    return 0;

  return handle->timeout - handle->loop->time;
}
