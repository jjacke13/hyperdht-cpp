/* libuv-esp32 shim — prepare handles.
 * libudx uses uv_prepare_t for pending packet assembly batching. */

#include "internal.h"

int uv_prepare_init(uv_loop_t* loop, uv_prepare_t* handle) {
  uv__handle_init(loop, (uv_handle_t*)handle, UV_PREPARE);
  handle->prepare_cb = NULL;
  uv__queue_init(&handle->queue);
  return 0;
}

int uv_prepare_start(uv_prepare_t* handle, uv_prepare_cb cb) {
  if (uv__is_closing((uv_handle_t*)handle) || cb == NULL)
    return UV_EINVAL;

  if (uv__is_active((uv_handle_t*)handle))
    return 0;

  handle->prepare_cb = cb;
  uv__queue_insert_tail(&handle->loop->prepare_handles, &handle->queue);
  uv__handle_start((uv_handle_t*)handle);
  return 0;
}

int uv_prepare_stop(uv_prepare_t* handle) {
  if (!uv__is_active((uv_handle_t*)handle))
    return 0;

  uv__queue_remove(&handle->queue);
  uv__queue_init(&handle->queue);
  handle->prepare_cb = NULL;
  uv__handle_stop((uv_handle_t*)handle);
  return 0;
}
