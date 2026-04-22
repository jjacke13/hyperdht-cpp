/* Circular doubly-linked list — matches libuv's internal queue macros.
 * Used for handle_queue, prepare_handles, write_queue, etc.
 */

#ifndef UV_QUEUE_INL_H
#define UV_QUEUE_INL_H

#include <stddef.h>

static inline void uv__queue_init(struct uv__queue* q) {
  q->next = q;
  q->prev = q;
}

static inline int uv__queue_empty(const struct uv__queue* q) {
  return q->next == q;
}

static inline struct uv__queue* uv__queue_head(const struct uv__queue* q) {
  return q->next;
}

static inline struct uv__queue* uv__queue_next(const struct uv__queue* q) {
  return q->next;
}

static inline void uv__queue_insert_tail(struct uv__queue* h,
                                         struct uv__queue* q) {
  q->next = h;
  q->prev = h->prev;
  h->prev->next = q;
  h->prev = q;
}

static inline void uv__queue_insert_head(struct uv__queue* h,
                                         struct uv__queue* q) {
  q->next = h->next;
  q->prev = h;
  h->next->prev = q;
  h->next = q;
}

static inline void uv__queue_remove(struct uv__queue* q) {
  q->prev->next = q->next;
  q->next->prev = q->prev;
}

/* Move all entries from h to n. h becomes empty. */
static inline void uv__queue_move(struct uv__queue* h,
                                  struct uv__queue* n) {
  if (uv__queue_empty(h)) {
    uv__queue_init(n);
    return;
  }
  n->next = h->next;
  n->prev = h->prev;
  h->next->prev = n;
  h->prev->next = n;
  uv__queue_init(h);
}

#define uv__queue_data(ptr, type, field) \
  ((type*)((char*)(ptr) - offsetof(type, field)))

#endif /* UV_QUEUE_INL_H */
