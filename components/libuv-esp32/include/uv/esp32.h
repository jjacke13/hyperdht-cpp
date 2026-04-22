/* libuv-esp32 shim — ESP32/FreeRTOS private fields.
 * Replaces uv/unix.h private field macros with our own implementations.
 * Public struct layout (data, loop, type, close_cb, handle_queue, u)
 * MUST match real libuv exactly — libudx reads uv_udp_t.send_queue_count
 * at a fixed offset.
 */

#ifndef UV_ESP32_H
#define UV_ESP32_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <pthread.h>
#include <semaphore.h>

/* Forward declarations */
struct uv_loop_s;
struct uv__io_s;

typedef void (*uv__io_cb)(struct uv_loop_s* loop,
                          struct uv__io_s* w,
                          unsigned int events);
typedef struct uv__io_s uv__io_t;

struct uv__io_s {
  uv__io_cb cb;
  struct uv__queue pending_queue;
  struct uv__queue watcher_queue;
  unsigned int pevents;
  unsigned int events;
  int fd;
};

/* --- Handle private fields --- */

#define UV_HANDLE_PRIVATE_FIELDS                                              \
  uv_handle_t* next_closing;                                                  \
  unsigned int flags;                                                         \

/* --- UDP private fields --- */

#define UV_UDP_PRIVATE_FIELDS                                                 \
  uv_alloc_cb alloc_cb;                                                       \
  uv_udp_recv_cb recv_cb;                                                     \
  uv__io_t io_watcher;                                                        \
  struct uv__queue write_queue;                                               \
  struct uv__queue write_completed_queue;                                     \

/* --- UDP send request private fields --- */

#define UV_UDP_SEND_PRIVATE_FIELDS                                            \
  struct uv__queue queue;                                                     \
  union {                                                                     \
    struct sockaddr addr;                                                     \
    struct sockaddr_storage storage;                                          \
  } u;                                                                        \
  unsigned int nbufs;                                                         \
  uv_buf_t* bufs;                                                             \
  ssize_t status;                                                             \
  uv_udp_send_cb send_cb;                                                     \
  uv_buf_t bufsml[4];                                                         \

/* --- Timer private fields --- */

#define UV_TIMER_PRIVATE_FIELDS                                               \
  uv_timer_cb timer_cb;                                                       \
  union {                                                                     \
    void* heap[3];                                                            \
    struct uv__queue queue;                                                   \
  } node;                                                                     \
  uint64_t timeout;                                                           \
  uint64_t repeat;                                                            \
  uint64_t start_id;

/* --- Prepare private fields --- */

#define UV_PREPARE_PRIVATE_FIELDS                                             \
  uv_prepare_cb prepare_cb;                                                   \
  struct uv__queue queue;                                                     \

/* --- Async private fields --- */

#define UV_ASYNC_PRIVATE_FIELDS                                               \
  uv_async_cb async_cb;                                                       \
  struct uv__queue queue;                                                     \
  int pending;                                                                \

/* --- Check/Idle private fields (stubs, not used) --- */

#define UV_CHECK_PRIVATE_FIELDS                                               \
  void* check_cb;                                                             \
  struct uv__queue queue;                                                     \

#define UV_IDLE_PRIVATE_FIELDS                                                \
  void* idle_cb;                                                              \
  struct uv__queue queue;                                                     \

/* --- Stream private fields (stub — not used by libudx) --- */

#define UV_STREAM_PRIVATE_FIELDS                                              \
  void* connect_req;                                                          \
  void* shutdown_req;                                                         \
  uv__io_t io_watcher;                                                        \
  struct uv__queue write_queue;                                               \
  struct uv__queue write_completed_queue;                                     \
  void* connection_cb;                                                        \
  int delayed_error;                                                          \
  int accepted_fd;                                                            \
  void* queued_fds;                                                           \

#define UV_TCP_PRIVATE_FIELDS /* empty */
#define UV_PIPE_PRIVATE_FIELDS const char* pipe_fname;

/* --- Poll private fields (stub) --- */

#define UV_POLL_PRIVATE_FIELDS                                                \
  uv__io_t io_watcher;

/* --- Getaddrinfo private fields --- */

#define UV_GETADDRINFO_PRIVATE_FIELDS                                         \
  struct addrinfo* addrinfo;                                                  \
  void* cb;                                                                   \
  void* hints;                                                                \
  char* hostname;                                                             \
  char* service;                                                              \
  int retcode;

/* --- Request private fields --- */

#define UV_REQ_TYPE_PRIVATE    /* empty */
#define UV_REQ_PRIVATE_FIELDS  /* empty */
#define UV_PRIVATE_REQ_TYPES   /* empty */

#define UV_WRITE_PRIVATE_FIELDS                                               \
  struct uv__queue queue;                                                     \
  unsigned int write_index;                                                   \
  uv_buf_t* bufs;                                                            \
  unsigned int nbufs;                                                         \
  int error;                                                                  \
  uv_buf_t bufsml[4];                                                         \

#define UV_CONNECT_PRIVATE_FIELDS                                             \
  struct uv__queue queue;                                                     \

#define UV_SHUTDOWN_PRIVATE_FIELDS /* empty */

/* --- Loop private fields --- */

#define UV_LOOP_PRIVATE_FIELDS                                                \
  unsigned long flags;                                                        \
  int backend_fd;             /* eventfd for wakeup */                        \
  struct uv__queue pending_queue;                                             \
  struct uv__queue watcher_queue;                                             \
  uv__io_t** watchers;                                                        \
  unsigned int nwatchers;                                                     \
  unsigned int nfds;                                                          \
  /* ESP32: no threadpool, no signals, no processes */                        \
  uv_handle_t* closing_handles;                                               \
  struct uv__queue prepare_handles;                                           \
  struct uv__queue check_handles;                                             \
  struct uv__queue idle_handles;                                              \
  struct uv__queue async_handles;                                             \
  struct {                                                                    \
    void* min;                                                                \
    unsigned int nelts;                                                       \
  } timer_heap;                                                               \
  uint64_t timer_counter;                                                     \
  uint64_t time;                                                              \
  int wakeup_fd;              /* eventfd for uv_async */                      \

/* --- Platform fields (unused on ESP32) --- */

#define UV_PLATFORM_LOOP_FIELDS    /* empty */
#define UV_STREAM_PRIVATE_PLATFORM_FIELDS /* empty */
#define UV_IO_PRIVATE_PLATFORM_FIELDS     /* empty */

/* --- Work request (stub — no threadpool) --- */

struct uv__work {
  void (*work)(struct uv__work* w);
  void (*done)(struct uv__work* w, int status);
  struct uv_loop_s* loop;
  struct uv__queue wq;
};

#define UV_WORK_PRIVATE_FIELDS                                                \
  struct uv__work work_req;

/* FS (stub) */
#define UV_FS_PRIVATE_FIELDS  void* fs_fields_stub;
#define UV_GETNAMEINFO_PRIVATE_FIELDS void* getnameinfo_stub;

/* Types */
typedef int uv_file;
typedef int uv_os_sock_t;
typedef int uv_os_fd_t;
typedef pthread_t uv_thread_t;
typedef pthread_mutex_t uv_mutex_t;
typedef struct { pthread_mutex_t m; } uv_rwlock_t;
typedef pthread_cond_t uv_cond_t;
typedef pthread_once_t uv_once_t;
typedef sem_t uv_sem_t;
typedef uid_t uv_uid_t;
typedef gid_t uv_gid_t;

/* uv_buf_t — same layout as struct iovec on POSIX */
typedef struct {
  char* base;
  size_t len;
} uv_buf_t;

#endif /* UV_ESP32_H */
