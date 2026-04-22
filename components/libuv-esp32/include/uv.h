/* libuv-esp32 shim — drop-in replacement for libuv on ESP32/FreeRTOS.
 *
 * Implements only the ~40 functions that libudx + hyperdht-cpp actually call.
 * Struct layouts match real libuv exactly at the public-field level so that
 * libudx's direct field access (e.g. socket->uv_udp.send_queue_count) works.
 *
 * Copyright 2026 Vaios K. LGPL-3.0.
 */

#ifndef UV_H
#define UV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <netdb.h>  /* struct addrinfo — needed before callback typedefs */

/* Internal type — circular doubly-linked list node. */
struct uv__queue {
  struct uv__queue* next;
  struct uv__queue* prev;
};

/* Platform-specific types and private field macros. */
#include "uv/errno.h"
#include "uv/esp32.h"

/* ------------------------------------------------------------------ */
/* Type enums                                                          */
/* ------------------------------------------------------------------ */

typedef enum {
  UV_UNKNOWN_HANDLE = 0,
  UV_ASYNC,
  UV_CHECK,
  UV_FS_EVENT,
  UV_FS_POLL,
  UV_HANDLE,
  UV_IDLE,
  UV_NAMED_PIPE,
  UV_POLL,
  UV_PREPARE,
  UV_PROCESS,
  UV_STREAM,
  UV_TCP,
  UV_TIMER,
  UV_TTY,
  UV_UDP,
  UV_SIGNAL,
  UV_FILE,
  UV_HANDLE_TYPE_MAX
} uv_handle_type;

typedef enum {
  UV_UNKNOWN_REQ = 0,
  UV_REQ,
  UV_CONNECT,
  UV_WRITE,
  UV_SHUTDOWN,
  UV_UDP_SEND,
  UV_FS,
  UV_WORK,
  UV_GETADDRINFO,
  UV_GETNAMEINFO,
  UV_RANDOM,
  UV_REQ_TYPE_MAX
} uv_req_type;

typedef enum {
  UV_RUN_DEFAULT = 0,
  UV_RUN_ONCE,
  UV_RUN_NOWAIT
} uv_run_mode;

typedef enum {
  UV_LEAVE_GROUP = 0,
  UV_JOIN_GROUP
} uv_membership;

/* UDP flags */
enum uv_udp_flags {
  UV_UDP_IPV6ONLY = 1,
  UV_UDP_PARTIAL = 2,
  UV_UDP_REUSEADDR = 4,
  UV_UDP_MMSG_CHUNK = 8,
  UV_UDP_MMSG_FREE = 16,
  UV_UDP_LINUX_RECVERR = 32,
  UV_UDP_RECVMMSG = 256
};

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

struct uv_loop_s;
struct uv_handle_s;
struct uv_udp_s;
struct uv_udp_send_s;
struct uv_timer_s;
struct uv_prepare_s;
struct uv_async_s;
struct uv_check_s;
struct uv_idle_s;
struct uv_poll_s;
struct uv_stream_s;
struct uv_tcp_s;
struct uv_pipe_s;
struct uv_req_s;
struct uv_connect_s;
struct uv_shutdown_s;
struct uv_write_s;
struct uv_getaddrinfo_s;
struct uv_signal_s;
struct uv_process_s;
struct uv_work_s;

typedef struct uv_loop_s uv_loop_t;
typedef struct uv_handle_s uv_handle_t;
typedef struct uv_udp_s uv_udp_t;
typedef struct uv_udp_send_s uv_udp_send_t;
typedef struct uv_timer_s uv_timer_t;
typedef struct uv_prepare_s uv_prepare_t;
typedef struct uv_async_s uv_async_t;
typedef struct uv_check_s uv_check_t;
typedef struct uv_idle_s uv_idle_t;
typedef struct uv_poll_s uv_poll_t;
typedef struct uv_stream_s uv_stream_t;
typedef struct uv_tcp_s uv_tcp_t;
typedef struct uv_pipe_s uv_pipe_t;
typedef struct uv_req_s uv_req_t;
typedef struct uv_connect_s uv_connect_t;
typedef struct uv_shutdown_s uv_shutdown_t;
typedef struct uv_write_s uv_write_t;
typedef struct uv_getaddrinfo_s uv_getaddrinfo_t;
typedef struct uv_signal_s uv_signal_t;
typedef struct uv_process_s uv_process_t;
typedef struct uv_work_s uv_work_t;

/* ------------------------------------------------------------------ */
/* Callback typedefs                                                   */
/* ------------------------------------------------------------------ */

typedef void (*uv_close_cb)(uv_handle_t* handle);
typedef void (*uv_timer_cb)(uv_timer_t* handle);
typedef void (*uv_prepare_cb)(uv_prepare_t* handle);
typedef void (*uv_async_cb)(uv_async_t* handle);
typedef void (*uv_check_cb)(uv_check_t* handle);
typedef void (*uv_idle_cb)(uv_idle_t* handle);
typedef void (*uv_poll_cb)(uv_poll_t* handle, int status, int events);
typedef void (*uv_connection_cb)(uv_stream_t* server, int status);

typedef void (*uv_alloc_cb)(uv_handle_t* handle,
                            size_t suggested_size,
                            uv_buf_t* buf);

typedef void (*uv_udp_send_cb)(uv_udp_send_t* req, int status);

typedef void (*uv_udp_recv_cb)(uv_udp_t* handle,
                               ssize_t nread,
                               const uv_buf_t* buf,
                               const struct sockaddr* addr,
                               unsigned flags);

typedef void (*uv_read_cb)(uv_stream_t* stream,
                           ssize_t nread,
                           const uv_buf_t* buf);

typedef void (*uv_write_cb)(uv_write_t* req, int status);
typedef void (*uv_connect_cb)(uv_connect_t* req, int status);
typedef void (*uv_shutdown_cb)(uv_shutdown_t* req, int status);
typedef void (*uv_walk_cb)(uv_handle_t* handle, void* arg);

typedef void (*uv_getaddrinfo_cb)(uv_getaddrinfo_t* req,
                                  int status,
                                  struct addrinfo* res);

typedef void (*uv_work_cb)(uv_work_t* req);
typedef void (*uv_after_work_cb)(uv_work_t* req, int status);

/* ------------------------------------------------------------------ */
/* Struct definitions                                                  */
/* ------------------------------------------------------------------ */

/* UV_HANDLE_FIELDS — must match real libuv layout exactly.
 * libudx casts handles and accesses fields by offset. */
#define UV_HANDLE_FIELDS                                                      \
  /* public */                                                                \
  void* data;                                                                 \
  /* read-only */                                                             \
  uv_loop_t* loop;                                                            \
  uv_handle_type type;                                                        \
  /* private */                                                               \
  uv_close_cb close_cb;                                                       \
  struct uv__queue handle_queue;                                              \
  union {                                                                     \
    int fd;                                                                   \
    void* reserved[4];                                                        \
  } u;                                                                        \
  UV_HANDLE_PRIVATE_FIELDS                                                    \

#define UV_REQ_FIELDS                                                         \
  /* public */                                                                \
  void* data;                                                                 \
  /* read-only */                                                             \
  uv_req_type type;                                                           \
  /* private */                                                               \
  void* reserved[6];                                                          \
  UV_REQ_PRIVATE_FIELDS                                                       \

struct uv_handle_s {
  UV_HANDLE_FIELDS
};

struct uv_req_s {
  UV_REQ_FIELDS
};

/* uv_udp_t — libudx reads send_queue_count directly. */
struct uv_udp_s {
  UV_HANDLE_FIELDS
  size_t send_queue_size;
  size_t send_queue_count;
  UV_UDP_PRIVATE_FIELDS
};

struct uv_udp_send_s {
  UV_REQ_FIELDS
  uv_udp_t* handle;
  uv_udp_send_cb cb;
  UV_UDP_SEND_PRIVATE_FIELDS
};

struct uv_timer_s {
  UV_HANDLE_FIELDS
  UV_TIMER_PRIVATE_FIELDS
};

struct uv_prepare_s {
  UV_HANDLE_FIELDS
  UV_PREPARE_PRIVATE_FIELDS
};

struct uv_async_s {
  UV_HANDLE_FIELDS
  UV_ASYNC_PRIVATE_FIELDS
};

struct uv_check_s {
  UV_HANDLE_FIELDS
  UV_CHECK_PRIVATE_FIELDS
};

struct uv_idle_s {
  UV_HANDLE_FIELDS
  UV_IDLE_PRIVATE_FIELDS
};

struct uv_poll_s {
  UV_HANDLE_FIELDS
  uv_poll_cb poll_cb;
  UV_POLL_PRIVATE_FIELDS
};

struct uv_stream_s {
  UV_HANDLE_FIELDS
  size_t write_queue_size;
  uv_alloc_cb alloc_cb;
  uv_read_cb read_cb;
  UV_STREAM_PRIVATE_FIELDS
};

struct uv_tcp_s {
  UV_HANDLE_FIELDS
  size_t write_queue_size;
  uv_alloc_cb alloc_cb;
  uv_read_cb read_cb;
  UV_STREAM_PRIVATE_FIELDS
  UV_TCP_PRIVATE_FIELDS
};

struct uv_pipe_s {
  UV_HANDLE_FIELDS
  size_t write_queue_size;
  uv_alloc_cb alloc_cb;
  uv_read_cb read_cb;
  UV_STREAM_PRIVATE_FIELDS
  UV_PIPE_PRIVATE_FIELDS
  int ipc;
};

struct uv_connect_s {
  UV_REQ_FIELDS
  uv_connect_cb cb;
  uv_stream_t* handle;
  UV_CONNECT_PRIVATE_FIELDS
};

struct uv_shutdown_s {
  UV_REQ_FIELDS
  uv_stream_t* handle;
  uv_shutdown_cb cb;
  UV_SHUTDOWN_PRIVATE_FIELDS
};

struct uv_write_s {
  UV_REQ_FIELDS
  uv_write_cb cb;
  uv_stream_t* send_handle;
  uv_stream_t* handle;
  UV_WRITE_PRIVATE_FIELDS
};

struct uv_getaddrinfo_s {
  UV_REQ_FIELDS
  uv_loop_t* loop;
  UV_GETADDRINFO_PRIVATE_FIELDS
};

struct uv_signal_s {
  UV_HANDLE_FIELDS
  int signum;
};

struct uv_process_s {
  UV_HANDLE_FIELDS
  int pid;
  int status;
};

struct uv_work_s {
  UV_REQ_FIELDS
  uv_loop_t* loop;
  uv_work_cb work_cb;
  uv_after_work_cb after_work_cb;
  UV_WORK_PRIVATE_FIELDS
};

/* Interface address info */
typedef struct uv_interface_address_s {
  char name[64];
  char phys_addr[6];
  int is_internal;
  union {
    struct sockaddr_in address4;
    struct sockaddr_in6 address6;
  } address;
  union {
    struct sockaddr_in netmask4;
    struct sockaddr_in6 netmask6;
  } netmask;
} uv_interface_address_t;

/* uv_stat_t — stub for compilation, not used */
typedef struct { uint64_t st_size; } uv_stat_t;

/* uv_loop_t */
struct uv_loop_s {
  void* data;
  unsigned int active_handles;
  struct uv__queue handle_queue;
  union {
    void* unused;
    unsigned int count;
  } active_reqs;
  void* internal_fields;
  unsigned int stop_flag;
  UV_LOOP_PRIVATE_FIELDS
};

/* ------------------------------------------------------------------ */
/* Handle flags (internal, but needed for is_active/is_closing)        */
/* ------------------------------------------------------------------ */

enum {
  UV_HANDLE_CLOSING  = 0x00000001,
  UV_HANDLE_CLOSED   = 0x00000002,
  UV_HANDLE_ACTIVE   = 0x00000004,
  UV_HANDLE_REF      = 0x00000008,
  UV_HANDLE_INTERNAL = 0x00000010,
  UV_HANDLE_BOUND    = 0x00002000,
  UV_HANDLE_READING  = 0x00004000,
};

/* ------------------------------------------------------------------ */
/* Function declarations                                               */
/* ------------------------------------------------------------------ */

/* --- Loop --- */
int uv_loop_init(uv_loop_t* loop);
int uv_loop_close(uv_loop_t* loop);
int uv_run(uv_loop_t* loop, uv_run_mode mode);
void uv_stop(uv_loop_t* loop);
void uv_update_time(uv_loop_t* loop);
uint64_t uv_now(const uv_loop_t* loop);
int uv_loop_alive(const uv_loop_t* loop);
int uv_backend_fd(const uv_loop_t* loop);

/* --- Handle --- */
void uv_close(uv_handle_t* handle, uv_close_cb close_cb);
int uv_is_active(const uv_handle_t* handle);
int uv_is_closing(const uv_handle_t* handle);
void uv_ref(uv_handle_t* handle);
void uv_unref(uv_handle_t* handle);
int uv_has_ref(const uv_handle_t* handle);
int uv_fileno(const uv_handle_t* handle, uv_os_fd_t* fd);
int uv_send_buffer_size(uv_handle_t* handle, int* value);
int uv_recv_buffer_size(uv_handle_t* handle, int* value);

/* --- Timer --- */
int uv_timer_init(uv_loop_t* loop, uv_timer_t* handle);
int uv_timer_start(uv_timer_t* handle, uv_timer_cb cb,
                   uint64_t timeout, uint64_t repeat);
int uv_timer_stop(uv_timer_t* handle);
int uv_timer_again(uv_timer_t* handle);
void uv_timer_set_repeat(uv_timer_t* handle, uint64_t repeat);
uint64_t uv_timer_get_repeat(const uv_timer_t* handle);
uint64_t uv_timer_get_due_in(const uv_timer_t* handle);

/* --- UDP --- */
int uv_udp_init(uv_loop_t* loop, uv_udp_t* handle);
int uv_udp_init_ex(uv_loop_t* loop, uv_udp_t* handle, unsigned int flags);
int uv_udp_bind(uv_udp_t* handle, const struct sockaddr* addr,
                unsigned int flags);
int uv_udp_getsockname(const uv_udp_t* handle, struct sockaddr* name,
                       int* namelen);
int uv_udp_send(uv_udp_send_t* req, uv_udp_t* handle,
                const uv_buf_t bufs[], unsigned int nbufs,
                const struct sockaddr* addr, uv_udp_send_cb send_cb);
int uv_udp_try_send(uv_udp_t* handle, const uv_buf_t bufs[],
                    unsigned int nbufs, const struct sockaddr* addr);
int uv_udp_recv_start(uv_udp_t* handle, uv_alloc_cb alloc_cb,
                      uv_udp_recv_cb recv_cb);
int uv_udp_recv_stop(uv_udp_t* handle);
int uv_udp_set_ttl(uv_udp_t* handle, int ttl);
int uv_udp_set_membership(uv_udp_t* handle, const char* multicast_addr,
                          const char* interface_addr, uv_membership membership);
int uv_udp_set_source_membership(uv_udp_t* handle,
                                 const char* multicast_addr,
                                 const char* interface_addr,
                                 const char* source_addr,
                                 uv_membership membership);
int uv_udp_set_multicast_loop(uv_udp_t* handle, int on);
int uv_udp_set_multicast_interface(uv_udp_t* handle,
                                   const char* interface_addr);

/* --- Prepare --- */
int uv_prepare_init(uv_loop_t* loop, uv_prepare_t* handle);
int uv_prepare_start(uv_prepare_t* handle, uv_prepare_cb cb);
int uv_prepare_stop(uv_prepare_t* handle);

/* --- Async --- */
int uv_async_init(uv_loop_t* loop, uv_async_t* handle, uv_async_cb cb);
int uv_async_send(uv_async_t* handle);

/* Poll event flags */
enum uv_poll_event {
  UV_READABLE = 1,
  UV_WRITABLE = 2,
  UV_DISCONNECT = 4,
  UV_PRIORITIZED = 8,
};

/* --- Poll (stub) --- */
int uv_poll_init(uv_loop_t* loop, uv_poll_t* handle, int fd);
int uv_poll_start(uv_poll_t* handle, int events, uv_poll_cb cb);
int uv_poll_stop(uv_poll_t* handle);

/* --- Getaddrinfo --- */
int uv_getaddrinfo(uv_loop_t* loop, uv_getaddrinfo_t* req,
                   uv_getaddrinfo_cb getaddrinfo_cb, const char* node,
                   const char* service, const struct addrinfo* hints);
void uv_freeaddrinfo(struct addrinfo* ai);

/* --- Interface --- */
int uv_interface_addresses(uv_interface_address_t** addresses, int* count);
void uv_free_interface_addresses(uv_interface_address_t* addresses, int count);

/* --- Utility --- */
uv_buf_t uv_buf_init(char* base, unsigned int len);
uint64_t uv_hrtime(void);
const char* uv_strerror(int err);
const char* uv_err_name(int err);
int uv_ip4_addr(const char* ip, int port, struct sockaddr_in* addr);
int uv_ip6_addr(const char* ip, int port, struct sockaddr_in6* addr);
int uv_ip4_name(const struct sockaddr_in* src, char* dst, size_t size);
int uv_ip6_name(const struct sockaddr_in6* src, char* dst, size_t size);
int uv_inet_ntop(int af, const void* src, char* dst, size_t size);
int uv_inet_pton(int af, const char* src, void* dst);

/* Version (stub) */
unsigned int uv_version(void);
const char* uv_version_string(void);

/* Walk (stub) */
void uv_walk(uv_loop_t* loop, uv_walk_cb walk_cb, void* arg);

/* Handle info */
size_t uv_handle_size(uv_handle_type type);
const char* uv_handle_type_name(uv_handle_type type);

#ifdef __cplusplus
}
#endif

#endif /* UV_H */
