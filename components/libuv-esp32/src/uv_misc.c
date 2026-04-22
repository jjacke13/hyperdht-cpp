/* libuv-esp32 shim — utility functions. */

#define _POSIX_C_SOURCE 199309L

#include "internal.h"

#include <time.h>
#include <arpa/inet.h>

uv_buf_t uv_buf_init(char* base, unsigned int len) {
  uv_buf_t buf;
  buf.base = base;
  buf.len = len;
  return buf;
}

uint64_t uv_hrtime(void) {
#ifdef ESP_PLATFORM
  extern int64_t esp_timer_get_time(void);
  return (uint64_t)esp_timer_get_time() * 1000;  /* us → ns */
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

int uv_ip4_addr(const char* ip, int port, struct sockaddr_in* addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sin_family = AF_INET;
  addr->sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, ip, &addr->sin_addr) != 1)
    return UV_EINVAL;
  return 0;
}

int uv_ip6_addr(const char* ip, int port, struct sockaddr_in6* addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sin6_family = AF_INET6;
  addr->sin6_port = htons((uint16_t)port);
  if (inet_pton(AF_INET6, ip, &addr->sin6_addr) != 1)
    return UV_EINVAL;
  return 0;
}

int uv_ip4_name(const struct sockaddr_in* src, char* dst, size_t size) {
  if (inet_ntop(AF_INET, &src->sin_addr, dst, (socklen_t)size) == NULL)
    return UV_ENOSPC;
  return 0;
}

int uv_ip6_name(const struct sockaddr_in6* src, char* dst, size_t size) {
  if (inet_ntop(AF_INET6, &src->sin6_addr, dst, (socklen_t)size) == NULL)
    return UV_ENOSPC;
  return 0;
}

int uv_inet_ntop(int af, const void* src, char* dst, size_t size) {
  if (inet_ntop(af, src, dst, (socklen_t)size) == NULL)
    return UV_ENOSPC;
  return 0;
}

int uv_inet_pton(int af, const char* src, void* dst) {
  if (inet_pton(af, src, dst) != 1)
    return UV_EINVAL;
  return 0;
}

/* Error string table */
const char* uv_strerror(int err) {
  if (err >= 0)
    return "success";

  switch (err) {
    case UV_EAGAIN:       return "resource temporarily unavailable";
    case UV_EADDRINUSE:   return "address already in use";
    case UV_EADDRNOTAVAIL:return "address not available";
    case UV_EAFNOSUPPORT: return "address family not supported";
    case UV_EBADF:        return "bad file descriptor";
    case UV_EBUSY:        return "resource busy or locked";
    case UV_ECANCELED:    return "operation canceled";
    case UV_ECONNABORTED: return "software caused connection abort";
    case UV_ECONNREFUSED: return "connection refused";
    case UV_ECONNRESET:   return "connection reset by peer";
    case UV_EHOSTUNREACH: return "host is unreachable";
    case UV_EINTR:        return "interrupted system call";
    case UV_EINVAL:       return "invalid argument";
    case UV_EMSGSIZE:     return "message too long";
    case UV_ENETDOWN:     return "network is down";
    case UV_ENETUNREACH:  return "network is unreachable";
    case UV_ENOBUFS:      return "no buffer space available";
    case UV_ENOMEM:       return "not enough memory";
    case UV_ENOSYS:       return "function not implemented";
    case UV_ENOTSOCK:     return "socket operation on non-socket";
    case UV_EPERM:        return "operation not permitted";
    case UV_ETIMEDOUT:    return "connection timed out";
    case UV_EOF:          return "end of file";
    default:              return "unknown error";
  }
}

const char* uv_err_name(int err) {
  if (err >= 0)
    return "OK";

  switch (err) {
    case UV_EAGAIN:       return "EAGAIN";
    case UV_EADDRINUSE:   return "EADDRINUSE";
    case UV_EBADF:        return "EBADF";
    case UV_ECANCELED:    return "ECANCELED";
    case UV_ECONNREFUSED: return "ECONNREFUSED";
    case UV_ECONNRESET:   return "ECONNRESET";
    case UV_EINVAL:       return "EINVAL";
    case UV_ENOMEM:       return "ENOMEM";
    case UV_ENOSYS:       return "ENOSYS";
    case UV_ETIMEDOUT:    return "ETIMEDOUT";
    case UV_EOF:          return "EOF";
    default:              return "UNKNOWN";
  }
}

unsigned int uv_version(void) {
  return 0x01330000;  /* 1.51.0 — matches the libuv we're shimming */
}

const char* uv_version_string(void) {
  return "1.51.0-esp32";
}

void uv_walk(uv_loop_t* loop, uv_walk_cb walk_cb, void* arg) {
  struct uv__queue* q;
  for (q = uv__queue_head(&loop->handle_queue);
       q != &loop->handle_queue;
       q = uv__queue_next(q)) {
    uv_handle_t* h = uv__queue_data(q, uv_handle_t, handle_queue);
    walk_cb(h, arg);
  }
}
