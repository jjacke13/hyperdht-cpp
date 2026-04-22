/* libuv-esp32 shim — UDP socket operations on lwIP. */

#include "internal.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

static int uv__set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return UV_EINVAL;
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return uv__translate_errno(errno);
  return 0;
}

int uv_udp_init(uv_loop_t* loop, uv_udp_t* handle) {
  return uv_udp_init_ex(loop, handle, AF_INET);
}

int uv_udp_init_ex(uv_loop_t* loop, uv_udp_t* handle, unsigned int flags) {
  int domain = AF_INET;
  int fd;

  uv__handle_init(loop, (uv_handle_t*)handle, UV_UDP);
  handle->send_queue_size = 0;
  handle->send_queue_count = 0;
  handle->alloc_cb = NULL;
  handle->recv_cb = NULL;
  handle->io_watcher.fd = -1;
  handle->io_watcher.events = 0;
  handle->io_watcher.pevents = 0;
  handle->io_watcher.cb = NULL;
  uv__queue_init(&handle->io_watcher.pending_queue);
  uv__queue_init(&handle->io_watcher.watcher_queue);
  uv__queue_init(&handle->write_queue);
  uv__queue_init(&handle->write_completed_queue);

  if (flags & UV_UDP_IPV6ONLY)
    domain = AF_INET6;

  fd = socket(domain, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0)
    return uv__translate_errno(errno);

  int rc = uv__set_nonblock(fd);
  if (rc != 0) {
    close(fd);
    return rc;
  }

  handle->io_watcher.fd = fd;
  handle->u.fd = fd;
  return 0;
}

int uv_udp_bind(uv_udp_t* handle, const struct sockaddr* addr,
                unsigned int flags) {
  int fd = handle->io_watcher.fd;
  int on = 1;
  socklen_t addrlen;

  if (fd < 0) return UV_EBADF;

  /* SO_REUSEADDR (needs CONFIG_LWIP_SO_REUSE=y on ESP-IDF) */
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  if (flags & UV_UDP_REUSEADDR) {
    /* Already set above */
  }

  if (addr->sa_family == AF_INET)
    addrlen = sizeof(struct sockaddr_in);
  else if (addr->sa_family == AF_INET6)
    addrlen = sizeof(struct sockaddr_in6);
  else
    return UV_EINVAL;

  if (bind(fd, addr, addrlen) != 0)
    return uv__translate_errno(errno);

  handle->flags |= UV_HANDLE_BOUND;
  return 0;
}

int uv_udp_getsockname(const uv_udp_t* handle, struct sockaddr* name,
                       int* namelen) {
  int fd = handle->io_watcher.fd;
  socklen_t len;

  if (fd < 0) return UV_EBADF;

  len = (socklen_t)*namelen;
  if (getsockname(fd, name, &len) != 0)
    return uv__translate_errno(errno);

  *namelen = (int)len;
  return 0;
}

int uv_udp_try_send(uv_udp_t* handle, const uv_buf_t bufs[],
                    unsigned int nbufs, const struct sockaddr* addr) {
  int fd = handle->io_watcher.fd;
  struct msghdr msg;
  struct iovec iov[16];
  ssize_t sent;
  socklen_t addrlen;

  if (fd < 0) return UV_EBADF;
  if (nbufs > 16) return UV_EINVAL;

  for (unsigned int i = 0; i < nbufs; i++) {
    iov[i].iov_base = bufs[i].base;
    iov[i].iov_len = bufs[i].len;
  }

  if (addr->sa_family == AF_INET)
    addrlen = sizeof(struct sockaddr_in);
  else
    addrlen = sizeof(struct sockaddr_in6);

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = (void*)addr;
  msg.msg_namelen = addrlen;
  msg.msg_iov = iov;
  msg.msg_iovlen = (int)nbufs;

  sent = sendmsg(fd, &msg, 0);
  if (sent < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return UV_EAGAIN;
    return uv__translate_errno(errno);
  }

  return (int)sent;
}

/* Queued (async) send — uses a linked list of send requests.
 * The actual sendmsg() happens in the loop's I/O dispatch phase
 * when the socket becomes writable. */
int uv_udp_send(uv_udp_send_t* req, uv_udp_t* handle,
                const uv_buf_t bufs[], unsigned int nbufs,
                const struct sockaddr* addr, uv_udp_send_cb send_cb) {
  if (handle->io_watcher.fd < 0) return UV_EBADF;
  if (nbufs == 0) return UV_EINVAL;

  memset(req, 0, sizeof(*req));
  req->type = UV_UDP_SEND;
  req->handle = handle;
  req->cb = send_cb;

  /* Copy address */
  if (addr->sa_family == AF_INET)
    memcpy(&req->u.storage, addr, sizeof(struct sockaddr_in));
  else
    memcpy(&req->u.storage, addr, sizeof(struct sockaddr_in6));

  /* Copy buffers — use small inline array if possible */
  req->nbufs = nbufs;
  if (nbufs <= 4) {
    req->bufs = req->bufsml;
  } else {
    req->bufs = (uv_buf_t*)malloc(nbufs * sizeof(uv_buf_t));
    if (!req->bufs) return UV_ENOMEM;
  }
  memcpy(req->bufs, bufs, nbufs * sizeof(uv_buf_t));

  /* Track queue size */
  size_t total = 0;
  for (unsigned int i = 0; i < nbufs; i++)
    total += bufs[i].len;
  handle->send_queue_size += total;
  handle->send_queue_count++;
  req->status = (ssize_t)total;

  /* Enqueue */
  uv__queue_insert_tail(&handle->write_queue, &req->queue);

  /* Mark fd as needing POLLOUT */
  handle->io_watcher.pevents |= 0x04; /* POLLOUT */

  return 0;
}

int uv_udp_recv_start(uv_udp_t* handle, uv_alloc_cb alloc_cb,
                      uv_udp_recv_cb recv_cb) {
  if (handle->io_watcher.fd < 0) return UV_EBADF;
  if (uv__is_closing((uv_handle_t*)handle)) return UV_EINVAL;
  if (handle->recv_cb != NULL) return UV_EALREADY;

  handle->alloc_cb = alloc_cb;
  handle->recv_cb = recv_cb;
  handle->io_watcher.pevents |= 0x01; /* POLLIN */
  handle->flags |= UV_HANDLE_READING;
  uv__handle_start((uv_handle_t*)handle);
  return 0;
}

int uv_udp_recv_stop(uv_udp_t* handle) {
  handle->alloc_cb = NULL;
  handle->recv_cb = NULL;
  handle->io_watcher.pevents &= ~0x01;
  handle->flags &= ~UV_HANDLE_READING;
  return 0;
}

int uv_udp_set_ttl(uv_udp_t* handle, int ttl) {
  int fd = handle->io_watcher.fd;
  if (fd < 0) return UV_EBADF;
  if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
    return uv__translate_errno(errno);
  return 0;
}

/* Multicast — stub as UV_ENOSYS (DHT doesn't use multicast) */
int uv_udp_set_membership(uv_udp_t* handle, const char* multicast_addr,
                          const char* interface_addr,
                          uv_membership membership) {
  (void)handle; (void)multicast_addr; (void)interface_addr; (void)membership;
  return UV_ENOSYS;
}

int uv_udp_set_source_membership(uv_udp_t* handle,
                                 const char* multicast_addr,
                                 const char* interface_addr,
                                 const char* source_addr,
                                 uv_membership membership) {
  (void)handle; (void)multicast_addr; (void)interface_addr;
  (void)source_addr; (void)membership;
  return UV_ENOSYS;
}

int uv_udp_set_multicast_loop(uv_udp_t* handle, int on) {
  (void)handle; (void)on;
  return UV_ENOSYS;
}

int uv_udp_set_multicast_interface(uv_udp_t* handle,
                                   const char* interface_addr) {
  (void)handle; (void)interface_addr;
  return UV_ENOSYS;
}
