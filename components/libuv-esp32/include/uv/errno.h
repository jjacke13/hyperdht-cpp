/* libuv-esp32 shim — error codes.
 * Matches libuv's UV_ERRNO_MAP exactly so libudx error handling works.
 */

#ifndef UV_ERRNO_H
#define UV_ERRNO_H

#include <errno.h>

/* Map UV errors to negative unique values.
 * Real libuv uses the same scheme: UV__ERR(x) = -(x). */
#define UV__ERR(x) (-(x))

#define UV_ERRNO_MAP(XX)                                                      \
  XX(E2BIG, "argument list too long")                                         \
  XX(EACCES, "permission denied")                                             \
  XX(EADDRINUSE, "address already in use")                                    \
  XX(EADDRNOTAVAIL, "address not available")                                  \
  XX(EAFNOSUPPORT, "address family not supported")                            \
  XX(EAGAIN, "resource temporarily unavailable")                              \
  XX(EAI_ADDRFAMILY, "address family not supported")                          \
  XX(EAI_AGAIN, "temporary failure")                                          \
  XX(EAI_BADFLAGS, "bad ai_flags value")                                      \
  XX(EAI_BADHINTS, "invalid value for hints")                                 \
  XX(EAI_CANCELED, "request canceled")                                        \
  XX(EAI_FAIL, "permanent failure")                                           \
  XX(EAI_FAMILY, "ai_family not supported")                                   \
  XX(EAI_MEMORY, "out of memory")                                             \
  XX(EAI_NODATA, "no address")                                                \
  XX(EAI_NONAME, "unknown node or service")                                   \
  XX(EAI_OVERFLOW, "argument buffer overflow")                                \
  XX(EAI_PROTOCOL, "resolved protocol is unknown")                            \
  XX(EAI_SERVICE, "service not available for socket type")                    \
  XX(EAI_SOCKTYPE, "socket type not supported")                               \
  XX(EALREADY, "connection already in progress")                              \
  XX(EBADF, "bad file descriptor")                                            \
  XX(EBUSY, "resource busy or locked")                                        \
  XX(ECANCELED, "operation canceled")                                         \
  XX(ECHARSET, "invalid Unicode character")                                   \
  XX(ECONNABORTED, "software caused connection abort")                        \
  XX(ECONNREFUSED, "connection refused")                                      \
  XX(ECONNRESET, "connection reset by peer")                                  \
  XX(EDESTADDRREQ, "destination address required")                            \
  XX(EEXIST, "file already exists")                                           \
  XX(EFAULT, "bad address in system call argument")                           \
  XX(EFBIG, "file too large")                                                 \
  XX(EHOSTUNREACH, "host is unreachable")                                     \
  XX(EINTR, "interrupted system call")                                        \
  XX(EINVAL, "invalid argument")                                              \
  XX(EIO, "i/o error")                                                        \
  XX(EISCONN, "socket is already connected")                                  \
  XX(EISDIR, "illegal operation on a directory")                              \
  XX(ELOOP, "too many symbolic links encountered")                            \
  XX(EMFILE, "too many open files")                                           \
  XX(EMSGSIZE, "message too long")                                            \
  XX(ENAMETOOLONG, "name too long")                                           \
  XX(ENETDOWN, "network is down")                                             \
  XX(ENETUNREACH, "network is unreachable")                                   \
  XX(ENFILE, "file table overflow")                                           \
  XX(ENOBUFS, "no buffer space available")                                    \
  XX(ENODEV, "no such device")                                                \
  XX(ENOENT, "no such file or directory")                                     \
  XX(ENOMEM, "not enough memory")                                             \
  XX(ENONET, "machine is not on the network")                                 \
  XX(ENOPROTOOPT, "protocol not available")                                   \
  XX(ENOSPC, "no space left on device")                                       \
  XX(ENOSYS, "function not implemented")                                      \
  XX(ENOTCONN, "socket is not connected")                                     \
  XX(ENOTDIR, "not a directory")                                              \
  XX(ENOTEMPTY, "directory not empty")                                        \
  XX(ENOTSOCK, "socket operation on non-socket")                              \
  XX(ENOTSUP, "operation not supported on socket")                            \
  XX(EOVERFLOW, "value too large for defined data type")                      \
  XX(EPERM, "operation not permitted")                                        \
  XX(EPIPE, "broken pipe")                                                    \
  XX(EPROTO, "protocol error")                                                \
  XX(EPROTONOSUPPORT, "protocol not supported")                               \
  XX(EPROTOTYPE, "protocol wrong type for socket")                            \
  XX(ERANGE, "result too large")                                              \
  XX(EROFS, "read-only file system")                                          \
  XX(ESHUTDOWN, "cannot send after transport endpoint shutdown")              \
  XX(ESPIPE, "invalid seek")                                                  \
  XX(ESRCH, "no such process")                                                \
  XX(ETIMEDOUT, "connection timed out")                                       \
  XX(ETXTBSY, "text file is busy")                                            \
  XX(EXDEV, "cross-device link not permitted")                                \
  XX(UNKNOWN, "unknown error")                                                \
  XX(EOF, "end of file")                                                      \
  XX(ENXIO, "no such device or address")                                      \
  XX(EMLINK, "too many links")                                                \
  XX(ENOTTY, "inappropriate ioctl for device")                                \
  XX(EFTYPE, "inappropriate file type or format")                             \
  XX(EILSEQ, "illegal byte sequence")                                         \
  XX(ESOCKTNOSUPPORT, "socket type not supported")                            \
  XX(EUNATCH, "protocol driver not attached")                                 \

/* Generate UV_E* constants.
 * Real libuv: UV_EAGAIN = UV__ERR(EAGAIN), UV_EOF = UV__ERR(4095), etc.
 * EAI_* use an offset to avoid colliding with system errno values. */
#define UV_ERRNO_GEN(name, msg) UV_ ## name = UV__ERR(UV__ ## name),

/* Internal values for the errno map */
enum {
  UV__E2BIG = E2BIG,
  UV__EACCES = EACCES,
  UV__EADDRINUSE = EADDRINUSE,
  UV__EADDRNOTAVAIL = EADDRNOTAVAIL,
  UV__EAFNOSUPPORT = EAFNOSUPPORT,
  UV__EAGAIN = EAGAIN,
  UV__EALREADY = EALREADY,
  UV__EBADF = EBADF,
  UV__EBUSY = EBUSY,
  UV__ECANCELED = ECANCELED,
  UV__ECONNABORTED = ECONNABORTED,
  UV__ECONNREFUSED = ECONNREFUSED,
  UV__ECONNRESET = ECONNRESET,
  UV__EDESTADDRREQ = EDESTADDRREQ,
  UV__EEXIST = EEXIST,
  UV__EFAULT = EFAULT,
  UV__EFBIG = EFBIG,
  UV__EHOSTUNREACH = EHOSTUNREACH,
  UV__EINTR = EINTR,
  UV__EINVAL = EINVAL,
  UV__EIO = EIO,
  UV__EISCONN = EISCONN,
  UV__EISDIR = EISDIR,
  UV__ELOOP = ELOOP,
  UV__EMFILE = EMFILE,
  UV__EMSGSIZE = EMSGSIZE,
  UV__ENAMETOOLONG = ENAMETOOLONG,
  UV__ENETDOWN = ENETDOWN,
  UV__ENETUNREACH = ENETUNREACH,
  UV__ENFILE = ENFILE,
  UV__ENOBUFS = ENOBUFS,
  UV__ENODEV = ENODEV,
  UV__ENOENT = ENOENT,
  UV__ENOMEM = ENOMEM,
  UV__ENONET = ENOPROTOOPT + 1,  /* may not exist on all platforms */
  UV__ENOPROTOOPT = ENOPROTOOPT,
  UV__ENOSPC = ENOSPC,
  UV__ENOSYS = ENOSYS,
  UV__ENOTCONN = ENOTCONN,
  UV__ENOTDIR = ENOTDIR,
  UV__ENOTEMPTY = ENOTEMPTY,
  UV__ENOTSOCK = ENOTSOCK,
  UV__ENOTSUP = ENOTSUP,
  UV__EOVERFLOW = EOVERFLOW,
  UV__EPERM = EPERM,
  UV__EPIPE = EPIPE,
  UV__EPROTO = EPROTO,
  UV__EPROTONOSUPPORT = EPROTONOSUPPORT,
  UV__EPROTOTYPE = EPROTOTYPE,
  UV__ERANGE = ERANGE,
  UV__EROFS = EROFS,
  UV__ESHUTDOWN = ESHUTDOWN,
  UV__ESPIPE = ESPIPE,
  UV__ESRCH = ESRCH,
  UV__ETIMEDOUT = ETIMEDOUT,
  UV__ETXTBSY = ETXTBSY,
  UV__EXDEV = EXDEV,
  UV__ENXIO = ENXIO,
  UV__EMLINK = EMLINK,
  UV__ENOTTY = ENOTTY,
  UV__EILSEQ = EILSEQ,
  /* Synthetic errors */
  UV__ECHARSET = 4080,
  UV__UNKNOWN = 4094,
  UV__EOF = 4095,
  UV__EFTYPE = 4030,
  UV__ESOCKTNOSUPPORT = 4031,
  UV__EUNATCH = 4032,
  /* EAI errors — offset by 3000 to avoid collisions */
  UV__EAI_ADDRFAMILY = 3000,
  UV__EAI_AGAIN = 3001,
  UV__EAI_BADFLAGS = 3002,
  UV__EAI_BADHINTS = 3003,
  UV__EAI_CANCELED = 3004,
  UV__EAI_FAIL = 3005,
  UV__EAI_FAMILY = 3006,
  UV__EAI_MEMORY = 3007,
  UV__EAI_NODATA = 3008,
  UV__EAI_NONAME = 3009,
  UV__EAI_OVERFLOW = 3010,
  UV__EAI_PROTOCOL = 3011,
  UV__EAI_SERVICE = 3012,
  UV__EAI_SOCKTYPE = 3013,
};

typedef enum {
  UV_ERRNO_MAP(UV_ERRNO_GEN)
} uv_errno_t;

#undef UV_ERRNO_GEN

#endif /* UV_ERRNO_H */
