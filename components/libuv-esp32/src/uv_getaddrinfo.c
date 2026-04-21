/* libuv-esp32 shim — DNS resolution.
 * Uses lwip_getaddrinfo() synchronously (no threadpool on ESP32).
 * Real libuv does this on the threadpool; we run it inline since
 * the DHT rarely resolves hostnames (bootstrap nodes are IPs). */

#define _POSIX_C_SOURCE 200112L

#include "internal.h"
#include <netdb.h>

int uv_getaddrinfo(uv_loop_t* loop, uv_getaddrinfo_t* req,
                   uv_getaddrinfo_cb cb, const char* node,
                   const char* service, const struct addrinfo* hints) {
  struct addrinfo* res = NULL;
  int rc;

  (void)loop;

  rc = getaddrinfo(node, service, hints, &res);
  if (rc != 0) {
    if (cb) cb(req, UV_EAI_NONAME, NULL);
    return 0;  /* Callback-style: always returns 0 */
  }

  if (cb) cb(req, 0, res);
  return 0;
}

void uv_freeaddrinfo(struct addrinfo* ai) {
  freeaddrinfo(ai);
}
