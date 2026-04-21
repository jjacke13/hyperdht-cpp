/* libuv-esp32 shim — network interface enumeration.
 *
 * On ESP-IDF: uses esp_netif_next() + esp_netif_get_ip_info().
 * On Linux (host testing): returns a single loopback entry.
 */

#include "internal.h"

#ifdef ESP_PLATFORM
#include <esp_netif.h>
#include <esp_mac.h>

int uv_interface_addresses(uv_interface_address_t** addrs, int* count) {
  /* Count interfaces */
  int n = 0;
  esp_netif_t* netif = NULL;
  while ((netif = esp_netif_next(netif)) != NULL)
    n++;

  if (n == 0) {
    *addrs = NULL;
    *count = 0;
    return 0;
  }

  *addrs = (uv_interface_address_t*)calloc((size_t)n,
                                           sizeof(uv_interface_address_t));
  if (!*addrs) return UV_ENOMEM;

  int i = 0;
  netif = NULL;
  while ((netif = esp_netif_next(netif)) != NULL && i < n) {
    uv_interface_address_t* a = &(*addrs)[i];

    const char* key = esp_netif_get_ifkey(netif);
    if (key)
      strncpy(a->name, key, sizeof(a->name) - 1);
    else
      strncpy(a->name, "?", sizeof(a->name) - 1);

    esp_netif_get_mac(netif, (uint8_t*)a->phys_addr);
    a->is_internal = 0;

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
      struct sockaddr_in* sa = (struct sockaddr_in*)&a->address.address4;
      sa->sin_family = AF_INET;
      sa->sin_addr.s_addr = ip_info.ip.addr;

      struct sockaddr_in* nm = (struct sockaddr_in*)&a->netmask.netmask4;
      nm->sin_family = AF_INET;
      nm->sin_addr.s_addr = ip_info.netmask.addr;
    }
    i++;
  }

  *count = i;
  return 0;
}

#else /* Linux host */

int uv_interface_addresses(uv_interface_address_t** addrs, int* count) {
  /* Minimal stub for host testing — return loopback only */
  *addrs = (uv_interface_address_t*)calloc(1, sizeof(uv_interface_address_t));
  if (!*addrs) return UV_ENOMEM;

  strncpy((*addrs)[0].name, "lo", sizeof((*addrs)[0].name));
  (*addrs)[0].is_internal = 1;
  struct sockaddr_in* sa = (struct sockaddr_in*)&(*addrs)[0].address.address4;
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = htonl(0x7f000001);  /* 127.0.0.1 */

  *count = 1;
  return 0;
}

#endif

void uv_free_interface_addresses(uv_interface_address_t* addrs, int count) {
  (void)count;
  free(addrs);
}
