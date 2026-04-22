idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES libuv-esp32 hyperdht esp_wifi esp_event esp_netif nvs_flash
)
