/* HyperDHT on ESP32-S3 — connect to echo server. */

#include <stdio.h>
#include <string.h>
#include <uv.h>
#include <hyperdht/hyperdht.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_heap_caps.h"

#define TAG "dht"
#define WIFI_CONNECTED_BIT BIT0
static EventGroupHandle_t s_wifi_event_group;

static const uint8_t SERVER_PK[32] = {
    0xb7, 0xc5, 0xc4, 0xe9, 0x09, 0xad, 0x28, 0xe2,
    0x07, 0x1c, 0x48, 0xa0, 0x9f, 0x33, 0x0e, 0xc2,
    0x73, 0x52, 0x48, 0xa4, 0xe4, 0xd8, 0x75, 0x90,
    0x32, 0xa9, 0xb5, 0x7b, 0x0f, 0x2e, 0x7a, 0xec
};

static hyperdht_t* g_dht = NULL;
static hyperdht_stream_t* g_stream = NULL;

/* --- WiFi --- */

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
        esp_wifi_connect();
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "WiFi disconnected, retrying...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*)event_data;
        ESP_LOGI(TAG, "got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_event_handler_instance_t i1, i2;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &i1));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &i2));
    wifi_config_t wc = {
        .sta = { .ssid = CONFIG_WIFI_SSID, .password = CONFIG_WIFI_PASSWORD },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "connecting to WiFi: %s", CONFIG_WIFI_SSID);
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
        WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(15000));
    if (!(bits & WIFI_CONNECTED_BIT))
        ESP_LOGE(TAG, "WiFi FAILED");
}

/* --- Stream callbacks --- */

static void on_stream_open(void* userdata) {
    (void)userdata;
    ESP_LOGI(TAG, "stream OPEN — sending hello");
    const char* msg = "hello from ESP32-S3!";
    hyperdht_stream_write(g_stream, (const uint8_t*)msg, strlen(msg));
}

static void on_stream_data(const uint8_t* data, size_t len, void* userdata) {
    ESP_LOGI(TAG, "ECHO received (%zu bytes): %.*s", len, (int)len, (const char*)data);
}

static void on_stream_close(void* userdata) {
    ESP_LOGI(TAG, "stream CLOSED");
}

/* --- Connect callback --- */

static void on_connect(int error, const hyperdht_connection_t* conn, void* userdata) {
    if (error != 0) {
        ESP_LOGE(TAG, "connect FAILED: %d", error);
        return;
    }

    ESP_LOGI(TAG, "CONNECTED to %s:%u", conn->peer_host, conn->peer_port);

    g_stream = hyperdht_stream_open(
        g_dht, conn, on_stream_open, on_stream_data, on_stream_close, NULL);

    if (!g_stream)
        ESP_LOGE(TAG, "stream_open failed!");
}

/* --- Bootstrap callback --- */

static void on_bootstrapped(void* userdata) {
    hyperdht_t* dht = (hyperdht_t*)userdata;
    ESP_LOGI(TAG, "BOOTSTRAPPED on port %u — connecting to server...",
             hyperdht_port(dht));
    hyperdht_connect(dht, SERVER_PK, on_connect, NULL);
}

/* --- Main --- */

void app_main(void) {
    ESP_LOGI(TAG, "HyperDHT ESP32-S3 — echo test");
    ESP_LOGI(TAG, "  free heap: %zu KB",
             heap_caps_get_free_size(MALLOC_CAP_DEFAULT) / 1024);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_sta();

    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_opts_t opts;
    hyperdht_opts_default(&opts);
    opts.use_public_bootstrap = 1;

    ESP_LOGI(TAG, "creating DHT node...");
    g_dht = hyperdht_create(&loop, &opts);
    if (!g_dht) {
        ESP_LOGE(TAG, "create failed!");
        return;
    }

    hyperdht_bind(g_dht, 0);
    ESP_LOGI(TAG, "bound on port %u", hyperdht_port(g_dht));
    hyperdht_on_bootstrapped(g_dht, on_bootstrapped, g_dht);

    ESP_LOGI(TAG, "running...");
    while (uv_run(&loop, UV_RUN_ONCE))
        vTaskDelay(1);

    ESP_LOGI(TAG, "done");
}
