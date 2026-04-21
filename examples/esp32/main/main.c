/* HyperDHT on ESP32-S3 — bootstrap test. */

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
    if (bits & WIFI_CONNECTED_BIT)
        ESP_LOGI(TAG, "WiFi connected");
    else
        ESP_LOGE(TAG, "WiFi connection FAILED");
}

static void on_bootstrapped(void* userdata) {
    hyperdht_t* dht = (hyperdht_t*)userdata;
    ESP_LOGI(TAG, "*** BOOTSTRAPPED on port %u ***", hyperdht_port(dht));
    ESP_LOGI(TAG, "  online:     %d", hyperdht_is_online(dht));
    ESP_LOGI(TAG, "  free heap:  %zu KB",
             heap_caps_get_free_size(MALLOC_CAP_DEFAULT) / 1024);
}

void app_main(void) {
    ESP_LOGI(TAG, "HyperDHT ESP32-S3 bootstrap test");
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
    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    if (!dht) {
        ESP_LOGE(TAG, "hyperdht_create failed!");
        return;
    }

    int rc = hyperdht_bind(dht, 0);
    ESP_LOGI(TAG, "bind rc=%d, port=%u", rc, hyperdht_port(dht));
    hyperdht_on_bootstrapped(dht, on_bootstrapped, dht);

    ESP_LOGI(TAG, "running event loop (v2) — active_handles=%u",
             loop.active_handles);
    int iter = 0;
    int alive;
    do {
        alive = uv_run(&loop, UV_RUN_ONCE);
        if (++iter % 100 == 1)
            ESP_LOGI(TAG, "iter %d, alive=%d, handles=%u, time=%llu",
                     iter, alive, loop.active_handles,
                     (unsigned long long)uv_now(&loop));
        vTaskDelay(1);
    } while (alive);

    ESP_LOGI(TAG, "cleaning up...");
    hyperdht_destroy(dht, NULL, NULL);
    while (uv_run(&loop, UV_RUN_ONCE))
        vTaskDelay(1);
    hyperdht_free(dht);
    uv_loop_close(&loop);
    ESP_LOGI(TAG, "done");
}
