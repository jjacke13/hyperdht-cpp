/* HyperDHT echo server on ESP32-S3.
 *
 * Listens for P2P connections and echoes any received data back.
 * Public key printed on boot — give it to clients.
 *
 * Build:
 *   cd examples/esp32/echo-server
 *   nix develop ../../../#esp32
 *   idf.py set-target esp32s3 && idf.py menuconfig  (set WiFi)
 *   idf.py -p /dev/ttyACM0 flash monitor
 */

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

#define TAG "echo-srv"
#define WIFI_CONNECTED_BIT BIT0

static EventGroupHandle_t s_wifi_event_group;
static hyperdht_t* g_dht = NULL;

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

/* --- Per-connection echo --- */

typedef struct {
    hyperdht_stream_t* stream;
    int open;
} echo_ctx_t;

static void on_data(const uint8_t* data, size_t len, void* ud) {
    echo_ctx_t* ctx = (echo_ctx_t*)ud;
    if (!ctx || !ctx->stream || !ctx->open) return;
    ESP_LOGI(TAG, "  recv %zu bytes, echoing", len);
    hyperdht_stream_write(ctx->stream, data, len);
}

static void on_open(void* ud) {
    echo_ctx_t* ctx = (echo_ctx_t*)ud;
    if (ctx) ctx->open = 1;
    ESP_LOGI(TAG, "  stream open");
}

static void on_close(void* ud) {
    ESP_LOGI(TAG, "  stream closed");
    free(ud);
}

static void on_connection(const hyperdht_connection_t* conn, void* ud) {
    hyperdht_t* dht = (hyperdht_t*)ud;

    ESP_LOGI(TAG, "connection from %s:%u  key=%02x%02x%02x%02x...",
             conn->peer_host, conn->peer_port,
             conn->remote_public_key[0], conn->remote_public_key[1],
             conn->remote_public_key[2], conn->remote_public_key[3]);

    echo_ctx_t* ctx = (echo_ctx_t*)calloc(1, sizeof(echo_ctx_t));
    if (!ctx) return;

    hyperdht_stream_t* stream = hyperdht_stream_open(
        dht, conn, on_open, on_data, on_close, ctx);

    if (stream) {
        ctx->stream = stream;
    } else {
        ESP_LOGE(TAG, "  stream_open failed");
        free(ctx);
    }
}

/* --- Server events --- */

static void on_listening(void* ud) {
    (void)ud;
    ESP_LOGI(TAG, "announced — accepting connections");
    ESP_LOGI(TAG, "  free heap: %zu KB",
             heap_caps_get_free_size(MALLOC_CAP_DEFAULT) / 1024);
}

/* --- Main --- */

void app_main(void) {
    ESP_LOGI(TAG, "HyperDHT ESP32-S3 — echo server");

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

    /* Seed from menuconfig */
    const char* seed_hex = CONFIG_SERVER_SEED;
    if (seed_hex && strlen(seed_hex) == 64) {
        for (int i = 0; i < 32; i++) {
            unsigned byte;
            sscanf(seed_hex + i * 2, "%02x", &byte);
            opts.seed[i] = (uint8_t)byte;
        }
        opts.seed_is_set = 1;
    }

    g_dht = hyperdht_create(&loop, &opts);
    if (!g_dht) { ESP_LOGE(TAG, "create failed!"); return; }

    hyperdht_bind(g_dht, 0);

    /* Print public key */
    hyperdht_keypair_t kp;
    hyperdht_default_keypair(g_dht, &kp);
    char pk_hex[65];
    for (int i = 0; i < 32; i++)
        sprintf(pk_hex + i * 2, "%02x", kp.public_key[i]);
    pk_hex[64] = '\0';

    ESP_LOGI(TAG, "public key: %s", pk_hex);

    /* Listen */
    hyperdht_server_t* srv = hyperdht_server_create(g_dht);
    hyperdht_server_on_listening(srv, on_listening, NULL);
    hyperdht_server_listen(srv, &kp, on_connection, g_dht);

    ESP_LOGI(TAG, "listening on port %u...", hyperdht_port(g_dht));

    while (uv_run(&loop, UV_RUN_ONCE))
        vTaskDelay(1);

    ESP_LOGI(TAG, "done");
}
