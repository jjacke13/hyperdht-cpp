/* Minimal ESP32 test — verify libuv-esp32 shim works.
 *
 * Creates a loop, starts a timer, runs the loop for a few ticks,
 * then cleans up. This validates the shim's core functionality
 * (loop, timer, select) before wiring up the full DHT.
 */

#include <stdio.h>
#include <uv.h>

#ifdef ESP_PLATFORM
#include "esp_log.h"
#define TAG "dht"
#define LOG(fmt, ...) ESP_LOGI(TAG, fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
#endif

static int tick_count = 0;

static void on_timer(uv_timer_t* handle) {
  tick_count++;
  LOG("tick %d — loop time: %llu ms", tick_count, (unsigned long long)uv_now(handle->loop));

  if (tick_count >= 5) {
    LOG("stopping after %d ticks", tick_count);
    uv_timer_stop(handle);
    uv_close((uv_handle_t*)handle, NULL);
  }
}

#ifdef ESP_PLATFORM
void app_main(void) {
#else
int main(void) {
#endif
  LOG("libuv-esp32 shim test");
  LOG("  uv version: %s", uv_version_string());

  uv_loop_t loop;
  uv_loop_init(&loop);

  uv_timer_t timer;
  uv_timer_init(&loop, &timer);
  uv_timer_start(&timer, on_timer, 0, 500);  /* fire every 500ms */

  LOG("running loop...");
  uv_run(&loop, UV_RUN_DEFAULT);

  uv_loop_close(&loop);
  LOG("done — %d ticks completed", tick_count);

#ifndef ESP_PLATFORM
  return tick_count == 5 ? 0 : 1;
#endif
}
