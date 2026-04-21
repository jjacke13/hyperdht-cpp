# libuv-esp32 shim — minimal libuv replacement for ESP32/FreeRTOS.
#
# Two build modes:
# 1. ESP-IDF component: idf_component_register() (when IDF_TARGET is set)
# 2. Standalone CMake: for host testing (Linux, no ESP-IDF)

if(DEFINED IDF_TARGET)
  # ESP-IDF component mode
  idf_component_register(
    SRCS
      "src/uv_loop.c"
      "src/uv_handle.c"
      "src/uv_timer.c"
      "src/uv_udp.c"
      "src/uv_prepare.c"
      "src/uv_async.c"
      "src/uv_poll.c"
      "src/uv_misc.c"
      "src/uv_interface.c"
      "src/uv_getaddrinfo.c"
    INCLUDE_DIRS
      "include"
    PRIV_REQUIRES
      lwip
      esp_netif
      esp_timer
      vfs
      esp_event
  )
else()
  # Standalone mode (host testing)
  cmake_minimum_required(VERSION 3.20)
  project(libuv-esp32 C)

  add_library(uv STATIC
    src/uv_loop.c
    src/uv_handle.c
    src/uv_timer.c
    src/uv_udp.c
    src/uv_prepare.c
    src/uv_async.c
    src/uv_poll.c
    src/uv_misc.c
    src/uv_interface.c
    src/uv_getaddrinfo.c
  )

  target_include_directories(uv PUBLIC include)
  target_include_directories(uv PRIVATE src)
  target_compile_options(uv PRIVATE -Wall -Wextra -Werror -std=c11)
  target_compile_definitions(uv PRIVATE _GNU_SOURCE)

  # On Linux, we need pthread for mutex types in the header
  find_package(Threads REQUIRED)
  target_link_libraries(uv PRIVATE Threads::Threads)
endif()
