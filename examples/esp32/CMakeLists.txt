# ESP-IDF project — HyperDHT on ESP32-S3
cmake_minimum_required(VERSION 3.16)

# Extra component directories (our shim + library)
set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/../../components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(hyperdht-esp32)
