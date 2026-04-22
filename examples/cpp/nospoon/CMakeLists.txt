# Nospoon P2P VPN — standalone build
#
# Build (from repo root, after building libhyperdht):
#   cmake -B build-nospoon -G Ninja -S examples/cpp/nospoon
#   ninja -C build-nospoon

cmake_minimum_required(VERSION 3.20)
project(nospoon LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

add_executable(nospoon
    main.cpp
    server.cpp
    client.cpp)

target_include_directories(nospoon PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../deps/libudx/include)

find_library(SODIUM_LIB sodium REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link against the shared library (build/ produces .so by default)
target_link_libraries(nospoon PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../build/libhyperdht.so
    ${SODIUM_LIB}
    ${UV_LIB})
