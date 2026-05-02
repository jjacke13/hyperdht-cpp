# Nospoon P2P VPN — cross-platform build (Linux + Windows).
#
# Build (Linux, after building libhyperdht into ../../../build):
#   cmake -B build-nospoon -G Ninja -S examples/cpp/nospoon
#   ninja -C build-nospoon
#
# Build (Windows, vcpkg + MSVC, after building hyperdht into ../../../build-shared):
#   cmake -B build-nospoon -G Ninja -S examples/cpp/nospoon \
#       -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
#       -DVCPKG_TARGET_TRIPLET=x64-windows-static-md \
#       -DHYPERDHT_LIB_DIR=../../../build-shared
#   cmake --build build-nospoon

cmake_minimum_required(VERSION 3.20)
project(nospoon LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(nospoon
    main.cpp
    server.cpp
    client.cpp)

if(WIN32)
    target_sources(nospoon PRIVATE
        tun_windows.cpp
        full_tunnel_windows.cpp)
else()
    target_sources(nospoon PRIVATE
        full_tunnel_linux.cpp)
endif()

target_include_directories(nospoon PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../deps/libudx/include)

# Suppress libudx debug_printf noise (TLP, congestion control chatter)
target_compile_definitions(nospoon PRIVATE NDEBUG)

# === Dependencies ===

if(WIN32)
    # vcpkg provides config packages for libsodium + libuv.
    find_package(unofficial-sodium CONFIG REQUIRED)
    find_package(libuv CONFIG REQUIRED)
    set(SODIUM_TARGET unofficial-sodium::sodium)
    if(TARGET libuv::uv_a)
        set(UV_TARGET libuv::uv_a)
    elseif(TARGET libuv::uv)
        set(UV_TARGET libuv::uv)
    else()
        message(FATAL_ERROR "libuv vcpkg target not found")
    endif()

    target_compile_definitions(nospoon PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS)
    # We link the static hyperdht.lib (the DLL only exports the C FFI;
    # nospoon uses C++ classes directly). Don't define HYPERDHT_SHARED.
else()
    find_library(SODIUM_LIB sodium REQUIRED)
    find_library(UV_LIB uv REQUIRED)
    set(SODIUM_TARGET ${SODIUM_LIB})
    set(UV_TARGET ${UV_LIB})
endif()

# hyperdht library — pass HYPERDHT_LIB_DIR to override (Linux defaults to
# ../../../build, the existing standalone-build convention).
if(NOT DEFINED HYPERDHT_LIB_DIR)
    set(HYPERDHT_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../build)
endif()

if(WIN32)
    # Link the STATIC hyperdht.lib — the DLL build only exports the C FFI
    # surface (HYPERDHT_API), and nospoon uses C++ classes directly.
    # Pass HYPERDHT_LIB_DIR pointing at the static-build directory.
    set(HYPERDHT_LIB ${HYPERDHT_LIB_DIR}/hyperdht.lib)
    # libudx is a separate static archive in the same build dir.
    list(APPEND HYPERDHT_LIB ${HYPERDHT_LIB_DIR}/udx.lib)
else()
    set(HYPERDHT_LIB ${HYPERDHT_LIB_DIR}/libhyperdht.so)
endif()

target_link_libraries(nospoon PRIVATE
    ${HYPERDHT_LIB}
    ${SODIUM_TARGET}
    ${UV_TARGET})

if(WIN32)
    # raw socket types come in via libuv but we link the SDK libs explicitly
    # (winsock + ip-helper for routing/forwarding queries used elsewhere).
    target_link_libraries(nospoon PRIVATE Ws2_32 Iphlpapi)
endif()
