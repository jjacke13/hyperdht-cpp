cmake_minimum_required(VERSION 3.20)
project(hyperdht-cpp
    VERSION 0.1.0
    LANGUAGES C CXX
    DESCRIPTION "C++ reimplementation of HyperDHT"
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# === Options ===
option(HYPERDHT_DEBUG "Enable debug logging to stderr" OFF)
option(HYPERDHT_EMBEDDED "Reduce sizing constants for embedded targets (ESP32)" OFF)

# === Dependencies ===

# Support two modes: pkg-config (desktop) or explicit paths (Android cross-compile)
if(NOT CMAKE_DISABLE_FIND_PACKAGE_PkgConfig AND NOT SODIUM_LIBRARY)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    pkg_check_modules(UV REQUIRED IMPORTED_TARGET libuv)
    set(SODIUM_TARGET PkgConfig::SODIUM)
    set(UV_TARGET PkgConfig::UV)
else()
    # Android / manual: SODIUM_INCLUDE_DIR, SODIUM_LIBRARY, UV_INCLUDE_DIR, UV_LIBRARY
    add_library(sodium_ext STATIC IMPORTED)
    set_target_properties(sodium_ext PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")
    add_library(uv_ext STATIC IMPORTED)
    set_target_properties(uv_ext PROPERTIES
        IMPORTED_LOCATION "${UV_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${UV_INCLUDE_DIR}")
    set(SODIUM_TARGET sodium_ext)
    set(UV_TARGET uv_ext)
endif()

# libudx — C library from git submodule
# libudx is always static (internal dependency, compiled into libhyperdht)
add_library(udx STATIC
    deps/libudx/src/udx.c
    deps/libudx/src/io_posix.c
    deps/libudx/src/cirbuf.c
    deps/libudx/src/queue.c
    deps/libudx/src/endian.c
    deps/libudx/src/udx_bbr.c
    deps/libudx/src/udx_rate.c
    deps/libudx/src/win_filter.c
    deps/libudx/src/win_filter_f64.c
)
target_include_directories(udx
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/libudx/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE deps/libudx/src
)
target_link_libraries(udx PUBLIC ${UV_TARGET})

# Android NDK's Bionic: IN6_IS_ADDR_V4MAPPED macro uses ntohl without
# the header that declares it. Suppress the implicit declaration warning.
# ntohl is always available at link time on Bionic.
if(ANDROID)
    target_compile_options(udx PRIVATE -Wno-implicit-function-declaration)
endif()

# === Library ===

add_library(hyperdht
    src/compact.cpp
    src/udx.cpp
    src/noise_wrap.cpp
    src/secret_stream.cpp
    src/routing_table.cpp
    src/tokens.cpp
    src/messages.cpp
    src/rpc.cpp
    src/rpc_handlers.cpp
    src/announce.cpp
    src/query.cpp
    src/dht_ops.cpp
    src/peer_connect.cpp
    src/holepunch.cpp
    src/nat_sampler.cpp
    src/socket_pool.cpp
    src/connection_pool.cpp
    src/async_utils.cpp
    src/health.cpp
    src/protomux.cpp
    src/dht_messages.cpp
    src/announce_sig.cpp
    src/router.cpp
    src/server_connection.cpp
    src/announcer.cpp
    src/server.cpp
    src/blind_relay.cpp
    src/dht.cpp
    src/connect.cpp
    src/dht_storage.cpp
    src/dht_network.cpp
    src/ffi_core.cpp
    src/ffi_server.cpp
    src/ffi_stream.cpp
    src/ffi_storage.cpp
)
target_include_directories(hyperdht PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(hyperdht PUBLIC
    udx
    ${SODIUM_TARGET}
    ${UV_TARGET}
)
if(HYPERDHT_DEBUG)
    target_compile_definitions(hyperdht PUBLIC HYPERDHT_DEBUG=1)
endif()
if(HYPERDHT_EMBEDDED)
    target_compile_definitions(hyperdht PUBLIC HYPERDHT_EMBEDDED=1)
endif()

# Position-independent code (needed for shared lib and when static is linked into a .so)
set_target_properties(hyperdht PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(udx PROPERTIES POSITION_INDEPENDENT_CODE ON)

# When building as shared library in Release mode, export only HYPERDHT_API functions.
# In Debug mode, all symbols are visible (needed for tests that use C++ internals).
if(BUILD_SHARED_LIBS)
    target_compile_definitions(hyperdht PRIVATE HYPERDHT_SHARED=1)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set_target_properties(hyperdht PROPERTIES
            C_VISIBILITY_PRESET hidden
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
        )
    endif()
endif()

# === Install rules ===

include(GNUInstallDirs)

# Install the library and libudx (both must be in the export set).
# For shared builds, libudx is compiled into libhyperdht.so so its
# .a is not needed by consumers — but CMake requires it in the export.
install(TARGETS hyperdht udx
    EXPORT hyperdht-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install public headers
install(DIRECTORY include/hyperdht
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

# Install libudx headers (dependency)
install(DIRECTORY deps/libudx/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# Install CMake package config (for find_package(hyperdht))
install(EXPORT hyperdht-targets
    FILE hyperdht-config.cmake
    NAMESPACE hyperdht::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/hyperdht
)

# Generate pkg-config file
if(NOT BUILD_SHARED_LIBS)
    set(HYPERDHT_PC_EXTRA_LIBS "-ludx")
else()
    set(HYPERDHT_PC_EXTRA_LIBS "")
endif()
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/hyperdht.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/hyperdht.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/hyperdht.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# === Tests ===

option(HYPERDHT_BUILD_TESTS "Build tests" ON)

if(HYPERDHT_BUILD_TESTS)
    # Try system GTest first (nix provides it), fall back to FetchContent
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.15.2
        )
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()

    enable_testing()

    # ── Unit tests (offline, automated) ─────────────────────────────
    include(GoogleTest)

    # Helper: define a unit test executable with label "unit"
    macro(add_unit_test name)
        add_executable(${name} test/${name}.cpp)
        target_link_libraries(${name} PRIVATE hyperdht GTest::gtest_main)
        gtest_discover_tests(${name} PROPERTIES LABELS "unit")
    endmacro()

    add_unit_test(test_compact)
    add_unit_test(test_compact_cross)
    add_unit_test(test_udx)
    add_unit_test(test_udx_cross)
    add_unit_test(test_udx_packet_capture)
    add_unit_test(test_noise)
    add_unit_test(test_noise_cross)
    add_unit_test(test_secret_stream)
    add_unit_test(test_crypto_verify)
    add_unit_test(test_routing_table)
    add_unit_test(test_wire_compat)
    add_unit_test(test_edge_cases)
    add_unit_test(test_lru_cache)
    add_unit_test(test_c_api)
    add_unit_test(test_tokens)
    add_unit_test(test_messages)
    add_unit_test(test_rpc_ping)
    add_unit_test(test_rpc_bootstrap)
    add_unit_test(test_rpc_handlers)
    add_unit_test(test_announce)
    add_unit_test(test_query)
    add_unit_test(test_dht_ops)
    add_unit_test(test_holepunch)
    add_unit_test(test_hyperdht)
    add_unit_test(test_server)
    add_unit_test(test_announcer)
    add_unit_test(test_server_holepunch)
    add_unit_test(test_server_handshake)
    add_unit_test(test_router)
    add_unit_test(test_announce_sig)
    add_unit_test(test_dht_messages)
    add_unit_test(test_protomux)
    add_unit_test(test_protomux_secretstream)
    add_unit_test(test_blind_relay)
    add_unit_test(test_health)
    add_unit_test(test_nat_sampler)
    add_unit_test(test_socket_pool)
    add_unit_test(test_connection_pool)
    add_unit_test(test_async_utils)

    # ── Live tests (need network / external peers) ───────────────
    # Run with: ctest -L live

    macro(add_live_test name)
        add_executable(${name} test/${name}.cpp)
        target_link_libraries(${name} PRIVATE hyperdht GTest::gtest_main)
        gtest_discover_tests(${name} PROPERTIES LABELS "live")
    endmacro()

    add_live_test(test_server_live)
    add_live_test(test_live_connect)
    add_live_test(test_storage_live)

    # Bootstrap walk against the public HyperDHT network.
    # Skips automatically when unreachable.
    add_live_test(test_live_bootstrap_smoke)

    # Echo test against the permanent JS fixture.
    # Skips when SERVER_KEY env var is not set.
    add_live_test(test_echo_fixture)
endif()
