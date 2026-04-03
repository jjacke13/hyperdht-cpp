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

# === Dependencies ===

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(UV REQUIRED IMPORTED_TARGET libuv)

# libudx — C library from git submodule
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
target_link_libraries(udx PUBLIC PkgConfig::UV)

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
    src/health.cpp
    src/protomux.cpp
    src/dht_messages.cpp
    src/announce_sig.cpp
    src/router.cpp
    src/server_connection.cpp
    src/announcer.cpp
    src/server.cpp
    src/dht.cpp
    src/hyperdht_api.cpp
)
target_include_directories(hyperdht PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(hyperdht PUBLIC
    udx
    PkgConfig::SODIUM
    PkgConfig::UV
)
if(HYPERDHT_DEBUG)
    target_compile_definitions(hyperdht PUBLIC HYPERDHT_DEBUG=1)
endif()

# Position-independent code (needed if static lib is linked into a .so)
set_target_properties(hyperdht PROPERTIES POSITION_INDEPENDENT_CODE ON)

# === Install rules ===

include(GNUInstallDirs)

# Install the library and libudx
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
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    add_executable(test_compact test/test_compact.cpp)
    target_link_libraries(test_compact PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_compact COMMAND test_compact)

    add_executable(test_compact_cross test/test_compact_cross.cpp)
    target_link_libraries(test_compact_cross PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_compact_cross COMMAND test_compact_cross)

    add_executable(test_udx test/test_udx.cpp)
    target_link_libraries(test_udx PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_udx COMMAND test_udx)

    add_executable(test_udx_cross test/test_udx_cross.cpp)
    target_link_libraries(test_udx_cross PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_udx_cross COMMAND test_udx_cross)

    add_executable(test_udx_packet_capture test/test_udx_packet_capture.cpp)
    target_link_libraries(test_udx_packet_capture PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_udx_packet_capture COMMAND test_udx_packet_capture)

    add_executable(test_noise test/test_noise.cpp)
    target_link_libraries(test_noise PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_noise COMMAND test_noise)

    add_executable(test_noise_cross test/test_noise_cross.cpp)
    target_link_libraries(test_noise_cross PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_noise_cross COMMAND test_noise_cross)

    add_executable(test_secret_stream test/test_secret_stream.cpp)
    target_link_libraries(test_secret_stream PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_secret_stream COMMAND test_secret_stream)

    add_executable(test_crypto_verify test/test_crypto_verify.cpp)
    target_link_libraries(test_crypto_verify PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_crypto_verify COMMAND test_crypto_verify)

    add_executable(test_routing_table test/test_routing_table.cpp)
    target_link_libraries(test_routing_table PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_routing_table COMMAND test_routing_table)

    include(GoogleTest)
    gtest_discover_tests(test_compact)
    gtest_discover_tests(test_compact_cross)
    gtest_discover_tests(test_udx)
    gtest_discover_tests(test_udx_cross)
    gtest_discover_tests(test_udx_packet_capture)
    gtest_discover_tests(test_noise)
    gtest_discover_tests(test_noise_cross)
    gtest_discover_tests(test_secret_stream)
    gtest_discover_tests(test_crypto_verify)

    add_executable(test_wire_compat test/test_wire_compat.cpp)
    target_link_libraries(test_wire_compat PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_wire_compat COMMAND test_wire_compat)
    gtest_discover_tests(test_wire_compat)

    add_executable(test_edge_cases test/test_edge_cases.cpp)
    target_link_libraries(test_edge_cases PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_edge_cases COMMAND test_edge_cases)
    gtest_discover_tests(test_edge_cases)

    add_executable(test_c_api test/test_c_api.cpp)
    target_link_libraries(test_c_api PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_c_api COMMAND test_c_api)
    gtest_discover_tests(test_c_api)
    gtest_discover_tests(test_routing_table)

    add_executable(test_tokens test/test_tokens.cpp)
    target_link_libraries(test_tokens PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_tokens COMMAND test_tokens)
    gtest_discover_tests(test_tokens)

    add_executable(test_messages test/test_messages.cpp)
    target_link_libraries(test_messages PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_messages COMMAND test_messages)
    gtest_discover_tests(test_messages)

    add_executable(test_rpc_ping test/test_rpc_ping.cpp)
    target_link_libraries(test_rpc_ping PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_rpc_ping COMMAND test_rpc_ping)
    gtest_discover_tests(test_rpc_ping)

    add_executable(test_rpc_bootstrap test/test_rpc_bootstrap.cpp)
    target_link_libraries(test_rpc_bootstrap PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_rpc_bootstrap COMMAND test_rpc_bootstrap)
    gtest_discover_tests(test_rpc_bootstrap)

    add_executable(test_rpc_handlers test/test_rpc_handlers.cpp)
    target_link_libraries(test_rpc_handlers PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_rpc_handlers COMMAND test_rpc_handlers)
    gtest_discover_tests(test_rpc_handlers)

    add_executable(test_announce test/test_announce.cpp)
    target_link_libraries(test_announce PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_announce COMMAND test_announce)
    gtest_discover_tests(test_announce)

    add_executable(test_query test/test_query.cpp)
    target_link_libraries(test_query PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_query COMMAND test_query)
    gtest_discover_tests(test_query)

    add_executable(test_dht_ops test/test_dht_ops.cpp)
    target_link_libraries(test_dht_ops PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_dht_ops COMMAND test_dht_ops)
    gtest_discover_tests(test_dht_ops)

    add_executable(test_holepunch test/test_holepunch.cpp)
    target_link_libraries(test_holepunch PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_holepunch COMMAND test_holepunch)
    gtest_discover_tests(test_holepunch)

    add_executable(test_server_live test/test_server_live.cpp)
    target_link_libraries(test_server_live PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_server_live COMMAND test_server_live)
    gtest_discover_tests(test_server_live)

    add_executable(test_hyperdht test/test_hyperdht.cpp)
    target_link_libraries(test_hyperdht PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_hyperdht COMMAND test_hyperdht)
    gtest_discover_tests(test_hyperdht)

    add_executable(test_server test/test_server.cpp)
    target_link_libraries(test_server PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_server COMMAND test_server)
    gtest_discover_tests(test_server)

    add_executable(test_announcer test/test_announcer.cpp)
    target_link_libraries(test_announcer PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_announcer COMMAND test_announcer)
    gtest_discover_tests(test_announcer)

    add_executable(test_server_holepunch test/test_server_holepunch.cpp)
    target_link_libraries(test_server_holepunch PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_server_holepunch COMMAND test_server_holepunch)
    gtest_discover_tests(test_server_holepunch)

    add_executable(test_server_handshake test/test_server_handshake.cpp)
    target_link_libraries(test_server_handshake PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_server_handshake COMMAND test_server_handshake)
    gtest_discover_tests(test_server_handshake)

    add_executable(test_router test/test_router.cpp)
    target_link_libraries(test_router PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_router COMMAND test_router)
    gtest_discover_tests(test_router)

    add_executable(test_announce_sig test/test_announce_sig.cpp)
    target_link_libraries(test_announce_sig PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_announce_sig COMMAND test_announce_sig)
    gtest_discover_tests(test_announce_sig)

    add_executable(test_dht_messages test/test_dht_messages.cpp)
    target_link_libraries(test_dht_messages PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_dht_messages COMMAND test_dht_messages)
    gtest_discover_tests(test_dht_messages)

    add_executable(test_protomux test/test_protomux.cpp)
    target_link_libraries(test_protomux PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_protomux COMMAND test_protomux)
    gtest_discover_tests(test_protomux)

    add_executable(test_health test/test_health.cpp)
    target_link_libraries(test_health PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_health COMMAND test_health)
    gtest_discover_tests(test_health)

    add_executable(test_nat_sampler test/test_nat_sampler.cpp)
    target_link_libraries(test_nat_sampler PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_nat_sampler COMMAND test_nat_sampler)
    gtest_discover_tests(test_nat_sampler)

    add_executable(test_live_connect test/test_live_connect.cpp)
    target_link_libraries(test_live_connect PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_live_connect COMMAND test_live_connect)
    gtest_discover_tests(test_live_connect)

    add_executable(test_storage_live test/test_storage_live.cpp)
    target_link_libraries(test_storage_live PRIVATE hyperdht GTest::gtest_main)
    add_test(NAME test_storage_live COMMAND test_storage_live)
    gtest_discover_tests(test_storage_live)
endif()
