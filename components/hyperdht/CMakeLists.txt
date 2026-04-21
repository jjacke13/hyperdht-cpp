# hyperdht-cpp as an ESP-IDF component.
# Only compiles the source files needed for the C FFI — not the full 35-file set.
# ESP-IDF links components with --whole-archive, so every .o gets linked in
# including its global constructors. Keeping the list minimal avoids
# C++ static init issues that crash the FreeRTOS scheduler.

set(HDHT_DIR "${CMAKE_CURRENT_LIST_DIR}/../..")

# Explicitly list only the files needed for the C FFI + their dependencies.
# Order: FFI layer → high-level → mid-level → low-level
set(HDHT_SRCS
    # C FFI entry points
    "${HDHT_DIR}/src/ffi_core.cpp"
    "${HDHT_DIR}/src/ffi_server.cpp"
    "${HDHT_DIR}/src/ffi_storage.cpp"
    "${HDHT_DIR}/src/ffi_stream.cpp"
    # High-level DHT
    "${HDHT_DIR}/src/dht.cpp"
    "${HDHT_DIR}/src/dht_network.cpp"
    "${HDHT_DIR}/src/dht_ops.cpp"
    "${HDHT_DIR}/src/dht_storage.cpp"
    "${HDHT_DIR}/src/server.cpp"
    "${HDHT_DIR}/src/server_connection.cpp"
    # Connect pipeline
    "${HDHT_DIR}/src/connect.cpp"
    "${HDHT_DIR}/src/peer_connect.cpp"
    "${HDHT_DIR}/src/holepunch.cpp"
    "${HDHT_DIR}/src/blind_relay.cpp"
    # Query + announce
    "${HDHT_DIR}/src/query.cpp"
    "${HDHT_DIR}/src/announce.cpp"
    "${HDHT_DIR}/src/announcer.cpp"
    "${HDHT_DIR}/src/announce_sig.cpp"
    # RPC + routing
    "${HDHT_DIR}/src/rpc.cpp"
    "${HDHT_DIR}/src/rpc_handlers.cpp"
    "${HDHT_DIR}/src/routing_table.cpp"
    "${HDHT_DIR}/src/tokens.cpp"
    "${HDHT_DIR}/src/router.cpp"
    # Protocol layers
    "${HDHT_DIR}/src/secret_stream.cpp"
    "${HDHT_DIR}/src/noise_wrap.cpp"
    "${HDHT_DIR}/src/protomux.cpp"
    "${HDHT_DIR}/src/compact.cpp"
    "${HDHT_DIR}/src/messages.cpp"
    "${HDHT_DIR}/src/dht_messages.cpp"
    # Transport + utilities
    "${HDHT_DIR}/src/udx.cpp"
    "${HDHT_DIR}/src/socket_pool.cpp"
    "${HDHT_DIR}/src/connection_pool.cpp"
    "${HDHT_DIR}/src/nat_sampler.cpp"
    "${HDHT_DIR}/src/health.cpp"
    "${HDHT_DIR}/src/async_utils.cpp"
)

idf_component_register(
    SRCS ${HDHT_SRCS}
    INCLUDE_DIRS
        "${HDHT_DIR}/include"
    PRIV_INCLUDE_DIRS
        "${HDHT_DIR}/deps/libudx/include"
    REQUIRES
        libuv-esp32
        libudx
        libsodium
    PRIV_REQUIRES
        lwip
)

# C++20 + embedded sizing (no exceptions, no RTTI — reduces static init overhead)
target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++20 -fno-rtti -fno-exceptions)
target_compile_definitions(${COMPONENT_LIB} PUBLIC HYPERDHT_EMBEDDED=1)
target_compile_definitions(${COMPONENT_LIB} PRIVATE _GNU_SOURCE)

# CRITICAL: ESP-IDF links components with --whole-archive by default,
# which forces ALL object files (and their C++ global constructors) to
# load even if unused. This overflows the startup stack and corrupts
# FreeRTOS state. Disable whole-archive for this component.
set_property(TARGET ${COMPONENT_LIB} PROPERTY
    WHOLE_ARCHIVE OFF
)
# Also try the interface property that ESP-IDF checks
set_property(TARGET ${COMPONENT_LIB} PROPERTY
    INTERFACE_LINK_LIBRARIES_DIRECT_EXCLUDE ""
)
