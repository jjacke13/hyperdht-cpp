# hyperdht-cpp as an ESP-IDF component.
# Compiles the full library from source for Xtensa with HYPERDHT_EMBEDDED.

set(HDHT_DIR "${CMAKE_CURRENT_LIST_DIR}/../..")

# All source files
file(GLOB HDHT_SRCS "${HDHT_DIR}/src/*.cpp")

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

# C++20 + embedded sizing + exceptions (required by the library)
target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++20 -fexceptions)
target_compile_definitions(${COMPONENT_LIB} PUBLIC HYPERDHT_EMBEDDED=1)
target_compile_definitions(${COMPONENT_LIB} PRIVATE _GNU_SOURCE)
