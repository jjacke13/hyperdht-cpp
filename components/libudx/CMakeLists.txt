# libudx as an ESP-IDF component.
# Wraps deps/libudx/ — compiles from source with the Xtensa toolchain.

set(LIBUDX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../deps/libudx")

idf_component_register(
    SRCS
        "${LIBUDX_DIR}/src/udx.c"
        "${LIBUDX_DIR}/src/udx_bbr.c"
        "${LIBUDX_DIR}/src/udx_rate.c"
        "${LIBUDX_DIR}/src/cirbuf.c"
        "${LIBUDX_DIR}/src/endian.c"
        "${LIBUDX_DIR}/src/queue.c"
        "${LIBUDX_DIR}/src/io_posix.c"
        "${LIBUDX_DIR}/src/win_filter.c"
        "${LIBUDX_DIR}/src/win_filter_f64.c"
    INCLUDE_DIRS
        "${LIBUDX_DIR}/include"
    PRIV_INCLUDE_DIRS
        "${LIBUDX_DIR}/src"
    REQUIRES
        libuv-esp32
    PRIV_REQUIRES
        lwip
)

# libudx needs _GNU_SOURCE for sendmsg/recvmsg
target_compile_definitions(${COMPONENT_LIB} PRIVATE _GNU_SOURCE)

# Suppress format warnings on Xtensa (32-bit: int64_t = long long, not long)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-format)

# lwIP doesn't have path MTU discovery constants — provide stubs.
# The setsockopt/getsockopt calls will fail with ENOPROTOOPT,
# which libudx handles gracefully (returns -1, caller skips).
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    IP_MTU=14
    IPV6_MTU=86
    IP_MTU_DISCOVER=10
    IPV6_MTU_DISCOVER=23
    IP_PMTUDISC_PROBE=3
    IPV6_PMTUDISC_PROBE=3
)
