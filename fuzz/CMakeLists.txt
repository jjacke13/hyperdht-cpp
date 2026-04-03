# Fuzz targets — build with: cmake -S fuzz -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
# Run with: ./build-fuzz/fuzz_compact -max_total_time=30

cmake_minimum_required(VERSION 3.20)
project(hyperdht-fuzz LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Sanitizer + fuzzer flags
set(FUZZ_FLAGS "-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FUZZ_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FUZZ_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${FUZZ_FLAGS}")

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(UV REQUIRED libuv)

# Build libudx as a static library (exclude Windows-only files)
file(GLOB LIBUDX_SOURCES ../deps/libudx/src/*.c)
list(FILTER LIBUDX_SOURCES EXCLUDE REGEX "io_win\\.c$")
add_library(udx STATIC ${LIBUDX_SOURCES})
target_include_directories(udx PUBLIC ../deps/libudx/include PRIVATE ../deps/libudx/src)
target_link_libraries(udx PRIVATE ${UV_LIBRARIES})

# Build the hyperdht library (static, with fuzz flags)
file(GLOB HYPERDHT_SOURCES ../src/*.cpp)
add_library(hyperdht STATIC ${HYPERDHT_SOURCES})
target_include_directories(hyperdht PUBLIC ../include)
target_link_libraries(hyperdht PUBLIC udx ${SODIUM_LIBRARIES} ${UV_LIBRARIES})
target_include_directories(hyperdht PUBLIC
    ${SODIUM_INCLUDE_DIRS} ${UV_INCLUDE_DIRS}
    ../deps/libudx/include)

# Fuzz targets
set(FUZZ_TARGETS
    fuzz_compact
    fuzz_messages
    fuzz_handshake_msg
    fuzz_holepunch_msg
    fuzz_noise_payload
)

foreach(target ${FUZZ_TARGETS})
    add_executable(${target} ${target}.cpp)
    target_link_libraries(${target} PRIVATE hyperdht)
endforeach()
