# Fuzz targets — build with: cmake -S fuzz -B build-fuzz -G Ninja \
#   -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ && ninja -C build-fuzz
#
# Run one target, keeping its corpus so successive runs compound:
#
#   UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ASAN_OPTIONS=abort_on_error=1 \
#     ./build-fuzz/fuzz_compact -max_total_time=1800 -print_final_stats=1 \
#     -artifact_prefix=fuzz/artifacts/fuzz_compact- fuzz/corpus/fuzz_compact
#
# UBSAN_OPTIONS matters: -fsanitize=undefined below defaults to
# print-and-continue, so without halt_on_error a UB finding neither stops the
# fuzzer nor fails the run — it just scrolls past in the log.
#
# fuzz/corpus/ and fuzz/artifacts/ are gitignored working data.

cmake_minimum_required(VERSION 3.20)
project(hyperdht-fuzz LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Sanitizer + coverage flags, applied to everything.
#
# `fuzzer-no-link` (not `fuzzer`) is deliberate: it instruments for coverage
# WITHOUT linking libFuzzer's own main(). The fuzz targets add `-fsanitize=fuzzer`
# individually below to pull that main in. Putting plain `fuzzer` here instead
# would make every executable in this project carry libFuzzer's main, so any
# helper with a main() of its own (gen_seeds) fails to link with
# "multiple definition of `main`".
set(FUZZ_FLAGS "-fsanitize=address,undefined,fuzzer-no-link -fno-omit-frame-pointer")
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
    fuzz_blind_relay
    fuzz_protomux
    fuzz_noise_handshake
    fuzz_secret_stream
)

# Seed generator — not a fuzz target, no libFuzzer entry point.
add_executable(gen_seeds gen_seeds.cpp)
target_link_libraries(gen_seeds PRIVATE hyperdht)

foreach(target ${FUZZ_TARGETS})
    add_executable(${target} ${target}.cpp)
    target_link_libraries(${target} PRIVATE hyperdht)
    # Only the fuzz targets get libFuzzer's main().
    target_compile_options(${target} PRIVATE -fsanitize=fuzzer)
    target_link_options(${target} PRIVATE -fsanitize=fuzzer)
endforeach()
