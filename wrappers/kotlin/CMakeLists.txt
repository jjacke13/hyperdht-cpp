# NDK build for the JNI bridge — produces libhyperdht_jni.so
#
# Used by build.gradle.kts via externalNativeBuild.cmake.
# Expects pre-built libhyperdht.a + libudx.a per ABI in libs/<ABI>/

cmake_minimum_required(VERSION 3.22)
project(hyperdht_jni)

add_library(hyperdht_jni SHARED
    src/main/cpp/hyperdht_jni.cpp)

# Pre-built static libraries per Android ABI
set(LIBS_DIR ${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI})

target_include_directories(hyperdht_jni PRIVATE
    ${CMAKE_SOURCE_DIR}/../../include
    ${CMAKE_SOURCE_DIR}/../../deps/libudx/include)

target_link_libraries(hyperdht_jni
    ${LIBS_DIR}/libhyperdht.a
    ${LIBS_DIR}/libudx.a
    sodium
    uv
    log)
