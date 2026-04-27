#pragma once

// Debug logging — enabled with cmake -DHYPERDHT_DEBUG=ON
// Silent by default (production mode).
//
// On Android, DHT_LOG routes to logcat via __android_log_print.
// On other platforms, it routes to stderr via fprintf.

#include <cstdio>

#ifdef HYPERDHT_DEBUG
  #if defined(__ANDROID__)
    #include <android/log.h>
    #define DHT_LOG(...) __android_log_print(ANDROID_LOG_DEBUG, "HyperDHT-C", __VA_ARGS__)
  #else
    #define DHT_LOG(...) fprintf(stderr, __VA_ARGS__)
  #endif
#else
  #define DHT_LOG(...) ((void)0)
#endif
