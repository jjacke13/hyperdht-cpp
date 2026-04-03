#pragma once

// Debug logging — enabled with cmake -DHYPERDHT_DEBUG=ON
// Silent by default (production mode).

#include <cstdio>

#ifdef HYPERDHT_DEBUG
#define DHT_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DHT_LOG(...) ((void)0)
#endif
