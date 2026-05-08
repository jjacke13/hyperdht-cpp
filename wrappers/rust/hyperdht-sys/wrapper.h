/* Bindgen entry point: pulls in both libuv (needed for the Rust wrapper's
 * libuv pump thread) and hyperdht's public C FFI. */
#include <uv.h>
#include "hyperdht/hyperdht.h"
