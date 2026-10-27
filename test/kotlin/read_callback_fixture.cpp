// Host-only callback injection for the Kotlin read test, not a transport test.
#include <hyperdht/hyperdht.h>

extern "C" int __real_hyperdht_immutable_get(hyperdht_t*, const uint8_t*,
    hyperdht_value_cb, hyperdht_done_cb, void*);

extern "C" int __wrap_hyperdht_immutable_get(hyperdht_t* dht,
    const uint8_t* target, hyperdht_value_cb value, hyperdht_done_cb done, void* ud) {
    if (target[0] < 0xe0 || target[0] > 0xe4)
        return __real_hyperdht_immutable_get(dht, target, value, done, ud);
    const uint8_t bytes[] = {'r', 'e', 'a', 'd'};
    if (target[0] == 0xe2) value(bytes, sizeof(bytes), ud);
    const int error = target[0] == 0xe0 ? 1 : target[0] == 0xe3 ? HYPERDHT_ERR_CANCELLED
                    : target[0] == 0xe4 ? 73 : 0;
    done(error, ud);
    return 0;
}
