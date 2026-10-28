// Host-only immediate rejections through the real JNI bridge, not transport.
#include <hyperdht/hyperdht.h>

extern "C" int __real_hyperdht_connect(hyperdht_t*, const uint8_t*,
    hyperdht_connect_cb, void*);
extern "C" int __real_hyperdht_immutable_get(hyperdht_t*, const uint8_t*,
    hyperdht_value_cb, hyperdht_done_cb, void*);
extern "C" int __real_hyperdht_immutable_put(hyperdht_t*, const uint8_t*, size_t,
    hyperdht_done_cb, void*);
extern "C" int __real_hyperdht_mutable_put(hyperdht_t*, const hyperdht_keypair_t*,
    const uint8_t*, size_t, uint64_t, hyperdht_done_cb, void*);

extern "C" int __wrap_hyperdht_connect(hyperdht_t* dht, const uint8_t* pk,
    hyperdht_connect_cb cb, void* ud) {
    if (pk[0] == 0xf0) return -1; // No callback on immediate rejection.
    if (pk[0] == 0xf1) { cb(-2, nullptr, ud); return 0; }
    return __real_hyperdht_connect(dht, pk, cb, ud);
}

extern "C" int __wrap_hyperdht_immutable_get(hyperdht_t* dht, const uint8_t* key,
    hyperdht_value_cb value, hyperdht_done_cb done, void* ud) {
    if (key[0] == 0xf0) return -1;
    if (key[0] == 0xf1) { done(0, ud); return 0; }
    return __real_hyperdht_immutable_get(dht, key, value, done, ud);
}

extern "C" int __wrap_hyperdht_immutable_put(hyperdht_t* dht, const uint8_t* value,
    size_t len, hyperdht_done_cb done, void* ud) {
    if (len == 0) return __real_hyperdht_immutable_put(dht, value, len, done, ud);
    done(value[0] == 2 ? 1 : 0, ud);
    return 0;
}

extern "C" int __wrap_hyperdht_mutable_put(hyperdht_t* dht, const hyperdht_keypair_t* kp,
    const uint8_t* value, size_t len, uint64_t seq, hyperdht_done_cb done, void* ud) {
    if (len == 0) return __real_hyperdht_mutable_put(dht, kp, value, len, seq, done, ud);
    done(value[0] == 2 ? 1 : 0, ud);
    return 0;
}
