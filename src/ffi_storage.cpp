// FFI storage: immutable/mutable put/get, DHT state, events, queries, lifecycle, misc.
#include "ffi_internal.hpp"

// ---------------------------------------------------------------------------
// Mutable/Immutable storage
// ---------------------------------------------------------------------------

int hyperdht_immutable_put(hyperdht_t* dht,
                           const uint8_t* value, size_t len,
                           hyperdht_done_cb cb, void* userdata) {
    if (!dht || !dht->dht || !value || len == 0) return -1;

    std::vector<uint8_t> val(value, value + len);
    dht->dht->immutable_put(val,
        [cb, userdata](const hyperdht::HyperDHT::ImmutablePutResult&) {
            if (cb) cb(0, userdata);
        });
    return 0;
}

int hyperdht_immutable_get(hyperdht_t* dht,
                           const uint8_t target[32],
                           hyperdht_value_cb cb,
                           hyperdht_done_cb done_cb,
                           void* userdata) {
    if (!dht || !dht->dht || !target) return -1;

    std::array<uint8_t, 32> t{};
    memcpy(t.data(), target, 32);

    dht->dht->immutable_get(t,
        // on_value — streaming per-reply
        [cb, userdata](const std::vector<uint8_t>& value) {
            if (cb) cb(value.data(), value.size(), userdata);
        },
        // on_done — once at completion
        [done_cb, userdata](const hyperdht::HyperDHT::ImmutableGetResult&) {
            if (done_cb) done_cb(0, userdata);
        });
    return 0;
}

int hyperdht_mutable_put(hyperdht_t* dht,
                         const hyperdht_keypair_t* kp,
                         const uint8_t* value, size_t len,
                         uint64_t seq,
                         hyperdht_done_cb cb, void* userdata) {
    if (!dht || !dht->dht || !kp || !value || len == 0) return -1;

    hyperdht::noise::Keypair cpp_kp;
    memcpy(cpp_kp.public_key.data(), kp->public_key, 32);
    memcpy(cpp_kp.secret_key.data(), kp->secret_key, 64);

    std::vector<uint8_t> val(value, value + len);
    dht->dht->mutable_put(cpp_kp, val, seq,
        [cb, userdata](const hyperdht::HyperDHT::MutablePutResult&) {
            if (cb) cb(0, userdata);
        });
    return 0;
}

int hyperdht_mutable_get(hyperdht_t* dht,
                         const uint8_t public_key[32],
                         uint64_t min_seq,
                         hyperdht_mutable_cb cb,
                         hyperdht_done_cb done_cb,
                         void* userdata) {
    if (!dht || !dht->dht || !public_key) return -1;

    hyperdht::noise::PubKey pk{};
    memcpy(pk.data(), public_key, 32);

    dht->dht->mutable_get(pk, min_seq, /*latest=*/true,
        // on_value — streaming per-reply
        [cb, userdata](const hyperdht::dht_ops::MutableResult& r) {
            if (cb) cb(r.seq, r.value.data(), r.value.size(),
                       r.signature.data(), userdata);
        },
        // on_done — once at completion
        [done_cb, userdata](const hyperdht::HyperDHT::MutableGetResult&) {
            if (done_cb) done_cb(0, userdata);
        });
    return 0;
}

hyperdht_query_t* hyperdht_immutable_get_ex(hyperdht_t* dht,
                                             const uint8_t target[32],
                                             hyperdht_value_cb cb,
                                             hyperdht_done_cb done_cb,
                                             void* userdata) {
    if (!dht || !dht->dht || !target) return nullptr;

    std::array<uint8_t, 32> t{};
    memcpy(t.data(), target, 32);

    auto* handle = make_query_handle(done_cb, userdata);
    auto state = handle->state;
    handle->state->q = dht->dht->immutable_get(t,
        [state, cb](const std::vector<uint8_t>& value) {
            if (!state->done_cb) return;  // detached via free
            if (cb) cb(value.data(), value.size(), state->userdata);
        },
        // Immutable's done signature differs but make_done_fn adapts via auto&
        [state](const hyperdht::HyperDHT::ImmutableGetResult&) {
            state->done = true;
            if (state->done_cb) {
                int err = state->cancelled ? HYPERDHT_ERR_CANCELLED : 0;
                state->done_cb(err, state->userdata);
            }
        });
    return handle;
}

hyperdht_query_t* hyperdht_mutable_get_ex(hyperdht_t* dht,
                                           const uint8_t public_key[32],
                                           uint64_t min_seq,
                                           hyperdht_mutable_cb cb,
                                           hyperdht_done_cb done_cb,
                                           void* userdata) {
    if (!dht || !dht->dht || !public_key) return nullptr;

    hyperdht::noise::PubKey pk{};
    memcpy(pk.data(), public_key, 32);

    auto* handle = make_query_handle(done_cb, userdata);
    auto state = handle->state;
    handle->state->q = dht->dht->mutable_get(pk, min_seq, /*latest=*/true,
        [state, cb](const hyperdht::dht_ops::MutableResult& r) {
            if (!state->done_cb) return;
            if (cb) cb(r.seq, r.value.data(), r.value.size(),
                       r.signature.data(), state->userdata);
        },
        [state](const hyperdht::HyperDHT::MutableGetResult&) {
            state->done = true;
            if (state->done_cb) {
                int err = state->cancelled ? HYPERDHT_ERR_CANCELLED : 0;
                state->done_cb(err, state->userdata);
            }
        });
    return handle;
}

// ---------------------------------------------------------------------------
// DHT state queries
// ---------------------------------------------------------------------------

int hyperdht_is_online(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->is_online() ? 1 : 0;
}

int hyperdht_is_degraded(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->is_degraded() ? 1 : 0;
}

int hyperdht_is_persistent(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->is_persistent() ? 1 : 0;
}

int hyperdht_is_bootstrapped(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->is_bootstrapped() ? 1 : 0;
}

int hyperdht_is_suspended(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->is_suspended() ? 1 : 0;
}

// ---------------------------------------------------------------------------
// DHT event hooks
// ---------------------------------------------------------------------------

void hyperdht_on_bootstrapped(hyperdht_t* dht,
                               hyperdht_event_cb cb, void* userdata) {
    if (!dht || !dht->dht) return;
    if (!cb) {
        dht->dht->on_bootstrapped(nullptr);
        return;
    }
    dht->dht->on_bootstrapped([cb, userdata]() { cb(userdata); });
}

void hyperdht_on_network_change(hyperdht_t* dht,
                                 hyperdht_event_cb cb, void* userdata) {
    if (!dht || !dht->dht) return;
    if (!cb) {
        dht->dht->on_network_change(nullptr);
        return;
    }
    dht->dht->on_network_change([cb, userdata]() { cb(userdata); });
}

void hyperdht_on_network_update(hyperdht_t* dht,
                                 hyperdht_event_cb cb, void* userdata) {
    if (!dht || !dht->dht) return;
    if (!cb) {
        dht->dht->on_network_update(nullptr);
        return;
    }
    dht->dht->on_network_update([cb, userdata]() { cb(userdata); });
}

void hyperdht_on_persistent(hyperdht_t* dht,
                             hyperdht_event_cb cb, void* userdata) {
    if (!dht || !dht->dht) return;
    if (!cb) {
        dht->dht->on_persistent(nullptr);
        return;
    }
    dht->dht->on_persistent([cb, userdata]() { cb(userdata); });
}

// ---------------------------------------------------------------------------
// DHT query operations: find_peer, lookup, announce, unannounce
// ---------------------------------------------------------------------------

int hyperdht_find_peer(hyperdht_t* dht,
                        const uint8_t public_key[32],
                        hyperdht_peer_cb on_reply,
                        hyperdht_done_cb on_done,
                        void* userdata) {
    if (!dht || !dht->dht || !public_key) return -1;

    hyperdht::noise::PubKey pk{};
    memcpy(pk.data(), public_key, 32);

    dht->dht->find_peer(pk,
        [on_reply, userdata](const hyperdht::query::QueryReply& reply) {
            if (on_reply && reply.value.has_value() && !reply.value->empty()) {
                auto host = reply.from_addr.host_string();
                on_reply(reply.value->data(), reply.value->size(),
                         host.c_str(), reply.from_addr.port, userdata);
            }
        },
        [on_done, userdata](const std::vector<hyperdht::query::QueryReply>&) {
            if (on_done) on_done(0, userdata);
        });
    return 0;
}

int hyperdht_lookup(hyperdht_t* dht,
                     const uint8_t target[32],
                     hyperdht_peer_cb on_reply,
                     hyperdht_done_cb on_done,
                     void* userdata) {
    if (!dht || !dht->dht || !target) return -1;

    hyperdht::routing::NodeId t{};
    memcpy(t.data(), target, 32);

    dht->dht->lookup(t,
        [on_reply, userdata](const hyperdht::query::QueryReply& reply) {
            if (on_reply && reply.value.has_value() && !reply.value->empty()) {
                auto host = reply.from_addr.host_string();
                on_reply(reply.value->data(), reply.value->size(),
                         host.c_str(), reply.from_addr.port, userdata);
            }
        },
        [on_done, userdata](const std::vector<hyperdht::query::QueryReply>&) {
            if (on_done) on_done(0, userdata);
        });
    return 0;
}

int hyperdht_announce(hyperdht_t* dht,
                       const uint8_t target[32],
                       const uint8_t* value, size_t value_len,
                       hyperdht_done_cb on_done,
                       void* userdata) {
    if (!dht || !dht->dht || !target || !value || value_len == 0) return -1;

    hyperdht::routing::NodeId t{};
    memcpy(t.data(), target, 32);
    std::vector<uint8_t> val(value, value + value_len);

    dht->dht->announce(t, val,
        [on_done, userdata](const std::vector<hyperdht::query::QueryReply>&) {
            if (on_done) on_done(0, userdata);
        });
    return 0;
}


hyperdht_query_t* hyperdht_find_peer_ex(hyperdht_t* dht,
                                         const uint8_t public_key[32],
                                         hyperdht_peer_cb on_reply,
                                         hyperdht_done_cb on_done,
                                         void* userdata) {
    if (!dht || !dht->dht || !public_key) return nullptr;

    hyperdht::noise::PubKey pk{};
    memcpy(pk.data(), public_key, 32);

    auto* handle = make_query_handle(on_done, userdata);
    auto state = handle->state;  // shared copy for lambdas
    handle->state->q = dht->dht->find_peer(pk,
        [state, on_reply](const hyperdht::query::QueryReply& reply) {
            // on_reply fires per-visit while query is alive; silent no-op
            // if the user freed (done_cb-less snapshot of userdata).
            if (!state->done_cb) return;  // detached via free
            if (on_reply && reply.value.has_value() && !reply.value->empty()) {
                auto host = reply.from_addr.host_string();
                on_reply(reply.value->data(), reply.value->size(),
                         host.c_str(), reply.from_addr.port, state->userdata);
            }
        },
        make_done_fn<std::vector<hyperdht::query::QueryReply>>(state));
    return handle;
}

hyperdht_query_t* hyperdht_lookup_ex(hyperdht_t* dht,
                                      const uint8_t target[32],
                                      hyperdht_peer_cb on_reply,
                                      hyperdht_done_cb on_done,
                                      void* userdata) {
    if (!dht || !dht->dht || !target) return nullptr;

    hyperdht::routing::NodeId t{};
    memcpy(t.data(), target, 32);

    auto* handle = make_query_handle(on_done, userdata);
    auto state = handle->state;
    handle->state->q = dht->dht->lookup(t,
        [state, on_reply](const hyperdht::query::QueryReply& reply) {
            if (!state->done_cb) return;
            if (on_reply && reply.value.has_value() && !reply.value->empty()) {
                auto host = reply.from_addr.host_string();
                on_reply(reply.value->data(), reply.value->size(),
                         host.c_str(), reply.from_addr.port, state->userdata);
            }
        },
        make_done_fn<std::vector<hyperdht::query::QueryReply>>(state));
    return handle;
}

int hyperdht_unannounce(hyperdht_t* dht,
                         const uint8_t public_key[32],
                         const hyperdht_keypair_t* kp,
                         hyperdht_done_cb on_done,
                         void* userdata) {
    if (!dht || !dht->dht || !public_key || !kp) return -1;

    hyperdht::noise::PubKey pk{};
    memcpy(pk.data(), public_key, 32);

    hyperdht::noise::Keypair cpp_kp;
    memcpy(cpp_kp.public_key.data(), kp->public_key, 32);
    memcpy(cpp_kp.secret_key.data(), kp->secret_key, 64);

    dht->dht->unannounce(pk, cpp_kp,
        [on_done, userdata]() {
            if (on_done) on_done(0, userdata);
        });
    return 0;
}

// ---------------------------------------------------------------------------
// DHT lifecycle: suspend, resume
// ---------------------------------------------------------------------------

void hyperdht_suspend(hyperdht_t* dht) {
    if (dht && dht->dht) dht->dht->suspend();
}

void hyperdht_resume(hyperdht_t* dht) {
    if (dht && dht->dht) dht->dht->resume();
}

void hyperdht_suspend_logged(hyperdht_t* dht,
                             hyperdht_log_cb log_cb, void* userdata) {
    if (!dht || !dht->dht) return;
    if (!log_cb) { dht->dht->suspend(); return; }
    // Bridge C `const char*` callback -> C++ std::function<void(const char*)>.
    dht->dht->suspend([log_cb, userdata](const char* msg) {
        log_cb(msg, userdata);
    });
}

void hyperdht_resume_logged(hyperdht_t* dht,
                            hyperdht_log_cb log_cb, void* userdata) {
    if (!dht || !dht->dht) return;
    if (!log_cb) { dht->dht->resume(); return; }
    dht->dht->resume([log_cb, userdata](const char* msg) {
        log_cb(msg, userdata);
    });
}

// ---------------------------------------------------------------------------
// DHT misc: hash, connection_keep_alive, to_array, add_node, remote_address
// ---------------------------------------------------------------------------

void hyperdht_hash(const uint8_t* data, size_t len, uint8_t out[32]) {
    if (!data || !out) return;
    auto h = hyperdht::HyperDHT::hash(data, len);
    memcpy(out, h.data(), 32);
}

uint64_t hyperdht_connection_keep_alive(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->connection_keep_alive();
}

size_t hyperdht_to_array(const hyperdht_t* dht,
                         char* hosts_flat, uint16_t* ports, size_t cap) {
    if (!dht || !dht->dht || !hosts_flat || !ports || cap == 0) return 0;
    auto snapshot = dht->dht->to_array(cap);
    size_t n = std::min(snapshot.size(), cap);
    for (size_t i = 0; i < n; ++i) {
        auto h = snapshot[i].host_string();
        char* slot = hosts_flat + i * HYPERDHT_HOST_STRIDE;
        std::strncpy(slot, h.c_str(), HYPERDHT_HOST_STRIDE - 1);
        slot[HYPERDHT_HOST_STRIDE - 1] = '\0';
        ports[i] = snapshot[i].port;
    }
    return n;
}

int hyperdht_add_node(hyperdht_t* dht, const char* host, uint16_t port) {
    if (!dht || !dht->dht || !host) return -1;
    // Validate via uv_ip4_addr so we don't insert malformed hosts into
    // the routing table (the RoutingTable itself takes the string at
    // face value).
    struct sockaddr_in probe{};
    if (uv_ip4_addr(host, port, &probe) != 0) return -2;
    dht->dht->add_node(
        hyperdht::compact::Ipv4Address::from_string(host, port));
    return 0;
}

int hyperdht_remote_address(const hyperdht_t* dht,
                            char out_host[46], uint16_t* out_port) {
    if (!dht || !dht->dht || !out_host || !out_port) return -1;
    auto addr = dht->dht->remote_address();
    if (!addr) return -1;
    auto h = addr->host_string();
    std::strncpy(out_host, h.c_str(), 45);
    out_host[45] = '\0';
    *out_port = addr->port;
    return 0;
}
