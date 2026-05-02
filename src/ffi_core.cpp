// FFI core: query cancel/free, keypair, DHT lifecycle, connect.
#include "ffi_internal.hpp"

const char* hyperdht_connect_strerror(int error) {
    switch (error) {
        case  0: return "success";
        case -1: return "DHT destroyed during connect";
        case -2: return "peer not found";
        case -3: return "peer connection failed (all relay handshakes failed)";
        case -4: return "no connectable addresses from server";
        case -5: return "holepunch failed";
        case -6: return "holepunch timeout";
        case -7: return "blind relay pairing failed";
        case -8: return "cancelled";
        default: return "unknown error";
    }
}

// ---------------------------------------------------------------------------
// Query cancellation (shared by all *_ex variants)
// ---------------------------------------------------------------------------

extern "C" void hyperdht_query_cancel(hyperdht_query_t* q) {
    if (!q || !q->state) return;
    auto& st = *q->state;
    if (st.done) return;        // already completed — idempotent no-op
    st.cancelled = true;
    if (st.q) st.q->destroy();  // triggers on_done (which sets st.done)
}

extern "C" void hyperdht_query_free(hyperdht_query_t* q) {
    if (!q) return;
    // Detach the callback so any late completion is silent — the lambda
    // still holds `state` alive until it fires, but won't reach user code.
    if (q->state) {
        q->state->done_cb = nullptr;
        q->state->userdata = nullptr;
    }
    delete q;  // state may still be alive via lambda ref, which is fine
}

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

void hyperdht_keypair_generate(hyperdht_keypair_t* out) {
    if (!out) return;
    auto kp = hyperdht::noise::generate_keypair();
    memcpy(out->public_key, kp.public_key.data(), 32);
    memcpy(out->secret_key, kp.secret_key.data(), 64);
    sodium_memzero(kp.secret_key.data(), 64);  // C10: zero stack copy
}

void hyperdht_keypair_from_seed(hyperdht_keypair_t* out, const uint8_t seed[32]) {
    if (!out || !seed) return;
    hyperdht::noise::Seed s{};
    memcpy(s.data(), seed, 32);
    auto kp = hyperdht::noise::generate_keypair(s);
    memcpy(out->public_key, kp.public_key.data(), 32);
    memcpy(out->secret_key, kp.secret_key.data(), 64);
    sodium_memzero(s.data(), 32);              // C10: zero seed
    sodium_memzero(kp.secret_key.data(), 64);  // C10: zero stack copy
}

void hyperdht_keypair_zero(hyperdht_keypair_t* kp) {
    if (!kp) return;
    sodium_memzero(kp->secret_key, 64);
    sodium_memzero(kp->public_key, 32);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

void hyperdht_opts_default(hyperdht_opts_t* opts) {
    if (!opts) return;
    opts->port = 0;
    opts->ephemeral = 1;
    opts->use_public_bootstrap = 0;
    // Sentinel: "keep the C++ default (5000 ms)". Callers can override
    // with any value; 0 explicitly disables keep-alive.
    opts->connection_keep_alive = UINT64_MAX;
    memset(opts->seed, 0, sizeof(opts->seed));
    opts->seed_is_set = 0;
    opts->_pad0 = 0;  // explicit layout pinning
    opts->host = nullptr;
    opts->nodes = nullptr;
    opts->nodes_len = 0;
}

hyperdht_t* hyperdht_create(uv_loop_t* loop, const hyperdht_opts_t* opts) {
    if (!loop) return nullptr;

    hyperdht::DhtOptions cpp_opts;
    if (opts) {
        cpp_opts.port = opts->port;
        cpp_opts.ephemeral = (opts->ephemeral != 0);

        // Bootstrap precedence: explicit `nodes[]` wins; otherwise
        // `use_public_bootstrap` seeds the canonical 3-node list.
        if (opts->nodes && opts->nodes_len > 0) {
            cpp_opts.bootstrap.reserve(opts->nodes_len);
            for (size_t i = 0; i < opts->nodes_len; ++i) {
                auto parsed = parse_host_port(opts->nodes[i]);
                if (parsed) cpp_opts.bootstrap.push_back(*parsed);
            }
        } else if (opts->use_public_bootstrap) {
            cpp_opts.bootstrap =
                hyperdht::HyperDHT::default_bootstrap_nodes();
        }

        // Keep-alive: UINT64_MAX = unset (keep the C++ default), any other
        // value is taken literally (including 0 for "disabled", matching
        // JS `connectionKeepAlive: false`).
        if (opts->connection_keep_alive != UINT64_MAX) {
            cpp_opts.connection_keep_alive = opts->connection_keep_alive;
        }

        // Optional deterministic seed → derive default keypair at
        // HyperDHT construction time. JS parity: `new DHT({ seed })`.
        if (opts->seed_is_set) {
            hyperdht::noise::Seed s{};
            std::memcpy(s.data(), opts->seed, 32);
            cpp_opts.seed = s;
        }

        // Optional bind interface.
        if (opts->host && opts->host[0] != '\0') {
            cpp_opts.host = opts->host;
        }
    }

    auto* h = new (std::nothrow) hyperdht_s;
    if (!h) return nullptr;

    h->dht = std::make_unique<hyperdht::HyperDHT>(loop, cpp_opts);
    return h;
}

int hyperdht_bind(hyperdht_t* dht, uint16_t port) {
    if (!dht || !dht->dht) return -1;
    if (port != 0) {
        dht->dht->set_port(port);
    }
    return dht->dht->bind();
}

uint16_t hyperdht_port(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->port();
}

int hyperdht_is_destroyed(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 1;
    return dht->dht->is_destroyed() ? 1 : 0;
}

void hyperdht_destroy(hyperdht_t* dht, hyperdht_close_cb cb, void* userdata) {
    if (!dht) {
        if (cb) cb(userdata);
        return;
    }
    if (!dht->dht) {
        delete dht;
        if (cb) cb(userdata);
        return;
    }

    // Schedule close. The caller MUST:
    // 1. Call uv_run() to drain pending close callbacks
    // 2. Then call hyperdht_free() to release memory
    // The callback fires synchronously to signal destruction started.
    dht->dht->destroy();
    if (cb) cb(userdata);
}

void hyperdht_destroy_force(hyperdht_t* dht,
                            hyperdht_close_cb cb, void* userdata) {
    if (!dht) {
        if (cb) cb(userdata);
        return;
    }
    if (!dht->dht) {
        delete dht;
        if (cb) cb(userdata);
        return;
    }
    hyperdht::HyperDHT::DestroyOptions opts;
    opts.force = true;
    dht->dht->destroy(opts);
    if (cb) cb(userdata);
}

void hyperdht_free(hyperdht_t* dht) {
    delete dht;
}

void hyperdht_default_keypair(const hyperdht_t* dht, hyperdht_keypair_t* out) {
    if (!dht || !dht->dht || !out) return;
    const auto& kp = dht->dht->default_keypair();
    memcpy(out->public_key, kp.public_key.data(), 32);
    memcpy(out->secret_key, kp.secret_key.data(), 64);
}

// ---------------------------------------------------------------------------
// Client: connect
// ---------------------------------------------------------------------------

int hyperdht_connect(hyperdht_t* dht,
                     const uint8_t remote_pk[32],
                     hyperdht_connect_cb cb,
                     void* userdata) {
    return hyperdht_connect_ex(dht, remote_pk, nullptr, cb, userdata);
}

void hyperdht_connect_opts_default(hyperdht_connect_opts_t* opts) {
    if (!opts) return;
    opts->keypair = nullptr;
    opts->relay_through = nullptr;
    opts->relay_keep_alive_ms = 0;  // 0 = library default (5000 ms)
    opts->fast_open = 1;
    opts->local_connection = 1;
}

int hyperdht_connect_ex(hyperdht_t* dht,
                        const uint8_t remote_pk[32],
                        const hyperdht_connect_opts_t* opts,
                        hyperdht_connect_cb cb,
                        void* userdata) {
    if (!dht || !dht->dht || !remote_pk || !cb) return -1;

    hyperdht::noise::PubKey pk{};
    memcpy(pk.data(), remote_pk, 32);

    hyperdht::ConnectOptions cpp_opts;

    if (opts) {
        // Custom keypair: copy the 32-byte public + 64-byte secret into
        // a noise::Keypair. The secret-key layout matches libsodium's
        // (seed|public), which is what noise::Keypair expects.
        if (opts->keypair) {
            hyperdht::noise::Keypair kp;
            std::memcpy(kp.public_key.data(), opts->keypair->public_key, 32);
            std::memcpy(kp.secret_key.data(), opts->keypair->secret_key, 64);
            cpp_opts.keypair = kp;
            sodium_memzero(kp.secret_key.data(), 64);  // C10
        }
        if (opts->relay_through) {
            hyperdht::noise::PubKey rpk{};
            std::memcpy(rpk.data(), opts->relay_through, 32);
            cpp_opts.relay_through = rpk;
        }
        if (opts->relay_keep_alive_ms != 0) {
            cpp_opts.relay_keep_alive = opts->relay_keep_alive_ms;
        }
        cpp_opts.fast_open = (opts->fast_open != 0);
        cpp_opts.local_connection = (opts->local_connection != 0);
    }

    dht->dht->connect(pk, cpp_opts,
        [cb, userdata](int error, const hyperdht::ConnectResult& result) {
            dispatch_connect_result(cb, userdata, error, result, true);
        });

    return 0;
}

int hyperdht_connect_and_open_stream(
    hyperdht_t* dht,
    const uint8_t remote_pk[32],
    hyperdht_connect_stream_cb on_connect,
    hyperdht_close_cb on_open,
    hyperdht_data_cb on_data,
    hyperdht_close_cb on_close,
    void* userdata) {

    if (!dht || !dht->dht || !remote_pk || !on_connect) return -1;

    hyperdht::noise::PubKey pk{};
    memcpy(pk.data(), remote_pk, 32);

    hyperdht::ConnectOptions cpp_opts;
    dht->dht->connect(pk, cpp_opts,
        [dht, on_connect, on_open, on_data, on_close, userdata](
            int error, const hyperdht::ConnectResult& result) {

            if (error != 0) {
                on_connect(error, nullptr, userdata);
                return;
            }

            hyperdht_connection_t conn{};
            fill_connection(&conn, result.tx_key, result.rx_key,
                            result.handshake_hash, result.remote_public_key,
                            result.peer_address, result.remote_udx_id,
                            result.local_udx_id, true);
            conn.raw_stream = result.raw_stream;
            conn.udx_socket = result.udx_socket;
            conn._internal = result.socket_keepalive
                ? new std::shared_ptr<void>(result.socket_keepalive)
                : nullptr;

            // Open stream NOW — conn is still alive on the stack
            hyperdht_stream_t* stream = hyperdht_stream_open(
                dht, &conn, on_open, on_data, on_close, userdata);

            if (conn._internal) {
                delete static_cast<std::shared_ptr<void>*>(conn._internal);
            }

            on_connect(stream ? 0 : -1, stream, userdata);
        });

    return 0;
}
