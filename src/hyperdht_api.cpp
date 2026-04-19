/**
 * hyperdht-cpp C API implementation — thin shims to C++ objects.
 */

#include "hyperdht/hyperdht.h"

#include <sodium.h>

#include <cstring>
#include <functional>
#include <memory>

#include "hyperdht/dht.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/secret_stream.hpp"
#include "hyperdht/server.hpp"

#include <udx.h>

// ---------------------------------------------------------------------------
// Internal: wrapper structs for opaque pointers
// ---------------------------------------------------------------------------

struct hyperdht_s {
    std::unique_ptr<hyperdht::HyperDHT> dht;
};

struct hyperdht_server_s {
    hyperdht::server::Server* server = nullptr;  // Owned by HyperDHT
    hyperdht_connection_cb cb = nullptr;
    void* userdata = nullptr;
};

// FFI query handle — two-layer ownership to make cancel, done, and
// free all UAF-safe regardless of order.
//
//   QueryState (heap, shared_ptr):
//     owned by two parties:
//       1. `hyperdht_query_s` (user's wrapper)
//       2. the on_done lambda closure
//     Destroyed when BOTH refs drop — never before.
//
//   hyperdht_query_s (heap, raw ptr returned to user):
//     exactly one instance per query, holds ONE shared_ptr<QueryState>.
//     Deleted by `hyperdht_query_free()`. Safe to delete at any time —
//     the state lives on via the lambda's ref until completion.
//
// Guarantees this gives FFI consumers:
//
//   - `hyperdht_query_cancel(h)` is idempotent. Checks `state->done`
//     first; flips `state->cancelled`; triggers Query::destroy().
//   - `hyperdht_query_cancel(h)` AFTER done fired is a no-op (saw
//     `state->done == true`).
//   - `hyperdht_query_free(h)` detaches the user's callback then
//     releases the user's ref. Outstanding lambda refs keep the state
//     alive silently (callback detached → late completion is a no-op).
//   - Double-free is prevented by the usual `delete h` UB rule — user
//     must not call free twice (same rule as any C handle).
struct QueryState {
    std::shared_ptr<hyperdht::query::Query> q;
    hyperdht_done_cb done_cb = nullptr;
    void* userdata = nullptr;
    bool done = false;
    bool cancelled = false;
};

struct hyperdht_query_s {
    std::shared_ptr<QueryState> state;
};

// Helper: allocate handle + state, wire the done callback location.
static hyperdht_query_t* make_query_handle(hyperdht_done_cb done_cb,
                                            void* userdata) {
    auto* h = new hyperdht_query_s;
    h->state = std::make_shared<QueryState>();
    h->state->done_cb = done_cb;
    h->state->userdata = userdata;
    return h;
}

// Helper: build an on_done lambda that fires the user's done_cb
// through `state`. Reads `done_cb` / `userdata` AT INVOCATION TIME so
// that `hyperdht_query_free()` can detach by nulling them — a late
// completion after free becomes silent.
template <class Result>
static std::function<void(const Result&)>
make_done_fn(std::shared_ptr<QueryState> state) {
    return [state](const Result&) {
        state->done = true;
        if (state->done_cb) {
            int err = state->cancelled ? HYPERDHT_ERR_CANCELLED : 0;
            state->done_cb(err, state->userdata);
        }
    };
}

// Helper: fill hyperdht_connection_t from C++ ConnectionInfo
static void fill_connection(hyperdht_connection_t* out,
                             const hyperdht::noise::Key& tx,
                             const hyperdht::noise::Key& rx,
                             const hyperdht::noise::Hash& hash,
                             const std::array<uint8_t, 32>& remote_pk,
                             const hyperdht::compact::Ipv4Address& addr,
                             uint32_t remote_udx, uint32_t local_udx,
                             bool initiator) {
    memcpy(out->remote_public_key, remote_pk.data(), 32);
    memcpy(out->tx_key, tx.data(), 32);
    memcpy(out->rx_key, rx.data(), 32);
    static_assert(sizeof(out->handshake_hash) == 64);
    memcpy(out->handshake_hash, hash.data(), 64);
    out->remote_udx_id = remote_udx;
    out->local_udx_id = local_udx;
    auto host = addr.host_string();
    strncpy(out->peer_host, host.c_str(), sizeof(out->peer_host) - 1);
    out->peer_host[sizeof(out->peer_host) - 1] = '\0';
    out->peer_port = addr.port;
    out->is_initiator = initiator ? 1 : 0;
    out->raw_stream = nullptr;
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
}

void hyperdht_keypair_from_seed(hyperdht_keypair_t* out, const uint8_t seed[32]) {
    if (!out || !seed) return;
    hyperdht::noise::Seed s{};
    memcpy(s.data(), seed, 32);
    auto kp = hyperdht::noise::generate_keypair(s);
    memcpy(out->public_key, kp.public_key.data(), 32);
    memcpy(out->secret_key, kp.secret_key.data(), 64);
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

// Helper: parse "host:port" → compact::Ipv4Address. Returns std::nullopt
// on malformed input so the caller can decide whether to skip or error.
static std::optional<hyperdht::compact::Ipv4Address>
parse_host_port(const char* s) {
    if (!s) return std::nullopt;
    const char* colon = strrchr(s, ':');
    if (!colon || colon == s) return std::nullopt;
    std::string host(s, colon - s);
    int port = std::atoi(colon + 1);
    if (port <= 0 || port > 65535) return std::nullopt;
    return hyperdht::compact::Ipv4Address::from_string(
        host, static_cast<uint16_t>(port));
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
    // Port 0 uses the port from DhtOptions (or ephemeral)
    // Non-zero port overrides DhtOptions
    if (port != 0) {
        // TODO: forward port to bind — currently HyperDHT::bind() uses opts_.port
        // For now, this is a known limitation: port must be set via opts at creation
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

// Shared connect result → C callback bridge (used by both connect and
// connect_ex). Converts ConnectResult into hyperdht_connection_t, manages
// the pool-socket keepalive lifetime, and dispatches the user's cb.
static void dispatch_connect_result(hyperdht_connect_cb cb, void* userdata,
                                    int error,
                                    const hyperdht::ConnectResult& result,
                                    bool is_initiator) {
    if (error != 0) {
        cb(error, nullptr, userdata);
        return;
    }
    hyperdht_connection_t conn{};
    fill_connection(&conn, result.tx_key, result.rx_key,
                    result.handshake_hash, result.remote_public_key,
                    result.peer_address, result.remote_udx_id,
                    result.local_udx_id, is_initiator);
    conn.raw_stream = result.raw_stream;
    conn.udx_socket = result.udx_socket;
    conn._internal = result.socket_keepalive
        ? new std::shared_ptr<void>(result.socket_keepalive)
        : nullptr;
    cb(0, &conn, userdata);
    if (conn._internal) {
        delete static_cast<std::shared_ptr<void>*>(conn._internal);
    }
}

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
            cpp_opts.keypair = std::move(kp);
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

// ---------------------------------------------------------------------------
// Server: listen
// ---------------------------------------------------------------------------

hyperdht_server_t* hyperdht_server_create(hyperdht_t* dht) {
    if (!dht || !dht->dht) return nullptr;

    auto* srv = new (std::nothrow) hyperdht_server_s;
    if (!srv) return nullptr;

    srv->server = dht->dht->create_server();
    if (!srv->server) {
        delete srv;
        return nullptr;
    }
    return srv;
}

int hyperdht_server_listen(hyperdht_server_t* srv,
                           const hyperdht_keypair_t* kp,
                           hyperdht_connection_cb cb,
                           void* userdata) {
    if (!srv || !srv->server || !kp || !cb) return -1;

    srv->cb = cb;
    srv->userdata = userdata;

    hyperdht::noise::Keypair cpp_kp;
    memcpy(cpp_kp.public_key.data(), kp->public_key, 32);
    memcpy(cpp_kp.secret_key.data(), kp->secret_key, 64);

    srv->server->listen(cpp_kp,
        [srv](const hyperdht::server::ConnectionInfo& info) {
            hyperdht_connection_t conn{};
            fill_connection(&conn, info.tx_key, info.rx_key,
                            info.handshake_hash, info.remote_public_key,
                            info.peer_address, info.remote_udx_id,
                            info.local_udx_id, info.is_initiator);
            conn.raw_stream = info.raw_stream;
            conn.udx_socket = info.udx_socket;
            srv->cb(&conn, srv->userdata);
        });

    return 0;
}

void hyperdht_server_set_firewall(hyperdht_server_t* srv,
                                   hyperdht_firewall_cb cb,
                                   void* userdata) {
    if (!srv || !srv->server) return;

    if (!cb) {
        srv->server->set_firewall(nullptr);
        return;
    }

    srv->server->set_firewall(
        [cb, userdata](const std::array<uint8_t, 32>& pk,
                       const hyperdht::peer_connect::NoisePayload&,
                       const hyperdht::compact::Ipv4Address& addr) -> bool {
            auto host = addr.host_string();
            return cb(pk.data(), host.c_str(), addr.port, userdata) == 0;
        });
}

void hyperdht_server_close(hyperdht_server_t* srv,
                           hyperdht_close_cb cb,
                           void* userdata) {
    if (!srv || !srv->server) {
        if (cb) cb(userdata);
        delete srv;
        return;
    }

    srv->server->close([srv, cb, userdata]() {
        delete srv;
        if (cb) cb(userdata);
    });
}

void hyperdht_server_close_force(hyperdht_server_t* srv,
                                 hyperdht_close_cb cb, void* userdata) {
    if (!srv || !srv->server) {
        if (cb) cb(userdata);
        delete srv;
        return;
    }
    srv->server->close(/*force=*/true, [srv, cb, userdata]() {
        delete srv;
        if (cb) cb(userdata);
    });
}

void hyperdht_server_suspend_logged(hyperdht_server_t* srv,
                                    hyperdht_log_cb log_cb, void* userdata) {
    if (!srv || !srv->server) return;
    if (!log_cb) { srv->server->suspend(); return; }
    srv->server->suspend([log_cb, userdata](const char* msg) {
        log_cb(msg, userdata);
    });
}

void hyperdht_server_refresh(hyperdht_server_t* srv) {
    if (!srv || !srv->server) return;
    srv->server->refresh();
}

// ---------------------------------------------------------------------------
// Mutable/Immutable storage — delegate to the HyperDHT class methods so
// both C++ and C consumers hit the same code path.
//
// Get operations use the new streaming `on_value` overload so the C `cb`
// fires once per verified reply (matching the documented contract of
// `cb` being "called for each verified result") rather than aggregated
// at query completion. `done_cb` fires once at the end of the query.
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
// Encrypted streams — refactored to SecretStreamDuplex (§10).
//
// Previously this section hand-rolled the header exchange + frame parser +
// encrypt/decrypt loop on top of the low-level `SecretStream` primitive.
// That version worked for basic read/write but didn't apply
// `DhtOptions::connection_keep_alive`, so continuous P2P data over NAT
// eventually died when the NAT pinhole timed out after ~30 seconds of
// silence.
//
// The refactored version delegates all of that to `SecretStreamDuplex`
// (the same wrapper `test/test_live_connect.cpp` has been dogfooding
// for a while). Keep-alive and idle-timeout now come for free from
// `dht->make_duplex_options()`, matching JS's automatic behaviour in
// `hyperdht/lib/connect.js:41-46`.
// ---------------------------------------------------------------------------

struct hyperdht_stream_s {
    // Heap-allocated UDX stream (self-delete close cb registered with
    // `udx_stream_init`). Whether we created it or reused one from the
    // connect/server handshake path is irrelevant once Duplex takes over —
    // both lifetimes converge on the same teardown sequence.
    udx_stream_t* raw = nullptr;
    hyperdht::secret_stream::SecretStreamDuplex* duplex = nullptr;
    hyperdht_t* dht = nullptr;

    hyperdht_close_cb on_open = nullptr;
    hyperdht_data_cb on_data = nullptr;
    hyperdht_close_cb on_close = nullptr;
    void* userdata = nullptr;

    bool closed = false;

    // Keeps the holepunch pool socket alive for the UDX stream's lifetime.
    // The raw UDX stream holds a raw pointer to the pool socket (via
    // udx_stream_connect). This shared_ptr prevents the pool from being
    // closed while the stream is active.
    std::shared_ptr<void> socket_keepalive;
};

// `on_close` wrapper: fires the user callback exactly once, then frees
// the wrapper. The Duplex destructor tears down the raw UDX stream.
static void stream_fire_close(hyperdht_stream_s* s) {
    if (s->closed) return;
    s->closed = true;
    if (s->on_close) s->on_close(s->userdata);
    // Free the Duplex first — its destructor detaches from raw_stream
    // and wipes key material. The raw UDX stream is deleted by libudx
    // itself once its close callback fires (the `delete s;` lambda we
    // passed to `udx_stream_init` in `create_raw_stream`).
    delete s->duplex;
    s->duplex = nullptr;
    delete s;
}

hyperdht_stream_t* hyperdht_stream_open(
    hyperdht_t* dht,
    const hyperdht_connection_t* conn,
    hyperdht_close_cb on_open,
    hyperdht_data_cb on_data,
    hyperdht_close_cb on_close,
    void* userdata) {

    if (!dht || !dht->dht || !conn) return nullptr;

    // ---- 1. Obtain a heap-allocated raw UDX stream ----
    udx_stream_t* raw = nullptr;
    if (conn->raw_stream) {
        // Pre-created by the connect/server handshake path. Already
        // heap-allocated with a self-delete close callback (see
        // `ClientRawStreamCtx` setup in `dht.cpp` or the server-side
        // `create_raw_stream()` call). We take ownership transfer.
        raw = static_cast<udx_stream_t*>(conn->raw_stream);
        // The handshake path may have stored its own context in data_;
        // clear it before the Duplex installs its own callbacks. Any
        // previous firewall callback was consumed when the server sent
        // its first UDX packet, so the stored context is safe to drop.
        if (raw->data) {
            // Defensive: we cannot know the exact type of the previous
            // `raw->data` from here, so we just null it. If it leaked a
            // small allocation that's the caller's problem — the
            // handshake paths that produce `conn->raw_stream` clean up
            // their own context when they stash the pointer in the
            // `ConnectResult`.
            raw->data = nullptr;
        }

        if (conn->peer_port != 0) {
            struct sockaddr_in dest{};
            uv_ip4_addr(conn->peer_host, conn->peer_port, &dest);
            // Use the holepunch-discovered socket when available — it has
            // the correct NAT mapping. Fall back to the main RPC socket.
            udx_socket_t* sock = conn->udx_socket
                ? static_cast<udx_socket_t*>(conn->udx_socket)
                : dht->dht->socket().socket_handle();
            udx_stream_connect(raw, sock,
                               conn->remote_udx_id,
                               reinterpret_cast<const struct sockaddr*>(&dest));
        }
    } else {
        // Fallback: create a new UDX stream ourselves. Matches the
        // pattern used by `HyperDHT::create_raw_stream()`: heap
        // allocation + self-delete close callback so libudx deletes
        // the struct when its async close fires.
        if (conn->peer_port == 0) return nullptr;

        raw = new (std::nothrow) udx_stream_t{};
        if (!raw) return nullptr;

        int rc = udx_stream_init(dht->dht->socket().udx_handle(), raw,
                                 conn->local_udx_id,
                                 [](udx_stream_t*, int) {},
                                 [](udx_stream_t* s) { delete s; });
        if (rc != 0) {
            delete raw;
            return nullptr;
        }

        struct sockaddr_in dest{};
        uv_ip4_addr(conn->peer_host, conn->peer_port, &dest);
        udx_stream_connect(raw, dht->dht->socket().socket_handle(),
                           conn->remote_udx_id,
                           reinterpret_cast<const struct sockaddr*>(&dest));
    }

    // ---- 2. Build the SecretStreamDuplex handshake context ----
    hyperdht::secret_stream::DuplexHandshake hs{};
    std::memcpy(hs.tx_key.data(), conn->tx_key, 32);
    std::memcpy(hs.rx_key.data(), conn->rx_key, 32);
    std::memcpy(hs.handshake_hash.data(), conn->handshake_hash, 64);
    std::memcpy(hs.remote_public_key.data(), conn->remote_public_key, 32);
    // `public_key` on the Duplex is metadata-only (exposed via a getter,
    // never touched by the cipher). Use the DHT's default keypair as a
    // reasonable default — servers that listened under a different
    // keypair will see a mismatched metadata pubkey, but since no crypto
    // uses this field the stream still works correctly.
    hs.public_key = dht->dht->default_keypair().public_key;
    hs.is_initiator = (conn->is_initiator != 0);

    // ---- 3. Allocate the wrapper + construct the Duplex ----
    auto* s = new (std::nothrow) hyperdht_stream_s;
    if (!s) {
        // OOM after raw stream init: must destroy the raw stream so its
        // self-delete close callback frees the heap allocation. Covers
        // both the just-created path and the reused-from-conn path —
        // either way the raw stream now belongs to nobody and would
        // leak otherwise.
        udx_stream_destroy(raw);
        return nullptr;
    }
    s->raw = raw;
    s->dht = dht;
    s->on_open = on_open;
    s->on_data = on_data;
    s->on_close = on_close;
    s->userdata = userdata;

    // Take ownership of the pool socket keepalive from the connection.
    // This keeps the holepunch pool socket alive for the stream's lifetime.
    if (conn->_internal) {
        s->socket_keepalive = std::move(
            *static_cast<std::shared_ptr<void>*>(conn->_internal));
        delete static_cast<std::shared_ptr<void>*>(conn->_internal);
        // Cast away const to null the consumed pointer — prevents the
        // connect callback's cleanup from double-freeing.
        const_cast<hyperdht_connection_t*>(conn)->_internal = nullptr;
    }

    // `make_duplex_options()` populates `keep_alive_ms` from
    // `DhtOptions::connection_keep_alive` (default 5000 ms) — this is
    // the §7 polish wire-up, finally active on the C FFI path as well.
    auto duplex_opts = dht->dht->make_duplex_options();
    s->duplex = new hyperdht::secret_stream::SecretStreamDuplex(
        raw, hs, dht->dht->loop(), duplex_opts);

    // ---- 4. Install event callbacks ----
    s->duplex->on_connect([s]() {
        // The header exchange is complete; the encrypted channel is up.
        if (s->on_open) s->on_open(s->userdata);
    });
    s->duplex->on_message([s](const uint8_t* data, size_t len) {
        if (s->on_data) s->on_data(data, len, s->userdata);
    });
    s->duplex->on_end([s]() {
        // Peer signalled half-close; begin our own teardown so on_close
        // fires for the user. `end()` is idempotent.
        if (s->duplex) s->duplex->end();
    });
    s->duplex->on_close([s](int /*err*/) {
        stream_fire_close(s);
    });

    // ---- 5. Fire off the header exchange ----
    s->duplex->start();
    return s;
}

int hyperdht_stream_write(hyperdht_stream_t* stream,
                          const uint8_t* data, size_t len) {
    if (!stream || !stream->duplex || stream->closed || !data) return -1;
    if (!stream->duplex->is_connected()) return -1;
    return stream->duplex->write(data, len, nullptr);
}

int hyperdht_stream_write_with_drain(hyperdht_stream_t* stream,
                                      const uint8_t* data, size_t len,
                                      hyperdht_drain_cb on_drain,
                                      void* userdata) {
    if (!stream || !stream->duplex || stream->closed || !data) return -1;
    if (!stream->duplex->is_connected()) return -1;
    if (!on_drain) {
        return stream->duplex->write(data, len, nullptr);
    }
    return stream->duplex->write(data, len,
        [stream, on_drain, userdata](int /*status*/) {
            // Guard: stream may have been closed between write and drain.
            if (stream->closed) return;
            on_drain(stream, userdata);
        });
}

void hyperdht_stream_close(hyperdht_stream_t* stream) {
    if (!stream || stream->closed || !stream->duplex) return;
    // Graceful close: `end()` sends write_end on the underlying UDX
    // stream; when both sides finish, the Duplex fires `on_close` and
    // `stream_fire_close` frees the wrapper.
    stream->duplex->end();
}

int hyperdht_stream_is_open(const hyperdht_stream_t* stream) {
    if (!stream || !stream->duplex) return 0;
    return stream->duplex->is_connected() ? 1 : 0;
}

// =========================================================================
// Phase C: Extended C API (2026-04-14)
// =========================================================================

// --- C2: DHT state ---

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

// --- C3: DHT event hooks ---

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

// --- C4: DHT query operations ---

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

// --- C5: DHT lifecycle ---

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
    // Bridge C `const char*` callback → C++ std::function<void(const char*)>.
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

// --- C6: DHT misc ---

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

// --- C7: Server state ---

void hyperdht_server_suspend(hyperdht_server_t* srv) {
    if (srv && srv->server) srv->server->suspend();
}

void hyperdht_server_resume(hyperdht_server_t* srv) {
    if (srv && srv->server) srv->server->resume();
}

void hyperdht_server_notify_online(hyperdht_server_t* srv) {
    if (srv && srv->server) srv->server->notify_online();
}

int hyperdht_server_is_listening(const hyperdht_server_t* srv) {
    if (!srv || !srv->server) return 0;
    return srv->server->is_listening() ? 1 : 0;
}

int hyperdht_server_public_key(const hyperdht_server_t* srv,
                                uint8_t out[32]) {
    if (!srv || !srv->server || !out) return -1;
    if (!srv->server->is_listening()) return -1;
    auto& pk = srv->server->public_key();
    memcpy(out, pk.data(), 32);
    return 0;
}

void hyperdht_server_on_listening(hyperdht_server_t* srv,
                                  hyperdht_event_cb cb, void* userdata) {
    if (!srv || !srv->server) return;
    if (!cb) { srv->server->on_listening(nullptr); return; }
    srv->server->on_listening([cb, userdata]() { cb(userdata); });
}

int hyperdht_server_address(const hyperdht_server_t* srv,
                            char out_host[46], uint16_t* out_port) {
    if (!srv || !srv->server || !out_host || !out_port) return -1;
    auto info = srv->server->address();
    if (!srv->server->is_listening() || info.host.empty() || info.port == 0) {
        return -1;
    }
    std::strncpy(out_host, info.host.c_str(), 45);
    out_host[45] = '\0';
    *out_port = info.port;
    return 0;
}

// --- C8: Server config ---

void hyperdht_server_set_holepunch(hyperdht_server_t* srv,
                                    hyperdht_holepunch_cb cb,
                                    void* userdata) {
    if (!srv || !srv->server) return;

    if (!cb) {
        srv->server->set_holepunch(nullptr);
        return;
    }

    srv->server->set_holepunch(
        [cb, userdata](uint32_t remote_fw, uint32_t local_fw,
                       const std::vector<hyperdht::compact::Ipv4Address>& remote_addrs,
                       const std::vector<hyperdht::compact::Ipv4Address>& local_addrs) -> bool {
            return cb(remote_fw, local_fw,
                      static_cast<int>(remote_addrs.size()),
                      static_cast<int>(local_addrs.size()),
                      userdata) == 0;
        });
}

// The FFI firewall-done handle wraps the std::function the C++ layer
// handed us. The user's C callback takes a pointer into this struct;
// hyperdht_firewall_done() invokes the std::function and deletes the
// wrapper so a second call is a safe no-op (nullptr fn).
//
// Also owns snapshots of `remote_pk` and `peer_host`: the C++ layer
// hands us references that are valid only for the synchronous call
// window into the user callback. The async firewall pattern requires
// those values to outlive the callback frame (user might hand them
// to a DB lookup that completes seconds later), so we copy them into
// this struct and expose pointers to OUR storage instead. The user
// may safely read these via the `remote_pk` / `peer_host` fields
// passed to their callback, AND may retain those pointers until they
// invoke `hyperdht_firewall_done()` — at which point this whole
// struct is destroyed.
struct hyperdht_firewall_done_s {
    hyperdht::server::Server::FirewallDoneCb fn;
    std::array<uint8_t, 32> pk_copy{};
    char host_copy[46] = {0};
};

void hyperdht_firewall_done(hyperdht_firewall_done_t* done, int reject) {
    if (!done || !done->fn) return;  // already invoked — no-op
    // Move the std::function out so a stale pointer can't call twice
    // through us. The C++ side has its own once-guard; this is belt +
    // braces for the FFI layer.
    auto fn = std::move(done->fn);
    done->fn = nullptr;
    fn(reject != 0);
    delete done;
}

void hyperdht_server_set_firewall_async(hyperdht_server_t* srv,
                                         hyperdht_firewall_async_cb cb,
                                         void* userdata) {
    if (!srv || !srv->server) return;

    if (!cb) {
        srv->server->set_firewall_async(nullptr);
        return;
    }

    srv->server->set_firewall_async(
        [cb, userdata](const std::array<uint8_t, 32>& pk,
                       const hyperdht::peer_connect::NoisePayload& /*payload*/,
                       const hyperdht::compact::Ipv4Address& addr,
                       hyperdht::server::Server::FirewallDoneCb done) {
            // C1 fix: snapshot pk + host INTO the handle before calling
            // the user. The C callback is expected to store the handle
            // and call hyperdht_firewall_done() after an async policy
            // check — by which point the original `pk` and `addr.host_string()`
            // would be out of scope. Pointers we hand to the user MUST
            // stay valid until they call us back.
            auto* handle = new hyperdht_firewall_done_s{};
            handle->fn = std::move(done);
            handle->pk_copy = pk;
            auto host = addr.host_string();
            std::strncpy(handle->host_copy, host.c_str(),
                         sizeof(handle->host_copy) - 1);
            // C caller must call hyperdht_firewall_done(handle, reject)
            // exactly once — we hand them ownership of `handle`.
            cb(handle->pk_copy.data(), handle->host_copy,
               addr.port, handle, userdata);
        });
}

// ---------------------------------------------------------------------------
// Phase E: Blind Relay
// ---------------------------------------------------------------------------

void hyperdht_server_set_relay_through(hyperdht_server_t* srv,
                                        const uint8_t* relay_pk,
                                        uint64_t keep_alive_ms) {
    if (!srv || !srv->server) return;

    if (relay_pk) {
        hyperdht::noise::PubKey pk{};
        memcpy(pk.data(), relay_pk, 32);
        srv->server->relay_through = pk;
    } else {
        srv->server->relay_through = std::nullopt;
    }
    srv->server->relay_keep_alive = keep_alive_ms;
}

void hyperdht_connect_relay(hyperdht_t* dht,
                             const uint8_t* remote_pk,
                             const uint8_t* relay_pk,
                             uint64_t relay_keep_alive_ms,
                             hyperdht_connect_cb cb,
                             void* userdata) {
    if (!dht || !dht->dht || !remote_pk || !cb) {
        if (cb) cb(-1, nullptr, userdata);
        return;
    }

    hyperdht::noise::PubKey pk{};
    memcpy(pk.data(), remote_pk, 32);

    hyperdht::ConnectOptions opts;
    if (relay_pk) {
        hyperdht::noise::PubKey rpk{};
        memcpy(rpk.data(), relay_pk, 32);
        opts.relay_through = rpk;
    }
    opts.relay_keep_alive = relay_keep_alive_ms;

    dht->dht->connect(pk, opts,
        [cb, userdata](int error, const hyperdht::ConnectResult& result) {
            if (error != 0) {
                cb(error, nullptr, userdata);
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
            cb(0, &conn, userdata);
            if (conn._internal) {
                delete static_cast<std::shared_ptr<void>*>(conn._internal);
            }
        });
}

int hyperdht_relay_stats_attempts(hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->stats().relaying.attempts;
}

int hyperdht_relay_stats_successes(hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->stats().relaying.successes;
}

int hyperdht_relay_stats_aborts(hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->stats().relaying.aborts;
}

int hyperdht_punch_stats_consistent(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->stats().punches.consistent;
}
int hyperdht_punch_stats_random(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->stats().punches.random;
}
int hyperdht_punch_stats_open(const hyperdht_t* dht) {
    if (!dht || !dht->dht) return 0;
    return dht->dht->stats().punches.open;
}

int hyperdht_ping(hyperdht_t* dht,
                  const char* host, uint16_t port,
                  hyperdht_ping_cb cb, void* userdata) {
    if (!dht || !dht->dht || !host || !cb) return -1;
    struct sockaddr_in probe{};
    if (uv_ip4_addr(host, port, &probe) != 0) return -2;
    auto addr = hyperdht::compact::Ipv4Address::from_string(host, port);
    dht->dht->ping(addr, [cb, userdata](bool ok) {
        cb(ok ? 1 : 0, userdata);
    });
    return 0;
}

// ---------------------------------------------------------------------------
// File descriptor polling
// ---------------------------------------------------------------------------

struct hyperdht_poll_s {
    uv_poll_t handle;
    hyperdht_poll_cb cb;
    void* userdata;
    int fd;
};

static void on_poll(uv_poll_t* handle, int status, int events) {
    auto* p = static_cast<hyperdht_poll_t*>(handle->data);
    if (!p || !p->cb || status < 0) return;
    int mapped = 0;
    if (events & UV_READABLE) mapped |= HYPERDHT_POLL_READABLE;
    if (events & UV_WRITABLE) mapped |= HYPERDHT_POLL_WRITABLE;
    p->cb(p->fd, mapped, p->userdata);
}

hyperdht_poll_t* hyperdht_poll_start(hyperdht_t* dht,
                                     int fd, int events,
                                     hyperdht_poll_cb cb,
                                     void* userdata) {
    if (!dht || !dht->dht || fd < 0 || !cb) return nullptr;

    auto* p = new (std::nothrow) hyperdht_poll_t{};
    if (!p) return nullptr;

    p->cb = cb;
    p->userdata = userdata;
    p->fd = fd;
    p->handle.data = p;

    if (uv_poll_init(dht->dht->loop(), &p->handle, fd) != 0) {
        delete p;
        return nullptr;
    }

    int uv_events = 0;
    if (events & HYPERDHT_POLL_READABLE) uv_events |= UV_READABLE;
    if (events & HYPERDHT_POLL_WRITABLE) uv_events |= UV_WRITABLE;

    if (uv_poll_start(&p->handle, uv_events, on_poll) != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(&p->handle),
                 [](uv_handle_t* h) { delete static_cast<hyperdht_poll_t*>(h->data); });
        return nullptr;
    }

    return p;
}

void hyperdht_poll_stop(hyperdht_poll_t* handle) {
    if (!handle) return;
    uv_poll_stop(&handle->handle);
    uv_close(reinterpret_cast<uv_handle_t*>(&handle->handle),
             [](uv_handle_t* h) { delete static_cast<hyperdht_poll_t*>(h->data); });
}
