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

hyperdht_t* hyperdht_create(uv_loop_t* loop, const hyperdht_opts_t* opts) {
    if (!loop) return nullptr;

    hyperdht::DhtOptions cpp_opts;
    if (opts) {
        cpp_opts.port = opts->port;
        cpp_opts.ephemeral = (opts->ephemeral != 0);
        // §2: wire the `use_public_bootstrap` flag through to the C++
        // layer. When set, the HyperDHT constructor stores the 3 public
        // seed nodes in `opts_.bootstrap`, and `bind()` will launch a
        // one-shot FIND_NODE(our_id) walk on behalf of the caller.
        if (opts->use_public_bootstrap) {
            cpp_opts.bootstrap =
                hyperdht::HyperDHT::default_bootstrap_nodes();
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
    if (!dht || !dht->dht || !remote_pk || !cb) return -1;

    hyperdht::noise::PubKey pk{};
    memcpy(pk.data(), remote_pk, 32);

    dht->dht->connect(pk, [cb, userdata](int error, const hyperdht::ConnectResult& result) {
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
        conn.udx_socket = result.udx_socket;  // Socket from holepunch probe
        // Stash the pool socket keepalive so hyperdht_stream_open can pick it up.
        // Heap-allocated shared_ptr — stream_open takes ownership.
        conn._internal = result.socket_keepalive
            ? new std::shared_ptr<void>(result.socket_keepalive)
            : nullptr;
        cb(0, &conn, userdata);
        // Clean up if user didn't call stream_open (didn't consume _internal)
        if (conn._internal) {
            delete static_cast<std::shared_ptr<void>*>(conn._internal);
        }
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
            conn.raw_stream = info.raw_stream;  // Pass pre-created rawStream
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
