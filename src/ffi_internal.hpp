// Shared internal types and helpers for the FFI shim files (ffi_*.cpp).
#pragma once

#include "hyperdht/hyperdht.h"

#include <sodium.h>

#include <cstring>
#include <functional>
#include <memory>
#include <optional>

#include "hyperdht/dht.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/secret_stream.hpp"
#include "hyperdht/server.hpp"

#include <udx.h>

// ---------------------------------------------------------------------------
// Opaque wrapper structs
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

// ---------------------------------------------------------------------------
// Stream wrapper
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

// ---------------------------------------------------------------------------
// Inline helpers used by multiple ffi_*.cpp files
// ---------------------------------------------------------------------------

// Allocate handle + state, wire the done callback location.
inline hyperdht_query_t* make_query_handle(hyperdht_done_cb done_cb,
                                            void* userdata) {
    auto* h = new hyperdht_query_s;
    h->state = std::make_shared<QueryState>();
    h->state->done_cb = done_cb;
    h->state->userdata = userdata;
    return h;
}

// Build an on_done lambda that fires the user's done_cb through `state`.
// Reads `done_cb` / `userdata` AT INVOCATION TIME so that
// `hyperdht_query_free()` can detach by nulling them — a late
// completion after free becomes silent.
template <class Result>
inline std::function<void(const Result&)>
make_done_fn(std::shared_ptr<QueryState> state) {
    return [state](const Result&) {
        state->done = true;
        if (state->done_cb) {
            int err = state->cancelled ? HYPERDHT_ERR_CANCELLED : 0;
            state->done_cb(err, state->userdata);
        }
    };
}

// Fill hyperdht_connection_t from C++ ConnectionInfo fields.
inline void fill_connection(hyperdht_connection_t* out,
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

// `on_close` wrapper: fires the user callback exactly once, then frees
// the wrapper. The Duplex destructor tears down the raw UDX stream.
inline void stream_fire_close(hyperdht_stream_s* s) {
    if (s->closed) return;
    s->closed = true;
    if (s->on_close) s->on_close(s->userdata);
    // destroy() stops the UDX stream (udx_stream_destroy) and timers
    // BEFORE we delete the duplex. Without this, the UDX stream keeps
    // receiving data and calls on_udx_read with data=nullptr → crash.
    // destroy() is idempotent (checks destroyed_ flag).
    if (s->duplex) s->duplex->destroy(0);
    delete s->duplex;
    s->duplex = nullptr;
    delete s;
}

// Parse "host:port" → compact::Ipv4Address. Returns std::nullopt on
// malformed input so the caller can decide whether to skip or error.
inline std::optional<hyperdht::compact::Ipv4Address>
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

// Shared connect result → C callback bridge (used by both connect and
// connect_relay). Converts ConnectResult into hyperdht_connection_t,
// manages the pool-socket keepalive lifetime, and dispatches the user's cb.
inline void dispatch_connect_result(hyperdht_connect_cb cb, void* userdata,
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
