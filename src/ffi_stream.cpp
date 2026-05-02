// FFI stream: encrypted stream open/write/close, file-descriptor polling.
//
// Safety: drain callbacks use shared_ptr<bool> closed_flag (survives stream
// deletion). uv_ip4_addr return value is checked. Zero-event polls rejected.
#include "ffi_internal.hpp"
#include "hyperdht/debug.hpp"

// ---------------------------------------------------------------------------
// Encrypted streams — delegates to SecretStreamDuplex (see ffi_internal.hpp
// for hyperdht_stream_s and stream_fire_close).
// ---------------------------------------------------------------------------

hyperdht_stream_t* hyperdht_stream_open(
    hyperdht_t* dht,
    const hyperdht_connection_t* conn,
    hyperdht_close_cb on_open,
    hyperdht_data_cb on_data,
    hyperdht_close_cb on_close,
    void* userdata) {

    if (!dht || !dht->dht || !conn) return nullptr;

    DHT_LOG("  [ffi-stream] stream_open: peer=%s:%u raw_stream=%p udx_socket=%p "
            "initiator=%d remote_udx_id=%u local_udx_id=%u\n",
            conn->peer_host, conn->peer_port, conn->raw_stream,
            conn->udx_socket, conn->is_initiator,
            conn->remote_udx_id, conn->local_udx_id);

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
            int rc = uv_ip4_addr(conn->peer_host, conn->peer_port, &dest);
            if (rc != 0) {  // H19: invalid address
                udx_stream_destroy(raw);
                return nullptr;
            }
            // Use the holepunch-discovered socket when available — it has
            // the correct NAT mapping. Fall back to the main RPC socket.
            udx_socket_t* sock = conn->udx_socket
                ? static_cast<udx_socket_t*>(conn->udx_socket)
                : dht->dht->socket().socket_handle();

            // Debug: identify which socket is being used
            struct sockaddr_in sock_addr{};
            int sock_len = sizeof(sock_addr);
            udx_socket_getsockname(sock, reinterpret_cast<struct sockaddr*>(&sock_addr), &sock_len);
            DHT_LOG("  [ffi-stream] stream connecting via %s socket (port %u) → %s:%u\n",
                    conn->udx_socket ? "holepunch" : "server_socket",
                    ntohs(sock_addr.sin_port), conn->peer_host, conn->peer_port);

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
    // the section-7 polish wire-up, finally active on the C FFI path as well.
    auto duplex_opts = dht->dht->make_duplex_options();
    s->duplex = new hyperdht::secret_stream::SecretStreamDuplex(
        raw, hs, dht->dht->loop(), duplex_opts);

    // ---- 4. Install event callbacks ----
    s->duplex->on_connect([s]() {
        DHT_LOG("  [ffi-stream] SecretStream header exchange COMPLETE (on_connect)\n");
        // The header exchange is complete; the encrypted channel is up.
        if (s->on_open) s->on_open(s->userdata);
    });
    s->duplex->on_message([s](const uint8_t* data, size_t len) {
        DHT_LOG("  [ffi-stream] on_message: %zu bytes (closed=%d)\n", len, s->closed ? 1 : 0);
        if (s->on_data) s->on_data(data, len, s->userdata);
    });
    s->duplex->on_udp_message([s](const uint8_t* data, size_t len) {
        // Drops are intentional when no callback is installed yet —
        // mirrors the reliable-stream behaviour and keeps install
        // semantics asymmetric (set-once vs constructor) flexible.
        if (s->closed) return;
        if (s->on_udp_message) {
            s->on_udp_message(data, len, s->udp_userdata);
        }
    });
    s->duplex->on_end([s]() {
        DHT_LOG("  [ffi-stream] on_end: peer half-closed\n");
        // Peer signalled half-close; begin our own teardown so on_close
        // fires for the user. `end()` is idempotent.
        if (s->duplex) s->duplex->end();
    });
    s->duplex->on_close([s](int err) {
        DHT_LOG("  [ffi-stream] on_close: err=%d\n", err);
        stream_fire_close(s);
    });

    // ---- 5. Fire off the header exchange ----
    DHT_LOG("  [ffi-stream] starting SecretStream header exchange (initiator=%d)\n",
            hs.is_initiator ? 1 : 0);
    s->duplex->start();
    DHT_LOG("  [ffi-stream] stream_open returning stream=%p\n", s);
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
    // H18: capture shared closed_flag — survives stream deletion
    auto closed_flag = stream->closed_flag;
    return stream->duplex->write(data, len,
        [closed_flag, stream, on_drain, userdata](int /*status*/) {
            if (*closed_flag) return;
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

int hyperdht_stream_set_on_udp_message(hyperdht_stream_t* stream,
                                        hyperdht_udp_msg_cb cb,
                                        void* userdata) {
    if (!stream) return -1;
    stream->on_udp_message = cb;
    stream->udp_userdata = userdata;
    return 0;
}

int hyperdht_stream_send_udp(hyperdht_stream_t* stream,
                              const uint8_t* data, size_t len) {
    if (!stream || stream->closed || !stream->duplex || !data) return -1;
    return stream->duplex->send_udp(data, len);
}

int hyperdht_stream_try_send_udp(hyperdht_stream_t* stream,
                                  const uint8_t* data, size_t len) {
    if (!stream || stream->closed || !stream->duplex || !data) return -1;
    return stream->duplex->try_send_udp(data, len);
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
    // M16: reject zero events — would create zombie poll handle
    if (uv_events == 0) { delete p; return nullptr; }

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
