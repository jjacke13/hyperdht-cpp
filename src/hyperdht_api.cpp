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
        cb(0, &conn, userdata);
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
// Mutable/Immutable storage
// ---------------------------------------------------------------------------

int hyperdht_immutable_put(hyperdht_t* dht,
                           const uint8_t* value, size_t len,
                           hyperdht_done_cb cb, void* userdata) {
    if (!dht || !dht->dht || !value || len == 0) return -1;

    std::vector<uint8_t> val(value, value + len);
    hyperdht::dht_ops::immutable_put(dht->dht->socket(), val,
        [cb, userdata](const std::vector<hyperdht::query::QueryReply>&) {
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

    hyperdht::dht_ops::immutable_get(dht->dht->socket(), t,
        [cb, userdata](const std::vector<uint8_t>& value) {
            if (cb) cb(value.data(), value.size(), userdata);
        },
        [done_cb, userdata](const std::vector<hyperdht::query::QueryReply>&) {
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
    hyperdht::dht_ops::mutable_put(dht->dht->socket(), cpp_kp, val, seq,
        [cb, userdata](const std::vector<hyperdht::query::QueryReply>&) {
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

    std::array<uint8_t, 32> pk{};
    memcpy(pk.data(), public_key, 32);

    hyperdht::dht_ops::mutable_get(dht->dht->socket(), pk, min_seq,
        [cb, userdata](const hyperdht::dht_ops::MutableResult& result) {
            if (cb) cb(result.seq, result.value.data(), result.value.size(),
                       result.signature.data(), userdata);
        },
        [done_cb, userdata](const std::vector<hyperdht::query::QueryReply>&) {
            if (done_cb) done_cb(0, userdata);
        });
    return 0;
}

// ---------------------------------------------------------------------------
// Encrypted streams — UDX + SecretStream over an established connection
// ---------------------------------------------------------------------------

struct hyperdht_stream_s {
    udx_stream_t raw_stream{};
    hyperdht::secret_stream::SecretStream* ss = nullptr;
    hyperdht_t* dht = nullptr;

    hyperdht_close_cb on_open = nullptr;
    hyperdht_data_cb on_data = nullptr;
    hyperdht_close_cb on_close = nullptr;
    void* userdata = nullptr;

    std::vector<uint8_t> recv_buf;
    bool header_sent = false;
    bool header_received = false;
    bool open = false;
    bool closed = false;

    void check_open() {
        if (!open && header_sent && header_received) {
            open = true;
            if (on_open) on_open(userdata);
        }
    }
};

static void stream_on_read(udx_stream_t* raw, ssize_t nread, const uv_buf_t* buf) {
    auto* s = static_cast<hyperdht_stream_s*>(raw->data);
    if (!s) return;
    if (nread <= 0) {
        if (nread < 0 && !s->closed) {
            s->closed = true;
            // Destroy triggers stream_on_close_cb which fires on_close and frees
            udx_stream_destroy(raw);
        }
        return;
    }

    auto* data = reinterpret_cast<const uint8_t*>(buf->base);
    s->recv_buf.insert(s->recv_buf.end(), data, data + nread);

    // Phase 1: header exchange (59 bytes: uint24_le(56) + 56-byte payload)
    if (!s->header_received) {
        if (s->recv_buf.size() >= 59) {
            uint32_t hdr_len = static_cast<uint32_t>(s->recv_buf[0])
                             | (static_cast<uint32_t>(s->recv_buf[1]) << 8)
                             | (static_cast<uint32_t>(s->recv_buf[2]) << 16);
            if (hdr_len == 56) {
                s->ss->receive_header(s->recv_buf.data() + 3, 56);
                s->header_received = true;
                s->recv_buf.erase(s->recv_buf.begin(), s->recv_buf.begin() + 59);
                s->check_open();
            }
        }
        if (!s->header_received) return;
    }

    // Phase 2: decrypt data frames (uint24_le(len) + encrypted_payload)
    while (s->recv_buf.size() >= 3) {
        uint32_t frame_len = static_cast<uint32_t>(s->recv_buf[0])
                           | (static_cast<uint32_t>(s->recv_buf[1]) << 8)
                           | (static_cast<uint32_t>(s->recv_buf[2]) << 16);
        if (s->recv_buf.size() < 3 + frame_len) break;

        auto dec = s->ss->decrypt(s->recv_buf.data() + 3, frame_len);
        s->recv_buf.erase(s->recv_buf.begin(),
                          s->recv_buf.begin() + 3 + frame_len);

        if (dec.has_value() && s->on_data) {
            s->on_data(dec->data(), dec->size(), s->userdata);
        }
    }
}

static void stream_on_close_cb(udx_stream_t* raw, int) {
    auto* s = static_cast<hyperdht_stream_s*>(raw->data);
    if (!s) return;
    if (!s->closed) {
        s->closed = true;
        if (s->on_close) s->on_close(s->userdata);
    }
    // Free resources — the UDX stream is fully closed at this point
    raw->data = nullptr;
    delete s->ss;
    delete s;
}

// Send the SecretStream header over the connected UDX stream.
static void stream_send_header(hyperdht_stream_s* s) {
    auto header = s->ss->create_header_message();
    auto* hdr_buf = new std::vector<uint8_t>(std::move(header));
    uv_buf_t uv_buf = uv_buf_init(
        reinterpret_cast<char*>(hdr_buf->data()),
        static_cast<unsigned int>(hdr_buf->size()));

    auto* wreq = static_cast<udx_stream_write_t*>(
        calloc(1, sizeof(udx_stream_write_t) + sizeof(udx_stream_write_buf_t)));

    struct HdrCtx { std::vector<uint8_t>* buf; hyperdht_stream_s* stream; };
    wreq->data = new HdrCtx{hdr_buf, s};

    udx_stream_write(wreq, &s->raw_stream, &uv_buf, 1,
        [](udx_stream_write_t* req, int status, int) {
            auto* ctx = static_cast<HdrCtx*>(req->data);
            if (status >= 0) {
                ctx->stream->header_sent = true;
                ctx->stream->check_open();
            }
            delete ctx->buf;
            delete ctx;
            free(req);
        });
}

hyperdht_stream_t* hyperdht_stream_open(
    hyperdht_t* dht,
    const hyperdht_connection_t* conn,
    hyperdht_close_cb on_open,
    hyperdht_data_cb on_data,
    hyperdht_close_cb on_close,
    void* userdata) {

    if (!dht || !dht->dht || !conn) return nullptr;

    auto* s = new (std::nothrow) hyperdht_stream_s;
    if (!s) return nullptr;

    s->dht = dht;
    s->on_open = on_open;
    s->on_data = on_data;
    s->on_close = on_close;
    s->userdata = userdata;

    // Create SecretStream from connection keys
    hyperdht::noise::Key tx{}, rx{};
    hyperdht::noise::Hash hash{};
    memcpy(tx.data(), conn->tx_key, 32);
    memcpy(rx.data(), conn->rx_key, 32);
    memcpy(hash.data(), conn->handshake_hash, 64);

    s->ss = new hyperdht::secret_stream::SecretStream(
        tx, rx, hash, conn->is_initiator != 0);

    // Init UDX stream
    udx_stream_init(dht->dht->socket().udx_handle(), &s->raw_stream,
                    conn->local_udx_id, stream_on_close_cb, nullptr);
    s->raw_stream.data = s;

    // Connect to peer immediately. The address from the holepunch payload
    // may not be the client's real CGNAT address, causing brief rto
    // retransmissions until UDX adjusts. The proper fix (creating the
    // rawStream during handshake with a firewall callback, like JS does)
    // requires handshake deduplication first to avoid cirbuf collisions.
    if (conn->peer_port == 0) {
        delete s->ss;
        delete s;
        return nullptr;
    }
    struct sockaddr_in dest{};
    uv_ip4_addr(conn->peer_host, conn->peer_port, &dest);
    udx_stream_connect(&s->raw_stream, dht->dht->socket().socket_handle(),
                       conn->remote_udx_id,
                       reinterpret_cast<const struct sockaddr*>(&dest));

    // Send SecretStream header
    stream_send_header(s);

    // Start reading
    udx_stream_read_start(&s->raw_stream, stream_on_read);

    return s;
}

int hyperdht_stream_write(hyperdht_stream_t* stream,
                          const uint8_t* data, size_t len) {
    if (!stream || !stream->open || stream->closed || !data) return -1;

    // Encrypt with SecretStream (XChaCha20-Poly1305)
    auto encrypted = stream->ss->encrypt(data, len);
    auto* enc_buf = new std::vector<uint8_t>(std::move(encrypted));
    uv_buf_t uv_buf = uv_buf_init(
        reinterpret_cast<char*>(enc_buf->data()),
        static_cast<unsigned int>(enc_buf->size()));

    auto* wreq = static_cast<udx_stream_write_t*>(
        calloc(1, sizeof(udx_stream_write_t) + sizeof(udx_stream_write_buf_t)));
    wreq->data = enc_buf;

    int rc = udx_stream_write(wreq, &stream->raw_stream, &uv_buf, 1,
        [](udx_stream_write_t* req, int, int) {
            delete static_cast<std::vector<uint8_t>*>(req->data);
            free(req);
        });

    if (rc < 0) {
        delete enc_buf;
        free(wreq);
    }
    return rc >= 0 ? 0 : rc;
}

void hyperdht_stream_close(hyperdht_stream_t* stream) {
    if (!stream || stream->closed) return;
    stream->closed = true;

    // Graceful close: send write_end so the remote knows we're done.
    // The UDX stream stays alive for data to drain. When both sides
    // have ended, stream_on_close_cb fires and frees resources.
    // Do NOT call udx_stream_destroy here — it races with pending
    // writes and triggers a ref_count assertion in libudx.
    auto* wreq = static_cast<udx_stream_write_t*>(
        calloc(1, sizeof(udx_stream_write_t) + sizeof(udx_stream_write_buf_t)));
    udx_stream_write_end(wreq, &stream->raw_stream, nullptr, 0,
        [](udx_stream_write_t* req, int, int) { free(req); });
}

int hyperdht_stream_is_open(const hyperdht_stream_t* stream) {
    if (!stream) return 0;
    return stream->open ? 1 : 0;
}
