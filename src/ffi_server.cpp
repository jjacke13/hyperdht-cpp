// FFI server: create, listen, firewall, close, state, config, relay, stats.
//
// Safety: hyperdht_firewall_done uses atomic<bool> to prevent double-call UAF.
// srv->server is nulled after close to prevent accidental re-use.
#include "ffi_internal.hpp"
#include <atomic>

// ---------------------------------------------------------------------------
// Server: create, listen, firewall, close, suspend, refresh
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
    sodium_memzero(cpp_kp.secret_key.data(), 64);  // C10

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
        srv->server = nullptr;  // M17: prevent accidental re-use
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
        srv->server = nullptr;  // M17
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
// Server state: suspend, resume, notify, listening, public_key, address
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Server config: holepunch, firewall_done, firewall_async
// ---------------------------------------------------------------------------

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
    std::atomic<bool> called{false};  // H15: prevent double-call UAF
};

void hyperdht_firewall_done(hyperdht_firewall_done_t* done, int reject) {
    if (!done) return;
    if (done->called.exchange(true)) return;  // H15: already invoked
    if (done->fn) {
        auto fn = std::move(done->fn);
        fn(reject != 0);
    }
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
// Relay, punch stats, ping
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
            dispatch_connect_result(cb, userdata, error, result, true);
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
