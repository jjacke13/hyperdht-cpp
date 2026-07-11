// Relay → direct upgrade — changeRemote state machine. See relay_upgrade.hpp.

#include "hyperdht/relay_upgrade.hpp"

#include <netinet/in.h>

#include <cstring>

#include "hyperdht/secret_stream.hpp"  // reach ctx via stream->data → Duplex

namespace hyperdht {
namespace relay_upgrade {

// UDX_STREAM_DEAD is private to udx.c (== DESTROYING | CLOSED). Reconstruct it
// from the public flags so we can reject a racing-teardown stream before it
// reaches udx (which would return UV_EINVAL anyway, but being explicit lets us
// also skip the same-udx dereference below on a half-torn-down stream).
static constexpr int STREAM_DEAD = UDX_STREAM_DESTROYING | UDX_STREAM_CLOSED;

UpgradeState try_change_remote(udx_stream_t* stream, udx_socket_t* direct_sock, uint32_t remote_id,
                               const struct sockaddr* addr,
                               udx_stream_remote_changed_cb on_confirmed) {
    if (!stream || !direct_sock || !addr)
        return UpgradeState::STAY_ON_RELAY;

    // The relay-upgrade caller always migrates a stream that is already
    // CONNECTED (to the relay). If it isn't connected, stream->socket may be
    // null and the same-udx check below would dereference null. The
    // not-yet-connected case is the fresh-connect branch (JS connect.js:469),
    // handled by the caller, not here.
    if (!(stream->status & UDX_STREAM_CONNECTED))
        return UpgradeState::STAY_ON_RELAY;
    if (stream->status & STREAM_DEAD)
        return UpgradeState::STAY_ON_RELAY;
    if (!stream->socket)
        return UpgradeState::STAY_ON_RELAY;

    // Hazard 5: udx_stream_change_remote asserts socket->udx == stream->socket->udx.
    // A cross-udx migration is a hard abort — validate first, never call.
    if (direct_sock->udx != stream->socket->udx)
        return UpgradeState::STAY_ON_RELAY;

    // Reject port 0 explicitly (udx also rejects with UV_EINVAL).
    if (addr->sa_family == AF_INET &&
        reinterpret_cast<const struct sockaddr_in*>(addr)->sin_port == 0) {
        return UpgradeState::STAY_ON_RELAY;
    }
    if (addr->sa_family == AF_INET6 &&
        reinterpret_cast<const struct sockaddr_in6*>(addr)->sin6_port == 0) {
        return UpgradeState::STAY_ON_RELAY;
    }

    int ret = udx_stream_change_remote(stream, direct_sock, remote_id, addr, on_confirmed);
    if (ret == 1)
        return UpgradeState::CONFIRMED_NOW;  // callback never fires
    if (ret == 0)
        return UpgradeState::DEFERRED;   // callback fires on ack
    return UpgradeState::STAY_ON_RELAY;  // negative → error
}

// ===========================================================================
// UpgradeContext — confirmDirectUpgrade orchestration (JS PR #266)
// ===========================================================================

UpgradeContext::UpgradeContext(udx_stream_t* emitted_stream, uint32_t remote_udx_id,
                               udx_socket_t* relay_socket)
    : stream_(emitted_stream), remote_id_(remote_udx_id), relay_socket_(relay_socket) {}

UpgradeContext::~UpgradeContext() {
    // Belt-and-suspenders: if we still own the relay control connection
    // (never upgraded, never saw the stream close), tear it down hard.
    if (!relay_closed_ && relay_.destroy) relay_.destroy();
}

// JS onsocket (connect.js:453-487 / server.js:305-342), the "relay won
// earlier" branch — in our topology the emitted stream is ALWAYS connected to
// the relay, so we only ever migrate (never fresh-connect). One-shot.
void UpgradeContext::on_socket(udx_socket_t* direct_sock, const struct sockaddr* addr) {
    if (!alive_ || upgraded_ || !stream_ || !direct_sock || !addr) return;
    upgraded_ = true;  // JS: rawStream = null

    direct_socket_ = direct_sock;

    UpgradeState st = try_change_remote(stream_, direct_sock, remote_id_, addr,
                                        &UpgradeContext::on_remote_changed);
    confirm_direct_upgrade(st);
}

// JS firewall callback (connect.js:124-137 / server.js:282-291).
void UpgradeContext::on_firewall(udx_socket_t* sock, const struct sockaddr* from) {
    if (!alive_) return;
    // isRelay: the packet arrived on the relay control socket. udx only fires
    // the firewall for a socket != the stream's current socket, so pre-
    // migration this never matches (the stream is ON the relay socket); post-
    // migration it flags a relay straggler → the upgrade is not yet provably
    // confirmed on the direct path (#266 relay straggler rule).
    if (sock == relay_socket_) {
        valid_upgrade_ = false;
        return;
    }
    // A direct-source packet. Pre-migration this IS the upgrade trigger (JS
    // firewall → onsocket); post-migration it just reaffirms validUpgrade.
    valid_upgrade_ = true;
    if (!upgraded_) on_socket(sock, from);
}

// JS confirmDirectUpgrade (connect.js:466-487): once the remote-changed
// completes (CONFIRMED_NOW immediately; DEFERRED on the udx callback), arm the
// ondirect wait and nudge the peer. STAY_ON_RELAY means the migration failed
// benignly — keep running on the relay, a supported steady state.
void UpgradeContext::confirm_direct_upgrade(UpgradeState st) {
    if (st == UpgradeState::CONFIRMED_NOW) arm_confirmation();
    // DEFERRED: on_remote_changed() → arm_confirmation() after in-flight drain.
    // STAY_ON_RELAY: nothing.
}

void UpgradeContext::arm_confirmation() {
    if (!alive_ || !stream_) return;
    awaiting_direct_ = true;
    valid_upgrade_ = true;
    send_nudge();
}

// Send ONE zero-length raw udx message. The peer's firewall sees a direct-
// source packet and migrates its end; empty secret-stream keepalive frames are
// swallowed when keepAlive != 0, so the nudge must be raw udx (doc / #266).
void UpgradeContext::send_nudge() {
    if (!stream_ || !(stream_->status & UDX_STREAM_CONNECTED)) return;
    auto* req = new udx_stream_send_t{};
    uint8_t dummy = 0;
    uv_buf_t buf = uv_buf_init(reinterpret_cast<char*>(&dummy), 0);
    int rc = udx_stream_send(req, stream_, &buf, 1,
        [](udx_stream_send_t* r, int /*status*/) { delete r; });
    if (rc < 0) delete req;
}

// JS ondirect (connect.js:474-486): any data/message arriving after we armed.
void UpgradeContext::on_raw_activity() {
    if (!alive_ || !awaiting_direct_ || relay_closed_) return;
    if (!valid_upgrade_) {
        // A relay straggler slipped in after we armed. Reset and wait for a
        // packet that provably arrived on the direct path (#266).
        valid_upgrade_ = true;
        return;
    }
    // Confirmed: traffic provably arrived on the direct path. Close the relay.
    awaiting_direct_ = false;
    close_relay_connection();
}

void UpgradeContext::on_stream_closed() {
    alive_ = false;
    stream_ = nullptr;  // hazard 8 — never touch the dead stream again
    if (!relay_closed_) {
        relay_closed_ = true;
        auto d = std::move(relay_.destroy);
        relay_.close = nullptr;
        relay_.destroy = nullptr;
        if (d) d();
        relay_.refs.reset();
    }
}

// JS closeRelayConnection (connect.js:489-495): graceful `.end()`; keep refs
// (the FIN flushes) until this context dies with the stream.
void UpgradeContext::close_relay_connection() {
    if (relay_closed_) return;
    relay_closed_ = true;
    if (relay_.close) {
        auto c = std::move(relay_.close);
        relay_.close = nullptr;
        c();
    }
    relay_.destroy = nullptr;  // graceful close supersedes hard teardown
}

// Captureless udx remote-changed callback (DEFERRED case). Reaches the context
// via stream->data → Duplex → upgrade_ctx(). Safe against a torn-down Duplex
// (data nulled) and a dead context (alive_ false).
void UpgradeContext::on_remote_changed(udx_stream_t* s) {
    if (!s) return;
    auto* duplex = static_cast<secret_stream::SecretStreamDuplex*>(s->data);
    if (!duplex) return;
    auto* ctx = static_cast<UpgradeContext*>(duplex->upgrade_ctx());
    if (!ctx || !ctx->alive_) return;
    ctx->arm_confirmation();
}

// ---------------------------------------------------------------------------
// attach_to_duplex — wire the three taps from an opaque context handle.
// ---------------------------------------------------------------------------

void attach_to_duplex(secret_stream::SecretStreamDuplex& duplex,
                      std::shared_ptr<void> ctx_void) {
    if (!ctx_void) return;
    auto* ctx = static_cast<UpgradeContext*>(ctx_void.get());
    duplex.attach_upgrade(
        ctx_void,  // keeps the context alive for the Duplex's lifetime
        [ctx]() { ctx->on_raw_activity(); },
        [ctx](udx_socket_t* s, const struct sockaddr* f) { ctx->on_firewall(s, f); },
        [ctx]() { ctx->on_stream_closed(); });
}

}  // namespace relay_upgrade
}  // namespace hyperdht
