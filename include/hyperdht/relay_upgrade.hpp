#pragma once

// Relay → direct upgrade — the changeRemote state machine (JS PR #266 family).
//
// When a connection is established over a blind relay and a holepunch later
// lands, the SAME live UDX stream is migrated onto the direct socket via
// udx_stream_change_remote() — no new stream, no data loss. This header
// isolates the one genuinely tricky piece: the libudx change-remote contract
// (verified in deps/libudx/src/udx.c:2404-2459), whose return value encodes a
// three-way state that the caller MUST handle exactly, and whose same-udx_t
// precondition is a hard `assert` (abort), not a graceful error.
//
// See docs/RELAY-UPGRADE-PORT.md for the full design. The higher-level
// confirmDirectUpgrade orchestration (send a zero-length nudge, wait for
// direct-path arrival, then gracefully end the relay control stream) lives at
// the call site because it needs a per-stream context slot that the emitted
// stream's SecretStreamDuplex owns — see that doc's "Lifetime hazards".

#include <udx.h>

#include <netinet/in.h>

#include <cstdint>
#include <functional>
#include <memory>

namespace hyperdht {
namespace secret_stream { class SecretStreamDuplex; }
namespace relay_upgrade {

// Outcome of try_change_remote(), mapping the libudx return code + our
// preconditions onto the three states the caller must distinguish.
enum class UpgradeState {
    // udx returned 1: there were no unacked in-flight packets, so the switch
    // took effect immediately and the remote-changed callback will NEVER fire.
    // The caller must treat the migration as confirmed NOW and must not wait
    // on the callback (doc hazard 4).
    CONFIRMED_NOW,
    // udx returned 0: the switch is deferred until packets queued before it
    // drain to the old (relay) remote; `on_confirmed` fires from udx once the
    // peer acks a post-switch packet.
    DEFERRED,
    // Precondition failed, or udx returned a negative error (stream dead, port
    // 0, racing teardown). Do NOT migrate — keep running on the relay path
    // (doc hazard 6). Never fatal.
    STAY_ON_RELAY,
};

// Safe wrapper over udx_stream_change_remote().
//
// Validates every precondition BEFORE calling — in particular the
// same-udx_t invariant (`socket->udx == stream->socket->udx`), which
// udx_stream_change_remote asserts on and would otherwise abort the process
// (doc hazard 5). All our sockets live on one udx_t per DHT, but a racing
// teardown or a mis-plumbed socket must degrade to STAY_ON_RELAY, not crash.
//
//   stream       the live data stream currently on the relay path (CONNECTED)
//   direct_sock  the socket that received the direct (punched) packet
//   remote_id    the peer's UDX stream id (from the handshake udx payload)
//   addr         the peer's direct address (sockaddr_in / _in6, port != 0)
//   on_confirmed captureless udx callback for the DEFERRED case; ignored for
//                CONFIRMED_NOW (never invoked). May be nullptr.
UpgradeState try_change_remote(udx_stream_t* stream, udx_socket_t* direct_sock, uint32_t remote_id,
                               const struct sockaddr* addr,
                               udx_stream_remote_changed_cb on_confirmed);

// ---------------------------------------------------------------------------
// RelayOwner — explicit owner of the relay control connection (doc hazard 2).
//
// After the connection is emitted over a blind relay, nothing in the DHT
// layer owns the relay control connection any more (it survived via an
// accidental ref cycle in cpp / a one-shot lambda on the server). The
// UpgradeContext takes explicit ownership via this type-erased holder: the
// caller packs the relay duplex + mux + blind-relay client + keepalive +
// timeout into `refs` and supplies the two teardown actions.
//
//   close    graceful shutdown after a CONFIRMED direct upgrade — JS
//            closeRelayConnection: `.end()` the relay control stream so the
//            relay node learns we're done. `refs` are kept (the FIN flushes)
//            until the UpgradeContext dies.
//   destroy  hard teardown for stream death / pair error / 15s timeout — JS
//            destroyRelayConnection: `.destroy()` + drop refs.
struct RelayOwner {
    std::shared_ptr<void> refs;      // keeps duplex/mux/client/timeout alive
    std::function<void()>  close;    // graceful end (post-confirmation)
    std::function<void()>  destroy;  // hard teardown
};

// ---------------------------------------------------------------------------
// UpgradeContext — owns the relay control connection past emit and drives the
// confirmDirectUpgrade state machine (JS PR #266). Shared by client + server.
//
// Attached to the emitted stream's SecretStreamDuplex (see
// SecretStreamDuplex::attach_upgrade) so the firewall / remote-changed /
// raw-activity taps can reach it via stream->data → Duplex → context. Held by
// BOTH the Duplex (stream lifetime) and the DHT connect/handshake state (until
// the puncher resolves) so it outlives whichever party dies first.
//
// One-shot: a single relay→direct migration, matching JS onsocket
// (`rawStream = null`). Mid-connection NAT remaps are out of scope (JS doesn't
// handle them either — see the doc).
// ---------------------------------------------------------------------------
class UpgradeContext {
public:
    // emitted_stream  the live app stream currently on the relay path
    // remote_udx_id   the peer's UDX stream id (from the handshake payload)
    // relay_socket    the local socket the relay control connection uses —
    //                 used to distinguish relay stragglers from direct packets
    UpgradeContext(udx_stream_t* emitted_stream, uint32_t remote_udx_id,
                   udx_socket_t* relay_socket);
    ~UpgradeContext();

    UpgradeContext(const UpgradeContext&) = delete;
    UpgradeContext& operator=(const UpgradeContext&) = delete;

    // Install the relay control connection owner (doc hazard 2). Call once,
    // before attaching to the Duplex.
    void set_relay_owner(RelayOwner owner) { relay_ = std::move(owner); }

    // Take over the punched pool socket's keepalive (doc hazard 3) so the
    // direct socket stays pinned for the emitted stream's whole life.
    void set_socket_keepalive(std::shared_ptr<void> ka) {
        socket_keepalive_ = std::move(ka);
    }

    // JS onsocket — one-shot upgrade trigger. Called from the punch-success
    // path (both sides) and from the firewall tap when a direct-source packet
    // arrives before the puncher notices. `direct_sock` is OUR local socket
    // owning the direct path; `addr` is the peer's direct address.
    void on_socket(udx_socket_t* direct_sock, const struct sockaddr* addr);

    // Duplex taps (see SecretStreamDuplex::attach_upgrade).
    void on_firewall(udx_socket_t* sock, const struct sockaddr* from);
    void on_raw_activity();    // the doc's `ondirect`
    void on_stream_closed();   // liveness gate (doc hazards 5/8)

    // Test / observability hooks.
    bool is_relay_closed() const { return relay_closed_; }
    bool is_upgraded()     const { return upgraded_; }
    bool is_valid_upgrade() const { return valid_upgrade_; }

private:
    void confirm_direct_upgrade(UpgradeState st);
    void arm_confirmation();
    void send_nudge();
    void close_relay_connection();
    static void on_remote_changed(udx_stream_t* s);

    udx_stream_t* stream_;            // emitted stream; nulled on close
    uint32_t      remote_id_;
    udx_socket_t* relay_socket_;
    udx_socket_t* direct_socket_ = nullptr;
    bool valid_upgrade_   = true;    // #266 flag
    bool upgraded_        = false;   // one-shot onsocket guard
    bool awaiting_direct_ = false;   // confirmDirectUpgrade armed
    bool relay_closed_    = false;
    bool alive_           = true;    // false after on_stream_closed()
    RelayOwner relay_;
    std::shared_ptr<void> socket_keepalive_;
};

// Attach an UpgradeContext (carried as an opaque std::shared_ptr<void> on
// ConnectResult / ConnectionInfo) to the emitted stream's Duplex. Wires the
// three taps so the migration can drive. Call BEFORE duplex.start(). No-op if
// `ctx` is null — a consumer that ignores the handle simply gets no upgrade
// (graceful degradation to the pre-#266 relay behaviour, never a UAF).
void attach_to_duplex(secret_stream::SecretStreamDuplex& duplex,
                      std::shared_ptr<void> ctx);

}  // namespace relay_upgrade
}  // namespace hyperdht
