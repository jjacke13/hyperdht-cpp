// Isolation tests for the relay→direct changeRemote state machine
// (hyperdht::relay_upgrade). The full relay→direct upgrade is only observable
// live (cross-NAT), so these prove the one piece we CAN prove deterministically
// on loopback: the libudx change-remote contract + precondition guards, i.e.
// doc hazards 4 (ret==1 → callback never fires), 5 (same-udx assert avoided),
// and 6 (preconditions degrade to STAY_ON_RELAY, never crash).

#include <gtest/gtest.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "hyperdht/async_utils.hpp"
#include "hyperdht/blind_relay.hpp"
#include "hyperdht/dht.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/protomux.hpp"
#include "hyperdht/relay_upgrade.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/secret_stream.hpp"
#include "hyperdht/server.hpp"
#include "hyperdht/udx.hpp"

using namespace hyperdht::udx;
using hyperdht::relay_upgrade::try_change_remote;
using hyperdht::relay_upgrade::UpgradeState;
using hyperdht::relay_upgrade::UpgradeContext;
using hyperdht::relay_upgrade::RelayOwner;
using hyperdht::secret_stream::SecretStreamDuplex;
using hyperdht::secret_stream::DuplexHandshake;

static struct sockaddr_in loopback(uint16_t port) {
    struct sockaddr_in a{};
    uv_ip4_addr("127.0.0.1", port, &a);
    return a;
}
static struct sockaddr_in bound_of(UdxSocket& s) {
    struct sockaddr_in a{};
    int len = sizeof(a);
    s.getsockname(reinterpret_cast<struct sockaddr*>(&a), &len);
    return a;
}

// A freshly connected stream with no unacked in-flight packets: udx returns 1
// (acts now), so the migration is confirmed immediately and the remote-changed
// callback must NEVER fire. If the caller waited on that callback it would hang
// forever — doc hazard 4.
TEST(RelayUpgrade, FreshStreamConfirmsNowCallbackNeverFires) {
    uv_loop_t loop;
    uv_loop_init(&loop);
    Udx udx(&loop);

    UdxSocket relay(udx), direct(udx), peer(udx);
    auto a = loopback(0);
    ASSERT_EQ(relay.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);
    a = loopback(0);
    ASSERT_EQ(direct.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);
    a = loopback(0);
    ASSERT_EQ(peer.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);

    auto relay_bound = bound_of(relay);
    auto peer_bound = bound_of(peer);

    static int cb_fired = 0;
    cb_fired = 0;

    UdxStream stream(udx, 1, [](udx_stream_t*, int) {}, nullptr);
    // Connect to the "relay" socket first (simulating the relay path).
    ASSERT_EQ(stream.connect(relay, 2, reinterpret_cast<const struct sockaddr*>(&relay_bound)), 0);

    // Migrate onto the "direct" socket. No writes happened → no unacked
    // in-flight → udx acts now → CONFIRMED_NOW.
    auto st = try_change_remote(stream.handle(), direct.handle(), 2,
                                reinterpret_cast<const struct sockaddr*>(&peer_bound),
                                [](udx_stream_t*) { cb_fired++; });
    EXPECT_EQ(st, UpgradeState::CONFIRMED_NOW);

    // Pump the loop a few times — the deferred callback must never fire.
    for (int i = 0; i < 5; i++)
        uv_run(&loop, UV_RUN_NOWAIT);
    EXPECT_EQ(cb_fired, 0) << "remote-changed callback fired for a ret==1 migration";

    udx_stream_destroy(stream.handle());
    relay.close();
    direct.close();
    peer.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// The relay→direct migration is an ADOPTION: the client's direct nudge fires
// the firewall tap with the server session's punch socket, and changeRemote
// binds the live relayed stream to it. The session that owns that socket is
// reaped independently (punch_clear_wait), so the context must hold the socket
// itself — the same hazard the punched path solves with
// ConnectionInfo::socket_keepalive. Server::on_handshake_result hands it over
// at emit (`upgrade->set_socket_keepalive(conn->punch_socket)`); this proves
// the holding half survives both the owner drop and the migration.
TEST(RelayUpgradeContext, SocketKeepaliveHoldsTheMigrationTarget) {
    uv_loop_t loop;
    uv_loop_init(&loop);
    Udx udx(&loop);

    UdxSocket relay(udx);
    auto a = loopback(0);
    ASSERT_EQ(relay.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);

    // The session's punch socket, owned by a shared_ptr exactly as
    // ServerConnection owns it.
    auto punch = std::make_shared<hyperdht::holepunch::PoolSocket>(
        &loop, udx.handle());
    ASSERT_EQ(punch->bind(), 0);
    std::weak_ptr<hyperdht::holepunch::PoolSocket> weak = punch;
    auto* punch_handle = punch->socket_handle();
    struct sockaddr_in punch_addr{};
    int len = sizeof(punch_addr);
    udx_socket_getsockname(punch_handle,
                           reinterpret_cast<struct sockaddr*>(&punch_addr), &len);

    UdxStream stream(udx, 1, [](udx_stream_t*, int) {}, nullptr);
    auto relay_bound = bound_of(relay);
    ASSERT_EQ(stream.connect(relay, 2,
                             reinterpret_cast<const struct sockaddr*>(&relay_bound)),
              0);

    auto ctx = std::make_shared<UpgradeContext>(stream.handle(), 2,
                                                relay.handle());
    ctx->set_socket_keepalive(punch);

    punch.reset();  // the session is reaped by the clear-wait backstop
    ASSERT_FALSE(weak.expired()) << "upgrade context did not hold the socket";

    // The client's direct nudge arrives on the punch socket.
    ctx->on_firewall(punch_handle,
                     reinterpret_cast<const struct sockaddr*>(&punch_addr));
    EXPECT_TRUE(ctx->is_upgraded());
    EXPECT_FALSE(weak.expired())
        << "migration target freed under the stream it now carries";

    udx_stream_destroy(stream.handle());
    uv_run(&loop, UV_RUN_NOWAIT);
    ctx.reset();  // the emitted stream is finally gone
    EXPECT_TRUE(weak.expired());

    relay.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// A stream that was never connected: stream->socket is null. try_change_remote
// must NOT touch udx (which would dereference null / hit the same-udx assert) —
// it degrades to STAY_ON_RELAY. Doc hazard 6.
TEST(RelayUpgrade, UnconnectedStreamStaysOnRelay) {
    uv_loop_t loop;
    uv_loop_init(&loop);
    Udx udx(&loop);

    UdxSocket direct(udx), peer(udx);
    auto a = loopback(0);
    ASSERT_EQ(direct.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);
    a = loopback(0);
    ASSERT_EQ(peer.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);
    auto peer_bound = bound_of(peer);

    UdxStream stream(udx, 7, [](udx_stream_t*, int) {}, nullptr);
    // Deliberately NOT connected.
    auto st = try_change_remote(stream.handle(), direct.handle(), 2,
                                reinterpret_cast<const struct sockaddr*>(&peer_bound), nullptr);
    EXPECT_EQ(st, UpgradeState::STAY_ON_RELAY);

    udx_stream_destroy(stream.handle());
    direct.close();
    peer.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// Migrating onto a socket that lives on a DIFFERENT udx_t is a hard abort
// inside udx_stream_change_remote (`assert(socket->udx == stream->socket->udx)`).
// try_change_remote must catch this BEFORE calling and degrade — doc hazard 5.
TEST(RelayUpgrade, CrossUdxStaysOnRelayNoAbort) {
    uv_loop_t loop;
    uv_loop_init(&loop);
    Udx udx_a(&loop);
    Udx udx_b(&loop);  // separate udx_t — its sockets must be rejected

    UdxSocket relay(udx_a), peer(udx_a);
    UdxSocket other(udx_b);
    auto a = loopback(0);
    ASSERT_EQ(relay.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);
    a = loopback(0);
    ASSERT_EQ(peer.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);
    a = loopback(0);
    ASSERT_EQ(other.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);

    auto relay_bound = bound_of(relay);
    auto peer_bound = bound_of(peer);

    UdxStream stream(udx_a, 1, [](udx_stream_t*, int) {}, nullptr);
    ASSERT_EQ(stream.connect(relay, 2, reinterpret_cast<const struct sockaddr*>(&relay_bound)), 0);

    // `other` is on udx_b — must be rejected without calling udx (no abort).
    auto st = try_change_remote(stream.handle(), other.handle(), 2,
                                reinterpret_cast<const struct sockaddr*>(&peer_bound), nullptr);
    EXPECT_EQ(st, UpgradeState::STAY_ON_RELAY);

    udx_stream_destroy(stream.handle());
    relay.close();
    peer.close();
    other.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// Port 0 is invalid for a remote address — degrade to STAY_ON_RELAY.
TEST(RelayUpgrade, ZeroPortStaysOnRelay) {
    uv_loop_t loop;
    uv_loop_init(&loop);
    Udx udx(&loop);

    UdxSocket relay(udx), direct(udx);
    auto a = loopback(0);
    ASSERT_EQ(relay.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);
    a = loopback(0);
    ASSERT_EQ(direct.bind(reinterpret_cast<const struct sockaddr*>(&a)), 0);
    auto relay_bound = bound_of(relay);

    UdxStream stream(udx, 1, [](udx_stream_t*, int) {}, nullptr);
    ASSERT_EQ(stream.connect(relay, 2, reinterpret_cast<const struct sockaddr*>(&relay_bound)), 0);

    auto zero = loopback(0);  // port 0
    auto st = try_change_remote(stream.handle(), direct.handle(), 2,
                                reinterpret_cast<const struct sockaddr*>(&zero), nullptr);
    EXPECT_EQ(st, UpgradeState::STAY_ON_RELAY);

    udx_stream_destroy(stream.handle());
    relay.close();
    direct.close();
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

// Null arguments must never crash.
TEST(RelayUpgrade, NullArgsStayOnRelay) {
    auto addr = loopback(1234);
    EXPECT_EQ(try_change_remote(nullptr, nullptr, 0,
                                reinterpret_cast<const struct sockaddr*>(&addr), nullptr),
              UpgradeState::STAY_ON_RELAY);
}

// ============================================================================
// UpgradeContext — confirmDirectUpgrade orchestration, full choreography and
// lifecycle, on a single udx_t / loop. Two socket pairs: pair 1 stands in for
// the relay path (the migration mechanics don't need a real blind-relay node),
// pair 2 is the "direct" (punched) path.
// ============================================================================

namespace ru_choreo {

// Full noise handshake → two DuplexHandshake structs (mirrors the helper in
// test_secret_stream.cpp; duplicated to keep the files independent).
static std::pair<DuplexHandshake, DuplexHandshake> make_hs_pair() {
    using namespace hyperdht::noise;
    Seed is{}, rs{};
    is.fill(0x51);
    rs.fill(0x52);
    auto ikp = generate_keypair(is);
    auto rkp = generate_keypair(rs);
    uint8_t prologue[] = {0x00};
    NoiseIK initiator(true, ikp, prologue, 1, &rkp.public_key);
    NoiseIK responder(false, rkp, prologue, 1, nullptr);
    auto m1 = initiator.send();
    responder.recv(m1.data(), m1.size());
    auto m2 = responder.send();
    initiator.recv(m2.data(), m2.size());

    DuplexHandshake ih{}, rh{};
    ih.tx_key = initiator.tx_key();  ih.rx_key = initiator.rx_key();
    ih.handshake_hash = initiator.handshake_hash();
    ih.public_key = ikp.public_key;  ih.remote_public_key = rkp.public_key;
    ih.is_initiator = true;
    rh.tx_key = responder.tx_key();  rh.rx_key = responder.rx_key();
    rh.handshake_hash = responder.handshake_hash();
    rh.public_key = rkp.public_key;  rh.remote_public_key = ikp.public_key;
    rh.is_initiator = false;
    return {ih, rh};
}

// Owns 4 sockets (relay pair + direct pair) + 2 app streams on one udx/loop.
struct Fixture {
    uv_loop_t loop;
    udx_t udx;
    udx_socket_t relayA, relayB, directA, directB;
    udx_stream_t streamA, streamB;   // A local id 1, B local id 2

    Fixture() {
        uv_loop_init(&loop);
        udx_init(&loop, &udx, nullptr);
        for (auto* s : {&relayA, &relayB, &directA, &directB})
            udx_socket_init(&udx, s, nullptr);
        struct sockaddr_in a{};
        uv_ip4_addr("127.0.0.1", 0, &a);
        for (auto* s : {&relayA, &relayB, &directA, &directB})
            udx_socket_bind(s, reinterpret_cast<const struct sockaddr*>(&a), 0);

        udx_stream_init(&udx, &streamA, 1, nullptr, nullptr);
        udx_stream_init(&udx, &streamB, 2, nullptr, nullptr);

        // Connect the app streams over the RELAY pair (relayA <-> relayB).
        auto ba = bound(relayA), bb = bound(relayB);
        udx_stream_connect(&streamA, &relayA, 2,
                           reinterpret_cast<const struct sockaddr*>(&bb));
        udx_stream_connect(&streamB, &relayB, 1,
                           reinterpret_cast<const struct sockaddr*>(&ba));
    }

    static struct sockaddr_in bound(udx_socket_t& s) {
        struct sockaddr_in a{};
        int len = sizeof(a);
        udx_socket_getsockname(&s, reinterpret_cast<struct sockaddr*>(&a), &len);
        return a;
    }

    ~Fixture() {
        for (auto* s : {&relayA, &relayB, &directA, &directB})
            udx_socket_close(s);
        uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop);
    }
};

// Bounded event-loop pump: run until `done` or a hard time cap. A repeating
// 2 ms timer polls the predicate and uv_stop()s the loop — UV_RUN_DEFAULT would
// otherwise never return because the udx sockets keep the loop alive forever.
static void pump_until(uv_loop_t* loop, std::function<bool()> done,
                       int max_ms = 4000) {
    struct Ctx { std::function<bool()> done; int elapsed; int max_ms; };
    auto* tick = new uv_timer_t;
    uv_timer_init(loop, tick);
    tick->data = new Ctx{std::move(done), 0, max_ms};
    uv_timer_start(tick, [](uv_timer_t* t) {
        auto* c = static_cast<Ctx*>(t->data);
        c->elapsed += 2;
        if (c->done() || c->elapsed >= c->max_ms) uv_stop(t->loop);
    }, 0, 2);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_timer_stop(tick);
    uv_close(reinterpret_cast<uv_handle_t*>(tick), [](uv_handle_t* h) {
        delete static_cast<Ctx*>(h->data);
        delete reinterpret_cast<uv_timer_t*>(h);
    });
    uv_run(loop, UV_RUN_NOWAIT);
}

}  // namespace ru_choreo

// (3)+(1) Full choreography: both peers upgrade, the zero-length nudge crosses,
// ondirect fires, and the relay stand-in refs are released ONLY after direct-
// arrival confirmation — plus app data continues to flow on the direct path.
TEST(RelayUpgradeContext, FullChoreographyReleasesRelayOnlyAfterConfirm) {
    using namespace ru_choreo;
    Fixture fx;
    auto [ih, rh] = make_hs_pair();

    SecretStreamDuplex da(&fx.streamA, ih, &fx.loop);
    SecretStreamDuplex db(&fx.streamB, rh, &fx.loop);

    auto ca = std::make_shared<UpgradeContext>(&fx.streamA, 2, &fx.relayA);
    auto cb = std::make_shared<UpgradeContext>(&fx.streamB, 1, &fx.relayB);

    bool relayA_closed = false, relayB_closed = false;
    {
        RelayOwner oa;
        oa.close   = [&] { relayA_closed = true; };
        oa.destroy = [&] { relayA_closed = true; };
        ca->set_relay_owner(std::move(oa));
        RelayOwner ob;
        ob.close   = [&] { relayB_closed = true; };
        ob.destroy = [&] { relayB_closed = true; };
        cb->set_relay_owner(std::move(ob));
    }

    da.attach_upgrade(ca,
        [c = ca.get()] { c->on_raw_activity(); },
        [c = ca.get()](udx_socket_t* s, const struct sockaddr* f) { c->on_firewall(s, f); },
        [c = ca.get()] { c->on_stream_closed(); });
    db.attach_upgrade(cb,
        [c = cb.get()] { c->on_raw_activity(); },
        [c = cb.get()](udx_socket_t* s, const struct sockaddr* f) { c->on_firewall(s, f); },
        [c = cb.get()] { c->on_stream_closed(); });

    std::string b_recv;
    db.on_message([&](const uint8_t* d, size_t n) {
        b_recv.assign(reinterpret_cast<const char*>(d), n);
    });

    da.start();
    db.start();

    // Drive to connected, then trigger the punch-success upgrade on A once.
    bool migrated = false;
    bool not_closed_at_migrate = false;
    auto directB_addr = Fixture::bound(fx.directB);
    uv_idle_t idle;
    uv_idle_init(&fx.loop, &idle);
    struct IdleCtx {
        SecretStreamDuplex* da; SecretStreamDuplex* db;
        UpgradeContext* ca; udx_socket_t* directA;
        struct sockaddr_in* directB_addr;
        bool* migrated; bool* not_closed; bool* rA;
    } ic{&da, &db, ca.get(), &fx.directA, &directB_addr,
         &migrated, &not_closed_at_migrate, &relayA_closed};
    idle.data = &ic;
    uv_idle_start(&idle, [](uv_idle_t* h) {
        auto* c = static_cast<IdleCtx*>(h->data);
        if (*c->migrated) return;
        if (!c->da->is_connected() || !c->db->is_connected()) return;
        *c->migrated = true;
        // Simulate the punch landing on A: onsocket(directA, peer's direct addr).
        c->ca->on_socket(c->directA,
                         reinterpret_cast<const struct sockaddr*>(c->directB_addr));
        // #266 rule: the relay must NOT be released synchronously at migrate —
        // only after the peer's direct traffic confirms arrival.
        *c->not_closed = !*c->rA;
        uv_idle_stop(h);
        uv_close(reinterpret_cast<uv_handle_t*>(h), nullptr);
    });

    pump_until(&fx.loop, [&] { return relayA_closed && relayB_closed; });

    EXPECT_TRUE(migrated) << "streams never reached connected";
    EXPECT_TRUE(not_closed_at_migrate)
        << "relay released at migrate — must wait for direct-path confirmation";
    EXPECT_TRUE(relayA_closed) << "A relay not released after confirmation";
    EXPECT_TRUE(relayB_closed) << "B relay not released after confirmation";
    EXPECT_TRUE(ca->is_relay_closed());
    EXPECT_TRUE(cb->is_relay_closed());

    // Data continues on the direct path (streamA now on directA, streamB on directB).
    const char* msg = "direct-path-data";
    da.write(reinterpret_cast<const uint8_t*>(msg), 16, nullptr);
    pump_until(&fx.loop, [&] { return !b_recv.empty(); });
    EXPECT_EQ(b_recv, "direct-path-data")
        << "app data did not survive the relay→direct migration";

    da.destroy();
    db.destroy();
    pump_until(&fx.loop, [] { return false; }, 200);
}

// (4) Punch-fail steady state: onsocket never fires → the relay owner is never
// released and stays pinned. When the stream finally closes, the relay is torn
// down via the hard-destroy path (never the graceful close).
TEST(RelayUpgradeContext, PunchFailKeepsRelayUntilStreamClose) {
    using namespace ru_choreo;
    Fixture fx;
    auto [ih, rh] = make_hs_pair();

    SecretStreamDuplex da(&fx.streamA, ih, &fx.loop);
    SecretStreamDuplex db(&fx.streamB, rh, &fx.loop);
    auto ca = std::make_shared<UpgradeContext>(&fx.streamA, 2, &fx.relayA);

    bool graceful = false, hard = false;
    RelayOwner oa;
    oa.refs    = std::make_shared<int>(7);   // stand-in for the relay refs
    oa.close   = [&] { graceful = true; };
    oa.destroy = [&] { hard = true; };
    ca->set_relay_owner(std::move(oa));

    da.attach_upgrade(ca,
        [c = ca.get()] { c->on_raw_activity(); },
        [c = ca.get()](udx_socket_t* s, const struct sockaddr* f) { c->on_firewall(s, f); },
        [c = ca.get()] { c->on_stream_closed(); });

    da.start();
    db.start();
    pump_until(&fx.loop, [&] { return da.is_connected() && db.is_connected(); });

    // No punch → no onsocket. Relay owner must remain held.
    EXPECT_FALSE(graceful);
    EXPECT_FALSE(hard);
    EXPECT_FALSE(ca->is_relay_closed());
    EXPECT_FALSE(ca->is_upgraded());

    // Stream dies (user closes) → relay torn down via destroy, not close.
    da.destroy();
    pump_until(&fx.loop, [&] { return hard; }, 500);
    EXPECT_TRUE(hard) << "relay owner not destroyed on stream close";
    EXPECT_FALSE(graceful) << "punch-fail path must not graceful-close the relay";

    db.destroy();
    pump_until(&fx.loop, [] { return false; }, 200);
}

// (5) Mid-window destroy race: the user destroys the emitted stream mid-upgrade
// (after onsocket armed the migration, before confirmation). The close tap must
// release the context so every later async hop degrades to a no-op — no crash,
// no touch of the dead stream.
TEST(RelayUpgradeContext, MidWindowStreamDestroyNoCrash) {
    using namespace ru_choreo;
    Fixture fx;
    auto [ih, rh] = make_hs_pair();

    SecretStreamDuplex da(&fx.streamA, ih, &fx.loop);
    SecretStreamDuplex db(&fx.streamB, rh, &fx.loop);
    auto ca = std::make_shared<UpgradeContext>(&fx.streamA, 2, &fx.relayA);

    bool torn = false;
    RelayOwner oa;
    oa.close   = [&] { torn = true; };
    oa.destroy = [&] { torn = true; };
    ca->set_relay_owner(std::move(oa));

    da.attach_upgrade(ca,
        [c = ca.get()] { c->on_raw_activity(); },
        [c = ca.get()](udx_socket_t* s, const struct sockaddr* f) { c->on_firewall(s, f); },
        [c = ca.get()] { c->on_stream_closed(); });

    da.start();
    db.start();
    pump_until(&fx.loop, [&] { return da.is_connected() && db.is_connected(); });

    // Arm the migration...
    auto directB_addr = Fixture::bound(fx.directB);
    ca->on_socket(&fx.directA,
                  reinterpret_cast<const struct sockaddr*>(&directB_addr));
    EXPECT_TRUE(ca->is_upgraded());

    // ...then destroy the stream mid-window. The close tap fires on_stream_closed.
    da.destroy();
    EXPECT_TRUE(torn) << "close tap did not release the relay owner";

    // Late async hops must all be no-ops now (context marked dead, stream nulled).
    ca->on_raw_activity();
    ca->on_firewall(&fx.directA, reinterpret_cast<const struct sockaddr*>(&directB_addr));
    ca->on_socket(&fx.directA, reinterpret_cast<const struct sockaddr*>(&directB_addr));

    pump_until(&fx.loop, [] { return false; }, 300);  // drain — must not crash
    db.destroy();
    pump_until(&fx.loop, [] { return false; }, 200);
    SUCCEED();
}

// (2) DEFERRED confirmation: a burst is written WITHOUT draining the loop so
// there are unacked packets in flight; try_change_remote returns 0 (deferred)
// and the confirmation arms only after the remote-changed callback fires.
TEST(RelayUpgradeContext, DeferredConfirmArmsAfterDrain) {
    using namespace ru_choreo;
    Fixture fx;
    auto [ih, rh] = make_hs_pair();

    // Keepalive on both ends (the "second half of #266"): after migration the
    // burst's acks straggle in on the relay socket and (correctly) reset
    // validUpgrade; the inherited keepalive supplies the continuous direct-path
    // traffic that re-confirms the upgrade. Without keepalive a single straggler
    // could leave the connection un-confirmed forever — which is exactly why the
    // relayed emitted stream must inherit connectionKeepAlive.
    hyperdht::secret_stream::DuplexOptions dopts;
    dopts.keep_alive_ms = 50;
    SecretStreamDuplex da(&fx.streamA, ih, &fx.loop, dopts);
    SecretStreamDuplex db(&fx.streamB, rh, &fx.loop, dopts);
    auto ca = std::make_shared<UpgradeContext>(&fx.streamA, 2, &fx.relayA);
    auto cb = std::make_shared<UpgradeContext>(&fx.streamB, 1, &fx.relayB);

    bool relayA_closed = false, relayB_closed = false;
    RelayOwner oa; oa.close = [&] { relayA_closed = true; }; oa.destroy = [&] { relayA_closed = true; };
    ca->set_relay_owner(std::move(oa));
    RelayOwner ob; ob.close = [&] { relayB_closed = true; }; ob.destroy = [&] { relayB_closed = true; };
    cb->set_relay_owner(std::move(ob));

    da.attach_upgrade(ca,
        [c = ca.get()] { c->on_raw_activity(); },
        [c = ca.get()](udx_socket_t* s, const struct sockaddr* f) { c->on_firewall(s, f); },
        [c = ca.get()] { c->on_stream_closed(); });
    db.attach_upgrade(cb,
        [c = cb.get()] { c->on_raw_activity(); },
        [c = cb.get()](udx_socket_t* s, const struct sockaddr* f) { c->on_firewall(s, f); },
        [c = cb.get()] { c->on_stream_closed(); });

    da.start();
    db.start();
    pump_until(&fx.loop, [&] { return da.is_connected() && db.is_connected(); });

    // Write a large-ish burst then migrate IMMEDIATELY (same tick) so packets
    // are still unacked in flight → change_remote defers.
    std::vector<uint8_t> big(4096, 0xAB);
    da.write(big.data(), big.size(), nullptr);
    auto directB_addr = Fixture::bound(fx.directB);
    ca->on_socket(&fx.directA,
                  reinterpret_cast<const struct sockaddr*>(&directB_addr));
    EXPECT_TRUE(ca->is_upgraded());

    // The deferred remote-changed callback fires after the in-flight burst
    // drains; the choreography then completes and both relays release.
    pump_until(&fx.loop, [&] { return relayA_closed && relayB_closed; });
    EXPECT_TRUE(relayA_closed);
    EXPECT_TRUE(relayB_closed);

    da.destroy();
    db.destroy();
    pump_until(&fx.loop, [] { return false; }, 200);
}

// ===========================================================================
// Server relay emit — the wiring that FILLS the socket keepalive
// (src/server.cpp:1138). RelayUpgradeContext.SocketKeepaliveHoldsTheMigration-
// Target above proves UpgradeContext's holding half; deleting the server call
// site left it, and the whole suite, green.
//
// Everything below the client's PEER_HANDSHAKE is real server code: the
// session's punch socket, dht_->connect() to the relay peer, the SecretStream
// + Protomux + blind-relay chain, the pairing-success emit that builds the
// UpgradeContext, and the clear-wait backstop that reaps the session while the
// relayed stream lives on. Only the relay PEER is faked.
//
// ONE DEVIATION, forced by a live bug (reported, not fixed here): this server
// never actually puts its pair request on the wire. Both relay chains write
// the Protomux OPEN in the same frame as `duplex->start()`, where
// SecretStreamDuplex::write refuses everything until the header exchange
// completes (secret_stream.cpp:577 → rc -2), then call BlindRelayClient::pair()
// before the channel is open, where Channel::send refuses too
// (protomux.cpp:264). JS has neither guard: NoiseSecretStream is a Duplex that
// buffers pre-handshake writes, and protomux `send()` only checks `closed`
// (protomux/index.js:253-255) because the RECEIVER buffers messages for a
// not-yet-opened channel — which our Mux also implements. So the fake relay
// opens its channel and sends the pair reply unprompted: exactly the bytes a
// relay would have sent had the request arrived, leaving everything from
// `on_paired` onwards — the code under test — untouched.
// ===========================================================================

namespace ru_relay_emit {

using hyperdht::compact::Ipv4Address;
namespace bl = hyperdht::blind_relay;
namespace pc = hyperdht::peer_connect;
namespace msgs = hyperdht::messages;

constexpr uint32_t EP_UDX_ID = 4242;   // the relay endpoint's UDX stream id
constexpr uint32_t PAIRED_ID = 77;     // the id the relay assigns to us

// Bound-but-silent loopback sockets, seeded into the routing table. An EMPTY
// table makes the query engine (dht_ops.cpp:32-38) and the pool NAT discovery
// (holepunch.cpp:1345) fall back to the three PUBLIC bootstrap nodes — a unit
// test must never reach them. 7 = discover's MAX_TARGETS, so the fallback
// branch is never entered.
struct SilentNodes {
    static constexpr size_t COUNT = 7;

    explicit SilentNodes(uv_loop_t* loop) {
        for (size_t i = 0; i < COUNT; i++) {
            auto* h = new uv_udp_t;
            uv_udp_init(loop, h);
            auto a = loopback(0);
            uv_udp_bind(h, reinterpret_cast<const struct sockaddr*>(&a), 0);
            int len = sizeof(a);
            uv_udp_getsockname(h, reinterpret_cast<struct sockaddr*>(&a), &len);
            ports_.push_back(ntohs(a.sin_port));
            handles_.push_back(h);
        }
    }

    ~SilentNodes() {
        for (auto* h : handles_) {
            uv_close(reinterpret_cast<uv_handle_t*>(h),
                     [](uv_handle_t* x) { delete reinterpret_cast<uv_udp_t*>(x); });
        }
    }

    void seed(hyperdht::HyperDHT& dht) const {
        for (auto p : ports_) {
            dht.add_node(Ipv4Address::from_string("127.0.0.1", p));
        }
    }

  private:
    std::vector<uv_udp_t*> handles_;
    std::vector<uint16_t> ports_;
};

// The relay peer, whole: a DHT node that completes the PEER_HANDSHAKE for the
// relay keypair, plus the UDX endpoint behind it speaking SecretStream →
// Protomux → blind-relay.
struct FakeRelayPeer {
    FakeRelayPeer(uv_loop_t* loop, const hyperdht::noise::Keypair& kp,
                  const bl::Token& token)
        : loop_(loop), kp_(kp), token_(token),
          node_(loop, node_id()), udx_(loop), ep_(udx_) {
        node_.bind(0);
        auto a = loopback(0);
        ep_.bind(reinterpret_cast<const struct sockaddr*>(&a));
        ep_.recv_start([](udx_socket_t*, ssize_t, const uv_buf_t*,
                          const struct sockaddr*) {});
        node_.on_request([this](const msgs::Request& req) { on_request(req); });
    }

    ~FakeRelayPeer() {
        if (duplex_) duplex_->destroy(0);   // destroys stream_ too
        uv_run(loop_, UV_RUN_NOWAIT);
        mux_.reset();
        duplex_.reset();
        start_timer_.reset();
        node_.close();
        ep_.close();
    }

    Ipv4Address node_addr() {
        return Ipv4Address::from_string("127.0.0.1", node_.port());
    }
    Ipv4Address ep_addr() {
        struct sockaddr_in a{};
        int len = sizeof(a);
        ep_.getsockname(reinterpret_cast<struct sockaddr*>(&a), &len);
        return Ipv4Address::from_string("127.0.0.1", ntohs(a.sin_port));
    }

  private:
    static hyperdht::routing::NodeId node_id() {
        hyperdht::routing::NodeId id{};
        id.fill(0x0b);
        return id;
    }

    void on_request(const msgs::Request& req) {
        if (req.internal && req.command == msgs::CMD_PING) {
            msgs::Response resp;
            resp.tid = req.tid;
            resp.from.addr = req.from.addr;
            node_.reply(resp, req.from_server);
            return;
        }
        if (req.command != msgs::CMD_PEER_HANDSHAKE || !req.value) return;

        auto hs = pc::decode_handshake_msg(req.value->data(), req.value->size());
        const auto& prol = hyperdht::dht_messages::ns_peer_handshake();
        hyperdht::noise::NoiseIK responder(false, kp_, prol.data(), prol.size());
        auto p1 = responder.recv(hs.noise.data(), hs.noise.size());
        if (!p1) { ADD_FAILURE() << "relay peer could not read msg1"; return; }
        auto cp = pc::decode_noise_payload(p1->data(), p1->size());
        peer_udx_id_ = cp.udx.has_value() ? cp.udx->id : 0;
        peer_addr_ = req.from.addr;

        // CONSISTENT + holepunch info keeps every early-completion branch in
        // on_handshake_success shut (direct connect / no-holepunch-info), so
        // the connect can only finish through the rawStream firewall — the one
        // path that fills ConnectResult::udx_socket, which the relay chain
        // needs to connect its control stream.
        pc::NoisePayload rp;
        rp.version = 1;
        rp.error = pc::ERROR_NONE;
        rp.firewall = pc::FIREWALL_CONSISTENT;
        rp.addresses4.push_back(ep_addr());
        rp.udx = pc::UdxInfo{1, false, EP_UDX_ID, 0};
        rp.has_secret_stream = true;
        pc::HolepunchInfo hp;
        hp.id = 1;
        pc::RelayInfo ri;
        ri.relay_address = node_addr();
        ri.peer_address = ep_addr();
        hp.relays.push_back(ri);
        rp.holepunch = hp;

        auto rpb = pc::encode_noise_payload(rp);
        pc::HandshakeMessage reply_msg;
        reply_msg.mode = pc::MODE_REPLY;
        reply_msg.noise = responder.send(rpb.data(), rpb.size());

        msgs::Response resp;
        resp.tid = req.tid;
        // Doubles as the wire `to` (→ hs.client_address) AND the datagram
        // destination (rpc.cpp:558-573). No reply peer_address, so
        // hs.server_address stays empty and the LAN shortcut — which would
        // complete the connect with a null udx_socket — never arms
        // (`relayed = server_addr_js != relay_addr` is false).
        resp.from.addr = req.from.addr;
        resp.value = pc::encode_handshake_msg(reply_msg);
        node_.reply(resp, req.from_server);

        hs_.tx_key = responder.tx_key();
        hs_.rx_key = responder.rx_key();
        hs_.handshake_hash = responder.handshake_hash();
        hs_.public_key = kp_.public_key;
        hs_.is_initiator = false;

        // Deliberately AFTER the reply is on the wire and processed: udx hands
        // a packet for an unconnected stream to the firewall callback and then
        // processes it, dropping the payload when no read callback is
        // installed yet (udx.c:1348) — it is acked, so it never comes back.
        // The connect callback only installs one synchronously (connect +
        // duplex->start()) once the handshake result is in, so an endpoint
        // that speaks too early loses its SecretStream header for good.
        start_timer_ = std::make_unique<hyperdht::async_utils::UvTimer>(loop_);
        start_timer_->start([this]() { start_endpoint(); }, 80);
    }

    void start_endpoint() {
        stream_ = new udx_stream_t;
        udx_stream_init(udx_.handle(), stream_, EP_UDX_ID,
                        [](udx_stream_t*, int) {},
                        [](udx_stream_t* s) { delete s; });
        struct sockaddr_in dest{};
        uv_ip4_addr(peer_addr_.host_string().c_str(), peer_addr_.port, &dest);
        udx_stream_connect(stream_, ep_.handle(), peer_udx_id_,
                           reinterpret_cast<const struct sockaddr*>(&dest));

        duplex_ = std::make_unique<SecretStreamDuplex>(stream_, hs_, loop_);
        mux_ = std::make_unique<hyperdht::protomux::Mux>(
            [this](const uint8_t* d, size_t n) {
                duplex_->write(d, n, nullptr);
                return true;
            });
        duplex_->on_message([this](const uint8_t* d, size_t n) {
            if (mux_ && !mux_->is_destroyed()) mux_->on_data(d, n);
        });
        duplex_->on_connect([this]() { open_relay_channel(); });
        duplex_->start();
    }

    void open_relay_channel() {
        std::vector<uint8_t> id(kp_.public_key.begin(), kp_.public_key.end());
        auto* channel = mux_->create_channel(bl::PROTOCOL_NAME, id, false);
        ASSERT_NE(channel, nullptr);
        channel->add_message({});   // 0 = pair
        channel->add_message({});   // 1 = unpair
        channel->open();

        bl::PairMessage pm;
        pm.is_initiator = false;    // the client proposed the relay
        pm.token = token_;
        pm.id = PAIRED_ID;
        pm.seq = 0;
        auto payload = bl::encode_pair(pm);

        // Hand-framed [localId][messageType][payload] — Channel::send() is
        // gated on the remote OPEN, which never arrives (see the header note).
        ASSERT_LT(channel->local_id(), 0xfdu);
        std::vector<uint8_t> frame;
        frame.push_back(static_cast<uint8_t>(channel->local_id()));
        frame.push_back(0);
        frame.insert(frame.end(), payload.begin(), payload.end());
        duplex_->write(frame.data(), frame.size(), nullptr);
    }

    uv_loop_t* loop_;
    hyperdht::noise::Keypair kp_;
    bl::Token token_;
    hyperdht::rpc::RpcSocket node_;
    hyperdht::udx::Udx udx_;
    hyperdht::udx::UdxSocket ep_;
    std::unique_ptr<hyperdht::async_utils::UvTimer> start_timer_;
    udx_stream_t* stream_ = nullptr;
    std::unique_ptr<SecretStreamDuplex> duplex_;
    std::unique_ptr<hyperdht::protomux::Mux> mux_;
    DuplexHandshake hs_{};
    Ipv4Address peer_addr_{};
    uint32_t peer_udx_id_ = 0;
};

}  // namespace ru_relay_emit

TEST(ServerRelayEmit, UpgradeHoldsTheSessionPunchSocket) {
    using namespace ru_relay_emit;
    using hyperdht::server::ConnectionInfo;

    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht::noise::Seed relay_seed{};
    relay_seed.fill(0x71);
    auto relay_kp = hyperdht::noise::generate_keypair(relay_seed);
    bl::Token token{};
    token.fill(0x33);

    auto relay = std::make_unique<FakeRelayPeer>(&loop, relay_kp, token);

    hyperdht::HyperDHT dht(&loop);            // empty bootstrap — offline
    ASSERT_EQ(dht.bind(), 0);
    auto silent = std::make_unique<SilentNodes>(&loop);
    silent->seed(dht);
    dht.add_node(relay->node_addr());
    dht.cache_relay_addresses(relay_kp.public_key, {relay->node_addr()});

    auto* srv = dht.create_server();
    ASSERT_NE(srv, nullptr);
    srv->handshake_clear_wait = 1500;   // the session must outlive the pairing
    srv->punch_clear_wait = 1500;       // and then be reaped inside the test

    hyperdht::noise::Seed server_seed{};
    server_seed.fill(0x11);
    auto server_kp = hyperdht::noise::generate_keypair(server_seed);

    bool emitted = false;
    std::shared_ptr<void> emitted_upgrade;
    udx_stream_t* emitted_raw = nullptr;
    srv->listen(server_kp, [&](const ConnectionInfo& info) {
        emitted = true;
        emitted_upgrade = info.upgrade;
        emitted_raw = info.raw_stream;
    });

    // A relayed handshake (→ punch socket) that also proposes relayThrough
    // (→ the blind-relay path), i.e. JS server.js:397-399 with :436.
    hyperdht::noise::Seed client_seed{};
    client_seed.fill(0x22);
    auto client_kp = hyperdht::noise::generate_keypair(client_seed);
    const auto& prol = hyperdht::dht_messages::ns_peer_handshake();
    hyperdht::noise::NoiseIK client_noise(true, client_kp, prol.data(),
                                          prol.size(), &server_kp.public_key);

    pc::NoisePayload cp;
    cp.version = 1;
    cp.firewall = pc::FIREWALL_CONSISTENT;
    cp.udx = pc::UdxInfo{1, false, 12345, 0};
    cp.has_secret_stream = true;
    cp.addresses4.push_back(Ipv4Address::from_string("10.0.0.1", 5000));
    pc::RelayThroughInfo rt;
    rt.public_key = relay_kp.public_key;
    rt.token = token;
    cp.relay_through = rt;
    auto cpb = pc::encode_noise_payload(cp);

    pc::HandshakeMessage hs_msg;
    hs_msg.noise = client_noise.send(cpb.data(), cpb.size());
    hs_msg.mode = pc::MODE_FROM_RELAY;
    hs_msg.peer_address = Ipv4Address::from_string("10.0.0.1", 5000);

    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, server_kp.public_key.data(), 32,
                       nullptr, 0);
    msgs::Request req;
    req.target = target;
    req.value = pc::encode_handshake_msg(hs_msg);
    req.command = msgs::CMD_PEER_HANDSHAKE;
    req.from.addr = relay->node_addr();
    req.tid = 1;

    uint32_t hp_id = 0;
    auto absorb = [&](const std::vector<uint8_t>& value) {
        auto resp_hs = pc::decode_handshake_msg(value.data(), value.size());
        auto plain = client_noise.recv(resp_hs.noise.data(),
                                       resp_hs.noise.size());
        ASSERT_TRUE(plain.has_value());
        auto sp = pc::decode_noise_payload(plain->data(), plain->size());
        ASSERT_TRUE(sp.holepunch.has_value());
        hp_id = sp.holepunch->id;
    };
    ASSERT_TRUE(dht.router().handle_peer_handshake(
        req,
        [&](const msgs::Response& resp) {
            ASSERT_TRUE(resp.value.has_value());
            absorb(*resp.value);
        },
        [&](const msgs::Request& relay_req, udx_socket_t*) {
            ASSERT_TRUE(relay_req.value.has_value());
            auto fwd = pc::decode_handshake_msg(relay_req.value->data(),
                                                relay_req.value->size());
            pc::HandshakeMessage inner;
            inner.mode = pc::MODE_REPLY;
            inner.noise = fwd.noise;
            absorb(pc::encode_handshake_msg(inner));
        }));

    auto* session = srv->session(hp_id);
    ASSERT_NE(session, nullptr);
    ASSERT_TRUE(session->punch_socket)
        << "a relayed handshake must acquire a punch socket";
    std::weak_ptr<hyperdht::holepunch::PoolSocket> weak = session->punch_socket;

    ru_choreo::pump_until(&loop, [&] { return emitted; }, 8000);
    ASSERT_TRUE(emitted) << "the relay pairing never emitted a connection";
    ASSERT_TRUE(emitted_upgrade) << "relay emit carried no upgrade context";

    // The session — sole owner of the punch socket — is reaped by the
    // clear-wait backstop while the relayed stream lives on. The client's
    // direct nudge can still arrive on that socket and migrate this stream,
    // so the upgrade context has to be holding it.
    ru_choreo::pump_until(&loop, [&] { return srv->session(hp_id) == nullptr; },
                          8000);
    ASSERT_EQ(srv->session(hp_id), nullptr) << "session outlived the backstop";
    EXPECT_FALSE(weak.expired())
        << "punch socket freed under the stream the upgrade may migrate";

    emitted_upgrade.reset();
    ru_choreo::pump_until(&loop, [] { return false; }, 100);
    EXPECT_TRUE(weak.expired()) << "nothing but the upgrade should hold it";

    if (emitted_raw) hyperdht::udx::destroy_stream_once(emitted_raw);
    ru_choreo::pump_until(&loop, [] { return false; }, 50);
    dht.destroy();
    relay.reset();
    silent.reset();   // its uv_close callbacks need a live loop
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}
