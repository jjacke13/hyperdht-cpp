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

#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/relay_upgrade.hpp"
#include "hyperdht/secret_stream.hpp"
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
