// PoolSocket inbound-request path: a DHT request arriving on the punch socket
// must be dispatched to the on_request consumer, feed the NAT sampler, and be
// answerable with a reply sent from that same socket.
//
// JS: hyperdht/lib/server.js:508-511 — PEER_HOLEPUNCH rounds that land on the
// session's punch socket (`req.socket === p.socket`) call
// `p.nat.add(req.to, req.from)` and are replied to on that socket.

#include <gtest/gtest.h>

#include <cstring>
#include <functional>
#include <optional>
#include <vector>

#include <uv.h>

#include "hyperdht/compact.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/routing_table.hpp"
#include "hyperdht/udx.hpp"

using hyperdht::compact::Ipv4Address;
using hyperdht::holepunch::PoolSocket;
using hyperdht::udx::Udx;
using hyperdht::udx::UdxSocket;
namespace messages = hyperdht::messages;

namespace {

uint16_t port_of(udx_socket_t* s) {
    struct sockaddr_in a{};
    int len = sizeof(a);
    udx_socket_getsockname(s, reinterpret_cast<struct sockaddr*>(&a), &len);
    return ntohs(a.sin_port);
}

// Reply straight back on the socket a datagram arrived on. Used by the
// throwaway responders below, which have no fixture to lean on.
void send_raw(udx_socket_t* s, const std::vector<uint8_t>& data,
              const struct sockaddr_in* to) {
    struct SendCtx {
        udx_socket_send_t req{};
        std::vector<uint8_t> buf;
    };
    auto* ctx = new SendCtx;
    ctx->buf = data;
    ctx->req.data = ctx;
    uv_buf_t b = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                             static_cast<unsigned int>(ctx->buf.size()));
    udx_socket_send(&ctx->req, s, &b, 1,
                    reinterpret_cast<const struct sockaddr*>(to),
                    [](udx_socket_send_t* r, int) {
                        delete static_cast<SendCtx*>(r->data);
                    });
}

}  // namespace

class PoolSocketRequests : public ::testing::Test {
  protected:
    uv_loop_t loop_{};
    std::unique_ptr<Udx> udx_;
    std::unique_ptr<PoolSocket> pool_;
    std::unique_ptr<UdxSocket> plain_;  // stands in for the remote peer
    std::optional<messages::Response> received_;
    uint16_t received_src_port_ = 0;  // UDP source of the reply

    void SetUp() override {
        uv_loop_init(&loop_);
        udx_ = std::make_unique<Udx>(&loop_);

        pool_ = std::make_unique<PoolSocket>(&loop_, udx_->handle());
        ASSERT_EQ(pool_->bind(), 0);

        plain_ = std::make_unique<UdxSocket>(*udx_);
        struct sockaddr_in any{};
        uv_ip4_addr("127.0.0.1", 0, &any);
        ASSERT_EQ(plain_->bind(reinterpret_cast<const struct sockaddr*>(&any)), 0);
        plain_->handle()->data = this;
        ASSERT_EQ(plain_->recv_start(on_plain_recv), 0);
    }

    // Teardown must survive a fatal ASSERT_* in SetUp (gtest still runs it),
    // so every step is null-guarded and the loop is always drained before
    // uv_loop_close — an un-drained close callback wedges the loop.
    void TearDown() override {
        if (pool_) pool_->close();
        if (plain_) plain_->close();
        uv_run(&loop_, UV_RUN_DEFAULT);
        pool_.reset();
        plain_.reset();
        udx_.reset();
        uv_loop_close(&loop_);
    }

    std::optional<messages::Request> plain_got_request_;

    static void on_plain_recv(udx_socket_t* s, ssize_t nread,
                              const uv_buf_t* buf, const struct sockaddr* addr) {
        auto* self = static_cast<PoolSocketRequests*>(s->data);
        if (!self || nread <= 0 || !addr) return;
        messages::Request req;
        messages::Response resp;
        auto type = messages::decode_message(
            reinterpret_cast<const uint8_t*>(buf->base),
            static_cast<size_t>(nread), req, resp);
        if (type == messages::REQUEST_ID) {
            self->plain_got_request_ = req;
            return;
        }
        if (type != messages::RESPONSE_ID) return;
        self->received_ = resp;
        self->received_src_port_ = ntohs(
            reinterpret_cast<const struct sockaddr_in*>(addr)->sin_port);
    }

    Ipv4Address bound_addr(udx_socket_t* s) const {
        struct sockaddr_in a{};
        int len = sizeof(a);
        udx_socket_getsockname(s, reinterpret_cast<struct sockaddr*>(&a), &len);
        return Ipv4Address::from_string("127.0.0.1", ntohs(a.sin_port));
    }

    Ipv4Address pool_addr() { return bound_addr(pool_->socket_handle()); }

    void send_from_plain_socket(const std::vector<uint8_t>& data,
                                const Ipv4Address& to) {
        struct SendCtx {
            udx_socket_send_t req{};
            std::vector<uint8_t> buf;
        };
        auto* ctx = new SendCtx;
        ctx->buf = data;
        ctx->req.data = ctx;
        uv_buf_t b = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                 static_cast<unsigned int>(ctx->buf.size()));
        struct sockaddr_in dest{};
        uv_ip4_addr(to.host_string().c_str(), to.port, &dest);
        plain_->send(&ctx->req, &b, 1,
                     reinterpret_cast<const struct sockaddr*>(&dest),
                     [](udx_socket_send_t* r, int) {
                         delete static_cast<SendCtx*>(r->data);
                     });
    }

    // Pump the loop until pred() or the deadline. The 1ms repeating timer
    // keeps UV_RUN_ONCE from blocking forever when nothing else is pending.
    bool run_loop_until(const std::function<bool()>& pred,
                        uint64_t timeout_ms = 2000) {
        uv_timer_t tick{};
        uv_timer_init(&loop_, &tick);
        uv_timer_start(&tick, [](uv_timer_t*) {}, 1, 1);
        uv_update_time(&loop_);
        uint64_t deadline = uv_now(&loop_) + timeout_ms;
        while (!pred() && uv_now(&loop_) < deadline) {
            uv_run(&loop_, UV_RUN_ONCE);
        }
        uv_timer_stop(&tick);
        uv_close(reinterpret_cast<uv_handle_t*>(&tick), nullptr);
        uv_run(&loop_, UV_RUN_NOWAIT);  // drain the close cb — `tick` is on the stack
        return pred();
    }
};

TEST_F(PoolSocketRequests, InboundRequestDispatchesAndReplyRoundTrips) {
    messages::Request req;
    req.tid = 777;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.internal = false;
    req.to.addr = pool_addr();  // wire `to` = the pool socket's addr
    req.value = std::vector<uint8_t>{1, 2, 3};

    std::optional<messages::Request> got;
    pool_->on_request([&](const messages::Request& r, const Ipv4Address& from) {
        got = r;
        messages::Response resp;
        resp.tid = r.tid;
        resp.from.addr = from;  // destination, per RpcSocket::reply convention
        resp.value = std::vector<uint8_t>{9};
        pool_->reply(resp);
    });

    send_from_plain_socket(messages::encode_request(req), pool_addr());
    run_loop_until([&] { return got.has_value(); });
    ASSERT_TRUE(got);
    EXPECT_EQ(got->tid, 777);
    EXPECT_EQ(got->command, messages::CMD_PEER_HOLEPUNCH);
    ASSERT_TRUE(got->value.has_value());
    EXPECT_EQ(*got->value, (std::vector<uint8_t>{1, 2, 3}));

    run_loop_until([&] { return received_.has_value(); });
    ASSERT_TRUE(received_);
    EXPECT_EQ(received_->tid, 777);
    ASSERT_TRUE(received_->value.has_value());
    EXPECT_EQ(*received_->value, (std::vector<uint8_t>{9}));

    // The whole point of reply(): the answer egresses from the SAME socket the
    // request landed on. A reply from any other source port is dropped by
    // stateful conntrack/CGNAT on a real path (see rpc.cpp:556-565).
    EXPECT_EQ(received_src_port_, pool_addr().port)
        << "reply did not egress from the pool socket";
}

// An inbound request is unauthenticated at this layer, so PoolSocket must NOT
// sample it. JS runs `p.nat.add(req.to, req.from)` only after the payload
// decrypts and the round reports error==NONE (server.js:491-511) — otherwise
// three datagrams from three spoofed sources carrying a chosen `to` pin the
// session's advertised address and firewall. The consumer owns the add; see
// `ServerPunchSocket.UndecryptableRoundChangesNoState` for the server-level
// version of this with a real decrypt.
TEST_F(PoolSocketRequests, RequestDoesNotFeedNatSampler) {
    messages::Request req;
    req.tid = 1;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.to.addr = Ipv4Address::from_string("203.0.113.7", 4242);

    bool dispatched = false;
    pool_->on_request([&](const messages::Request&, const Ipv4Address&) {
        dispatched = true;
    });
    send_from_plain_socket(messages::encode_request(req), pool_addr());
    run_loop_until([&] { return dispatched; });

    ASSERT_TRUE(dispatched) << "request must still reach the consumer";
    EXPECT_EQ(pool_->nat_sampler().sampled(), 0);
    EXPECT_EQ(pool_->nat_sampler().host(), "");
}

// Same attack, other message type: a RESPONSE nobody asked for must not reach
// the NAT sampler either. The connecting client learns the punch socket's
// address from the handshake reply, so an unmatched-response feed lets it pin
// the session's advertised address and firewall from three of its OWN source
// ports — no spoofing needed. JS samples only on MATCHED replies (dht-rpc
// io.js dispatches by tid; connect.js:578 / nat.js add from the ping reply).
TEST_F(PoolSocketRequests, UnmatchedResponseDoesNotFeedNatSampler) {
    messages::Response resp;
    resp.tid = 4242;  // nothing inflight has this tid
    resp.from.addr = Ipv4Address::from_string("198.51.100.9", 1234);

    send_from_plain_socket(messages::encode_response(resp), pool_addr());
    run_loop_until([] { return false; }, 100);

    EXPECT_EQ(pool_->nat_sampler().sampled(), 0);
    EXPECT_EQ(pool_->nat_sampler().host(), "");
}

// The other half of the gate: a reply to OUR request still samples, because
// that is the whole point of the NAT-discovery PING campaign
// (discover_pool_addresses → nat.js autoSample). Guards against "fix" the
// unmatched case by killing sampling outright.
TEST_F(PoolSocketRequests, MatchedResponseFeedsNatSampler) {
    messages::Request ping;
    ping.command = messages::CMD_PING;
    ping.internal = true;
    ping.to.addr = bound_addr(plain_->handle());

    bool answered = false;
    pool_->request(ping, [&](const messages::Response&) { answered = true; });

    ASSERT_TRUE(run_loop_until([&] { return plain_got_request_.has_value(); }));

    messages::Response resp;
    resp.tid = plain_got_request_->tid;
    resp.from.addr = Ipv4Address::from_string("198.51.100.9", 1234);  // wire `to`
    send_from_plain_socket(messages::encode_response(resp), pool_addr());

    ASSERT_TRUE(run_loop_until([&] { return answered; }));
    EXPECT_EQ(pool_->nat_sampler().sampled(), 1);
    EXPECT_EQ(pool_->nat_sampler().host(), "198.51.100.9");
}

// close() must not pull the socket out from under a stream that was adopted
// onto it (udx_socket_close returns UV_EBUSY, udx.c:2175), and the refusal has
// to be visible in a SHIPPED build — DHT_LOG compiles to a no-op there
// (debug.hpp:19), so the counter is the only diagnostic that survives.
TEST_F(PoolSocketRequests, BusyCloseKeepsSocketOpenAndCounts) {
    udx_stream_t stream{};
    ASSERT_EQ(udx_stream_init(udx_->handle(), &stream, 4321,
                              [](udx_stream_t*, int) {}, nullptr), 0);
    struct sockaddr_in dest{};
    uv_ip4_addr("127.0.0.1", bound_addr(plain_->handle()).port, &dest);
    ASSERT_EQ(udx_stream_connect(&stream, pool_->socket_handle(), 99,
                                 reinterpret_cast<const struct sockaddr*>(&dest)),
              0);

    auto* handle = pool_->socket_handle();
    uint64_t before = hyperdht::udx::busy_close_count();

    pool_->close();

    EXPECT_EQ(hyperdht::udx::busy_close_count(), before + 1);
    EXPECT_TRUE(pool_->is_closing());
    EXPECT_EQ(pool_->socket_handle(), handle)
        << "close() nulled a handle udx still owns";
    EXPECT_FALSE(uv_is_closing(reinterpret_cast<uv_handle_t*>(handle)))
        << "socket closed under a live stream";

    // Clean up what the contract violation left behind: the stream goes first,
    // then the socket can actually close (this is what the keepalive would
    // have guaranteed in the right order).
    hyperdht::udx::destroy_stream_once(&stream);
    run_loop_until([] { return false; }, 60);
    EXPECT_TRUE(hyperdht::udx::close_socket_unless_busy(handle));
    run_loop_until([] { return false; }, 60);
    pool_.reset();  // TearDown must not double-close
}

// No consumer wired → the request is dropped like any other unknown traffic,
// and nothing is fed to the sampler.
TEST_F(PoolSocketRequests, RequestWithoutConsumerIsDropped) {
    messages::Request req;
    req.tid = 2;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.to.addr = Ipv4Address::from_string("203.0.113.7", 4242);

    send_from_plain_socket(messages::encode_request(req), pool_addr());
    run_loop_until([&] { return false; }, 100);

    EXPECT_EQ(pool_->nat_sampler().sampled(), 0);
    EXPECT_FALSE(received_.has_value());
}

// ---------------------------------------------------------------------------
// discover_pool_addresses must resolve the MOMENT the classification lands,
// not when the last straggler ping gives up.
//
// JS `nat.js:172-179` resolves `analyzing` from inside `add()`: as soon as the
// firewall becomes CONSISTENT/OPEN (typically the 3rd sample) or
// `sampled >= _minSamples`. It never waits for outstanding pings.
//
// We used to fire only when every target had answered or exhausted its
// retries. On a server that is the gate in front of every parked PEER_HOLEPUNCH
// round: one dead node in the routing table held the reply for
// attempts x per-attempt timeout, which routinely outlives the client's own
// round budget — it aborts with -5 and the server answers a tid nobody is
// waiting for.
// ---------------------------------------------------------------------------

TEST_F(PoolSocketRequests, DiscoverSettlesOnClassificationNotOnStragglers) {
    // Four nodes that answer instantly and agree on our address (three
    // matching samples is already CONSISTENT), plus black holes that never
    // answer at all.
    struct Responder {
        std::unique_ptr<UdxSocket> sock;
        uint16_t port = 0;
        Ipv4Address observed{};
    };
    std::vector<std::unique_ptr<Responder>> live;
    auto observed = Ipv4Address::from_string("203.0.113.9", 40404);

    for (int i = 0; i < 4; i++) {
        auto r = std::make_unique<Responder>();
        r->sock = std::make_unique<UdxSocket>(*udx_);
        struct sockaddr_in any{};
        uv_ip4_addr("127.0.0.1", 0, &any);
        EXPECT_EQ(r->sock->bind(reinterpret_cast<const struct sockaddr*>(&any)), 0);
        r->observed = observed;
        r->port = port_of(r->sock->handle());
        r->sock->handle()->data = r.get();
        EXPECT_EQ(r->sock->recv_start(
            [](udx_socket_t* s, ssize_t nread, const uv_buf_t* buf,
               const struct sockaddr* addr) {
                auto* self = static_cast<Responder*>(s->data);
                if (!self || nread <= 0 || !addr) return;
                messages::Request req;
                messages::Response resp;
                if (messages::decode_message(
                        reinterpret_cast<const uint8_t*>(buf->base),
                        static_cast<size_t>(nread), req, resp) !=
                    messages::REQUEST_ID) {
                    return;
                }
                if (req.command != messages::CMD_PING || !req.internal) return;
                messages::Response out;
                out.tid = req.tid;
                out.from.addr = self->observed;  // wire `to` = how it sees us
                const auto* in =
                    reinterpret_cast<const struct sockaddr_in*>(addr);
                send_raw(s, messages::encode_response(out), in);
            }), 0);
        live.push_back(std::move(r));
    }

    // Seven table entries so discover fills MAX_TARGETS from the table alone
    // and never falls back to the public bootstrap nodes. skip stays 0 below
    // eight entries, so the four responders are all within the chosen slice.
    hyperdht::routing::RoutingTable table(hyperdht::routing::NodeId{});
    int seeded = 0;
    for (auto& r : live) {
        hyperdht::routing::Node n;
        n.id.fill(static_cast<uint8_t>(++seeded));
        n.host = "127.0.0.1";
        n.port = r->port;
        table.add(n);
    }
    // Black holes: ports nothing is bound to. These are what used to hold the
    // whole campaign hostage.
    for (uint16_t p : {(uint16_t)9001, (uint16_t)9002, (uint16_t)9003}) {
        hyperdht::routing::Node n;
        n.id.fill(static_cast<uint8_t>(++seeded));
        n.host = "127.0.0.1";
        n.port = p;
        table.add(n);
    }

    bool done = false;
    bool ok = false;
    uv_update_time(&loop_);
    uint64_t started = uv_now(&loop_);
    uint64_t settled_at = 0;

    hyperdht::holepunch::discover_pool_addresses(
        *pool_, table, Ipv4Address::from_string("127.0.0.1", 9004),
        [&](bool result) {
            done = true;
            ok = result;
            uv_update_time(&loop_);
            settled_at = uv_now(&loop_);
        });

    run_loop_until([&] { return done; }, 4000);
    ASSERT_TRUE(done) << "discover never resolved";
    EXPECT_TRUE(ok) << "four agreeing samples must be a usable verdict";

    // The black holes get MAX_REQUEST_ATTEMPTS tries at >= 200 ms each
    // (RpcSocket::timeout_for's floor), so waiting for them cannot come in
    // under 600 ms. Loopback replies land in single-digit ms.
    EXPECT_LT(settled_at - started, 300u)
        << "settled in " << (settled_at - started)
        << " ms — that is straggler time, not classification time";

    // The campaign's own requests are still outstanding; draining them here
    // keeps TearDown's close from racing an inflight retry timer.
    run_loop_until([] { return false; }, 50);
    pool_->close();
    run_loop_until([] { return false; }, 50);
    for (auto& r : live) r->sock->close();
    run_loop_until([] { return false; }, 50);
}
