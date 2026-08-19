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
#include "hyperdht/udx.hpp"

using hyperdht::compact::Ipv4Address;
using hyperdht::holepunch::PoolSocket;
using hyperdht::udx::Udx;
using hyperdht::udx::UdxSocket;
namespace messages = hyperdht::messages;

class PoolSocketRequests : public ::testing::Test {
  protected:
    uv_loop_t loop_{};
    std::unique_ptr<Udx> udx_;
    std::unique_ptr<PoolSocket> pool_;
    std::unique_ptr<UdxSocket> plain_;  // stands in for the remote peer
    std::optional<messages::Response> received_;

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

    static void on_plain_recv(udx_socket_t* s, ssize_t nread,
                              const uv_buf_t* buf, const struct sockaddr*) {
        auto* self = static_cast<PoolSocketRequests*>(s->data);
        if (!self || nread <= 0) return;
        messages::Request req;
        messages::Response resp;
        auto type = messages::decode_message(
            reinterpret_cast<const uint8_t*>(buf->base),
            static_cast<size_t>(nread), req, resp);
        if (type == messages::RESPONSE_ID) self->received_ = resp;
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
}

TEST_F(PoolSocketRequests, RequestFeedsNatSampler) {
    // wire `to` field = our external address as the sender saw us
    // (JS server.js:510 p.nat.add(req.to, req.from)).
    messages::Request req;
    req.tid = 1;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.to.addr = Ipv4Address::from_string("203.0.113.7", 4242);

    pool_->on_request([](const messages::Request&, const Ipv4Address&) {});
    send_from_plain_socket(messages::encode_request(req), pool_addr());
    run_loop_until([&] { return pool_->nat_sampler().sampled() > 0; });

    EXPECT_GE(pool_->nat_sampler().sampled(), 1);
    EXPECT_EQ(pool_->nat_sampler().host(), "203.0.113.7");
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
