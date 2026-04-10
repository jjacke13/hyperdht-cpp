// Integration test: Protomux over SecretStreamDuplex over a real UDX pair.
//
// Validates that the three layers compose correctly end-to-end:
//
//   [Protomux channel send/recv]
//        ↓
//   [SecretStreamDuplex write/on_message + framing/encrypt/decrypt]
//        ↓
//   [udx_stream_t reliable byte stream]
//
// Unlike the existing test_protomux.cpp (which uses a synchronous
// LoopbackMux), this test runs a real libuv loop with two UDX streams
// connected via two loopback sockets. Each stream is wrapped in a
// SecretStreamDuplex, and each Duplex is further wrapped in a Protomux
// Mux. Messages sent via a Protomux Channel get batched (optionally),
// encrypted by the Duplex, travel over UDX, get decrypted on the other
// side, and dispatched back into the remote Mux.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <sodium.h>
#include <udx.h>
#include <uv.h>

#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/protomux.hpp"
#include "hyperdht/secret_stream.hpp"

using namespace hyperdht;

// ---------------------------------------------------------------------------
// Handshake pair helper — runs a full Noise IK round-trip between two
// in-process endpoints and returns both sides' DuplexHandshake structs.
// ---------------------------------------------------------------------------

static std::pair<secret_stream::DuplexHandshake,
                 secret_stream::DuplexHandshake> make_handshake_pair() {
    noise::Seed is{}, rs{};
    is.fill(0x33);
    rs.fill(0x44);
    auto ikp = noise::generate_keypair(is);
    auto rkp = noise::generate_keypair(rs);

    uint8_t prologue[] = {0x00};
    noise::NoiseIK initiator(true,  ikp, prologue, 1, &rkp.public_key);
    noise::NoiseIK responder(false, rkp, prologue, 1, nullptr);

    auto m1 = initiator.send();
    auto r1 = responder.recv(m1.data(), m1.size());
    EXPECT_TRUE(r1.has_value());
    auto m2 = responder.send();
    auto r2 = initiator.recv(m2.data(), m2.size());
    EXPECT_TRUE(r2.has_value());

    secret_stream::DuplexHandshake ih{}, rh{};
    ih.tx_key = initiator.tx_key();
    ih.rx_key = initiator.rx_key();
    ih.handshake_hash = initiator.handshake_hash();
    ih.public_key = ikp.public_key;
    ih.remote_public_key = rkp.public_key;
    ih.is_initiator = true;

    rh.tx_key = responder.tx_key();
    rh.rx_key = responder.rx_key();
    rh.handshake_hash = responder.handshake_hash();
    rh.public_key = rkp.public_key;
    rh.remote_public_key = ikp.public_key;
    rh.is_initiator = false;

    return {ih, rh};
}

// ---------------------------------------------------------------------------
// UDX loopback fixture — two sockets, two streams, all on one loop.
// Borrowed verbatim from test_secret_stream.cpp's DuplexLoopback pattern.
// ---------------------------------------------------------------------------

struct UdxPair {
    uv_loop_t loop;
    udx_t udx;
    udx_socket_t sock1, sock2;
    udx_stream_t stream1, stream2;
    bool shutdown_called = false;

    UdxPair() {
        uv_loop_init(&loop);
        udx_init(&loop, &udx, nullptr);
        udx_socket_init(&udx, &sock1, nullptr);
        udx_socket_init(&udx, &sock2, nullptr);

        struct sockaddr_in a{};
        uv_ip4_addr("127.0.0.1", 0, &a);
        udx_socket_bind(&sock1, reinterpret_cast<const struct sockaddr*>(&a), 0);
        udx_socket_bind(&sock2, reinterpret_cast<const struct sockaddr*>(&a), 0);

        udx_stream_init(&udx, &stream1, 1, nullptr, nullptr);
        udx_stream_init(&udx, &stream2, 2, nullptr, nullptr);

        struct sockaddr_in b1{}, b2{};
        int len = sizeof(b1);
        udx_socket_getsockname(&sock1, reinterpret_cast<struct sockaddr*>(&b1), &len);
        len = sizeof(b2);
        udx_socket_getsockname(&sock2, reinterpret_cast<struct sockaddr*>(&b2), &len);

        udx_stream_connect(&stream1, &sock1, 2,
                           reinterpret_cast<const struct sockaddr*>(&b2));
        udx_stream_connect(&stream2, &sock2, 1,
                           reinterpret_cast<const struct sockaddr*>(&b1));
    }

    // Begin graceful shutdown: end both duplexes. Sockets are closed
    // later from the user on_close callback.
    void begin_shutdown(secret_stream::SecretStreamDuplex* i,
                        secret_stream::SecretStreamDuplex* r) {
        if (shutdown_called) return;
        shutdown_called = true;
        if (i) i->end();
        if (r) r->end();
    }

    void close_sockets() {
        udx_socket_close(&sock1);
        udx_socket_close(&sock2);
    }

    ~UdxPair() {
        if (!shutdown_called) {
            udx_stream_destroy(&stream1);
            udx_stream_destroy(&stream2);
            udx_socket_close(&sock1);
            udx_socket_close(&sock2);
            uv_run(&loop, UV_RUN_DEFAULT);
        }
        uv_loop_close(&loop);
    }
};

// ---------------------------------------------------------------------------
// Glue: wire a Mux's WriteFn to a SecretStreamDuplex, and feed incoming
// messages from the Duplex into the Mux's on_data. Each side owns its
// own Mux, Duplex, and the "glue" state bundled into a struct.
// ---------------------------------------------------------------------------

struct Stack {
    secret_stream::SecretStreamDuplex* duplex;
    std::unique_ptr<protomux::Mux> mux;

    explicit Stack(secret_stream::SecretStreamDuplex* d) : duplex(d) {
        mux = std::make_unique<protomux::Mux>(
            [this](const uint8_t* data, size_t len) -> bool {
                // Write the protomux frame as one encrypted message.
                // SecretStreamDuplex.write() returns 0 on submission
                // success; we report true (drained) regardless since
                // UDX doesn't surface backpressure synchronously.
                int rc = duplex->write(data, len, nullptr);
                return rc == 0;
            });

        // Feed decrypted payloads from the Duplex into the Mux.
        duplex->on_message([this](const uint8_t* data, size_t len) {
            mux->on_data(data, len);
        });
    }
};

// ---------------------------------------------------------------------------
// Test 1 — a single protomux channel carries bidirectional messages
// through the encrypted SecretStream pipe.
// ---------------------------------------------------------------------------

TEST(ProtomuxSecretStream, ChannelOverEncryptedStream) {
    UdxPair pair;
    auto [ih, rh] = make_handshake_pair();

    secret_stream::SecretStreamDuplex dup_i(&pair.stream1, ih, &pair.loop);
    secret_stream::SecretStreamDuplex dup_r(&pair.stream2, rh, &pair.loop);

    Stack stack_i(&dup_i);
    Stack stack_r(&dup_r);

    // Watchdog is created later, but referenced from shutdown paths.
    uv_timer_t wd;
    uv_timer_init(&pair.loop, &wd);
    auto close_watchdog = [&]() {
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&wd))) {
            uv_close(reinterpret_cast<uv_handle_t*>(&wd), nullptr);
        }
    };

    // Channels to be created once both Duplexes are connected.
    protomux::Channel* ch_i = nullptr;
    protomux::Channel* ch_r = nullptr;

    std::string received_on_r;
    std::string received_on_i;
    int closes = 0;

    auto wire_channels = [&]() {
        // Create the channels. Both sides use the same protocol so they
        // pair automatically (via the OPEN frames exchanged over UDX).
        ch_i = stack_i.mux->create_channel("echo");
        ch_r = stack_r.mux->create_channel("echo");
        ASSERT_NE(ch_i, nullptr);
        ASSERT_NE(ch_r, nullptr);

        // Each side registers a message type 0 and records what it gets.
        ch_i->add_message({[&](const uint8_t* d, size_t n) {
            received_on_i.assign(reinterpret_cast<const char*>(d), n);
            if (!received_on_r.empty() && !received_on_i.empty()) {
                close_watchdog();
                pair.begin_shutdown(&dup_i, &dup_r);
            }
        }});
        ch_r->add_message({[&](const uint8_t* d, size_t n) {
            received_on_r.assign(reinterpret_cast<const char*>(d), n);
            // Reply back to the initiator from inside the handler —
            // ch_r is guaranteed to be open at this point because we
            // received a data frame from the paired remote.
            const char* reply = "hello from responder";
            ch_r->send(0, reinterpret_cast<const uint8_t*>(reply), 20);
        }});

        // Channel open is async (the OPEN frame travels over UDX), so we
        // must send from on_open, not immediately after open().
        ch_i->on_open = [&](const uint8_t*, size_t) {
            const char* hi = "hello from initiator";
            ch_i->send(0, reinterpret_cast<const uint8_t*>(hi), 20);
        };

        ch_i->open();
        ch_r->open();
    };

    // Hook wire_channels to fire as soon as BOTH Duplexes report connected.
    bool both_connected = false;
    auto maybe_wire = [&]() {
        if (both_connected) return;
        if (!dup_i.is_connected() || !dup_r.is_connected()) return;
        both_connected = true;
        wire_channels();
    };
    dup_i.on_connect([&]() { maybe_wire(); });
    dup_r.on_connect([&]() { maybe_wire(); });

    auto close_cb = [&](int) {
        closes++;
        if (closes == 2) pair.close_sockets();
    };
    dup_i.on_close(close_cb);
    dup_r.on_close(close_cb);

    dup_i.start();
    dup_r.start();

    // Watchdog — force shutdown after 3s in case something wedges.
    struct WD {
        UdxPair* p;
        secret_stream::SecretStreamDuplex* i;
        secret_stream::SecretStreamDuplex* r;
    } wdc{&pair, &dup_i, &dup_r};
    wd.data = &wdc;
    uv_timer_start(&wd, [](uv_timer_t* t) {
        auto* w = static_cast<WD*>(t->data);
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
        w->p->begin_shutdown(w->i, w->r);
    }, 3000, 0);

    uv_run(&pair.loop, UV_RUN_DEFAULT);

    EXPECT_EQ(received_on_r, "hello from initiator");
    EXPECT_EQ(received_on_i, "hello from responder");
}

// ---------------------------------------------------------------------------
// Test 2 — cork/uncork batching: send three messages while corked, the
// Mux emits a single batch frame, which gets encrypted as one SecretStream
// message and decrypted as one on the other side, then decoded back into
// the three original messages in order.
// ---------------------------------------------------------------------------

TEST(ProtomuxSecretStream, CorkBatchingSurvivesEncryption) {
    UdxPair pair;
    auto [ih, rh] = make_handshake_pair();

    secret_stream::SecretStreamDuplex dup_i(&pair.stream1, ih, &pair.loop);
    secret_stream::SecretStreamDuplex dup_r(&pair.stream2, rh, &pair.loop);

    Stack stack_i(&dup_i);
    Stack stack_r(&dup_r);

    uv_timer_t wd;
    uv_timer_init(&pair.loop, &wd);
    auto close_watchdog = [&]() {
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&wd))) {
            uv_close(reinterpret_cast<uv_handle_t*>(&wd), nullptr);
        }
    };

    protomux::Channel* ch_i = nullptr;
    protomux::Channel* ch_r = nullptr;
    std::vector<std::string> received;
    int closes = 0;

    auto wire_channels = [&]() {
        ch_i = stack_i.mux->create_channel("batch");
        ch_r = stack_r.mux->create_channel("batch");
        ASSERT_NE(ch_i, nullptr);
        ASSERT_NE(ch_r, nullptr);

        ch_i->add_message({});
        ch_r->add_message({[&](const uint8_t* d, size_t n) {
            received.emplace_back(reinterpret_cast<const char*>(d), n);
            if (received.size() == 3) {
                close_watchdog();
                pair.begin_shutdown(&dup_i, &dup_r);
            }
        }});

        // Drive the corked sends from on_open so ch_i is guaranteed
        // paired (and ch_i->send will succeed).
        ch_i->on_open = [&](const uint8_t*, size_t) {
            stack_i.mux->cork();
            const char* m1 = "one";
            const char* m2 = "two";
            const char* m3 = "three";
            ch_i->send(0, reinterpret_cast<const uint8_t*>(m1), 3);
            ch_i->send(0, reinterpret_cast<const uint8_t*>(m2), 3);
            ch_i->send(0, reinterpret_cast<const uint8_t*>(m3), 5);
            stack_i.mux->uncork();
        };

        ch_i->open();
        ch_r->open();
    };

    bool both_connected = false;
    auto maybe_wire = [&]() {
        if (both_connected) return;
        if (!dup_i.is_connected() || !dup_r.is_connected()) return;
        both_connected = true;
        wire_channels();
    };
    dup_i.on_connect([&]() { maybe_wire(); });
    dup_r.on_connect([&]() { maybe_wire(); });

    auto close_cb = [&](int) {
        closes++;
        if (closes == 2) pair.close_sockets();
    };
    dup_i.on_close(close_cb);
    dup_r.on_close(close_cb);

    dup_i.start();
    dup_r.start();

    struct WD2 {
        UdxPair* p;
        secret_stream::SecretStreamDuplex* i;
        secret_stream::SecretStreamDuplex* r;
    } wdc{&pair, &dup_i, &dup_r};
    wd.data = &wdc;
    uv_timer_start(&wd, [](uv_timer_t* t) {
        auto* w = static_cast<WD2*>(t->data);
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
        w->p->begin_shutdown(w->i, w->r);
    }, 3000, 0);

    uv_run(&pair.loop, UV_RUN_DEFAULT);

    ASSERT_EQ(received.size(), 3u);
    EXPECT_EQ(received[0], "one");
    EXPECT_EQ(received[1], "two");
    EXPECT_EQ(received[2], "three");
}
