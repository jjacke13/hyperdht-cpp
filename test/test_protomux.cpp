// Protomux unit tests — channel multiplexing over framed stream.
//
// These test the core Protomux logic without a real network:
// - Varint encode/decode
// - Channel open/close lifecycle
// - Channel pairing
// - Message dispatch
// - Cork/uncork batching

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "hyperdht/protomux.hpp"

using namespace hyperdht::protomux;

// ---------------------------------------------------------------------------
// Varint encode/decode
// ---------------------------------------------------------------------------

TEST(Varint, SingleByte) {
    uint8_t buf[9];
    EXPECT_EQ(varint_encode(buf, 0), 1u);
    EXPECT_EQ(buf[0], 0x00);

    EXPECT_EQ(varint_encode(buf, 42), 1u);
    EXPECT_EQ(buf[0], 42);

    EXPECT_EQ(varint_encode(buf, 252), 1u);
    EXPECT_EQ(buf[0], 252);
}

TEST(Varint, TwoByte) {
    uint8_t buf[9];
    EXPECT_EQ(varint_encode(buf, 253), 3u);
    EXPECT_EQ(buf[0], 0xFD);

    EXPECT_EQ(varint_encode(buf, 65535), 3u);
}

TEST(Varint, FourByte) {
    uint8_t buf[9];
    EXPECT_EQ(varint_encode(buf, 65536), 5u);
    EXPECT_EQ(buf[0], 0xFE);
}

TEST(Varint, RoundTrip) {
    std::vector<uint64_t> values = {0, 1, 42, 252, 253, 255, 256, 65535,
                                     65536, 1000000, 0xFFFFFFFF};
    for (uint64_t v : values) {
        uint8_t buf[9];
        size_t n = varint_encode(buf, v);

        const uint8_t* ptr = buf;
        const uint8_t* end = buf + n;
        uint64_t decoded = varint_decode(ptr, end);
        EXPECT_EQ(decoded, v) << "Failed for value " << v;
        EXPECT_EQ(ptr, end) << "Didn't consume all bytes for " << v;
    }
}

// ---------------------------------------------------------------------------
// Mux helpers: loopback pair
// ---------------------------------------------------------------------------

struct LoopbackMux {
    Mux a;
    Mux b;

    LoopbackMux()
        : a([this](const uint8_t* data, size_t len) {
              b.on_data(data, len);
          }),
          b([this](const uint8_t* data, size_t len) {
              a.on_data(data, len);
          }) {}
};

// ---------------------------------------------------------------------------
// Channel lifecycle
// ---------------------------------------------------------------------------

TEST(Protomux, ChannelOpenPair) {
    LoopbackMux mux;

    bool a_opened = false;
    bool b_opened = false;

    auto* ch_a = mux.a.create_channel("test-protocol");
    ch_a->on_open = [&](const uint8_t*, size_t) { a_opened = true; };

    // Register notify on side B
    mux.b.on_notify([&](const std::string& proto, const std::vector<uint8_t>&,
                        const uint8_t*, size_t) {
        EXPECT_EQ(proto, "test-protocol");
        auto* ch_b = mux.b.create_channel("test-protocol");
        ch_b->on_open = [&](const uint8_t*, size_t) { b_opened = true; };
        ch_b->open();
    });

    ch_a->open();

    EXPECT_TRUE(a_opened);
    EXPECT_TRUE(b_opened);
    EXPECT_TRUE(ch_a->is_open());
    EXPECT_GT(ch_a->remote_id(), 0u);
}

TEST(Protomux, ChannelOpenBothSides) {
    LoopbackMux mux;

    bool a_opened = false;
    bool b_opened = false;

    auto* ch_a = mux.a.create_channel("test-protocol");
    ch_a->on_open = [&](const uint8_t*, size_t) { a_opened = true; };

    auto* ch_b = mux.b.create_channel("test-protocol");
    ch_b->on_open = [&](const uint8_t*, size_t) { b_opened = true; };

    // Both sides open — they should pair
    ch_a->open();
    ch_b->open();

    EXPECT_TRUE(a_opened);
    EXPECT_TRUE(b_opened);
}

TEST(Protomux, ChannelClose) {
    LoopbackMux mux;

    bool b_closed = false;

    auto* ch_a = mux.a.create_channel("proto");
    auto* ch_b = mux.b.create_channel("proto");
    ch_b->on_close = [&]() { b_closed = true; };

    ch_a->open();
    ch_b->open();
    EXPECT_TRUE(ch_a->is_open());

    // close() sends CLOSE message to remote, then calls destroy() which
    // frees the channel via remove_channel. After this call, ch_a is a
    // dangling pointer — do not dereference it.
    ch_a->close();

    // The remote side (ch_b) should have received the CLOSE and fired its callback.
    EXPECT_TRUE(b_closed);
}

// ---------------------------------------------------------------------------
// Message dispatch
// ---------------------------------------------------------------------------

TEST(Protomux, SendReceiveMessage) {
    LoopbackMux mux;

    std::vector<uint8_t> received;

    auto* ch_a = mux.a.create_channel("echo");
    auto* ch_b = mux.b.create_channel("echo");

    ch_a->add_message(MessageHandler{});  // type 0 on A (unused)
    ch_b->add_message(MessageHandler{     // type 0 on B
        [&](const uint8_t* data, size_t len) {
            received.assign(data, data + len);
        }
    });

    ch_a->open();
    ch_b->open();

    // Send from A to B
    std::vector<uint8_t> msg = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    EXPECT_TRUE(ch_a->send(0, msg.data(), msg.size()));

    ASSERT_EQ(received.size(), 5u);
    EXPECT_EQ(received, msg);
}

TEST(Protomux, MultipleMessageTypes) {
    LoopbackMux mux;

    int type0_count = 0;
    int type1_count = 0;

    auto* ch_a = mux.a.create_channel("multi");
    auto* ch_b = mux.b.create_channel("multi");

    ch_a->add_message(MessageHandler{});  // type 0
    ch_a->add_message(MessageHandler{});  // type 1

    ch_b->add_message(MessageHandler{
        [&](const uint8_t*, size_t) { type0_count++; }
    });
    ch_b->add_message(MessageHandler{
        [&](const uint8_t*, size_t) { type1_count++; }
    });

    ch_a->open();
    ch_b->open();

    uint8_t data = 0;
    ch_a->send(0, &data, 1);
    ch_a->send(1, &data, 1);
    ch_a->send(0, &data, 1);

    EXPECT_EQ(type0_count, 2);
    EXPECT_EQ(type1_count, 1);
}

// ---------------------------------------------------------------------------
// Handshake data
// ---------------------------------------------------------------------------

TEST(Protomux, HandshakeExchange) {
    LoopbackMux mux;

    std::vector<uint8_t> a_received_hs;
    std::vector<uint8_t> b_received_hs;

    auto* ch_a = mux.a.create_channel("hs-proto");
    ch_a->on_open = [&](const uint8_t* hs, size_t len) {
        a_received_hs.assign(hs, hs + len);
    };

    auto* ch_b = mux.b.create_channel("hs-proto");
    ch_b->on_open = [&](const uint8_t* hs, size_t len) {
        b_received_hs.assign(hs, hs + len);
    };

    std::vector<uint8_t> hs_a = {1, 2, 3};
    std::vector<uint8_t> hs_b = {4, 5, 6, 7};

    ch_a->open(hs_a.data(), hs_a.size());
    ch_b->open(hs_b.data(), hs_b.size());

    EXPECT_EQ(a_received_hs, hs_b);
    EXPECT_EQ(b_received_hs, hs_a);
}

// ---------------------------------------------------------------------------
// Multiple channels
// ---------------------------------------------------------------------------

TEST(Protomux, MultipleChannels) {
    LoopbackMux mux;

    int ch1_msgs = 0;
    int ch2_msgs = 0;

    auto* a1 = mux.a.create_channel("proto-1");
    auto* a2 = mux.a.create_channel("proto-2");
    auto* b1 = mux.b.create_channel("proto-1");
    auto* b2 = mux.b.create_channel("proto-2");

    a1->add_message(MessageHandler{});
    a2->add_message(MessageHandler{});
    b1->add_message(MessageHandler{[&](const uint8_t*, size_t) { ch1_msgs++; }});
    b2->add_message(MessageHandler{[&](const uint8_t*, size_t) { ch2_msgs++; }});

    a1->open(); b1->open();
    a2->open(); b2->open();

    uint8_t data = 0;
    a1->send(0, &data, 1);
    a2->send(0, &data, 1);
    a2->send(0, &data, 1);

    EXPECT_EQ(ch1_msgs, 1);
    EXPECT_EQ(ch2_msgs, 2);
}

// ---------------------------------------------------------------------------
// Send before open should fail
// ---------------------------------------------------------------------------

TEST(Protomux, SendBeforeOpenFails) {
    LoopbackMux mux;
    auto* ch = mux.a.create_channel("proto");
    ch->add_message(MessageHandler{});

    uint8_t data = 0;
    EXPECT_FALSE(ch->send(0, &data, 1));
}

// ---------------------------------------------------------------------------
// Channel with binary ID
// ---------------------------------------------------------------------------

TEST(Protomux, ChannelWithBinaryId) {
    LoopbackMux mux;

    bool paired = false;
    std::vector<uint8_t> id = {0xDE, 0xAD, 0xBE, 0xEF};

    auto* ch_a = mux.a.create_channel("id-proto", id);
    ch_a->on_open = [&](const uint8_t*, size_t) { paired = true; };

    auto* ch_b = mux.b.create_channel("id-proto", id);
    ch_a->open();
    ch_b->open();

    EXPECT_TRUE(paired);
}

TEST(Protomux, DifferentIdsDontPair) {
    LoopbackMux mux;

    bool a_opened = false;

    auto* ch_a = mux.a.create_channel("proto", {0x01});
    ch_a->on_open = [&](const uint8_t*, size_t) { a_opened = true; };

    auto* ch_b = mux.b.create_channel("proto", {0x02});

    ch_a->open();
    ch_b->open();

    EXPECT_FALSE(a_opened) << "Different IDs should not pair";
}
