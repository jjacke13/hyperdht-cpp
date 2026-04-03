// Live cross-test: mutable/immutable put/get against the real DHT network.
//
// Test 1 (C++ put): Put values, print hashes for JS to retrieve.
// Test 2 (C++ get): Retrieve values put by JS (hashes passed via env vars).
//
// Usage:
//   C++ put:  ./test_storage_live --gtest_filter='*CppPut*'
//   C++ get:  IMMUTABLE_HASH=<hex> MUTABLE_PUBKEY=<hex> ./test_storage_live --gtest_filter='*CppGet*'

#include <gtest/gtest.h>

#include <sodium.h>
#include <uv.h>

#include <cstdlib>
#include <cstring>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/compact.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/query.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"

using namespace hyperdht;

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; i++) {
        out.push_back(h[data[i] >> 4]);
        out.push_back(h[data[i] & 0x0F]);
    }
    return out;
}

static std::array<uint8_t, 32> hex_to_32(const char* hex) {
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        out[i] = static_cast<uint8_t>(byte);
    }
    return out;
}

// ---------------------------------------------------------------------------
// C++ Put — put values and print hashes for JS to retrieve
// ---------------------------------------------------------------------------

TEST(StorageLive, CppPut) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    ASSERT_EQ(socket.bind(0), 0);

    rpc::RpcHandlers handlers(socket);
    handlers.install();

    bool imm_done = false;
    bool mut_done = false;

    // --- Immutable Put ---
    std::vector<uint8_t> imm_value = {'h', 'e', 'l', 'l', 'o', ' ',
                                       'f', 'r', 'o', 'm', ' ', 'C', '+', '+'};
    std::array<uint8_t, 32> imm_hash{};
    crypto_generichash(imm_hash.data(), 32,
                       imm_value.data(), imm_value.size(),
                       nullptr, 0);

    printf("  Immutable PUT: value='hello from C++'\n");
    printf("  hash: %s\n", to_hex(imm_hash.data(), 32).c_str());

    auto imm_q = dht_ops::immutable_put(socket, imm_value,
        [&](const std::vector<query::QueryReply>&) { imm_done = true; });

    // --- Mutable Put ---
    noise::Seed seed{};
    seed.fill(0x77);
    auto kp = noise::generate_keypair(seed);

    std::vector<uint8_t> mut_value = {'m', 'u', 't', 'a', 'b', 'l', 'e', ' ',
                                       'f', 'r', 'o', 'm', ' ', 'C', '+', '+'};
    uint64_t seq = 1;

    printf("  Mutable PUT: value='mutable from C++' seq=%lu\n", seq);
    printf("  publicKey: %s\n", to_hex(kp.public_key.data(), 32).c_str());

    auto mut_q = dht_ops::mutable_put(socket, kp, mut_value, seq,
        [&](const std::vector<query::QueryReply>&) { mut_done = true; });

    // Timeout
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    struct TimerCtx { bool* imm; bool* mut; rpc::RpcSocket* sock; };
    TimerCtx tctx{&imm_done, &mut_done, &socket};
    timer.data = &tctx;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* c = static_cast<TimerCtx*>(t->data);
        c->sock->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 20000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    printf("  Immutable done: %s\n", imm_done ? "yes" : "no");
    printf("  Mutable done: %s\n", mut_done ? "yes" : "no");
    EXPECT_TRUE(imm_done) << "Immutable PUT should complete";
    EXPECT_TRUE(mut_done) << "Mutable PUT should complete";

    if (imm_done && mut_done) {
        printf("\n  JS can retrieve with:\n");
        printf("    node storage_get.js %s %s\n",
               to_hex(imm_hash.data(), 32).c_str(),
               to_hex(kp.public_key.data(), 32).c_str());
    }
}

// ---------------------------------------------------------------------------
// C++ Get — retrieve values put by JS (pass hashes via env vars)
// ---------------------------------------------------------------------------

TEST(StorageLive, CppGet) {
    const char* imm_hex = std::getenv("IMMUTABLE_HASH");
    const char* mut_hex = std::getenv("MUTABLE_PUBKEY");

    if (!imm_hex && !mut_hex) {
        GTEST_SKIP() << "Set IMMUTABLE_HASH and/or MUTABLE_PUBKEY env vars";
    }

    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    our_id.fill(0x42);
    rpc::RpcSocket socket(&loop, our_id);
    ASSERT_EQ(socket.bind(0), 0);

    rpc::RpcHandlers handlers(socket);
    handlers.install();

    bool imm_found = false;
    std::string imm_got;
    bool mut_found = false;
    uint64_t mut_seq = 0;
    std::string mut_got;

    // --- Immutable Get ---
    if (imm_hex && strlen(imm_hex) == 64) {
        auto target = hex_to_32(imm_hex);
        printf("  Immutable GET: %s\n", imm_hex);

        dht_ops::immutable_get(socket, target,
            [&](const std::vector<uint8_t>& value) {
                imm_found = true;
                imm_got = std::string(value.begin(), value.end());
                printf("  GOT: '%s'\n", imm_got.c_str());
            },
            [](const std::vector<query::QueryReply>&) {});
    }

    // --- Mutable Get ---
    if (mut_hex && strlen(mut_hex) == 64) {
        auto pubkey = hex_to_32(mut_hex);
        printf("  Mutable GET: %s\n", mut_hex);

        dht_ops::mutable_get(socket, pubkey, 0,
            [&](const dht_ops::MutableResult& result) {
                mut_found = true;
                mut_seq = result.seq;
                mut_got = std::string(result.value.begin(), result.value.end());
                printf("  GOT: seq=%lu value='%s'\n", result.seq, mut_got.c_str());
            },
            [](const std::vector<query::QueryReply>&) {});
    }

    // Timeout
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &socket;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* s = static_cast<rpc::RpcSocket*>(t->data);
        s->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 20000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    if (imm_hex) {
        EXPECT_TRUE(imm_found) << "Immutable value not found on DHT";
    }
    if (mut_hex) {
        EXPECT_TRUE(mut_found) << "Mutable value not found on DHT";
    }
}
