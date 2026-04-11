// Live cross-test: mutable/immutable put/get against the real DHT network.
//
// Drives the tests through the PUBLIC `HyperDHT` class API — the same
// code path a real consumer app would use. This validates the §5 wrapper
// layer (HyperDHT::immutable_put/get, HyperDHT::mutable_put/get) end-to-end,
// not just the underlying `dht_ops::*` primitives.
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

#include "hyperdht/dht.hpp"
#include "hyperdht/noise_wrap.hpp"

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
//
// Uses HyperDHT::immutable_put and HyperDHT::mutable_put so the live run
// exercises the §5 wrapper layer + its result struct population.
// ---------------------------------------------------------------------------

TEST(StorageLive, CppPut) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);
    ASSERT_EQ(dht.bind(), 0);
    printf("  Bound HyperDHT on port %u\n", dht.port());

    bool imm_done = false;
    bool mut_done = false;
    std::array<uint8_t, 32> imm_hash{};
    noise::PubKey mut_pubkey{};
    uint64_t returned_seq = 0;
    std::array<uint8_t, 64> returned_sig{};
    size_t imm_closest_nodes = 0;
    size_t mut_closest_nodes = 0;

    // --- Immutable Put ---
    std::vector<uint8_t> imm_value = {'h', 'e', 'l', 'l', 'o', ' ',
                                       'f', 'r', 'o', 'm', ' ', 'C', '+', '+'};

    printf("  Immutable PUT: value='hello from C++'\n");
    auto imm_q = dht.immutable_put(imm_value,
        [&](const HyperDHT::ImmutablePutResult& r) {
            imm_done = true;
            imm_hash = r.hash;
            imm_closest_nodes = r.closest_nodes.size();
            printf("  Immutable PUT done: hash=%s (%zu closest nodes)\n",
                   to_hex(r.hash.data(), 32).c_str(),
                   r.closest_nodes.size());
        });
    ASSERT_NE(imm_q, nullptr);

    // --- Mutable Put ---
    auto kp = noise::generate_keypair();  // Random keypair for each run
    printf("  Mutable PUT keypair: %s\n",
           to_hex(kp.public_key.data(), 32).c_str());

    std::vector<uint8_t> mut_value = {'m', 'u', 't', 'a', 'b', 'l', 'e', ' ',
                                       'f', 'r', 'o', 'm', ' ', 'C', '+', '+'};
    uint64_t seq = 1;

    printf("  Mutable PUT: value='mutable from C++' seq=%lu\n", seq);
    auto mut_q = dht.mutable_put(kp, mut_value, seq,
        [&](const HyperDHT::MutablePutResult& r) {
            mut_done = true;
            mut_pubkey = r.public_key;
            returned_seq = r.seq;
            returned_sig = r.signature;
            mut_closest_nodes = r.closest_nodes.size();
            printf("  Mutable PUT done: pubkey=%s seq=%lu (%zu closest nodes)\n",
                   to_hex(r.public_key.data(), 32).c_str(),
                   r.seq, r.closest_nodes.size());
        });
    ASSERT_NE(mut_q, nullptr);

    // Timeout to bound the test
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &dht;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* d = static_cast<HyperDHT*>(t->data);
        d->destroy();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 20000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    printf("  Immutable done: %s\n", imm_done ? "yes" : "no");
    printf("  Mutable done: %s\n", mut_done ? "yes" : "no");
    EXPECT_TRUE(imm_done) << "Immutable PUT should complete";
    EXPECT_TRUE(mut_done) << "Mutable PUT should complete";

    // Verify the result struct fields populate correctly — this is the
    // §5 wrapper contract. An app that passes the returned fields to
    // a second process (e.g. displayed as a reconnect token) MUST see
    // valid hash / pubkey / seq / signature.
    if (imm_done) {
        // hash must match BLAKE2b(value) locally
        std::array<uint8_t, 32> expected_hash{};
        crypto_generichash(expected_hash.data(), 32,
                           imm_value.data(), imm_value.size(), nullptr, 0);
        EXPECT_EQ(imm_hash, expected_hash)
            << "ImmutablePutResult.hash must equal BLAKE2b(value)";
        EXPECT_GT(imm_closest_nodes, 0u)
            << "ImmutablePutResult.closest_nodes must be populated";
    }
    if (mut_done) {
        EXPECT_EQ(mut_pubkey, kp.public_key)
            << "MutablePutResult.public_key must match the signing key";
        EXPECT_EQ(returned_seq, seq)
            << "MutablePutResult.seq must echo the input seq";
        // Signature must be non-zero (we can't verify here without the
        // primitive, but zero would indicate a bug)
        bool sig_nonzero = false;
        for (auto b : returned_sig) { if (b != 0) { sig_nonzero = true; break; } }
        EXPECT_TRUE(sig_nonzero) << "MutablePutResult.signature must be populated";
        EXPECT_GT(mut_closest_nodes, 0u)
            << "MutablePutResult.closest_nodes must be populated";
    }

    if (imm_done && mut_done) {
        printf("\n  JS can retrieve with:\n");
        printf("    node storage_get.js %s %s\n",
               to_hex(imm_hash.data(), 32).c_str(),
               to_hex(kp.public_key.data(), 32).c_str());
    }
}

// ---------------------------------------------------------------------------
// C++ Get — retrieve values put by JS (pass hashes via env vars)
//
// Uses HyperDHT::immutable_get and HyperDHT::mutable_get so the live run
// exercises the §5 wrapper layer including the streaming on_value callback
// overload that the C FFI also depends on.
// ---------------------------------------------------------------------------

TEST(StorageLive, CppGet) {
    const char* imm_hex = std::getenv("IMMUTABLE_HASH");
    const char* mut_hex = std::getenv("MUTABLE_PUBKEY");

    if (!imm_hex && !mut_hex) {
        GTEST_SKIP() << "Set IMMUTABLE_HASH and/or MUTABLE_PUBKEY env vars";
    }

    uv_loop_t loop;
    uv_loop_init(&loop);

    HyperDHT dht(&loop);
    ASSERT_EQ(dht.bind(), 0);
    printf("  Bound HyperDHT on port %u\n", dht.port());

    bool imm_done_fired = false;
    bool mut_done_fired = false;
    HyperDHT::ImmutableGetResult imm_result;
    HyperDHT::MutableGetResult mut_result;
    int imm_stream_calls = 0;
    int mut_stream_calls = 0;

    // --- Immutable Get (streaming overload) ---
    if (imm_hex && strlen(imm_hex) == 64) {
        auto target = hex_to_32(imm_hex);
        printf("  Immutable GET: %s\n", imm_hex);

        dht.immutable_get(target,
            // Streaming per-reply callback — counts how many DHT nodes
            // answered with a verified value.
            [&](const std::vector<uint8_t>& value) {
                imm_stream_calls++;
                std::string s(value.begin(), value.end());
                printf("  [stream %d] GOT: '%s'\n", imm_stream_calls, s.c_str());
            },
            // Query-complete callback — aggregated result (first match).
            [&](const HyperDHT::ImmutableGetResult& r) {
                imm_done_fired = true;
                imm_result = r;
                printf("  Immutable GET done: found=%d value='%s' "
                       "(stream calls=%d)\n",
                       r.found ? 1 : 0,
                       r.found ? std::string(r.value.begin(),
                                              r.value.end()).c_str() : "(none)",
                       imm_stream_calls);
            });
    }

    // --- Mutable Get (streaming overload) ---
    if (mut_hex && strlen(mut_hex) == 64) {
        auto pubkey_arr = hex_to_32(mut_hex);
        noise::PubKey pubkey{};
        std::copy(pubkey_arr.begin(), pubkey_arr.end(), pubkey.begin());
        printf("  Mutable GET: %s\n", mut_hex);

        dht.mutable_get(pubkey, /*min_seq=*/0, /*latest=*/true,
            // Streaming per-reply callback
            [&](const dht_ops::MutableResult& r) {
                mut_stream_calls++;
                std::string s(r.value.begin(), r.value.end());
                printf("  [stream %d] GOT seq=%lu value='%s'\n",
                       mut_stream_calls, r.seq, s.c_str());
            },
            // Query-complete callback — latest-seq winner
            [&](const HyperDHT::MutableGetResult& r) {
                mut_done_fired = true;
                mut_result = r;
                printf("  Mutable GET done: found=%d seq=%lu value='%s' "
                       "(stream calls=%d)\n",
                       r.found ? 1 : 0, r.seq,
                       r.found ? std::string(r.value.begin(),
                                              r.value.end()).c_str() : "(none)",
                       mut_stream_calls);
            });
    }

    // Timeout
    uv_timer_t timer;
    uv_timer_init(&loop, &timer);
    timer.data = &dht;
    uv_timer_start(&timer, [](uv_timer_t* t) {
        auto* d = static_cast<HyperDHT*>(t->data);
        d->destroy();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 20000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    if (imm_hex) {
        EXPECT_TRUE(imm_done_fired) << "ImmutableGet on_done must fire";
        EXPECT_TRUE(imm_result.found) << "Immutable value not found on DHT";
        EXPECT_GT(imm_stream_calls, 0)
            << "Streaming on_value callback must fire at least once";
    }
    if (mut_hex) {
        EXPECT_TRUE(mut_done_fired) << "MutableGet on_done must fire";
        EXPECT_TRUE(mut_result.found) << "Mutable value not found on DHT";
        EXPECT_GT(mut_stream_calls, 0)
            << "Streaming on_value callback must fire at least once";
        EXPECT_GT(mut_result.seq, 0u) << "Mutable result seq must be set";
    }
}
