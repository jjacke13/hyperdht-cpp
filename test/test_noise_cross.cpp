#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/noise_wrap.hpp"

using namespace hyperdht::noise;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(hex_chars[data[i] >> 4]);
        out.push_back(hex_chars[data[i] & 0x0F]);
    }
    return out;
}

template <size_t N>
static std::string to_hex(const std::array<uint8_t, N>& arr) {
    return to_hex(arr.data(), N);
}

static std::string to_hex(const std::vector<uint8_t>& v) {
    return to_hex(v.data(), v.size());
}

static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        auto byte_str = hex.substr(i * 2, 2);
        out[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Compute the real HyperDHT prologue: NS_PEER_HANDSHAKE
// crypto.namespace('hyperswarm/dht', [4,5,6,0,1])[3]
//
// namespace(name, ids):
//   ns[0:32] = BLAKE2b("hyperswarm/dht")
//   for each id: output[i] = BLAKE2b(ns[0:32] || id_byte)
//
// PEER_HANDSHAKE command = 0, but it's the 4th element [4,5,6,0,1]
// so ns_byte = 0 for PEER_HANDSHAKE
// ---------------------------------------------------------------------------

static std::array<uint8_t, 32> compute_ns_peer_handshake() {
    // Step 1: BLAKE2b-256("hyperswarm/dht") → 32 bytes
    uint8_t ns_hash[32];
    const char* name = "hyperswarm/dht";
    crypto_generichash(ns_hash, 32,
                       reinterpret_cast<const uint8_t*>(name), std::strlen(name),
                       nullptr, 0);

    // Step 2: ns = ns_hash || command_byte(0)
    uint8_t ns_input[33];
    std::memcpy(ns_input, ns_hash, 32);
    ns_input[32] = 0;  // PEER_HANDSHAKE command = 0

    // Step 3: BLAKE2b-256(ns_input) → 32 bytes
    std::array<uint8_t, 32> result{};
    crypto_generichash(result.data(), 32, ns_input, 33, nullptr, 0);
    return result;
}

// ---------------------------------------------------------------------------
// Cross-test context for pipe communication
// ---------------------------------------------------------------------------

struct NoiseCrossCtx {
    std::string js_output;
    std::string pipe_buf;
    uv_pipe_t stdout_pipe;
    uv_pipe_t stdin_pipe;
    uv_process_t process;
    std::string msg1_hex;
    bool write_done = false;
};

static void on_alloc(uv_handle_t*, size_t suggested, uv_buf_t* buf) {
    buf->base = new char[suggested];
    buf->len = static_cast<unsigned int>(suggested);
}

static void on_close_handle(uv_handle_t*) {}

static void on_pipe_read(uv_stream_t* pipe, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<NoiseCrossCtx*>(pipe->data);
    if (nread > 0) {
        ctx->js_output.append(buf->base, static_cast<size_t>(nread));
    }
    delete[] buf->base;
}

static void on_write_done(uv_write_t* req, int) {
    auto* ctx = static_cast<NoiseCrossCtx*>(req->data);
    ctx->write_done = true;
    // Close stdin pipe to signal EOF to the child
    uv_close(reinterpret_cast<uv_handle_t*>(&ctx->stdin_pipe), on_close_handle);
    delete req;
}

static void on_process_exit(uv_process_t* proc, int64_t, int) {
    auto* ctx = static_cast<NoiseCrossCtx*>(proc->data);
    uv_close(reinterpret_cast<uv_handle_t*>(&ctx->stdout_pipe), on_close_handle);
    uv_close(reinterpret_cast<uv_handle_t*>(proc), on_close_handle);
}

// ---------------------------------------------------------------------------
// Test: C++ initiator ↔ JS responder Noise IK handshake
// Uses the REAL HyperDHT prologue (NS_PEER_HANDSHAKE)
// ---------------------------------------------------------------------------

TEST(NoiseCross, HandshakeWithJS) {
    // Compute real prologue
    auto prologue = compute_ns_peer_handshake();
    EXPECT_EQ(to_hex(prologue),
        "14d6d4b49214ab1033ed204976caa258bae9e1e8543b9ad1fd996a910b0c4e3a")
        << "Prologue should match JS NS_PEER_HANDSHAKE";

    // Create C++ initiator with fixed seed
    Seed i_seed{};
    i_seed.fill(0x00);
    auto i_kp = generate_keypair(i_seed);

    // Responder pubkey (JS uses seed 0xFF*32)
    Seed r_seed{};
    r_seed.fill(0xFF);
    auto r_kp = generate_keypair(r_seed);

    // Create Noise IK initiator with real prologue
    NoiseIK initiator(true, i_kp, prologue.data(), prologue.size(),
                      &r_kp.public_key);

    // Generate msg1
    auto msg1 = initiator.send();
    ASSERT_EQ(msg1.size(), 96u);

    // Spawn JS responder
    uv_loop_t loop;
    uv_loop_init(&loop);

    NoiseCrossCtx ctx;
    ctx.msg1_hex = to_hex(msg1) + "\n";

    uv_pipe_init(&loop, &ctx.stdin_pipe, 0);
    uv_pipe_init(&loop, &ctx.stdout_pipe, 0);
    ctx.stdin_pipe.data = &ctx;
    ctx.stdout_pipe.data = &ctx;

    std::string test_dir = __FILE__;
    test_dir = test_dir.substr(0, test_dir.rfind('/'));
    std::string script = test_dir + "/js/noise_responder.js";

    char* args[] = {
        const_cast<char*>("node"),
        const_cast<char*>(script.c_str()),
        nullptr
    };

    uv_process_options_t opts{};
    uv_stdio_container_t stdio[3];
    // stdin: parent writes, child reads
    stdio[0].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_READABLE_PIPE);
    stdio[0].data.stream = reinterpret_cast<uv_stream_t*>(&ctx.stdin_pipe);
    // stdout: child writes, parent reads
    stdio[1].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
    stdio[1].data.stream = reinterpret_cast<uv_stream_t*>(&ctx.stdout_pipe);
    // stderr: inherit
    stdio[2].flags = UV_INHERIT_FD;
    stdio[2].data.fd = 2;
    opts.stdio_count = 3;
    opts.stdio = stdio;
    opts.file = "node";
    opts.args = args;
    opts.exit_cb = on_process_exit;
    ctx.process.data = &ctx;

    int rc = uv_spawn(&loop, &ctx.process, &opts);
    ASSERT_EQ(rc, 0) << "Failed to spawn node: " << uv_strerror(rc);

    // Write msg1 hex to stdin
    auto* write_req = new uv_write_t;
    write_req->data = &ctx;
    uv_buf_t wbuf = uv_buf_init(const_cast<char*>(ctx.msg1_hex.data()),
                                  static_cast<unsigned int>(ctx.msg1_hex.size()));
    uv_write(write_req, reinterpret_cast<uv_stream_t*>(&ctx.stdin_pipe),
             &wbuf, 1, on_write_done);

    // Read stdout
    uv_read_start(reinterpret_cast<uv_stream_t*>(&ctx.stdout_pipe),
                  on_alloc, on_pipe_read);

    uv_run(&loop, UV_RUN_DEFAULT);

    // Parse JS output: msg2_hex\nhash_hex\ntx_hex\nrx_hex\nremote_pk_hex\n
    std::vector<std::string> lines;
    std::string line;
    for (char c : ctx.js_output) {
        if (c == '\n') {
            if (!line.empty()) lines.push_back(line);
            line.clear();
        } else {
            line.push_back(c);
        }
    }
    if (!line.empty()) lines.push_back(line);

    ASSERT_GE(lines.size(), 5u) << "Expected 5 lines from JS, got "
        << lines.size() << ": " << ctx.js_output;

    auto msg2_hex = lines[0];
    auto js_hash_hex = lines[1];
    auto js_tx_hex = lines[2];
    auto js_rx_hex = lines[3];
    auto js_remote_pk_hex = lines[4];

    // Process msg2 on C++ side
    auto msg2_bytes = from_hex(msg2_hex);
    ASSERT_EQ(msg2_bytes.size(), 48u) << "msg2 should be 48 bytes";

    auto payload2 = initiator.recv(msg2_bytes.data(), msg2_bytes.size());
    ASSERT_TRUE(payload2.has_value()) << "C++ should decrypt JS msg2";
    EXPECT_TRUE(initiator.is_complete());

    // Verify handshake hash matches
    EXPECT_EQ(to_hex(initiator.handshake_hash()), js_hash_hex)
        << "Handshake hash should match between C++ and JS";

    // Verify keys are complementary:
    // C++ initiator tx = JS responder rx
    // C++ initiator rx = JS responder tx
    EXPECT_EQ(to_hex(initiator.tx_key()), js_rx_hex)
        << "C++ tx should equal JS rx (responder's rx is initiator's tx)";
    EXPECT_EQ(to_hex(initiator.rx_key()), js_tx_hex)
        << "C++ rx should equal JS tx (responder's tx is initiator's rx)";

    // Verify JS correctly identified our public key
    EXPECT_EQ(js_remote_pk_hex, to_hex(i_kp.public_key))
        << "JS should identify C++ initiator's public key";

    uv_loop_close(&loop);
}
