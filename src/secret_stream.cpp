#include "hyperdht/secret_stream.hpp"

#include <sodium.h>

#include <cassert>
#include <cstring>

namespace hyperdht {
namespace secret_stream {

// STATE_BUF_SIZE now uses sizeof directly — no assertion needed

// Namespace values: crypto.namespace('hyperswarm/secret-stream', 3)
// Computed as: BLAKE2b-256(BLAKE2b-256("hyperswarm/secret-stream") || index_byte)
static const uint8_t NS_INITIATOR[32] = {
    0xa9, 0x31, 0xa0, 0x15, 0x5b, 0x5c, 0x09, 0xe6,
    0xd2, 0x86, 0x28, 0x23, 0x6a, 0xf8, 0x3c, 0x4b,
    0x8a, 0x6a, 0xf9, 0xaf, 0x60, 0x98, 0x6e, 0xde,
    0xed, 0xe9, 0xdc, 0x5d, 0x63, 0x19, 0x2b, 0xf7
};
static const uint8_t NS_RESPONDER[32] = {
    0x74, 0x2c, 0x9d, 0x83, 0x3d, 0x43, 0x0a, 0xf4,
    0xc4, 0x8a, 0x87, 0x05, 0xe9, 0x16, 0x31, 0xee,
    0xcf, 0x29, 0x54, 0x42, 0xbb, 0xca, 0x18, 0x99,
    0x6e, 0x59, 0x70, 0x97, 0x72, 0x3b, 0x10, 0x61
};

// ---------------------------------------------------------------------------
// Stream ID
// ---------------------------------------------------------------------------

StreamId compute_stream_id(const noise::Hash& handshake_hash, bool is_initiator) {
    StreamId id{};
    const uint8_t* ns = is_initiator ? NS_INITIATOR : NS_RESPONDER;
    // BLAKE2b-256(ns, handshake_hash) — ns is the "message", handshake_hash is the "key"
    crypto_generichash(id.data(), STREAM_ID_LEN,
                       ns, 32,
                       handshake_hash.data(), noise::HASHLEN);
    return id;
}

// ---------------------------------------------------------------------------
// uint24_le framing
// ---------------------------------------------------------------------------

void write_uint24_le(uint8_t* buf, uint32_t value) {
    buf[0] = static_cast<uint8_t>(value);
    buf[1] = static_cast<uint8_t>(value >> 8);
    buf[2] = static_cast<uint8_t>(value >> 16);
}

uint32_t read_uint24_le(const uint8_t* buf) {
    return static_cast<uint32_t>(buf[0])
         | (static_cast<uint32_t>(buf[1]) << 8)
         | (static_cast<uint32_t>(buf[2]) << 16);
}

// ---------------------------------------------------------------------------
// SecretStream
// ---------------------------------------------------------------------------

SecretStream::SecretStream(const Key& tx_key, const Key& rx_key,
                           const noise::Hash& handshake_hash, bool is_initiator,
                           uv_loop_t* loop)
    : is_initiator_(is_initiator), tx_key_(tx_key), rx_key_(rx_key), loop_(loop) {

    // Compute stream IDs
    local_id_ = compute_stream_id(handshake_hash, is_initiator);
    remote_id_ = compute_stream_id(handshake_hash, !is_initiator);

    // Initialize Push (encrypt) state — generates the 24-byte header
    auto* push = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state*>(push_state_);
    crypto_secretstream_xchacha20poly1305_init_push(push, header_bytes_, tx_key_.data());
}

SecretStream::~SecretStream() {
    stop_timers();
    sodium_memzero(push_state_, sizeof(push_state_));
    sodium_memzero(pull_state_, sizeof(pull_state_));
    sodium_memzero(tx_key_.data(), KEYBYTES);
    sodium_memzero(rx_key_.data(), KEYBYTES);
}

std::vector<uint8_t> SecretStream::create_header_message() {
    // Wire format: uint24_le(56) + stream_id(32) + header(24) = 59 bytes
    std::vector<uint8_t> msg(3 + ID_HEADER_BYTES);
    write_uint24_le(msg.data(), static_cast<uint32_t>(ID_HEADER_BYTES));
    std::memcpy(msg.data() + 3, local_id_.data(), STREAM_ID_LEN);
    std::memcpy(msg.data() + 3 + STREAM_ID_LEN, header_bytes_, HEADERBYTES);
    header_sent_ = true;
    return msg;
}

bool SecretStream::receive_header(const uint8_t* data, size_t len) {
    if (len != ID_HEADER_BYTES) return false;

    // Verify stream ID
    StreamId received_id{};
    std::memcpy(received_id.data(), data, STREAM_ID_LEN);
    if (received_id != remote_id_) return false;

    // Initialize Pull (decrypt) state with the 24-byte header
    const uint8_t* header = data + STREAM_ID_LEN;
    auto* pull = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state*>(pull_state_);
    int rc = crypto_secretstream_xchacha20poly1305_init_pull(pull, header, rx_key_.data());
    if (rc != 0) return false;

    header_received_ = true;
    return true;
}

bool SecretStream::is_ready() const {
    return header_sent_ && header_received_;
}

std::vector<uint8_t> SecretStream::encrypt(const uint8_t* data, size_t len) {
    if (!is_ready()) return {};  // Runtime guard (assert stripped in release)

    // uint24_le max = 0xFFFFFF = 16777215
    if (len > 0xFFFFFF - ABYTES) return {};  // Guard overflow before comparison

    // Encrypted payload: tag(1) + ciphertext + mac(16) = len + ABYTES
    size_t enc_len = len + ABYTES;
    std::vector<uint8_t> msg(3 + enc_len);

    // Length prefix
    write_uint24_le(msg.data(), static_cast<uint32_t>(enc_len));

    // Encrypt
    auto* push = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state*>(push_state_);
    unsigned long long out_len = 0;
    int rc = crypto_secretstream_xchacha20poly1305_push(
        push,
        msg.data() + 3, &out_len,
        data, len,
        nullptr, 0,  // no additional data
        crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
    if (rc != 0) return {};

    // Correct size in case out_len differs from expected
    msg.resize(3 + static_cast<size_t>(out_len));
    write_uint24_le(msg.data(), static_cast<uint32_t>(out_len));

    // Refresh keepalive timer — we just sent data
    if (keepalive_timer_ != nullptr) {
        uv_timer_again(keepalive_timer_);
    }

    return msg;
}

std::optional<std::vector<uint8_t>> SecretStream::decrypt(const uint8_t* data, size_t len) {
    if (!is_ready()) return std::nullopt;  // Runtime guard (assert stripped in release)

    if (len < ABYTES) return std::nullopt;

    // Refresh timeout timer — we just received data
    if (timeout_timer_ != nullptr) {
        uv_timer_again(timeout_timer_);
    }

    std::vector<uint8_t> pt(len - ABYTES);
    unsigned long long pt_len = 0;
    unsigned char tag = 0;

    auto* pull = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state*>(pull_state_);
    int rc = crypto_secretstream_xchacha20poly1305_pull(
        pull,
        pt.data(), &pt_len, &tag,
        data, len,
        nullptr, 0);  // no additional data

    if (rc != 0) return std::nullopt;
    pt.resize(static_cast<size_t>(pt_len));

    // Suppress empty keepalive messages (JS: if plain.byteLength === 0 && keepAlive !== 0)
    if (pt.empty() && keep_alive_ms_ > 0) {
        return std::nullopt;
    }

    return pt;
}

// ---------------------------------------------------------------------------
// Timer management
// ---------------------------------------------------------------------------

void SecretStream::set_timeout(uint64_t ms, OnTimeoutCallback cb) {
    stop_timer(timeout_timer_);
    timeout_ms_ = ms;
    on_timeout_ = std::move(cb);
    if (ms > 0 && loop_ != nullptr) {
        start_timeout_timer();
    }
}

void SecretStream::set_keep_alive(uint64_t ms, OnKeepaliveCallback cb) {
    stop_timer(keepalive_timer_);
    keep_alive_ms_ = ms;
    on_keepalive_ = std::move(cb);
    if (ms > 0 && loop_ != nullptr) {
        start_keepalive_timer();
    }
}

void SecretStream::stop_timers() {
    stop_timer(timeout_timer_);
    stop_timer(keepalive_timer_);
}

void SecretStream::start_timeout_timer() {
    timeout_timer_ = new uv_timer_t;
    uv_timer_init(loop_, timeout_timer_);
    timeout_timer_->data = this;
    // Single-fire: fires once after timeout_ms_, repeat=timeout_ms_ for uv_timer_again
    uv_timer_start(timeout_timer_, on_timeout_cb, timeout_ms_, timeout_ms_);
}

void SecretStream::start_keepalive_timer() {
    keepalive_timer_ = new uv_timer_t;
    uv_timer_init(loop_, keepalive_timer_);
    keepalive_timer_->data = this;
    // Repeating: fires every keep_alive_ms_ of idle
    uv_timer_start(keepalive_timer_, on_keepalive_cb, keep_alive_ms_, keep_alive_ms_);
}

void SecretStream::stop_timer(uv_timer_t*& timer) {
    if (timer != nullptr) {
        uv_timer_stop(timer);
        timer->data = nullptr;  // Prevent stale this in callback
        uv_close(reinterpret_cast<uv_handle_t*>(timer), on_timer_close);
        timer = nullptr;
    }
}

void SecretStream::on_timeout_cb(uv_timer_t* handle) {
    auto* self = static_cast<SecretStream*>(handle->data);
    // Stop the timer — timeout fires once
    uv_timer_stop(handle);
    if (self->on_timeout_) {
        self->on_timeout_();
    }
}

void SecretStream::on_keepalive_cb(uv_timer_t* handle) {
    auto* self = static_cast<SecretStream*>(handle->data);
    if (self->on_keepalive_) {
        self->on_keepalive_();
    }
}

void SecretStream::on_timer_close(uv_handle_t* handle) {
    delete reinterpret_cast<uv_timer_t*>(handle);
}

}  // namespace secret_stream
}  // namespace hyperdht
