#pragma once

// Phase 5: SecretStream — XChaCha20-Poly1305 secretstream encryption
// Wraps Noise IK handshake keys into libsodium's secretstream for
// ongoing encrypted communication.
//
// Wire format:
//   Header (first message): uint24_le(56) + stream_id(32) + secretstream_header(24)
//   Data messages:          uint24_le(len) + encrypted_payload(len)
//     where encrypted_payload = tag(1) + ciphertext + mac(16)

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/noise_wrap.hpp"

namespace hyperdht {
namespace secret_stream {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr size_t KEYBYTES = 32;           // XChaCha20 key
constexpr size_t HEADERBYTES = 24;        // secretstream header
constexpr size_t ABYTES = 17;             // 1 tag byte + 16 MAC
constexpr size_t STREAM_ID_LEN = 32;      // Stream ID (BLAKE2b-256)
constexpr size_t ID_HEADER_BYTES = HEADERBYTES + STREAM_ID_LEN;  // 56

using StreamId = std::array<uint8_t, STREAM_ID_LEN>;
using Key = std::array<uint8_t, KEYBYTES>;

// ---------------------------------------------------------------------------
// Stream ID computation
// ---------------------------------------------------------------------------

// stream_id = BLAKE2b-256(NS_INITIATOR_or_RESPONDER, handshake_hash)
StreamId compute_stream_id(const noise::Hash& handshake_hash, bool is_initiator);

// ---------------------------------------------------------------------------
// uint24_le framing helpers
// ---------------------------------------------------------------------------

void write_uint24_le(uint8_t* buf, uint32_t value);
uint32_t read_uint24_le(const uint8_t* buf);

// ---------------------------------------------------------------------------
// SecretStream — encrypts/decrypts messages using secretstream
// ---------------------------------------------------------------------------

// Callbacks for timer events
using OnTimeoutCallback = std::function<void()>;
using OnKeepaliveCallback = std::function<void()>;

class SecretStream {
public:
    // Initialize from completed Noise IK handshake results
    // tx_key: our transmit key (from Noise split)
    // rx_key: our receive key (from Noise split)
    // handshake_hash: from completed Noise handshake
    // is_initiator: which side of the handshake we are
    // loop: optional libuv event loop for timer support (nullptr to disable)
    SecretStream(const Key& tx_key, const Key& rx_key,
                 const noise::Hash& handshake_hash, bool is_initiator,
                 uv_loop_t* loop = nullptr);

    ~SecretStream();

    // Non-copyable, non-movable (holds crypto state + timer handles)
    SecretStream(const SecretStream&) = delete;
    SecretStream& operator=(const SecretStream&) = delete;
    SecretStream(SecretStream&&) = delete;
    SecretStream& operator=(SecretStream&&) = delete;

    // Generate our header message (59 bytes: 3 + 56)
    // Must be sent as the FIRST message on the stream
    std::vector<uint8_t> create_header_message();

    // Process the remote's header message
    // Input: the 56-byte payload (after stripping uint24_le length prefix)
    // Returns false if stream ID doesn't match or header is invalid
    bool receive_header(const uint8_t* data, size_t len);

    // Is the stream ready for data? (both header sent and received)
    bool is_ready() const;

    // Encrypt a message for sending
    // Returns: framed message (uint24_le(len) + encrypted_payload)
    // Also refreshes the keepalive timer (we just sent data)
    std::vector<uint8_t> encrypt(const uint8_t* data, size_t len);

    // Decrypt a received message
    // Input: the encrypted payload (after stripping uint24_le length prefix)
    // Returns: decrypted plaintext, or nullopt on auth failure
    // Also refreshes the timeout timer (we just received data)
    // Empty messages (0-byte plaintext) are suppressed when keepalive is active
    std::optional<std::vector<uint8_t>> decrypt(const uint8_t* data, size_t len);

    // -----------------------------------------------------------------------
    // Keepalive / Timeout (matches JS @hyperswarm/secret-stream)
    // -----------------------------------------------------------------------

    // Set inactivity timeout (ms). If no data is received within this window,
    // the on_timeout callback fires. 0 = disabled. Refreshed on every decrypt().
    void set_timeout(uint64_t ms, OnTimeoutCallback cb);

    // Set keepalive interval (ms). If no data is sent within this window,
    // the on_keepalive callback fires (caller should send an empty message).
    // 0 = disabled. Refreshed on every encrypt().
    void set_keep_alive(uint64_t ms, OnKeepaliveCallback cb);

    // Stop all timers (call before destroying the stream)
    void stop_timers();

    // Current timer values
    uint64_t timeout() const { return timeout_ms_; }
    uint64_t keep_alive() const { return keep_alive_ms_; }

    // Our stream ID and expected remote stream ID
    const StreamId& local_id() const { return local_id_; }
    const StreamId& remote_id() const { return remote_id_; }

    // Buffer size matches actual libsodium state
    static constexpr size_t STATE_BUF_SIZE = sizeof(crypto_secretstream_xchacha20poly1305_state);

private:
    bool is_initiator_;
    bool header_sent_ = false;
    bool header_received_ = false;

    StreamId local_id_;
    StreamId remote_id_;

    alignas(8) uint8_t push_state_[STATE_BUF_SIZE];
    alignas(8) uint8_t pull_state_[STATE_BUF_SIZE];

    Key tx_key_;
    Key rx_key_;
    uint8_t header_bytes_[HEADERBYTES];  // Generated during push init

    // Timer state
    uv_loop_t* loop_ = nullptr;
    uint64_t timeout_ms_ = 0;
    uint64_t keep_alive_ms_ = 0;
    uv_timer_t* timeout_timer_ = nullptr;
    uv_timer_t* keepalive_timer_ = nullptr;
    OnTimeoutCallback on_timeout_;
    OnKeepaliveCallback on_keepalive_;

    void start_timeout_timer();
    void start_keepalive_timer();
    void stop_timer(uv_timer_t*& timer);

    static void on_timeout_cb(uv_timer_t* handle);
    static void on_keepalive_cb(uv_timer_t* handle);
    static void on_timer_close(uv_handle_t* handle);
};

}  // namespace secret_stream
}  // namespace hyperdht
