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
#include <memory>
#include <optional>
#include <vector>

#include <sodium.h>
#include <udx.h>
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

// ---------------------------------------------------------------------------
// SecretStreamDuplex — user-facing Duplex wrapper
//
// Composes a SecretStream crypto primitive with a caller-owned udx_stream_t
// to provide the full JS @hyperswarm/secret-stream API:
//   * Automatic header exchange (sends ours on start, parses theirs on read)
//   * Frame parser (uint24_le length + encrypted body)
//   * write() / end() / destroy() with drain callbacks
//   * on_connect / on_message / on_end / on_close events
//   * send_udp() / try_send_udp() unordered secretbox messages + on_udp_message
//   * set_timeout() / set_keep_alive() (delegates to SecretStream timers)
//
// Lifetime contract: the caller owns the udx_stream_t*. The Duplex installs
// its own read + close callbacks on the stream during start(), stores `this`
// in stream->data, and restores those slots on destruction. The caller MUST
// NOT destroy the stream before the Duplex is destroyed (or fires on_close).
// ---------------------------------------------------------------------------

// Max plaintext size per write — enforced by uint24_le frame length.
// Matches JS MAX_ATOMIC_WRITE = 0xFFFFFF (16 777 215) minus ABYTES.
constexpr size_t MAX_ATOMIC_WRITE = 0xFFFFFF - ABYTES;

// Pre-computed keys passed to SecretStreamDuplex constructor, equivalent to
// JS `handshake = { tx, rx, hash, publicKey, remotePublicKey }`.
struct DuplexHandshake {
    Key tx_key{};
    Key rx_key{};
    noise::Hash handshake_hash{};
    std::array<uint8_t, 32> public_key{};
    std::array<uint8_t, 32> remote_public_key{};
    bool is_initiator = false;
};

struct DuplexOptions {
    uint64_t keep_alive_ms = 0;   // 0 = disabled
    uint64_t timeout_ms    = 0;   // 0 = disabled
    bool enable_send       = true; // enable secretbox send/trySend + on_udp_message
};

class SecretStreamDuplex {
public:
    // Event callback types
    using OnConnectCb   = std::function<void()>;
    using OnMessageCb   = std::function<void(const uint8_t* data, size_t len)>;
    using OnEndCb       = std::function<void()>;
    using OnCloseCb     = std::function<void(int error)>;
    using OnUdpMsgCb    = std::function<void(const uint8_t* data, size_t len)>;
    using WriteDoneCb   = std::function<void(int status)>;

    // Construct: caller-initialized stream, pre-computed handshake keys,
    // event loop for timers. Does NOT take ownership of the raw_stream.
    SecretStreamDuplex(udx_stream_t* raw_stream,
                       const DuplexHandshake& hs,
                       uv_loop_t* loop,
                       DuplexOptions opts = {});

    ~SecretStreamDuplex();

    SecretStreamDuplex(const SecretStreamDuplex&) = delete;
    SecretStreamDuplex& operator=(const SecretStreamDuplex&) = delete;
    SecretStreamDuplex(SecretStreamDuplex&&) = delete;
    SecretStreamDuplex& operator=(SecretStreamDuplex&&) = delete;

    // Event registration. Set before start() for guaranteed delivery.
    void on_connect(OnConnectCb cb)     { on_connect_ = std::move(cb); }
    void on_message(OnMessageCb cb)     { on_message_ = std::move(cb); }
    void on_end(OnEndCb cb)             { on_end_ = std::move(cb); }
    void on_close(OnCloseCb cb)         { on_close_ = std::move(cb); }
    void on_udp_message(OnUdpMsgCb cb)  { on_udp_message_ = std::move(cb); }

    // Start I/O: installs udx read callback, sends our header frame.
    // Idempotent.
    void start();

    // Write plaintext data. Encrypts + frames + writes to the UDX stream.
    // `cb` fires with 0 on successful drain or a negative error code.
    // Returns 0 on submission success, or negative on error (e.g. too big,
    // not connected, already destroyed).
    int write(const uint8_t* data, size_t len, WriteDoneCb cb = nullptr);

    // Graceful shutdown: marks end-of-stream and triggers UDX write_end.
    // on_close fires once the underlying stream finishes closing.
    void end();

    // Immediate destroy. Passes `error` to on_close. Idempotent.
    void destroy(int error = 0);

    // Unordered UDP messages via secretbox. Bypasses the reliable stream.
    // Returns 0 on submission success, negative on error.
    // Requires enable_send == true in construction options.
    int send_udp(const uint8_t* data, size_t len);
    int try_send_udp(const uint8_t* data, size_t len);

    // Timer configuration (delegates to internal SecretStream).
    // Setting keep_alive > 0 makes the stream auto-write an empty frame
    // on idle; the peer's matching keep_alive will swallow it silently.
    // Setting timeout > 0 auto-destroys on idle receive.
    void set_timeout(uint64_t ms);
    void set_keep_alive(uint64_t ms);

    // State
    bool is_connected() const { return connected_; }
    bool is_destroyed() const { return destroyed_; }
    bool is_ended() const     { return ended_; }

    // Identity / metadata (zero-copy views)
    const StreamId& local_id()  const { return crypto_.local_id(); }
    const StreamId& remote_id() const { return crypto_.remote_id(); }
    const noise::Hash& handshake_hash() const { return hs_.handshake_hash; }
    const std::array<uint8_t, 32>& public_key() const { return hs_.public_key; }
    const std::array<uint8_t, 32>& remote_public_key() const {
        return hs_.remote_public_key;
    }
    bool is_initiator() const { return hs_.is_initiator; }

    // Traffic counters (bytes AFTER our framing + encryption).
    uint64_t raw_bytes_read()    const { return raw_bytes_read_; }
    uint64_t raw_bytes_written() const { return raw_bytes_written_; }

    // Current timer values (delegates to internal SecretStream). Useful
    // for tests that verify `DuplexOptions::keep_alive_ms` was applied.
    uint64_t keep_alive_ms() const { return crypto_.keep_alive(); }
    uint64_t timeout_ms()    const { return crypto_.timeout(); }

    // Access the underlying raw UDX stream (read-only). Caller should NOT
    // install their own callbacks while the Duplex owns the stream.
    udx_stream_t* raw_stream() { return raw_stream_; }

private:
    udx_stream_t* raw_stream_;
    uv_loop_t*    loop_;
    DuplexHandshake hs_;
    DuplexOptions   opts_;
    SecretStream    crypto_;

    // Lifecycle flags
    bool started_   = false;
    bool connected_ = false;   // both headers exchanged
    bool header_sent_ = false;
    bool header_received_ = false;
    bool ended_     = false;   // user called end()
    bool destroyed_ = false;
    bool read_started_ = false;
    int  close_error_ = 0;
    bool on_close_fired_ = false;

    // Incoming frame parser state
    std::vector<uint8_t> recv_buf_;  // byte accumulator (up to one full frame)

    // Unordered secretbox send/recv state (JS `_sendState`)
    bool send_state_ready_ = false;
    std::array<uint8_t, 32> secretbox_tx_key_{};
    std::array<uint8_t, 32> secretbox_rx_key_{};
    std::array<uint8_t, 8>  nonce_counter_{};  // current outgoing counter
    std::array<uint8_t, 8>  nonce_initial_{};  // counter wrap detection

    // Byte counters
    uint64_t raw_bytes_read_    = 0;
    uint64_t raw_bytes_written_ = 0;

    // Event callbacks
    OnConnectCb   on_connect_;
    OnMessageCb   on_message_;
    OnEndCb       on_end_;
    OnCloseCb     on_close_;
    OnUdpMsgCb    on_udp_message_;

    // Liveness flag shared with async callbacks. Set to true in the
    // constructor, reset to false in the destructor. Write/send ack
    // callbacks capture a copy of this shared_ptr and check it before
    // touching any instance state — this breaks the dangling-pointer
    // trap where an in-flight UDX callback runs after the Duplex is
    // destroyed.
    std::shared_ptr<bool> alive_;

    // Pending user write-done callbacks keyed by the write request pointer.
    // Stored via heap-alloc WriteCtx (see .cpp).

    // Helpers
    void setup_secret_send();
    void send_header_frame();
    void process_incoming_bytes(const uint8_t* data, size_t len);
    bool try_extract_frame();    // returns true if a full frame was consumed
    void handle_frame(std::vector<uint8_t> msg);
    void maybe_fire_connect();
    void fire_close(int err);
    std::vector<uint8_t> box_message(const uint8_t* data, size_t len);
    bool unbox_message(const uint8_t* data, size_t len,
                       std::vector<uint8_t>& out);

    // UDX callbacks — installed on the raw stream during start().
    static void on_udx_read(udx_stream_t* s, ssize_t nread, const uv_buf_t* buf);
    static void on_udx_close(udx_stream_t* s, int err);
    static void on_udx_recv_message(udx_stream_t* s, ssize_t nread, const uv_buf_t* buf);
};

}  // namespace secret_stream
}  // namespace hyperdht
