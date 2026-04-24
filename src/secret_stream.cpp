// SecretStream implementation — wraps Noise IK keys into libsodium's
// XChaCha20-Poly1305 secretstream. Performs the 56-byte header
// exchange (stream_id + header) before encrypted payloads flow.
//
// SecretStreamDuplex extends this with UDX I/O, frame parsing, and the
// user-facing duplex API matching JS @hyperswarm/secret-stream.

#include "hyperdht/secret_stream.hpp"

#include <sodium.h>

#include <cassert>
#include <cstdlib>
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
//
// JS: .analysis/js/@hyperswarm/secret-stream/index.js:373-397 (_setupSecretStream
//     — wraps Push/Pull, computes stream id, writes header frame)
//     .analysis/js/@hyperswarm/secret-stream/index.js:629-632 (streamId helper)
//
// C++ diffs from JS:
//   - JS combines header generation + raw write in _setupSecretStream; C++
//     splits into create_header_message() (caller writes it) so the duplex
//     wrapper owns the actual UDX write.
//   - JS uses a streamx Push/Pull pair; C++ uses raw libsodium
//     crypto_secretstream_xchacha20poly1305 state.
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

// JS: index.js:304-326 — _incoming() in setup phase: verifies remoteId,
//     calls _decrypt.init(header), then flips _setup = false.
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

// JS: index.js:471-501 — _write(): wraps payload with uint24 length prefix +
//     ABYTES, calls _encrypt.next(plain, wrapped.subarray(3)), refreshes
//     keepalive timer.
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

// JS: index.js:328-350 — _incoming() data path: refreshes timeout, calls
//     _decrypt.next, suppresses empty keepalive frames.
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
//
// JS: .analysis/js/@hyperswarm/secret-stream/index.js:93-116 (setTimeout / setKeepAlive
//     — uses the `timeout-refresh` package, which `refresh()`es on each I/O)
//     .analysis/js/@hyperswarm/secret-stream/index.js:520-532 (_clearTimeout / _clearKeepAlive)
//     .analysis/js/@hyperswarm/secret-stream/index.js:638-645 (destroyTimeout / sendKeepAlive)
//
// C++ diffs from JS:
//   - JS leans on `timeout-refresh` (refs/unrefs the libuv handle for free);
//     C++ uses raw uv_timer_t and emulates "refresh on I/O" via uv_timer_again.
//   - C++ nulls timer->data in stop_timer() to defend against late callbacks
//     after destruction (single-threaded libuv makes this very unlikely but
//     the check is cheap).
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
    // Stop the timer — timeout fires once.
    uv_timer_stop(handle);
    // Guard against a late fire after stop_timer() nulled `data`: in
    // single-threaded libuv this is extremely unlikely, but the check is
    // cheap and makes the callback safe against any future reordering.
    auto* self = static_cast<SecretStream*>(handle->data);
    if (!self) return;
    if (self->on_timeout_) self->on_timeout_();
}

void SecretStream::on_keepalive_cb(uv_timer_t* handle) {
    auto* self = static_cast<SecretStream*>(handle->data);
    if (!self) return;  // see on_timeout_cb comment
    if (self->on_keepalive_) self->on_keepalive_();
}

void SecretStream::on_timer_close(uv_handle_t* handle) {
    delete reinterpret_cast<uv_timer_t*>(handle);
}

// ===========================================================================
// SecretStreamDuplex
// ===========================================================================

// NS_SEND — third namespace value from `crypto.namespace('hyperswarm/secret-stream', 3)`.
// Used to derive secretbox keys for unordered UDP messages (JS: `_setupSecretSend`).
static const uint8_t NS_SEND[32] = {
    0xcb, 0x46, 0xcf, 0x52, 0xdc, 0xaf, 0x3d, 0x69,
    0xe9, 0xed, 0x0c, 0x56, 0x47, 0x51, 0xb1, 0x1d,
    0xe9, 0xe7, 0x7c, 0x3e, 0xa2, 0x8c, 0xaa, 0xc5,
    0xa9, 0xf7, 0x5c, 0xd2, 0x30, 0xd6, 0xc8, 0x35
};

// Per-write context — owns the encrypted buffer until the ack fires.
// `alive` is a weak_ptr to the owning Duplex's liveness flag; if the
// Duplex is destroyed before the ack arrives, the lock() returns null
// and the callback bails out without dereferencing the stale owner.
struct DuplexWriteCtx {
    SecretStreamDuplex* owner;
    std::weak_ptr<bool> alive;
    std::vector<uint8_t> buf;
    SecretStreamDuplex::WriteDoneCb cb;
};

// Per-send context — owns the secretbox envelope until the send ack fires.
struct DuplexSendCtx {
    SecretStreamDuplex* owner;
    std::weak_ptr<bool> alive;
    std::vector<uint8_t> buf;
};

// ---------------------------------------------------------------------------
// SecretStreamDuplex — constructor + destructor
//
// JS: .analysis/js/@hyperswarm/secret-stream/index.js:15-83 (NoiseSecretStream
//     constructor — sets handshake state, parser state, opens promise)
//     .analysis/js/@hyperswarm/secret-stream/index.js:534-539 (_destroy)
//
// C++ diffs from JS:
//   - JS extends streamx Duplex and tracks liveness via the `destroyed`/
//     `destroying` flags inherited from streamx; C++ uses
//     `std::shared_ptr<bool> alive_` + weak_ptr in every write context so
//     in-flight UDX ack callbacks bail out cleanly when the duplex dies.
//   - JS clears `rawStream` reference in `_predestroy`; C++ nulls
//     raw_stream_->data so any late on_udx_read/on_udx_close fires through
//     `if (!self) return`.
// ---------------------------------------------------------------------------

SecretStreamDuplex::SecretStreamDuplex(udx_stream_t* raw_stream,
                                       const DuplexHandshake& hs,
                                       uv_loop_t* loop,
                                       DuplexOptions opts)
    : raw_stream_(raw_stream),
      loop_(loop),
      hs_(hs),
      opts_(std::move(opts)),
      crypto_(hs.tx_key, hs.rx_key, hs.handshake_hash, hs.is_initiator, loop),
      alive_(std::make_shared<bool>(true)) {

    if (opts_.enable_send) {
        setup_secret_send();
    }
}

SecretStreamDuplex::~SecretStreamDuplex() {
    // Mark ourselves dead BEFORE detaching the raw stream, so any in-flight
    // write/send ack callback that runs after us sees a null weak_ptr and
    // bails out before touching `owner`.
    *alive_ = false;

    // Stop timers if destroy() wasn't called first. The timers use async
    // uv_close — their on_timer_close callback frees the timer handle
    // on the next uv_run iteration. We null timer->data so the callback
    // doesn't dereference the now-dead SecretStream.
    crypto_.stop_timers();

    // Detach from the raw stream so any pending UDX read/close callback
    // also sees a null `data` pointer.
    if (raw_stream_) {
        raw_stream_->data = nullptr;
    }
    // Sensitive key material is wiped by SecretStream's own destructor.
    sodium_memzero(secretbox_tx_key_.data(), secretbox_tx_key_.size());
    sodium_memzero(secretbox_rx_key_.data(), secretbox_rx_key_.size());
}

// ---------------------------------------------------------------------------
// Secret send setup — derives two secretbox keys from the handshake hash.
// Mirrors JS `_setupSecretSend`: the initiator's TX key is a keyed BLAKE2b
// of [NS_INITIATOR, NS_SEND] with the hash as the key, and the responder's
// is the dual. We also pick a random 8-byte counter initial for nonces.
// ---------------------------------------------------------------------------

// JS: index.js:399-421 — _setupSecretSend(): derives encrypt/decrypt secrets
//     via crypto_generichash_batch over [NS_(INI|RES), NS_SEND] keyed by the
//     handshake hash, then randomises the 8-byte nonce counter.
void SecretStreamDuplex::setup_secret_send() {
    // JS uses crypto_generichash_batch which hashes a sequence of inputs.
    // Equivalent: init state, update with each input, finalize.
    auto batch_hash = [](std::array<uint8_t, 32>& out,
                         const uint8_t* in1, size_t in1_len,
                         const uint8_t* in2, size_t in2_len,
                         const uint8_t* key, size_t key_len) {
        crypto_generichash_state st;
        crypto_generichash_init(&st, key, key_len, 32);
        crypto_generichash_update(&st, in1, in1_len);
        crypto_generichash_update(&st, in2, in2_len);
        crypto_generichash_final(&st, out.data(), 32);
    };

    const uint8_t* first  = hs_.is_initiator ? NS_INITIATOR : NS_RESPONDER;
    const uint8_t* second = hs_.is_initiator ? NS_RESPONDER : NS_INITIATOR;

    batch_hash(secretbox_tx_key_,
               first,  32,
               NS_SEND, 32,
               hs_.handshake_hash.data(), noise::HASHLEN);

    batch_hash(secretbox_rx_key_,
               second, 32,
               NS_SEND, 32,
               hs_.handshake_hash.data(), noise::HASHLEN);

    // Random initial counter value (used for wrap detection).
    randombytes_buf(nonce_initial_.data(), nonce_initial_.size());
    nonce_counter_ = nonce_initial_;

    send_state_ready_ = true;
}

// ---------------------------------------------------------------------------
// start() — install read + close callbacks, send our header frame
//
// JS: .analysis/js/@hyperswarm/secret-stream/index.js:123-153 (start — wires
//     'data'/'end'/'drain'/'message' listeners, kicks the handshake)
//     .analysis/js/@hyperswarm/secret-stream/index.js:423-444 (_open — installs
//     listeners, fires _onhandshakert(send()) for the initiator)
//
// C++ diffs from JS:
//   - JS performs the Noise handshake here for the streamx Duplex; C++
//     receives an already-completed handshake (DuplexHandshake) so this
//     reduces to wiring UDX callbacks and emitting the 59-byte header frame.
// ---------------------------------------------------------------------------

void SecretStreamDuplex::start() {
    if (started_ || destroyed_) return;
    started_ = true;

    // Wire up our instance into the raw stream's data slot and callbacks.
    // The user is expected to have initialized the stream (udx_stream_init)
    // but NOT installed a read callback yet.
    raw_stream_->data = this;
    raw_stream_->on_read = nullptr;    // cleared — we install via recv/read_start
    raw_stream_->on_close = on_udx_close;

    // Start receiving reliable data frames + unordered messages (if enabled).
    udx_stream_read_start(raw_stream_, on_udx_read);
    if (opts_.enable_send) {
        udx_stream_recv_start(raw_stream_, on_udx_recv_message);
    }

    // Send our 59-byte header frame first.
    send_header_frame();

    // Configure timers from options.
    if (opts_.keep_alive_ms > 0) {
        set_keep_alive(opts_.keep_alive_ms);
    }
    if (opts_.timeout_ms > 0) {
        set_timeout(opts_.timeout_ms);
    }
}

// JS: index.js:373-397 — _setupSecretStream() also writes the header buffer
//     directly via this._rawStream.write(buf). C++ instead enqueues a
//     udx_stream_write request whose ack flips header_sent_ and may fire
//     on_connect via maybe_fire_connect().
void SecretStreamDuplex::send_header_frame() {
    auto header = crypto_.create_header_message();
    header_sent_ = false;  // will flip in the ack callback

    auto* ctx = new DuplexWriteCtx{this, alive_, std::move(header), nullptr};
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                   static_cast<unsigned int>(ctx->buf.size()));

    // udx_stream_write_t has a flexible array — heap-allocate with room for bufs.
    auto* wreq = static_cast<udx_stream_write_t*>(
        std::calloc(1, static_cast<size_t>(udx_stream_write_sizeof(1))));
    wreq->data = ctx;

    int rc = udx_stream_write(wreq, raw_stream_, &uv_buf, 1,
        [](udx_stream_write_t* req, int status, int /*unordered*/) {
            auto* ctx = static_cast<DuplexWriteCtx*>(req->data);
            auto alive = ctx->alive.lock();
            if (alive && *alive) {
                SecretStreamDuplex* self = ctx->owner;
                if (status >= 0) {
                    self->header_sent_ = true;
                    self->raw_bytes_written_ += ctx->buf.size();
                    self->maybe_fire_connect();
                } else {
                    self->destroy(status);
                }
            }
            delete ctx;
            std::free(req);
        });

    if (rc < 0) {
        // udx_stream_write failed synchronously — cleanup and error out.
        delete ctx;
        std::free(wreq);
        destroy(rc);
    }
}

// ---------------------------------------------------------------------------
// write() — encrypt a plaintext payload and submit as a UDX write
//
// JS: .analysis/js/@hyperswarm/secret-stream/index.js:471-501 (_write — wraps
//     and encrypts in place, refreshes keepalive, parks cb in _drainDone if
//     the raw stream returns false)
//
// C++ diffs from JS:
//   - JS uses streamx's _write(data, cb) and parks the cb in `_drainDone`
//     for backpressure. C++ does NOT do streamx-style backpressure — every
//     write gets its own DuplexWriteCtx + udx_stream_write request and the
//     user cb fires directly from the ack callback.
//   - The DuplexWriteCtx::alive weak_ptr ensures the user cb is not invoked
//     after destroy(); see UAF safety note on the constructor.
// ---------------------------------------------------------------------------

int SecretStreamDuplex::write(const uint8_t* data, size_t len,
                              WriteDoneCb cb) {
    if (destroyed_ || ended_) return -1;
    if (!connected_) return -2;
    if (len > MAX_ATOMIC_WRITE) return -3;

    auto encrypted = crypto_.encrypt(data, len);
    if (encrypted.empty() && len != 0) return -4;

    auto* ctx = new DuplexWriteCtx{this, alive_, std::move(encrypted), std::move(cb)};
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                   static_cast<unsigned int>(ctx->buf.size()));

    auto* wreq = static_cast<udx_stream_write_t*>(
        std::calloc(1, static_cast<size_t>(udx_stream_write_sizeof(1))));
    wreq->data = ctx;

    int rc = udx_stream_write(wreq, raw_stream_, &uv_buf, 1,
        [](udx_stream_write_t* req, int status, int /*unordered*/) {
            auto* ctx = static_cast<DuplexWriteCtx*>(req->data);
            auto alive = ctx->alive.lock();
            if (alive && *alive) {
                SecretStreamDuplex* self = ctx->owner;
                if (status >= 0) {
                    self->raw_bytes_written_ += ctx->buf.size();
                }
                // Only fire the user cb if the owner is still alive — the
                // user may have captured `this` or other Duplex state in
                // the lambda. A dropped cb is acceptable when the owner
                // was destroyed out from under us.
                if (ctx->cb) ctx->cb(status);
            }
            delete ctx;
            std::free(req);
        });

    if (rc < 0) {
        delete ctx;
        std::free(wreq);
        return rc;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// end() — send a UDX write_end (empty body) to gracefully close the stream
// ---------------------------------------------------------------------------

// JS: index.js:503-508 — _final(cb): clears keepalive, decrements _ended,
//     calls this._rawStream.end(). C++ submits a udx_stream_write_end
//     request with no payload and lets UDX flush in-flight writes first.
void SecretStreamDuplex::end() {
    if (ended_ || destroyed_) return;
    ended_ = true;

    // udx_stream_write_sizeof requires nwbufs > 0 even when no buffers are
    // actually passed; test_udx.cpp uses sizeof(1) + (nullptr, 0).
    auto* wreq = static_cast<udx_stream_write_t*>(
        std::calloc(1, static_cast<size_t>(udx_stream_write_sizeof(1))));

    int rc = udx_stream_write_end(wreq, raw_stream_, nullptr, 0,
        [](udx_stream_write_t* req, int /*status*/, int /*unordered*/) {
            std::free(req);
        });
    if (rc < 0) {
        std::free(wreq);
        destroy(rc);
    }
}

// ---------------------------------------------------------------------------
// destroy() — immediate close. Fires on_close exactly once.
// ---------------------------------------------------------------------------

// JS: index.js:446-469 (_predestroy — cancels pending callbacks, destroys
//     rawStream) and index.js:534-539 (_destroy — clears timers, resolves
//     opened promise to false). C++ folds both into destroy() and lets the
//     UDX on_close callback fire fire_close().
void SecretStreamDuplex::destroy(int error) {
    if (destroyed_) return;
    destroyed_ = true;
    close_error_ = error;

    crypto_.stop_timers();

    if (raw_stream_) {
        // UDX destroy triggers on_udx_close, which calls fire_close.
        udx_stream_destroy(raw_stream_);
    } else {
        fire_close(error);
    }
}

void SecretStreamDuplex::fire_close(int err) {
    if (on_close_fired_) return;
    on_close_fired_ = true;
    if (on_close_) on_close_(err);
}

// ---------------------------------------------------------------------------
// Incoming data — frame parser state machine
//
// JS: .analysis/js/@hyperswarm/secret-stream/index.js:219-277 (_onrawdata —
//     two-state parser: state 0 reads uint24 length, state 1 accumulates
//     body, calls _incoming when complete)
//     .analysis/js/@hyperswarm/secret-stream/index.js:296-350 (_incoming —
//     dispatches to handshake/header/decrypt depending on _setup flag)
//
// C++ diffs from JS:
//   - JS uses a (state, len, tmp, message) FSM that interleaves length bytes
//     with body bytes; C++ uses a single accumulating recv_buf_ and a much
//     simpler "have we got 3 bytes? have we got the body?" loop in
//     try_extract_frame(). Behaviour matches at the byte level.
//   - C++ matches JS's split-message convention via the boolean
//     header_received_ — first frame is the 56-byte header, every subsequent
//     frame is encrypted payload.
//   - C++ enforces an explicit upper bound (MAX_ATOMIC_WRITE + ABYTES) and
//     rejects zero-length frames; JS just lets the secretstream auth fail.
// ---------------------------------------------------------------------------

void SecretStreamDuplex::process_incoming_bytes(const uint8_t* data, size_t len) {
    if (len == 0) return;
    raw_bytes_read_ += len;
    recv_buf_.insert(recv_buf_.end(), data, data + len);

    // Extract as many complete frames as possible.
    while (!destroyed_ && try_extract_frame()) {
        // loop
    }
}

bool SecretStreamDuplex::try_extract_frame() {
    if (recv_buf_.size() < 3) return false;

    uint32_t frame_len = read_uint24_le(recv_buf_.data());

    // Enforce the same upper bound we apply to outgoing writes, plus
    // the header-frame size (ID_HEADER_BYTES = 56). Anything larger is a
    // protocol violation and we shouldn't keep accumulating bytes waiting
    // for the full body — destroy the stream immediately.
    constexpr uint32_t FRAME_LEN_MAX =
        static_cast<uint32_t>(MAX_ATOMIC_WRITE + ABYTES);
    if (frame_len > FRAME_LEN_MAX) {
        destroy(-9);  // oversized frame
        return false;
    }

    // Explicitly reject zero-length frames — they are not a valid
    // secretstream frame (a legitimate frame always carries at least a
    // 1-byte tag + 16-byte MAC).
    if (frame_len == 0) {
        destroy(-10);
        return false;
    }

    if (recv_buf_.size() < 3 + frame_len) return false;

    // Copy the frame body out and consume it from the buffer.
    std::vector<uint8_t> body(recv_buf_.begin() + 3,
                              recv_buf_.begin() + 3 + frame_len);
    recv_buf_.erase(recv_buf_.begin(),
                    recv_buf_.begin() + 3 + frame_len);

    handle_frame(std::move(body));
    return true;
}

void SecretStreamDuplex::handle_frame(std::vector<uint8_t> msg) {
    if (!header_received_) {
        // First frame is the 56-byte header.
        if (msg.size() != ID_HEADER_BYTES) {
            destroy(-5);
            return;
        }
        if (!crypto_.receive_header(msg.data(), msg.size())) {
            destroy(-6);
            return;
        }
        header_received_ = true;
        maybe_fire_connect();
        return;
    }

    // Data frame — decrypt. decrypt() returns nullopt for suppressed empty
    // keepalives OR on auth failure; we treat both as "no message to deliver".
    auto plain = crypto_.decrypt(msg.data(), msg.size());
    if (!plain.has_value()) return;

    // JS buffers data that arrives before on_connect via Node.js Readable
    // stream internals. We do the same explicitly: queue messages until
    // the header exchange is complete, then replay in maybe_fire_connect().
    if (!connected_) {
        pending_messages_.push_back(std::move(*plain));
        // Cap: prevent unbounded growth from a malicious peer flooding
        // data before the header exchange completes. The window is
        // normally sub-RTT (1-2 messages), so 64 is very generous.
        // JS mitigates this via Node.js Readable highWaterMark backpressure.
        // Long-term fix: read-side backpressure (udx_stream_read_stop).
        if (pending_messages_.size() > 64) {
            destroy(-7);
        }
        return;
    }
    if (on_message_) on_message_(plain->data(), plain->size());
}

void SecretStreamDuplex::maybe_fire_connect() {
    if (connected_) return;
    if (!header_sent_ || !header_received_) return;
    connected_ = true;
    if (on_connect_) on_connect_();

    // Replay messages that arrived before the header exchange completed.
    // JS does this implicitly via Node.js Readable buffer; we do it
    // explicitly. Move the queue out first — on_message_ callbacks may
    // trigger re-entrant writes that modify state.
    auto pending = std::move(pending_messages_);
    for (const auto& msg : pending) {
        if (destroyed_ || !on_message_) break;
        on_message_(msg.data(), msg.size());
    }
}

// ---------------------------------------------------------------------------
// Unordered secretbox send/recv
//
// JS: .analysis/js/@hyperswarm/secret-stream/index.js:541-562 (_boxMessage —
//     increments counter, fails on wrap-to-initial, builds 8B counter +
//     16B MAC + ciphertext envelope)
//     .analysis/js/@hyperswarm/secret-stream/index.js:564-579 (send / trySend)
//     .analysis/js/@hyperswarm/secret-stream/index.js:580-601 (_onmessage —
//     reverses the envelope and emits 'message')
// ---------------------------------------------------------------------------

std::vector<uint8_t> SecretStreamDuplex::box_message(const uint8_t* data,
                                                      size_t len) {
    // Increment the 8-byte counter (LE), detect wrap-to-initial.
    sodium_increment(nonce_counter_.data(), nonce_counter_.size());
    if (nonce_counter_ == nonce_initial_) {
        // Exhausted the entire counter space — must destroy the stream.
        destroy(-7);
        return {};
    }

    // Envelope layout: 8-byte counter prefix + MAC + ciphertext.
    // Total length: 8 + crypto_secretbox_MACBYTES + len
    constexpr size_t NB = crypto_secretbox_NONCEBYTES;   // 24
    constexpr size_t MB = crypto_secretbox_MACBYTES;     // 16

    std::vector<uint8_t> env(8 + MB + len);

    // Write 8-byte counter prefix (JS uses this as the on-wire "nonce" bytes).
    std::memcpy(env.data(), nonce_counter_.data(), 8);

    // Build the full 24-byte nonce (8 counter bytes + 16 zero pad).
    uint8_t nonce[NB];
    std::memset(nonce, 0, NB);
    std::memcpy(nonce, nonce_counter_.data(), 8);

    int rc = crypto_secretbox_easy(env.data() + 8, data, len,
                                    nonce, secretbox_tx_key_.data());
    if (rc != 0) return {};
    return env;
}

bool SecretStreamDuplex::unbox_message(const uint8_t* data, size_t len,
                                        std::vector<uint8_t>& out) {
    constexpr size_t NB = crypto_secretbox_NONCEBYTES;
    constexpr size_t MB = crypto_secretbox_MACBYTES;

    if (len < 8 + MB) return false;  // too small to contain anything

    uint8_t nonce[NB];
    std::memset(nonce, 0, NB);
    std::memcpy(nonce, data, 8);

    const uint8_t* ct = data + 8;
    size_t ct_len = len - 8;

    out.resize(ct_len - MB);
    int rc = crypto_secretbox_open_easy(out.data(), ct, ct_len,
                                         nonce, secretbox_rx_key_.data());
    if (rc != 0) {
        out.clear();
        return false;
    }
    return true;
}

int SecretStreamDuplex::send_udp(const uint8_t* data, size_t len) {
    if (destroyed_ || !send_state_ready_) return -1;

    auto env = box_message(data, len);
    if (env.empty()) return -2;

    auto* ctx = new DuplexSendCtx{this, alive_, std::move(env)};
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                   static_cast<unsigned int>(ctx->buf.size()));

    // udx_stream_send_t has no flexible array member — value-initialize.
    auto* sreq = new udx_stream_send_t{};
    sreq->data = ctx;

    int rc = udx_stream_send(sreq, raw_stream_, &uv_buf, 1,
        [](udx_stream_send_t* req, int /*status*/) {
            auto* ctx = static_cast<DuplexSendCtx*>(req->data);
            // No owner-touching work needed — the envelope is owned by the
            // ctx and deleted unconditionally.
            delete ctx;
            delete req;
        });
    if (rc < 0) {
        delete ctx;
        delete sreq;
        return rc;
    }
    return 0;
}

int SecretStreamDuplex::try_send_udp(const uint8_t* data, size_t len) {
    // JS `trySend` is fire-and-forget — we just delegate.
    return send_udp(data, len);
}

// ---------------------------------------------------------------------------
// Timer forwarding
//
// JS: .analysis/js/@hyperswarm/secret-stream/index.js:93-121 (setTimeout /
//     setKeepAlive / sendKeepAlive — keepAlive sends an empty alloc()'d frame)
//     .analysis/js/@hyperswarm/secret-stream/index.js:638-645 (destroyTimeout /
//     sendKeepAlive helpers)
// ---------------------------------------------------------------------------

void SecretStreamDuplex::set_timeout(uint64_t ms) {
    crypto_.set_timeout(ms, [this]() { destroy(-8); });
}

void SecretStreamDuplex::set_keep_alive(uint64_t ms) {
    crypto_.set_keep_alive(ms, [this]() {
        // Send an empty encrypted frame. The peer's matching keep_alive
        // swallows it silently (SecretStream::decrypt returns nullopt).
        if (connected_ && !destroyed_) {
            write(nullptr, 0, nullptr);
        }
    });
}

// ---------------------------------------------------------------------------
// UDX callbacks
//
// JS: .analysis/js/@hyperswarm/secret-stream/index.js:211-294 (_onrawerror /
//     _onrawclose / _onrawdata / _onrawend / _onrawdrain — streamx event
//     handlers attached in _open)
//     .analysis/js/@hyperswarm/secret-stream/index.js:580-601 (_onmessage —
//     handler for the unordered UDP message channel)
// ---------------------------------------------------------------------------

void SecretStreamDuplex::on_udx_read(udx_stream_t* s, ssize_t nread,
                                     const uv_buf_t* buf) {
    auto* self = static_cast<SecretStreamDuplex*>(s->data);
    if (!self) return;

    if (nread == UV_EOF) {
        if (self->on_end_) self->on_end_();
        return;
    }
    if (nread < 0) {
        self->destroy(static_cast<int>(nread));
        return;
    }

    self->process_incoming_bytes(
        reinterpret_cast<const uint8_t*>(buf->base),
        static_cast<size_t>(nread));
}

void SecretStreamDuplex::on_udx_close(udx_stream_t* s, int err) {
    auto* self = static_cast<SecretStreamDuplex*>(s->data);
    if (!self) return;
    // Break the back-pointer so a late UDX callback doesn't find `this`
    // mid-destruction.
    s->data = nullptr;
    self->destroyed_ = true;
    // Prefer the error code the caller supplied to destroy() (if any) —
    // libudx always passes 0 here even when we aborted for a protocol
    // error like a malformed frame.
    int report_err = self->close_error_ != 0 ? self->close_error_ : err;
    self->fire_close(report_err);
}

void SecretStreamDuplex::on_udx_recv_message(udx_stream_t* s, ssize_t nread,
                                             const uv_buf_t* buf) {
    auto* self = static_cast<SecretStreamDuplex*>(s->data);
    if (!self || !self->send_state_ready_) return;
    if (nread <= 0) return;

    std::vector<uint8_t> plain;
    if (!self->unbox_message(
            reinterpret_cast<const uint8_t*>(buf->base),
            static_cast<size_t>(nread),
            plain)) {
        return;  // invalid / auth failed — silently drop (matches JS)
    }
    if (self->on_udp_message_) {
        self->on_udp_message_(plain.data(), plain.size());
    }
}

}  // namespace secret_stream
}  // namespace hyperdht
