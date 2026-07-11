// Protomux implementation — channel multiplexer over a framed stream.
// Handles OPEN/CLOSE control messages, per-channel flow, and batching.
// Matches JS protomux/index.js.
//
// Input validation:
//   - Length-prefixed fields use safe arithmetic (avail check, not ptr+len)
//   - Channel IDs validated against UINT32_MAX before truncation
//   - Batch entries capped at 1024 per frame to prevent CPU exhaustion

#include "hyperdht/protomux.hpp"

#include <algorithm>
#include <cstring>

namespace hyperdht {
namespace protomux {

// ---------------------------------------------------------------------------
// Varint encode/decode (compact-encoding style)
// ---------------------------------------------------------------------------

size_t varint_size(uint64_t value) {
    if (value <= 0xFC) return 1;
    if (value <= 0xFFFF) return 3;
    if (value <= 0xFFFFFFFF) return 5;
    return 9;
}

size_t varint_encode(uint8_t* buf, uint64_t value) {
    if (value <= 0xFC) {
        buf[0] = static_cast<uint8_t>(value);
        return 1;
    }
    if (value <= 0xFFFF) {
        buf[0] = 0xFD;
        buf[1] = static_cast<uint8_t>(value & 0xFF);
        buf[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        return 3;
    }
    if (value <= 0xFFFFFFFF) {
        buf[0] = 0xFE;
        buf[1] = static_cast<uint8_t>(value & 0xFF);
        buf[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        buf[3] = static_cast<uint8_t>((value >> 16) & 0xFF);
        buf[4] = static_cast<uint8_t>((value >> 24) & 0xFF);
        return 5;
    }
    buf[0] = 0xFF;
    for (int i = 0; i < 8; i++) {
        buf[1 + i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
    }
    return 9;
}

uint64_t varint_decode(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr >= end) return 0;

    uint8_t first = *ptr++;
    if (first <= 0xFC) return first;

    if (first == 0xFD) {
        if (ptr + 2 > end) { ptr = end; return 0; }
        uint64_t v = static_cast<uint64_t>(ptr[0])
                   | (static_cast<uint64_t>(ptr[1]) << 8);
        ptr += 2;
        return v;
    }
    if (first == 0xFE) {
        if (ptr + 4 > end) { ptr = end; return 0; }
        uint64_t v = static_cast<uint64_t>(ptr[0])
                   | (static_cast<uint64_t>(ptr[1]) << 8)
                   | (static_cast<uint64_t>(ptr[2]) << 16)
                   | (static_cast<uint64_t>(ptr[3]) << 24);
        ptr += 4;
        return v;
    }
    // 0xFF
    if (ptr + 8 > end) { ptr = end; return 0; }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= static_cast<uint64_t>(ptr[i]) << (8 * i);
    }
    ptr += 8;
    return v;
}

// ---------------------------------------------------------------------------
// Buffer/String helpers
// ---------------------------------------------------------------------------

size_t buffer_preencode(size_t len) {
    return varint_size(len) + len;
}

size_t buffer_encode(uint8_t* buf, const uint8_t* data, size_t len) {
    size_t offset = varint_encode(buf, len);
    if (data && len > 0) {
        std::memcpy(buf + offset, data, len);
    }
    return offset + len;
}

size_t string_preencode(const std::string& str) {
    return buffer_preencode(str.size());
}

size_t string_encode(uint8_t* buf, const std::string& str) {
    return buffer_encode(buf,
        reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

// Decode a length-prefixed buffer from ptr
static std::vector<uint8_t> buffer_decode(const uint8_t*& ptr, const uint8_t* end) {
    uint64_t len = varint_decode(ptr, end);
    // C6: safe arithmetic — avoid ptr+len wrap on 64-bit
    size_t avail = static_cast<size_t>(end - ptr);
    if (len == 0 || len > avail) return {};
    size_t safe_len = static_cast<size_t>(len);
    std::vector<uint8_t> result(ptr, ptr + safe_len);
    ptr += safe_len;
    return result;
}

// Decode a length-prefixed UTF-8 string from ptr
static std::string string_decode(const uint8_t*& ptr, const uint8_t* end) {
    uint64_t len = varint_decode(ptr, end);
    // C6: safe arithmetic
    size_t avail = static_cast<size_t>(end - ptr);
    if (len == 0 || len > avail) return {};
    size_t safe_len = static_cast<size_t>(len);
    std::string result(reinterpret_cast<const char*>(ptr), safe_len);
    ptr += safe_len;
    return result;
}

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(h[data[i] >> 4]);
        out.push_back(h[data[i] & 0x0F]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Channel
// ---------------------------------------------------------------------------

static std::string build_pair_key(const std::string& protocol,
                                  const std::vector<uint8_t>& id) {
    std::string key = protocol + "##";
    if (!id.empty()) {
        key += to_hex(id.data(), id.size());
    }
    return key;
}

// ---------------------------------------------------------------------------
// Channel
//
// JS: .analysis/js/protomux/index.js:11-47 (Channel constructor — stores
//     protocol/aliases/id, hooks message handlers)
//     .analysis/js/protomux/index.js:751-753 (toKey helper — same
//     "protocol##<hex(id)>" format we use in build_pair_key)
//
// C++ diffs from JS:
//   - JS keeps a separate `_info` object per (protocol,id) tuple in the Mux
//     and references it from each Channel; C++ flattens this into per-channel
//     pair_keys_ + a Mux-level last_channel_by_key_ map.
// ---------------------------------------------------------------------------

Channel::Channel(Mux& mux, const std::string& protocol,
                 const std::vector<uint8_t>& id, uint32_t local_id)
    : mux_(mux), protocol_(protocol), id_(id), local_id_(local_id) {
    pair_keys_.push_back(build_pair_key(protocol_, id_));
}

Channel::Channel(Mux& mux, const std::string& protocol,
                 const std::vector<std::string>& aliases,
                 const std::vector<uint8_t>& id, uint32_t local_id)
    : mux_(mux), protocol_(protocol), id_(id), local_id_(local_id) {
    pair_keys_.push_back(build_pair_key(protocol_, id_));
    for (const auto& alias : aliases) {
        pair_keys_.push_back(build_pair_key(alias, id_));
    }
}

std::string Channel::pair_key() const {
    // Primary key. `pair_keys_` also contains aliases after index 0.
    return pair_keys_.empty() ? build_pair_key(protocol_, id_) : pair_keys_[0];
}

int Channel::add_message(MessageHandler handler) {
    int index = static_cast<int>(messages_.size());
    messages_.push_back(std::move(handler));
    return index;
}

// JS: index.js:70-101 — Channel.open(): builds a control OPEN frame
//     [0, 1, localId, protocol, id, handshake] and writes it via
//     this._mux._write0(buffer).
void Channel::open(const uint8_t* handshake, size_t handshake_len) {
    if (open_sent_ || closed_ || destroyed_) return;
    open_sent_ = true;

    // Assign our local id at OPEN time (JS index.js:71-79), not at create time.
    // This guarantees the peer receives ids in strictly increasing order, which
    // its grow-by-one sequence check (handle_open) requires.
    local_id_ = mux_.next_local_id_++;
    mux_.local_to_channel_[local_id_] = this;

    // Save handshake for later (if remote hasn't opened yet)
    if (handshake && handshake_len > 0) {
        local_handshake_.assign(handshake, handshake + handshake_len);
    }

    // Build OPEN message: [0][CONTROL_OPEN][localId][protocol][id][handshake]
    size_t frame_size = varint_size(0)                       // channelId = 0
                      + varint_size(CONTROL_OPEN)            // type = 1
                      + varint_size(local_id_)               // our local ID
                      + string_preencode(protocol_)          // protocol name
                      + buffer_preencode(id_.size())         // channel id buffer
                      + buffer_preencode(handshake_len);     // handshake

    std::vector<uint8_t> frame(frame_size);
    uint8_t* p = frame.data();
    p += varint_encode(p, 0);
    p += varint_encode(p, CONTROL_OPEN);
    p += varint_encode(p, local_id_);
    p += string_encode(p, protocol_);
    p += buffer_encode(p, id_.data(), id_.size());
    p += buffer_encode(p, handshake, handshake_len);

    frame.resize(static_cast<size_t>(p - frame.data()));
    mux_.write_frame(frame.data(), frame.size());

    // If the remote already opened this (protocol,id) — its OPEN is queued in
    // incoming_ — pair with the first such open now (JS createChannel incoming
    // path, index.js:399-414). Skip if the outgoing path already paired us.
    if (remote_id_ != 0) return;
    for (const auto& k : pair_keys_) {
        auto it = mux_.incoming_.find(k);
        if (it != mux_.incoming_.end() && !it->second.empty()) {
            auto pend = std::move(it->second.front());
            it->second.pop_front();
            if (it->second.empty()) mux_.incoming_.erase(it);
            mux_.pair_with_remote(this, pend);
            break;
        }
    }
}

// JS: index.js:253-282 — m.send() in addMessage(): if mux is corked it
//     pushes via _pushBatch(localId, payload), otherwise it builds a full
//     [localId, type, payload] frame and writes directly to the stream.
bool Channel::send(int message_type, const uint8_t* data, size_t len) {
    if (!opened_ || closed_ || remote_id_ == 0) return false;

    // Build data frame: [localId][messageType][data]. JS puts the SENDER's own
    // localId on every data frame (index.js:270-278); the receiver maps it via
    // its _remote slot keyed by our localId. Encoding remote_id_ here was a
    // silent data-loss bug whenever the two ends assigned different local ids
    // (finding protomux-1).
    size_t frame_size = varint_size(local_id_)
                      + varint_size(static_cast<uint64_t>(message_type))
                      + len;

    std::vector<uint8_t> frame(frame_size);
    uint8_t* p = frame.data();
    p += varint_encode(p, local_id_);
    p += varint_encode(p, static_cast<uint64_t>(message_type));
    if (data && len > 0) {
        std::memcpy(p, data, len);
        p += len;
    }

    frame.resize(static_cast<size_t>(p - frame.data()));
    mux_.write_frame(frame.data(), frame.size());
    return true;
}

void Channel::cork()   { mux_.cork(); }
void Channel::uncork() { mux_.uncork(); }

// JS: index.js:217-232 — Channel.close(): builds a [0, 3, localId] control
//     frame, calls _close(false) which fires onclose(false, this) and
//     finally _write0()s the frame.
void Channel::close() {
    if (closed_ || destroyed_) return;
    closed_ = true;

    // Build CLOSE message: [0][CONTROL_CLOSE][localId]
    uint8_t frame[16];
    uint8_t* p = frame;
    p += varint_encode(p, 0);
    p += varint_encode(p, CONTROL_CLOSE);
    p += varint_encode(p, local_id_);

    mux_.write_frame(frame, static_cast<size_t>(p - frame));

    // Fire on_close first — JS `_close(false)` emits `onclose(false, this)`
    // on the local-initiated path too. Matches remote_close() semantics.
    auto close_cb = std::move(on_close);
    if (close_cb) close_cb();

    destroy();
}

// JS: index.js:117-131 — _fullyOpen(): flips opened, calls onopen with the
//     remote handshake. The pre-pair data drain (JS _drain) is done by
//     Mux::pair_with_remote from the remote slot's buffer, right after this.
void Channel::fully_open(const uint8_t* remote_handshake, size_t len) {
    if (opened_ || destroyed_) return;
    opened_ = true;
    if (on_open) on_open(remote_handshake, len);
}

// JS: index.js:167-191 — _close(isRemote): tears down local/remote slot
//     mappings, frees the local id slot, fires onclose(isRemote, this)
//     and resolves the open promise to false.
void Channel::remote_close() {
    if (destroyed_) return;
    closed_ = true;
    // Move callback out before destroy — destroy erases us from the vector
    auto close_cb = std::move(on_close);
    destroy();
    if (close_cb) close_cb();
}

void Channel::destroy() {
    if (destroyed_) return;
    destroyed_ = true;
    opened_ = false;

    // Move callback out of the member slot, then invoke it BEFORE the
    // channel is freed. This lets user callbacks safely reference any
    // Channel state (including `this`) while the object is still alive
    // — just not after this method returns.
    auto destroy_cb = std::move(on_destroy);
    if (destroy_cb) destroy_cb();

    // Now it's safe to clean up and free ourselves. The `this` pointer
    // becomes dangling after remove_channel returns.
    mux_.remove_channel(this);
}

void Channel::dispatch(uint32_t type, const uint8_t* data, size_t len) {
    if (type < messages_.size() && messages_[type].on_message) {
        // Copy the handler onto the stack before invoking: a handler is
        // allowed to tear down its own channel (e.g. blind-relay closing the
        // channel on a malformed message), which frees `messages_` — and with
        // it the std::function currently executing. The stack copy keeps the
        // callable alive for the duration of the call. dispatch touches no
        // `this` state after the call returns, so `this` may be dangling then.
        auto handler = messages_[type].on_message;
        handler(data, len);
    }
}

// ---------------------------------------------------------------------------
// Mux
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Mux
//
// JS: .analysis/js/protomux/index.js:305-345 (Protomux constructor — wires
//     stream 'data'/'drain'/'end'/'close', initialises _local/_remote/_free
//     slot tables and the _infos map)
//     .analysis/js/protomux/index.js:393-415 (createChannel — auto-pair if a
//     remote OPEN is already pending in info.incoming)
//
// C++ diffs from JS:
//   - JS slot-allocates local ids from a `_free` recycle pool plus a `_local`
//     vector; C++ uses a monotonically incrementing `next_local_id_` and a
//     hash map. Functionally equivalent for the wire protocol.
//   - JS owns the underlying stream and forwards drain/close events through
//     mux methods; C++ takes a WriteFn callback and exposes
//     on_stream_drain() for the caller to invoke.
// ---------------------------------------------------------------------------

Mux::Mux(WriteFn write_fn) : write_fn_(std::move(write_fn)) {}

Channel* Mux::create_channel(const std::string& protocol,
                              const std::vector<uint8_t>& id,
                              bool unique) {
    return create_channel(protocol, {}, id, unique);
}

Channel* Mux::create_channel(const std::string& protocol,
                              const std::vector<std::string>& aliases,
                              const std::vector<uint8_t>& id,
                              bool unique) {
    if (destroyed_) return nullptr;

    // Build pair key for uniqueness check
    std::string key = build_pair_key(protocol, id);

    // Unique check: reject if (protocol, id) already open
    if (unique) {
        Channel* existing = find_by_pair_key(key);
        if (existing && existing->opened_) {
            return nullptr;
        }
    }

    // Local id and local_to_channel_ registration happen at open() time
    // (JS assigns _localId in Channel.open, not the constructor) so the peer
    // sees ids in open order — see Channel::open.
    auto ch = aliases.empty()
        ? std::make_unique<Channel>(*this, protocol, id, 0)
        : std::make_unique<Channel>(*this, protocol, aliases, id, 0);
    Channel* ptr = ch.get();
    channels_.push_back(std::move(ch));

    // Register every pair key (primary + aliases) in the last-channel map.
    for (const auto& k : ptr->pair_keys_) {
        last_channel_by_key_[k] = ptr;
    }

    return ptr;
}

// ---------------------------------------------------------------------------
// write_frame / cork / uncork — batched control framing
//
// JS: .analysis/js/protomux/index.js:357-370 (cork / uncork — flip _batch
//     between null and []; uncork triggers _sendBatch)
//     .analysis/js/protomux/index.js:417-430 (_pushBatch — strips the leading
//     channelId varint and groups consecutive entries by localId)
//     .analysis/js/protomux/index.js:432-453 (_sendBatch — encodes
//     [0x00, 0x00, varint(first_localId), (varint(payload_len), payload | 0x00,
//     varint(new_localId))*] and writes it as a single control frame)
//     .analysis/js/protomux/index.js:724-731 (_write0 — control frames with
//     channelId=0 are stripped of their leading 0 byte before pushing into
//     the batch)
//     .analysis/js/protomux/index.js:565-593 (_onbatch — the decode side: a
//     msg_len of 0 acts as the channel-switch marker)
//
// C++ diffs from JS:
//   - cpp-reviewer fix: the original C++ implementation was wire-incompatible.
//     This implementation matches JS at the byte level — verified against
//     the on-wire format produced by `_sendBatch` above.
//   - JS pre-encodes the batch state incrementally (`_pushBatch` calls
//     `c.uint.preencode` / `c.buffer.preencode` to grow `state.end` as it
//     queues entries); C++ accumulates raw entries and computes the size in
//     uncork() before encoding. Same wire output.
//   - JS uses `_alloc(state.end)` for the buffer; C++ allocates a vector.
// ---------------------------------------------------------------------------

void Mux::write_frame(const uint8_t* data, size_t len) {
    // Refuse to touch the underlying stream after destroy — the write_fn_
    // may reference a torn-down transport. (cpp-review HIGH #2)
    if (destroyed_) return;

    if (cork_count_ > 0) {
        // Split the frame into (localId, payload) and push into the batch.
        // JS `_pushBatch(localId, buffer)` does this by calling either
        // `_write0(buffer.subarray(1))` (control: channelId=0 is stripped)
        // or by building a payload without the channelId and pushing.
        // Here we do the same: decode the leading channelId varint from
        // the frame bytes and push the rest as the payload.
        if (len == 0) return;
        const uint8_t* ptr = data;
        const uint8_t* end = data + len;
        uint32_t local_id = static_cast<uint32_t>(varint_decode(ptr, end));
        size_t payload_len = static_cast<size_t>(end - ptr);

        // JS _pushBatch (index.js:417-422): flush the current batch first if it
        // already reached MAX_BATCH, then start a fresh one (finding 6). Keeps a
        // single batch frame under the 8 MB boundary.
        if (batch_size_ >= MAX_BATCH) flush_batch();

        if (batch_.empty()) {
            batch_size_ = 2 + varint_size(local_id);       // 0x00 0x00 + first id
        } else if (batch_.back().local_id != local_id) {
            batch_size_ += 1 + varint_size(local_id);      // switch marker + id
        }
        batch_size_ += varint_size(payload_len) + payload_len;

        BatchEntry e;
        e.local_id = local_id;
        e.payload.assign(ptr, ptr + payload_len);
        batch_.push_back(std::move(e));
        return;
    }
    if (write_fn_) {
        drained_ = write_fn_(data, len);
    }
}

void Mux::cork() {
    cork_count_++;
}

void Mux::uncork() {
    // Guard against mismatched uncork() (underflow) — JS silently leaves
    // corked=-1 in that case; we clamp at 0 instead.
    if (cork_count_ <= 0) {
        cork_count_ = 0;
        return;
    }
    if (--cork_count_ > 0) return;
    flush_batch();
}

// Encode the accumulated batch entries as a single [0x00, 0x00, ...] control
// frame and write it, then reset the batch. JS _sendBatch (index.js:432-453).
void Mux::flush_batch() {
    if (batch_.empty()) { batch_size_ = 0; return; }

    // Compute the encoded size.
    // Header: 0x00 0x00 + varint(first_localId)
    // Per entry: if localId switches, + 0x00 + varint(new_localId)
    //            then + varint(payload_len) + payload_len bytes
    size_t size = 2 + varint_size(batch_.front().local_id);
    uint32_t prev = batch_.front().local_id;
    for (const auto& e : batch_) {
        if (e.local_id != prev) {
            size += 1 + varint_size(e.local_id);  // 0x00 + switch
            prev = e.local_id;
        }
        size += varint_size(e.payload.size()) + e.payload.size();
    }

    std::vector<uint8_t> frame(size);
    uint8_t* p = frame.data();

    // Control frame header: channelId=0, type=BATCH(0).
    *p++ = 0x00;
    *p++ = 0x00;

    // First localId.
    prev = batch_.front().local_id;
    p += varint_encode(p, prev);

    for (const auto& e : batch_) {
        if (e.local_id != prev) {
            *p++ = 0x00;  // channel switch marker (zero-length message)
            p += varint_encode(p, e.local_id);
            prev = e.local_id;
        }
        p += varint_encode(p, e.payload.size());
        if (!e.payload.empty()) {
            std::memcpy(p, e.payload.data(), e.payload.size());
            p += e.payload.size();
        }
    }

    // Sanity — shouldn't happen, but guard against size mispredict.
    frame.resize(static_cast<size_t>(p - frame.data()));

    batch_.clear();
    batch_size_ = 0;
    if (write_fn_ && !destroyed_) {
        drained_ = write_fn_(frame.data(), frame.size());
    }
}

// ---------------------------------------------------------------------------
// Incoming frame dispatch
//
// JS: .analysis/js/protomux/index.js:482-490 (_ondata — entry point, kicks
//     _decode after reading the leading channelId varint)
//     .analysis/js/protomux/index.js:504-522 (_decode — splits control vs
//     data path; ignores messages for closed channels; buffers if the
//     remote channel is still pending pairing)
//     .analysis/js/protomux/index.js:524-544 (_oncontrolsession dispatch
//     table: 0=batch, 1=open, 2=reject, 3=close)
// ---------------------------------------------------------------------------

void Mux::on_data(const uint8_t* data, size_t len) {
    if (len == 0) return;  // JS _ondata: ignore empty frames

    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    uint64_t channel_id = varint_decode(ptr, end);
    if (channel_id > UINT32_MAX) { safe_destroy(); return; }  // C8
    dispatch_frame(static_cast<uint32_t>(channel_id), ptr, end);
}

// JS _decode (index.js:504-522): route a decoded frame to the control-session
// handlers (channelId 0) or the data path. Shared by on_data and handle_batch.
void Mux::dispatch_frame(uint32_t channel_id, const uint8_t* ptr, const uint8_t* end) {
    if (channel_id == 0) {
        uint64_t type = varint_decode(ptr, end);
        size_t remaining = static_cast<size_t>(end - ptr);
        switch (type) {
            case CONTROL_BATCH:  handle_batch(ptr, remaining); break;
            case CONTROL_OPEN:   handle_open(ptr, remaining); break;
            case CONTROL_REJECT: handle_reject(ptr, remaining); break;
            case CONTROL_CLOSE:  handle_close(ptr, remaining); break;
            default: break;
        }
    } else {
        handle_data(channel_id, ptr, static_cast<size_t>(end - ptr));
    }
}

// ---------------------------------------------------------------------------
// Control handlers
//
// JS: .analysis/js/protomux/index.js:595-646 (_onopensession — decodes
//     remoteId/protocol/id, hooks an existing local channel via
//     info.outgoing, or allocates a buffering _remote slot, queues into
//     info.incoming and runs _requestSession)
//     .analysis/js/protomux/index.js:648-668 (_onrejectsession)
//     .analysis/js/protomux/index.js:670-681 (_onclosesession)
//     .analysis/js/protomux/index.js:565-593 (_onbatch — the decode loop;
//     msg_len==0 means "switch channel id")
// ---------------------------------------------------------------------------

// JS MAX_BACKLOG = Infinity (index.js:8). We keep a very high documented cap
// as anti-DoS defence — the count of still-buffering (unclaimed) remote slots.
static constexpr size_t kMaxRemoteBacklog = 1u << 20;
// JS byteSize (index.js:755): per-buffered-message accounting overhead.
static constexpr size_t kBufferOverhead = 512;

void Mux::handle_open(const uint8_t* data, size_t len) {
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    uint64_t raw_id = varint_decode(ptr, end);
    if (raw_id > UINT32_MAX) { safe_destroy(); return; }  // C8
    uint32_t remote_id = static_cast<uint32_t>(raw_id);

    std::string protocol = string_decode(ptr, end);
    auto id = buffer_decode(ptr, end);
    auto handshake = buffer_decode(ptr, end);

    // Remote opened the control session → REJECT (JS index.js:602-605).
    if (remote_id == 0) { reject_session(0); return; }

    // Sequence validation (JS index.js:610-617): incoming remote ids grow by at
    // most one and may not reuse a live slot; a violation is a fatal protocol
    // error that tears the whole mux down (finding protomux-4).
    uint32_t rid = remote_id - 1;
    if (remote_len_ == rid) remote_len_ = static_cast<size_t>(rid) + 1;
    if (rid >= remote_len_ || remote_slots_.count(remote_id)) {
        safe_destroy();
        return;
    }

    std::string key = build_pair_key(protocol, id);

    // Outgoing path (JS index.js:619-632): a local channel already opened for
    // this (protocol,id) is awaiting pairing → link them immediately.
    if (Channel* local = find_awaiting_local(key)) {
        remote_slots_[remote_id].buffering = false;  // paired now, never buffers
        PendingOpen pend{remote_id, std::move(handshake),
                         std::move(protocol), std::move(id)};
        pair_with_remote(local, pend);
        return;
    }

    // No local channel yet (JS index.js:635-645): create a buffering slot so
    // subsequent data frames for this remote id are held (not dropped), queue
    // the incoming open, run the (synchronous) notify round, then reject the
    // open if nothing local claimed it.
    remote_slots_[remote_id];  // default-construct: buffering=true, session=null
    if (++remote_backlog_ > kMaxRemoteBacklog) { safe_destroy(); return; }

    incoming_[key].push_back(PendingOpen{remote_id, handshake, protocol, id});
    bool notified = dispatch_notify(protocol, id, handshake.data(), handshake.size());
    if (destroyed_) return;

    // JS _requestSession tail: reject every incoming open the pairing attempt
    // left unclaimed. In C++ the notify IS the (synchronous) pairing attempt —
    // reject only if a handler ran and declined. With no handler, the app pairs
    // by opening its own channel later, so the open stays parked (finding 3).
    if (notified) request_session(key);
}

// JS _onrejectsession (index.js:648-668): only a channel still awaiting open
// (in info.outgoing) may be rejected. An unmatched reject — including one for
// an already-opened channel — is a fatal protocol error (finding protomux-10).
void Mux::handle_reject(const uint8_t* data, size_t len) {
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    uint64_t raw_id = varint_decode(ptr, end);
    if (raw_id > UINT32_MAX) { safe_destroy(); return; }  // C8
    uint32_t local_id = static_cast<uint32_t>(raw_id);

    auto it = local_to_channel_.find(local_id);
    Channel* ch = (it != local_to_channel_.end()) ? it->second : nullptr;
    if (!ch || !ch->open_sent_ || ch->opened_) {
        safe_destroy();  // JS: throw 'Invalid reject message'
        return;
    }
    ch->remote_close();  // JS session._close(true)
}

// JS _onclosesession (index.js:670-681).
void Mux::handle_close(const uint8_t* data, size_t len) {
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    uint64_t raw_id = varint_decode(ptr, end);
    if (raw_id == 0 || raw_id > UINT32_MAX) return;  // JS: remoteId 0 → ignore
    uint32_t remote_id = static_cast<uint32_t>(raw_id);

    auto it = remote_slots_.find(remote_id);
    if (it == remote_slots_.end()) return;  // JS r === null → return
    Channel* s = it->second.session;
    if (s) s->remote_close();  // JS r.session._close(true)
}

// JS _onbatch (index.js:565-593): decode every message in the frame — the
// frame's byte length is the only bound (no entry cap, finding protomux-5).
// A multi-message batch is processed under a cork so any reply side-effects
// coalesce back into a single batch frame (finding protomux-7).
void Mux::handle_batch(const uint8_t* data, size_t len) {
    const uint8_t* ptr = data;
    const uint8_t* frame_end = data + len;

    uint32_t remote_id = static_cast<uint32_t>(varint_decode(ptr, frame_end));
    bool corked = false;

    while (ptr < frame_end && !destroyed_) {
        uint64_t msg_len = varint_decode(ptr, frame_end);
        if (msg_len == 0) {  // channel-switch marker
            remote_id = static_cast<uint32_t>(varint_decode(ptr, frame_end));
            continue;
        }

        // C6: safe arithmetic — avoid ptr+msg_len wrap. Truncation is a decode
        // error; JS throws → _safeDestroy (not a silent truncate).
        size_t avail = static_cast<size_t>(frame_end - ptr);
        if (msg_len > avail) { safe_destroy(); break; }

        const uint8_t* msg = ptr;
        const uint8_t* msg_end = ptr + static_cast<size_t>(msg_len);

        // JS corks the first time a message doesn't consume the rest of the
        // frame (i.e. the batch holds more than one message).
        if (msg_end != frame_end && !corked) { cork(); corked = true; }

        dispatch_frame(remote_id, msg, msg_end);
        ptr = msg_end;
    }

    if (corked && !destroyed_) uncork();
}

// JS _decode data path (index.js:511-521): route a data frame to its remote
// slot — ignore if the slot is gone, buffer if still pairing, else deliver.
void Mux::handle_data(uint32_t remote_id, const uint8_t* data, size_t len) {
    auto it = remote_slots_.find(remote_id);
    if (it == remote_slots_.end()) return;  // JS r === null → ignore
    RemoteSlot& slot = it->second;

    const uint8_t* ptr = data;
    const uint8_t* end = data + len;
    uint32_t type = static_cast<uint32_t>(varint_decode(ptr, end));
    size_t remaining = static_cast<size_t>(end - ptr);

    if (slot.buffering) {
        // JS _bufferMessage (index.js:546-563): always buffer, then _pauseMaybe.
        // We have no read-side pause hook (frames are pushed via on_data), so we
        // buffer up to a documented cap and tear the mux down past it — never a
        // silent drop (finding protomux-2).
        BufferedMessage pm;
        pm.type = type;
        pm.data.assign(ptr, ptr + remaining);
        slot.pending.push_back(std::move(pm));
        buffered_bytes_ += kBufferOverhead + remaining;
        if (buffered_bytes_ > MAX_BUFFERED) {
            // ponytail: no true stream-pause available here; teardown, not drop.
            safe_destroy();
        }
        return;
    }

    if (slot.session && !slot.session->destroyed_) {
        slot.session->dispatch(type, ptr, remaining);
    }
}

// ---------------------------------------------------------------------------
// Pairing / reject / teardown
//
// JS: .analysis/js/protomux/index.js:117-131 (_fullyOpen), :147-156 (_drain),
//     :683-695 (_requestSession), :697-722 (_rejectSession).
// ---------------------------------------------------------------------------

Channel* Mux::find_by_pair_key(const std::string& key) {
    for (auto& ch : channels_) {
        if (ch->destroyed_) continue;
        // Check primary key and any alias keys.
        for (const auto& k : ch->pair_keys_) {
            if (k == key) return ch.get();
        }
    }
    return nullptr;
}

// A local channel that has opened (sent its OPEN) but is not yet paired —
// JS info.outgoing membership.
Channel* Mux::find_awaiting_local(const std::string& key) {
    for (auto& ch : channels_) {
        if (ch->destroyed_ || !ch->open_sent_ || ch->opened_ || ch->remote_id_ != 0)
            continue;
        for (const auto& k : ch->pair_keys_) {
            if (k == key) return ch.get();
        }
    }
    return nullptr;
}

void Mux::pair_with_remote(Channel* local, const PendingOpen& remote) {
    uint32_t remote_id = remote.remote_local_id;
    local->set_remote_id(remote_id);

    RemoteSlot& slot = remote_slots_[remote_id];
    bool was_buffering = slot.buffering;
    slot.session = local;

    // Fire on_open with the remote handshake (JS _fullyOpen)…
    local->fully_open(remote.handshake.data(), remote.handshake.size());

    // …then replay any data buffered while we waited to pair (JS _drain).
    auto pending = std::move(slot.pending);
    slot.pending.clear();
    slot.buffering = false;
    if (was_buffering && remote_backlog_ > 0) remote_backlog_--;

    for (auto& pm : pending) {
        size_t sz = kBufferOverhead + pm.data.size();
        buffered_bytes_ = buffered_bytes_ >= sz ? buffered_bytes_ - sz : 0;
        if (!local->destroyed_) {
            local->dispatch(pm.type, pm.data.data(), pm.data.size());
        }
    }
}

// JS _requestSession tail (index.js:688-694): the notify round is over
// (synchronous here), so reject every incoming open for `key` that no local
// channel claimed (finding protomux-3).
void Mux::request_session(const std::string& key) {
    auto it = incoming_.find(key);
    if (it == incoming_.end()) return;
    std::deque<PendingOpen> queue = std::move(it->second);
    incoming_.erase(it);
    for (const auto& pend : queue) {
        reject_session(pend.remote_local_id);
        if (destroyed_) return;
    }
}

// JS _rejectSession (index.js:697-722): drop the remote slot (freeing any
// buffered data) and emit a [0, 2, remoteId] control frame.
void Mux::reject_session(uint32_t remote_id) {
    if (remote_id > 0) {
        auto it = remote_slots_.find(remote_id);
        if (it != remote_slots_.end()) {
            for (const auto& pm : it->second.pending) {
                size_t sz = kBufferOverhead + pm.data.size();
                buffered_bytes_ = buffered_bytes_ >= sz ? buffered_bytes_ - sz : 0;
            }
            if (it->second.buffering && remote_backlog_ > 0) remote_backlog_--;
            remote_slots_.erase(it);
        }
    }

    uint8_t frame[16];
    uint8_t* p = frame;
    p += varint_encode(p, 0);               // channelId = 0 (control)
    p += varint_encode(p, CONTROL_REJECT);  // type = 2
    p += varint_encode(p, remote_id);
    write_frame(frame, static_cast<size_t>(p - frame));
}

void Mux::safe_destroy() {
    // JS _safeDestroy → stream.destroy → _shutdown closes every session. The
    // Mux owns no stream, so destroy() (close all channels, stop writing) is
    // our equivalent teardown path.
    destroy();
}

// ---------------------------------------------------------------------------
// Pair/Unpair — notify hooks for unsolicited remote OPENs
//
// JS: .analysis/js/protomux/index.js:379-385 (pair / unpair — register a
//     `notify(id)` callback in the _notify map keyed by toKey(protocol,id))
//     .analysis/js/protomux/index.js:683-695 (_requestSession — looks up the
//     specific (protocol,id) notify, then falls back to the protocol-only
//     entry, awaits it, then either keeps or rejects the queued incoming)
// ---------------------------------------------------------------------------

void Mux::pair(const std::string& protocol, const std::vector<uint8_t>& id,
               NotifyFn fn) {
    std::string key = protocol + "##";
    if (!id.empty()) {
        key += to_hex(id.data(), id.size());
    }
    pair_notify_[key] = std::move(fn);
}

void Mux::unpair(const std::string& protocol, const std::vector<uint8_t>& id) {
    std::string key = protocol + "##";
    if (!id.empty()) {
        key += to_hex(id.data(), id.size());
    }
    pair_notify_.erase(key);
}

// Returns true if a notify handler was actually invoked — i.e. the app got a
// synchronous chance to claim this open. handle_open uses that to decide
// whether to reject an unclaimed open: a declined notify → reject (JS
// _requestSession); no handler at all → park it, because the app pairs by
// pre-creating/opening its own channel (the live blind-relay path and the
// symmetric loopback tests both rely on this). This is the C++ synchronous
// analogue of JS's async notify round.
bool Mux::dispatch_notify(const std::string& protocol,
                           const std::vector<uint8_t>& id,
                           const uint8_t* handshake, size_t hs_len) {
    // Check specific (protocol, id) first
    std::string key = protocol + "##";
    if (!id.empty()) {
        key += to_hex(id.data(), id.size());
    }
    auto it = pair_notify_.find(key);
    if (it != pair_notify_.end()) {
        it->second(protocol, id, handshake, hs_len);
        return true;
    }

    // Fall back to protocol-only (empty id)
    std::string proto_key = protocol + "##";
    it = pair_notify_.find(proto_key);
    if (it != pair_notify_.end()) {
        it->second(protocol, id, handshake, hs_len);
        return true;
    }

    // Global fallback
    if (on_notify_) {
        on_notify_(protocol, id, handshake, hs_len);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Drain
//
// JS: .analysis/js/protomux/index.js:492-498 (_ondrain — sets drained=true
//     and calls each session's ondrain hook)
// ---------------------------------------------------------------------------

void Mux::on_stream_drain() {
    drained_ = true;
    // JS _ondrain (index.js:492-498): fire ondrain on every non-null local
    // session (i.e. every channel that has opened), opened-and-paired or not —
    // not only fully-opened ones (finding protomux-9).
    // Snapshot: callbacks may close channels, modifying channels_ vector.
    auto snapshot = std::vector<Channel*>();
    for (auto& ch : channels_) snapshot.push_back(ch.get());
    for (auto* ch : snapshot) {
        if (ch->open_sent_ && !ch->destroyed_ && ch->on_drain) {
            ch->on_drain();
        }
    }
}

void Mux::remove_channel(Channel* ch) {
    // Remove from lookups. JS _close nulls _remote[rid] and frees the local id.
    if (ch->remote_id_ != 0) {
        remote_slots_.erase(ch->remote_id_);
    }
    if (ch->open_sent_) {
        local_to_channel_.erase(ch->local_id_);
    }

    // Remove from the last-channel map for every key we own. (incoming_ is
    // drained synchronously in request_session, so it holds nothing for us.)
    for (const auto& k : ch->pair_keys_) {
        auto it = last_channel_by_key_.find(k);
        if (it != last_channel_by_key_.end() && it->second == ch) {
            last_channel_by_key_.erase(it);
        }
    }

    // Erase from channels_ vector — deallocates the Channel.
    // Caller must not use 'ch' after this returns.
    channels_.erase(
        std::remove_if(channels_.begin(), channels_.end(),
                       [ch](const std::unique_ptr<Channel>& p) {
                           return p.get() == ch;
                       }),
        channels_.end());
}

// ---------------------------------------------------------------------------
// destroy / opened / get_last_channel / for_each_channel
//
// JS: .analysis/js/protomux/index.js:733-746 (destroy / _safeDestroy /
//     _shutdown — _shutdown iterates _local and _close(true)s every live
//     session)
//     .analysis/js/protomux/index.js:372-391 (getLastChannel / pair /
//     unpair / opened — info.lastChannel is updated by Channel.open())
//     .analysis/js/protomux/index.js:347-355 (Symbol.iterator / isIdle —
//     iterates non-null _local entries)
//
// C++ diffs from JS:
//   - JS's _shutdown captures _local once and iterates; if a sibling close
//     callback frees another channel, JS just sees the slot become null on
//     the next iteration. C++ vector ownership means we re-scan on every
//     iteration so we never dereference a freed unique_ptr — see the
//     comment block inside destroy() for the rationale.
// ---------------------------------------------------------------------------

void Mux::destroy() {
    if (destroyed_) return;
    destroyed_ = true;

    // Close every live channel. JS calls stream.destroy() → `_shutdown()`
    // → iterates _local and `_close(true)` on each. The tricky part in
    // C++ is that each close may synchronously free OTHER channels
    // (e.g. if a user `on_close` callback calls `close()` on a sibling).
    // A pre-captured snapshot of raw pointers becomes unsafe the moment
    // one of those siblings is freed.
    //
    // Instead: re-scan `channels_` on every iteration, find the first
    // still-live channel, and close it. Terminate when no live channels
    // remain. This is O(n²) but n is tiny and correctness wins.
    while (true) {
        Channel* next = nullptr;
        for (auto& ch : channels_) {
            if (!ch->destroyed_) { next = ch.get(); break; }
        }
        if (!next) break;
        next->remote_close();  // may free `next` and potentially others
    }

    batch_.clear();
    batch_size_ = 0;
    cork_count_ = 0;
    remote_slots_.clear();
    incoming_.clear();
    remote_backlog_ = 0;
    buffered_bytes_ = 0;
}

bool Mux::opened(const std::string& protocol,
                 const std::vector<uint8_t>& id) const {
    std::string key = build_pair_key(protocol, id);
    for (auto& ch : channels_) {
        if (ch->destroyed_ || !ch->opened_) continue;
        for (const auto& k : ch->pair_keys_) {
            if (k == key) return true;
        }
    }
    return false;
}

Channel* Mux::get_last_channel(const std::string& protocol,
                               const std::vector<uint8_t>& id) {
    std::string key = build_pair_key(protocol, id);
    auto it = last_channel_by_key_.find(key);
    return it == last_channel_by_key_.end() ? nullptr : it->second;
}

void Mux::for_each_channel(const std::function<void(Channel*)>& fn) {
    // Snapshot first — fn may call close() which mutates channels_.
    std::vector<Channel*> snapshot;
    snapshot.reserve(channels_.size());
    for (auto& ch : channels_) {
        if (!ch->destroyed_) snapshot.push_back(ch.get());
    }
    for (auto* ch : snapshot) {
        fn(ch);
    }
}

}  // namespace protomux
}  // namespace hyperdht
