// Protomux implementation — channel multiplexer over a framed stream.
// Handles OPEN/CLOSE control messages, per-channel flow, and batching.
// Matches JS protomux/index.js.

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
    if (len == 0 || ptr + len > end) return {};
    std::vector<uint8_t> result(ptr, ptr + len);
    ptr += len;
    return result;
}

// Decode a length-prefixed UTF-8 string from ptr
static std::string string_decode(const uint8_t*& ptr, const uint8_t* end) {
    uint64_t len = varint_decode(ptr, end);
    if (len == 0 || ptr + len > end) return {};
    std::string result(reinterpret_cast<const char*>(ptr), len);
    ptr += len;
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

void Channel::open(const uint8_t* handshake, size_t handshake_len) {
    if (open_sent_ || closed_ || destroyed_) return;
    open_sent_ = true;

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

    // Check if there's already a pending remote OPEN for any of our
    // pair keys (primary or alias). This happens when the remote
    // opened before we did.
    for (const auto& k : pair_keys_) {
        auto it = mux_.pending_remote_.find(k);
        if (it != mux_.pending_remote_.end()) {
            auto pending = it->second;
            mux_.pending_remote_.erase(it);
            mux_.try_pair(this, pending);
            break;
        }
    }
}

bool Channel::send(int message_type, const uint8_t* data, size_t len) {
    if (!opened_ || closed_ || remote_id_ == 0) return false;

    // Build data frame: [remoteId][messageType][data]
    size_t frame_size = varint_size(remote_id_)
                      + varint_size(static_cast<uint64_t>(message_type))
                      + len;

    std::vector<uint8_t> frame(frame_size);
    uint8_t* p = frame.data();
    p += varint_encode(p, remote_id_);
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

void Channel::fully_open(const uint8_t* remote_handshake, size_t len) {
    if (opened_ || destroyed_) return;
    opened_ = true;
    if (on_open) on_open(remote_handshake, len);
    drain_pending();
}

void Channel::drain_pending() {
    // Process any messages that arrived before channel was fully opened
    auto pending = std::move(pending_messages_);
    pending_messages_.clear();
    for (const auto& pm : pending) {
        if (mux_.buffered_bytes_ >= pm.data.size())
            mux_.buffered_bytes_ -= pm.data.size();
        else
            mux_.buffered_bytes_ = 0;
        if (!destroyed_) {
            dispatch(pm.type, pm.data.data(), pm.data.size());
        }
    }
}

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
        messages_[type].on_message(data, len);
    }
}

// ---------------------------------------------------------------------------
// Mux
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

    uint32_t local_id = next_local_id_++;
    auto ch = aliases.empty()
        ? std::make_unique<Channel>(*this, protocol, id, local_id)
        : std::make_unique<Channel>(*this, protocol, aliases, id, local_id);
    Channel* ptr = ch.get();
    channels_.push_back(std::move(ch));
    local_to_channel_[local_id] = ptr;

    // Register every pair key (primary + aliases) in the last-channel map.
    for (const auto& k : ptr->pair_keys_) {
        last_channel_by_key_[k] = ptr;
    }

    return ptr;
}

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
    if (batch_.empty()) return;

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
    if (write_fn_) {
        drained_ = write_fn_(frame.data(), frame.size());
    }
}

// ---------------------------------------------------------------------------
// Incoming frame dispatch
// ---------------------------------------------------------------------------

void Mux::on_data(const uint8_t* data, size_t len) {
    if (len == 0) return;

    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    uint64_t channel_id = varint_decode(ptr, end);
    if (ptr >= end) return;

    if (channel_id == 0) {
        // Control session
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
        // Data message for a channel
        handle_data(static_cast<uint32_t>(channel_id), ptr,
                    static_cast<size_t>(end - ptr));
    }
}

// ---------------------------------------------------------------------------
// Control handlers
// ---------------------------------------------------------------------------

void Mux::handle_open(const uint8_t* data, size_t len) {
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    uint32_t remote_local_id = static_cast<uint32_t>(varint_decode(ptr, end));
    if (remote_local_id == 0) return;

    std::string protocol = string_decode(ptr, end);
    if (protocol.empty()) return;

    auto id = buffer_decode(ptr, end);
    auto handshake = buffer_decode(ptr, end);

    // Build pair key
    std::string key = protocol + "##";
    if (!id.empty()) {
        key += to_hex(id.data(), id.size());
    }

    // Check if we already have a local channel for this (protocol, id)
    Channel* local = find_by_pair_key(key);
    if (local && local->open_sent_ && !local->opened_) {
        // Pairing: local channel exists and was opened → link them
        PendingOpen pending{remote_local_id, std::move(handshake),
                            std::move(protocol), std::move(id)};
        try_pair(local, pending);
    } else {
        // No local channel yet — store as pending and notify.
        // Copy values for the callback since the callback may erase
        // from pending_remote_ (by calling create_channel + open).
        PendingOpen pending{remote_local_id, handshake, protocol, id};
        pending_remote_[key] = std::move(pending);

        dispatch_notify(protocol, id, handshake.data(), handshake.size());
    }
}

void Mux::handle_reject(const uint8_t* data, size_t len) {
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    uint32_t remote_id = static_cast<uint32_t>(varint_decode(ptr, end));
    if (remote_id == 0 || ptr > end) return;  // Guard truncation (varint returns 0)

    auto it = local_to_channel_.find(remote_id);
    if (it != local_to_channel_.end()) {
        it->second->remote_close();
    }
}

void Mux::handle_close(const uint8_t* data, size_t len) {
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    uint32_t remote_local_id = static_cast<uint32_t>(varint_decode(ptr, end));
    if (remote_local_id == 0 || ptr > end) return;  // Guard truncation

    auto it = remote_to_channel_.find(remote_local_id);
    if (it != remote_to_channel_.end()) {
        it->second->remote_close();
    }
}

void Mux::handle_batch(const uint8_t* data, size_t len) {
    // Batch format: [channelId][msg1_len][msg1][msg2_len][msg2]...[0][channelId2]...
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    while (ptr < end) {
        uint64_t channel_id = varint_decode(ptr, end);

        while (ptr < end) {
            uint64_t msg_len = varint_decode(ptr, end);
            if (msg_len == 0) break;  // End of this channel's messages

            if (ptr + msg_len > end) return;  // Truncated

            // Each sub-message is a complete frame for this channel
            if (channel_id == 0) {
                // Control sub-message
                if (msg_len > 0) {
                    const uint8_t* sub = ptr;
                    uint64_t type = varint_decode(sub, ptr + msg_len);
                    size_t remaining = static_cast<size_t>((ptr + msg_len) - sub);
                    switch (type) {
                        case CONTROL_OPEN:   handle_open(sub, remaining); break;
                        case CONTROL_REJECT: handle_reject(sub, remaining); break;
                        case CONTROL_CLOSE:  handle_close(sub, remaining); break;
                        default: break;
                    }
                }
            } else {
                handle_data(static_cast<uint32_t>(channel_id), ptr,
                            static_cast<size_t>(msg_len));
            }

            ptr += msg_len;
        }
    }
}

void Mux::handle_data(uint32_t channel_id, const uint8_t* data, size_t len) {
    // channel_id is the remote's local ID — which is our "remote_id" for this channel
    auto it = remote_to_channel_.find(channel_id);
    if (it == remote_to_channel_.end()) return;

    Channel* ch = it->second;
    if (ch->destroyed_) return;

    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    uint32_t type = static_cast<uint32_t>(varint_decode(ptr, end));
    size_t remaining = static_cast<size_t>(end - ptr);

    if (!ch->opened_) {
        // Buffer the message until channel is fully opened
        // Enforce MAX_BUFFERED to prevent unbounded memory growth
        if (buffered_bytes_ + remaining > MAX_BUFFERED) {
            return;  // Drop message — backpressure exceeded
        }
        Channel::PendingMessage pm;
        pm.type = type;
        pm.data.assign(ptr, ptr + remaining);
        buffered_bytes_ += remaining;
        ch->pending_messages_.push_back(std::move(pm));
        return;
    }

    ch->dispatch(type, ptr, remaining);
}

// ---------------------------------------------------------------------------
// Pairing
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

void Mux::try_pair(Channel* local, const PendingOpen& remote) {
    // Link: remote's local_id becomes our "remote_id" for sending
    local->set_remote_id(remote.remote_local_id);
    remote_to_channel_[remote.remote_local_id] = local;

    // Fully open with the remote's handshake
    local->fully_open(remote.handshake.data(), remote.handshake.size());
}

// ---------------------------------------------------------------------------
// Pair/Unpair
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

void Mux::dispatch_notify(const std::string& protocol,
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
        return;
    }

    // Fall back to protocol-only (empty id)
    std::string proto_key = protocol + "##";
    it = pair_notify_.find(proto_key);
    if (it != pair_notify_.end()) {
        it->second(protocol, id, handshake, hs_len);
        return;
    }

    // Global fallback
    if (on_notify_) {
        on_notify_(protocol, id, handshake, hs_len);
    }
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

void Mux::on_stream_drain() {
    drained_ = true;
    // Snapshot: callbacks may close channels, modifying channels_ vector
    auto snapshot = std::vector<Channel*>();
    for (auto& ch : channels_) snapshot.push_back(ch.get());
    for (auto* ch : snapshot) {
        if (ch->opened_ && !ch->destroyed_ && ch->on_drain) {
            ch->on_drain();
        }
    }
}

void Mux::remove_channel(Channel* ch) {
    // Remove from lookups
    if (ch->remote_id_ != 0) {
        remote_to_channel_.erase(ch->remote_id_);
    }
    local_to_channel_.erase(ch->local_id_);

    // Remove from pending + last-channel map for every key we own.
    for (const auto& k : ch->pair_keys_) {
        pending_remote_.erase(k);
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
    cork_count_ = 0;
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
