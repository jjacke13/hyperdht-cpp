#pragma once

// Phase 6: Protomux — channel multiplexer over a framed stream.
//
// Multiplexes virtual channels over a single SecretStream connection.
// Each channel is identified by (protocol_name, id) and carries typed messages.
//
// Wire format (each SecretStream message = one Protomux frame):
//   [channelId_varint] [type_varint] [payload...]
//
// channelId=0 is the control session:
//   type 0 = BATCH   (multiple messages packed)
//   type 1 = OPEN    (open channel: localId + protocol + id + handshake)
//   type 2 = REJECT  (reject channel open)
//   type 3 = CLOSE   (close channel)
//
// channelId>0 is a data channel:
//   type N = message index N (defined by channel's registered handlers)
//
// Channels pair by (protocol, id): when both sides open the same
// (protocol, id), the channels are linked and data can flow.

#include <any>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace hyperdht {
namespace protomux {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint32_t CONTROL_BATCH = 0;
constexpr uint32_t CONTROL_OPEN = 1;
constexpr uint32_t CONTROL_REJECT = 2;
constexpr uint32_t CONTROL_CLOSE = 3;

constexpr size_t MAX_BUFFERED = 32768;  // 32KB backpressure threshold

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

class Mux;

// ---------------------------------------------------------------------------
// Message handler — registered per message type on a channel
// ---------------------------------------------------------------------------

struct MessageHandler {
    std::function<void(const uint8_t* data, size_t len)> on_message;
};

// ---------------------------------------------------------------------------
// Channel — a virtual stream within the mux
// ---------------------------------------------------------------------------

class Channel {
public:
    Channel(Mux& mux, const std::string& protocol,
            const std::vector<uint8_t>& id, uint32_t local_id);

    // Register a message type handler. Returns the message type index.
    int add_message(MessageHandler handler);

    // Open the channel (sends OPEN to remote). Optional handshake data.
    void open(const uint8_t* handshake = nullptr, size_t handshake_len = 0);

    // Send a typed message on this channel
    bool send(int message_type, const uint8_t* data, size_t len);

    // Close the channel (sends CLOSE to remote)
    void close();

    // State
    bool is_open() const { return opened_; }
    bool is_closed() const { return closed_; }
    const std::string& protocol() const { return protocol_; }
    const std::vector<uint8_t>& id() const { return id_; }
    uint32_t local_id() const { return local_id_; }
    uint32_t remote_id() const { return remote_id_; }

    // Arbitrary application data (matches JS userData)
    std::any user_data;

    // Callbacks
    std::function<void(const uint8_t* handshake, size_t len)> on_open;
    std::function<void()> on_close;
    std::function<void()> on_destroy;
    std::function<void()> on_drain;  // Fired when mux is drained

private:
    friend class Mux;

    Mux& mux_;
    std::string protocol_;
    std::vector<uint8_t> id_;
    uint32_t local_id_;
    uint32_t remote_id_ = 0;

    bool open_sent_ = false;
    bool opened_ = false;        // Both sides have opened
    bool closed_ = false;
    bool destroyed_ = false;

    std::vector<uint8_t> local_handshake_;
    std::vector<MessageHandler> messages_;

    // Buffered messages received before channel is fully opened
    struct PendingMessage {
        uint32_t type;
        std::vector<uint8_t> data;
    };
    std::vector<PendingMessage> pending_messages_;

    // Pairing key: "protocol##hex(id)"
    std::string pair_key() const;

    // Called by Mux when remote opens matching channel
    void set_remote_id(uint32_t id) { remote_id_ = id; }
    void fully_open(const uint8_t* remote_handshake, size_t len);
    void drain_pending();  // Process buffered messages after open
    void remote_close();
    void destroy();
    void dispatch(uint32_t type, const uint8_t* data, size_t len);
};

// ---------------------------------------------------------------------------
// Mux — the multiplexer over a framed stream
// ---------------------------------------------------------------------------

class Mux {
public:
    // write_fn: called to write a frame to the underlying stream.
    // Returns true if drained (no backpressure), false if backpressured.
    using WriteFn = std::function<bool(const uint8_t* data, size_t len)>;
    explicit Mux(WriteFn write_fn);

    // Create a channel. Returns a non-owning pointer (Mux owns the channel).
    // unique: if true (default), returns nullptr if (protocol, id) already open
    Channel* create_channel(const std::string& protocol,
                            const std::vector<uint8_t>& id = {},
                            bool unique = true);

    // Feed an incoming frame (after SecretStream decryption).
    // Each call = one complete Protomux frame.
    void on_data(const uint8_t* data, size_t len);

    // Cork/uncork for batching multiple sends into one frame
    void cork();
    void uncork();

    // -----------------------------------------------------------------------
    // Notify: per-protocol callback registration (matches JS pair/unpair)
    // -----------------------------------------------------------------------

    using NotifyFn = std::function<void(const std::string& protocol,
                                        const std::vector<uint8_t>& id,
                                        const uint8_t* handshake, size_t hs_len)>;

    // Register a notify callback for a specific (protocol, id) pair.
    // If id is empty, matches any id for that protocol.
    void pair(const std::string& protocol, const std::vector<uint8_t>& id,
              NotifyFn fn);

    // Unregister a notify callback
    void unpair(const std::string& protocol, const std::vector<uint8_t>& id);

    // Global fallback notify (called if no pair match)
    void on_notify(NotifyFn fn) { on_notify_ = std::move(fn); }

    // -----------------------------------------------------------------------
    // Backpressure
    // -----------------------------------------------------------------------

    // True if the underlying stream has capacity (no backpressure)
    bool drained() const { return drained_; }

    // Call when underlying stream drains — fires ondrain on all channels
    void on_stream_drain();

    // Number of bytes buffered in pending message queues
    size_t buffered() const { return buffered_bytes_; }

    // -----------------------------------------------------------------------
    // State queries
    // -----------------------------------------------------------------------

    // Number of active channels
    size_t channel_count() const { return channels_.size(); }

    // True if all allocated local IDs are freed (no active channels)
    bool is_idle() const { return channels_.empty(); }

private:
    friend class Channel;

    WriteFn write_fn_;
    NotifyFn on_notify_;

    uint32_t next_local_id_ = 1;
    std::vector<std::unique_ptr<Channel>> channels_;

    // Remote ID → Channel* lookup (for incoming data messages)
    std::unordered_map<uint32_t, Channel*> remote_to_channel_;

    // Local ID → Channel* lookup (for incoming CLOSE/pairing)
    std::unordered_map<uint32_t, Channel*> local_to_channel_;

    // Per-protocol notify callbacks (pair/unpair)
    std::unordered_map<std::string, NotifyFn> pair_notify_;

    // Pending remote opens waiting for local pairing
    struct PendingOpen {
        uint32_t remote_local_id;   // The remote's local ID for this channel
        std::vector<uint8_t> handshake;
        std::string protocol;
        std::vector<uint8_t> id;
    };
    std::unordered_map<std::string, PendingOpen> pending_remote_;

    // Cork state
    int cork_count_ = 0;
    std::vector<uint8_t> cork_buffer_;

    // Backpressure state
    bool drained_ = true;
    size_t buffered_bytes_ = 0;

    // Write a frame (respects cork, updates drained)
    void write_frame(const uint8_t* data, size_t len);

    // Control message handlers
    void handle_open(const uint8_t* data, size_t len);
    void handle_reject(const uint8_t* data, size_t len);
    void handle_close(const uint8_t* data, size_t len);
    void handle_batch(const uint8_t* data, size_t len);
    void handle_data(uint32_t channel_id, const uint8_t* data, size_t len);

    // Pairing
    Channel* find_by_pair_key(const std::string& key);
    void try_pair(Channel* local, const PendingOpen& remote);

    // Notify dispatch — checks pair map then global fallback
    void dispatch_notify(const std::string& protocol,
                         const std::vector<uint8_t>& id,
                         const uint8_t* handshake, size_t hs_len);

    // Remove a channel from all lookups
    void remove_channel(Channel* ch);
};

// ---------------------------------------------------------------------------
// Varint helpers (Protomux uses compact-encoding varints)
// ---------------------------------------------------------------------------

size_t varint_encode(uint8_t* buf, uint64_t value);
uint64_t varint_decode(const uint8_t*& ptr, const uint8_t* end);
size_t varint_size(uint64_t value);

// Buffer helpers (length-prefixed)
size_t buffer_encode(uint8_t* buf, const uint8_t* data, size_t len);
size_t buffer_preencode(size_t len);

// String helpers (UTF-8, length-prefixed)
size_t string_encode(uint8_t* buf, const std::string& str);
size_t string_preencode(const std::string& str);

}  // namespace protomux
}  // namespace hyperdht
