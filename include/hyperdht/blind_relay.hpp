#pragma once

// Blind Relay — fallback connection path when holepunch fails.
//
// When two peers can't establish a direct UDP connection (e.g., RANDOM+RANDOM
// NAT), they relay traffic through a third-party node. The relay node sees
// only encrypted ciphertext (hence "blind").
//
// Architecture:
//   - BlindRelayClient: used by endpoints (client + server) to negotiate
//     a relay through a relay node via a Protomux "blind-relay" channel.
//   - BlindRelayServer: used by relay nodes to accept and match pairs.
//
// Wire protocol over Protomux channel "blind-relay":
//   Message 0 (Pair):   [flags:bitfield(7)] [token:fixed32] [id:uint] [seq:uint]
//   Message 1 (Unpair): [flags:bitfield(0)] [token:fixed32]
//
// Pairing flow:
//   1. Peer A sends Pair(isInitiator=true, token=T, id=streamA, seq=0)
//   2. Peer B sends Pair(isInitiator=false, token=T, id=streamB, seq=0)
//   3. Relay matches by token, creates two relay streams, calls
//      udx_stream_relay_to() bidirectionally
//   4. Relay sends Pair response to each peer with the relay stream's ID
//   5. Peers connect their rawStreams to the relay's address using the
//      relay stream ID → data flows: A → relay → B (encrypted end-to-end)
//
// JS reference: blind-relay/index.js
// =========================================================================
// JS FLOW MAP
// =========================================================================
//
// C++ class/function                    JS file (blind-relay/index.js)  JS lines
// ────────────────────────────────────── ─────────────────────────────── ────────
// PairMessage / UnpairMessage           m.pair / m.unpair               (encoding)
// encode_pair / decode_pair             m.pair.encode/decode
// encode_unpair / decode_unpair         m.unpair.encode/decode
// BlindRelayClient                      BlindRelayClient               283-437
//   ::pair                              Client.pair()                   358-386
//   ::unpair                            Client.unpair()                 388-401
//   ::on_pair_response                  Client._onpair()               372-381
//   (no inbound unpair handler)         Client._unpair (send-only)     319-321
// BlindRelayServer                      BlindRelayServer               11-47
// BlindRelaySession                     BlindRelaySession              49-243
//   ::on_pair                           Session._onpair()              137-186
//   ::on_unpair                         Session._onunpair()            188-211
// token()                               exports.token()                 (bottom)
// =========================================================================

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <udx.h>
#include <uv.h>

#include "hyperdht/protomux.hpp"

namespace hyperdht {
namespace blind_relay {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

inline constexpr const char* PROTOCOL_NAME = "blind-relay";
inline constexpr uint64_t RELAY_TIMEOUT_MS = 15000;  // 15s pairing timeout
inline constexpr uint64_t RELAY_KEEP_ALIVE_MS = 5000; // default keep-alive

// Error codes for BlindRelayClient callbacks (JS: blind-relay/lib/errors.js)
namespace RelayError {
    constexpr int CHANNEL_CLOSED    = -1;  // JS: CHANNEL_CLOSED
    constexpr int CHANNEL_DESTROYED = -2;  // JS: CHANNEL_DESTROYED
    constexpr int ALREADY_PAIRING   = -3;  // JS: ALREADY_PAIRING
    constexpr int PAIRING_CANCELLED = -4;  // JS: PAIRING_CANCELLED
    constexpr int DESTROYED         = -5;  // Client destroyed with pending requests
}

// ---------------------------------------------------------------------------
// Messages — Pair and Unpair
// ---------------------------------------------------------------------------

using Token = std::array<uint8_t, 32>;

struct PairMessage {
    bool is_initiator = false;
    Token token{};
    uint32_t id = 0;     // UDX stream ID
    uint32_t seq = 0;    // Initial sequence (always 0)
};

struct UnpairMessage {
    Token token{};
};

// Encode/decode Pair message.
// decode returns std::nullopt on a truncated/malformed buffer — the JS
// decoder (compact-encoding) throws in that case, which tears the protomux
// connection down. Callers must mirror that: never act on a partial message.
std::vector<uint8_t> encode_pair(const PairMessage& m);
std::optional<PairMessage> decode_pair(const uint8_t* data, size_t len);

// Encode/decode Unpair message (same failure contract as decode_pair).
std::vector<uint8_t> encode_unpair(const UnpairMessage& m);
std::optional<UnpairMessage> decode_unpair(const uint8_t* data, size_t len);

// Generate a random 32-byte token (JS: relay.token())
Token generate_token();

// Token → hex string for map keys
std::string token_hex(const Token& t);

// ---------------------------------------------------------------------------
// BlindRelayClient — used by endpoints to negotiate relay
// ---------------------------------------------------------------------------
// JS: BlindRelayClient (blind-relay/index.js:283-437)
//
// Usage:
//   auto* channel = mux->create_channel("blind-relay", relay_socket_pk);
//   BlindRelayClient client(channel);
//   client.pair(true, token, my_raw_stream_id,
//       [](uint32_t remote_id) { /* pairing succeeded */ },
//       [](int err) { /* pairing failed */ });

class BlindRelayClient {
public:
    // Callback when pairing succeeds: receives the relay's stream ID for us
    using OnPairedCb = std::function<void(uint32_t remote_id)>;
    // Callback on error/timeout
    using OnErrorCb = std::function<void(int err)>;

    explicit BlindRelayClient(protomux::Channel* channel);
    ~BlindRelayClient();

    BlindRelayClient(const BlindRelayClient&) = delete;
    BlindRelayClient& operator=(const BlindRelayClient&) = delete;

    // Open the Protomux channel (sends OPEN to relay node)
    void open(const uint8_t* handshake = nullptr, size_t handshake_len = 0);

    // Request a relay pairing.
    // JS: client.pair(isInitiator, token, stream) → BlindRelayRequest
    //
    // is_initiator: true if WE proposed relay, false if remote proposed
    // token: pre-agreed 32-byte token (from NoisePayload relayThrough)
    // local_stream_id: our rawStream's UDX stream ID
    // on_paired: called with the relay's assigned stream ID on success
    // on_error: called on failure (timeout, cancel, channel close)
    void pair(bool is_initiator, const Token& token, uint32_t local_stream_id,
              OnPairedCb on_paired, OnErrorCb on_error = nullptr);

    // Cancel a pending pairing. Sends Unpair message.
    // JS: client.unpair(token)
    void unpair(const Token& token);

    // Close the channel gracefully
    void close();

    // Destroy immediately
    void destroy();

    bool is_closed() const { return closed_; }
    bool is_destroyed() const { return destroyed_; }

private:
    protomux::Channel* channel_;
    std::shared_ptr<bool> alive_;  // Sentinel for safe async callbacks
    bool closed_ = false;
    bool destroyed_ = false;

    // Registered Protomux message type indices
    int pair_msg_type_ = -1;
    int unpair_msg_type_ = -1;

    // Pending pair requests by token hex
    struct PairRequest {
        bool is_initiator;
        Token token;
        uint32_t local_stream_id;
        OnPairedCb on_paired;
        OnErrorCb on_error;
    };
    std::unordered_map<std::string, PairRequest> requests_;

    // Message handlers.
    // Note: there is no on_unpair handler. Like JS (index.js:319-321), the
    // client registers the unpair message type for SENDING only and ignores
    // any inbound unpair. The type is still registered (keeping message index
    // 1) so unpair sends have a stable wire index.
    void on_pair_response(const uint8_t* data, size_t len);
};

// ---------------------------------------------------------------------------
// BlindRelayServer — used by relay nodes to accept and match pairs
// ---------------------------------------------------------------------------
// JS: BlindRelayServer + BlindRelaySession (blind-relay/index.js:11-243)
//
// Usage (relay node):
//   BlindRelayServer relay_server(loop, udx_handle);
//   relay_server.accept(mux);  // for each incoming connection's mux

// Forward declaration
class BlindRelaySession;

// Per relay-stream context, stored in udx_stream_t::data. Carries the peer's
// UDX stream id so the firewall callback can connect() on the first inbound
// packet (JS BlindRelayLink.remoteId), plus a back-reference so the close
// callback can drop the stream from its session's map. Allocated when a relay
// stream is created in on_pair; freed by relay_stream_close_cb.
struct RelayStreamCtx {
    std::weak_ptr<bool> session_alive;   // guards `session` against UAF
    BlindRelaySession* session = nullptr;
    std::string key;                     // token hex — key into streams_
    uint32_t remote_id = 0;              // peer's UDX stream id (connect target)
};

// udx firewall callback for a relay stream. On the first inbound packet from
// an unknown remote it connects the stream to that source using the peer's
// stream id, then returns 0 so the packet is accepted and relayed.
//
// Mirrors JS BlindRelayLink._onfirewall (index.js:276-280): connect(), then
// `return false`. libudx's firewall contract: a non-zero return DROPS the
// packet (process_packet `return 1`), a zero return ACCEPTS it (falls through
// to relay_packet). JS `return false` therefore maps to returning 0 here —
// the freshly-connected stream then relays the very packet that connected it.
int relay_firewall_cb(udx_stream_t* stream, udx_socket_t* socket,
                      const struct sockaddr* from);

// udx close callback for a relay stream. Drops the stream from its session's
// streams_ map and frees the RelayStreamCtx. Mirrors JS
// `stream.on('close', () => session._streams.delete(keyString))`
// (index.js:166). udx folds stream errors into close(status<0), so this one
// callback also covers JS's separate `.on('error', session._onerror)`.
void relay_stream_close_cb(udx_stream_t* stream, int status);

// Factory for creating relay UDX streams. The relay node owns the udx_t and
// socket, so it — not blind-relay — allocates the udx_stream_t. blind-relay
// supplies the close callback (so it observes close, per finding above) and a
// user_data pointer (the RelayStreamCtx) that the factory must store in
// stream->data. The factory owns the stream's MEMORY via its own finalize_cb.
// Mirrors JS `_createStream({ firewall })` where the DHT provides the stream.
using CreateStreamFn =
    std::function<udx_stream_t*(udx_stream_close_cb close_cb, void* user_data)>;

class BlindRelayServer {
public:
    explicit BlindRelayServer(CreateStreamFn create_stream);
    ~BlindRelayServer();

    BlindRelayServer(const BlindRelayServer&) = delete;
    BlindRelayServer& operator=(const BlindRelayServer&) = delete;

    // Accept a new session on the given mux (one per incoming connection)
    BlindRelaySession* accept(protomux::Mux* mux,
                              const std::vector<uint8_t>& channel_id = {});

    // Graceful close (JS index.js:36-46). Marks the server closing and asks
    // each session to end(); a session with in-flight pairings drains via its
    // pending_close_/endMaybe machinery and removes itself once its channel
    // actually closes. on_closed (if set) fires when the last session is gone.
    // The destructor performs a hard destroy of anything still live.
    void close();

    // Fired once the last session has drained after close(). Optional.
    std::function<void()> on_closed;

    // Called by a session when its channel closes, so the server can drop it.
    // Safe to call from within the session's own close path — the session's
    // owning unique_ptr is moved aside (not freed) and reaped later.
    void notify_session_closed(BlindRelaySession* session);

    // Pairing state — shared across all sessions
    struct RelayPair {
        Token token;
        struct Link {
            BlindRelaySession* session = nullptr;
            bool is_initiator = false;
            uint32_t remote_id = 0;     // Peer's stream ID
            udx_stream_t* stream = nullptr;  // Relay stream (created on match)
        };
        // links[0] = non-initiator, links[1] = initiator
        Link links[2]{};
        bool has(bool is_initiator) const { return links[is_initiator ? 1 : 0].session != nullptr; }
        bool paired() const { return links[0].session != nullptr && links[1].session != nullptr; }
        Link& remote(bool is_initiator) { return links[is_initiator ? 0 : 1]; }
        // H25: creation time for TTL eviction of unpaired entries.
        // (C++ anti-DoS hardening; JS blind-relay has no TTL and no cap.)
        std::chrono::steady_clock::time_point created_at = std::chrono::steady_clock::now();
    };

    // Get or create a pairing by token
    RelayPair& get_or_create_pair(const Token& token);
    void remove_pair(const Token& token);
    void remove_pair_by_key(const std::string& hex_key);
    size_t pairing_count() const { return pairings_.size(); }  // H25
    bool has_pair(const std::string& key) const { return pairings_.count(key) > 0; }

    CreateStreamFn create_stream_fn;

private:
    // Reap sessions moved aside by notify_session_closed(). Called at safe
    // points (accept/close), never while a session method is on the stack.
    void reap_zombies() { zombies_.clear(); }

    std::unordered_map<std::string, RelayPair> pairings_;
    std::vector<std::unique_ptr<BlindRelaySession>> sessions_;
    // Sessions that closed themselves; kept alive here until reaped so the
    // self-removal in notify_session_closed() never frees a session mid-call.
    std::vector<std::unique_ptr<BlindRelaySession>> zombies_;
    bool closing_ = false;
};

// ---------------------------------------------------------------------------
// BlindRelaySession — one relay session per incoming Protomux connection
// ---------------------------------------------------------------------------

class BlindRelaySession {
public:
    BlindRelaySession(BlindRelayServer& server, protomux::Channel* channel);
    ~BlindRelaySession();

    BlindRelaySession(const BlindRelaySession&) = delete;
    BlindRelaySession& operator=(const BlindRelaySession&) = delete;

    // Open the channel
    void open();

    // Close gracefully (waits for in-flight pairings)
    void close();

    // Destroy immediately
    void destroy();

    bool is_closed() const { return closed_; }

    // Event callback: fires when a pair completes
    using OnPairCb = std::function<void(bool is_initiator, const Token& token,
                                        udx_stream_t* stream, uint32_t remote_id)>;
    OnPairCb on_pair_event;

    // Drop a relay stream from streams_ once udx has closed it. Invoked by
    // relay_stream_close_cb. Mirrors JS `session._streams.delete(keyString)`
    // (index.js:166). Erase-only — no endMaybe here (JS ties endMaybe to
    // _pairing, not _streams).
    void on_stream_closed(const std::string& key);

private:
    BlindRelayServer& server_;
    protomux::Channel* channel_;
    std::shared_ptr<bool> alive_;  // Sentinel for safe async callbacks
    bool closed_ = false;
    bool destroyed_ = false;
    bool pending_close_ = false;  // Set by close() when pairings are in-flight

    int pair_msg_type_ = -1;
    int unpair_msg_type_ = -1;

    // Tokens we're currently pairing (waiting for match)
    std::unordered_set<std::string> pairing_tokens_;
    // Active relay streams by token hex
    std::unordered_map<std::string, udx_stream_t*> streams_;

    // Message handlers
    void on_pair(const uint8_t* data, size_t len);
    void on_unpair(const uint8_t* data, size_t len);
};

}  // namespace blind_relay
}  // namespace hyperdht
