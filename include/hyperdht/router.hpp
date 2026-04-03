#pragma once

// Router — forward table for incoming PEER_HANDSHAKE and PEER_HOLEPUNCH.
//
// Maps target hash → ForwardEntry. When a Server calls listen(), it registers
// in the Router. When a PEER_HANDSHAKE/HOLEPUNCH arrives, the Router dispatches
// to the correct Server's handler.
//
// Relay routing (from router.js):
//   Client sends FROM_CLIENT → Router changes to FROM_RELAY → forwards to Server
//   Server responds → Router sends back as REPLY to Client

#include <functional>
#include <unordered_map>
#include <vector>

#include "hyperdht/announce.hpp"
#include "hyperdht/compact.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/peer_connect.hpp"

namespace hyperdht {
namespace router {

// ---------------------------------------------------------------------------
// ForwardEntry — what's registered for a target
// ---------------------------------------------------------------------------

struct ForwardEntry {
    // Called when PEER_HANDSHAKE arrives for this target.
    // noise: the raw Noise msg1 bytes from the client
    // peer_address: the client's address as seen by the relay
    // reply_fn: call with Noise msg2 bytes to respond
    using HandshakeFn = std::function<void(
        const std::vector<uint8_t>& noise,
        const compact::Ipv4Address& peer_address,
        std::function<void(std::vector<uint8_t> reply_noise)> reply_fn)>;

    // Called when PEER_HOLEPUNCH arrives for this target.
    // msg: the decoded holepunch message (id, payload, peerAddress)
    // reply_fn: call with encoded reply value
    using HolepunchFn = std::function<void(
        const std::vector<uint8_t>& value,
        const compact::Ipv4Address& peer_address,
        std::function<void(std::vector<uint8_t> reply_value)> reply_fn)>;

    HandshakeFn on_peer_handshake;
    HolepunchFn on_peer_holepunch;
    std::vector<uint8_t> record;  // Encoded PeerRecord for FIND_PEER responses
};

// ---------------------------------------------------------------------------
// Router — the forward table
// ---------------------------------------------------------------------------

class Router {
public:
    // Register a target → entry mapping
    void set(const announce::TargetKey& target, ForwardEntry entry);

    // Look up a target. Returns nullptr if not found.
    ForwardEntry* get(const announce::TargetKey& target);

    // Remove a target mapping
    void remove(const announce::TargetKey& target);

    // Check if a target is registered
    bool has(const announce::TargetKey& target) const;

    // Get the peer record for a target (for FIND_PEER responses)
    const std::vector<uint8_t>* record(const announce::TargetKey& target) const;

    // Clear all entries
    void clear();

    size_t size() const { return forwards_.size(); }

    // Callback types for reply (sends RESPONSE) and relay (sends REQUEST).
    // The relay path is used when mode=FROM_RELAY: the server sends a REQUEST
    // back to the relay node, which then converts it to a RESPONSE for the client.
    using ReplyFn = std::function<void(const messages::Response&)>;
    using RelayFn = std::function<void(const messages::Request&)>;

    // Handle incoming PEER_HANDSHAKE request.
    // Returns true if handled (target found in router), false if not our target.
    bool handle_peer_handshake(const messages::Request& req,
                               ReplyFn reply, RelayFn relay);

    // Handle incoming PEER_HOLEPUNCH request.
    // Returns true if handled, false if not our target.
    bool handle_peer_holepunch(const messages::Request& req,
                               ReplyFn reply, RelayFn relay);

private:
    std::unordered_map<announce::TargetKey, ForwardEntry, announce::KeyHash> forwards_;
};

}  // namespace router
}  // namespace hyperdht
