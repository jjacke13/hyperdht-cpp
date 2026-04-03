#pragma once

// Announcer — periodic announcement of a server's presence on the DHT.
//
// Flow:
//   1. find_peer(target) to discover k closest nodes
//   2. For each: request token via FIND_PEER, then ANNOUNCE with signed record
//   3. Track relay addresses (which DHT nodes store our announcement)
//   4. Re-announce every ~5 minutes
//   5. On stop: UNANNOUNCE from all relay nodes
//
// Relay tracking uses 3 generations (rotate on each update cycle).

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <uv.h>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/compact.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/query.hpp"
#include "hyperdht/rpc.hpp"

namespace hyperdht {
namespace announcer {

// ---------------------------------------------------------------------------
// Announcer
// ---------------------------------------------------------------------------

class Announcer {
public:
    Announcer(rpc::RpcSocket& socket, const noise::Keypair& keypair,
              const std::array<uint8_t, 32>& target);
    ~Announcer();

    Announcer(const Announcer&) = delete;
    Announcer& operator=(const Announcer&) = delete;

    // Start announcing (runs initial update immediately, then background loop)
    void start();

    // Stop: unannounce from all relay nodes, stop background timer
    void stop(std::function<void()> on_done = nullptr);

    // Force immediate re-announcement
    void refresh();

    // Is the announcer running?
    bool is_running() const { return running_; }

    // Current relay info (for NoisePayload holepunch field)
    const std::vector<peer_connect::RelayInfo>& relays() const { return relays_; }

    // Encoded peer record (for Router's FIND_PEER response)
    const std::vector<uint8_t>& record() const { return record_; }

private:
    rpc::RpcSocket& socket_;
    noise::Keypair keypair_;
    std::array<uint8_t, 32> target_;

    std::vector<uint8_t> record_;  // Encoded PeerRecord
    std::vector<peer_connect::RelayInfo> relays_;

    // Relay tracking: address → node info
    struct RelayNode {
        compact::Ipv4Address addr;
        std::array<uint8_t, 32> node_id;
        std::array<uint8_t, 32> token;
    };
    std::vector<RelayNode> active_relays_;

    // Background timer
    uv_timer_t* bg_timer_ = nullptr;
    bool running_ = false;
    bool updating_ = false;

    // Shared pointer to keep alive during async operations
    std::shared_ptr<query::Query> current_query_;

    void update();
    void commit(const query::QueryReply& node);
    void unannounce_node(const RelayNode& relay);
    void build_relays();

    static void on_bg_timer(uv_timer_t* timer);
};

}  // namespace announcer
}  // namespace hyperdht
