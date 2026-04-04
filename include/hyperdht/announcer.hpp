#pragma once

// Announcer — periodic announcement of a server's presence on the DHT.
//
// Flow:
//   1. find_peer(target) to discover k closest nodes
//   2. For each: ANNOUNCE with signed record
//   3. Track relay addresses (which DHT nodes store our announcement)
//   4. Ping relays every 5s to keep NAT mappings alive
//   5. Re-announce every ~5 minutes
//   6. On stop: UNANNOUNCE from all relay nodes

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

// Minimum active relays before triggering a full refresh (matches JS MIN_ACTIVE)
constexpr int MIN_ACTIVE = 3;

class Announcer {
public:
    Announcer(rpc::RpcSocket& socket, const noise::Keypair& keypair,
              const std::array<uint8_t, 32>& target);
    ~Announcer();

    Announcer(const Announcer&) = delete;
    Announcer& operator=(const Announcer&) = delete;

    void start();
    void stop(std::function<void()> on_done = nullptr);
    void refresh();

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

    // Relay tracking
    struct RelayNode {
        compact::Ipv4Address addr;         // Relay node's address
        compact::Ipv4Address peer_addr;    // Our address as seen by this relay (from `to` field)
        std::array<uint8_t, 32> node_id;
        std::array<uint8_t, 32> token;
    };
    std::vector<RelayNode> active_relays_;

    // Timers
    uv_timer_t* bg_timer_ = nullptr;    // Re-announce (~5 min)
    uv_timer_t* ping_timer_ = nullptr;  // Relay keepalive (~5s)
    bool running_ = false;
    bool updating_ = false;
    bool has_reannounced_ = false;  // prevent update→build_relays→update loop

    std::shared_ptr<query::Query> current_query_;

    void update();
    void commit(const query::QueryReply& node);
    void unannounce_node(const RelayNode& relay);
    void build_relays();
    void ping_relays();

    static void on_bg_timer(uv_timer_t* timer);
    static void on_ping_timer(uv_timer_t* timer);
};

}  // namespace announcer
}  // namespace hyperdht
