#include "hyperdht/announcer.hpp"

#include <sodium.h>

#include <cstdio>

#include "hyperdht/debug.hpp"

namespace hyperdht {
namespace announcer {

// Re-announce interval: ~5 minutes (60 ticks * 5s bg tick)
// We use a direct timer instead of counting ticks.
constexpr uint64_t REANNOUNCE_MS = 5 * 60 * 1000;  // 5 minutes

Announcer::Announcer(rpc::RpcSocket& socket, const noise::Keypair& keypair,
                     const std::array<uint8_t, 32>& target)
    : socket_(socket), keypair_(keypair), target_(target) {

    // Build the peer record: publicKey + empty relay addresses (filled after first announce)
    dht_messages::PeerRecord peer;
    peer.public_key = keypair.public_key;
    record_ = dht_messages::encode_peer_record(peer);
}

Announcer::~Announcer() {
    if (bg_timer_) {
        uv_timer_stop(bg_timer_);
        bg_timer_->data = nullptr;  // Prevent on_bg_timer from dereferencing dead this
        uv_close(reinterpret_cast<uv_handle_t*>(bg_timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        bg_timer_ = nullptr;
    }
}

void Announcer::start() {
    if (running_) return;
    running_ = true;

    // Run first update immediately
    update();

    // Start background re-announce timer
    bg_timer_ = new uv_timer_t;
    uv_timer_init(socket_.loop(), bg_timer_);
    bg_timer_->data = this;
    uv_timer_start(bg_timer_, on_bg_timer, REANNOUNCE_MS, REANNOUNCE_MS);
}

void Announcer::stop(std::function<void()> on_done) {
    if (!running_) {
        if (on_done) on_done();
        return;
    }
    running_ = false;

    // Stop timer — null data to prevent callback from dereferencing dead this
    if (bg_timer_) {
        uv_timer_stop(bg_timer_);
        bg_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(bg_timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        bg_timer_ = nullptr;
    }

    // Don't reset current_query_ — let it finish naturally.
    // All callbacks check `running_` before touching `this`.
    // The query shared_ptr will be released in on_done.

    // Unannounce from all active relay nodes
    for (const auto& relay : active_relays_) {
        unannounce_node(relay);
    }
    active_relays_.clear();
    relays_.clear();

    if (on_done) on_done();
}

void Announcer::refresh() {
    if (!running_) return;
    update();
}

// ---------------------------------------------------------------------------
// Background timer
// ---------------------------------------------------------------------------

void Announcer::on_bg_timer(uv_timer_t* timer) {
    auto* self = static_cast<Announcer*>(timer->data);
    if (!self || !self->running_) return;
    self->update();
}

// ---------------------------------------------------------------------------
// Update: find k closest → announce to each
// ---------------------------------------------------------------------------

void Announcer::update() {
    if (updating_ || !running_) return;
    updating_ = true;

    // findPeer to discover k closest nodes that might store our announcement
    current_query_ = dht_ops::find_peer(socket_,
        keypair_.public_key,
        // on_reply: collect nodes with tokens
        [this](const query::QueryReply& reply) {
            if (!running_) return;
            // Commit: announce to this node
            commit(reply);
        },
        // on_done: query complete
        [this](const std::vector<query::QueryReply>&) {
            updating_ = false;
            current_query_.reset();
            if (running_) build_relays();
        });
}

// ---------------------------------------------------------------------------
// Commit: sign and send ANNOUNCE to a single node
// ---------------------------------------------------------------------------

void Announcer::commit(const query::QueryReply& node) {
    if (!node.token.has_value()) {
        DHT_LOG( "  [announcer] skip %s:%u (no token)\n",
                node.from_addr.host_string().c_str(), node.from_addr.port);
        return;
    }

    DHT_LOG( "  [announcer] commit to %s:%u (id=%02x%02x...)\n",
            node.from_addr.host_string().c_str(), node.from_addr.port,
            node.from_id[0], node.from_id[1]);

    // Get the node's routing table ID (needed for signature)
    auto node_id = node.from_id;
    auto token = *node.token;

    // Build the announce message with current relay addresses
    dht_messages::AnnounceMessage ann;
    dht_messages::PeerRecord peer;
    peer.public_key = keypair_.public_key;
    for (const auto& ri : relays_) {
        peer.relay_addresses.push_back(ri.relay_address);
    }
    ann.peer = peer;

    // Sign the announcement
    auto signature = announce_sig::sign_announce(
        target_, node_id, token.data(), token.size(), ann, keypair_);
    ann.signature = signature;

    // Encode the announce message
    auto ann_value = dht_messages::encode_announce_msg(ann);

    // Send ANNOUNCE request
    messages::Request req;
    req.to.addr = node.from_addr;
    req.command = messages::CMD_ANNOUNCE;
    req.target = target_;
    req.token = token;
    req.value = std::move(ann_value);

    socket_.request(req,
        [this, node](const messages::Response& resp) {
            if (!running_) return;
            DHT_LOG( "  [announcer] ANNOUNCE accepted by %s:%u\n",
                    node.from_addr.host_string().c_str(), node.from_addr.port);

            // Success — track this node as a relay
            RelayNode relay;
            relay.addr = node.from_addr;
            relay.node_id = node.from_id;
            if (node.token.has_value()) {
                relay.token = *node.token;
            }

            // Check if we already have this relay
            for (auto& existing : active_relays_) {
                if (existing.addr.host_string() == relay.addr.host_string() &&
                    existing.addr.port == relay.addr.port) {
                    existing = relay;  // Update token
                    return;
                }
            }

            // Add new relay (limit to 3)
            if (active_relays_.size() < 3) {
                active_relays_.push_back(relay);
            }
        },
        [node](uint16_t) {
            DHT_LOG( "  [announcer] ANNOUNCE timeout from %s:%u\n",
                    node.from_addr.host_string().c_str(), node.from_addr.port);
        });
}

// ---------------------------------------------------------------------------
// Unannounce from a single relay node
// ---------------------------------------------------------------------------

void Announcer::unannounce_node(const RelayNode& relay) {
    // Build unannounce message (same as announce but with UNANNOUNCE command)
    dht_messages::AnnounceMessage ann;
    dht_messages::PeerRecord peer;
    peer.public_key = keypair_.public_key;
    ann.peer = peer;

    auto signature = announce_sig::sign_unannounce(
        target_, relay.node_id, relay.token.data(), relay.token.size(),
        ann, keypair_);
    ann.signature = signature;

    auto ann_value = dht_messages::encode_announce_msg(ann);

    messages::Request req;
    req.to.addr = relay.addr;
    req.command = messages::CMD_UNANNOUNCE;
    req.target = target_;
    req.token = relay.token;
    req.value = std::move(ann_value);

    // Fire and forget — don't wait for response
    socket_.request(req, [](const messages::Response&) {}, [](uint16_t) {});
}

// ---------------------------------------------------------------------------
// Build relay info from active relays
// ---------------------------------------------------------------------------

void Announcer::build_relays() {
    relays_.clear();

    // Our public address (from NAT sampler)
    auto our_host = socket_.nat_sampler().host();
    uint16_t our_port = socket_.nat_sampler().port();

    for (const auto& relay : active_relays_) {
        peer_connect::RelayInfo ri;
        ri.relay_address = relay.addr;
        if (!our_host.empty() && our_port > 0) {
            ri.peer_address = compact::Ipv4Address::from_string(our_host, our_port);
        } else {
            ri.peer_address = compact::Ipv4Address::from_string("0.0.0.0", 0);
        }
        relays_.push_back(ri);
    }

    // Update the peer record with relay addresses — this is what findPeer returns
    dht_messages::PeerRecord peer;
    peer.public_key = keypair_.public_key;
    for (const auto& ri : relays_) {
        peer.relay_addresses.push_back(ri.relay_address);
    }
    record_ = dht_messages::encode_peer_record(peer);

    DHT_LOG( "  [announcer] Built relay list: %zu relays\n", relays_.size());
    for (const auto& ri : relays_) {
        DHT_LOG( "    relay: %s:%u\n",
                ri.relay_address.host_string().c_str(), ri.relay_address.port);
    }

    // If we have relays, immediately re-announce with the updated record
    // so findPeer returns our relay addresses
    if (!relays_.empty() && running_) {
        DHT_LOG( "  [announcer] Re-announcing with %zu relay addresses\n",
                relays_.size());
        update();
    }
}

}  // namespace announcer
}  // namespace hyperdht
