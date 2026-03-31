#include "hyperdht/dht_ops.hpp"

#include <sodium.h>

#include <cstring>

namespace hyperdht {
namespace dht_ops {

// ---------------------------------------------------------------------------
// Hash utility
// ---------------------------------------------------------------------------

std::array<uint8_t, 32> hash_public_key(const uint8_t* pubkey, size_t len) {
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, pubkey, len, nullptr, 0);
    return target;
}

// ---------------------------------------------------------------------------
// Bootstrap helper — adds the 3 public bootstrap nodes to a query
// ---------------------------------------------------------------------------

static void add_default_bootstrap(query::Query* q, rpc::RpcSocket& socket) {
    // If routing table is empty, add public bootstrap nodes
    if (socket.table().size() == 0) {
        q->add_bootstrap(compact::Ipv4Address::from_string("88.99.3.86", 49737));
        q->add_bootstrap(compact::Ipv4Address::from_string("142.93.90.113", 49737));
        q->add_bootstrap(compact::Ipv4Address::from_string("138.68.147.8", 49737));
    }
}

// ---------------------------------------------------------------------------
// findPeer
// ---------------------------------------------------------------------------

query::Query* find_peer(rpc::RpcSocket& socket,
                        const uint8_t* public_key, size_t pk_len,
                        query::OnReplyCallback on_reply,
                        query::OnDoneCallback on_done) {
    auto target = hash_public_key(public_key, pk_len);
    routing::NodeId target_id{};
    std::copy(target.begin(), target.end(), target_id.begin());

    auto* q = new query::Query(socket, target_id, messages::CMD_FIND_PEER);
    q->on_reply(std::move(on_reply));
    q->on_done(std::move(on_done));
    add_default_bootstrap(q, socket);
    q->start();
    return q;
}

query::Query* find_peer(rpc::RpcSocket& socket,
                        const std::array<uint8_t, 32>& public_key,
                        query::OnReplyCallback on_reply,
                        query::OnDoneCallback on_done) {
    return find_peer(socket, public_key.data(), public_key.size(),
                     std::move(on_reply), std::move(on_done));
}

// ---------------------------------------------------------------------------
// lookup
// ---------------------------------------------------------------------------

query::Query* lookup(rpc::RpcSocket& socket,
                     const routing::NodeId& target,
                     query::OnReplyCallback on_reply,
                     query::OnDoneCallback on_done) {
    auto* q = new query::Query(socket, target, messages::CMD_LOOKUP);
    q->on_reply(std::move(on_reply));
    q->on_done(std::move(on_done));
    add_default_bootstrap(q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// announce
// ---------------------------------------------------------------------------

query::Query* announce(rpc::RpcSocket& socket,
                       const routing::NodeId& target,
                       const std::vector<uint8_t>& value,
                       query::OnDoneCallback on_done) {
    auto* q = new query::Query(socket, target, messages::CMD_ANNOUNCE, &value);
    q->on_done(std::move(on_done));

    // Commit phase: send ANNOUNCE with token to each closest node
    q->set_commit([&socket, target, value](
            const query::QueryReply& node,
            rpc::OnResponseCallback commit_done) {
        messages::Request req;
        req.to.addr = node.from_addr;
        req.command = messages::CMD_ANNOUNCE;
        req.target = target;
        if (node.token.has_value()) {
            req.token = *node.token;
        }
        req.value = value;
        socket.request(req, std::move(commit_done));
    });

    add_default_bootstrap(q, socket);
    q->start();
    return q;
}

}  // namespace dht_ops
}  // namespace hyperdht
