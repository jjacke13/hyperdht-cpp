#include "hyperdht/dht_ops.hpp"

#include <sodium.h>

#include <cstring>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/dht_messages.hpp"

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

static void add_default_bootstrap(query::Query& q, const rpc::RpcSocket& socket) {
    if (socket.table().size() == 0) {
        q.add_bootstrap(compact::Ipv4Address::from_string("88.99.3.86", 49737));
        q.add_bootstrap(compact::Ipv4Address::from_string("142.93.90.113", 49737));
        q.add_bootstrap(compact::Ipv4Address::from_string("138.68.147.8", 49737));
    }
}

// ---------------------------------------------------------------------------
// findPeer
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> find_peer(rpc::RpcSocket& socket,
                                         const uint8_t* public_key, size_t pk_len,
                                         query::OnReplyCallback on_reply,
                                         query::OnDoneCallback on_done) {
    auto target = hash_public_key(public_key, pk_len);
    routing::NodeId target_id{};
    std::copy(target.begin(), target.end(), target_id.begin());

    auto q = query::Query::create(socket, target_id, messages::CMD_FIND_PEER);
    q->on_reply(std::move(on_reply));
    q->on_done(std::move(on_done));
    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

std::shared_ptr<query::Query> find_peer(rpc::RpcSocket& socket,
                                         const std::array<uint8_t, 32>& public_key,
                                         query::OnReplyCallback on_reply,
                                         query::OnDoneCallback on_done) {
    return find_peer(socket, public_key.data(), public_key.size(),
                     std::move(on_reply), std::move(on_done));
}

// ---------------------------------------------------------------------------
// lookup
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> lookup(rpc::RpcSocket& socket,
                                      const routing::NodeId& target,
                                      query::OnReplyCallback on_reply,
                                      query::OnDoneCallback on_done) {
    auto q = query::Query::create(socket, target, messages::CMD_LOOKUP);
    q->on_reply(std::move(on_reply));
    q->on_done(std::move(on_done));
    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// announce
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> announce(rpc::RpcSocket& socket,
                                        const routing::NodeId& target,
                                        const std::vector<uint8_t>& value,
                                        query::OnDoneCallback on_done) {
    auto q = query::Query::create(socket, target, messages::CMD_ANNOUNCE, &value);
    q->on_done(std::move(on_done));

    // Commit phase: capture socket as pointer (must outlive query)
    q->set_commit([socket_ptr = &socket, target, value](
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
        socket_ptr->request(req, std::move(commit_done));
    });

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// immutable_put — target = BLAKE2b(value), query IMMUTABLE_GET, commit IMMUTABLE_PUT
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> immutable_put(rpc::RpcSocket& socket,
                                             const std::vector<uint8_t>& value,
                                             query::OnDoneCallback on_done) {
    auto target = hash_public_key(value.data(), value.size());
    routing::NodeId target_id{};
    std::copy(target.begin(), target.end(), target_id.begin());

    // Query phase: IMMUTABLE_GET to find closest nodes
    auto q = query::Query::create(socket, target_id, messages::CMD_IMMUTABLE_GET);
    q->on_done(std::move(on_done));

    // Commit phase: IMMUTABLE_PUT to each closest node
    q->set_commit([socket_ptr = &socket, target_id, value](
            const query::QueryReply& node,
            rpc::OnResponseCallback commit_done) {
        messages::Request req;
        req.to.addr = node.from_addr;
        req.command = messages::CMD_IMMUTABLE_PUT;
        req.target = target_id;
        if (node.token.has_value()) req.token = *node.token;
        req.value = value;
        socket_ptr->request(req, std::move(commit_done));
    });

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// immutable_get — query IMMUTABLE_GET, verify hash on each reply
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> immutable_get(rpc::RpcSocket& socket,
                                             const std::array<uint8_t, 32>& target,
                                             OnValueCallback on_result,
                                             query::OnDoneCallback on_done) {
    routing::NodeId target_id{};
    std::copy(target.begin(), target.end(), target_id.begin());

    auto q = query::Query::create(socket, target_id, messages::CMD_IMMUTABLE_GET);
    q->on_done(std::move(on_done));

    // Verify each reply: BLAKE2b(value) must equal target
    q->on_reply([target, on_result](const query::QueryReply& reply) {
        if (!reply.value.has_value() || reply.value->empty()) return;

        std::array<uint8_t, 32> check{};
        crypto_generichash(check.data(), 32,
                           reply.value->data(), reply.value->size(),
                           nullptr, 0);

        if (check == target && on_result) {
            on_result(*reply.value);
        }
    });

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// mutable_put — sign, query MUTABLE_GET, commit MUTABLE_PUT
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> mutable_put(rpc::RpcSocket& socket,
                                           const noise::Keypair& keypair,
                                           const std::vector<uint8_t>& value,
                                           uint64_t seq,
                                           query::OnDoneCallback on_done) {
    auto target = hash_public_key(keypair.public_key.data(), 32);
    routing::NodeId target_id{};
    std::copy(target.begin(), target.end(), target_id.begin());

    // Pre-sign the value
    auto signature = announce_sig::sign_mutable(
        seq, value.data(), value.size(), keypair);

    // Build the encoded MutablePutRequest
    dht_messages::MutablePutRequest put;
    put.public_key = keypair.public_key;
    put.seq = seq;
    put.value = value;
    put.signature = signature;
    auto encoded = dht_messages::encode_mutable_put(put);

    // Query phase: MUTABLE_GET with seq=0 to find closest nodes
    compact::State s;
    compact::Uint::preencode(s, 0);
    std::vector<uint8_t> seq_buf(s.end);
    s.buffer = seq_buf.data();
    s.start = 0;
    compact::Uint::encode(s, 0);

    auto q = query::Query::create(socket, target_id, messages::CMD_MUTABLE_GET, &seq_buf);
    q->on_done(std::move(on_done));

    // Commit phase: MUTABLE_PUT to each closest node
    q->set_commit([socket_ptr = &socket, target_id, encoded](
            const query::QueryReply& node,
            rpc::OnResponseCallback commit_done) {
        messages::Request req;
        req.to.addr = node.from_addr;
        req.command = messages::CMD_MUTABLE_PUT;
        req.target = target_id;
        if (node.token.has_value()) req.token = *node.token;
        req.value = encoded;
        socket_ptr->request(req, std::move(commit_done));
    });

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// mutable_get — query MUTABLE_GET, verify signature, track highest seq
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> mutable_get(rpc::RpcSocket& socket,
                                           const std::array<uint8_t, 32>& public_key,
                                           uint64_t min_seq,
                                           OnMutableCallback on_result,
                                           query::OnDoneCallback on_done) {
    auto target = hash_public_key(public_key.data(), 32);
    routing::NodeId target_id{};
    std::copy(target.begin(), target.end(), target_id.begin());

    // Encode min_seq as the query value
    compact::State s;
    compact::Uint::preencode(s, min_seq);
    std::vector<uint8_t> seq_buf(s.end);
    s.buffer = seq_buf.data();
    s.start = 0;
    compact::Uint::encode(s, min_seq);

    auto q = query::Query::create(socket, target_id, messages::CMD_MUTABLE_GET, &seq_buf);
    q->on_done(std::move(on_done));

    // Verify each reply: signature must be valid and seq >= min_seq
    q->on_reply([public_key, min_seq, on_result](const query::QueryReply& reply) {
        if (!reply.value.has_value() || reply.value->empty()) return;

        auto resp = dht_messages::decode_mutable_get_resp(
            reply.value->data(), reply.value->size());

        if (resp.value.empty()) return;
        if (resp.seq < min_seq) return;

        // Verify Ed25519 signature
        if (!announce_sig::verify_mutable(
                resp.signature, resp.seq,
                resp.value.data(), resp.value.size(),
                public_key)) {
            return;
        }

        if (on_result) {
            MutableResult result;
            result.seq = resp.seq;
            result.value = resp.value;
            result.signature = resp.signature;
            on_result(result);
        }
    });

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

}  // namespace dht_ops
}  // namespace hyperdht
