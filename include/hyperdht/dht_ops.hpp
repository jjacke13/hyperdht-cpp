#pragma once

// High-level DHT operations — findPeer, lookup, announce, unannounce.
// These wrap the iterative query engine with the appropriate HyperDHT commands.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "hyperdht/query.hpp"
#include "hyperdht/rpc.hpp"

namespace hyperdht {
namespace dht_ops {

// ---------------------------------------------------------------------------
// Utility: hash a public key to get the DHT target
// ---------------------------------------------------------------------------

// target = BLAKE2b-256(publicKey)
std::array<uint8_t, 32> hash_public_key(const uint8_t* pubkey, size_t len);

// ---------------------------------------------------------------------------
// findPeer — find nodes that have announced at a public key
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> find_peer(rpc::RpcSocket& socket,
                                         const uint8_t* public_key, size_t pk_len,
                                         query::OnReplyCallback on_reply,
                                         query::OnDoneCallback on_done);

std::shared_ptr<query::Query> find_peer(rpc::RpcSocket& socket,
                                         const std::array<uint8_t, 32>& public_key,
                                         query::OnReplyCallback on_reply,
                                         query::OnDoneCallback on_done);

// ---------------------------------------------------------------------------
// lookup — generic iterative query with a custom command
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> lookup(rpc::RpcSocket& socket,
                                      const routing::NodeId& target,
                                      query::OnReplyCallback on_reply,
                                      query::OnDoneCallback on_done);

// ---------------------------------------------------------------------------
// announce — announce at a target, then commit to k closest
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> announce(rpc::RpcSocket& socket,
                                        const routing::NodeId& target,
                                        const std::vector<uint8_t>& value,
                                        query::OnDoneCallback on_done);

}  // namespace dht_ops
}  // namespace hyperdht
