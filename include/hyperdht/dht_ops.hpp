#pragma once

// High-level DHT operations — findPeer, lookup, announce, unannounce.
// These wrap the iterative query engine with the appropriate HyperDHT commands.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
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

// Start a FIND_PEER query for the given public key.
// Returns a Query that iteratively walks the DHT.
// Results arrive via on_reply callback (value field contains announcements).
query::Query* find_peer(rpc::RpcSocket& socket,
                        const uint8_t* public_key, size_t pk_len,
                        query::OnReplyCallback on_reply,
                        query::OnDoneCallback on_done);

// Convenience: 32-byte public key
query::Query* find_peer(rpc::RpcSocket& socket,
                        const std::array<uint8_t, 32>& public_key,
                        query::OnReplyCallback on_reply,
                        query::OnDoneCallback on_done);

// ---------------------------------------------------------------------------
// lookup — generic iterative query with a custom command
// ---------------------------------------------------------------------------

query::Query* lookup(rpc::RpcSocket& socket,
                     const routing::NodeId& target,
                     query::OnReplyCallback on_reply,
                     query::OnDoneCallback on_done);

// ---------------------------------------------------------------------------
// announce — announce at a target, then commit to k closest
// ---------------------------------------------------------------------------

query::Query* announce(rpc::RpcSocket& socket,
                       const routing::NodeId& target,
                       const std::vector<uint8_t>& value,
                       query::OnDoneCallback on_done);

}  // namespace dht_ops
}  // namespace hyperdht
