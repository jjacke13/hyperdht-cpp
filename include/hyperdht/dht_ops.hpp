#pragma once

// High-level DHT operations — findPeer, lookup, announce, unannounce.
// These wrap the iterative query engine with the appropriate HyperDHT commands.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "hyperdht/noise_wrap.hpp"
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
//
// LIFETIME: The caller must ensure `socket` outlives the returned Query.
// The Query holds a reference to the socket for the iterative walk and
// commit phase. This contract applies to all functions below that return
// a shared_ptr<Query>.
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> announce(rpc::RpcSocket& socket,
                                        const routing::NodeId& target,
                                        const std::vector<uint8_t>& value,
                                        query::OnDoneCallback on_done);

// ---------------------------------------------------------------------------
// immutablePut — store a value at target = BLAKE2b(value)
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> immutable_put(rpc::RpcSocket& socket,
                                             const std::vector<uint8_t>& value,
                                             query::OnDoneCallback on_done);

// ---------------------------------------------------------------------------
// immutableGet — retrieve a value by its content hash
// ---------------------------------------------------------------------------

// on_result is called for each verified result (hash matches target).
// The caller can stop the query early if desired.
using OnValueCallback = std::function<void(const std::vector<uint8_t>& value)>;

std::shared_ptr<query::Query> immutable_get(rpc::RpcSocket& socket,
                                             const std::array<uint8_t, 32>& target,
                                             OnValueCallback on_result,
                                             query::OnDoneCallback on_done);

// ---------------------------------------------------------------------------
// mutablePut — store a signed value at target = BLAKE2b(publicKey)
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> mutable_put(rpc::RpcSocket& socket,
                                           const noise::Keypair& keypair,
                                           const std::vector<uint8_t>& value,
                                           uint64_t seq,
                                           query::OnDoneCallback on_done);

// ---------------------------------------------------------------------------
// mutableGet — retrieve the latest signed value for a public key
// ---------------------------------------------------------------------------

struct MutableResult {
    uint64_t seq = 0;
    std::vector<uint8_t> value;
    std::array<uint8_t, 64> signature{};
};

// on_result is called for each verified result (valid signature, seq >= min_seq).
using OnMutableCallback = std::function<void(const MutableResult& result)>;

std::shared_ptr<query::Query> mutable_get(rpc::RpcSocket& socket,
                                           const std::array<uint8_t, 32>& public_key,
                                           uint64_t min_seq,
                                           OnMutableCallback on_result,
                                           query::OnDoneCallback on_done);

}  // namespace dht_ops
}  // namespace hyperdht
