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

// JS `announce(target, keyPair, relayAddresses, opts)` (index.js:244-264):
// walk = CMD_LOOKUP (value-less — the walk must NOT carry a token-less ANNOUNCE,
// which JS persistent nodes silently drop). The commit signs a FRESH announce
// record PER closest reply, over (target, reply.token, reply.from.id, peer) via
// `announce_sig::sign_announce` — a single pre-signed value cannot verify at any
// node because the signable covers that node's per-request token + id.
//
// `keypair`   — signs each per-node ANNOUNCE (JS keyPair).
// `relay_addresses` — the peer's relay addresses embedded in the signed record
//                     (JS `relayAddresses`; typically empty for a bare DHT
//                     announce — the server-side Announcer path is separate).
// `bump`      — relay-port bump signal (JS `opts.bump`, default 0).
// `clear_keypair`: dhttop-6. When non-null, the walk runs through
//   lookup+unannounce (JS `opts.clear` → lookupAndUnannounce, index.js:250) so
//   stale records for our key are removed BEFORE the new ANNOUNCE lands.
std::shared_ptr<query::Query> announce(rpc::RpcSocket& socket,
                                        const routing::NodeId& target,
                                        const noise::Keypair& keypair,
                                        const std::vector<compact::Ipv4Address>& relay_addresses,
                                        uint64_t bump,
                                        query::OnDoneCallback on_done,
                                        const noise::Keypair* clear_keypair = nullptr);

// ---------------------------------------------------------------------------
// lookup_and_unannounce — LOOKUP walk that, per reply, removes OUR old
// announcement from any node still holding it, then runs an optional commit.
//
// JS: hyperdht/index.js:197-238 (lookupAndUnannounce). The per-reply `map`
// decodes the lookup reply and, when our key is present (or the node is at
// the 20-record cap), fires a signed UNANNOUNCE to that node. The query's
// commit awaits ALL in-flight unannounces (Promise.all) before running the
// user commit — so on_done never fires until the unannounces settle.
//
// `user_commit`: the announce commit for the clear-announce path (dhttop-6),
// or nullptr for a plain unannounce (JS noop commit). `on_reply` forwards
// each raw reply to the caller (may be nullptr).
std::shared_ptr<query::Query> lookup_and_unannounce(
    rpc::RpcSocket& socket,
    const routing::NodeId& target,
    const noise::Keypair& keypair,
    query::OnReplyCallback on_reply,
    query::OnCommitCallback user_commit,
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

// When `latest == false`, the query destroys itself after the FIRST
// verified result, matching JS `mutableGet(pk, { latest: false })`
// (index.js:319-328). When `true` (default), the walk completes so
// the caller can pick the max-seq reply. Single-shot destroy() on
// first match avoids wasted traffic when callers only need "any valid".
std::shared_ptr<query::Query> mutable_get(rpc::RpcSocket& socket,
                                           const std::array<uint8_t, 32>& public_key,
                                           uint64_t min_seq,
                                           OnMutableCallback on_result,
                                           query::OnDoneCallback on_done,
                                           bool latest = true);

}  // namespace dht_ops
}  // namespace hyperdht
