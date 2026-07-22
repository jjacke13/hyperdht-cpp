// High-level DHT operations implementation — findPeer, lookup,
// announce, unannounce. Each wraps the iterative query engine with
// the appropriate HyperDHT command and result aggregation.

#include "hyperdht/dht_ops.hpp"

#include <sodium.h>

#include <cstring>

#include "hyperdht/announce.hpp"
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
// findPeer — Kademlia walk for FIND_PEER. Target = BLAKE2b(public_key).
//
// JS: .analysis/js/hyperdht/index.js:186-190 (findPeer)
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> find_peer(rpc::RpcSocket& socket,
                                         const uint8_t* public_key, size_t pk_len,
                                         query::OnReplyCallback on_reply,
                                         query::OnDoneCallback on_done,
                                         const std::vector<SeedNode>* seed_nodes) {
    auto target = hash_public_key(public_key, pk_len);
    routing::NodeId target_id{};
    std::copy(target.begin(), target.end(), target_id.begin());

    auto q = query::Query::create(socket, target_id, messages::CMD_FIND_PEER);
    q->on_reply(std::move(on_reply));
    q->on_done(std::move(on_done));
    // JS announcer.js:156 — `nodes: this._closestNodes` reseeds the walk with
    // the previous cycle's closest nodes (query.js:47-67 frontier pre-seed).
    // Seeds are copied into the query before start(); the caller's vector is
    // not referenced afterwards.
    if (seed_nodes) {
        for (const auto& s : *seed_nodes) q->add_seed_node(s.id, s.addr);
    }
    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

std::shared_ptr<query::Query> find_peer(rpc::RpcSocket& socket,
                                         const std::array<uint8_t, 32>& public_key,
                                         query::OnReplyCallback on_reply,
                                         query::OnDoneCallback on_done,
                                         const std::vector<SeedNode>* seed_nodes) {
    return find_peer(socket, public_key.data(), public_key.size(),
                     std::move(on_reply), std::move(on_done), seed_nodes);
}

// ---------------------------------------------------------------------------
// lookup — Kademlia walk for LOOKUP. Caller supplies the target hash.
//
// JS: .analysis/js/hyperdht/index.js:192-195 (lookup)
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
// make_announce_commit — the per-closest-reply ANNOUNCE commit. Builds and
// signs a FRESH announce record for the replying node, over that node's issued
// token + id, then sends CMD_ANNOUNCE with the token. Shared by the plain
// announce and the clear-announce (dhttop-6) paths. Mirrors the server-side
// Announcer::commit (announcer.cpp) — the in-repo per-node-signing reference.
//
// JS: .analysis/js/hyperdht/index.js:464-488 (_requestAnnounce).
//
// The socket + keypair are captured; the LIFETIME contract (see header)
// requires the socket to outlive the query.
// ---------------------------------------------------------------------------

static query::OnCommitCallback make_announce_commit(
    rpc::RpcSocket& socket,
    const routing::NodeId& target,
    const noise::Keypair& keypair,
    const std::vector<compact::Ipv4Address>& relay_addresses,
    uint64_t bump) {
    return [&socket, target, keypair, relay_addresses, bump](
            const query::QueryReply& node,
            rpc::OnResponseCallback on_response,
            rpc::OnTimeoutCallback on_timeout) {
        // do_commit maps EVERY closest reply (JS query.js:220-228); a tokenless
        // node cannot be signed for, so settle it as a FAILED commit — exactly
        // JS autoCommit's reject on a reply with no token (query.js:392-393).
        if (!node.token.has_value()) { on_timeout(0); return; }

        // JS _requestAnnounce: ann = { peer:{publicKey, relayAddresses}, bump },
        // signed over (target, token, from.id, ann) with NS.ANNOUNCE.
        dht_messages::AnnounceMessage ann;
        dht_messages::PeerRecord peer;
        peer.public_key = keypair.public_key;
        peer.relay_addresses = relay_addresses;
        ann.peer = peer;
        ann.bump = bump;
        ann.signature = announce_sig::sign_announce(
            target, node.from_id,
            node.token->data(), node.token->size(), ann, keypair);

        messages::Request req;
        req.to.addr = node.from_addr;
        req.command = messages::CMD_ANNOUNCE;
        req.target = target;
        req.token = *node.token;
        req.value = dht_messages::encode_announce_msg(ann);
        uint16_t tid = socket.request(req, std::move(on_response), on_timeout);
        // Dropped by the congestion queue → neither callback will fire.
        // Settle the commit now so the query can't hang.
        if (tid == 0) on_timeout(0);
    };
}

// ---------------------------------------------------------------------------
// announce — LOOKUP walk (value-less) + commit phase that signs and sends a
// per-node ANNOUNCE to each closest node with its issued token. With
// `clear_keypair`, first removes our stale records (dhttop-6).
//
// JS: .analysis/js/hyperdht/index.js:244-264 (announce — wraps lookup, or
//     lookupAndUnannounce when opts.clear, with a commit fn calling
//     _requestAnnounce).
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> announce(rpc::RpcSocket& socket,
                                        const routing::NodeId& target,
                                        const noise::Keypair& keypair,
                                        const std::vector<compact::Ipv4Address>& relay_addresses,
                                        uint64_t bump,
                                        query::OnDoneCallback on_done,
                                        const noise::Keypair* clear_keypair) {
    auto commit = make_announce_commit(socket, target, keypair,
                                       relay_addresses, bump);

    // dhttop-6: clear path (JS index.js:250 `opts.clear ? lookupAndUnannounce
    // : lookup`). The announce commit becomes the user commit folded in after
    // the unannounces settle.
    if (clear_keypair) {
        return lookup_and_unannounce(
            socket, target, *clear_keypair,
            /*on_reply=*/nullptr,
            std::move(commit),
            std::move(on_done));
    }

    // JS walk = CMD_LOOKUP with NO value (persistent nodes drop token-less
    // ANNOUNCE walk requests, so the old CMD_ANNOUNCE walk never landed).
    auto q = query::Query::create(socket, target, messages::CMD_LOOKUP);
    q->on_done(std::move(on_done));
    q->set_commit(std::move(commit));

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// lookup_and_unannounce — see header. LOOKUP walk; per-reply map fires signed
// UNANNOUNCE for our stale records; commit awaits the unannounces then runs
// the user commit (announce for clear, noop for plain unannounce).
//
// JS: .analysis/js/hyperdht/index.js:197-238 (lookupAndUnannounce),
//     :490-512 (_requestUnannounce).
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> lookup_and_unannounce(
    rpc::RpcSocket& socket,
    const routing::NodeId& target,
    const noise::Keypair& keypair,
    query::OnReplyCallback on_reply,
    query::OnCommitCallback user_commit,
    query::OnDoneCallback on_done) {

    auto q = query::Query::create(socket, target, messages::CMD_LOOKUP);

    // Shared state: in-flight UNANNOUNCE requests + commits deferred until they
    // settle. Mirrors JS `unannounces` array + `await Promise.all(unannounces)`.
    struct Tracker {
        int inflight = 0;
        std::vector<std::function<void()>> deferred;
        void settle() {
            if (inflight > 0) --inflight;
            if (inflight == 0 && !deferred.empty()) {
                auto pending = std::move(deferred);
                deferred.clear();
                for (auto& fn : pending) fn();
            }
        }
    };
    auto tracker = std::make_shared<Tracker>();
    const auto our_pk = keypair.public_key;

    // map (per reply): unannounce our stale record. JS index.js:216-237.
    q->on_reply([&socket, target, keypair, our_pk, tracker, on_reply](
                    const query::QueryReply& reply) {
        if (on_reply) on_reply(reply);

        // JS: `if (!data.token) return`; `if (!data.from.id) return`.
        if (!reply.token.has_value()) return;
        routing::NodeId zero_id{};
        if (reply.from_id == zero_id) return;
        if (!reply.value.has_value() || reply.value->empty()) return;

        // found = ≥20 records OR our key present (JS index.js:221-224).
        auto parsed = dht_messages::decode_lookup_reply(
            reply.value->data(), reply.value->size());
        bool found = parsed.peers.size() >= announce::MAX_PEERS_PER_TARGET;
        for (size_t i = 0; !found && i < parsed.peers.size(); ++i) {
            auto pr = dht_messages::decode_peer_record(
                parsed.peers[i].data(), parsed.peers[i].size());
            if (pr.public_key == our_pk) found = true;
        }
        if (!found) return;

        // Build + sign the UNANNOUNCE (JS _requestUnannounce, index.js:490-512):
        // empty relay list, NS.UNANNOUNCE signature over (target, token,
        // replying node id, peer).
        dht_messages::AnnounceMessage unann;
        dht_messages::PeerRecord peer;
        peer.public_key = our_pk;
        unann.peer = peer;
        unann.signature = announce_sig::sign_unannounce(
            target, reply.from_id,
            reply.token->data(), reply.token->size(),
            unann, keypair);

        messages::Request req;
        req.to.addr = reply.from_addr;
        req.command = messages::CMD_UNANNOUNCE;
        req.target = target;
        req.token = *reply.token;
        req.value = dht_messages::encode_announce_msg(unann);

        ++tracker->inflight;
        uint16_t tid = socket.request(req,
            [tracker](const messages::Response&) { tracker->settle(); },
            [tracker](uint16_t) { tracker->settle(); });
        if (tid == 0) tracker->settle();  // dropped → settle now, can't hang
    });

    // commit (per closest reply): await outstanding unannounces (JS
    // index.js:211-214 `await Promise.all(unannounces)`), then run user_commit.
    // Deferring the send until unannounces settle prevents a fresh ANNOUNCE
    // from racing a late UNANNOUNCE to the same node.
    q->set_commit([tracker, user_commit](
            const query::QueryReply& node,
            rpc::OnResponseCallback on_response,
            rpc::OnTimeoutCallback on_timeout) {
        auto run = [node, user_commit, on_response, on_timeout]() mutable {
            if (user_commit) {
                user_commit(node, std::move(on_response), std::move(on_timeout));
            } else {
                // Plain unannounce: JS userCommit is noop → resolve success.
                messages::Response empty;
                on_response(empty);
            }
        };
        if (tracker->inflight == 0) {
            run();
        } else {
            tracker->deferred.push_back(std::move(run));
        }
    });

    q->on_done(std::move(on_done));
    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// immutable_put — target = BLAKE2b(value), query IMMUTABLE_GET to find
// the closest nodes, then commit IMMUTABLE_PUT to each.
//
// JS: .analysis/js/hyperdht/index.js:281-300 (immutablePut)
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
    auto q_weak = std::weak_ptr<query::Query>(q);
    q->set_commit([q_weak, target_id, value](
            const query::QueryReply& node,
            rpc::OnResponseCallback on_response,
            rpc::OnTimeoutCallback on_timeout) {
        auto q_locked = q_weak.lock();
        if (!q_locked) return;
        messages::Request req;
        req.to.addr = node.from_addr;
        req.command = messages::CMD_IMMUTABLE_PUT;
        req.target = target_id;
        if (node.token.has_value()) req.token = *node.token;
        req.value = value;
        uint16_t tid = q_locked->socket().request(
            req, std::move(on_response), on_timeout);
        if (tid == 0) on_timeout(0);
    });

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// immutable_get — query IMMUTABLE_GET, verify BLAKE2b(value) == target on
// every reply, surface verified values via `on_result`.
//
// JS: .analysis/js/hyperdht/index.js:266-279 (immutableGet — for-await loop
//     with crypto_generichash check before returning the first match)
//
// C++ diffs from JS:
//   - Matches JS behaviour: the first verified reply short-circuits the
//     walk via `query.destroy()`. on_result fires exactly once per query
//     in the happy path.
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> immutable_get(rpc::RpcSocket& socket,
                                             const std::array<uint8_t, 32>& target,
                                             OnValueCallback on_result,
                                             query::OnDoneCallback on_done) {
    routing::NodeId target_id{};
    std::copy(target.begin(), target.end(), target_id.begin());

    auto q = query::Query::create(socket, target_id, messages::CMD_IMMUTABLE_GET);
    q->on_done(std::move(on_done));

    // Verify each reply: BLAKE2b(value) must equal target.
    // Capture a weak_ptr so the on_reply lambda can call destroy() on the
    // query itself (JS: `return node` inside `for await` exits the
    // iterator, which destroys the query — index.js:275).
    auto q_weak = std::weak_ptr<query::Query>(q);
    q->on_reply([target, on_result, q_weak](const query::QueryReply& reply) {
        if (!reply.value.has_value() || reply.value->empty()) return;

        std::array<uint8_t, 32> check{};
        crypto_generichash(check.data(), 32,
                           reply.value->data(), reply.value->size(),
                           nullptr, 0);

        if (check == target) {
            if (on_result) on_result(*reply.value);
            if (auto q_ = q_weak.lock()) q_->destroy();
        }
    });

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// mutable_put — Ed25519-sign (seq, value), query MUTABLE_GET (with seq=0)
// to locate closest nodes, commit MUTABLE_PUT to each.
//
// JS: .analysis/js/hyperdht/index.js:355-390 (mutablePut)
//     .analysis/js/hyperdht/lib/persistent.js:236-244 (Persistent.signMutable)
//
// C++ diffs from JS:
//   - JS supports `opts.signMutable` so callers can plug in custom signers
//     (HSM, hardware keys, etc). C++ always uses libsodium directly via
//     `announce_sig::sign_mutable`. A signer-injection hook is tracked
//     under docs/JS-PARITY-GAPS.md.
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
    auto q_weak = std::weak_ptr<query::Query>(q);
    q->set_commit([q_weak, target_id, encoded](
            const query::QueryReply& node,
            rpc::OnResponseCallback on_response,
            rpc::OnTimeoutCallback on_timeout) {
        auto q_locked = q_weak.lock();
        if (!q_locked) return;
        messages::Request req;
        req.to.addr = node.from_addr;
        req.command = messages::CMD_MUTABLE_PUT;
        req.target = target_id;
        if (node.token.has_value()) req.token = *node.token;
        req.value = encoded;
        uint16_t tid = q_locked->socket().request(
            req, std::move(on_response), on_timeout);
        if (tid == 0) on_timeout(0);
    });

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

// ---------------------------------------------------------------------------
// mutable_get — query MUTABLE_GET with min_seq, verify Ed25519 signature
// and `seq >= min_seq` on every reply, fire `on_result` for each.
//
// JS: .analysis/js/hyperdht/index.js:302-353 (mutableGet)
//     .analysis/js/hyperdht/lib/persistent.js:259-267 (verifyMutable)
//
// C++ diffs from JS:
//   - JS aggregates the best result (`latest=true`) inline in the
//     for-await loop (index.js:319-328). C++ surfaces every verified
//     result via `on_result`; the latest-seq tracking lives in
//     `HyperDHT::mutable_get` to keep the dht_ops layer stateless.
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> mutable_get(rpc::RpcSocket& socket,
                                           const std::array<uint8_t, 32>& public_key,
                                           uint64_t min_seq,
                                           OnMutableCallback on_result,
                                           query::OnDoneCallback on_done,
                                           bool latest) {
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

    // When `latest == false`, early-terminate on the first verified reply.
    // JS: index.js:319-328 returns the first valid node and exits the
    // `for await` loop, which tears down the query. Mirror with destroy().
    auto q_weak = std::weak_ptr<query::Query>(q);
    q->on_reply([public_key, min_seq, on_result, latest, q_weak](
                    const query::QueryReply& reply) {
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

        if (!latest) {
            if (auto q_ = q_weak.lock()) q_->destroy();
        }
    });

    add_default_bootstrap(*q, socket);
    q->start();
    return q;
}

}  // namespace dht_ops
}  // namespace hyperdht
