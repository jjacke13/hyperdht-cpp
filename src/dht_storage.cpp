// HyperDHT storage operations — find_peer, lookup, announce, unannounce,
// ping, immutable/mutable put/get.
//
// Split from src/dht.cpp. See dht.cpp for the JS flow map overview.

#include "hyperdht/dht.hpp"

#include <cstdio>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/debug.hpp"
#include "hyperdht/dht_ops.hpp"

namespace hyperdht {

// ---------------------------------------------------------------------------
// DHT operations (thin wrappers)
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> HyperDHT::find_peer(
    const noise::PubKey& public_key,
    query::OnReplyCallback on_reply,
    query::OnDoneCallback on_done) {
    ensure_bound();
    return dht_ops::find_peer(*socket_, public_key,
                               std::move(on_reply), std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::lookup(
    const routing::NodeId& target,
    query::OnReplyCallback on_reply,
    query::OnDoneCallback on_done) {
    ensure_bound();
    return dht_ops::lookup(*socket_, target,
                            std::move(on_reply), std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::announce(
    const routing::NodeId& target,
    const noise::Keypair& keypair,
    const std::vector<compact::Ipv4Address>& relay_addresses,
    uint64_t bump,
    query::OnDoneCallback on_done) {
    ensure_bound();
    return dht_ops::announce(*socket_, target, keypair, relay_addresses, bump,
                             std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::announce(
    const routing::NodeId& target,
    const noise::Keypair& keypair,
    const std::vector<compact::Ipv4Address>& relay_addresses,
    uint64_t bump,
    const noise::Keypair& clear_keypair,
    query::OnDoneCallback on_done) {
    // dhttop-6: clear-announce. JS `announce(..., { clear: true })` routes
    // through lookupAndUnannounce (index.js:250) so stale records for our key
    // are removed before the new ANNOUNCE lands.
    ensure_bound();
    return dht_ops::announce(*socket_, target, keypair, relay_addresses, bump,
                             std::move(on_done), &clear_keypair);
}

// ---------------------------------------------------------------------------
// lookupAndUnannounce (dhttop-1)
//
// JS: .analysis/js/hyperdht/index.js:197-238 (lookupAndUnannounce — a LOOKUP
//     query whose per-reply map signs + sends UNANNOUNCE to each node still
//     holding our record; the commit awaits all in-flight unannounces).
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> HyperDHT::lookup_and_unannounce(
    const noise::PubKey& public_key,
    const noise::Keypair& keypair,
    query::OnReplyCallback on_reply,
    query::OnDoneCallback on_done) {
    ensure_bound();
    // target = BLAKE2b(public_key) — the self-announce topic (matches the
    // existing C++ convention; JS callers pass `target` directly).
    routing::NodeId target{};
    crypto_generichash(target.data(), 32, public_key.data(), 32, nullptr, 0);

    // JS index.js:203-206 — if this node is itself a persistent store, unlink
    // our own local record before hitting the network
    // (`this._persistent.unannounce(target, keyPair.publicKey)`,
    // persistent.js:45-51). Our target IS BLAKE2b(publicKey), so this is
    // always the self-announce case: drop the relay-only router entry that a
    // self-ANNOUNCE created (persistent.js:49 `_router.delete`). Never clobber
    // a live local Server's entry (it owns its own lifecycle via Server::close).
    // (JS also removes from the records cache keyed by pubkey; the C++
    // AnnounceStore is keyed by sender address, so a by-pubkey removal has no
    // clean analog and stale self-records are left to TTL expiry.)
    if (socket_ && !socket_->is_ephemeral()) {
        announce::TargetKey tk{};
        std::copy(target.begin(), target.end(), tk.begin());
        auto* entry = router_.get(tk);
        if (entry && !entry->on_peer_handshake) {
            router_.remove(tk);
        }
    }

    return dht_ops::lookup_and_unannounce(
        *socket_, target, keypair,
        std::move(on_reply),
        /*user_commit=*/nullptr,  // plain unannounce → noop commit (JS)
        std::move(on_done));
}

// ---------------------------------------------------------------------------
// ping — PING an arbitrary address and fire a bool callback.
//
// ---------------------------------------------------------------------------
// B1: unannounce — standalone convenience wrapper
// JS: hyperdht/index.js:240-242
// ---------------------------------------------------------------------------

void HyperDHT::unannounce(const noise::PubKey& public_key,
                           const noise::Keypair& keypair,
                           std::function<void()> on_done) {
    lookup_and_unannounce(public_key, keypair,
        [](const query::QueryReply&) {},
        [on_done](int /*error*/, const std::vector<query::QueryReply>&) {
            if (on_done) on_done();
        });
}

// ---------------------------------------------------------------------------
// JS: .analysis/js/dht-rpc/index.js:260-299 (dht.ping — wraps io.createRequest
//     with PING cmd and returns a Promise)
// ---------------------------------------------------------------------------

void HyperDHT::ping(const compact::Ipv4Address& addr,
                     std::function<void(bool ok)> on_done) {
    ensure_bound();
    messages::Request req;
    req.command = messages::CMD_PING;
    req.internal = true;
    req.to.addr = addr;

    socket_->request(req,
        [on_done](const messages::Response&) {
            if (on_done) on_done(true);
        },
        [on_done](uint16_t) {
            if (on_done) on_done(false);
        });
}

// ---------------------------------------------------------------------------
// Mutable / Immutable storage — thin wrappers around dht_ops that surface
// JS-shaped result structs through the public HyperDHT class.
//
// JS: .analysis/js/hyperdht/index.js:266-279 (immutableGet)
//     .analysis/js/hyperdht/index.js:281-300 (immutablePut)
//     .analysis/js/hyperdht/index.js:302-353 (mutableGet)
//     .analysis/js/hyperdht/index.js:355-390 (mutablePut)
//
// These match the JS reference in `hyperdht/index.js` (immutablePut,
// immutableGet, mutablePut, mutableGet). The underlying dht_ops functions
// handle signing, target computation, query+commit. We add a small shim
// on top that (a) produces the JS-style result struct with `closest_nodes`,
// (b) forwards streaming per-result callbacks for get operations, and
// (c) tracks best-seen results for mutable_get so the caller gets the latest.
//
// C++ diffs from JS:
//   - JS `mutableGet` consumes the query as an async iterator and tracks
//     the best-seen result inline (index.js:319-328). C++ uses an
//     `on_value` reply callback that mutates a shared_ptr<MutableGetResult>.
//   - JS `immutableGet` returns the first reply whose hash matches the
//     target (index.js:272-275). C++ does the same check inside dht_ops
//     and just aggregates here.
//   - JS computes the signature inside the query commit; C++ pre-signs
//     in `dht_ops::mutable_put` so the result struct can be returned
//     immediately on completion.
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> HyperDHT::immutable_put(
    const std::vector<uint8_t>& value,
    ImmutablePutCallback on_done) {
    // JS: empty values are rejected server-side. Reject at the class layer
    // so callers get an immediate nullptr instead of a silent failed query.
    if (value.empty()) {
        DHT_LOG("  [dht] immutable_put: rejected (empty value)\n");
        return nullptr;
    }
    ensure_bound();

    // Target is BLAKE2b(value) — compute here so we can hand it to the caller.
    // `dht_ops::immutable_put` also computes the hash internally; this minor
    // double-work is acceptable to keep the wrapper layer self-contained.
    ImmutablePutResult result;
    crypto_generichash(result.hash.data(), 32,
                       value.data(), value.size(), nullptr, 0);

    DHT_LOG("  [dht] immutable_put: value=%zu bytes, "
            "hash=%02x%02x%02x%02x...\n",
            value.size(),
            result.hash[0], result.hash[1], result.hash[2], result.hash[3]);

    return dht_ops::immutable_put(*socket_, value,
        [on_done = std::move(on_done), result = std::move(result)](
                int /*error*/, const std::vector<query::QueryReply>& closest) mutable {
            DHT_LOG("  [dht] immutable_put done: %zu closest nodes\n",
                    closest.size());
            result.closest_nodes = closest;
            if (on_done) on_done(result);
        });
}

std::shared_ptr<query::Query> HyperDHT::immutable_get(
    const std::array<uint8_t, 32>& target,
    ImmutableGetCallback on_done) {
    return immutable_get(target, /*on_value=*/nullptr, std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::immutable_get(
    const std::array<uint8_t, 32>& target,
    ImmutableValueCallback on_value,
    ImmutableGetCallback on_done) {
    ensure_bound();

    DHT_LOG("  [dht] immutable_get: target=%02x%02x%02x%02x...\n",
            target[0], target[1], target[2], target[3]);

    // Accumulate the first verified reply. `dht_ops::immutable_get` already
    // verifies BLAKE2b(value) === target, so any callback invocation is good.
    // Share state between on_result and on_done via a shared_ptr so they
    // can both safely mutate it across the async query lifetime.
    auto result = std::make_shared<ImmutableGetResult>();

    return dht_ops::immutable_get(*socket_, target,
        [result, on_value = std::move(on_value)](
                const std::vector<uint8_t>& value) {
            // Forward streaming callback (if any) on every verified reply.
            if (on_value) on_value(value);
            // Aggregate the first match for the on_done summary.
            if (!result->found) {
                DHT_LOG("  [dht] immutable_get: first verified value "
                        "(%zu bytes)\n", value.size());
                result->found = true;
                result->value = value;
            }
        },
        [on_done = std::move(on_done), result](
                int /*error*/, const std::vector<query::QueryReply>&) {
            DHT_LOG("  [dht] immutable_get done: found=%d\n",
                    result->found ? 1 : 0);
            if (on_done) on_done(*result);
        });
}

std::shared_ptr<query::Query> HyperDHT::mutable_put(
    const noise::Keypair& keypair,
    const std::vector<uint8_t>& value,
    uint64_t seq,
    MutablePutCallback on_done) {
    if (value.empty()) {
        DHT_LOG("  [dht] mutable_put: rejected (empty value)\n");
        return nullptr;
    }
    ensure_bound();

    // Pre-compute the result we'll hand back. Signature is deterministic
    // from (seq, value, secret_key), so we can produce it locally without
    // waiting for the commit phase.
    MutablePutResult result;
    result.public_key = keypair.public_key;
    result.seq = seq;
    result.signature = announce_sig::sign_mutable(
        seq, value.data(), value.size(), keypair);

    DHT_LOG("  [dht] mutable_put: pk=%02x%02x%02x%02x... seq=%llu "
            "value=%zu bytes\n",
            keypair.public_key[0], keypair.public_key[1],
            keypair.public_key[2], keypair.public_key[3],
            static_cast<unsigned long long>(seq), value.size());

    return dht_ops::mutable_put(*socket_, keypair, value, seq,
        [on_done = std::move(on_done), result = std::move(result)](
                int /*error*/, const std::vector<query::QueryReply>& closest) mutable {
            DHT_LOG("  [dht] mutable_put done: %zu closest nodes\n",
                    closest.size());
            result.closest_nodes = closest;
            if (on_done) on_done(result);
        });
}

std::shared_ptr<query::Query> HyperDHT::mutable_get(
    const noise::PubKey& public_key,
    uint64_t min_seq,
    bool latest,
    MutableGetCallback on_done) {
    return mutable_get(public_key, min_seq, latest,
                       /*on_value=*/nullptr, std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::mutable_get(
    const noise::PubKey& public_key,
    uint64_t min_seq,
    bool latest,
    MutableValueCallback on_value,
    MutableGetCallback on_done) {
    ensure_bound();

    DHT_LOG("  [dht] mutable_get: pk=%02x%02x%02x%02x... "
            "min_seq=%llu latest=%d\n",
            public_key[0], public_key[1], public_key[2], public_key[3],
            static_cast<unsigned long long>(min_seq), latest ? 1 : 0);

    // Track the best-seen result across all replies. `dht_ops::mutable_get`
    // already verifies signatures and filters by `min_seq`, so any result
    // arriving here is valid.
    //
    // JS semantics (hyperdht/index.js:319-328):
    //   - With `latest=true` (default): return the highest-seq valid reply.
    //   - With `latest=false`: return the FIRST valid reply. Early query
    //     termination is a §9 follow-up; until then the walk continues but
    //     the result is frozen after the first match.
    auto result = std::make_shared<MutableGetResult>();

    return dht_ops::mutable_get(*socket_, public_key, min_seq,
        [result, latest, on_value = std::move(on_value)](
                const dht_ops::MutableResult& r) {
            // Streaming callback first (if any) — receives every verified reply.
            if (on_value) on_value(r);

            if (!result->found) {
                DHT_LOG("  [dht] mutable_get: first verified reply "
                        "seq=%llu (%zu bytes)\n",
                        static_cast<unsigned long long>(r.seq),
                        r.value.size());
                result->found = true;
                result->seq = r.seq;
                result->value = r.value;
                result->signature = r.signature;
                return;
            }
            // Already have one. If `latest==false`, keep the first.
            if (!latest) return;
            // Otherwise prefer the highest seq seen so far.
            if (r.seq > result->seq) {
                DHT_LOG("  [dht] mutable_get: newer seq=%llu replaces %llu\n",
                        static_cast<unsigned long long>(r.seq),
                        static_cast<unsigned long long>(result->seq));
                result->seq = r.seq;
                result->value = r.value;
                result->signature = r.signature;
            }
        },
        [on_done = std::move(on_done), result](
                int /*error*/, const std::vector<query::QueryReply>&) {
            DHT_LOG("  [dht] mutable_get done: found=%d seq=%llu\n",
                    result->found ? 1 : 0,
                    static_cast<unsigned long long>(result->seq));
            if (on_done) on_done(*result);
        });
}

}  // namespace hyperdht
