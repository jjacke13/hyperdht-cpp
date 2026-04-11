#pragma once

// DHT RPC request handlers — respond to incoming dht-rpc and HyperDHT commands.
// dht-rpc (internal): PING, PING_NAT, FIND_NODE, DOWN_HINT, DELAYED_PING
// HyperDHT (external): FIND_PEER, LOOKUP, ANNOUNCE, UNANNOUNCE, MUTABLE/IMMUTABLE_*
//
// These handlers make our node a full participant in the DHT network,
// able to answer queries and store announcements for other peers.

#include <string>
#include <vector>

#include "hyperdht/announce.hpp"
#include "hyperdht/lru_cache.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"

namespace hyperdht {
namespace rpc {

// ---------------------------------------------------------------------------
// Storage cache config (JS: hyperdht/index.js:597 defaultCacheOpts)
// ---------------------------------------------------------------------------

struct StorageCacheConfig {
    // Max entries in the mutable/immutable caches. JS splits mutable and
    // immutable into `maxSize/2` each (index.js:610-615). We follow that
    // split internally — callers pass one `max_size` and we halve it.
    //
    // NOTE: values < 2 are clamped to a per-cache minimum of 1 entry
    // (so `max_size == 0` does NOT disable storage — it degenerates to
    // 1-entry LRUs). Pass a much larger value or bypass the cache in
    // other ways if you need storage disabled.
    size_t max_size = 65536;

    // Max entry age in ms. JS uses 48h for mutable/immutable specifically
    // (index.js:611,615) while other caches use 20 min. We expose one
    // `ttl_ms` for the storage caches — default 48h to match JS behavior.
    uint64_t ttl_ms = 48ULL * 60 * 60 * 1000;
};

// ---------------------------------------------------------------------------
// RpcHandlers — processes incoming dht-rpc and HyperDHT commands
// ---------------------------------------------------------------------------

class RpcHandlers {
public:
    // router is optional — if null, PEER_HANDSHAKE/HOLEPUNCH are not dispatched
    explicit RpcHandlers(RpcSocket& socket,
                         router::Router* router = nullptr,
                         StorageCacheConfig cache_config = {});

    // Install the handler on the RpcSocket (calls socket.on_request)
    void install();

    // Handle an incoming request — dispatches to the appropriate handler
    void handle(const messages::Request& req);

    // Access the announce store (for testing)
    const announce::AnnounceStore& store() const { return store_; }
    announce::AnnounceStore& store() { return store_; }

private:
    RpcSocket& socket_;
    router::Router* router_ = nullptr;
    announce::AnnounceStore store_;

    // dht-rpc internal commands
    void handle_ping(const messages::Request& req);
    void handle_ping_nat(const messages::Request& req);
    void handle_find_node(const messages::Request& req);
    void handle_down_hint(const messages::Request& req);
    void handle_delayed_ping(const messages::Request& req);

    // HyperDHT external commands
    void handle_find_peer(const messages::Request& req);
    void handle_lookup(const messages::Request& req);
    void handle_announce(const messages::Request& req);
    void handle_unannounce(const messages::Request& req);
    void handle_mutable_put(const messages::Request& req);
    void handle_mutable_get(const messages::Request& req);
    void handle_immutable_put(const messages::Request& req);
    void handle_immutable_get(const messages::Request& req);

    // Build a response with closer nodes to the target
    messages::Response make_query_response(const messages::Request& req);

    // Mutable/immutable storage — LRU caches. Max entries split in half
    // between the two caches to match JS `hyperdht/index.js:610-615`.
    static constexpr uint64_t GC_INTERVAL_MS = 60000;  // 1 minute

    uint64_t storage_ttl_ms_;
    LruCache<std::string, std::vector<uint8_t>> mutables_;
    LruCache<std::string, std::vector<uint8_t>> immutables_;
    uv_timer_t* gc_timer_ = nullptr;

    // DELAYED_PING pending replies: one heap-allocated struct per scheduled reply.
    // Timer is embedded; on fire we send the reply and uv_close the timer (the close
    // callback deletes the struct). On destructor, we orphan + uv_close all pending.
    struct DelayedReply {
        uv_timer_t timer;
        RpcHandlers* owner;         // Null after destruction to prevent use-after-free
        uint16_t tid;
        compact::Ipv4Address from;
    };
    std::vector<DelayedReply*> pending_delayed_;

    static void on_delayed_ping_fire(uv_timer_t* timer);

    static std::string to_hex_key(const std::array<uint8_t, 32>& t) {
        static const char h[] = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (auto b : t) { out.push_back(h[b >> 4]); out.push_back(h[b & 0x0F]); }
        return out;
    }

    void start_gc_timer();
    static void on_gc_tick(uv_timer_t* timer);

public:
    ~RpcHandlers();

    // Test accessors for pre-populating storage
    void mutables_put(const std::array<uint8_t, 32>& target, std::vector<uint8_t> value) {
        mutables_.put(to_hex_key(target), std::move(value), 0);
    }
    void immutables_put(const std::array<uint8_t, 32>& target, std::vector<uint8_t> value) {
        immutables_.put(to_hex_key(target), std::move(value), 0);
    }
};

}  // namespace rpc
}  // namespace hyperdht
