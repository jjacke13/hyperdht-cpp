#pragma once

// DHT RPC request handlers — respond to incoming dht-rpc and HyperDHT commands.
// dht-rpc (internal): PING, PING_NAT, FIND_NODE, DOWN_HINT
// HyperDHT (external): FIND_PEER, LOOKUP, ANNOUNCE, UNANNOUNCE
//
// These handlers make our node a full participant in the DHT network,
// able to answer queries and store announcements for other peers.

#include <string>

#include "hyperdht/announce.hpp"
#include "hyperdht/lru_cache.hpp"
#include "hyperdht/messages.hpp"
#include "hyperdht/router.hpp"
#include "hyperdht/rpc.hpp"

namespace hyperdht {
namespace rpc {

// ---------------------------------------------------------------------------
// RpcHandlers — processes incoming dht-rpc and HyperDHT commands
// ---------------------------------------------------------------------------

class RpcHandlers {
public:
    // router is optional — if null, PEER_HANDSHAKE/HOLEPUNCH are not dispatched
    explicit RpcHandlers(RpcSocket& socket, router::Router* router = nullptr);

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

    // Mutable/immutable storage — LRU cache, 32K max entries, 48h TTL
    static constexpr size_t STORAGE_MAX_ENTRIES = 32768;
    static constexpr uint64_t STORAGE_TTL_MS = 48ULL * 60 * 60 * 1000;  // 48 hours
    static constexpr uint64_t GC_INTERVAL_MS = 60000;  // 1 minute

    LruCache<std::string, std::vector<uint8_t>> mutables_{STORAGE_MAX_ENTRIES};
    LruCache<std::string, std::vector<uint8_t>> immutables_{STORAGE_MAX_ENTRIES};
    uv_timer_t* gc_timer_ = nullptr;

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
