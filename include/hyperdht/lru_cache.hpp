#pragma once

// LRU cache with max size and TTL eviction.
// Thread-unsafe (single-threaded libuv model).
//
// Matches JS xache behavior:
// - Max entries: evicts oldest on insert when full
// - TTL: gc() removes entries older than max_age
// - get() promotes to front (most recently used)
// - put() resets created_at timestamp

#include <cstddef>
#include <cstdint>
#include <list>
#include <string>
#include <unordered_map>

namespace hyperdht {

template <typename Key, typename Value>
class LruCache {
public:
    explicit LruCache(size_t max_size) : max_size_(max_size) {}

    // Insert or update. Evicts oldest if at capacity.
    void put(const Key& key, Value value, uint64_t now_ms) {
        auto it = map_.find(key);
        if (it != map_.end()) {
            // Update: move to front, refresh timestamp
            entries_.splice(entries_.begin(), entries_, it->second);
            it->second->value = std::move(value);
            it->second->created_at = now_ms;
            return;
        }

        // Evict oldest if full
        while (entries_.size() >= max_size_ && !entries_.empty()) {
            auto& oldest = entries_.back();
            map_.erase(oldest.key);
            entries_.pop_back();
        }

        // Insert at front
        entries_.emplace_front(Entry{key, std::move(value), now_ms});
        map_[key] = entries_.begin();
    }

    // Lookup. Returns nullptr if not found. Promotes to front.
    const Value* get(const Key& key) {
        auto it = map_.find(key);
        if (it == map_.end()) return nullptr;
        // Promote to front (most recently used)
        entries_.splice(entries_.begin(), entries_, it->second);
        return &it->second->value;
    }

    // Remove by key.
    void remove(const Key& key) {
        auto it = map_.find(key);
        if (it == map_.end()) return;
        entries_.erase(it->second);
        map_.erase(it);
    }

    // Evict entries older than max_age_ms. Walk from oldest (back).
    void gc(uint64_t now_ms, uint64_t max_age_ms) {
        while (!entries_.empty()) {
            auto& oldest = entries_.back();
            if (now_ms >= oldest.created_at &&
                (now_ms - oldest.created_at) > max_age_ms) {
                map_.erase(oldest.key);
                entries_.pop_back();
            } else {
                break;  // Entries are ordered by insertion — once we hit a fresh one, stop
            }
        }
    }

    size_t size() const { return map_.size(); }
    bool empty() const { return map_.empty(); }
    size_t max_size() const { return max_size_; }

private:
    struct Entry {
        Key key;
        Value value;
        uint64_t created_at = 0;
    };

    size_t max_size_;
    std::list<Entry> entries_;                                  // front = newest, back = oldest
    std::unordered_map<Key, typename std::list<Entry>::iterator> map_;
};

}  // namespace hyperdht
