#pragma once
// IP routing table: maps destination IPv4 address -> stream pointer.
// Parses IP headers at fixed offsets (no full IP stack needed).

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <unordered_map>

namespace nospoon {

class RoutingTable {
public:
    void add(uint32_t ip, void* stream) { routes_[ip] = stream; }
    void remove(uint32_t ip) { routes_.erase(ip); }

    void remove_stream(void* stream) {
        for (auto it = routes_.begin(); it != routes_.end();) {
            if (it->second == stream)
                it = routes_.erase(it);
            else
                ++it;
        }
    }

    void* lookup(uint32_t ip) const {
        auto it = routes_.find(ip);
        return (it != routes_.end()) ? it->second : nullptr;
    }

    // Extract destination IP from raw IPv4 packet header (offset 16)
    static uint32_t dest_ip(const uint8_t* pkt, size_t len) {
        if (len < 20 || (pkt[0] >> 4) != 4) return 0;
        uint32_t ip;
        std::memcpy(&ip, pkt + 16, 4);
        return ip;
    }

    // Extract source IP from raw IPv4 packet header (offset 12)
    static uint32_t src_ip(const uint8_t* pkt, size_t len) {
        if (len < 20 || (pkt[0] >> 4) != 4) return 0;
        uint32_t ip;
        std::memcpy(&ip, pkt + 12, 4);
        return ip;
    }

    static std::string ip_to_string(uint32_t ip) {
        auto* b = reinterpret_cast<const uint8_t*>(&ip);
        char buf[16];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        return buf;
    }

    static uint32_t string_to_ip(const std::string& s) {
        unsigned a, b, c, d;
        if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
        uint8_t bytes[4] = {(uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d};
        uint32_t ip;
        std::memcpy(&ip, bytes, 4);
        return ip;
    }

private:
    std::unordered_map<uint32_t, void*> routes_;
};

}  // namespace nospoon
