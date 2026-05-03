#pragma once
// IP routing table — maps a destination IP (string) to a stream pointer.
// Supports both IPv4 and IPv6 packets.
//
// String keys mean a single map handles both address families; matches
// nospoon/lib/routing.js exactly. Format: dotted-quad for v4, lowercase
// colon-hex with :: zero-collapsing for v6.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>

namespace nospoon {

class RoutingTable {
public:
    void add(const std::string& ip, void* stream) { routes_[ip] = stream; }
    void remove(const std::string& ip) { routes_.erase(ip); }

    void remove_stream(void* stream) {
        for (auto it = routes_.begin(); it != routes_.end();) {
            if (it->second == stream)
                it = routes_.erase(it);
            else
                ++it;
        }
    }

    void* lookup(const std::string& ip) const {
        auto it = routes_.find(ip);
        return (it != routes_.end()) ? it->second : nullptr;
    }

    size_t size() const { return routes_.size(); }

    // ---------------------------------------------------------------------
    // IP packet header parsers
    // ---------------------------------------------------------------------

    // Returns "" on invalid / unknown version.
    static std::string read_dest_ip(const uint8_t* pkt, size_t len) {
        if (len < 1) return {};
        uint8_t version = (pkt[0] >> 4) & 0x0f;
        if (version == 4) {
            if (len < 20) return {};
            return format_ipv4(pkt, 16);   // dest IP at offset 16
        }
        if (version == 6) {
            if (len < 40) return {};
            return format_ipv6(pkt, 24);   // dest IP at offset 24 (16 bytes)
        }
        return {};
    }

    static std::string read_src_ip(const uint8_t* pkt, size_t len) {
        if (len < 1) return {};
        uint8_t version = (pkt[0] >> 4) & 0x0f;
        if (version == 4) {
            if (len < 20) return {};
            return format_ipv4(pkt, 12);   // src IP at offset 12
        }
        if (version == 6) {
            if (len < 40) return {};
            return format_ipv6(pkt, 8);    // src IP at offset 8 (16 bytes)
        }
        return {};
    }

    static std::string format_ipv4(const uint8_t* pkt, size_t off) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                      pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]);
        return buf;
    }

    // Format a 16-byte IPv6 address starting at pkt[off]. Lowercase hex,
    // collapses the longest run of zero groups to ::. Matches the form
    // emitted by nospoon/lib/routing.js so we can use these strings as
    // map keys interchangeably with what comes off the wire.
    static std::string format_ipv6(const uint8_t* pkt, size_t off) {
        uint16_t groups[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = (uint16_t(pkt[off + i * 2]) << 8) | pkt[off + i * 2 + 1];
        }
        // Find longest run of zero groups (length must be >= 2 to use ::).
        int best_start = -1, best_len = 0;
        int cur_start = -1, cur_len = 0;
        for (int i = 0; i < 8; i++) {
            if (groups[i] == 0) {
                if (cur_start < 0) cur_start = i;
                cur_len++;
                if (cur_len > best_len) {
                    best_start = cur_start;
                    best_len = cur_len;
                }
            } else {
                cur_start = -1;
                cur_len = 0;
            }
        }
        if (best_len < 2) { best_start = -1; best_len = 0; }

        std::string out;
        out.reserve(40);
        for (int i = 0; i < 8; i++) {
            if (i == best_start) {
                out += "::";
                i += best_len - 1;
                continue;
            }
            if (!out.empty() && out.back() != ':') out += ':';
            char buf[8];
            std::snprintf(buf, sizeof(buf), "%x", groups[i]);
            out += buf;
        }
        if (out.empty()) out = "::";
        return out;
    }

private:
    std::unordered_map<std::string, void*> routes_;
};

}  // namespace nospoon
