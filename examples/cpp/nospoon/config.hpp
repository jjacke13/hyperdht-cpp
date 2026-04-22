#pragma once
// JSONC config parser for nospoon VPN.
// Supports // and /* */ comments (stripped before parsing).
// Schema is fixed and simple — no generic JSON library needed.

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

namespace nospoon {

struct Config {
    std::string mode;        // "server" or "client"
    std::string ip;          // "10.0.0.1/24"
    std::string seed;        // 64-char hex (optional)
    std::string server_key;  // client only: server pubkey hex
    int mtu = 1400;
    std::map<std::string, std::string> peers;  // pubkey_hex -> ip

    // Parse IP without CIDR prefix
    std::string ip_address() const {
        auto slash = ip.find('/');
        return (slash != std::string::npos) ? ip.substr(0, slash) : ip;
    }
};

// Strip // and /* */ comments from JSONC
inline std::string strip_comments(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    bool in_string = false;
    for (size_t i = 0; i < input.size(); i++) {
        if (in_string) {
            out.push_back(input[i]);
            if (input[i] == '"' && (i == 0 || input[i - 1] != '\\'))
                in_string = false;
            continue;
        }
        if (input[i] == '"') {
            in_string = true;
            out.push_back(input[i]);
        } else if (i + 1 < input.size() && input[i] == '/' && input[i + 1] == '/') {
            // Line comment — skip to newline
            while (i < input.size() && input[i] != '\n') i++;
        } else if (i + 1 < input.size() && input[i] == '/' && input[i + 1] == '*') {
            // Block comment — skip to */
            i += 2;
            while (i + 1 < input.size() && !(input[i] == '*' && input[i + 1] == '/')) i++;
            i++;  // skip closing /
        } else {
            out.push_back(input[i]);
        }
    }
    return out;
}

// Minimal JSON string value extractor
inline std::string json_string(const std::string& json, const std::string& key) {
    auto pattern = "\"" + key + "\"";
    auto pos = json.find(pattern);
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + pattern.size() + 1);
    if (pos == std::string::npos) return "";
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

// Minimal JSON integer value extractor
inline int json_int(const std::string& json, const std::string& key, int fallback) {
    auto pattern = "\"" + key + "\"";
    auto pos = json.find(pattern);
    if (pos == std::string::npos) return fallback;
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return fallback;
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    return std::atoi(json.c_str() + pos);
}

// Parse the peers object: {"hex_key": "ip", ...}
inline std::map<std::string, std::string> json_peers(const std::string& json) {
    std::map<std::string, std::string> result;
    auto pos = json.find("\"peers\"");
    if (pos == std::string::npos) return result;
    pos = json.find('{', pos);
    if (pos == std::string::npos) return result;
    auto end = json.find('}', pos);
    if (end == std::string::npos) return result;
    auto block = json.substr(pos + 1, end - pos - 1);

    // Extract key-value pairs from the block
    size_t i = 0;
    while (i < block.size()) {
        auto k_start = block.find('"', i);
        if (k_start == std::string::npos) break;
        auto k_end = block.find('"', k_start + 1);
        if (k_end == std::string::npos) break;
        auto v_start = block.find('"', k_end + 1);
        if (v_start == std::string::npos) break;
        auto v_end = block.find('"', v_start + 1);
        if (v_end == std::string::npos) break;

        auto key = block.substr(k_start + 1, k_end - k_start - 1);
        auto val = block.substr(v_start + 1, v_end - v_start - 1);
        result[key] = val;
        i = v_end + 1;
    }
    return result;
}

// Load and parse config file
inline Config load_config(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        fprintf(stderr, "Error: cannot open %s\n", path.c_str());
        std::exit(1);
    }
    std::stringstream buf;
    buf << f.rdbuf();
    auto json = strip_comments(buf.str());

    Config cfg;
    cfg.mode = json_string(json, "mode");
    cfg.ip = json_string(json, "ip");
    cfg.seed = json_string(json, "seed");
    cfg.server_key = json_string(json, "server");
    cfg.mtu = json_int(json, "mtu", 1400);
    cfg.peers = json_peers(json);

    if (cfg.mode.empty()) {
        fprintf(stderr, "Error: config must have \"mode\": \"server\" or \"client\"\n");
        std::exit(1);
    }
    if (cfg.ip.empty()) {
        fprintf(stderr, "Error: config must have \"ip\": \"x.x.x.x/y\"\n");
        std::exit(1);
    }
    return cfg;
}

// Parse 64-char hex string to 32 bytes
inline bool hex_to_bytes(const std::string& hex, uint8_t* out, size_t len) {
    if (hex.size() != len * 2) return false;
    for (size_t i = 0; i < len; i++) {
        unsigned byte;
        if (sscanf(hex.c_str() + i * 2, "%02x", &byte) != 1) return false;
        out[i] = static_cast<uint8_t>(byte);
    }
    return true;
}

inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        out += buf;
    }
    return out;
}

}  // namespace nospoon
