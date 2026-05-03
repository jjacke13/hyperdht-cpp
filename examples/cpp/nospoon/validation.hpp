#pragma once
// Input validation for config fields. Mirrors nospoon/lib/validation.js.

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <regex>
#include <string>

namespace nospoon::validation {

struct Result {
    bool valid = true;
    std::string error;
};

inline Result validate_hex64(const std::string& value, const std::string& label) {
    if (value.size() != 64) {
        return {false, label + " must be exactly 64 hex characters"};
    }
    for (char c : value) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return {false, label + " must be exactly 64 hex characters"};
        }
    }
    return {};
}

inline Result validate_cidr(const std::string& value, const std::string& label) {
    static const std::regex re(R"(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$)");
    if (!std::regex_match(value, re)) {
        return {false, label + " must be in CIDR format (e.g. 10.0.0.1/24)"};
    }
    auto slash = value.find('/');
    int prefix = std::atoi(value.substr(slash + 1).c_str());
    if (prefix < 0 || prefix > 32) {
        return {false, label + " has invalid prefix (0-32)"};
    }
    int o[4];
    std::sscanf(value.c_str(), "%d.%d.%d.%d", &o[0], &o[1], &o[2], &o[3]);
    for (int v : o) {
        if (v < 0 || v > 255) {
            return {false, label + " has invalid IP octet (0-255)"};
        }
    }
    return {};
}

inline Result validate_cidr_v6(const std::string& value, const std::string& label) {
    auto slash = value.find('/');
    if (slash == std::string::npos) {
        return {false, label + " must be in CIDR format (e.g. fd00::1/64)"};
    }
    std::string addr = value.substr(0, slash);
    int prefix = std::atoi(value.substr(slash + 1).c_str());
    if (prefix < 1 || prefix > 128) {
        return {false, label + " has invalid prefix (1-128)"};
    }
    // Quick-and-loose IPv6 syntax check: must contain at least one colon and
    // only valid hex / colon characters. Real validity is verified by the OS
    // when we feed it to ifconfig/netsh/ip.
    if (addr.find(':') == std::string::npos) {
        return {false, label + " is not a valid IPv6 address"};
    }
    for (char c : addr) {
        if (c != ':' && !std::isxdigit(static_cast<unsigned char>(c))) {
            return {false, label + " has invalid character"};
        }
    }
    return {};
}

inline Result validate_mtu(int value) {
    if (value < 576 || value > 65535) {
        return {false, "MTU must be between 576 and 65535"};
    }
    return {};
}

}  // namespace nospoon::validation
