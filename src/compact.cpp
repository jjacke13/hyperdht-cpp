// compact-encoding implementation — varints, fixed-width ints,
// raw/length-prefixed buffers, IPv4/IPv6 (compact-encoding-net).
// Matches the JS reference wire format byte-for-byte.
//
// Buffer::decode capped at 64KB to prevent allocation attacks.

#include "hyperdht/compact.hpp"

#include <charconv>

namespace hyperdht::compact {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static inline bool has_bytes(const State& s, size_t n) {
    // Use subtraction to avoid size_t overflow: start + n could wrap around
    return s.start <= s.end && n <= s.end - s.start;
}

// Check buffer is writable and has space (for encode paths)
static inline bool can_write(const State& s, size_t n) {
    return s.buffer != nullptr && s.start + n <= s.end;
}

static inline void write_le16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}

static inline void write_le32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

static inline void write_le64(uint8_t* p, uint64_t v) {
    write_le32(p, static_cast<uint32_t>(v));
    write_le32(p + 4, static_cast<uint32_t>(v >> 32));
}

static inline uint16_t read_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

static inline uint32_t read_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

static inline uint64_t read_le64(const uint8_t* p) {
    return static_cast<uint64_t>(read_le32(p)) |
           (static_cast<uint64_t>(read_le32(p + 4)) << 32);
}

// ---------------------------------------------------------------------------
// Uint (varint)
// ---------------------------------------------------------------------------

void Uint::preencode(State& s, uint64_t v) {
    if (v <= 0xFC)
        s.end += 1;
    else if (v <= 0xFFFF)
        s.end += 3;
    else if (v <= 0xFFFFFFFF)
        s.end += 5;
    else
        s.end += 9;
}

void Uint::encode(State& s, uint64_t v) {
    if (s.error || s.buffer == nullptr) { s.error = true; return; }
    if (v <= 0xFC) {
        if (!has_bytes(s, 1)) { s.error = true; return; }
        s.buffer[s.start++] = static_cast<uint8_t>(v);
    } else if (v <= 0xFFFF) {
        if (!has_bytes(s, 3)) { s.error = true; return; }
        s.buffer[s.start++] = 0xFD;
        write_le16(s.buffer + s.start, static_cast<uint16_t>(v));
        s.start += 2;
    } else if (v <= 0xFFFFFFFF) {
        if (!has_bytes(s, 5)) { s.error = true; return; }
        s.buffer[s.start++] = 0xFE;
        write_le32(s.buffer + s.start, static_cast<uint32_t>(v));
        s.start += 4;
    } else {
        if (!has_bytes(s, 9)) { s.error = true; return; }
        s.buffer[s.start++] = 0xFF;
        write_le64(s.buffer + s.start, v);
        s.start += 8;
    }
}

uint64_t Uint::decode(State& s) {
    if (s.error || !has_bytes(s, 1)) { s.error = true; return 0; }
    uint8_t first = s.data()[s.start++];
    if (first <= 0xFC) return first;
    if (first == 0xFD) {
        if (!has_bytes(s, 2)) { s.error = true; return 0; }
        uint16_t v = read_le16(s.data() + s.start);
        s.start += 2;
        return v;
    }
    if (first == 0xFE) {
        if (!has_bytes(s, 4)) { s.error = true; return 0; }
        uint32_t v = read_le32(s.data() + s.start);
        s.start += 4;
        return v;
    }
    // 0xFF
    if (!has_bytes(s, 8)) { s.error = true; return 0; }
    uint64_t v = read_le64(s.data() + s.start);
    s.start += 8;
    return v;
}

// ---------------------------------------------------------------------------
// Uint8
// ---------------------------------------------------------------------------

void Uint8::preencode(State& s, uint8_t) { s.end += 1; }

void Uint8::encode(State& s, uint8_t v) {
    if (s.error || !s.buffer || !has_bytes(s, 1)) { s.error = true; return; }
    s.buffer[s.start++] = v;
}

uint8_t Uint8::decode(State& s) {
    if (s.error || !has_bytes(s, 1)) { s.error = true; return 0; }
    return s.data()[s.start++];
}

// ---------------------------------------------------------------------------
// Uint16
// ---------------------------------------------------------------------------

void Uint16::preencode(State& s, uint16_t) { s.end += 2; }

void Uint16::encode(State& s, uint16_t v) {
    if (s.error || !s.buffer || !has_bytes(s, 2)) { s.error = true; return; }
    write_le16(s.buffer + s.start, v);
    s.start += 2;
}

uint16_t Uint16::decode(State& s) {
    if (s.error || !has_bytes(s, 2)) { s.error = true; return 0; }
    uint16_t v = read_le16(s.data() + s.start);
    s.start += 2;
    return v;
}

// ---------------------------------------------------------------------------
// Uint32
// ---------------------------------------------------------------------------

void Uint32::preencode(State& s, uint32_t) { s.end += 4; }

void Uint32::encode(State& s, uint32_t v) {
    if (s.error || !s.buffer || !has_bytes(s, 4)) { s.error = true; return; }
    write_le32(s.buffer + s.start, v);
    s.start += 4;
}

uint32_t Uint32::decode(State& s) {
    if (s.error || !has_bytes(s, 4)) { s.error = true; return 0; }
    uint32_t v = read_le32(s.data() + s.start);
    s.start += 4;
    return v;
}

// ---------------------------------------------------------------------------
// Uint64
// ---------------------------------------------------------------------------

void Uint64::preencode(State& s, uint64_t) { s.end += 8; }

void Uint64::encode(State& s, uint64_t v) {
    if (s.error || !s.buffer || !has_bytes(s, 8)) { s.error = true; return; }
    write_le64(s.buffer + s.start, v);
    s.start += 8;
}

uint64_t Uint64::decode(State& s) {
    if (s.error || !has_bytes(s, 8)) { s.error = true; return 0; }
    uint64_t v = read_le64(s.data() + s.start);
    s.start += 8;
    return v;
}

// ---------------------------------------------------------------------------
// Bool
// ---------------------------------------------------------------------------

void Bool::preencode(State& s, bool) { s.end += 1; }

void Bool::encode(State& s, bool v) {
    if (s.error || !s.buffer) { s.error = true; return; }
    Uint8::encode(s, v ? 1 : 0);
}

bool Bool::decode(State& s) {
    return Uint8::decode(s) != 0;
}

// ---------------------------------------------------------------------------
// Buffer (nullable, length-prefixed)
// ---------------------------------------------------------------------------

void Buffer::preencode(State& s, const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        s.end += 1;  // null marker
    } else {
        Uint::preencode(s, len);
        s.end += len;
    }
}

void Buffer::preencode_null(State& s) { s.end += 1; }

void Buffer::encode(State& s, const uint8_t* data, size_t len) {
    if (s.error || !s.buffer) { s.error = true; return; }
    if (data == nullptr || len == 0) {
        Uint8::encode(s, 0);
    } else {
        Uint::encode(s, len);
        if (s.error || !has_bytes(s, len)) { s.error = true; return; }
        std::memcpy(s.buffer + s.start, data, len);
        s.start += len;
    }
}

void Buffer::encode_null(State& s) { Uint8::encode(s, 0); }

Buffer::DecodeResult Buffer::decode(State& s) {
    auto len = Uint::decode(s);
    if (s.error) return {};
    if (len == 0) return {};  // null
    constexpr size_t MAX_BUFFER_DECODE = 65536;  // H12: cap allocation size
    if (len > MAX_BUFFER_DECODE) { s.error = true; return {}; }
    if (!has_bytes(s, static_cast<size_t>(len))) { s.error = true; return {}; }
    const uint8_t* ptr = s.data() + s.start;
    s.start += static_cast<size_t>(len);
    return {ptr, static_cast<size_t>(len)};
}

// ---------------------------------------------------------------------------
// Raw
// ---------------------------------------------------------------------------

void Raw::preencode(State& s, const uint8_t*, size_t len) { s.end += len; }

void Raw::encode(State& s, const uint8_t* data, size_t len) {
    if (s.error || !has_bytes(s, len)) { s.error = true; return; }
    if (len > 0) {
        std::memcpy(s.buffer + s.start, data, len);
        s.start += len;
    }
}

Raw::DecodeResult Raw::decode(State& s) {
    if (s.error) return {};
    size_t remaining = s.end - s.start;
    const uint8_t* ptr = s.data() + s.start;
    s.start = s.end;
    return {ptr, remaining};
}

// ---------------------------------------------------------------------------
// Fixed32
// ---------------------------------------------------------------------------

void Fixed32::preencode(State& s, const Value&) { s.end += SIZE; }

void Fixed32::encode(State& s, const Value& v) {
    if (s.error || !has_bytes(s, SIZE)) { s.error = true; return; }
    std::memcpy(s.buffer + s.start, v.data(), SIZE);
    s.start += SIZE;
}

Fixed32::Value Fixed32::decode(State& s) {
    Value v{};
    if (s.error || !has_bytes(s, SIZE)) { s.error = true; return v; }
    std::memcpy(v.data(), s.data() + s.start, SIZE);
    s.start += SIZE;
    return v;
}

// ---------------------------------------------------------------------------
// Fixed64
// ---------------------------------------------------------------------------

void Fixed64::preencode(State& s, const Value&) { s.end += SIZE; }

void Fixed64::encode(State& s, const Value& v) {
    if (s.error || !has_bytes(s, SIZE)) { s.error = true; return; }
    std::memcpy(s.buffer + s.start, v.data(), SIZE);
    s.start += SIZE;
}

Fixed64::Value Fixed64::decode(State& s) {
    Value v{};
    if (s.error || !has_bytes(s, SIZE)) { s.error = true; return v; }
    std::memcpy(v.data(), s.data() + s.start, SIZE);
    s.start += SIZE;
    return v;
}

// ---------------------------------------------------------------------------
// Ipv4Address
// ---------------------------------------------------------------------------

std::string Ipv4Address::host_string() const {
    std::string result;
    result.reserve(15);  // max "255.255.255.255"
    for (int i = 0; i < 4; ++i) {
        if (i > 0) result += '.';
        char buf[4];
        auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), host[i]);
        result.append(buf, ptr);
    }
    return result;
}

Ipv4Address Ipv4Address::from_string(const std::string& host_str, uint16_t port) {
    Ipv4Address addr;
    addr.port = port;
    size_t pos = 0;
    for (int i = 0; i < 4 && pos <= host_str.size(); ++i) {
        size_t dot = host_str.find('.', pos);
        if (dot == std::string::npos) dot = host_str.size();
        unsigned int octet_val = 0;
        auto [p, ec] = std::from_chars(host_str.data() + pos, host_str.data() + dot, octet_val);
        if (ec != std::errc{} || octet_val > 255) {
            return Ipv4Address{};  // Parse error — return zeroed address
        }
        addr.host[i] = static_cast<uint8_t>(octet_val);
        pos = dot + 1;
    }
    return addr;
}

// ---------------------------------------------------------------------------
// Ipv4Addr codec
// ---------------------------------------------------------------------------

void Ipv4Addr::preencode(State& s, const Ipv4Address&) { s.end += SIZE; }

void Ipv4Addr::encode(State& s, const Ipv4Address& v) {
    if (s.error || !has_bytes(s, SIZE)) { s.error = true; return; }
    // 4 bytes: IPv4 octets (network order, same as sequential bytes)
    std::memcpy(s.buffer + s.start, v.host.data(), 4);
    s.start += 4;
    // 2 bytes: port LE
    write_le16(s.buffer + s.start, v.port);
    s.start += 2;
}

Ipv4Address Ipv4Addr::decode(State& s) {
    Ipv4Address addr;
    if (s.error || !has_bytes(s, SIZE)) { s.error = true; return addr; }
    std::memcpy(addr.host.data(), s.data() + s.start, 4);
    s.start += 4;
    addr.port = read_le16(s.data() + s.start);
    s.start += 2;
    return addr;
}

// ---------------------------------------------------------------------------
// Ipv6Address — string conversion
// ---------------------------------------------------------------------------

std::string Ipv6Address::host_string() const {
    // JS compact-encoding-net outputs full expanded hex groups with no ::
    // e.g. "fe80:0:0:0:0:0:0:1"
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(39);  // max "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
    for (int g = 0; g < 8; g++) {
        if (g > 0) result += ':';
        uint16_t val = static_cast<uint16_t>(host[g * 2]) << 8 |
                       static_cast<uint16_t>(host[g * 2 + 1]);
        // Output without leading zeros (matches JS .toString(16))
        if (val == 0) {
            result += '0';
        } else {
            char buf[5];
            int len = 0;
            for (uint16_t v = val; v > 0; v >>= 4) {
                buf[len++] = hex_chars[v & 0xf];
            }
            for (int i = len - 1; i >= 0; i--) {
                result += buf[i];
            }
        }
    }
    return result;
}

Ipv6Address Ipv6Address::from_string(const std::string& host_str, uint16_t port) {
    Ipv6Address addr;
    addr.port = port;

    // Split on ':' into tokens, noting where '::' appears
    // "fe80::1" → tokens = ["fe80", "", "1"], double_colon between index 0 and 1
    // "2001:db8:0:0:0:0:0:1" → tokens = ["2001","db8","0","0","0","0","0","1"]
    // "::1" → tokens = ["", "", "1"]

    std::vector<uint16_t> before_groups;  // groups before ::
    std::vector<uint16_t> after_groups;   // groups after ::
    bool found_double_colon = false;

    // Find :: position in the string
    auto dc = host_str.find("::");
    std::string before_str, after_str;
    if (dc != std::string::npos) {
        found_double_colon = true;
        before_str = host_str.substr(0, dc);
        after_str = host_str.substr(dc + 2);
    } else {
        before_str = host_str;
    }

    // Parse colon-separated hex groups from a string
    auto parse_groups = [](const std::string& s, std::vector<uint16_t>& out) {
        if (s.empty()) return;
        size_t pos = 0;
        while (pos <= s.size()) {
            size_t colon = s.find(':', pos);
            if (colon == std::string::npos) colon = s.size();
            uint16_t val = 0;
            for (size_t i = pos; i < colon; i++) {
                char c = s[i];
                if (c >= '0' && c <= '9') val = val * 16 + (c - '0');
                else if (c >= 'a' && c <= 'f') val = val * 16 + (c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') val = val * 16 + (c - 'A' + 10);
            }
            out.push_back(val);
            pos = colon + 1;
        }
    };

    if (found_double_colon) {
        parse_groups(before_str, before_groups);
        parse_groups(after_str, after_groups);
        // Fill in zeros between before and after to make 8 groups
        size_t total = before_groups.size() + after_groups.size();
        size_t missing = (total < 8) ? (8 - total) : 0;
        std::vector<uint16_t> groups;
        groups.insert(groups.end(), before_groups.begin(), before_groups.end());
        for (size_t g = 0; g < missing; g++) groups.push_back(0);
        groups.insert(groups.end(), after_groups.begin(), after_groups.end());
        for (size_t g = 0; g < 8 && g < groups.size(); g++) {
            addr.host[g * 2] = static_cast<uint8_t>(groups[g] >> 8);
            addr.host[g * 2 + 1] = static_cast<uint8_t>(groups[g] & 0xff);
        }
    } else {
        parse_groups(before_str, before_groups);
        for (size_t g = 0; g < 8 && g < before_groups.size(); g++) {
            addr.host[g * 2] = static_cast<uint8_t>(before_groups[g] >> 8);
            addr.host[g * 2 + 1] = static_cast<uint8_t>(before_groups[g] & 0xff);
        }
    }

    return addr;
}

// ---------------------------------------------------------------------------
// Ipv6Addr codec
// ---------------------------------------------------------------------------

void Ipv6Addr::preencode(State& s, const Ipv6Address&) { s.end += SIZE; }

void Ipv6Addr::encode(State& s, const Ipv6Address& v) {
    if (s.error || !has_bytes(s, SIZE)) { s.error = true; return; }
    // 16 bytes: IPv6 address (big-endian, stored as-is)
    std::memcpy(s.buffer + s.start, v.host.data(), 16);
    s.start += 16;
    // 2 bytes: port LE
    write_le16(s.buffer + s.start, v.port);
    s.start += 2;
}

Ipv6Address Ipv6Addr::decode(State& s) {
    Ipv6Address addr;
    if (s.error || !has_bytes(s, SIZE)) { s.error = true; return addr; }
    std::memcpy(addr.host.data(), s.data() + s.start, 16);
    s.start += 16;
    addr.port = read_le16(s.data() + s.start);
    s.start += 2;
    return addr;
}

}  // namespace hyperdht::compact
