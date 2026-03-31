#include "hyperdht/compact.hpp"

#include <charconv>

namespace hyperdht::compact {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static inline bool has_bytes(const State& s, size_t n) {
    return s.start + n <= s.end;
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
    if (s.error) return;
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
    uint8_t first = s.buffer[s.start++];
    if (first <= 0xFC) return first;
    if (first == 0xFD) {
        if (!has_bytes(s, 2)) { s.error = true; return 0; }
        uint16_t v = read_le16(s.buffer + s.start);
        s.start += 2;
        return v;
    }
    if (first == 0xFE) {
        if (!has_bytes(s, 4)) { s.error = true; return 0; }
        uint32_t v = read_le32(s.buffer + s.start);
        s.start += 4;
        return v;
    }
    // 0xFF
    if (!has_bytes(s, 8)) { s.error = true; return 0; }
    uint64_t v = read_le64(s.buffer + s.start);
    s.start += 8;
    return v;
}

// ---------------------------------------------------------------------------
// Uint8
// ---------------------------------------------------------------------------

void Uint8::preencode(State& s, uint8_t) { s.end += 1; }

void Uint8::encode(State& s, uint8_t v) {
    if (s.error || !has_bytes(s, 1)) { s.error = true; return; }
    s.buffer[s.start++] = v;
}

uint8_t Uint8::decode(State& s) {
    if (s.error || !has_bytes(s, 1)) { s.error = true; return 0; }
    return s.buffer[s.start++];
}

// ---------------------------------------------------------------------------
// Uint16
// ---------------------------------------------------------------------------

void Uint16::preencode(State& s, uint16_t) { s.end += 2; }

void Uint16::encode(State& s, uint16_t v) {
    if (s.error || !has_bytes(s, 2)) { s.error = true; return; }
    write_le16(s.buffer + s.start, v);
    s.start += 2;
}

uint16_t Uint16::decode(State& s) {
    if (s.error || !has_bytes(s, 2)) { s.error = true; return 0; }
    uint16_t v = read_le16(s.buffer + s.start);
    s.start += 2;
    return v;
}

// ---------------------------------------------------------------------------
// Uint32
// ---------------------------------------------------------------------------

void Uint32::preencode(State& s, uint32_t) { s.end += 4; }

void Uint32::encode(State& s, uint32_t v) {
    if (s.error || !has_bytes(s, 4)) { s.error = true; return; }
    write_le32(s.buffer + s.start, v);
    s.start += 4;
}

uint32_t Uint32::decode(State& s) {
    if (s.error || !has_bytes(s, 4)) { s.error = true; return 0; }
    uint32_t v = read_le32(s.buffer + s.start);
    s.start += 4;
    return v;
}

// ---------------------------------------------------------------------------
// Uint64
// ---------------------------------------------------------------------------

void Uint64::preencode(State& s, uint64_t) { s.end += 8; }

void Uint64::encode(State& s, uint64_t v) {
    if (s.error || !has_bytes(s, 8)) { s.error = true; return; }
    write_le64(s.buffer + s.start, v);
    s.start += 8;
}

uint64_t Uint64::decode(State& s) {
    if (s.error || !has_bytes(s, 8)) { s.error = true; return 0; }
    uint64_t v = read_le64(s.buffer + s.start);
    s.start += 8;
    return v;
}

// ---------------------------------------------------------------------------
// Bool
// ---------------------------------------------------------------------------

void Bool::preencode(State& s, bool) { s.end += 1; }

void Bool::encode(State& s, bool v) {
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
    if (s.error) return;
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
    if (!has_bytes(s, static_cast<size_t>(len))) { s.error = true; return {}; }
    const uint8_t* ptr = s.buffer + s.start;
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
    const uint8_t* ptr = s.buffer + s.start;
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
    std::memcpy(v.data(), s.buffer + s.start, SIZE);
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
    std::memcpy(v.data(), s.buffer + s.start, SIZE);
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
        uint8_t octet = 0;
        std::from_chars(host_str.data() + pos, host_str.data() + dot, octet);
        addr.host[i] = octet;
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
    std::memcpy(addr.host.data(), s.buffer + s.start, 4);
    s.start += 4;
    addr.port = read_le16(s.buffer + s.start);
    s.start += 2;
    return addr;
}

}  // namespace hyperdht::compact
