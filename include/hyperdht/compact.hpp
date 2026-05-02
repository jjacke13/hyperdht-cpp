#pragma once

// compact-encoding — binary codec for varints, buffers, IPv4/IPv6, etc.
// C++ port of JS compact-encoding; wire-compatible with the JS reference.
// Used by all DHT messages and HyperDHT payloads.
//
// Input validation: Buffer::decode capped at 64KB. Array decode capped at
// 4096 elements. Varint-to-uint8/uint32 casts are range-checked at call sites.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace hyperdht::compact {

// ---------------------------------------------------------------------------
// State — encoding/decoding cursor (mirrors JS compact-encoding state object)
//
//  Preencode: State s; Enc::preencode(s, val); → s.end = total size
//  Encode:    s.buffer = buf.data(); s.start = 0; Enc::encode(s, val);
//  Decode:    auto s = State::for_decode(data, len); auto v = Enc::decode(s);
// ---------------------------------------------------------------------------
struct State {
    size_t start = 0;
    size_t end = 0;
    uint8_t* buffer = nullptr;  // For encode (mutable write access)
    bool error = false;

    // Read-only access — safe for both encode and decode states
    const uint8_t* data() const { return read_buffer_ ? read_buffer_ : buffer; }

    static State for_decode(const uint8_t* buf, size_t len) {
        State s;
        s.read_buffer_ = buf;
        s.end = len;
        return s;
    }

private:
    const uint8_t* read_buffer_ = nullptr;  // For decode (read-only)
};

// ---------------------------------------------------------------------------
// Varint (unsigned integer)
//   0..0xFC       → 1 byte inline
//   0xFD..0xFFFF  → 0xFD + uint16 LE
//   0x10000..0xFFFFFFFF → 0xFE + uint32 LE
//   > 0xFFFFFFFF  → 0xFF + uint64 LE
// ---------------------------------------------------------------------------
struct Uint {
    static void preencode(State& s, uint64_t v);
    static void encode(State& s, uint64_t v);
    static uint64_t decode(State& s);
};

// ---------------------------------------------------------------------------
// Fixed-size unsigned integers (little-endian)
// ---------------------------------------------------------------------------
struct Uint8 {
    static void preencode(State& s, uint8_t v);
    static void encode(State& s, uint8_t v);
    static uint8_t decode(State& s);
};

struct Uint16 {
    static void preencode(State& s, uint16_t v);
    static void encode(State& s, uint16_t v);
    static uint16_t decode(State& s);
};

struct Uint32 {
    static void preencode(State& s, uint32_t v);
    static void encode(State& s, uint32_t v);
    static uint32_t decode(State& s);
};

struct Uint64 {
    static void preencode(State& s, uint64_t v);
    static void encode(State& s, uint64_t v);
    static uint64_t decode(State& s);
};

// ---------------------------------------------------------------------------
// Bool — 1 byte: 0x00 or 0x01
// ---------------------------------------------------------------------------
struct Bool {
    static void preencode(State& s, bool v);
    static void encode(State& s, bool v);
    static bool decode(State& s);
};

// ---------------------------------------------------------------------------
// Buffer — nullable, length-prefixed bytes
//   null → [0x00]   non-null → varint(len) + raw bytes
//   On decode, len=0 returns empty span (null).
// ---------------------------------------------------------------------------
struct Buffer {
    static void preencode(State& s, const uint8_t* data, size_t len);
    static void preencode_null(State& s);
    static void encode(State& s, const uint8_t* data, size_t len);
    static void encode_null(State& s);

    struct DecodeResult {
        const uint8_t* data = nullptr;
        size_t len = 0;
        bool is_null() const { return data == nullptr; }
    };
    static DecodeResult decode(State& s);
};

// ---------------------------------------------------------------------------
// Raw — no prefix, consumes remaining bytes up to state.end
// ---------------------------------------------------------------------------
struct Raw {
    static void preencode(State& s, const uint8_t* data, size_t len);
    static void encode(State& s, const uint8_t* data, size_t len);

    struct DecodeResult {
        const uint8_t* data = nullptr;
        size_t len = 0;
    };
    static DecodeResult decode(State& s);
};

// ---------------------------------------------------------------------------
// Fixed32 / Fixed64 — raw 32/64 bytes, no length prefix
// ---------------------------------------------------------------------------
struct Fixed32 {
    static constexpr size_t SIZE = 32;
    using Value = std::array<uint8_t, 32>;

    static void preencode(State& s, const Value& v);
    static void encode(State& s, const Value& v);
    static Value decode(State& s);
};

struct Fixed64 {
    static constexpr size_t SIZE = 64;
    using Value = std::array<uint8_t, 64>;

    static void preencode(State& s, const Value& v);
    static void encode(State& s, const Value& v);
    static Value decode(State& s);
};

// ---------------------------------------------------------------------------
// IPv4 Address (compact-encoding-net)
//   Bytes 0-3: IPv4 octets (network order)
//   Bytes 4-5: Port (LE uint16)
//   Total: 6 bytes fixed
// ---------------------------------------------------------------------------
struct Ipv4Address {
    std::array<uint8_t, 4> host{};
    uint16_t port = 0;

    std::string host_string() const;
    static Ipv4Address from_string(const std::string& host, uint16_t port);

    bool operator==(const Ipv4Address& other) const = default;
};

struct Ipv4Addr {
    static constexpr size_t SIZE = 6;

    static void preencode(State& s, const Ipv4Address& v);
    static void encode(State& s, const Ipv4Address& v);
    static Ipv4Address decode(State& s);
};

// ---------------------------------------------------------------------------
// IPv6 Address (compact-encoding-net)
//   Bytes 0-15: 8 x 16-bit groups (big-endian / network order)
//   Bytes 16-17: Port (LE uint16)
//   Total: 18 bytes fixed
// ---------------------------------------------------------------------------
struct Ipv6Address {
    std::array<uint8_t, 16> host{};
    uint16_t port = 0;

    // Returns full expanded form: "fe80:0:0:0:0:0:0:1" (no :: compression,
    // matching JS compact-encoding-net decode output)
    std::string host_string() const;
    static Ipv6Address from_string(const std::string& host, uint16_t port);

    bool operator==(const Ipv6Address& other) const = default;
};

struct Ipv6Addr {
    static constexpr size_t SIZE = 18;

    static void preencode(State& s, const Ipv6Address& v);
    static void encode(State& s, const Ipv6Address& v);
    static Ipv6Address decode(State& s);
};

// ---------------------------------------------------------------------------
// Array combinator — varint(count) + count * Enc::encode(element)
//   Decode caps at 0x100000 (1M) elements.
// ---------------------------------------------------------------------------
static constexpr size_t ARRAY_MAX_LENGTH = 4096;  // H14: lowered from 0x100000

template <typename Enc, typename T>
struct Array {
    static void preencode(State& s, const std::vector<T>& v) {
        Uint::preencode(s, v.size());
        for (const auto& item : v) {
            Enc::preencode(s, item);
        }
    }

    static void encode(State& s, const std::vector<T>& v) {
        Uint::encode(s, v.size());
        for (const auto& item : v) {
            Enc::encode(s, item);
        }
    }

    static std::vector<T> decode(State& s) {
        auto count = Uint::decode(s);
        if (s.error || count > ARRAY_MAX_LENGTH) {
            s.error = true;
            return {};
        }
        std::vector<T> result;
        result.reserve(static_cast<size_t>(count));
        for (size_t i = 0; i < count && !s.error; ++i) {
            result.push_back(Enc::decode(s));
        }
        return result;
    }
};

// Convenience aliases for HyperDHT
using Ipv4Array = Array<Ipv4Addr, Ipv4Address>;
using Ipv6Array = Array<Ipv6Addr, Ipv6Address>;

// ---------------------------------------------------------------------------
// Frame combinator — varint(inner_length) + Enc::encode(value)
//   Allows skipping unknown data for forward compatibility.
// ---------------------------------------------------------------------------
template <typename Enc, typename T>
struct Frame {
    static void preencode(State& s, const T& v) {
        State inner;
        Enc::preencode(inner, v);
        Uint::preencode(s, inner.end);
        s.end += inner.end;
    }

    static void encode(State& s, const T& v) {
        State inner;
        Enc::preencode(inner, v);
        Uint::encode(s, inner.end);
        Enc::encode(s, v);
    }

    static T decode(State& s) {
        auto len = Uint::decode(s);
        if (s.error) return T{};
        size_t saved_end = s.end;
        s.end = s.start + static_cast<size_t>(len);
        if (s.end > saved_end) {
            s.error = true;
            s.end = saved_end;
            return T{};
        }
        auto result = Enc::decode(s);
        s.start = s.end;  // skip any unread bytes in the frame
        s.end = saved_end;
        return result;
    }
};

}  // namespace hyperdht::compact
