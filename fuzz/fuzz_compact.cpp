// Fuzz target: compact encoding decoders
// Tests: Uint, Uint16, Uint32, Uint64, Buffer, Ipv4Addr, Ipv4Array decode
// with arbitrary byte sequences.

#include "hyperdht/compact.hpp"

using namespace hyperdht::compact;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Uint (varint)
    {
        State s = State::for_decode(data, size);
        Uint::decode(s);
    }
    // Uint16
    {
        State s = State::for_decode(data, size);
        Uint16::decode(s);
    }
    // Uint32
    {
        State s = State::for_decode(data, size);
        Uint32::decode(s);
    }
    // Uint64
    {
        State s = State::for_decode(data, size);
        Uint64::decode(s);
    }
    // Bool
    {
        State s = State::for_decode(data, size);
        Bool::decode(s);
    }
    // Buffer (length-prefixed)
    {
        State s = State::for_decode(data, size);
        auto [ptr, len] = Buffer::decode(s);
        (void)ptr;
        (void)len;
    }
    // Fixed32
    {
        State s = State::for_decode(data, size);
        auto val = Fixed32::decode(s);
        (void)val;
    }
    // Ipv4Addr
    {
        State s = State::for_decode(data, size);
        auto addr = Ipv4Addr::decode(s);
        (void)addr;
    }
    // Ipv4Array
    {
        State s = State::for_decode(data, size);
        auto addrs = Ipv4Array::decode(s);
        (void)addrs;
    }

    return 0;
}
