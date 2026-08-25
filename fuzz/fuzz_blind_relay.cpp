// Fuzz target: blind-relay control message decoders
// Tests: decode_pair and decode_unpair with arbitrary byte sequences.
// These arrive over protomux from a relay peer, so the bytes are remote-
// controlled. The first input byte selects the decoder so one target covers
// both without halving the fuzzer's throughput on each.

#include <cstddef>
#include <cstdint>

#include "hyperdht/blind_relay.hpp"

using namespace hyperdht::blind_relay;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;

    const uint8_t selector = data[0];
    const uint8_t* body = data + 1;
    const size_t body_size = size - 1;

    if (selector & 1u) {
        auto msg = decode_pair(body, body_size);
        if (msg) {
            // Round-trip: a decoder that accepts a frame must re-encode it.
            auto buf = encode_pair(*msg);
            (void)buf;
        }
    } else {
        auto msg = decode_unpair(body, body_size);
        if (msg) {
            auto buf = encode_unpair(*msg);
            (void)buf;
        }
    }

    return 0;
}
