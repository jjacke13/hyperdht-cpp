// Fuzz target: PEER_HOLEPUNCH message decoder
// Tests: decode_holepunch_msg and decode_holepunch_payload with arbitrary bytes.

#include "hyperdht/holepunch.hpp"

using namespace hyperdht::holepunch;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Decode holepunch message (outer wrapper: mode, id, payload, peerAddress)
    {
        auto msg = decode_holepunch_msg(data, size);
        (void)msg;
    }

    // Round-trip
    {
        auto msg = decode_holepunch_msg(data, size);
        auto buf = encode_holepunch_msg(msg);
        (void)buf;
    }

    // Decode holepunch payload (inner: firewall, punching, addresses, token, etc.)
    {
        auto payload = decode_holepunch_payload(data, size);
        (void)payload;
    }

    return 0;
}
