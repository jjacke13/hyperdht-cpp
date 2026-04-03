// Fuzz target: PEER_HANDSHAKE message decoder
// Tests: decode_handshake_msg with arbitrary byte sequences.
// This parses untrusted data from the network (the value field of
// PEER_HANDSHAKE requests).

#include "hyperdht/peer_connect.hpp"

using namespace hyperdht::peer_connect;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Decode handshake message
    {
        auto msg = decode_handshake_msg(data, size);
        (void)msg;
    }

    // Round-trip: decode then re-encode
    {
        auto msg = decode_handshake_msg(data, size);
        auto buf = encode_handshake_msg(msg);
        (void)buf;
    }

    return 0;
}
