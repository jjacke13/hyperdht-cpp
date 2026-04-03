// Fuzz target: Noise payload decoder
// Tests: decode_noise_payload with arbitrary bytes.
// This is the encrypted payload inside Noise handshake messages —
// after decryption it's parsed as a NoisePayload struct.

#include "hyperdht/peer_connect.hpp"

using namespace hyperdht::peer_connect;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Decode noise payload
    {
        auto payload = decode_noise_payload(data, size);
        (void)payload;
    }

    // Round-trip
    {
        auto payload = decode_noise_payload(data, size);
        auto buf = encode_noise_payload(payload);
        (void)buf;
    }

    return 0;
}
