// Fuzz target: DHT message decoders
// Tests: decode_message (request + response), decode_request, decode_response
// with arbitrary byte sequences.

#include "hyperdht/messages.hpp"

using namespace hyperdht::messages;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Full message decode (auto-detects request vs response)
    {
        Request req;
        Response resp;
        decode_message(data, size, req, resp);
    }

    // Direct request decode (skip type byte)
    if (size > 0) {
        Request req;
        decode_request(data + 1, size - 1, req);
    }

    // Round-trip: decode then re-encode should not crash
    {
        Request req;
        Response resp;
        auto type = decode_message(data, size, req, resp);
        if (type == REQUEST_ID) {
            auto buf = encode_request(req);
            (void)buf;
        } else if (type == RESPONSE_ID) {
            auto buf = encode_response(resp);
            (void)buf;
        }
    }

    return 0;
}
