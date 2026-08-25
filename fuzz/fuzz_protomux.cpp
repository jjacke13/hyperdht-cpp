// Fuzz target: Protomux frame parser
// Tests: Mux::on_data with arbitrary bytes — varint framing, channel dispatch,
// OPEN/CLOSE/REJECT handling and the batch path (handle_batch).
//
// Reachable by any peer that completes a SecretStream: protomux carries the
// blind-relay control protocol, so these bytes come from a remote party.

#include <cstddef>
#include <cstdint>

#include "hyperdht/protomux.hpp"

using namespace hyperdht::protomux;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Sink writes — the fuzzer must not be shaped by backpressure behaviour.
    Mux mux([](const uint8_t*, size_t) { return true; });

    // One local channel so incoming OPENs can pair and the channel-dispatch
    // path is reachable, not just the "unknown protocol" reject path.
    Channel* ch = mux.create_channel("fuzz", {}, true);
    (void)ch;

    // One call = one complete frame, matching how SecretStream delivers.
    mux.on_data(data, size);

    mux.destroy();
    return 0;
}
