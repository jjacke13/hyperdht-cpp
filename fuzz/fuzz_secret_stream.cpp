// Fuzz target: SecretStream header + frame handling
//
// receive_header parses the remote's 56-byte header before the stream is
// ready, and decrypt() consumes attacker-supplied ciphertext frames. Both read
// bytes chosen by the peer; decrypt is AEAD so forged frames fail
// authentication, but the length/framing handling around it still runs on
// hostile input.
//
// Keys come from a fixed seed so a crash artifact reproduces on re-run.

#include <cstddef>
#include <cstdint>

#include <sodium.h>

#include "hyperdht/secret_stream.hpp"

using hyperdht::secret_stream::SecretStream;

namespace {

hyperdht::noise::Key fixed_key(uint8_t tag) {
    hyperdht::noise::Key k{};
    for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(i + tag);
    return k;
}

hyperdht::noise::Hash fixed_hash() {
    hyperdht::noise::Hash h{};
    for (size_t i = 0; i < h.size(); ++i) h[i] = static_cast<uint8_t>(0xA0 + i);
    return h;
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    if (sodium_init() < 0) __builtin_trap();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;

    // First byte splits the two entry points. They are separate states: a
    // stream that has not accepted a header must not decrypt, and the fuzzer
    // should be able to attack each without the other's setup cost.
    const uint8_t selector = data[0];
    const uint8_t* body = data + 1;
    const size_t body_size = size - 1;

    // No uv_loop_t — timers stay disabled, which keeps the target
    // deterministic and free of wall-clock dependence.
    SecretStream stream(fixed_key(1), fixed_key(2), fixed_hash(),
                        /*is_initiator=*/false, nullptr);

    auto ours = stream.create_header_message();
    (void)ours;

    if (selector & 1u) {
        // Hostile header bytes.
        bool ok = stream.receive_header(body, body_size);
        static volatile bool sink = false;
        sink = ok || stream.is_ready();
    } else {
        // Hostile ciphertext against a NOT-yet-ready stream. Reachable in
        // production by any peer that sends data before its header.
        auto pre = stream.decrypt(body, body_size);
        (void)pre;

        // Now make the stream genuinely ready. This needs the PEER's header,
        // not our own: create_header_message() embeds local_id_ (derived with
        // NS_INITIATOR for us), while receive_header compares against
        // remote_id_ (NS_RESPONDER) — see compute_stream_id,
        // src/secret_stream.cpp:40-48. Feeding our own header back therefore
        // always fails, leaving is_ready() false and decrypt() short-circuiting
        // at its first line, so the AEAD path would never be fuzzed at all.
        // Mirror the peer exactly: keys swapped, role flipped.
        SecretStream peer(fixed_key(2), fixed_key(1), fixed_hash(),
                          /*is_initiator=*/true, nullptr);
        auto peer_header = peer.create_header_message();
        if (peer_header.size() > 3) {
            stream.receive_header(peer_header.data() + 3, peer_header.size() - 3);
        }

        // Hostile ciphertext against a ready stream — this is the real target:
        // crypto_secretstream pull, plaintext length handling, and the
        // empty-keepalive suppression.
        auto post = stream.decrypt(body, body_size);
        (void)post;
    }

    return 0;
}
