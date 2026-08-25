// Fuzz target: Noise IK handshake processing (responder side)
//
// This is the deepest PRE-AUTHENTICATION surface in the library. Every
// PEER_HANDSHAKE request carries `msg.noise` — attacker-chosen bytes from any
// host on the internet — and those bytes go straight into NoiseIK::recv. There
// is no authentication upstream of this: the handshake IS the authentication.
//
// Note the difference from fuzz_noise_payload, which decodes the payload
// struct AFTER a handshake has succeeded. This target attacks the handshake
// state machine itself.

#include <array>
#include <cstddef>
#include <cstdint>

#include <sodium.h>

#include "hyperdht/noise_wrap.hpp"

using namespace hyperdht::noise;

namespace {

// Fixed seed: a crash artifact must reproduce on re-run, which a random
// keypair would prevent.
Keypair& responder_keypair() {
    static Keypair kp = [] {
        Seed seed{};
        for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(i);
        return generate_keypair(seed);
    }();
    return kp;
}

// Any fixed prologue exercises the same code path; the real HyperDHT value is
// a 32-byte namespace hash, so match the shape.
constexpr std::array<uint8_t, 32> kPrologue{};

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    if (sodium_init() < 0) __builtin_trap();
    responder_keypair();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Responder: remote_static is null (learned from msg1), which is the role
    // a listening server plays for every unsolicited handshake.
    NoiseIK responder(false, responder_keypair(), kPrologue.data(),
                      kPrologue.size(), nullptr);

    auto payload = responder.recv(data, size);

    // A successful recv only advances message_index_ 0 -> 1; is_complete()
    // needs >= 2 (src/noise_wrap.cpp:424,507). Production reaches that by
    // replying with msg2 — Server::finalize_handshake, src/server_connection.cpp:162-171.
    // Without this send() the split below is dead code for EVERY input,
    // including a perfectly valid msg1.
    if (payload) {
        auto msg2 = responder.send();
        static volatile size_t msg2_sink = 0;
        msg2_sink += msg2.size();
    }

    // A handshake that reports completion must expose consistent state; touch
    // it so a half-initialised split trips the sanitizers.
    if (responder.is_complete()) {
        auto tx = responder.tx_key();
        auto rx = responder.rx_key();
        auto hash = responder.handshake_hash();
        auto rs = responder.remote_public_key();
        static volatile size_t sink = 0;
        sink += tx[0] + rx[0] + hash[0] + rs[0];
    }
    (void)payload;

    return 0;
}
