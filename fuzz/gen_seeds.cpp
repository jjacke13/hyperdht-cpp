// Seed generator for the crypto fuzz targets.
//
// Random bytes never pass Poly1305, so an unseeded fuzzer bounces off the
// crypto wall and only ever exercises pre-MAC length/slicing code. Seeding the
// corpus with real protocol bytes puts it INSIDE the wall, where mutations
// reach the state machine. Measured: seeding lifts fuzz_noise_handshake from a
// 3-unit plateau to cov 144 / 11 corpus entries in 20 s.
//
// Build it with the fuzz targets, then:  ./build-fuzz/gen_seeds fuzz/corpus
#include <array>
#include <cstdio>
#include <string>
#include <vector>
#include <sodium.h>
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/secret_stream.hpp"

using namespace hyperdht::noise;

static void write_file(const std::string& path, const std::vector<uint8_t>& b) {
    // The corpus dirs are gitignored, so on a fresh clone they do not exist and
    // fopen returns NULL — check it rather than SEGV inside fwrite.
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        fprintf(stderr, "cannot write %s — does its directory exist?\n", path.c_str());
        exit(1);
    }
    fwrite(b.data(), 1, b.size(), f);
    fclose(f);
    printf("%s (%zu bytes)\n", path.c_str(), b.size());
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: gen_seeds <corpus-dir>\n");
        return 1;
    }
    sodium_init();
    std::string out = argv[1];

    Seed rseed{};
    for (size_t i = 0; i < rseed.size(); ++i) rseed[i] = (uint8_t)i;
    Keypair responder = generate_keypair(rseed);

    Seed iseed{};
    for (size_t i = 0; i < iseed.size(); ++i) iseed[i] = (uint8_t)(0x40 + i);
    Keypair initiator = generate_keypair(iseed);

    std::array<uint8_t, 32> prologue{};

    // Valid msg1 for the responder harness, with and without a payload.
    {
        NoiseIK init(true, initiator, prologue.data(), prologue.size(),
                     &responder.public_key);
        auto msg1 = init.send();
        write_file(out + "/fuzz_noise_handshake/seed_msg1", msg1);
    }
    {
        NoiseIK init(true, initiator, prologue.data(), prologue.size(),
                     &responder.public_key);
        std::vector<uint8_t> payload{1, 2, 3, 4, 5, 6, 7, 8};
        auto msg1 = init.send(payload.data(), payload.size());
        write_file(out + "/fuzz_noise_handshake/seed_msg1_payload", msg1);
    }

    // SecretStream: a real header (selector bit 1 -> receive_header) and a real
    // encrypted frame (selector bit 0 -> decrypt). Keys mirror the harness.
    {
        Key tx{}, rx{};
        for (size_t i = 0; i < tx.size(); ++i) tx[i] = (uint8_t)(i + 1);
        for (size_t i = 0; i < rx.size(); ++i) rx[i] = (uint8_t)(i + 2);
        Hash h{};
        for (size_t i = 0; i < h.size(); ++i) h[i] = (uint8_t)(0xA0 + i);

        // Peer side: tx/rx swapped, initiator flag flipped.
        hyperdht::secret_stream::SecretStream peer(rx, tx, h, true, nullptr);
        auto header = peer.create_header_message();
        std::vector<uint8_t> s1{1};  // selector: odd -> receive_header
        s1.insert(s1.end(), header.begin() + 3, header.end());
        write_file(out + "/fuzz_secret_stream/seed_header", s1);

        hyperdht::secret_stream::SecretStream us(tx, rx, h, false, nullptr);
        auto ours = us.create_header_message();
        peer.receive_header(ours.data() + 3, ours.size() - 3);
        std::vector<uint8_t> msg{'h', 'e', 'l', 'l', 'o'};
        auto frame = peer.encrypt(msg.data(), msg.size());
        std::vector<uint8_t> s0{0};  // selector: even -> decrypt
        s0.insert(s0.end(), frame.begin() + 3, frame.end());
        write_file(out + "/fuzz_secret_stream/seed_frame", s0);
    }
    return 0;
}
