// Nospoon — P2P VPN powered by hyperdht-cpp
//
// Usage:
//   nospoon <config.jsonc>     Start VPN (server or client mode)
//   nospoon genkey             Generate seed + public key pair
//
// Requires root/CAP_NET_ADMIN for TUN device creation.

#include "config.hpp"

#include <sodium.h>

#include <cstdio>
#include <cstring>

// Defined in server.cpp / client.cpp
int run_server(const nospoon::Config& config);
int run_client(const nospoon::Config& config);

static void genkey() {
    uint8_t seed[32];
    randombytes_buf(seed, sizeof(seed));

    // Derive keypair from seed (same as HyperDHT.keyPair(seed))
    uint8_t pk[32], sk[64];
    crypto_sign_seed_keypair(pk, sk, seed);

    printf("seed:       %s\n", nospoon::bytes_to_hex(seed, 32).c_str());
    printf("public_key: %s\n", nospoon::bytes_to_hex(pk, 32).c_str());
}

static void usage() {
    fprintf(stderr,
        "nospoon — P2P VPN powered by hyperdht-cpp\n"
        "\n"
        "Usage:\n"
        "  nospoon <config.jsonc>   Start VPN\n"
        "  nospoon genkey           Generate keypair\n"
        "\n"
        "Config (server):\n"
        "  { \"mode\": \"server\", \"ip\": \"10.0.0.1/24\", \"seed\": \"...\",\n"
        "    \"peers\": { \"<pubkey>\": \"10.0.0.2\" } }\n"
        "\n"
        "Config (client):\n"
        "  { \"mode\": \"client\", \"server\": \"<pubkey>\",\n"
        "    \"ip\": \"10.0.0.2/24\", \"seed\": \"...\" }\n");
}

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: sodium_init failed\n");
        return 1;
    }

    if (argc < 2) {
        usage();
        return 1;
    }

    if (std::strcmp(argv[1], "genkey") == 0) {
        genkey();
        return 0;
    }

    if (std::strcmp(argv[1], "--help") == 0 || std::strcmp(argv[1], "-h") == 0) {
        usage();
        return 0;
    }

    auto config = nospoon::load_config(argv[1]);

    if (config.mode == "server") {
        return run_server(config);
    } else if (config.mode == "client") {
        return run_client(config);
    } else {
        fprintf(stderr, "Error: unknown mode \"%s\" (use \"server\" or \"client\")\n",
                config.mode.c_str());
        return 1;
    }
}
