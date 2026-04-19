/**
 * HyperDHT client — connects to a server, sends a message, prints the echo.
 *
 * Usage:
 *   ./client <64-char-hex-public-key>
 *
 * Build:
 *   g++ -std=c++20 -O2 client.cpp -I../../include -L../../build -lhyperdht -lsodium -luv -o client
 */

#include <hyperdht/hyperdht.h>
#include <uv.h>

#include <cstdio>
#include <cstring>

static hyperdht_t* g_dht = nullptr;

static void on_data(const uint8_t* data, size_t len, void* ud) {
    printf("Received: %.*s\n", (int)len, data);
}

static void on_open(void* ud) {
    auto* stream = static_cast<hyperdht_stream_t*>(ud);
    printf("Stream open — sending hello\n");
    const char* msg = "hello from C++";
    hyperdht_stream_write(stream, (const uint8_t*)msg, strlen(msg));
}

static void on_close(void* ud) {
    printf("Stream closed\n");
}

static void on_connect(int error, const hyperdht_connection_t* conn, void* ud) {
    if (error != 0) {
        fprintf(stderr, "Connect failed: %d\n", error);
        hyperdht_destroy(g_dht, nullptr, nullptr);
        return;
    }

    printf("Connected to %s:%u\n", conn->peer_host, conn->peer_port);
    printf("  Remote key: ");
    for (int i = 0; i < 8; i++) printf("%02x", conn->remote_public_key[i]);
    printf("...\n");

    auto* stream = hyperdht_stream_open(g_dht, conn, on_open, on_data, on_close, nullptr);
    if (stream) {
        // Pass stream to on_open so it can write
        // (reuse the on_open userdata for the stream handle)
    }
}

int main(int argc, char** argv) {
    if (argc < 2 || strlen(argv[1]) != 64) {
        fprintf(stderr, "Usage: %s <64-char-hex-public-key>\n", argv[0]);
        return 1;
    }

    // Parse remote public key
    uint8_t remote_pk[32];
    for (int i = 0; i < 32; i++) {
        unsigned byte;
        sscanf(argv[1] + i * 2, "%02x", &byte);
        remote_pk[i] = (uint8_t)byte;
    }

    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_opts_t opts;
    hyperdht_opts_default(&opts);
    opts.use_public_bootstrap = 1;

    g_dht = hyperdht_create(&loop, &opts);
    if (!g_dht) {
        fprintf(stderr, "Failed to create DHT\n");
        return 1;
    }

    hyperdht_bind(g_dht, 0);

    printf("Connecting to ");
    for (int i = 0; i < 8; i++) printf("%02x", remote_pk[i]);
    printf("...\n");
    fflush(stdout);

    hyperdht_connect(g_dht, remote_pk, on_connect, nullptr);

    uv_run(&loop, UV_RUN_DEFAULT);

    hyperdht_destroy(g_dht, nullptr, nullptr);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(g_dht);
    uv_loop_close(&loop);
    return 0;
}
