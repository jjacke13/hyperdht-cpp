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

struct ClientCtx {
    hyperdht_stream_t* stream = nullptr;
};

static void on_data(const uint8_t* data, size_t len, void* ud) {
    printf("Received: %.*s\n", (int)len, data);
    fflush(stdout);
}

static void on_open(void* ud) {
    auto* ctx = static_cast<ClientCtx*>(ud);
    printf("Stream open — sending hello\n");
    fflush(stdout);
    const char* msg = "hello from C++";
    hyperdht_stream_write(ctx->stream, (const uint8_t*)msg, strlen(msg));
}

static void on_close(void* ud) {
    printf("Stream closed\n");
    fflush(stdout);
    delete static_cast<ClientCtx*>(ud);
}

static void on_connect(int error, const hyperdht_connection_t* conn, void* ud) {
    if (error != 0) {
        fprintf(stderr, "Connect failed: %s (%d)\n",
                hyperdht_connect_strerror(error), error);
        fflush(stderr);
        hyperdht_destroy(g_dht, nullptr, nullptr);
        return;
    }

    printf("Connected to %s:%u\n", conn->peer_host, conn->peer_port);
    printf("  Remote key: ");
    for (int i = 0; i < 8; i++) printf("%02x", conn->remote_public_key[i]);
    printf("...\n");
    fflush(stdout);

    auto* ctx = new ClientCtx;
    auto* stream = hyperdht_stream_open(g_dht, conn, on_open, on_data, on_close, ctx);
    if (stream) {
        ctx->stream = stream;
    } else {
        printf("stream_open failed!\n");
        fflush(stdout);
        delete ctx;
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
