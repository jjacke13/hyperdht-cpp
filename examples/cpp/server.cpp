/**
 * Persistent HyperDHT server — accepts connections and echoes data.
 *
 * Usage:
 *   ./server                          # random keypair
 *   ./server <64-char-hex-seed>       # deterministic identity
 *
 * Build:
 *   g++ -std=c++20 -O2 server.cpp -I../../include -L../../build -lhyperdht -lsodium -luv -o server
 */

#include <hyperdht/hyperdht.h>
#include <uv.h>

#include <cstdio>
#include <cstring>
#include <vector>

// Per-connection context: holds the stream pointer and buffers data
// that arrives before the SecretStream header exchange completes.
struct EchoCtx {
    hyperdht_stream_t* stream = nullptr;
    bool open = false;
    std::vector<std::vector<uint8_t>> pending;
};

static void on_data(const uint8_t* data, size_t len, void* ud) {
    auto* ctx = static_cast<EchoCtx*>(ud);
    if (!ctx || !ctx->stream) return;
    printf("  Received %zu bytes", len);
    if (!ctx->open) {
        // Buffer until stream is open (SecretStream header not exchanged yet)
        ctx->pending.emplace_back(data, data + len);
        printf(" (buffered, stream not open yet)\n");
    } else {
        printf(", echoing back\n");
        hyperdht_stream_write(ctx->stream, data, len);
    }
    fflush(stdout);
}

static void on_open(void* ud) {
    auto* ctx = static_cast<EchoCtx*>(ud);
    printf("  Stream open — ready for data\n");
    fflush(stdout);
    if (!ctx) return;
    ctx->open = true;
    // Flush buffered data
    for (auto& buf : ctx->pending) {
        printf("  Flushing %zu buffered bytes\n", buf.size());
        fflush(stdout);
        hyperdht_stream_write(ctx->stream, buf.data(), buf.size());
    }
    ctx->pending.clear();
}

static void on_close(void* ud) {
    printf("  Stream closed\n");
    fflush(stdout);
    auto* ctx = static_cast<EchoCtx*>(ud);
    delete ctx;
}

static void on_connection(const hyperdht_connection_t* conn, void* ud) {
    auto* dht = static_cast<hyperdht_t*>(ud);

    printf("Connection from %s:%u  key=", conn->peer_host, conn->peer_port);
    for (int i = 0; i < 8; i++) printf("%02x", conn->remote_public_key[i]);
    printf("...\n");
    fflush(stdout);

    // Allocate context first, pass as userdata, then store the stream handle.
    auto* ctx = new EchoCtx;
    auto* stream = hyperdht_stream_open(dht, conn, on_open, on_data, on_close, ctx);
    if (stream) {
        ctx->stream = stream;
    } else {
        delete ctx;
    }
}

int main(int argc, char** argv) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_opts_t opts;
    hyperdht_opts_default(&opts);
    opts.use_public_bootstrap = 1;

    // Deterministic seed from CLI arg
    if (argc > 1 && strlen(argv[1]) == 64) {
        for (int i = 0; i < 32; i++) {
            unsigned byte;
            sscanf(argv[1] + i * 2, "%02x", &byte);
            opts.seed[i] = (uint8_t)byte;
        }
        opts.seed_is_set = 1;
    }

    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    if (!dht) {
        fprintf(stderr, "Failed to create DHT\n");
        return 1;
    }

    hyperdht_bind(dht, 0);
    printf("DHT port: %u\n", hyperdht_port(dht));

    // Print public key
    hyperdht_keypair_t kp;
    hyperdht_default_keypair(dht, &kp);
    printf("Public key: ");
    for (int i = 0; i < 32; i++) printf("%02x", kp.public_key[i]);
    printf("\n\n");

    // Log bootstrap + network events
    hyperdht_on_bootstrapped(dht, [](void*) {
        printf("[event] Bootstrapped — DHT is ready\n");
        fflush(stdout);
    }, nullptr);

    hyperdht_on_network_change(dht, [](void*) {
        printf("[event] Network change detected\n");
        fflush(stdout);
    }, nullptr);

    // Create server
    hyperdht_server_t* srv = hyperdht_server_create(dht);

    hyperdht_server_on_listening(srv, [](void*) {
        printf("[event] Server announced — accepting peers\n");
        fflush(stdout);
    }, nullptr);

    hyperdht_server_listen(srv, &kp, on_connection, dht);

    printf("Listening... (Ctrl+C to stop)\n\n");
    fflush(stdout);

    uv_run(&loop, UV_RUN_DEFAULT);

    hyperdht_destroy(dht, nullptr, nullptr);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(dht);
    uv_loop_close(&loop);
    return 0;
}
