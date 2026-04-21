// Minimal native echo test — no JNI, no Java, no GoogleTest.
// Cross-compile for Android ARM64, push via adb, run natively.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hyperdht/hyperdht.h>
#include <uv.h>

typedef struct {
    hyperdht_t* dht;
    hyperdht_stream_t* stream;
    int connected;
    int echo_ok;
    int closed;
    uv_timer_t* timeout;
    const char* test_msg;
} State;

static void teardown(State* s) {
    s->closed = 1;
    if (s->timeout) {
        uv_timer_stop(s->timeout);
        uv_close((uv_handle_t*)s->timeout, NULL);
        s->timeout = NULL;
    }
    hyperdht_destroy(s->dht, NULL, NULL);
}

static void on_close(void* ud) {
    State* s = (State*)ud;
    printf("  Stream CLOSED\n");
    teardown(s);
}

static void on_timeout(uv_timer_t* t) {
    State* s = (State*)t->data;
    printf("  TIMEOUT — tearing down\n");
    if (s->stream) hyperdht_stream_close(s->stream);
    else teardown(s);
}

static void on_data(const uint8_t* data, size_t len, void* ud) {
    State* s = (State*)ud;
    printf("  ECHO (%zu bytes): %.*s\n", len, (int)len, data);
    if (len == strlen(s->test_msg) && memcmp(data, s->test_msg, len) == 0)
        s->echo_ok = 1;
    hyperdht_stream_close(s->stream);
}

static void on_open(void* ud) {
    State* s = (State*)ud;
    printf("  Stream OPEN\n");
    int rc = hyperdht_stream_write(s->stream,
        (const uint8_t*)s->test_msg, strlen(s->test_msg));
    printf("  Sent %zu bytes (rc=%d)\n", strlen(s->test_msg), rc);
}

static void on_connect(int error, const hyperdht_connection_t* conn, void* ud) {
    State* s = (State*)ud;
    printf("  connect: error=%d conn=%p\n", error, (void*)conn);
    if (error != 0 || !conn) {
        printf("  CONNECT FAILED (error=%d)\n", error);
        hyperdht_destroy(s->dht, NULL, NULL);
        return;
    }
    s->connected = 1;
    printf("  Connected! peer=%s:%u raw=%s\n",
           conn->peer_host, conn->peer_port,
           conn->raw_stream ? "yes" : "no");

    s->stream = hyperdht_stream_open(s->dht, conn,
        on_open, on_data, on_close, ud);
    if (!s->stream) {
        printf("  stream_open FAILED\n");
        hyperdht_destroy(s->dht, NULL, NULL);
    } else {
        printf("  stream_open OK (%p)\n", (void*)s->stream);
    }
}

int main(int argc, char** argv) {
    const char* key_hex = getenv("SERVER_KEY");
    if (!key_hex || strlen(key_hex) != 64) {
        if (argc > 1 && strlen(argv[1]) == 64) key_hex = argv[1];
        else { fprintf(stderr, "Usage: SERVER_KEY=<hex> %s\n", argv[0]); return 1; }
    }

    uint8_t server_pk[32];
    for (int i = 0; i < 32; i++) {
        unsigned int b;
        sscanf(key_hex + i * 2, "%02x", &b);
        server_pk[i] = (uint8_t)b;
    }

    uv_loop_t loop;
    uv_loop_init(&loop);

    hyperdht_opts_t opts = {0};
    opts.use_public_bootstrap = 1;
    hyperdht_t* dht = hyperdht_create(&loop, &opts);
    if (!dht) { fprintf(stderr, "create failed\n"); return 1; }
    hyperdht_bind(dht, 0);
    printf("  Bound to port %u\n", hyperdht_port(dht));

    State state = {0};
    state.dht = dht;
    state.test_msg = "hello from native Android test";

    printf("  Connecting...\n");
    hyperdht_connect(dht, server_pk, on_connect, &state);

    // Timeout
    state.timeout = (uv_timer_t*)malloc(sizeof(uv_timer_t));
    uv_timer_init(&loop, state.timeout);
    state.timeout->data = &state;
    uv_timer_start(state.timeout, on_timeout, 30000, 0);

    // UV_RUN_ONCE loop — same as Android/Kotlin
    while (uv_run(&loop, UV_RUN_ONCE) != 0) {}

    hyperdht_free(dht);
    uv_loop_close(&loop);

    printf("\n  Result: connected=%d echo=%d\n", state.connected, state.echo_ok);
    return state.echo_ok ? 0 : 1;
}
