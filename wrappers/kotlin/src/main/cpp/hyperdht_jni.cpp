/**
 * JNI bridge for hyperdht-cpp — thin C++ layer mapping JNI calls to the C FFI.
 *
 * Naming convention: Java_com_hyperdht_Native_<methodName>
 *
 * Callback pattern: C FFI callbacks fire on the libuv event loop thread.
 * We cache the JVM pointer at load time. Each callback uses
 * AttachCurrentThread to get a JNIEnv and calls the Java callback object.
 */

#include <jni.h>
#include <hyperdht/hyperdht.h>
#include <uv.h>

#include <cstdio>
#include <cstring>
#include <pthread.h>

static JavaVM* g_jvm = nullptr;

// Thread-local JNI attach state. The libuv event loop thread is long-lived;
// we attach once and detach via pthread_key destructor on thread exit.
static pthread_key_t g_jni_key;
static pthread_once_t g_jni_key_once = PTHREAD_ONCE_INIT;

static void detach_thread(void*) {
    if (g_jvm) g_jvm->DetachCurrentThread();
}

static void make_key() {
    pthread_key_create(&g_jni_key, detach_thread);
}

// Get JNIEnv for the current thread. Attaches if needed; auto-detaches
// when the thread exits via the pthread_key destructor.
static JNIEnv* get_env() {
    JNIEnv* env = nullptr;
    if (g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6) == JNI_OK) return env;
    pthread_once(&g_jni_key_once, make_key);
    g_jvm->AttachCurrentThread((void**)&env, nullptr);
    pthread_setspecific(g_jni_key, env);  // triggers detach_thread on exit
    return env;
}

// Check for JNI exception after a Call*Method. Clears and logs it.
static bool check_exception(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return true;
    }
    return false;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

// ---------------------------------------------------------------------------
// libuv loop
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jlong JNICALL
Java_com_hyperdht_Native_loopCreate(JNIEnv*, jobject) {
    auto* loop = new uv_loop_t;
    uv_loop_init(loop);
    return (jlong)loop;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_loopRunOnce(JNIEnv*, jobject, jlong ptr) {
    return uv_run((uv_loop_t*)ptr, UV_RUN_ONCE);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_loopClose(JNIEnv*, jobject, jlong ptr) {
    auto* loop = (uv_loop_t*)ptr;
    uv_loop_close(loop);
    delete loop;
}

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_keypairGenerate(
    JNIEnv* env, jobject, jbyteArray jpk, jbyteArray jsk)
{
    hyperdht_keypair_t kp;
    hyperdht_keypair_generate(&kp);
    env->SetByteArrayRegion(jpk, 0, 32, (jbyte*)kp.public_key);
    env->SetByteArrayRegion(jsk, 0, 64, (jbyte*)kp.secret_key);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_keypairFromSeed(
    JNIEnv* env, jobject, jbyteArray jseed, jbyteArray jpk, jbyteArray jsk)
{
    uint8_t seed[32];
    env->GetByteArrayRegion(jseed, 0, 32, (jbyte*)seed);
    hyperdht_keypair_t kp;
    hyperdht_keypair_from_seed(&kp, seed);
    env->SetByteArrayRegion(jpk, 0, 32, (jbyte*)kp.public_key);
    env->SetByteArrayRegion(jsk, 0, 64, (jbyte*)kp.secret_key);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jlong JNICALL
Java_com_hyperdht_Native_create(
    JNIEnv* env, jobject, jlong loopPtr, jint port, jboolean ephemeral,
    jboolean usePublicBootstrap, jint connectionKeepAlive,
    jbyteArray jseed, jstring jhost)
{
    hyperdht_opts_t opts;
    hyperdht_opts_default(&opts);
    opts.port = (uint16_t)port;
    opts.ephemeral = ephemeral ? 1 : 0;
    opts.use_public_bootstrap = usePublicBootstrap ? 1 : 0;
    opts.connection_keep_alive = (uint32_t)connectionKeepAlive;

    if (jseed) {
        env->GetByteArrayRegion(jseed, 0, 32, (jbyte*)opts.seed);
        opts.seed_is_set = 1;
    }

    const char* host = nullptr;
    if (jhost) host = env->GetStringUTFChars(jhost, nullptr);
    if (host) opts.host = host;

    auto* dht = hyperdht_create((uv_loop_t*)loopPtr, &opts);

    if (host) env->ReleaseStringUTFChars(jhost, host);
    return (jlong)dht;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_bind(JNIEnv*, jobject, jlong h, jint port) {
    return hyperdht_bind((hyperdht_t*)h, (uint16_t)port);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_port(JNIEnv*, jobject, jlong h) {
    return hyperdht_port((hyperdht_t*)h);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_destroy(JNIEnv*, jobject, jlong h) {
    hyperdht_destroy((hyperdht_t*)h, nullptr, nullptr);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_destroyForce(JNIEnv*, jobject, jlong h) {
    hyperdht_destroy_force((hyperdht_t*)h, nullptr, nullptr);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_free(JNIEnv*, jobject, jlong h) {
    hyperdht_free((hyperdht_t*)h);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_isDestroyed(JNIEnv*, jobject, jlong h) {
    return hyperdht_is_destroyed((hyperdht_t*)h) ? JNI_TRUE : JNI_FALSE;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_isOnline(JNIEnv*, jobject, jlong h) {
    return hyperdht_is_online((hyperdht_t*)h) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_isDegraded(JNIEnv*, jobject, jlong h) {
    return hyperdht_is_degraded((hyperdht_t*)h) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_isPersistent(JNIEnv*, jobject, jlong h) {
    return hyperdht_is_persistent((hyperdht_t*)h) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_isBootstrapped(JNIEnv*, jobject, jlong h) {
    return hyperdht_is_bootstrapped((hyperdht_t*)h) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_isSuspended(JNIEnv*, jobject, jlong h) {
    return hyperdht_is_suspended((hyperdht_t*)h) ? JNI_TRUE : JNI_FALSE;
}

// ---------------------------------------------------------------------------
// Connect (callback bridge)
// ---------------------------------------------------------------------------

struct ConnectCtx {
    jobject callback;  // global ref to ConnectCallback
};

static void jni_connect_cb(int error, const hyperdht_connection_t* conn, void* ud) {
    auto* ctx = static_cast<ConnectCtx*>(ud);
    JNIEnv* env = get_env();

    // CRITICAL: conn points to temporary memory that is freed after this
    // callback returns. We must copy it so Kotlin can use it later in
    // openStream(). The copy is freed by Kotlin via a destroy call.
    hyperdht_connection_t* copy = nullptr;
    if (error == 0 && conn) {
        copy = new hyperdht_connection_t;
        *copy = *conn;
    }

    jclass cls = env->GetObjectClass(ctx->callback);
    jmethodID mid = env->GetMethodID(cls, "onResult", "(IJ)V");
    env->CallVoidMethod(ctx->callback, mid, (jint)error, (jlong)copy);
    check_exception(env);

    env->DeleteGlobalRef(ctx->callback);
    delete ctx;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_connect(
    JNIEnv* env, jobject, jlong h, jbyteArray jpk, jobject jcallback)
{
    uint8_t pk[32];
    env->GetByteArrayRegion(jpk, 0, 32, (jbyte*)pk);

    auto* ctx = new ConnectCtx;
    ctx->callback = env->NewGlobalRef(jcallback);

    return hyperdht_connect((hyperdht_t*)h, pk, jni_connect_cb, ctx);
}

// Free a copied connection struct (allocated in jni_connect_cb / jni_connection_cb)
extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_connectionFree(JNIEnv*, jobject, jlong ptr) {
    delete (hyperdht_connection_t*)ptr;
}

// ---------------------------------------------------------------------------
// Events (Runnable bridge)
// ---------------------------------------------------------------------------

static void jni_event_cb(void* ud) {
    auto* ref = static_cast<jobject*>(ud);
    JNIEnv* env = get_env();
    jclass cls = env->GetObjectClass(*ref);
    jmethodID mid = env->GetMethodID(cls, "run", "()V");
    env->CallVoidMethod(*ref, mid);
    check_exception(env);
    // Note: don't delete — event callbacks fire multiple times.
    // Freed when DHT is destroyed (caller must release GlobalRefs).
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_onBootstrapped(
    JNIEnv* env, jobject, jlong h, jobject jcallback)
{
    auto* ref = new jobject(env->NewGlobalRef(jcallback));
    hyperdht_on_bootstrapped((hyperdht_t*)h, jni_event_cb, ref);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_onNetworkChange(
    JNIEnv* env, jobject, jlong h, jobject jcallback)
{
    auto* ref = new jobject(env->NewGlobalRef(jcallback));
    hyperdht_on_network_change((hyperdht_t*)h, jni_event_cb, ref);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_onNetworkUpdate(
    JNIEnv* env, jobject, jlong h, jobject jcallback)
{
    auto* ref = new jobject(env->NewGlobalRef(jcallback));
    hyperdht_on_network_update((hyperdht_t*)h, jni_event_cb, ref);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_onPersistent(
    JNIEnv* env, jobject, jlong h, jobject jcallback)
{
    auto* ref = new jobject(env->NewGlobalRef(jcallback));
    hyperdht_on_persistent((hyperdht_t*)h, jni_event_cb, ref);
}

// ---------------------------------------------------------------------------
// Stream (open, write, close)
// ---------------------------------------------------------------------------

struct StreamCtx {
    jobject onOpen;   // Runnable global ref
    jobject onData;   // DataCallback global ref
    jobject onClose;  // Runnable global ref
};

static void jni_stream_open_cb(void* ud) {
    auto* ctx = static_cast<StreamCtx*>(ud);
    JNIEnv* env = get_env();
    jclass cls = env->GetObjectClass(ctx->onOpen);
    jmethodID mid = env->GetMethodID(cls, "run", "()V");
    env->CallVoidMethod(ctx->onOpen, mid);
    check_exception(env);
}

static void jni_stream_data_cb(const uint8_t* data, size_t len, void* ud) {
    auto* ctx = static_cast<StreamCtx*>(ud);
    JNIEnv* env = get_env();

    jbyteArray jdata = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(jdata, 0, (jsize)len, (const jbyte*)data);

    jclass cls = env->GetObjectClass(ctx->onData);
    jmethodID mid = env->GetMethodID(cls, "onData", "([B)V");
    env->CallVoidMethod(ctx->onData, mid, jdata);
    check_exception(env);
    env->DeleteLocalRef(jdata);
}

static void jni_stream_close_cb(void* ud) {
    auto* ctx = static_cast<StreamCtx*>(ud);
    JNIEnv* env = get_env();

    jclass cls = env->GetObjectClass(ctx->onClose);
    jmethodID mid = env->GetMethodID(cls, "run", "()V");
    env->CallVoidMethod(ctx->onClose, mid);
    check_exception(env);

    env->DeleteGlobalRef(ctx->onOpen);
    env->DeleteGlobalRef(ctx->onData);
    env->DeleteGlobalRef(ctx->onClose);
    delete ctx;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_hyperdht_Native_streamOpen(
    JNIEnv* env, jobject, jlong dhtH, jlong connPtr,
    jobject jOnOpen, jobject jOnData, jobject jOnClose)
{
    auto* ctx = new StreamCtx;
    ctx->onOpen = env->NewGlobalRef(jOnOpen);
    ctx->onData = env->NewGlobalRef(jOnData);
    ctx->onClose = env->NewGlobalRef(jOnClose);

    auto* stream = hyperdht_stream_open(
        (hyperdht_t*)dhtH, (const hyperdht_connection_t*)connPtr,
        jni_stream_open_cb, jni_stream_data_cb, jni_stream_close_cb, ctx);

    if (!stream) {
        env->DeleteGlobalRef(ctx->onOpen);
        env->DeleteGlobalRef(ctx->onData);
        env->DeleteGlobalRef(ctx->onClose);
        delete ctx;
        return 0;
    }
    return (jlong)stream;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_streamWrite(
    JNIEnv* env, jobject, jlong h, jbyteArray jdata)
{
    jsize len = env->GetArrayLength(jdata);
    jbyte* data = env->GetByteArrayElements(jdata, nullptr);
    int rc = hyperdht_stream_write(
        (hyperdht_stream_t*)h, (const uint8_t*)data, (size_t)len);
    env->ReleaseByteArrayElements(jdata, data, JNI_ABORT);
    return rc;
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_streamClose(JNIEnv*, jobject, jlong h) {
    hyperdht_stream_close((hyperdht_stream_t*)h);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_streamIsOpen(JNIEnv*, jobject, jlong h) {
    return hyperdht_stream_is_open((hyperdht_stream_t*)h) ? JNI_TRUE : JNI_FALSE;
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_hash(
    JNIEnv* env, jobject, jbyteArray jdata, jbyteArray jout)
{
    jsize len = env->GetArrayLength(jdata);
    jbyte* data = env->GetByteArrayElements(jdata, nullptr);
    uint8_t out[32];
    hyperdht_hash((const uint8_t*)data, (size_t)len, out);
    env->ReleaseByteArrayElements(jdata, data, JNI_ABORT);
    env->SetByteArrayRegion(jout, 0, 32, (jbyte*)out);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_addNode(
    JNIEnv* env, jobject, jlong h, jstring jhost, jint port)
{
    const char* host = env->GetStringUTFChars(jhost, nullptr);
    int rc = hyperdht_add_node((hyperdht_t*)h, host, (uint16_t)port);
    env->ReleaseStringUTFChars(jhost, host);
    return rc;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct ServerCtx {
    jobject callback;  // ConnectionCallback global ref
};

static void jni_connection_cb(const hyperdht_connection_t* conn, void* ud) {
    auto* ctx = static_cast<ServerCtx*>(ud);
    JNIEnv* env = get_env();

    // Copy — conn is temporary, freed after callback returns
    auto* copy = new hyperdht_connection_t;
    *copy = *conn;

    jclass cls = env->GetObjectClass(ctx->callback);
    jmethodID mid = env->GetMethodID(cls, "onConnection", "(J)V");
    env->CallVoidMethod(ctx->callback, mid, (jlong)copy);
    check_exception(env);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_hyperdht_Native_serverCreate(JNIEnv*, jobject, jlong h) {
    return (jlong)hyperdht_server_create((hyperdht_t*)h);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_serverListen(
    JNIEnv* env, jobject, jlong sh, jbyteArray jpk, jbyteArray jsk,
    jobject jcallback)
{
    hyperdht_keypair_t kp;
    env->GetByteArrayRegion(jpk, 0, 32, (jbyte*)kp.public_key);
    env->GetByteArrayRegion(jsk, 0, 64, (jbyte*)kp.secret_key);

    auto* ctx = new ServerCtx;
    ctx->callback = env->NewGlobalRef(jcallback);

    return hyperdht_server_listen((hyperdht_server_t*)sh, &kp, jni_connection_cb, ctx);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_serverClose(JNIEnv* env, jobject, jlong sh, jobject jcb) {
    if (jcb) {
        auto* ref = new jobject(env->NewGlobalRef(jcb));
        hyperdht_server_close((hyperdht_server_t*)sh,
            [](void* ud) {
                auto* r = static_cast<jobject*>(ud);
                JNIEnv* e = get_env();
                jclass cls = e->GetObjectClass(*r);
                jmethodID mid = e->GetMethodID(cls, "run", "()V");
                e->CallVoidMethod(*r, mid);
                e->DeleteGlobalRef(*r);
                delete r;
            }, ref);
    } else {
        hyperdht_server_close((hyperdht_server_t*)sh, nullptr, nullptr);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_serverCloseForce(JNIEnv* env, jobject, jlong sh, jobject jcb) {
    if (jcb) {
        auto* ref = new jobject(env->NewGlobalRef(jcb));
        hyperdht_server_close_force((hyperdht_server_t*)sh,
            [](void* ud) {
                auto* r = static_cast<jobject*>(ud);
                JNIEnv* e = get_env();
                jclass cls = e->GetObjectClass(*r);
                jmethodID mid = e->GetMethodID(cls, "run", "()V");
                e->CallVoidMethod(*r, mid);
                e->DeleteGlobalRef(*r);
                delete r;
            }, ref);
    } else {
        hyperdht_server_close_force((hyperdht_server_t*)sh, nullptr, nullptr);
    }
}

static int jni_firewall_cb(const uint8_t pk[32], const char* host,
                            uint16_t port, void* ud) {
    auto* ref = static_cast<jobject*>(ud);
    JNIEnv* env = get_env();

    jbyteArray jpk = env->NewByteArray(32);
    env->SetByteArrayRegion(jpk, 0, 32, (const jbyte*)pk);
    jstring jhost = env->NewStringUTF(host);

    jclass cls = env->GetObjectClass(*ref);
    jmethodID mid = env->GetMethodID(cls, "onFirewall",
        "([BLjava/lang/String;I)Z");
    jboolean reject = env->CallBooleanMethod(*ref, mid, jpk, jhost, (jint)port);

    env->DeleteLocalRef(jpk);
    env->DeleteLocalRef(jhost);
    return reject ? 1 : 0;
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_serverSetFirewall(
    JNIEnv* env, jobject, jlong sh, jobject jcb)
{
    auto* ref = new jobject(env->NewGlobalRef(jcb));
    hyperdht_server_set_firewall((hyperdht_server_t*)sh, jni_firewall_cb, ref);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_serverSetFirewallAsync(
    JNIEnv* env, jobject, jlong sh, jobject jcb)
{
    auto* ref = new jobject(env->NewGlobalRef(jcb));
    hyperdht_server_set_firewall_async((hyperdht_server_t*)sh,
        [](const uint8_t pk[32], const char* host, uint16_t port,
           hyperdht_firewall_done_t* done, void* ud) {
            auto* r = static_cast<jobject*>(ud);
            JNIEnv* env = get_env();
            jbyteArray jpk = env->NewByteArray(32);
            env->SetByteArrayRegion(jpk, 0, 32, (const jbyte*)pk);
            jstring jhost = env->NewStringUTF(host);
            jclass cls = env->GetObjectClass(*r);
            jmethodID mid = env->GetMethodID(cls, "onFirewall",
                "([BLjava/lang/String;IJ)V");
            env->CallVoidMethod(*r, mid, jpk, jhost, (jint)port, (jlong)done);
            env->DeleteLocalRef(jpk);
            env->DeleteLocalRef(jhost);
        }, ref);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_serverRefresh(JNIEnv*, jobject, jlong sh) {
    hyperdht_server_refresh((hyperdht_server_t*)sh);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_serverIsListening(JNIEnv*, jobject, jlong sh) {
    return hyperdht_server_is_listening((hyperdht_server_t*)sh) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_serverPublicKey(JNIEnv* env, jobject, jlong sh, jbyteArray jout) {
    uint8_t out[32];
    int rc = hyperdht_server_public_key((hyperdht_server_t*)sh, out);
    if (rc == 0) env->SetByteArrayRegion(jout, 0, 32, (jbyte*)out);
    return rc == 0 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_serverOnListening(JNIEnv* env, jobject, jlong sh, jobject jcb) {
    auto* ref = new jobject(env->NewGlobalRef(jcb));
    hyperdht_server_on_listening((hyperdht_server_t*)sh, jni_event_cb, ref);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_serverSuspend(JNIEnv*, jobject, jlong sh) {
    hyperdht_server_suspend((hyperdht_server_t*)sh);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_serverResume(JNIEnv*, jobject, jlong sh) {
    hyperdht_server_resume((hyperdht_server_t*)sh);
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

struct DoneCtx {
    jobject callback;
};

static void jni_done_cb(int error, void* ud) {
    auto* ctx = static_cast<DoneCtx*>(ud);
    JNIEnv* env = get_env();
    jclass cls = env->GetObjectClass(ctx->callback);
    jmethodID mid = env->GetMethodID(cls, "onDone", "(I)V");
    env->CallVoidMethod(ctx->callback, mid, (jint)error);
    env->DeleteGlobalRef(ctx->callback);
    delete ctx;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_immutablePut(
    JNIEnv* env, jobject, jlong h, jbyteArray jval, jobject jcb)
{
    jsize len = env->GetArrayLength(jval);
    jbyte* data = env->GetByteArrayElements(jval, nullptr);
    auto* ctx = new DoneCtx{env->NewGlobalRef(jcb)};
    int rc = hyperdht_immutable_put((hyperdht_t*)h,
        (const uint8_t*)data, (size_t)len, jni_done_cb, ctx);
    env->ReleaseByteArrayElements(jval, data, JNI_ABORT);
    if (rc != 0) { env->DeleteGlobalRef(ctx->callback); delete ctx; }
    return rc;
}

struct ImmGetCtx {
    jobject valCb;
    jobject doneCb;
};

static void jni_value_cb(const uint8_t* value, size_t len, void* ud) {
    auto* ctx = static_cast<ImmGetCtx*>(ud);
    JNIEnv* env = get_env();
    jbyteArray jdata = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(jdata, 0, (jsize)len, (const jbyte*)value);
    jclass cls = env->GetObjectClass(ctx->valCb);
    jmethodID mid = env->GetMethodID(cls, "onValue", "([B)V");
    env->CallVoidMethod(ctx->valCb, mid, jdata);
    env->DeleteLocalRef(jdata);
}

static void jni_imm_get_done_cb(int error, void* ud) {
    auto* ctx = static_cast<ImmGetCtx*>(ud);
    JNIEnv* env = get_env();
    jclass cls = env->GetObjectClass(ctx->doneCb);
    jmethodID mid = env->GetMethodID(cls, "onDone", "(I)V");
    env->CallVoidMethod(ctx->doneCb, mid, (jint)error);
    env->DeleteGlobalRef(ctx->valCb);
    env->DeleteGlobalRef(ctx->doneCb);
    delete ctx;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_immutableGet(
    JNIEnv* env, jobject, jlong h, jbyteArray jtarget,
    jobject jValCb, jobject jDoneCb)
{
    uint8_t target[32];
    env->GetByteArrayRegion(jtarget, 0, 32, (jbyte*)target);
    auto* ctx = new ImmGetCtx{env->NewGlobalRef(jValCb), env->NewGlobalRef(jDoneCb)};
    int rc = hyperdht_immutable_get((hyperdht_t*)h, target,
        jni_value_cb, jni_imm_get_done_cb, ctx);
    if (rc != 0) {
        env->DeleteGlobalRef(ctx->valCb);
        env->DeleteGlobalRef(ctx->doneCb);
        delete ctx;
    }
    return rc;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_mutablePut(
    JNIEnv* env, jobject, jlong h, jbyteArray jpk, jbyteArray jsk,
    jbyteArray jval, jlong seq, jobject jcb)
{
    hyperdht_keypair_t kp;
    env->GetByteArrayRegion(jpk, 0, 32, (jbyte*)kp.public_key);
    env->GetByteArrayRegion(jsk, 0, 64, (jbyte*)kp.secret_key);
    jsize len = env->GetArrayLength(jval);
    jbyte* data = env->GetByteArrayElements(jval, nullptr);
    auto* ctx = new DoneCtx{env->NewGlobalRef(jcb)};
    int rc = hyperdht_mutable_put((hyperdht_t*)h, &kp,
        (const uint8_t*)data, (size_t)len, (uint64_t)seq, jni_done_cb, ctx);
    env->ReleaseByteArrayElements(jval, data, JNI_ABORT);
    if (rc != 0) { env->DeleteGlobalRef(ctx->callback); delete ctx; }
    return rc;
}

struct MutGetCtx {
    jobject valCb;
    jobject doneCb;
};

static void jni_mutable_value_cb(uint64_t seq, const uint8_t* value,
                                  size_t len, const uint8_t* sig, void* ud) {
    auto* ctx = static_cast<MutGetCtx*>(ud);
    JNIEnv* env = get_env();
    jbyteArray jval = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(jval, 0, (jsize)len, (const jbyte*)value);
    jbyteArray jsig = env->NewByteArray(64);
    env->SetByteArrayRegion(jsig, 0, 64, (const jbyte*)sig);
    jclass cls = env->GetObjectClass(ctx->valCb);
    jmethodID mid = env->GetMethodID(cls, "onValue", "(J[B[B)V");
    env->CallVoidMethod(ctx->valCb, mid, (jlong)seq, jval, jsig);
    env->DeleteLocalRef(jval);
    env->DeleteLocalRef(jsig);
}

static void jni_mut_get_done_cb(int error, void* ud) {
    auto* ctx = static_cast<MutGetCtx*>(ud);
    JNIEnv* env = get_env();
    jclass cls = env->GetObjectClass(ctx->doneCb);
    jmethodID mid = env->GetMethodID(cls, "onDone", "(I)V");
    env->CallVoidMethod(ctx->doneCb, mid, (jint)error);
    env->DeleteGlobalRef(ctx->valCb);
    env->DeleteGlobalRef(ctx->doneCb);
    delete ctx;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_mutableGet(
    JNIEnv* env, jobject, jlong h, jbyteArray jpk, jlong minSeq,
    jobject jValCb, jobject jDoneCb)
{
    uint8_t pk[32];
    env->GetByteArrayRegion(jpk, 0, 32, (jbyte*)pk);
    auto* ctx = new MutGetCtx{env->NewGlobalRef(jValCb), env->NewGlobalRef(jDoneCb)};
    int rc = hyperdht_mutable_get((hyperdht_t*)h, pk, (uint64_t)minSeq,
        jni_mutable_value_cb, jni_mut_get_done_cb, ctx);
    if (rc != 0) {
        env->DeleteGlobalRef(ctx->valCb);
        env->DeleteGlobalRef(ctx->doneCb);
        delete ctx;
    }
    return rc;
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

struct QueryCtx {
    jobject replyCb;
    jobject doneCb;
};

static void jni_peer_cb(const uint8_t* value, size_t len,
                         const char* host, uint16_t port, void* ud) {
    auto* ctx = static_cast<QueryCtx*>(ud);
    JNIEnv* env = get_env();
    jbyteArray jval = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(jval, 0, (jsize)len, (const jbyte*)value);
    jstring jhost = env->NewStringUTF(host);
    jclass cls = env->GetObjectClass(ctx->replyCb);
    jmethodID mid = env->GetMethodID(cls, "onPeer", "([BLjava/lang/String;I)V");
    env->CallVoidMethod(ctx->replyCb, mid, jval, jhost, (jint)port);
    env->DeleteLocalRef(jval);
    env->DeleteLocalRef(jhost);
}

static void jni_query_done_cb(int error, void* ud) {
    auto* ctx = static_cast<QueryCtx*>(ud);
    JNIEnv* env = get_env();
    jclass cls = env->GetObjectClass(ctx->doneCb);
    jmethodID mid = env->GetMethodID(cls, "onDone", "(I)V");
    env->CallVoidMethod(ctx->doneCb, mid, (jint)error);
    env->DeleteGlobalRef(ctx->replyCb);
    env->DeleteGlobalRef(ctx->doneCb);
    delete ctx;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_findPeer(
    JNIEnv* env, jobject, jlong h, jbyteArray jpk,
    jobject jReplyCb, jobject jDoneCb)
{
    uint8_t pk[32];
    env->GetByteArrayRegion(jpk, 0, 32, (jbyte*)pk);
    auto* ctx = new QueryCtx{env->NewGlobalRef(jReplyCb), env->NewGlobalRef(jDoneCb)};
    int rc = hyperdht_find_peer((hyperdht_t*)h, pk,
        jni_peer_cb, jni_query_done_cb, ctx);
    if (rc != 0) {
        env->DeleteGlobalRef(ctx->replyCb);
        env->DeleteGlobalRef(ctx->doneCb);
        delete ctx;
    }
    return rc;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_lookup(
    JNIEnv* env, jobject, jlong h, jbyteArray jtarget,
    jobject jReplyCb, jobject jDoneCb)
{
    uint8_t target[32];
    env->GetByteArrayRegion(jtarget, 0, 32, (jbyte*)target);
    auto* ctx = new QueryCtx{env->NewGlobalRef(jReplyCb), env->NewGlobalRef(jDoneCb)};
    int rc = hyperdht_lookup((hyperdht_t*)h, target,
        jni_peer_cb, jni_query_done_cb, ctx);
    if (rc != 0) {
        env->DeleteGlobalRef(ctx->replyCb);
        env->DeleteGlobalRef(ctx->doneCb);
        delete ctx;
    }
    return rc;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_announce(
    JNIEnv* env, jobject, jlong h, jbyteArray jtarget,
    jbyteArray jval, jobject jDoneCb)
{
    uint8_t target[32];
    env->GetByteArrayRegion(jtarget, 0, 32, (jbyte*)target);
    jsize len = env->GetArrayLength(jval);
    jbyte* data = env->GetByteArrayElements(jval, nullptr);
    auto* ctx = new DoneCtx{env->NewGlobalRef(jDoneCb)};
    int rc = hyperdht_announce((hyperdht_t*)h, target,
        (const uint8_t*)data, (size_t)len, jni_done_cb, ctx);
    env->ReleaseByteArrayElements(jval, data, JNI_ABORT);
    if (rc != 0) { env->DeleteGlobalRef(ctx->callback); delete ctx; }
    return rc;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_unannounce(
    JNIEnv* env, jobject, jlong h, jbyteArray jpubkey,
    jbyteArray jpk, jbyteArray jsk, jobject jDoneCb)
{
    uint8_t pubkey[32];
    env->GetByteArrayRegion(jpubkey, 0, 32, (jbyte*)pubkey);
    hyperdht_keypair_t kp;
    env->GetByteArrayRegion(jpk, 0, 32, (jbyte*)kp.public_key);
    env->GetByteArrayRegion(jsk, 0, 64, (jbyte*)kp.secret_key);
    auto* ctx = new DoneCtx{env->NewGlobalRef(jDoneCb)};
    int rc = hyperdht_unannounce((hyperdht_t*)h, pubkey, &kp, jni_done_cb, ctx);
    if (rc != 0) { env->DeleteGlobalRef(ctx->callback); delete ctx; }
    return rc;
}

// ---------------------------------------------------------------------------
// Ping
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_ping(
    JNIEnv* env, jobject, jlong h, jstring jhost, jint port, jobject jcb)
{
    const char* host = env->GetStringUTFChars(jhost, nullptr);
    auto* ref = new jobject(env->NewGlobalRef(jcb));
    int rc = hyperdht_ping((hyperdht_t*)h, host, (uint16_t)port,
        [](int success, void* ud) {
            auto* r = static_cast<jobject*>(ud);
            JNIEnv* e = get_env();
            jclass cls = e->GetObjectClass(*r);
            jmethodID mid = e->GetMethodID(cls, "onResult", "(Z)V");
            e->CallVoidMethod(*r, mid, success ? JNI_TRUE : JNI_FALSE);
            e->DeleteGlobalRef(*r);
            delete r;
        }, ref);
    env->ReleaseStringUTFChars(jhost, host);
    if (rc != 0) { env->DeleteGlobalRef(*ref); delete ref; }
    return rc;
}

// ---------------------------------------------------------------------------
// Poll
// ---------------------------------------------------------------------------

struct PollCtx {
    jobject callback;
};

extern "C" JNIEXPORT jlong JNICALL
Java_com_hyperdht_Native_pollStart(
    JNIEnv* env, jobject, jlong h, jint fd, jint events, jobject jcb)
{
    auto* ctx = new PollCtx{env->NewGlobalRef(jcb)};
    auto* handle = hyperdht_poll_start((hyperdht_t*)h, fd, events,
        [](int fd, int events, void* ud) {
            auto* c = static_cast<PollCtx*>(ud);
            JNIEnv* e = get_env();
            jclass cls = e->GetObjectClass(c->callback);
            jmethodID mid = e->GetMethodID(cls, "onPoll", "(II)V");
            e->CallVoidMethod(c->callback, mid, fd, events);
        }, ctx);
    if (!handle) {
        env->DeleteGlobalRef(ctx->callback);
        delete ctx;
        return 0;
    }
    return (jlong)handle;
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_pollStop(JNIEnv*, jobject, jlong h) {
    hyperdht_poll_stop((hyperdht_poll_t*)h);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_punchStatsConsistent(JNIEnv*, jobject, jlong h) {
    return hyperdht_punch_stats_consistent((hyperdht_t*)h);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_punchStatsRandom(JNIEnv*, jobject, jlong h) {
    return hyperdht_punch_stats_random((hyperdht_t*)h);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_punchStatsOpen(JNIEnv*, jobject, jlong h) {
    return hyperdht_punch_stats_open((hyperdht_t*)h);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_relayStatsAttempts(JNIEnv*, jobject, jlong h) {
    return hyperdht_relay_stats_attempts((hyperdht_t*)h);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_relayStatsSuccesses(JNIEnv*, jobject, jlong h) {
    return hyperdht_relay_stats_successes((hyperdht_t*)h);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_relayStatsAborts(JNIEnv*, jobject, jlong h) {
    return hyperdht_relay_stats_aborts((hyperdht_t*)h);
}

// ---------------------------------------------------------------------------
// Suspend / Resume
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_suspend(JNIEnv*, jobject, jlong h) {
    hyperdht_suspend((hyperdht_t*)h);
}

extern "C" JNIEXPORT void JNICALL
Java_com_hyperdht_Native_resume(JNIEnv*, jobject, jlong h) {
    hyperdht_resume((hyperdht_t*)h);
}

// ---------------------------------------------------------------------------
// Remote address
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hyperdht_Native_remoteAddress(JNIEnv* env, jobject, jlong h, jobjectArray jout) {
    char host[46];
    uint16_t port;
    int rc = hyperdht_remote_address((hyperdht_t*)h, host, &port);
    if (rc != 0) return JNI_FALSE;
    env->SetObjectArrayElement(jout, 0, env->NewStringUTF(host));
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);
    env->SetObjectArrayElement(jout, 1, env->NewStringUTF(port_str));
    return JNI_TRUE;
}

// ---------------------------------------------------------------------------
// Stream write with drain
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_streamWriteWithDrain(
    JNIEnv* env, jobject, jlong sh, jbyteArray jdata, jobject jcb)
{
    jsize len = env->GetArrayLength(jdata);
    jbyte* data = env->GetByteArrayElements(jdata, nullptr);
    int rc;
    if (jcb) {
        auto* ref = new jobject(env->NewGlobalRef(jcb));
        rc = hyperdht_stream_write_with_drain((hyperdht_stream_t*)sh,
            (const uint8_t*)data, (size_t)len,
            [](hyperdht_stream_t*, void* ud) {
                auto* r = static_cast<jobject*>(ud);
                JNIEnv* e = get_env();
                jclass cls = e->GetObjectClass(*r);
                jmethodID mid = e->GetMethodID(cls, "run", "()V");
                e->CallVoidMethod(*r, mid);
                e->DeleteGlobalRef(*r);
                delete r;
            }, ref);
        if (rc < 0) { env->DeleteGlobalRef(*ref); delete ref; }
    } else {
        rc = hyperdht_stream_write((hyperdht_stream_t*)sh,
            (const uint8_t*)data, (size_t)len);
    }
    env->ReleaseByteArrayElements(jdata, data, JNI_ABORT);
    return rc;
}

// ---------------------------------------------------------------------------
// Connect with options
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jint JNICALL
Java_com_hyperdht_Native_connectEx(
    JNIEnv* env, jobject, jlong h, jbyteArray jpk,
    jbyteArray jkpPk, jbyteArray jkpSk,
    jbyteArray jrelay, jboolean fastOpen, jboolean localConn,
    jobject jcallback)
{
    uint8_t pk[32];
    env->GetByteArrayRegion(jpk, 0, 32, (jbyte*)pk);

    hyperdht_connect_opts_t opts;
    hyperdht_connect_opts_default(&opts);
    opts.fast_open = fastOpen ? 1 : 0;
    opts.local_connection = localConn ? 1 : 0;

    hyperdht_keypair_t kp;
    if (jkpPk && jkpSk) {
        env->GetByteArrayRegion(jkpPk, 0, 32, (jbyte*)kp.public_key);
        env->GetByteArrayRegion(jkpSk, 0, 64, (jbyte*)kp.secret_key);
        opts.keypair = &kp;
    }

    uint8_t relay[32];
    if (jrelay) {
        env->GetByteArrayRegion(jrelay, 0, 32, (jbyte*)relay);
        opts.relay_through = relay;
    }

    auto* ctx = new ConnectCtx;
    ctx->callback = env->NewGlobalRef(jcallback);

    return hyperdht_connect_ex((hyperdht_t*)h, pk, &opts, jni_connect_cb, ctx);
}
