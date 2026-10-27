package com.hyperdht

/** Host JVM regression using the real wrapper sources and libhyperdht_jni. */
fun main() {
    val errors = listOf(
        Errors.OK to "success",
        Errors.DESTROYED to "DHT destroyed during connect",
        Errors.PEER_NOT_FOUND to "peer not found",
        Errors.CONNECTION_FAILED to "peer connection failed (all relay handshakes failed)",
        Errors.NO_ADDRESSES to "no connectable addresses from server",
        Errors.HOLEPUNCH_FAILED to "holepunch failed",
        Errors.HOLEPUNCH_TIMEOUT to "holepunch timeout",
        Errors.RELAY_FAILED to "blind relay pairing failed",
        Errors.CANCELLED to "cancelled",
        Errors.SERVER_ERROR to "server returned a handshake error or an incompatible reply",
    )
    check(Errors.CANCELLED == -8 && Errors.SERVER_ERROR == -9)
    for ((code, description) in errors) {
        check(Native.connectStrerror(code) == description)
        val error = DhtException(code)
        check(error.code == code && error.message == description)
    }
    check(Errors.describe(12345) == "unknown error")

    val loop = Native.loopCreate()
    val dht = Native.create(loop, 0, true, false, 5000, null, "127.0.0.1")
    check(dht != 0L && Native.bind(dht, 0) == 0)
    Native.destroyForce(dht)
    var callbacks = 0
    var callbackCode = 0
    var callbackStream = -1L
    val result = ConnectCallback { code, stream ->
        callbacks++
        callbackCode = code
        callbackStream = stream
    }
    check(Native.connectAndOpenStream(dht, KeyPair.generate().publicKey,
        Runnable { error("unexpected open") }, DataCallback { error("unexpected data") },
        Runnable {}, result) == 0)
    val deadline = System.nanoTime() + 5_000_000_000L
    while (callbacks == 0 && System.nanoTime() < deadline) Native.loopRunNowait(loop)
    check(callbacks == 1 && callbackStream == 0L)
    val error = DhtException(callbackCode)
    check(error.code == Errors.DESTROYED && error.message == "DHT destroyed during connect")
    while (Native.loopRunNowait(loop) != 0 && System.nanoTime() < deadline) {}
    Native.free(dht)
    Native.loopClose(loop)
    println("PASS: JNI descriptions, Kotlin exception codes and real connect failure")
}
