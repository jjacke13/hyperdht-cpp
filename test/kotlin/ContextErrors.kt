package com.hyperdht

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

/** Operation-aware messages through the real host JNI bridge. */
object ContextErrorsTest {
    @JvmStatic fun main(args: Array<String>) = runBlocking {
        HyperDHT(DhtOptions(host = "127.0.0.1")).use { dht ->
            suspend fun expect(code: Int, message: String, call: suspend () -> Any?) {
                try {
                    withTimeout(1000) { call() }
                    error("expected failure")
                } catch (error: DhtException) {
                    check(error.code == code && error.message == message) {
                        "expected '$message' ($code), received '${error.message}' (${error.code})"
                    }
                }
            }
            expect(-1, "immutablePut: invalid argument or handle (-1)") {
                dht.immutablePut(byteArrayOf())
            }
            expect(-1, "mutablePut: invalid argument or handle (-1)") {
                dht.mutablePut(KeyPair.generate(), byteArrayOf(), 0)
            }
            expect(-2, "ping: invalid IPv4 address (-2)") { dht.ping("invalid-ip", 1) }
            expect(-2, "addNode: invalid IPv4 address (-2)") { dht.addNode("invalid-ip", 1) }
            val key = ByteArray(32).also { it[0] = 0xf0.toByte() }
            expect(-1, "immutableGet: invalid argument or handle (-1)") { dht.immutableGet(key) }
            expect(-1, "connect: invalid argument or handle (-1)") { dht.connect(key) }
            expect(1, "immutablePut: too few nodes responded (1)") { dht.immutablePut(byteArrayOf(2)) }
            expect(1, "mutablePut: too few nodes responded (1)") {
                dht.mutablePut(KeyPair.generate(), byteArrayOf(2), 0)
            }
            expect(-1, "serverListen: invalid argument or handle (-1)") {
                val kp = KeyPair.generate()
                val rc = Native.serverListen(0L, kp.publicKey, kp.secretKey,
                    ConnectionCallback { error("unexpected connection") })
                Errors.checkCall(rc, "serverListen")
            }
        }
        check(Errors.describeQuery(-2) == "unknown query error")
        check(Errors.describeQuery(0) == "success")
        check(Errors.describeCall(0) == "success")
        check(Errors.describeCall(-73) == "unknown submission error")
        check(Errors.describeSystem(0) == "success")
        // libuv codes are platform-dependent: use a real bind failure on this host.
        val loop = Native.loopCreate()
        val dht = Native.create(loop, 0, true, false, 5000, null, "invalid-ip")
        val code = Native.bind(dht, 0)
        check(code < 0 && Errors.describeSystem(code).isNotBlank())
        check(Errors.describeSystem(code) != "unknown error")
        Native.destroyForce(dht)
        while (Native.loopRunNowait(loop) != 0) {}
        Native.free(dht)
        Native.loopClose(loop)
        println("PASS: Kotlin operation descriptions preserve validation error codes")
    }
}
