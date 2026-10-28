package com.hyperdht

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

/** Real JNI calls; the fixture only supplies immediate get/connect rejections. */
object ImmediateErrorsTest {
    @JvmStatic fun main(args: Array<String>) = runBlocking {
        HyperDHT(DhtOptions(host = "127.0.0.1")).use { dht ->
            val key = ByteArray(32).also { it[0] = 0xf0.toByte() }
            val keyPair = KeyPair.generate()
            val rejected: List<Pair<Int, suspend () -> Any?>> = listOf(
                -1 to { dht.immutablePut(byteArrayOf()) },
                -1 to { dht.mutablePut(keyPair, byteArrayOf(), 0) },
                -2 to { dht.ping("invalid-ip", 1) },
                -1 to { dht.immutableGet(key) },
                -1 to { dht.connect(key) },
            )
            var passed = 0
            for ((code, call) in rejected) {
                try {
                    withTimeout(1000) { call() }
                    error("rejected call succeeded")
                } catch (error: DhtException) {
                    check(error.code == code)
                    passed++
                } catch (error: kotlinx.coroutines.TimeoutCancellationException) {
                    println("FAIL: immediate error $code was ignored")
                }
            }
            check(passed == rejected.size) { "$passed/${rejected.size} rejections reported" }
            // Accepted calls may invoke their callback synchronously before returning zero.
            withTimeout(1000) {
                dht.immutablePut(byteArrayOf(1))
                dht.mutablePut(keyPair, byteArrayOf(1), 0)
                key[0] = 0xf1.toByte()
                check(dht.immutableGet(key) == null)
                try {
                    dht.connect(key)
                    error("callback failure was ignored")
                } catch (error: DhtException) {
                    check(error.code == Errors.PEER_NOT_FOUND)
                }
            }
        }
        println("PASS: five immediate rejections and synchronous accepted storage callbacks")
    }
}
