package com.hyperdht

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

/** Tests the real JNI/Kotlin path with controlled C completion callbacks. */
object ReadErrorsTest {
    @JvmStatic fun main(args: Array<String>) = runBlocking {
        HyperDHT(DhtOptions(host = "127.0.0.1")).use { dht ->
            for (mode in 0..4) {
                val target = ByteArray(32).also { it[0] = (0xe0 + mode).toByte() }
                val expectedError = when (mode) { 0 -> 1; 3 -> Errors.CANCELLED; 4 -> 73; else -> 0 }
                try {
                    val result = withTimeout(2000) { dht.immutableGet(target) }
                    check(expectedError == 0) { "read failure was reported as a value or null" }
                    if (mode == 1) check(result == null)
                    else check(result?.contentEquals("read".toByteArray()) == true)
                } catch (error: DhtException) {
                    check(expectedError != 0 && error.code == expectedError)
                    check(error.message == Errors.describe(expectedError))
                }
            }
        }
        println("PASS: Kotlin read success, miss, query error, cancellation and unknown code")
    }
}
