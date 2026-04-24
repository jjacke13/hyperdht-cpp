package com.hyperdht

/** Firewall classification constants. */
object Firewall {
    const val UNKNOWN = 0
    const val OPEN = 1
    const val CONSISTENT = 2
    const val RANDOM = 3
}

/** Connect error codes (matches C FFI HYPERDHT_ERR_*). */
object Errors {
    const val OK = 0
    const val DESTROYED = -1
    const val PEER_NOT_FOUND = -2
    const val CONNECTION_FAILED = -3
    const val NO_ADDRESSES = -4
    const val HOLEPUNCH_FAILED = -5
    const val HOLEPUNCH_TIMEOUT = -6
    const val RELAY_FAILED = -7
    const val CANCELLED = -8

    fun describe(code: Int): String = Native.connectStrerror(code)
}

/** HyperDHT error with numeric code and human-readable message. */
class DhtException(val code: Int, message: String = Errors.describe(code)) :
    Exception(message)

/** DHT node options. */
data class DhtOptions(
    val port: Int = 0,
    val ephemeral: Boolean = true,
    val usePublicBootstrap: Boolean = false,
    val connectionKeepAlive: Int = 5000,
    val seed: ByteArray? = null,
    val host: String? = null,
)

/** Network address. */
data class Address(val host: String, val port: Int)

/** Holepunch statistics. */
data class PunchStats(val consistent: Int, val random: Int, val open: Int)

/** Relay statistics. */
data class RelayStats(val attempts: Int, val successes: Int, val aborts: Int)
