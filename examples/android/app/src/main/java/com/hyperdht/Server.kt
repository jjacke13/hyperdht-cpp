package com.hyperdht

import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/** HyperDHT server — listens for incoming encrypted connections. */
class Server internal constructor(
    private val handle: Long,
    private val dhtHandle: Long,
    private val postToLoop: (Runnable) -> Unit,
) {
    private var listening = false

    /**
     * Listen for connections. Returns a Flow that emits ready-to-use Streams.
     *
     * The stream is opened inside the C connection callback while the
     * connection struct is still valid. This is critical — the struct
     * contains pointers that are freed after the callback returns.
     */
    fun listen(keyPair: KeyPair): Flow<Stream> = callbackFlow {
        check(!listening) { "Already listening" }
        listening = true

        val rc = Native.serverListen(handle, keyPair.publicKey, keyPair.secretKey,
            ConnectionCallback { connPtr ->
                // connPtr is valid ONLY during this callback — open stream NOW
                val stream = Stream.open(dhtHandle, connPtr, postToLoop)
                trySend(stream)
            })
        if (rc != 0) throw DhtException(rc, "server_listen failed: $rc")

        awaitClose { close() }
    }

    /** Set synchronous firewall. Return true to reject, false to accept. */
    fun setFirewall(filter: (remotePublicKey: ByteArray, host: String, port: Int) -> Boolean) {
        Native.serverSetFirewall(handle, FirewallCallback { pk, host, port ->
            filter(pk, host, port)
        })
    }

    /** Close the server (unannounce from DHT). */
    suspend fun close(): Unit = suspendCancellableCoroutine { cont ->
        Native.serverClose(handle, Runnable {
            if (cont.isActive) cont.resume(Unit)
        })
    }

    /** Force-close without unannouncing. */
    suspend fun closeForce(): Unit = suspendCancellableCoroutine { cont ->
        Native.serverCloseForce(handle, Runnable {
            if (cont.isActive) cont.resume(Unit)
        })
    }

    fun refresh() = Native.serverRefresh(handle)
    val isListening: Boolean get() = Native.serverIsListening(handle)

    val publicKey: ByteArray?
        get() {
            val out = ByteArray(32)
            return if (Native.serverPublicKey(handle, out)) out else null
        }

    fun suspend() = Native.serverSuspend(handle)
    fun resume() = Native.serverResume(handle)

    suspend fun awaitListening(): Unit = suspendCancellableCoroutine { cont ->
        Native.serverOnListening(handle, Runnable {
            if (cont.isActive) cont.resume(Unit)
        })
    }
}
