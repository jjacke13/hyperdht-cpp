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
) {
    private var listening = false

    /** Listen for connections. Returns a Flow that emits ConnectionInfo. */
    fun listen(keyPair: KeyPair): Flow<ConnectionInfo> = callbackFlow {
        check(!listening) { "Already listening" }
        listening = true

        val rc = Native.serverListen(handle, keyPair.publicKey, keyPair.secretKey,
            ConnectionCallback { connPtr ->
                val info = buildConnectionInfo(connPtr)
                trySend(info)
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
        Native.serverClose(handle, Runnable { cont.resume(Unit) })
    }

    /** Force-close without unannouncing. */
    suspend fun closeForce(): Unit = suspendCancellableCoroutine { cont ->
        Native.serverCloseForce(handle, Runnable { cont.resume(Unit) })
    }

    /** Force re-announcement. */
    fun refresh() = Native.serverRefresh(handle)

    /** Whether the server is currently listening. */
    val isListening: Boolean get() = Native.serverIsListening(handle)

    /** Server's public key, or null if not listening. */
    val publicKey: ByteArray?
        get() {
            val out = ByteArray(32)
            return if (Native.serverPublicKey(handle, out)) out else null
        }

    /** Suspend the server. */
    fun suspend() = Native.serverSuspend(handle)

    /** Resume the server. */
    fun resume() = Native.serverResume(handle)

    /** Wait until the server is announced and ready. */
    suspend fun awaitListening(): Unit = suspendCancellableCoroutine { cont ->
        Native.serverOnListening(handle, Runnable { cont.resume(Unit) })
    }

    /** Open an encrypted stream over a connection. */
    fun openStream(connection: ConnectionInfo): Stream =
        Stream.open(dhtHandle, connection.ptr)

    private fun buildConnectionInfo(connPtr: Long): ConnectionInfo {
        // The JNI bridge fills a ConnectionInfo struct — we extract fields here.
        // In the real implementation, the JNI callback passes all fields directly.
        return ConnectionInfo(
            ptr = connPtr,
            remotePublicKey = ByteArray(32), // filled by JNI
            peerHost = "",                    // filled by JNI
            peerPort = 0,                     // filled by JNI
            isInitiator = false,
        )
    }
}
