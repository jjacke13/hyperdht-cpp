package com.hyperdht

import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/** Encrypted read/write stream over an established connection. */
class Stream internal constructor(
    private var handle: Long,
    private val dhtHandle: Long,
    private val connPtr: Long,
) {
    private var closed = false

    /** True when the SecretStream header exchange is complete. */
    val isOpen: Boolean get() = handle != 0L && Native.streamIsOpen(handle)

    /** Suspend until the stream is open (header exchange complete). */
    suspend fun awaitOpen(): Unit = suspendCancellableCoroutine { cont ->
        // If already open, resume immediately
        if (isOpen) { cont.resume(Unit); return@suspendCancellableCoroutine }
        // Otherwise wait for on_open — wired during open()
        openContinuation = cont
    }

    /** Incoming data as a Flow. Collect to receive stream data. */
    val data: Flow<ByteArray> = callbackFlow {
        dataChannel = this
        awaitClose { dataChannel = null }
    }

    /** Write data to the encrypted stream. */
    fun write(data: ByteArray): Int {
        check(!closed) { "Stream is closed" }
        return Native.streamWrite(handle, data)
    }

    /** Close the stream gracefully. */
    fun close() {
        if (closed) return
        closed = true
        if (handle != 0L) {
            Native.streamClose(handle)
            handle = 0L
        }
    }

    // Internal: wired by HyperDHT.openStream()
    internal var openContinuation: kotlinx.coroutines.CancellableContinuation<Unit>? = null
    internal var dataChannel: kotlinx.coroutines.channels.SendChannel<ByteArray>? = null
    internal var onCloseCallback: (() -> Unit)? = null

    internal fun fireOpen() {
        openContinuation?.resume(Unit)
        openContinuation = null
    }

    internal fun fireData(bytes: ByteArray) {
        dataChannel?.trySend(bytes)
    }

    internal fun fireClose() {
        closed = true
        handle = 0L
        dataChannel?.close()
        onCloseCallback?.invoke()
    }

    companion object {
        /** Open a stream over a connection. Called by HyperDHT.openStream(). */
        internal fun open(
            dhtHandle: Long,
            connPtr: Long,
        ): Stream {
            val stream = Stream(0L, dhtHandle, connPtr)

            val onOpen = Runnable { stream.fireOpen() }
            val onData = DataCallback { data -> stream.fireData(data) }
            val onClose = Runnable { stream.fireClose() }

            val handle = Native.streamOpen(dhtHandle, connPtr, onOpen, onData, onClose)
            check(handle != 0L) { "Failed to open stream" }
            stream.handle = handle

            // Keep callback refs alive (prevent GC)
            stream._refs = arrayOf(onOpen, onData, onClose)

            return stream
        }
    }

    // prevent GC of callback objects passed to JNI
    @Suppress("unused")
    private var _refs: Array<Any>? = null
}
