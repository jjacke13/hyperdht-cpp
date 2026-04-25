package com.hyperdht

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Encrypted read/write stream over an established connection.
 *
 * All native calls are routed to the libuv event loop thread via
 * [postToLoop]. libuv is NOT thread-safe — calling native functions
 * from any other thread corrupts the handle queue and crashes in uv_run.
 */
class Stream internal constructor(
    private var handle: Long,
    private val dhtHandle: Long,
    private val connPtr: Long,
    private val postToLoop: (Runnable) -> Unit,
) {
    private var closed = false
    @Volatile private var opened = false
    private var openContinuation: kotlinx.coroutines.CancellableContinuation<Unit>? = null

    // Eagerly created channel — no data loss before collection.
    private val dataChannel = Channel<ByteArray>(Channel.UNLIMITED)

    /** True when the SecretStream header exchange is complete. */
    val isOpen: Boolean get() = opened && handle != 0L

    /** Suspend until the stream is open (header exchange complete). */
    suspend fun awaitOpen(): Unit = suspendCancellableCoroutine { cont ->
        synchronized(this) {
            if (opened) { cont.resume(Unit); return@suspendCancellableCoroutine }
            openContinuation = cont
        }
    }

    /** Incoming data as a Flow. Collect to receive stream data. */
    val data: Flow<ByteArray> = dataChannel.receiveAsFlow()

    /**
     * Write data to the encrypted stream. Thread-safe — posts to the
     * loop thread and suspends until the write completes.
     */
    suspend fun write(data: ByteArray): Int {
        check(!closed) { "Stream is closed" }
        return suspendCancellableCoroutine { cont ->
            postToLoop(Runnable {
                val rc = if (handle != 0L) Native.streamWrite(handle, data) else -1
                cont.resume(rc)
            })
        }
    }

    /**
     * Close the stream gracefully. Thread-safe — posts to the loop
     * thread (fire-and-forget, does not wait for close to complete).
     */
    fun close() {
        if (closed) return
        closed = true
        dataChannel.close()
        if (handle != 0L) {
            val h = handle
            handle = 0L
            postToLoop(Runnable { Native.streamClose(h) })
        }
    }

    // Called from JNI on the libuv thread
    internal fun fireOpen() {
        synchronized(this) {
            opened = true
            openContinuation?.resume(Unit)
            openContinuation = null
        }
    }

    internal fun fireData(bytes: ByteArray) {
        dataChannel.trySend(bytes)
    }

    internal fun fireClose() {
        closed = true
        handle = 0L
        dataChannel.close()
        onCloseCallback?.invoke()
    }

    /**
     * Mark this stream as closed without calling native close.
     * Used during HyperDHT.close() when the C layer handles cleanup.
     */
    internal fun markClosed() {
        synchronized(this) {
            if (closed) return
            closed = true
            handle = 0L
            openContinuation?.cancel()
            openContinuation = null
        }
        dataChannel.close()
    }

    internal var onCloseCallback: (() -> Unit)? = null

    // prevent GC of callback objects passed to JNI
    @Suppress("unused")
    internal var _refs: Array<Any>? = null

    internal fun setHandle(h: Long) { handle = h }
    internal fun retainCallbacks(vararg refs: Any) { _refs = arrayOf(*refs) }

    companion object {
        /** Create a pending stream (handle set later by connectAndOpenStream). */
        internal fun createPending(dhtHandle: Long, postToLoop: (Runnable) -> Unit): Stream =
            Stream(0L, dhtHandle, 0L, postToLoop)

        /**
         * Open a stream synchronously from a valid connection pointer.
         * MUST be called during the connection callback — connPtr is
         * invalidated after the callback returns.
         */
        internal fun open(
            dhtHandle: Long, connPtr: Long, postToLoop: (Runnable) -> Unit,
        ): Stream {
            val stream = Stream(0L, dhtHandle, connPtr, postToLoop)

            val onOpen = Runnable { stream.fireOpen() }
            val onData = DataCallback { data -> stream.fireData(data) }
            val onClose = Runnable { stream.fireClose() }

            val handle = Native.streamOpen(dhtHandle, connPtr, onOpen, onData, onClose)
            check(handle != 0L) { "Failed to open stream" }
            stream.handle = handle
            stream._refs = arrayOf(onOpen, onData, onClose)

            return stream
        }
    }
}
