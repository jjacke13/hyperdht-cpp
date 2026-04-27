package com.hyperdht

import android.util.Log
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

private const val TAG = "HyperDHT-Stream"

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
        Log.d(TAG, "awaitOpen: opened=$opened handle=$handle")
        synchronized(this) {
            if (opened) { Log.d(TAG, "awaitOpen: already open"); cont.resume(Unit); return@suspendCancellableCoroutine }
            openContinuation = cont
            Log.d(TAG, "awaitOpen: suspending")
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
        Log.d(TAG, "write: ${data.size} bytes, handle=$handle")
        return suspendCancellableCoroutine { cont ->
            postToLoop(Runnable {
                val rc = if (handle != 0L) Native.streamWrite(handle, data) else -1
                Log.d(TAG, "write: native rc=$rc")
                cont.resume(rc)
            })
        }
    }

    /**
     * Close the stream gracefully. Thread-safe — posts to the loop
     * thread (fire-and-forget, does not wait for close to complete).
     *
     * The dataChannel is NOT closed here — it stays open so that
     * in-flight data arriving on the libuv thread (via fireData)
     * is not silently dropped by trySend on a closed channel.
     * The channel is closed later by fireClose() when the native
     * on_close callback fires, guaranteeing correct ordering:
     * all data callbacks complete before the channel shuts down.
     */
    fun close() {
        if (closed) return
        closed = true
        if (handle != 0L) {
            val h = handle
            handle = 0L
            postToLoop(Runnable { Native.streamClose(h) })
        }
    }

    // Called from JNI on the libuv thread
    internal fun fireOpen() {
        Log.d(TAG, "fireOpen: opened=$opened handle=$handle")
        synchronized(this) {
            opened = true
            openContinuation?.resume(Unit)
            openContinuation = null
        }
        Log.d(TAG, "fireOpen: done")
    }

    internal fun fireData(bytes: ByteArray) {
        Log.d(TAG, "fireData: ${bytes.size} bytes, closed=$closed, handle=$handle")
        val result = dataChannel.trySend(bytes)
        Log.d(TAG, "fireData: trySend success=${result.isSuccess} failure=${result.isFailure} closed=${result.isClosed}")
    }

    internal fun fireClose() {
        Log.d(TAG, "fireClose: closed=$closed handle=$handle")
        closed = true
        handle = 0L
        dataChannel.close()
        onCloseCallback?.invoke()
        Log.d(TAG, "fireClose: done")
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
