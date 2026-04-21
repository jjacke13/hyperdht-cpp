package com.hyperdht

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/** Encrypted read/write stream over an established connection. */
class Stream internal constructor(
    private var handle: Long,
    private val dhtHandle: Long,
    private val connPtr: Long,
) {
    private var closed = false
    @Volatile private var opened = false
    private var openContinuation: kotlinx.coroutines.CancellableContinuation<Unit>? = null

    // Eagerly created channel — no data loss before collection.
    private val dataChannel = Channel<ByteArray>(Channel.UNLIMITED)

    /** True when the SecretStream header exchange is complete. */
    val isOpen: Boolean get() = handle != 0L && Native.streamIsOpen(handle)

    /** Suspend until the stream is open (header exchange complete). */
    suspend fun awaitOpen(): Unit = suspendCancellableCoroutine { cont ->
        synchronized(this) {
            if (opened) { cont.resume(Unit); return@suspendCancellableCoroutine }
            openContinuation = cont
        }
    }

    /** Incoming data as a Flow. Collect to receive stream data. */
    val data: Flow<ByteArray> = dataChannel.receiveAsFlow()

    /** Write data to the encrypted stream. */
    fun write(data: ByteArray): Int {
        check(!closed) { "Stream is closed" }
        return Native.streamWrite(handle, data)
    }

    /** Close the stream gracefully. */
    fun close() {
        if (closed) return
        closed = true
        dataChannel.close()
        if (handle != 0L) {
            Native.streamClose(handle)
            handle = 0L
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

    internal var onCloseCallback: (() -> Unit)? = null

    // prevent GC of callback objects passed to JNI
    @Suppress("unused")
    private var _refs: Array<Any>? = null

    companion object {
        internal fun open(dhtHandle: Long, connPtr: Long): Stream {
            val stream = Stream(0L, dhtHandle, connPtr)

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
