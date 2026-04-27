package com.hyperdht

import kotlinx.coroutines.*
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * HyperDHT node — connect to peers, listen for connections, store data.
 *
 * Threading model: ALL native calls execute on a single dedicated thread
 * via loopExecutor.execute(). The uv_run loop yields periodically to let
 * queued tasks run on the same thread. This ensures libuv's single-thread
 * requirement is always met.
 */
class HyperDHT(
    private val options: DhtOptions = DhtOptions(),
) : Closeable {

    private val loopExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "hyperdht-loop").apply { isDaemon = true }
    }
    private val loopDispatcher = loopExecutor.asCoroutineDispatcher()
    private val scope = CoroutineScope(loopDispatcher + SupervisorJob())

    private var loopHandle: Long = 0L
    private var handle: Long = 0L
    private var asyncHandle: Long = 0L
    private var loopJob: Job? = null
    @Volatile private var destroyed = false

    private val cbIdGen = AtomicLong(0)
    private val persistentRefs = ConcurrentHashMap<Long, Any>()
    internal val activeStreams: MutableSet<Stream> = ConcurrentHashMap.newKeySet()

    // Fixed keys for single-slot event callbacks (avoids unbounded map growth).
    // Each event type overwrites the same key instead of incrementing cbIdGen.
    private companion object {
        const val KEY_NETWORK_CHANGE = -1L
    }

    init {
        // ALL native calls on the loop thread
        runBlocking(loopDispatcher) {
            loopHandle = Native.loopCreate()
            handle = Native.create(
                loopHandle, options.port, options.ephemeral,
                options.usePublicBootstrap, options.connectionKeepAlive,
                options.seed, options.host,
            )
            check(handle != 0L) { "Failed to create HyperDHT instance" }
            asyncHandle = Native.asyncCreate(loopHandle)
            Native.bind(handle, options.port)
        }
    }

    /**
     * Post a task to the loop thread and wake up uv_run immediately.
     * Thread-safe — may be called from any thread (UI, IO, etc.).
     */
    internal fun postToLoop(block: Runnable) {
        loopExecutor.execute(block)
        Native.asyncSend(asyncHandle)
    }

    val port: Int get() = Native.port(handle)

    // --- Lifecycle ---

    fun start(): Job {
        check(loopJob == null) { "Already started" }
        loopJob = scope.launch {
            while (isActive && !destroyed) {
                Native.loopRunOnce(loopHandle)
                // Yield lets other tasks queued on this thread execute
                // (connect, write, etc.) before the next uv_run iteration.
                yield()
                // Flush: tasks executed during yield() may have queued
                // deferred libuv work (e.g. UDX's uv_prepare for packet
                // sends).  A non-blocking run processes those callbacks
                // so the data hits the wire BEFORE the next blocking poll,
                // preventing a full round-trip delay on the echo path.
                Native.loopRunNowait(loopHandle)
            }
        }
        return loopJob!!
    }

    override fun close() {
        if (destroyed) return
        destroyed = true
        try {
            runBlocking(loopDispatcher) {
                withTimeout(5000L) {
                    loopJob?.cancelAndJoin()
                    // Invalidate all active streams before destroying native resources
                    for (stream in activeStreams) {
                        stream.markClosed()
                    }
                    activeStreams.clear()
                    Native.asyncClose(asyncHandle)
                    Native.destroy(handle)
                    // Drain pending close callbacks with bounded iterations
                    var remaining = 500
                    while (Native.loopRunOnce(loopHandle) != 0 && remaining-- > 0) {}
                    Native.free(handle)
                    Native.loopClose(loopHandle)
                }
            }
        } catch (_: Exception) {
            // Timeout or cancellation — force cleanup to prevent ANR
            for (stream in activeStreams) {
                stream.markClosed()
            }
            activeStreams.clear()
        }
        loopExecutor.shutdownNow()
        persistentRefs.clear()
    }

    // --- Helper: run a native call on the loop thread + wake the loop ---

    private suspend fun <T> onLoop(block: () -> T): T =
        suspendCancellableCoroutine { cont ->
            try {
                loopExecutor.execute {
                    try {
                        cont.resume(block())
                    } catch (e: Throwable) {
                        cont.resumeWithException(e)
                    }
                }
                if (!destroyed) Native.asyncSend(asyncHandle)
            } catch (e: java.util.concurrent.RejectedExecutionException) {
                cont.resumeWithException(e)
            }
        }

    // --- State ---

    val isOnline: Boolean get() = Native.isOnline(handle)
    val isDegraded: Boolean get() = Native.isDegraded(handle)
    val isPersistent: Boolean get() = Native.isPersistent(handle)
    val isBootstrapped: Boolean get() = Native.isBootstrapped(handle)
    val isSuspended: Boolean get() = Native.isSuspended(handle)

    val remoteAddress: Address?
        get() {
            val out = arrayOfNulls<String>(2)
            return if (Native.remoteAddress(handle, out))
                Address(out[0]!!, out[1]!!.toInt())
            else null
        }

    val punchStats: PunchStats
        get() = PunchStats(
            consistent = Native.punchStatsConsistent(handle),
            random = Native.punchStatsRandom(handle),
            open = Native.punchStatsOpen(handle),
        )

    val relayStats: RelayStats
        get() = RelayStats(
            attempts = Native.relayStatsAttempts(handle),
            successes = Native.relayStatsSuccesses(handle),
            aborts = Native.relayStatsAborts(handle),
        )

    // --- Events ---

    suspend fun awaitBootstrapped() {
        if (isBootstrapped) return
        val deferred = CompletableDeferred<Unit>()
        val id = cbIdGen.incrementAndGet()
        val cb = Runnable {
            persistentRefs.remove(id)
            deferred.complete(Unit)
        }
        persistentRefs[id] = cb
        onLoop { Native.onBootstrapped(handle, cb) }
        deferred.await()
    }

    fun onNetworkChange(callback: () -> Unit) {
        val cb = Runnable { callback() }
        persistentRefs[KEY_NETWORK_CHANGE] = cb
        loopExecutor.execute { Native.onNetworkChange(handle, cb) }
    }

    // --- Connect ---

    /**
     * Connect to a remote peer and open an encrypted stream.
     *
     * The stream is opened atomically inside the C connect callback,
     * while the connection struct is still valid. This avoids the
     * dangling-pointer crash that occurs when stream_open is called
     * after the callback returns.
     */
    suspend fun connect(remotePublicKey: ByteArray): Stream {
        require(remotePublicKey.size == 32) { "Public key must be 32 bytes" }
        val deferred = CompletableDeferred<Stream>()

        val stream = Stream.createPending(handle, ::postToLoop)
        val onOpen = Runnable { stream.fireOpen() }
        val onData = DataCallback { data -> stream.fireData(data) }
        val onClose = Runnable {
            stream.fireClose()
            activeStreams.remove(stream)
        }
        stream.retainCallbacks(onOpen, onData, onClose)

        val cb = ConnectCallback { error, streamHandle ->
            if (error != 0) deferred.completeExceptionally(DhtException(error))
            else {
                stream.setHandle(streamHandle)
                activeStreams.add(stream)
                deferred.complete(stream)
            }
        }

        onLoop {
            Native.connectAndOpenStream(
                handle, remotePublicKey, onOpen, onData, onClose, cb)
        }

        return deferred.await()
    }

    // --- Server ---

    fun createServer(): Server = Server(Native.serverCreate(handle), handle, ::postToLoop, activeStreams)

    // --- Storage ---

    suspend fun immutablePut(value: ByteArray) {
        val deferred = CompletableDeferred<Unit>()
        val cb = DoneCallback { error ->
            if (error != 0) deferred.completeExceptionally(DhtException(error))
            else deferred.complete(Unit)
        }
        onLoop { Native.immutablePut(handle, value, cb) }
        deferred.await()
    }

    suspend fun immutableGet(target: ByteArray): ByteArray? {
        require(target.size == 32) { "Target must be 32 bytes" }
        val deferred = CompletableDeferred<ByteArray?>()
        var result: ByteArray? = null
        val valCb = ValueCallback { value -> result = value }
        val doneCb = DoneCallback { _ -> deferred.complete(result) }
        onLoop { Native.immutableGet(handle, target, valCb, doneCb) }
        return deferred.await()
    }

    suspend fun mutablePut(keyPair: KeyPair, value: ByteArray, seq: Long) {
        val deferred = CompletableDeferred<Unit>()
        val cb = DoneCallback { error ->
            if (error != 0) deferred.completeExceptionally(DhtException(error))
            else deferred.complete(Unit)
        }
        onLoop {
            Native.mutablePut(handle, keyPair.publicKey, keyPair.secretKey,
                value, seq, cb)
        }
        deferred.await()
    }

    // --- Utilities ---

    fun hash(data: ByteArray): ByteArray {
        val out = ByteArray(32)
        Native.hash(data, out)
        return out
    }

    suspend fun addNode(host: String, port: Int) = onLoop {
        val rc = Native.addNode(handle, host, port)
        if (rc != 0) throw DhtException(rc, "addNode failed: $rc")
    }

    suspend fun ping(host: String, port: Int): Boolean {
        val deferred = CompletableDeferred<Boolean>()
        val cb = PingCallback { success -> deferred.complete(success) }
        onLoop { Native.ping(handle, host, port, cb) }
        return deferred.await()
    }

    fun suspend() = loopExecutor.execute { Native.suspend(handle) }
    fun resume() = loopExecutor.execute { Native.resume(handle) }
}
