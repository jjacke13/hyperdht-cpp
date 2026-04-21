package com.hyperdht

import kotlinx.coroutines.*
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

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
        if (destroyed) return  // async handle already closed
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
                // (connect, write, etc.) before the next uv_run iteration
                yield()
            }
        }
        return loopJob!!
    }

    override fun close() {
        if (destroyed) return
        destroyed = true
        runBlocking(loopDispatcher) {
            loopJob?.cancelAndJoin()
            Native.asyncClose(asyncHandle)
            Native.destroy(handle)
            while (Native.loopRunOnce(loopHandle) != 0) {}
            Native.free(handle)
            Native.loopClose(loopHandle)
        }
        loopExecutor.shutdown()
        persistentRefs.clear()
    }

    // --- Helper: run a native call on the loop thread ---

    private suspend fun <T> onLoop(block: () -> T): T =
        withContext(loopDispatcher) { block() }

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
        val id = cbIdGen.incrementAndGet()
        val cb = Runnable { callback() }
        persistentRefs[id] = cb
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
        val onClose = Runnable { stream.fireClose() }
        stream.retainCallbacks(onOpen, onData, onClose)

        val cb = ConnectCallback { error, streamHandle ->
            if (error != 0) deferred.completeExceptionally(DhtException(error))
            else {
                stream.setHandle(streamHandle)
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

    fun createServer(): Server = Server(Native.serverCreate(handle), handle, ::postToLoop)

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
