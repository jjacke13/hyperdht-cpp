package com.hyperdht

import kotlinx.coroutines.*
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * HyperDHT node — connect to peers, listen for connections, store data.
 *
 * Usage:
 * ```kotlin
 * val dht = HyperDHT(usePublicBootstrap = true)
 * dht.start()
 *
 * val conn = dht.connect(serverPublicKey)
 * val stream = dht.openStream(conn)
 * stream.awaitOpen()
 * stream.write("hello".toByteArray())
 *
 * dht.close()
 * ```
 */
class HyperDHT(
    private val options: DhtOptions = DhtOptions(),
) : Closeable {

    private val loopHandle: Long = Native.loopCreate()
    private val handle: Long
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var loopJob: Job? = null
    @Volatile private var destroyed = false

    // Callback ref management: one-shot callbacks remove themselves;
    // persistent callbacks (events) are cleaned up in close().
    private val cbIdGen = AtomicLong(0)
    private val persistentRefs = ConcurrentHashMap<Long, Any>()

    init {
        handle = Native.create(
            loopHandle, options.port, options.ephemeral,
            options.usePublicBootstrap, options.connectionKeepAlive,
            options.seed, options.host,
        )
        check(handle != 0L) { "Failed to create HyperDHT instance" }
        Native.bind(handle, options.port)
    }

    /** DHT UDP port. */
    val port: Int get() = Native.port(handle)

    /** Default keypair. */
    val defaultKeyPair: KeyPair
        get() {
            val pk = ByteArray(32)
            val sk = ByteArray(64)
            // TODO: add Native.defaultKeypair(handle, pk, sk) JNI function
            return KeyPair(pk, sk)
        }

    // --- Lifecycle ---

    /** Start the libuv event loop on a background thread. */
    fun start(): Job {
        check(loopJob == null) { "Already started" }
        loopJob = scope.launch {
            while (isActive && !destroyed) {
                Native.loopRunOnce(loopHandle)
                yield()
            }
        }
        return loopJob!!
    }

    /** Stop the event loop and destroy the DHT instance. */
    override fun close() {
        if (destroyed) return
        destroyed = true
        scope.cancel()
        // Wait for the loop job to finish so we don't race with uv_run
        runBlocking { loopJob?.join() }
        Native.destroy(handle)
        // Drain remaining close callbacks
        while (Native.loopRunOnce(loopHandle) != 0) {}
        Native.free(handle)
        Native.loopClose(loopHandle)
        persistentRefs.clear()
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

    // --- Events (persistent callbacks — stored until close) ---

    suspend fun awaitBootstrapped(): Unit = suspendCancellableCoroutine { cont ->
        if (isBootstrapped) { cont.resume(Unit); return@suspendCancellableCoroutine }
        val id = cbIdGen.incrementAndGet()
        val cb = Runnable {
            persistentRefs.remove(id)
            if (cont.isActive) cont.resume(Unit)
        }
        persistentRefs[id] = cb
        Native.onBootstrapped(handle, cb)
    }

    fun onNetworkChange(callback: () -> Unit) {
        val id = cbIdGen.incrementAndGet()
        val cb = Runnable { callback() }
        persistentRefs[id] = cb
        Native.onNetworkChange(handle, cb)
    }

    fun onNetworkUpdate(callback: () -> Unit) {
        val id = cbIdGen.incrementAndGet()
        val cb = Runnable { callback() }
        persistentRefs[id] = cb
        Native.onNetworkUpdate(handle, cb)
    }

    // --- Connect ---

    /** Connect to a remote peer. Suspends until connection is established. */
    suspend fun connect(remotePublicKey: ByteArray): ConnectionInfo {
        require(remotePublicKey.size == 32) { "Public key must be 32 bytes" }
        return suspendCancellableCoroutine { cont ->
            val cb = ConnectCallback { error, connPtr ->
                if (!cont.isActive) return@ConnectCallback
                if (error != 0) cont.resumeWithException(DhtException(error))
                else cont.resume(ConnectionInfo(
                    ptr = connPtr,
                    remotePublicKey = remotePublicKey,
                    peerHost = "",
                    peerPort = 0,
                    isInitiator = true,
                ))
            }
            // One-shot: JNI GlobalRef prevents GC, freed in jni_connect_cb
            Native.connect(handle, remotePublicKey, cb)
        }
    }

    // --- Server ---

    fun createServer(): Server = Server(Native.serverCreate(handle), handle)

    // --- Stream ---

    fun openStream(connection: ConnectionInfo): Stream =
        Stream.open(handle, connection.ptr)

    // --- Storage ---

    suspend fun immutablePut(value: ByteArray): Unit =
        suspendCancellableCoroutine { cont ->
            val cb = DoneCallback { error ->
                if (!cont.isActive) return@DoneCallback
                if (error != 0) cont.resumeWithException(DhtException(error))
                else cont.resume(Unit)
            }
            Native.immutablePut(handle, value, cb)
        }

    suspend fun immutableGet(target: ByteArray): ByteArray? {
        require(target.size == 32) { "Target must be 32 bytes" }
        var result: ByteArray? = null
        suspendCancellableCoroutine { cont ->
            val valCb = ValueCallback { value -> result = value }
            val doneCb = DoneCallback { _ ->
                if (cont.isActive) cont.resume(Unit)
            }
            Native.immutableGet(handle, target, valCb, doneCb)
        }
        return result
    }

    suspend fun mutablePut(keyPair: KeyPair, value: ByteArray, seq: Long): Unit =
        suspendCancellableCoroutine { cont ->
            val cb = DoneCallback { error ->
                if (!cont.isActive) return@DoneCallback
                if (error != 0) cont.resumeWithException(DhtException(error))
                else cont.resume(Unit)
            }
            Native.mutablePut(handle, keyPair.publicKey, keyPair.secretKey,
                value, seq, cb)
        }

    // --- Utilities ---

    fun hash(data: ByteArray): ByteArray {
        val out = ByteArray(32)
        Native.hash(data, out)
        return out
    }

    fun addNode(host: String, port: Int) {
        val rc = Native.addNode(handle, host, port)
        if (rc != 0) throw DhtException(rc, "addNode failed: $rc")
    }

    suspend fun ping(host: String, port: Int): Boolean =
        suspendCancellableCoroutine { cont ->
            val cb = PingCallback { success ->
                if (cont.isActive) cont.resume(success)
            }
            Native.ping(handle, host, port, cb)
        }

    fun suspend() = Native.suspend(handle)
    fun resume() = Native.resume(handle)
}
