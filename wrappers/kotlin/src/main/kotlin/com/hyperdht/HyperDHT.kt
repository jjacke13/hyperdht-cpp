package com.hyperdht

import kotlinx.coroutines.*
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.Closeable
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * HyperDHT node — connect to peers, listen for connections, store data.
 *
 * Usage:
 * ```kotlin
 * val dht = HyperDHT(usePublicBootstrap = true)
 * dht.start()  // starts the event loop
 *
 * // Client
 * val conn = dht.connect(serverPublicKey)
 * val stream = dht.openStream(conn)
 * stream.awaitOpen()
 * stream.write("hello".toByteArray())
 *
 * // Server
 * val server = dht.createServer()
 * server.listen(keyPair).collect { conn ->
 *     val stream = server.openStream(conn)
 *     // handle connection
 * }
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
    private var destroyed = false

    // prevent GC of callback objects passed to JNI
    private val callbackRefs = mutableListOf<Any>()

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

    /** Default keypair (derived from seed or random). */
    val defaultKeyPair: KeyPair
        get() {
            val pk = ByteArray(32)
            val sk = ByteArray(64)
            // JNI fills pk/sk from hyperdht_default_keypair
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
        Native.destroy(handle)
        // Drain remaining callbacks
        while (Native.loopRunOnce(loopHandle) != 0) {}
        Native.free(handle)
        Native.loopClose(loopHandle)
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

    /** Suspend until bootstrap walk completes. */
    suspend fun awaitBootstrapped(): Unit = suspendCancellableCoroutine { cont ->
        if (isBootstrapped) { cont.resume(Unit); return@suspendCancellableCoroutine }
        val cb = Runnable { cont.resume(Unit) }
        callbackRefs.add(cb)
        Native.onBootstrapped(handle, cb)
    }

    fun onNetworkChange(callback: () -> Unit) {
        val cb = Runnable { callback() }
        callbackRefs.add(cb)
        Native.onNetworkChange(handle, cb)
    }

    fun onNetworkUpdate(callback: () -> Unit) {
        val cb = Runnable { callback() }
        callbackRefs.add(cb)
        Native.onNetworkUpdate(handle, cb)
    }

    // --- Connect ---

    /** Connect to a remote peer. Suspends until connection is established. */
    suspend fun connect(remotePublicKey: ByteArray): ConnectionInfo {
        require(remotePublicKey.size == 32) { "Public key must be 32 bytes" }
        return suspendCancellableCoroutine { cont ->
            val cb = ConnectCallback { error, connPtr ->
                if (error != 0) cont.resumeWithException(DhtException(error))
                else cont.resume(ConnectionInfo(
                    ptr = connPtr,
                    remotePublicKey = remotePublicKey,
                    peerHost = "", // filled by JNI
                    peerPort = 0,
                    isInitiator = true,
                ))
            }
            callbackRefs.add(cb)
            Native.connect(handle, remotePublicKey, cb)
        }
    }

    // --- Server ---

    /** Create a server instance. */
    fun createServer(): Server = Server(Native.serverCreate(handle), handle)

    // --- Stream ---

    /** Open an encrypted stream over a connection. */
    fun openStream(connection: ConnectionInfo): Stream =
        Stream.open(handle, connection.ptr)

    // --- Storage ---

    /** Store an immutable value. Returns when stored on the DHT. */
    suspend fun immutablePut(value: ByteArray): Unit =
        suspendCancellableCoroutine { cont ->
            val cb = DoneCallback { error ->
                if (error != 0) cont.resumeWithException(DhtException(error))
                else cont.resume(Unit)
            }
            callbackRefs.add(cb)
            Native.immutablePut(handle, value, cb)
        }

    /** Retrieve an immutable value by hash. */
    suspend fun immutableGet(target: ByteArray): ByteArray? {
        require(target.size == 32) { "Target must be 32 bytes" }
        var result: ByteArray? = null
        suspendCancellableCoroutine { cont ->
            val valCb = ValueCallback { value -> result = value }
            val doneCb = DoneCallback { _ -> cont.resume(Unit) }
            callbackRefs.addAll(listOf(valCb, doneCb))
            Native.immutableGet(handle, target, valCb, doneCb)
        }
        return result
    }

    /** Store a signed mutable value. */
    suspend fun mutablePut(keyPair: KeyPair, value: ByteArray, seq: Long): Unit =
        suspendCancellableCoroutine { cont ->
            val cb = DoneCallback { error ->
                if (error != 0) cont.resumeWithException(DhtException(error))
                else cont.resume(Unit)
            }
            callbackRefs.add(cb)
            Native.mutablePut(handle, keyPair.publicKey, keyPair.secretKey,
                value, seq, cb)
        }

    // --- Utilities ---

    /** BLAKE2b-256 hash. */
    fun hash(data: ByteArray): ByteArray {
        val out = ByteArray(32)
        Native.hash(data, out)
        return out
    }

    /** Add a node to the routing table. */
    fun addNode(host: String, port: Int) {
        val rc = Native.addNode(handle, host, port)
        if (rc != 0) throw DhtException(rc, "addNode failed: $rc")
    }

    /** Ping a peer directly. */
    suspend fun ping(host: String, port: Int): Boolean =
        suspendCancellableCoroutine { cont ->
            val cb = PingCallback { success -> cont.resume(success) }
            callbackRefs.add(cb)
            Native.ping(handle, host, port, cb)
        }

    /** Suspend the DHT. */
    fun suspend() = Native.suspend(handle)

    /** Resume the DHT. */
    fun resume() = Native.resume(handle)
}
