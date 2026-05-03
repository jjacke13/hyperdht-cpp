package com.hyperdht

/**
 * JNI native method declarations — thin bridge to the C FFI.
 *
 * All methods map 1:1 to hyperdht_* C functions. Opaque pointers are
 * passed as Long (jlong in JNI). Callbacks are Java functional interfaces
 * invoked from the libuv event loop thread.
 */
internal object Native {
    init { System.loadLibrary("hyperdht_jni") }

    // --- libuv loop ---
    external fun loopCreate(): Long
    external fun loopRunOnce(loopPtr: Long): Int
    external fun loopRunNowait(loopPtr: Long): Int
    external fun loopClose(loopPtr: Long)

    // --- Async wakeup (thread-safe uv_run kick) ---
    external fun asyncCreate(loopPtr: Long): Long
    external fun asyncSend(asyncPtr: Long)
    external fun asyncClose(asyncPtr: Long)

    // --- Keypair ---
    external fun keypairGenerate(pk: ByteArray, sk: ByteArray)
    external fun keypairFromSeed(seed: ByteArray, pk: ByteArray, sk: ByteArray)

    // --- Lifecycle ---
    external fun create(
        loopPtr: Long, port: Int, ephemeral: Boolean,
        usePublicBootstrap: Boolean, connectionKeepAlive: Int,
        seed: ByteArray?, host: String?,
    ): Long
    external fun bind(handle: Long, port: Int): Int
    external fun port(handle: Long): Int
    /**
     * Native UDP socket fds (for VpnService.protect() on Android, or any
     * other case where the application needs to mark the DHT's sockets as
     * bypassing a tunnel).  POSIX-only.  Returns -1 if the socket isn't
     * bound or on Windows.
     */
    external fun clientSocketFd(handle: Long): Int
    external fun serverSocketFd(handle: Long): Int
    external fun destroy(handle: Long)
    external fun destroyForce(handle: Long)
    external fun free(handle: Long)
    external fun isDestroyed(handle: Long): Boolean

    // --- State ---
    external fun isOnline(handle: Long): Boolean
    external fun isDegraded(handle: Long): Boolean
    external fun isPersistent(handle: Long): Boolean
    external fun isBootstrapped(handle: Long): Boolean
    external fun isSuspended(handle: Long): Boolean
    external fun remoteAddress(handle: Long, out: Array<String?>): Boolean

    // --- Events ---
    external fun onBootstrapped(handle: Long, callback: Runnable)
    external fun onNetworkChange(handle: Long, callback: Runnable)
    external fun onNetworkUpdate(handle: Long, callback: Runnable)
    external fun onPersistent(handle: Long, callback: Runnable)

    // --- Connect ---
    external fun connect(handle: Long, publicKey: ByteArray, callback: ConnectCallback): Int
    external fun connectAndOpenStream(
        handle: Long, publicKey: ByteArray,
        onOpen: Runnable, onData: DataCallback, onClose: Runnable,
        callback: ConnectCallback,
    ): Int
    external fun connectionFree(ptr: Long)  // legacy — no longer used
    external fun connectEx(
        handle: Long, publicKey: ByteArray,
        keypairPk: ByteArray?, keypairSk: ByteArray?,
        relayThrough: ByteArray?, fastOpen: Boolean, localConnection: Boolean,
        callback: ConnectCallback,
    ): Int

    // --- Server ---
    external fun serverCreate(handle: Long): Long
    external fun serverListen(
        serverHandle: Long, pk: ByteArray, sk: ByteArray,
        callback: ConnectionCallback,
    ): Int
    external fun serverClose(serverHandle: Long, callback: Runnable?)
    external fun serverCloseForce(serverHandle: Long, callback: Runnable?)
    external fun serverSetFirewall(serverHandle: Long, callback: FirewallCallback)
    external fun serverSetFirewallAsync(serverHandle: Long, callback: FirewallAsyncCallback)
    external fun serverRefresh(serverHandle: Long)
    external fun serverIsListening(serverHandle: Long): Boolean
    external fun serverPublicKey(serverHandle: Long, out: ByteArray): Boolean
    external fun serverOnListening(serverHandle: Long, callback: Runnable)
    external fun serverSuspend(serverHandle: Long)
    external fun serverResume(serverHandle: Long)

    // --- Stream ---
    external fun streamOpen(
        dhtHandle: Long, connPtr: Long,
        onOpen: Runnable?, onData: DataCallback?, onClose: Runnable?,
    ): Long
    external fun streamWrite(streamHandle: Long, data: ByteArray): Int
    external fun streamWriteWithDrain(
        streamHandle: Long, data: ByteArray, onDrain: Runnable?,
    ): Int
    external fun streamClose(streamHandle: Long)
    external fun streamIsOpen(streamHandle: Long): Boolean

    // --- Storage ---
    external fun immutablePut(handle: Long, value: ByteArray, callback: DoneCallback): Int
    external fun immutableGet(
        handle: Long, target: ByteArray,
        onValue: ValueCallback?, onDone: DoneCallback?,
    ): Int
    external fun mutablePut(
        handle: Long, pk: ByteArray, sk: ByteArray,
        value: ByteArray, seq: Long, callback: DoneCallback,
    ): Int
    external fun mutableGet(
        handle: Long, publicKey: ByteArray, minSeq: Long,
        onValue: MutableValueCallback?, onDone: DoneCallback?,
    ): Int

    // --- Queries ---
    external fun findPeer(
        handle: Long, publicKey: ByteArray,
        onReply: PeerCallback?, onDone: DoneCallback?,
    ): Int
    external fun lookup(
        handle: Long, target: ByteArray,
        onReply: PeerCallback?, onDone: DoneCallback?,
    ): Int
    external fun announce(
        handle: Long, target: ByteArray, value: ByteArray,
        onDone: DoneCallback?,
    ): Int
    external fun unannounce(
        handle: Long, publicKey: ByteArray, pk: ByteArray, sk: ByteArray,
        onDone: DoneCallback?,
    ): Int

    // --- Misc ---
    external fun connectStrerror(error: Int): String
    external fun hash(data: ByteArray, out: ByteArray)
    external fun addNode(handle: Long, host: String, port: Int): Int
    external fun ping(handle: Long, host: String, port: Int, callback: PingCallback): Int

    // --- Poll ---
    external fun pollStart(
        handle: Long, fd: Int, events: Int, callback: PollCallback,
    ): Long
    external fun pollStop(pollHandle: Long)

    // --- Stats ---
    external fun punchStatsConsistent(handle: Long): Int
    external fun punchStatsRandom(handle: Long): Int
    external fun punchStatsOpen(handle: Long): Int
    external fun relayStatsAttempts(handle: Long): Int
    external fun relayStatsSuccesses(handle: Long): Int
    external fun relayStatsAborts(handle: Long): Int

    // --- Suspend/Resume ---
    external fun suspend(handle: Long)
    external fun resume(handle: Long)
}

// Callback interfaces for JNI
fun interface ConnectCallback { fun onResult(error: Int, connPtr: Long) }
fun interface ConnectionCallback { fun onConnection(connPtr: Long) }
fun interface FirewallCallback { fun onFirewall(pk: ByteArray, host: String, port: Int): Boolean }
fun interface FirewallAsyncCallback {
    fun onFirewall(pk: ByteArray, host: String, port: Int, doneHandle: Long)
}
fun interface DataCallback { fun onData(data: ByteArray) }
fun interface ValueCallback { fun onValue(value: ByteArray) }
fun interface MutableValueCallback { fun onValue(seq: Long, value: ByteArray, sig: ByteArray) }
fun interface DoneCallback { fun onDone(error: Int) }
fun interface PeerCallback { fun onPeer(value: ByteArray, host: String, port: Int) }
fun interface PingCallback { fun onResult(success: Boolean) }
fun interface PollCallback { fun onPoll(fd: Int, events: Int) }
