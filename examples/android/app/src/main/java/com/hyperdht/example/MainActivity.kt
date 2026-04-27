package com.hyperdht.example

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import com.hyperdht.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first

private const val TAG = "EchoTest"

/**
 * HyperDHT P2P echo test — connects to a remote C++ echo server over
 * the public DHT network, sends a message, displays the echo.
 */
class MainActivity : Activity() {

    private val serverKeyHex =
        "b7c5c4e909ad28e2071c48a09f330ec2735248a4e4d8759032a9b57b0f2e7aec"

    private lateinit var statusText: TextView
    private lateinit var logText: TextView
    private lateinit var messageInput: EditText
    private lateinit var connectButton: Button

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var dht: HyperDHT? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        logText = findViewById(R.id.logText)
        messageInput = findViewById(R.id.messageInput)
        connectButton = findViewById(R.id.connectButton)

        connectButton.setOnClickListener { runEchoTest() }
    }

    private fun runEchoTest() {
        connectButton.isEnabled = false
        statusText.text = "Starting..."
        logText.text = ""

        scope.launch {
            try {
                log("Creating DHT node...")
                statusText.text = "Bootstrapping..."

                // HyperDHT runs all native calls on its own dedicated thread
                dht = HyperDHT(DhtOptions(usePublicBootstrap = true))
                dht!!.start()

                log("DHT port: ${dht!!.port}")
                log("Waiting for bootstrap...")

                dht!!.awaitBootstrapped()
                log("Bootstrapped!")
                statusText.text = "Connecting..."

                val serverKey = hexToBytes(serverKeyHex)
                log("Connecting to ${serverKeyHex.take(16)}...")

                val stream = dht!!.connect(serverKey)
                Log.d(TAG, "connect() returned, stream handle set")
                log("Connected! Waiting for stream open...")

                stream.awaitOpen()
                Log.d(TAG, "awaitOpen() returned")
                log("Stream open! Sending...")

                val message = messageInput.text.toString()
                val writeRc = stream.write(message.toByteArray())
                Log.d(TAG, "write() returned rc=$writeRc")
                log("Sent: $message (rc=$writeRc)")

                statusText.text = "Waiting for echo..."
                Log.d(TAG, "waiting for stream.data.first() with 10s timeout")

                val echo = withTimeoutOrNull(10000) {
                    stream.data.first()
                }

                Log.d(TAG, "echo result: ${echo?.size ?: "null"} bytes")

                if (echo != null) {
                    val echoStr = String(echo)
                    log("Echo: $echoStr")
                    statusText.text = if (echoStr == message) "Echo OK!" else "Echo mismatch!"
                } else {
                    log("Timeout waiting for echo")
                    Log.w(TAG, "TIMEOUT: no data received in 10s. stream.isOpen=${stream.isOpen}")
                    statusText.text = "Timeout"
                }

                stream.close()
                log("Done!")

            } catch (e: DhtException) {
                log("DHT error ${e.code}: ${e.message}")
                statusText.text = "Error: ${e.message}"
            } catch (e: Exception) {
                log("Error: ${e.javaClass.simpleName}: ${e.message}")
                statusText.text = "Error: ${e.message}"
            } finally {
                connectButton.isEnabled = true
                // Close on a background thread — runBlocking in dht.close()
                // blocks the calling thread, which freezes the UI if called
                // from Dispatchers.Main.
                val d = dht
                dht = null
                if (d != null) {
                    @Suppress("OPT_IN_USAGE")
                    GlobalScope.launch(Dispatchers.IO) {
                        try { d.close() } catch (_: Exception) {}
                    }
                }
            }
        }
    }

    private fun log(msg: String) {
        runOnUiThread {
            logText.append("$msg\n")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
        try { dht?.close() } catch (_: Exception) {}
    }

    companion object {
        private fun hexToBytes(hex: String): ByteArray {
            val bytes = ByteArray(hex.length / 2)
            for (i in bytes.indices) {
                bytes[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
            return bytes
        }
    }
}
