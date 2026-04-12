#!/usr/bin/env node
// ---------------------------------------------------------------------------
// hyperdht-cpp permanent test fixture
//
// A single long-running JS node that exposes three services for automated
// C++ cross-testing:
//
//   1. Echo server — accepts connections, echoes every message back.
//   2. Immutable storage — puts a known value at startup.
//   3. Mutable storage — puts a known signed value at startup.
//
// Deterministic keypair: derived from a shared seed so the C++ side knows
// the server pubkey without out-of-band coordination.
//
// Usage:
//   node test-fixture.js                      # default seed
//   FIXTURE_SEED=<64-hex> node test-fixture.js  # custom seed
//
// Designed to run permanently on:
//   - A VPS with a public static IP (firewall enabled, no open ports)
//   - A machine behind NAT
//
// Both scenarios exercise real holepunching. The fixture logs every
// event (handshake, connection, message, storage operations) with
// timestamps for diagnostic visibility.
// ---------------------------------------------------------------------------

'use strict'

const DHT = require('hyperdht')
const crypto = require('crypto')

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DEFAULT_SEED_HEX = crypto
  .createHash('sha256')
  .update('hyperdht-cpp-test-fixture-v1')
  .digest('hex')

const seedHex = process.env.FIXTURE_SEED || DEFAULT_SEED_HEX
const seed = Buffer.from(seedHex, 'hex')
if (seed.length !== 32) {
  console.error('FIXTURE_SEED must be 64 hex chars (32 bytes)')
  process.exit(1)
}

// Known test values for storage
const IMMUTABLE_VALUE = Buffer.from('hyperdht-cpp immutable test value v1')
const MUTABLE_VALUE = Buffer.from('hyperdht-cpp mutable test value v1')
const MUTABLE_SEQ = 1

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

function ts () {
  return new Date().toISOString()
}

function log (tag, ...args) {
  console.log(`[${ts()}] [${tag}]`, ...args)
}

function logHex (label, buf) {
  if (buf && buf.length > 0) {
    return `${label}=${buf.toString('hex').slice(0, 16)}...`
  }
  return `${label}=(empty)`
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

const stats = {
  started: new Date(),
  connections: 0,
  messagesEchoed: 0,
  bytesEchoed: 0,
  immutablePuts: 0,
  mutablePuts: 0,
  errors: 0
}

// Print stats every 30 seconds
setInterval(() => {
  const uptime = Math.floor((Date.now() - stats.started.getTime()) / 1000)
  log('stats',
    `uptime=${uptime}s`,
    `connections=${stats.connections}`,
    `echoed=${stats.messagesEchoed} msgs / ${stats.bytesEchoed} bytes`,
    `puts=(imm:${stats.immutablePuts} mut:${stats.mutablePuts})`,
    `errors=${stats.errors}`
  )
}, 30000).unref()

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main () {
  const keyPair = DHT.keyPair(seed)

  log('init', 'Fixture starting...')
  log('init', `seed       = ${seedHex}`)
  log('init', `public key = ${keyPair.publicKey.toString('hex')}`)

  // Create the DHT node
  const dht = new DHT()
  await dht.ready()

  const addr = dht.address()
  log('init', `DHT ready — bound to ${addr.host || '0.0.0.0'}:${addr.port}`)
  log('init', `DHT id     = ${dht.id ? dht.id.toString('hex').slice(0, 16) + '...' : '(not yet)'}`)
  log('init', `NAT host   = ${dht.host || '(unknown)'}`)
  log('init', `ephemeral  = ${dht.ephemeral}`)

  // Listen for persistent transition
  dht.once('persistent', () => {
    log('event', 'Node is now PERSISTENT (non-ephemeral)')
  })

  dht.on('network-change', () => {
    log('event', 'network-change — refreshing servers')
  })

  dht.on('network-update', () => {
    log('event', `network-update — online=${dht.online} degraded=${dht.degraded}`)
  })

  // -------------------------------------------------------------------
  // Service 1: Echo server
  // -------------------------------------------------------------------

  const server = dht.createServer({
    firewall (remotePublicKey, remotePayload, clientAddress) {
      log('handshake', `PEER_HANDSHAKE from ${remotePublicKey.toString('hex').slice(0, 16)}...`)
      log('handshake', `  client address = ${clientAddress.host}:${clientAddress.port}`)
      if (remotePayload) {
        log('handshake', `  version        = ${remotePayload.version || 'n/a'}`)
        log('handshake', `  firewall       = ${remotePayload.firewall}`)
        log('handshake', `  udx.id         = ${remotePayload.udx ? remotePayload.udx.id : 'n/a'}`)
        const addrs = remotePayload.addresses4 || []
        log('handshake', `  addresses4     = [${addrs.map(a => a.host + ':' + a.port).join(', ')}]`)
      }
      log('handshake', `  -> ACCEPT (firewall returns false)`)
      return false // accept all
    },
    holepunch (remoteFirewall, localFirewall, remoteAddresses, localAddresses) {
      log('holepunch', `HOLEPUNCH negotiation`)
      log('holepunch', `  remote firewall = ${remoteFirewall}`)
      log('holepunch', `  local firewall  = ${localFirewall}`)
      log('holepunch', `  remote addrs    = [${(remoteAddresses || []).map(a => a.host + ':' + a.port).join(', ')}]`)
      log('holepunch', `  local addrs     = [${(localAddresses || []).map(a => a.host + ':' + a.port).join(', ')}]`)
      log('holepunch', `  -> ALLOW (holepunch returns true)`)
      return true // allow all
    }
  }, (socket) => {
    stats.connections++
    const remotePk = socket.remotePublicKey.toString('hex')
    log('echo', `CONNECTION #${stats.connections} from ${remotePk.slice(0, 16)}...`)
    log('echo', `  handshake hash = ${socket.handshakeHash ? socket.handshakeHash.toString('hex').slice(0, 16) + '...' : 'n/a'}`)
    log('echo', `  initiator      = ${socket.isInitiator}`)
    log('echo', `  rawStream id   = ${socket.rawStream ? socket.rawStream.id : 'n/a'}`)

    socket.on('data', (data) => {
      stats.messagesEchoed++
      stats.bytesEchoed += data.length
      const preview = data.length <= 64
        ? data.toString('utf8')
        : data.toString('utf8').slice(0, 61) + '...'
      log('echo', `  RECV ${data.length} bytes from ${remotePk.slice(0, 8)}: "${preview}"`)

      // Echo it back
      socket.write(data)
      log('echo', `  SENT ${data.length} bytes (echo)`)
    })

    socket.on('end', () => {
      log('echo', `  END from ${remotePk.slice(0, 8)} — peer half-closed`)
      socket.end()
    })

    socket.on('close', () => {
      log('echo', `  CLOSE from ${remotePk.slice(0, 8)}`)
    })

    socket.on('error', (err) => {
      stats.errors++
      log('echo', `  ERROR from ${remotePk.slice(0, 8)}: ${err.message}`)
    })
  })

  await server.listen(keyPair)
  log('echo', `Server listening on ${keyPair.publicKey.toString('hex')}`)

  // -------------------------------------------------------------------
  // Service 2: Immutable storage
  // -------------------------------------------------------------------

  try {
    const immResult = await dht.immutablePut(IMMUTABLE_VALUE)
    stats.immutablePuts++
    log('storage', `Immutable PUT OK`)
    log('storage', `  hash  = ${immResult.hash.toString('hex')}`)
    log('storage', `  value = "${IMMUTABLE_VALUE.toString('utf8')}"`)
    log('storage', `  nodes = ${immResult.closestNodes.length}`)
  } catch (err) {
    stats.errors++
    log('storage', `Immutable PUT FAILED: ${err.message}`)
  }

  // -------------------------------------------------------------------
  // Service 3: Mutable storage
  // -------------------------------------------------------------------

  try {
    const mutResult = await dht.mutablePut(keyPair, MUTABLE_VALUE, {
      seq: MUTABLE_SEQ
    })
    stats.mutablePuts++
    log('storage', `Mutable PUT OK`)
    log('storage', `  pubkey    = ${keyPair.publicKey.toString('hex')}`)
    log('storage', `  seq       = ${MUTABLE_SEQ}`)
    log('storage', `  value     = "${MUTABLE_VALUE.toString('utf8')}"`)
    log('storage', `  signature = ${mutResult.signature.toString('hex').slice(0, 32)}...`)
    log('storage', `  nodes     = ${mutResult.closestNodes.length}`)
  } catch (err) {
    stats.errors++
    log('storage', `Mutable PUT FAILED: ${err.message}`)
  }

  // -------------------------------------------------------------------
  // Re-announce storage periodically (DHT entries expire after 20 min)
  // -------------------------------------------------------------------

  const REANNOUNCE_MS = 15 * 60 * 1000 // 15 minutes

  setInterval(async () => {
    log('storage', 'Re-announcing storage values...')

    try {
      await dht.immutablePut(IMMUTABLE_VALUE)
      stats.immutablePuts++
      log('storage', '  Immutable re-PUT OK')
    } catch (err) {
      stats.errors++
      log('storage', `  Immutable re-PUT FAILED: ${err.message}`)
    }

    try {
      // Bump seq on each re-announce so the value is always "latest"
      const seq = Math.floor(Date.now() / 1000)
      await dht.mutablePut(keyPair, MUTABLE_VALUE, { seq })
      stats.mutablePuts++
      log('storage', `  Mutable re-PUT OK (seq=${seq})`)
    } catch (err) {
      stats.errors++
      log('storage', `  Mutable re-PUT FAILED: ${err.message}`)
    }
  }, REANNOUNCE_MS).unref()

  // -------------------------------------------------------------------
  // Summary — printed after storage PUTs so we can include the hash
  // -------------------------------------------------------------------

  log('ready', '='.repeat(60))
  log('ready', 'FIXTURE READY — all services running')
  log('ready', '')
  log('ready', `  Echo server pubkey : ${keyPair.publicKey.toString('hex')}`)
  log('ready', `  Mutable pubkey     : ${keyPair.publicKey.toString('hex')}`)
  log('ready', `  Mutable seq        : ${MUTABLE_SEQ} (bumps on re-announce)`)
  log('ready', '')
  log('ready', '  Test from C++:')
  log('ready', `    SERVER_KEY=${keyPair.publicKey.toString('hex')} ./test_hyperdht --gtest_filter='*LiveConnect*'`)
  log('ready', '')
  log('ready', `  Or from another JS node:`)
  log('ready', `    const dht = new (require('hyperdht'))()`)
  log('ready', `    const socket = dht.connect(Buffer.from('${keyPair.publicKey.toString('hex')}', 'hex'))`)
  log('ready', `    socket.write('hello')`)
  log('ready', `    socket.on('data', d => console.log('echo:', d.toString()))`)
  log('ready', '='.repeat(60))

  // -------------------------------------------------------------------
  // Graceful shutdown
  // -------------------------------------------------------------------

  let shuttingDown = false

  async function shutdown (signal) {
    if (shuttingDown) return
    shuttingDown = true
    log('shutdown', `Received ${signal}, shutting down...`)

    try {
      await server.close()
      log('shutdown', 'Server closed')
    } catch (err) {
      log('shutdown', `Server close error: ${err.message}`)
    }

    try {
      await dht.destroy()
      log('shutdown', 'DHT destroyed')
    } catch (err) {
      log('shutdown', `DHT destroy error: ${err.message}`)
    }

    log('shutdown', `Final stats: ${JSON.stringify(stats)}`)
    process.exit(0)
  }

  process.on('SIGINT', () => shutdown('SIGINT'))
  process.on('SIGTERM', () => shutdown('SIGTERM'))

  // Keep alive
  process.on('uncaughtException', (err) => {
    stats.errors++
    log('FATAL', `Uncaught exception: ${err.stack || err.message}`)
    // Don't exit — try to keep running
  })

  process.on('unhandledRejection', (reason) => {
    stats.errors++
    log('FATAL', `Unhandled rejection: ${reason}`)
    // Don't exit — try to keep running
  })
}

main().catch((err) => {
  log('FATAL', `Startup failed: ${err.stack || err.message}`)
  process.exit(1)
})
