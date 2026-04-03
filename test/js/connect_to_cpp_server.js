#!/usr/bin/env node

// JS client that connects to the C++ HyperDHT server — debug version.
// Usage: node connect_to_cpp_server.js

const HyperDHT = require('hyperdht')

const SERVER_KEY = Buffer.from(
  '2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12',
  'hex'
)

async function main () {
  console.log('Creating DHT node...')
  const dht = new HyperDHT()

  await dht.ready()
  console.log('DHT ready, our key:', dht.defaultKeyPair.publicKey.toString('hex').slice(0, 16) + '...')
  console.log('Firewalled:', dht.firewalled)
  console.log()

  console.log('Connecting to C++ server:', SERVER_KEY.toString('hex').slice(0, 16) + '...')

  const socket = dht.connect(SERVER_KEY)

  socket.on('open', () => {
    console.log('CONNECTED!')
    console.log('  Remote public key:', socket.remotePublicKey.toString('hex').slice(0, 16) + '...')
    console.log('  Is initiator:', socket.isInitiator)

    setTimeout(() => {
      console.log('  Closing...')
      socket.destroy()
      dht.destroy()
      console.log('DONE')
    }, 2000)
  })

  socket.on('error', (err) => {
    console.error('Connection error:', err.message)
    console.error('  Code:', err.code)
    dht.destroy()
    process.exit(1)
  })

  socket.on('close', () => {
    console.log('Socket closed')
  })

  // Debug: raw stream events
  if (socket.rawStream) {
    socket.rawStream.on('connect', () => {
      console.log('  [raw] stream connected')
    })
    socket.rawStream.on('error', (err) => {
      console.log('  [raw] stream error:', err.message)
    })
    socket.rawStream.on('close', () => {
      console.log('  [raw] stream closed')
    })
  }

  // Debug: noise handshake events
  socket.on('handshake', () => {
    console.log('  [noise] handshake complete')
    console.log('  [noise] remote key:', socket.remotePublicKey?.toString('hex').slice(0, 16) + '...')
  })

  // Poll connection state
  const start = Date.now()
  const interval = setInterval(() => {
    const elapsed = ((Date.now() - start) / 1000).toFixed(1)
    const state = {
      connected: socket.connected,
      destroyed: socket.destroyed,
      opened: socket.opened,
      rawConnected: socket.rawStream?.connected,
      rawDestroyed: socket.rawStream?.destroyed
    }
    console.log(`  [${elapsed}s] state:`, JSON.stringify(state))
  }, 3000)

  // Timeout after 60 seconds
  setTimeout(() => {
    clearInterval(interval)
    console.error('TIMEOUT — could not connect within 60s')
    socket.destroy()
    dht.destroy()
    process.exit(1)
  }, 60000)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
