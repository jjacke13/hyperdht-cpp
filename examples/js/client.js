#!/usr/bin/env node
/**
 * HyperDHT client — connects to a server, sends a message, prints the echo.
 *
 * Usage:
 *   node client.js <64-hex-public-key>
 */

const HyperDHT = require('hyperdht')

async function main () {
  const pkHex = process.argv[2]
  if (!pkHex || pkHex.length !== 64) {
    console.error('Usage: node client.js <64-hex-public-key>')
    process.exit(1)
  }

  const remoteKey = Buffer.from(pkHex, 'hex')

  const dht = new HyperDHT()
  await dht.ready()

  console.log(`Connecting to ${pkHex.slice(0, 16)}...`)

  const socket = dht.connect(remoteKey)

  socket.on('open', () => {
    console.log(`Connected to ${socket.rawStream.remoteHost}:${socket.rawStream.remotePort}`)
    console.log('  Sending: hello from JS')
    socket.write(Buffer.from('hello from JS'))
  })

  socket.on('data', data => {
    console.log(`  Received: ${data.toString()}`)
  })

  socket.on('close', () => {
    console.log('  Closed')
    dht.destroy()
  })

  socket.on('error', err => {
    console.error(`  Error: ${err.message}`)
    dht.destroy()
  })
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
