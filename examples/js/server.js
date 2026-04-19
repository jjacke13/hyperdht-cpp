#!/usr/bin/env node
/**
 * Persistent HyperDHT server — accepts connections and echoes data.
 *
 * Usage:
 *   node server.js                    # random keypair
 *   node server.js <64-hex-seed>      # deterministic identity
 */

const HyperDHT = require('hyperdht')

async function main () {
  const seedHex = process.argv[2]
  const seed = seedHex ? Buffer.from(seedHex, 'hex') : undefined

  const dht = new HyperDHT()
  await dht.ready()

  const keyPair = seed
    ? HyperDHT.keyPair(seed)
    : HyperDHT.keyPair()

  const server = dht.createServer(socket => {
    const key = socket.remotePublicKey.toString('hex').slice(0, 16)
    console.log(`Connection from ${key}...`)

    socket.on('data', data => {
      console.log(`  Received ${data.length} bytes, echoing back`)
      socket.write(data)
    })

    socket.on('close', () => {
      console.log(`  Closed ${key}...`)
    })

    socket.on('error', err => {
      console.error(`  Error: ${err.message}`)
    })
  })

  await server.listen(keyPair)

  console.log(`DHT port: ${dht.port}`)
  console.log(`Public key: ${keyPair.publicKey.toString('hex')}`)
  console.log()
  console.log('Listening... (Ctrl+C to stop)')
  console.log()
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
