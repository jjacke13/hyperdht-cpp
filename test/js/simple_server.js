#!/usr/bin/env node

const HyperDHT = require('hyperdht')

async function main () {
  const dht = new HyperDHT()
  const server = dht.createServer()

  server.on('connection', (socket) => {
    console.log('Client connected!')
    console.log('  Remote key:', socket.remotePublicKey.toString('hex').slice(0, 16) + '...')
    socket.on('close', () => console.log('  Client disconnected'))
  })

  await server.listen()

  console.log('Server listening')
  console.log('Public key:', server.publicKey.toString('hex'))
  console.log('Ctrl+C to stop')
}

main().catch(console.error)
