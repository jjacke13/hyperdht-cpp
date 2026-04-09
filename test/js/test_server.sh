#!/bin/bash
# Start a simple JS HyperDHT server for testing C++ client connections.
# Usage: ./test/js/test_server.sh
# Then run: SERVER_KEY=<key> ./build/test_live_connect

cd "$(dirname "$0")" && node -e "
const DHT = require('hyperdht')
const dht = new DHT()
const server = dht.createServer(socket => {
  console.log('CONNECTED by', socket.remotePublicKey.toString('hex').slice(0,16) + '...')
  socket.on('data', d => console.log('DATA:', d.toString()))
  socket.end('hello from JS server')
  setTimeout(() => process.exit(0), 3000)
})
server.listen().then(() => {
  console.log('PUBLIC_KEY=' + server.publicKey.toString('hex'))
  console.log('LISTENING')
})
"
