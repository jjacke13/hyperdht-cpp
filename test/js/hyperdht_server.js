#!/usr/bin/env node

/**
 * Minimal HyperDHT server for testing PEER_HANDSHAKE.
 * Listens on a keypair and accepts all connections (no firewall).
 * Prints PORT and PUBKEY on stdout for the C++ client.
 */

const DHT = require('/home/jacke/Desktop/repos/hyperdht-cpp/.analysis/js/hyperdht')

async function main () {
  const dht = new DHT({ bootstrap: [] })
  await dht.ready()

  const server = dht.createServer(function (socket) {
    process.stderr.write('Connection from: ' + socket.remotePublicKey.toString('hex') + '\n')
    socket.on('data', (d) => process.stderr.write('Data: ' + d.toString() + '\n'))
    socket.on('error', () => {})
    socket.end()
  })

  // No firewall — accept everything
  server.on('connection', () => {})

  const keyPair = DHT.keyPair(Buffer.alloc(32, 0xBB))
  await server.listen(keyPair)

  const addr = dht.address()
  process.stdout.write('PORT:' + addr.port + '\n')
  process.stdout.write('PUBKEY:' + keyPair.publicKey.toString('hex') + '\n')
  process.stderr.write('HyperDHT server listening on port ' + addr.port + '\n')
  process.stderr.write('Public key: ' + keyPair.publicKey.toString('hex') + '\n')

  setTimeout(() => {
    process.stderr.write('Server timeout\n')
    server.close().then(() => dht.destroy()).then(() => process.exit(0))
  }, 15000).unref()
}

main().catch((err) => {
  process.stderr.write('ERROR: ' + err.message + '\n' + err.stack + '\n')
  process.exit(1)
})
