#!/usr/bin/env node
// Test whether a specific C++ DHT node responds to protocol queries.
// Usage: node test_node_queries.js <64-char-hex-pubkey>

const DHT = require('hyperdht')
const crypto = require('hypercore-crypto')

const SERVER_KEY = Buffer.from(
  process.argv[2] || 'b7c5c4e909ad28e2071c48a09f330ec2735248a4e4d8759032a9b57b0f2e7aec',
  'hex'
)

async function main () {
  const dht = new DHT()
  await dht.ready()

  console.log('Our node ID:', dht.id?.toString('hex') || '(ephemeral)')
  console.log('Testing server:', SERVER_KEY.toString('hex'))
  console.log()

  // 1. FIND_PEER — does the network know about this server?
  console.log('--- FIND_PEER (lookup on server key) ---')
  let found = false
  const target = crypto.discoveryKey(SERVER_KEY)
  for await (const data of dht.findPeer(SERVER_KEY)) {
    console.log('  Response from:', data.from?.host + ':' + data.from?.port)
    if (data.peer) {
      console.log('  FOUND peer:', {
        publicKey: data.peer.publicKey?.toString('hex')?.slice(0, 16) + '...',
        relayAddresses: data.peer.relayAddresses?.map(a => a.host + ':' + a.port)
      })
      found = true
    }
    if (data.closerNodes?.length) {
      console.log('  closerNodes:', data.closerNodes.length)
    }
  }
  console.log('  Result:', found ? 'FOUND on the DHT' : 'NOT FOUND')
  console.log()

  // 2. LOOKUP — what does the network store for a random key?
  //    This exercises other nodes' LOOKUP handlers.
  console.log('--- LOOKUP (random key, exercises storage handlers) ---')
  const randomKey = crypto.randomBytes(32)
  let lookupResponses = 0
  for await (const data of dht.lookup(randomKey)) {
    lookupResponses++
    if (lookupResponses <= 3) {
      console.log('  Response from:', data.from?.host + ':' + data.from?.port,
        '| closerNodes:', data.closerNodes?.length || 0,
        '| peers:', data.peers?.length || 0)
    }
  }
  console.log('  Total responses:', lookupResponses)
  console.log()

  // 3. Try connecting to the server — full PEER_HANDSHAKE
  console.log('--- PEER_HANDSHAKE (connect to server) ---')
  try {
    const socket = dht.connect(SERVER_KEY)
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.destroy()
        reject(new Error('timeout after 15s'))
      }, 15000)
      socket.on('open', () => {
        clearTimeout(timer)
        console.log('  Connected! Remote key:', socket.remotePublicKey?.toString('hex')?.slice(0, 16) + '...')

        // Send a test message
        socket.write(Buffer.from('hello from JS test'))
        socket.once('data', (data) => {
          console.log('  Echo received:', data.toString())
          socket.end()
          resolve()
        })
      })
      socket.on('error', (err) => {
        clearTimeout(timer)
        reject(err)
      })
    })
    console.log('  Result: CONNECTED + ECHO WORKS')
  } catch (err) {
    console.log('  Result: FAILED -', err.message)
  }

  console.log()
  console.log('--- Summary ---')
  console.log('Routing table size:', dht.table?.count || 0)
  console.log('Server announced:', found ? 'YES' : 'NO')

  await dht.destroy()
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
