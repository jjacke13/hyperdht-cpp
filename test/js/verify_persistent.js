const DHT = require('hyperdht')
const crypto = require('crypto')

const SERVER_KEY = Buffer.from('b7c5c4e909ad28e2071c48a09f330ec2735248a4e4d8759032a9b57b0f2e7aec', 'hex')

async function main() {
  const dht = new DHT()
  await dht.ready()
  console.log('DHT ready, our port:', dht.port)

  // Test 1: findPeer — does the network know about the server?
  console.log('\n--- Test 1: findPeer (is the server announced?) ---')
  let found = false
  for await (const data of dht.findPeer(SERVER_KEY)) {
    console.log('  Found peer:', data.peer?.publicKey?.toString('hex')?.slice(0, 16) + '...')
    if (data.peer?.relayAddresses) {
      for (const r of data.peer.relayAddresses) {
        console.log('    relay:', r.host + ':' + r.port)
      }
    }
    found = true
  }
  if (!found) console.log('  NOT FOUND on DHT')

  // Test 2: connect — can we actually reach it?
  console.log('\n--- Test 2: connect + echo ---')
  try {
    const socket = dht.connect(SERVER_KEY)
    socket.on('open', () => {
      console.log('  Stream open, sending hello...')
      socket.write(Buffer.from('verify from JS'))
    })
    socket.on('data', (data) => {
      console.log('  Echo received:', data.toString())
      socket.end()
    })
    socket.on('close', () => {
      console.log('  Stream closed')
      console.log('\nAll tests done.')
      dht.destroy()
    })
    socket.on('error', (err) => {
      console.log('  Connect error:', err.message)
      dht.destroy()
    })
  } catch (e) {
    console.log('  Connect failed:', e.message)
    dht.destroy()
  }
}

main().catch(err => {
  console.error('Fatal:', err)
  process.exit(1)
})

setTimeout(() => {
  console.log('\nTimeout — exiting')
  process.exit(0)
}, 30000)
