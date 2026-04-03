#!/usr/bin/env node

// Test: can we find the C++ server's announcement on the DHT?
// Usage: node findpeer_test.js
//
// If this prints peer records, the announcement is working.
// If it prints "no peers found", the announcement is broken.

const HyperDHT = require('hyperdht')

const SERVER_KEY = Buffer.from(
  '2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12',
  'hex'
)

async function main () {
  const dht = new HyperDHT()

  console.log('Looking for:', SERVER_KEY.toString('hex').slice(0, 16) + '...')
  console.log('Target hash:', HyperDHT.hash(SERVER_KEY).toString('hex').slice(0, 16) + '...')
  console.log()

  let found = 0

  const query = dht.findPeer(SERVER_KEY)

  for await (const peer of query) {
    found++
    console.log('Found peer #' + found + ':')
    console.log('  from:', peer.from.host + ':' + peer.from.port)
    if (peer.peer) {
      console.log('  peer.publicKey:', peer.peer.publicKey.toString('hex').slice(0, 16) + '...')
      console.log('  peer.relayAddresses:', peer.peer.relayAddresses.length)
      for (const addr of peer.peer.relayAddresses) {
        console.log('    relay:', addr.host + ':' + addr.port)
      }
    } else {
      console.log('  peer: null (raw value:', peer.value ? peer.value.length + ' bytes' : 'none', ')')
    }
    console.log()
  }

  if (found === 0) {
    console.log('NO PEERS FOUND — announcement not visible on DHT')
  } else {
    console.log('Found', found, 'peer(s) total')
  }

  await dht.destroy()
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
