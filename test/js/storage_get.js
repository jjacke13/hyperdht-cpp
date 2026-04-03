#!/usr/bin/env node

// Get values from the DHT that were put by C++.
// Usage: node storage_get.js <immutable_hash> [mutable_pubkey]

const HyperDHT = require('hyperdht')

async function main () {
  const args = process.argv.slice(2)
  if (args.length < 1) {
    console.log('Usage: node storage_get.js <immutable_hash> [mutable_pubkey]')
    process.exit(1)
  }

  const dht = new HyperDHT()
  await dht.ready()
  console.log('DHT ready')

  // --- Immutable Get ---
  const hash = Buffer.from(args[0], 'hex')
  console.log('Immutable GET for hash:', hash.toString('hex').slice(0, 16) + '...')
  const igot = await dht.immutableGet(hash)
  if (igot && igot.value) {
    console.log('  GOT:', igot.value.toString())
  } else {
    console.log('  NOT FOUND')
  }

  // --- Mutable Get ---
  if (args[1]) {
    const pubkey = Buffer.from(args[1], 'hex')
    console.log('Mutable GET for pubkey:', pubkey.toString('hex').slice(0, 16) + '...')
    const mgot = await dht.mutableGet(pubkey)
    if (mgot && mgot.value) {
      console.log('  GOT seq:', mgot.seq, 'value:', mgot.value.toString())
    } else {
      console.log('  NOT FOUND')
    }
  }

  dht.destroy()
}

main().catch(console.error)
