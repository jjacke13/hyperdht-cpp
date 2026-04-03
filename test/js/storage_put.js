#!/usr/bin/env node

// Put values on the DHT for cross-testing with C++.
// Usage: node storage_put.js

const HyperDHT = require('hyperdht')
const crypto = require('hypercore-crypto')

async function main () {
  const dht = new HyperDHT()
  await dht.ready()
  console.log('DHT ready')

  // --- Immutable Put ---
  const immutableValue = Buffer.from('hello from JS')
  const { hash } = await dht.immutablePut(immutableValue)
  console.log('Immutable PUT done')
  console.log('  hash:', hash.toString('hex'))
  console.log('  value:', immutableValue.toString())

  // Verify we can get it back
  const got = await dht.immutableGet(hash)
  if (got && got.value) {
    console.log('  self-get:', got.value.toString())
  }

  // --- Mutable Put ---
  const keyPair = HyperDHT.keyPair(Buffer.alloc(32, 0x99))
  const mutableValue = Buffer.from('mutable hello from JS')
  const { seq, signature } = await dht.mutablePut(keyPair, mutableValue, { seq: 1 })
  console.log('Mutable PUT done')
  console.log('  publicKey:', keyPair.publicKey.toString('hex'))
  console.log('  seq:', seq)
  console.log('  value:', mutableValue.toString())

  // Verify
  const mgot = await dht.mutableGet(keyPair.publicKey)
  if (mgot && mgot.value) {
    console.log('  self-get seq:', mgot.seq, 'value:', mgot.value.toString())
  }

  console.log('\nKeep running for 60s so C++ can retrieve...')
  console.log('C++ should look for:')
  console.log('  IMMUTABLE hash:', hash.toString('hex'))
  console.log('  MUTABLE pubkey:', keyPair.publicKey.toString('hex'))

  setTimeout(() => {
    console.log('Done')
    dht.destroy()
  }, 60000)
}

main().catch(console.error)
