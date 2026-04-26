#!/usr/bin/env node
// Test whether a specific C++ DHT node SERVES queries for other peers.
// Sends PING, FIND_NODE directly via dht-rpc, then FIND_PEER/LOOKUP via HyperDHT.

const DHT = require('hyperdht')
const RPC = require('dht-rpc')
const crypto = require('hypercore-crypto')

const TARGET_HOST = process.argv[2] || '89.147.110.205'
const TARGET_PORT = parseInt(process.argv[3] || '38398')

async function main () {
  const node = { host: TARGET_HOST, port: TARGET_PORT }
  console.log('Querying C++ node directly:', TARGET_HOST + ':' + TARGET_PORT)
  console.log()

  // Use dht-rpc directly for low-level queries
  const rpc = new RPC()
  await rpc.ready()

  // 1. PING
  console.log('--- PING ---')
  try {
    const pong = await rpc.ping(node)
    console.log('  PONG from:', pong.from.host + ':' + pong.from.port)
    console.log('  Node ID:', pong.from.id?.toString('hex')?.slice(0, 16) + '...')
    console.log('  Result: ALIVE')
  } catch (err) {
    console.log('  Result: FAILED -', err.message)
  }
  console.log()

  // 2. FIND_NODE — does it return closer nodes from its routing table?
  console.log('--- FIND_NODE (random target) ---')
  const randomTarget = crypto.randomBytes(32)
  try {
    const result = await rpc.request({
      command: 2, // FIND_NODE
      target: randomTarget
    }, node)
    console.log('  Response from:', result.from.host + ':' + result.from.port)
    console.log('  closerNodes:', result.closerNodes?.length || 0)
    if (result.closerNodes?.length > 0) {
      console.log('  Sample closer nodes:')
      for (const n of result.closerNodes.slice(0, 3)) {
        console.log('    ', n.host + ':' + n.port)
      }
    }
    console.log('  Result: SERVING ROUTING QUERIES')
  } catch (err) {
    console.log('  Result: FAILED -', err.message)
  }
  console.log()

  await rpc.destroy()

  // Now use HyperDHT for the higher-level queries
  const dht = new DHT()
  await dht.ready()

  // 3. FIND_PEER — send directly to our node via nodes hint
  console.log('--- FIND_PEER (random key → our node) ---')
  const randomKey = crypto.randomBytes(32)
  try {
    let responded = false
    const q = dht.findPeer(randomKey, { nodes: [node] })
    for await (const data of q) {
      if (data.from?.host === TARGET_HOST && data.from?.port === TARGET_PORT) {
        console.log('  Response from OUR node:', data.from.host + ':' + data.from.port)
        console.log('  peer:', data.peer ? 'found' : 'null (not stored — correct, it was random)')
        console.log('  closerNodes:', data.closerNodes?.length || 0)
        responded = true
      }
    }
    console.log('  Result:', responded ? 'SERVING FIND_PEER' : 'no direct response (may still be ephemeral)')
  } catch (err) {
    console.log('  Result: FAILED -', err.message)
  }
  console.log()

  // 4. LOOKUP — send directly to our node
  console.log('--- LOOKUP (random key → our node) ---')
  const randomKey2 = crypto.randomBytes(32)
  try {
    let responded = false
    const q = dht.lookup(randomKey2, { nodes: [node] })
    for await (const data of q) {
      if (data.from?.host === TARGET_HOST && data.from?.port === TARGET_PORT) {
        console.log('  Response from OUR node:', data.from.host + ':' + data.from.port)
        console.log('  peers:', data.peers?.length || 0)
        console.log('  closerNodes:', data.closerNodes?.length || 0)
        responded = true
      }
    }
    console.log('  Result:', responded ? 'SERVING LOOKUP' : 'no direct response (may still be ephemeral)')
  } catch (err) {
    console.log('  Result: FAILED -', err.message)
  }

  console.log()
  console.log('=== Summary ===')
  console.log('PING + FIND_NODE = node is alive and routing for the network')
  console.log('FIND_PEER + LOOKUP = node is persistent and storing/serving data for others')

  await dht.destroy()
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
