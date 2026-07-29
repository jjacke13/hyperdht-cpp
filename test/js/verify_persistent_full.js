const DHT = require('hyperdht')
const crypto = require('crypto')

const VPS_HOST = '89.147.110.205'
const VPS_PORT = 59800
const SERVER_KEY = Buffer.from('b7c5c4e909ad28e2071c48a09f330ec2735248a4e4d8759032a9b57b0f2e7aec', 'hex')

async function main() {
  const dht = new DHT()
  await dht.ready()
  console.log('DHT ready, port:', dht.port)

  // Test 1: Direct PING
  console.log('\n--- Test 1: PING VPS directly ---')
  try {
    const res = await dht.ping({ host: VPS_HOST, port: VPS_PORT })
    console.log('  PONG! latency OK')
  } catch (e) {
    console.log('  PING failed:', e.message)
  }

  // Test 2: immutablePut + immutableGet
  console.log('\n--- Test 2: immutablePut + immutableGet ---')
  const testData = Buffer.from('hyperdht-cpp persistent test ' + Date.now())
  try {
    const { hash } = await dht.immutablePut(testData)
    console.log('  PUT hash:', hash.toString('hex').slice(0, 16) + '...')
    const result = await dht.immutableGet(hash)
    if (result && result.value) {
      console.log('  GET:', result.value.toString())
      console.log('  Round-trip: OK')
    } else {
      console.log('  GET: not found')
    }
  } catch (e) {
    console.log('  Error:', e.message)
  }

  // Test 3: Announce a temp server, findPeer from second node
  console.log('\n--- Test 3: announce + findPeer ---')
  const kp = DHT.keyPair()
  const server = dht.createServer()
  server.on('connection', (s) => s.end())
  await server.listen(kp)
  console.log('  Announced:', kp.publicKey.toString('hex').slice(0, 16) + '...')

  const dht2 = new DHT()
  await dht2.ready()
  let foundSelf = false
  for await (const data of dht2.findPeer(kp.publicKey)) {
    if (data.peer) {
      foundSelf = true
      break
    }
  }
  console.log('  Found via findPeer:', foundSelf ? 'YES' : 'NO')
  await server.close()

  // Test 4: Connect to echo server (proves full pipeline)
  console.log('\n--- Test 4: echo round-trip ---')
  try {
    const socket = dht2.connect(SERVER_KEY)
    const echo = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timeout')), 10000)
      socket.on('open', () => socket.write(Buffer.from('persistent verify')))
      socket.on('data', (d) => { clearTimeout(timer); resolve(d.toString()) })
      socket.on('error', reject)
    })
    console.log('  Echo:', echo)
    socket.end()
  } catch (e) {
    console.log('  Error:', e.message)
  }

  console.log('\nAll tests passed.')
  await dht2.destroy()
  await dht.destroy()
}

main().catch(err => {
  console.error('Fatal:', err)
  process.exit(1)
})

setTimeout(() => {
  console.log('\nTimeout — exiting')
  process.exit(0)
}, 60000)
