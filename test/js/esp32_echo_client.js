#!/usr/bin/env node
// One-off JS echo client to test the ESP32 echo-server.
// Uses the test/js/node_modules — run from the hyperdht-cpp repo root.

const HyperDHT = require('hyperdht')

const SERVER_KEY = Buffer.from(
  '25fb5b5427530ae59d13ad54e778cefde687f1e5517a01f0cdbf3b5b1d0040a4',
  'hex'
)

const MESSAGE = 'hello from JS @ ' + new Date().toISOString()
const TIMEOUT_MS = 60_000

async function main () {
  const t0 = Date.now()
  const elapsed = () => `[t+${(Date.now() - t0) / 1000}s]`

  console.log(elapsed(), 'creating DHT node…')
  const dht = new HyperDHT()
  await dht.ready()
  console.log(elapsed(), 'DHT ready. Firewalled:', dht.firewalled)
  console.log(elapsed(), 'connecting to', SERVER_KEY.toString('hex').slice(0, 16) + '…')

  const socket = dht.connect(SERVER_KEY)

  const cleanup = (code) => {
    try { socket.destroy() } catch {}
    try { dht.destroy() } catch {}
    setTimeout(() => process.exit(code), 200)
  }

  const timer = setTimeout(() => {
    console.error(elapsed(), 'TIMEOUT — never received echo')
    cleanup(1)
  }, TIMEOUT_MS)

  socket.on('open', () => {
    console.log(elapsed(), 'OPEN — sending', JSON.stringify(MESSAGE))
    socket.write(MESSAGE)
  })

  socket.on('data', (d) => {
    const got = d.toString()
    console.log(elapsed(), 'echo:', JSON.stringify(got))
    if (got === MESSAGE) {
      console.log(elapsed(), 'PASS — echo matches')
      clearTimeout(timer)
      cleanup(0)
    }
  })

  socket.on('error', (err) => {
    console.error(elapsed(), 'socket error:', err.message)
    clearTimeout(timer)
    cleanup(2)
  })

  socket.on('close', () => {
    console.log(elapsed(), 'socket closed')
  })
}

main().catch((e) => {
  console.error('fatal:', e)
  process.exit(3)
})
