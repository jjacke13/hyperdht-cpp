// JS HyperDHT client -> C++ server, key passed on argv.
const HyperDHT = require('hyperdht')
const key = Buffer.from(process.argv[2], 'hex')

async function main () {
  const dht = new HyperDHT()
  await dht.ready()
  console.log('[js] ready, firewalled=' + dht.firewalled + ' remoteAddress=' +
              JSON.stringify(dht.remoteAddress()))
  const t0 = Date.now()
  const socket = dht.connect(key)

  const bail = setTimeout(() => {
    console.log('[js] TIMEOUT after ' + (Date.now() - t0) + 'ms')
    process.exit(2)
  }, 90000)

  socket.on('open', () => {
    clearTimeout(bail)
    console.log('[js] CONNECTED in ' + (Date.now() - t0) + 'ms')
    console.log('[js] punches=' + JSON.stringify(dht.stats.punches))
    socket.write(Buffer.from('ping-from-js'))
    setTimeout(() => { try { socket.destroy(); dht.destroy() } catch (e) {}; process.exit(0) }, 1500)
  })
  socket.on('data', (d) => {
    console.log('[js] got ' + d.length + ' bytes: ' + d.toString().slice(0, 40))
    clearTimeout(bail)
    socket.destroy(); dht.destroy()
    setTimeout(() => process.exit(0), 300)
  })
  socket.on('error', (err) => {
    console.log('[js] ERROR after ' + (Date.now() - t0) + 'ms: ' + err.message +
                ' code=' + err.code)
    clearTimeout(bail); dht.destroy(); process.exit(1)
  })
}
main()
