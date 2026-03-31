#!/usr/bin/env node

/**
 * Minimal dht-rpc node that responds to PING requests.
 * Prints its bound port on stdout as "PORT:<n>\n".
 * Exits after first PING response or 10s timeout.
 */

const DHT = require('/home/jacke/Desktop/repos/hyperdht-cpp/.analysis/js/dht-rpc')

async function main () {
  const node = new DHT({ bootstrap: [] })

  node.on('request', (req) => {
    process.stderr.write(`Received command=${req.command} from ${req.from.host}:${req.from.port}\n`)
    // PING = command 0 — dht-rpc handles it internally, but let's reply manually too
    if (req.command === 0) {
      req.reply(null)
    }
  })

  await node.bind()

  const addr = node.address()
  process.stdout.write('PORT:' + addr.port + '\n')
  process.stderr.write('DHT node listening on port ' + addr.port + '\n')

  // Exit after 10s timeout
  const timer = setTimeout(() => {
    process.stderr.write('dht_ping_server: timeout\n')
    node.destroy().then(() => process.exit(1))
  }, 10000)
  timer.unref()
}

main().catch((err) => {
  process.stderr.write('ERROR: ' + err.message + '\n')
  process.exit(1)
})
