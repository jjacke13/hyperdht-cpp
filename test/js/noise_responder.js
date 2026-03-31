#!/usr/bin/env node

/**
 * Noise IK responder for cross-testing with C++.
 *
 * Usage: echo "<hex_msg1>" | node noise_responder.js
 *
 * Uses the REAL HyperDHT prologue (NS_PEER_HANDSHAKE) and Ed25519 curve.
 * Responder seed: 0xFF * 32 (deterministic)
 *
 * Protocol:
 *   stdin:  hex-encoded Noise msg1 (one line)
 *   stdout: line 1: hex-encoded Noise msg2
 *           line 2: hex handshake hash
 *           line 3: hex tx key
 *           line 4: hex rx key
 *           line 5: hex remote static pubkey (initiator's)
 */

const b4a = require('b4a')
const NoiseHandshake = require('/home/jacke/Desktop/repos/hyperdht-cpp/.analysis/js/noise-handshake/noise.js')
const curve = require('/home/jacke/Desktop/repos/hyperdht-cpp/.analysis/js/noise-curve-ed')
const crypto = require('hypercore-crypto')

// Real HyperDHT prologue
const NS_PEER_HANDSHAKE = crypto.namespace('hyperswarm/dht', [4, 5, 6, 0, 1])[3]

// Fixed responder seed
const responderKp = curve.generateKeyPair(b4a.alloc(32, 0xFF))

// Print responder pubkey for C++ to know
process.stderr.write('Responder PK: ' + responderKp.publicKey.toString('hex') + '\n')

// Read msg1 from stdin
let input = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => { input += chunk })
process.stdin.on('end', () => {
  try {
    const msg1 = b4a.from(input.trim(), 'hex')

    // Create responder
    const responder = new NoiseHandshake('IK', false, responderKp, { curve })
    responder.initialise(NS_PEER_HANDSHAKE, undefined)

    // Process msg1
    const payload1 = responder.recv(msg1)

    // Generate msg2
    const msg2 = responder.send(b4a.alloc(0))

    // Output results
    process.stdout.write(msg2.toString('hex') + '\n')
    process.stdout.write(responder.hash.toString('hex') + '\n')
    process.stdout.write(responder.tx.toString('hex') + '\n')
    process.stdout.write(responder.rx.toString('hex') + '\n')
    process.stdout.write(responder.rs.toString('hex') + '\n')
  } catch (err) {
    process.stderr.write('ERROR: ' + err.message + '\n')
    process.exit(1)
  }
})
