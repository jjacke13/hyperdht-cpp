#!/usr/bin/env node

/**
 * Noise IK Handshake Test Vector Generator
 *
 * Uses noise-curve-ed (Ed25519) — the ACTUAL curve HyperDHT uses,
 * NOT the default X25519 from noise-handshake/dh.js.
 *
 * Output: Hex-encoded cryptographic values for C++ implementation testing.
 */

const sodium = require('sodium-universal')
const b4a = require('b4a')

// Load local Noise modules — using the CORRECT Ed25519 curve.
// These are in .analysis/js/ (gitignored reference copies from npm).
const path = require('path')
const ANALYSIS = path.join(__dirname, '..', '..', '.analysis', 'js')
const curve = require(path.join(ANALYSIS, 'noise-curve-ed'))
const NoiseHandshake = require(path.join(ANALYSIS, 'noise-handshake', 'noise.js'))
const hmac = require(path.join(ANALYSIS, 'noise-handshake', 'hmac.js'))
const { hkdf, HASHLEN } = require(path.join(ANALYSIS, 'noise-handshake', 'hkdf.js'))

// Fixed seeds for deterministic keypairs
const INITIATOR_SEED = b4a.alloc(32, 0x00) // All zeros
const RESPONDER_SEED = b4a.alloc(32, 0xFF) // All ones
const INITIATOR_EPHEMERAL_SEED = b4a.alloc(32, 0xAA)
const RESPONDER_EPHEMERAL_SEED = b4a.alloc(32, 0xBB)
const PROLOGUE = b4a.from([0]) // PEER_HANDSHAKE = 0

function toHex (buf) {
  return b4a.toBuffer(buf).toString('hex')
}

function log (title, value) {
  if (typeof value === 'object' && value !== null) {
    console.log(`${title}: ${toHex(value)}`)
  } else {
    console.log(`${title}: ${value}`)
  }
}

function sep (text) {
  console.log('\n' + '='.repeat(80))
  console.log(`  ${text}`)
  console.log('='.repeat(80) + '\n')
}

// ============================================================================
// Primitive Crypto Test Vectors
// ============================================================================

function testPrimitives () {
  sep('PRIMITIVE CRYPTO TEST VECTORS')

  // BLAKE2b-512
  console.log('// BLAKE2b-512')
  const h = b4a.alloc(HASHLEN)
  sodium.crypto_generichash(h, b4a.from('hello'))
  log('BLAKE2b-512("hello")', h)

  // HMAC-BLAKE2b (128-byte block)
  console.log('\n// HMAC-BLAKE2b')
  const hmacKey = b4a.alloc(32, 0x42)
  const hmacMsg = b4a.from('test message')
  const hmacOut = b4a.alloc(HASHLEN)
  hmac(hmacOut, [hmacMsg], hmacKey)
  log('Key', hmacKey)
  log('Message ("test message")', hmacMsg)
  log('HMAC', hmacOut)

  // HKDF
  console.log('\n// HKDF')
  const salt = b4a.alloc(32, 0x11)
  const ikm = b4a.alloc(32, 0x22)
  const [hk1, hk2] = hkdf(salt, ikm, '', 2 * HASHLEN)
  log('Salt', salt)
  log('IKM', ikm)
  log('Output1 (ck)', hk1)
  log('Output2 (k)', hk2)

  // Ed25519 DH (the REAL one HyperDHT uses)
  console.log('\n// Ed25519 DH (noise-curve-ed)')
  const kp1 = curve.generateKeyPair(b4a.alloc(32, 0x33))
  const kp2 = curve.generateKeyPair(b4a.alloc(32, 0x44))
  log('Seed1', b4a.alloc(32, 0x33))
  log('PK1', kp1.publicKey)
  log('SK1 (64 bytes)', kp1.secretKey)
  log('Seed2', b4a.alloc(32, 0x44))
  log('PK2', kp2.publicKey)
  log('SK2 (64 bytes)', kp2.secretKey)
  const dh12 = curve.dh(kp2.publicKey, kp1)
  const dh21 = curve.dh(kp1.publicKey, kp2)
  log('DH(sk1, pk2)', dh12)
  log('DH(sk2, pk1)', dh21)
  console.log('DH symmetric:', toHex(dh12) === toHex(dh21) ? 'PASS' : 'FAIL')

  // ChaCha20-Poly1305 AEAD
  console.log('\n// ChaCha20-Poly1305 IETF')
  const cKey = b4a.alloc(32, 0x55)
  const pt = b4a.from('secret message')
  const ad = b4a.alloc(0) // empty AD
  // Noise nonce: 4 zero bytes + LE uint32 counter + 4 zero bytes
  const nonce = b4a.alloc(12)
  const ct = b4a.alloc(pt.byteLength + 16)
  sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ct, pt, ad, null, nonce, cKey)
  log('Key', cKey)
  log('Plaintext ("secret message")', pt)
  log('Nonce (counter=0)', nonce)
  log('AD', ad)
  log('Ciphertext+Tag', ct)

  // With counter=1
  const nonce1 = b4a.alloc(12)
  const view1 = new DataView(nonce1.buffer, nonce1.byteOffset, nonce1.byteLength)
  view1.setUint32(4, 1, true)
  const ct1 = b4a.alloc(pt.byteLength + 16)
  sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ct1, pt, ad, null, nonce1, cKey)
  log('Nonce (counter=1)', nonce1)
  log('Ciphertext+Tag (counter=1)', ct1)
}

// ============================================================================
// Noise IK Handshake Test Vectors
// ============================================================================

function testHandshake () {
  sep('NOISE IK HANDSHAKE — Ed25519 curve')

  // Generate deterministic keypairs using noise-curve-ed
  console.log('// Keypair Generation (crypto_sign_seed_keypair)')
  const iKp = curve.generateKeyPair(INITIATOR_SEED)
  const rKp = curve.generateKeyPair(RESPONDER_SEED)

  log('Initiator Seed', INITIATOR_SEED)
  log('Initiator PK (32)', iKp.publicKey)
  log('Initiator SK (64)', iKp.secretKey)
  log('Responder Seed', RESPONDER_SEED)
  log('Responder PK (32)', rKp.publicKey)
  log('Responder SK (64)', rKp.secretKey)

  sep('PROTOCOL INITIALIZATION')

  // Protocol name with Ed25519 (NOT 25519)
  const protocolName = 'Noise_IK_Ed25519_ChaChaPoly_BLAKE2b'
  log('Protocol name', b4a.from(protocolName))
  console.log('Protocol name length:', protocolName.length)

  // Since protocolName (35 bytes) <= HASHLEN (64 bytes):
  // digest = protocol_name padded with zeros to 64 bytes
  // chainingKey = copy of digest
  const initDigest = b4a.alloc(HASHLEN)
  initDigest.set(b4a.from(protocolName))
  log('Initial digest (padded)', initDigest)
  log('Initial ck (same)', initDigest)

  sep('INITIATOR INIT')

  // Create initiator with Ed25519 curve
  const initiator = new NoiseHandshake('IK', true, iKp, { curve })
  // Inject fixed ephemeral for deterministic vectors
  initiator.e = curve.generateKeyPair(INITIATOR_EPHEMERAL_SEED)
  log('Initiator ephemeral seed', INITIATOR_EPHEMERAL_SEED)
  log('Initiator ephemeral PK', initiator.e.publicKey)
  log('Initiator ephemeral SK', initiator.e.secretKey)
  initiator.initialise(PROLOGUE, rKp.publicKey)

  log('Prologue', PROLOGUE)
  log('h after initialise()', initiator.digest)
  log('ck after initialise()', initiator.chainingKey)

  sep('RESPONDER INIT')

  const responder = new NoiseHandshake('IK', false, rKp, { curve })
  // Inject fixed ephemeral for deterministic vectors
  responder.e = curve.generateKeyPair(RESPONDER_EPHEMERAL_SEED)
  log('Responder ephemeral seed', RESPONDER_EPHEMERAL_SEED)
  log('Responder ephemeral PK', responder.e.publicKey)
  log('Responder ephemeral SK', responder.e.secretKey)
  responder.initialise(PROLOGUE, undefined)

  log('h after initialise()', responder.digest)
  log('ck after initialise()', responder.chainingKey)

  // Both sides should have same h and ck after init
  console.log('\nInit state match:', toHex(initiator.digest) === toHex(responder.digest) ? 'PASS' : 'FAIL')

  sep('MESSAGE 1: Initiator -> Responder')
  console.log('// IK pattern msg1 tokens: [e, es, s, ss]')

  const msg1 = initiator.send(b4a.alloc(0))
  log('Message 1', msg1)
  log('Message 1 length', msg1.byteLength)
  log('Initiator ck after msg1', initiator.chainingKey)
  log('Initiator h after msg1', initiator.digest)

  // Parse msg1 structure
  console.log('\n// Message 1 structure:')
  log('  e (ephemeral PK, bytes 0-31)', msg1.subarray(0, 32))
  log('  encrypted s (bytes 32-79)', msg1.subarray(32, 80))
  log('  encrypted payload (bytes 80-95)', msg1.subarray(80, 96))

  sep('MESSAGE 1: Responder receives')

  const payload1 = responder.recv(msg1)
  log('Payload', payload1)
  log('Responder ck after msg1', responder.chainingKey)
  log('Responder h after msg1', responder.digest)
  log('Responder re (ephemeral)', responder.re)
  log('Responder rs (static)', responder.rs)

  console.log('\nState after msg1 match:', toHex(initiator.chainingKey) === toHex(responder.chainingKey) ? 'PASS' : 'FAIL')

  sep('MESSAGE 2: Responder -> Initiator')
  console.log('// IK pattern msg2 tokens: [e, ee, se]')

  const msg2 = responder.send(b4a.alloc(0))
  log('Message 2', msg2)
  log('Message 2 length', msg2.byteLength)

  // Parse msg2 structure
  console.log('\n// Message 2 structure:')
  log('  e (ephemeral PK, bytes 0-31)', msg2.subarray(0, 32))
  log('  encrypted payload (bytes 32-47)', msg2.subarray(32, 48))

  sep('MESSAGE 2: Initiator receives')

  const payload2 = initiator.recv(msg2)
  log('Payload', payload2)

  sep('FINAL STATE')

  log('Initiator complete', initiator.complete)
  log('Responder complete', responder.complete)
  log('Initiator handshake hash', initiator.hash)
  log('Responder handshake hash', responder.hash)

  console.log('\n// Split keys (first 32 bytes of each HKDF output)')
  log('Initiator tx', initiator.tx)
  log('Initiator rx', initiator.rx)
  log('Responder tx', responder.tx)
  log('Responder rx', responder.rx)

  console.log('\n// Verification')
  console.log('tx/rx complementary:', toHex(initiator.tx) === toHex(responder.rx) &&
    toHex(initiator.rx) === toHex(responder.tx) ? 'PASS' : 'FAIL')
  console.log('Handshake hash match:', toHex(initiator.hash) === toHex(responder.hash) ? 'PASS' : 'FAIL')
}

// ============================================================================
// Main
// ============================================================================

try {
  testPrimitives()
  testHandshake()
  sep('DONE')
  console.log('All vectors generated with noise-curve-ed (Ed25519).')
} catch (err) {
  console.error('ERROR:', err.message)
  console.error(err.stack)
  process.exit(1)
}
