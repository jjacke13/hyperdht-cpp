#!/usr/bin/env node

// Generate wire-format test vectors for cross-testing C++ decoders.
// Outputs JSON with hex-encoded bytes for each message type.
// Usage: node generate_wire_vectors.js > wire_vectors.json

const c = require('compact-encoding')
const net = require('compact-encoding-net')
const { handshake, holepunch, announce, peer, mutablePutRequest, mutableGetResponse, mutableSignable } = require('hyperdht/lib/messages')

const vectors = {}

// 1. HandshakeMessage (mode=FROM_CLIENT, with noise and peerAddress)
{
  const msg = {
    mode: 0, // FROM_CLIENT
    noise: Buffer.from('deadbeef01020304', 'hex'),
    peerAddress: { host: '192.168.1.100', port: 9999 },
    relayAddress: null
  }
  vectors.handshake_from_client = Buffer.from(c.encode(handshake, msg)).toString('hex')
}

// 2. HandshakeMessage (mode=FROM_SERVER, with noise and peerAddress)
{
  const msg = {
    mode: 1, // FROM_SERVER
    noise: Buffer.from('aabbccdd', 'hex'),
    peerAddress: { host: '10.0.0.1', port: 5000 },
    relayAddress: null
  }
  vectors.handshake_from_server = Buffer.from(c.encode(handshake, msg)).toString('hex')
}

// 3. HandshakeMessage (mode=REPLY, no peerAddress)
{
  const msg = {
    mode: 4, // REPLY
    noise: Buffer.from('1122334455', 'hex'),
    peerAddress: null,
    relayAddress: null
  }
  vectors.handshake_reply = Buffer.from(c.encode(handshake, msg)).toString('hex')
}

// 4. HolepunchMessage (mode=FROM_RELAY, with id, payload, peerAddress)
{
  const msg = {
    mode: 2, // FROM_RELAY
    id: 42,
    payload: Buffer.from('encrypted_payload_data'),
    peerAddress: { host: '172.16.0.1', port: 8080 }
  }
  vectors.holepunch_from_relay = Buffer.from(c.encode(holepunch, msg)).toString('hex')
}

// 5. AnnounceMessage (with peer, signature, no refresh)
{
  const msg = {
    peer: {
      publicKey: Buffer.alloc(32, 0x42),
      relayAddresses: [
        { host: '1.2.3.4', port: 5000 },
        { host: '5.6.7.8', port: 6000 }
      ]
    },
    refresh: null,
    signature: Buffer.alloc(64, 0xAA),
    bump: 0
  }
  vectors.announce_with_sig = Buffer.from(c.encode(announce, msg)).toString('hex')
}

// 6. AnnounceMessage (refresh only, no peer)
{
  const msg = {
    peer: null,
    refresh: Buffer.alloc(32, 0xBB),
    signature: null,
    bump: 0
  }
  vectors.announce_refresh = Buffer.from(c.encode(announce, msg)).toString('hex')
}

// 7. PeerRecord (publicKey + relay addresses)
{
  const rec = {
    publicKey: Buffer.alloc(32, 0x11),
    relayAddresses: [
      { host: '88.99.3.86', port: 49737 }
    ]
  }
  vectors.peer_record = Buffer.from(c.encode(peer, rec)).toString('hex')
}

// 8. MutablePutRequest
{
  const msg = {
    publicKey: Buffer.alloc(32, 0x55),
    seq: 7,
    value: Buffer.from('hello mutable'),
    signature: Buffer.alloc(64, 0xCC)
  }
  vectors.mutable_put = Buffer.from(c.encode(mutablePutRequest, msg)).toString('hex')
}

// 9. MutableGetResponse
{
  const msg = {
    seq: 3,
    value: Buffer.from('stored value'),
    signature: Buffer.alloc(64, 0xDD)
  }
  vectors.mutable_get_resp = Buffer.from(c.encode(mutableGetResponse, msg)).toString('hex')
}

// 10. MutableSignable (what gets hashed for signing)
{
  const msg = {
    seq: 5,
    value: Buffer.from('sign this')
  }
  vectors.mutable_signable = Buffer.from(c.encode(mutableSignable, msg)).toString('hex')
}

console.log(JSON.stringify(vectors, null, 2))
