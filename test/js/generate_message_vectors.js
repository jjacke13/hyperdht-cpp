#!/usr/bin/env node

/**
 * Generate DHT RPC message test vectors.
 * Encodes known messages using the actual dht-rpc encoding and prints hex.
 */

const c = require('compact-encoding')
const net = require('compact-encoding-net')
const b4a = require('b4a')

// dht-rpc uses ipv4Address (not ipv4) and wraps it with c.array
const ipv4 = net.ipv4Address
const ipv4Array = c.array(ipv4)
const peer = { ipv4, ipv4Array }

const VERSION = 0b11
const REQUEST_ID = (0b0000 << 4) | VERSION   // 0x03
const RESPONSE_ID = (0b0001 << 4) | VERSION  // 0x13

function encodeRequest (opts) {
  const { tid, to, id, token, command, target, value, internal } = opts
  const hasId = !!id
  const hasToken = !!token
  const hasTarget = !!target
  const hasValue = !!value

  const state = { start: 0, end: 1 + 1 + 6 + 2, buffer: null }
  if (hasId) state.end += 32
  if (hasToken) state.end += 32
  c.uint.preencode(state, command)
  if (hasTarget) state.end += 32
  if (hasValue) c.buffer.preencode(state, value)

  state.buffer = b4a.allocUnsafe(state.end)
  state.buffer[state.start++] = REQUEST_ID
  state.buffer[state.start++] =
    (hasId ? 1 : 0) |
    (hasToken ? 2 : 0) |
    (internal ? 4 : 0) |
    (hasTarget ? 8 : 0) |
    (hasValue ? 16 : 0)

  c.uint16.encode(state, tid)
  peer.ipv4.encode(state, to)

  if (hasId) c.fixed32.encode(state, id)
  if (hasToken) c.fixed32.encode(state, token)
  c.uint.encode(state, command)
  if (hasTarget) c.fixed32.encode(state, target)
  if (hasValue) c.buffer.encode(state, value)

  return state.buffer
}

function encodeResponse (opts) {
  const { tid, from, id, token, closerNodes, error, value } = opts
  const hasId = !!id
  const hasToken = !!token
  const hasCloser = closerNodes && closerNodes.length > 0
  const hasError = error > 0
  const hasValue = !!value

  const state = { start: 0, end: 1 + 1 + 6 + 2, buffer: null }
  if (hasId) state.end += 32
  if (hasToken) state.end += 32
  if (hasCloser) peer.ipv4Array.preencode(state, closerNodes)
  if (hasError) c.uint.preencode(state, error)
  if (hasValue) c.buffer.preencode(state, value)

  state.buffer = b4a.allocUnsafe(state.end)
  state.buffer[state.start++] = RESPONSE_ID
  state.buffer[state.start++] =
    (hasId ? 1 : 0) |
    (hasToken ? 2 : 0) |
    (hasCloser ? 4 : 0) |
    (hasError ? 8 : 0) |
    (hasValue ? 16 : 0)

  c.uint16.encode(state, tid)
  peer.ipv4.encode(state, from)

  if (hasId) c.fixed32.encode(state, id)
  if (hasToken) c.fixed32.encode(state, token)
  if (hasCloser) peer.ipv4Array.encode(state, closerNodes)
  if (hasError) c.uint.encode(state, error)
  if (hasValue) c.buffer.encode(state, value)

  return state.buffer
}

// Test vector 1: Minimal PING request
const ping = encodeRequest({
  tid: 42,
  to: { host: '127.0.0.1', port: 8080 },
  command: 0,  // PING
  internal: false
})
console.log('PING_REQUEST:', ping.toString('hex'))

// Test vector 2: FIND_NODE request with all fields
const findNode = encodeRequest({
  tid: 1000,
  to: { host: '192.168.1.1', port: 49737 },
  id: b4a.alloc(32, 0xAA),
  token: b4a.alloc(32, 0xBB),
  command: 2,  // FIND_NODE
  target: b4a.alloc(32, 0xCC),
  value: b4a.from([0x01, 0x02, 0x03]),
  internal: false
})
console.log('FIND_NODE_REQUEST:', findNode.toString('hex'))

// Test vector 3: Minimal response
const minResp = encodeResponse({
  tid: 42,
  from: { host: '10.0.0.1', port: 3000 },
  error: 0
})
console.log('MINIMAL_RESPONSE:', minResp.toString('hex'))

// Test vector 4: Response with closer nodes and token
const closerResp = encodeResponse({
  tid: 100,
  from: { host: '10.0.0.1', port: 3000 },
  id: b4a.alloc(32, 0xDD),
  token: b4a.alloc(32, 0xEE),
  closerNodes: [
    { host: '192.168.1.1', port: 8001 },
    { host: '192.168.1.2', port: 8002 }
  ],
  error: 0
})
console.log('CLOSER_RESPONSE:', closerResp.toString('hex'))

// Test vector 5: Response with error
const errResp = encodeResponse({
  tid: 55,
  from: { host: '10.0.0.1', port: 3000 },
  error: 2  // INVALID_TOKEN
})
console.log('ERROR_RESPONSE:', errResp.toString('hex'))
