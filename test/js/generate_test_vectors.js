#!/usr/bin/env node

// Generate test vectors from the JS compact-encoding library.
// Output: JSON with hex-encoded byte arrays for each test case.
// Usage: node generate_test_vectors.js > test_vectors.json

const c = require('compact-encoding')
const net = require('compact-encoding-net')

function encode(enc, value) {
    const state = c.state()
    enc.preencode(state, value)
    state.buffer = Buffer.alloc(state.end)
    state.start = 0
    enc.encode(state, value)
    return Buffer.from(state.buffer).toString('hex')
}

const vectors = {
    // Varint
    varint: [
        { value: 0, hex: encode(c.uint, 0) },
        { value: 1, hex: encode(c.uint, 1) },
        { value: 42, hex: encode(c.uint, 42) },
        { value: 252, hex: encode(c.uint, 252) },
        { value: 253, hex: encode(c.uint, 253) },
        { value: 255, hex: encode(c.uint, 255) },
        { value: 256, hex: encode(c.uint, 256) },
        { value: 4200, hex: encode(c.uint, 4200) },
        { value: 65535, hex: encode(c.uint, 65535) },
        { value: 65536, hex: encode(c.uint, 65536) },
        { value: 300000, hex: encode(c.uint, 300000) },
        { value: 4294967295, hex: encode(c.uint, 4294967295) },
    ],

    // Fixed uint16 LE
    uint16: [
        { value: 0, hex: encode(c.uint16, 0) },
        { value: 0x1234, hex: encode(c.uint16, 0x1234) },
        { value: 0xFFFF, hex: encode(c.uint16, 0xFFFF) },
    ],

    // Fixed uint32 LE
    uint32: [
        { value: 0, hex: encode(c.uint32, 0) },
        { value: 0xDEADBEEF, hex: encode(c.uint32, 0xDEADBEEF) },
    ],

    // Bool
    bool: [
        { value: false, hex: encode(c.bool, false) },
        { value: true, hex: encode(c.bool, true) },
    ],

    // Buffer (nullable)
    buffer: [
        { value: null, hex: encode(c.buffer, null) },
        { value: 'deadbeef', hex: encode(c.buffer, Buffer.from('deadbeef', 'hex')) },
    ],

    // IPv4 address (compact-encoding-net)
    ipv4addr: [
        {
            host: '10.20.30.40', port: 0x1234,
            hex: encode(net.ipv4Address, { host: '10.20.30.40', port: 0x1234 })
        },
        {
            host: '88.99.3.86', port: 49737,
            hex: encode(net.ipv4Address, { host: '88.99.3.86', port: 49737 })
        },
        {
            host: '192.168.1.1', port: 8080,
            hex: encode(net.ipv4Address, { host: '192.168.1.1', port: 8080 })
        },
    ],

    // Array of IPv4 addresses
    ipv4array: [
        {
            addrs: [],
            hex: encode(c.array(net.ipv4Address), [])
        },
        {
            addrs: [
                { host: '192.168.1.1', port: 8080 },
                { host: '10.0.0.1', port: 443 },
            ],
            hex: encode(c.array(net.ipv4Address), [
                { host: '192.168.1.1', port: 8080 },
                { host: '10.0.0.1', port: 443 },
            ])
        },
    ],

    // IPv6 address (compact-encoding-net)
    ipv6addr: [
        {
            host: '2001:db8:0:0:0:0:0:1', port: 8080,
            hex: encode(net.ipv6Address, { host: '2001:db8::1', port: 8080 })
        },
        {
            host: 'fe80:0:0:0:0:0:0:1', port: 443,
            hex: encode(net.ipv6Address, { host: 'fe80::1', port: 443 })
        },
        {
            host: '0:0:0:0:0:0:0:1', port: 0,
            hex: encode(net.ipv6Address, { host: '::1', port: 0 })
        },
        {
            host: '0:0:0:0:0:0:0:0', port: 1234,
            hex: encode(net.ipv6Address, { host: '::', port: 1234 })
        },
        {
            host: '2001:db8:85a3:0:0:8a2e:370:7334', port: 49737,
            hex: encode(net.ipv6Address, { host: '2001:db8:85a3::8a2e:370:7334', port: 49737 })
        },
    ],

    // Array of IPv6 addresses
    ipv6array: [
        {
            addrs: [],
            hex: encode(c.array(net.ipv6Address), [])
        },
        {
            addrs: [
                { host: '2001:db8:0:0:0:0:0:1', port: 8080 },
                { host: 'fe80:0:0:0:0:0:0:1', port: 443 },
            ],
            hex: encode(c.array(net.ipv6Address), [
                { host: '2001:db8::1', port: 8080 },
                { host: 'fe80::1', port: 443 },
            ])
        },
    ],
}

console.log(JSON.stringify(vectors, null, 2))
