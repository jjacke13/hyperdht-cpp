#!/usr/bin/env node

// UDX echo server for C++ cross-testing.
//
// Usage: node udx_echo_server.js <remote_port>
//
// Protocol:
//   - JS stream ID = 1, C++ stream ID = 2
//   - JS connects to C++ at 127.0.0.1:<remote_port> with remote_id=2
//   - C++ connects to JS at the port printed below with remote_id=1
//   - JS echoes back any data received, then ends when remote ends

const UDX = require('udx-native')

const remotePort = parseInt(process.argv[2], 10)
if (!remotePort) {
    process.stderr.write('Usage: node udx_echo_server.js <remote_port>\n')
    process.exit(1)
}

const u = new UDX()
const socket = u.createSocket()
const stream = u.createStream(1, { firewall: () => false })

socket.bind(0)

// Connect our stream to the C++ side
stream.connect(socket, 2, remotePort, '127.0.0.1')

// Print our port so C++ can connect back
const port = socket.address().port
process.stdout.write('PORT:' + port + '\n')

stream.on('data', function (data) {
    stream.write(data)
})

stream.on('end', function () {
    stream.end()
})

stream.on('close', function () {
    socket.close()
})

// Safety timeout
const timer = setTimeout(function () {
    process.stderr.write('udx_echo_server: timeout\n')
    process.exit(1)
}, 10000)
timer.unref()
