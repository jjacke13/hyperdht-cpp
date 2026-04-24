# HyperDHT on ESP32

Run a HyperDHT peer on an ESP32-S3 microcontroller. Full P2P encrypted connections from a $5 chip -- same protocol as the JS ecosystem, wire-compatible with any HyperDHT peer on the public network.

## What's included

| Example | Description |
|---------|-------------|
| `examples/esp32/` (echo client) | Connects to a remote echo server by public key, sends a message, prints the echo |
| `examples/esp32/echo-server/` | Listens for P2P connections and echoes received data back |

Both examples use the same C FFI (`hyperdht.h`) that the Python and Kotlin wrappers use.

## Hardware

Tested on **ESP32-S3** with:
- 16MB flash
- 8MB octal PSRAM (required -- the library + crypto + WiFi stack needs ~4MB heap)
- WiFi STA mode

Other ESP32 variants (S2, C3, original ESP32) may work but are untested. The PSRAM requirement is the main constraint.

## Prerequisites

### With Nix (recommended)

```bash
nix develop .#esp32
```

This provides ESP-IDF v5.5+ and the Xtensa toolchain. Nothing else to install.

### Without Nix

Install [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/get-started/) v5.5 or later, then source the environment:

```bash
. ~/esp/esp-idf/export.sh
```

## Build and flash

### Echo server

```bash
cd examples/esp32/echo-server
idf.py set-target esp32s3
idf.py menuconfig        # Set WiFi SSID/password and optionally a server seed
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

On boot the server prints its public key:

```
public key: 25fb5b5427530ae59d13ad54e778cefde687f1e5517a01f0cdbf3b5b1d0040a4
listening on port 49737...
```

Give this key to any HyperDHT client (JS, Python, C++, Android) to connect.

### Echo client

```bash
cd examples/esp32
idf.py set-target esp32s3
idf.py menuconfig        # Set WiFi SSID/password
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

The client connects to the hardcoded server key in `main/main.c`. Edit `SERVER_PK` to point at your server.

## Configuration

Both examples use `idf.py menuconfig` for runtime configuration:

| Option | Description |
|--------|-------------|
| WiFi SSID | Your WiFi network name |
| WiFi Password | Your WiFi password |
| Server seed (echo-server only) | 64 hex chars for a deterministic keypair. Leave empty for random. |

The `sdkconfig` file (created by menuconfig) is gitignored since it contains WiFi credentials.

## How it works

The library is compiled as an ESP-IDF component from the same source files as the desktop build:

```
components/
  hyperdht/       <- Compiles src/*.cpp with -DHYPERDHT_EMBEDDED=1
  libudx/         <- libudx C library (git submodule)
  libuv-esp32/    <- libuv shim for ESP-IDF (lwIP + FreeRTOS)
```

`HYPERDHT_EMBEDDED=1` enables embedded-friendly defaults:
- Routing table bucket size reduced from k=20 to k=10
- Congestion window reduced from 80 to 16
- No exceptions, no RTTI (`-fno-exceptions -fno-rtti`)

The ESP-IDF component CMakeLists is at `components/hyperdht/CMakeLists.txt`. It references the source files directly from the repo root's `src/` directory, so rebuilding after library changes requires no extra steps.

## Connecting to the ESP32

From any HyperDHT client:

**JS:**
```javascript
const HyperDHT = require('hyperdht')
const node = new HyperDHT()
const socket = node.connect(Buffer.from('25fb5b54...', 'hex'))
socket.on('open', () => {
  socket.write(Buffer.from('hello'))
  socket.on('data', (d) => console.log('echo:', d.toString()))
})
```

**C++ (test_echo_fixture):**
```bash
cd build
SERVER_KEY=25fb5b54... ./test_echo_fixture
```

**Python:**
```python
from hyperdht import HyperDHT
dht = HyperDHT()
stream = dht.connect(bytes.fromhex('25fb5b54...'))
stream.write(b'hello')
print(stream.read())
```

**Android (Kotlin):**
The Android example app at `examples/android/` connects to a server key configured in `MainActivity.kt`.

## Memory usage

On ESP32-S3 with 8MB PSRAM, typical heap usage after bootstrap:

```
Free heap: ~4MB (out of 8MB PSRAM + 320KB internal)
```

The library uses ~2-3MB for the routing table, crypto state, connection buffers, and libuv handles.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Build fails: `component 'hyperdht' not found` | Check `EXTRA_COMPONENT_DIRS` in `CMakeLists.txt` points to `../../components` |
| WiFi won't connect | Verify SSID/password in menuconfig. Check 2.4GHz (ESP32 doesn't support 5GHz) |
| Crash on boot (stack overflow) | Increase `CONFIG_ESP_MAIN_TASK_STACK_SIZE` in sdkconfig.defaults (default: 32768) |
| `guru meditation` / panic | Ensure `CONFIG_FREERTOS_UNICORE=y` -- the library assumes single-core |
| Can't find ESP32 from remote client | Wait ~30s after boot for bootstrap + announce to propagate |
| Very slow first connection | Normal -- DHT bootstrap + findPeer + relay handshake takes 5-30s |

## ESP-IDF version

Tested with ESP-IDF v5.5. Earlier versions may work but v5.5+ is recommended for the C++20 toolchain support.
