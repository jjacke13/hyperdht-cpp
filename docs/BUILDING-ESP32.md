# Building for ESP32

This page is self-contained — it assumes no prior familiarity with
`hyperdht-cpp`. Goal: take you from a stock Ubuntu/Linux machine to
a flashed ESP32 running the library.

## What you're building

`hyperdht-cpp` is a C++ implementation of HyperDHT, a P2P
distributed hash table. The same library that powers desktop / Linux
/ Android peers also runs on an ESP32 microcontroller — same wire
protocol, fully interoperable with peers on any other platform. The
ESP32 connects out to the public HyperDHT (just like a phone or a
laptop client) and either dials other peers by their public key or
accepts incoming connections.

## Supported chip

**Only `ESP32-S3` is supported today.**

Why: the library + libsodium + WiFi + lwIP need roughly 4 MB of heap
to comfortably operate. That only fits on an ESP32-S3 with **8 MB
octal PSRAM**. Other ESP32 family chips (S2, C3, original ESP32)
either lack PSRAM or have insufficient SRAM. They may build but will
not run.

Tested hardware:
- ESP32-S3 SoC
- 16 MB flash
- 8 MB octal PSRAM (mandatory)
- 2.4 GHz WiFi (the only band ESP32 supports — no 5 GHz)

## The libuv shim — what it is and why

The desktop library is built on top of [libuv](https://libuv.org/),
the same event loop that powers Node.js. libuv does not exist on
FreeRTOS, so we ship a minimal reimplementation that lives at
`components/libuv-esp32/`. It provides roughly the 40 libuv functions
that hyperdht-cpp (and its dependency, libudx) actually call —
timers, UDP sockets, async wakeups, the `uv_run` event loop — all
backed by FreeRTOS tasks + lwIP sockets. Struct layouts match real
libuv at the public-field level so libudx's direct field access
keeps working unchanged.

You don't interact with the shim directly. It's pulled in as an
ESP-IDF component alongside `hyperdht`. The fact that the same
desktop sources compile cleanly on ESP32 is entirely due to this
shim — nothing in `src/*.cpp` is `#ifdef ESP32`'d.

## What you need

| | Version | What it is |
|---|---|---|
| **Linux host** | any modern distro | Build machine. macOS / Windows users can use a Linux VM. |
| **ESP-IDF** | **v5.5+** | Espressif's official SDK. Provides the Xtensa toolchain, FreeRTOS, lwIP, WiFi stack, `idf.py` build tool. |
| **ESP32-S3 board** | with 8 MB PSRAM | Hardware target. |
| **USB cable** | data-capable | To flash + monitor. Many "charging only" cables silently fail. |

There are two ways to install ESP-IDF.

---

## Path A — Nix (recommended on any Linux distro)

This repository ships a Nix flake with an `esp32` dev shell that
pulls in a pinned ESP-IDF and Xtensa toolchain — no manual install.

Prereqs: Nix installed with flakes enabled. If you don't have Nix,
the [Determinate Systems installer](https://install.determinate.systems/)
sets it up correctly in one command.

```bash
git clone --recursive https://github.com/jjacke13/hyperdht-cpp
cd hyperdht-cpp
nix develop .#esp32
```

The first invocation downloads ESP-IDF + toolchain (~1–2 GB).
Subsequent invocations are instant. Inside the shell, `idf.py` is on
`$PATH` and `IDF_PATH` is set.

Skip to **"Build and flash the echo example"** below.

---

## Path B — Ubuntu without Nix

If you don't want Nix, install ESP-IDF v5.5 directly. These steps
mirror Espressif's [official Linux setup
guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/get-started/linux-macos-setup.html).

### B1. Install prerequisites

```bash
sudo apt update
sudo apt install -y git wget flex bison gperf python3 python3-pip \
                    python3-venv cmake ninja-build ccache \
                    libffi-dev libssl-dev dfu-util libusb-1.0-0
```

### B2. Install ESP-IDF

```bash
mkdir -p ~/esp && cd ~/esp
git clone -b v5.5 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32s3        # downloads the Xtensa toolchain for S3
```

### B3. Source the environment

Every new terminal that will run `idf.py` needs:

```bash
. ~/esp/esp-idf/export.sh
```

You can add an alias to `~/.bashrc`:

```bash
alias get_idf='. $HOME/esp/esp-idf/export.sh'
```

Then run `get_idf` once per shell.

### B4. USB permissions

Your user must be in the `dialout` group to talk to `/dev/ttyACM0`
or `/dev/ttyUSB0`:

```bash
sudo usermod -aG dialout $USER
# log out and back in for it to take effect
```

### B5. Clone the repository

```bash
cd ~
git clone --recursive https://github.com/jjacke13/hyperdht-cpp
cd hyperdht-cpp
```

`--recursive` is important — it fetches the `libudx` submodule.

---

## Build and flash the echo example

Both install paths converge here. The repo ships two ready-to-flash
examples under `examples/esp32/`:

| Example | Path | What it does |
|---|---|---|
| Echo client | `examples/esp32/` | On boot, connects to a hard-coded peer pubkey, sends `"hello"`, prints the echo |
| Echo server | `examples/esp32/echo-server/` | On boot, prints its own pubkey, accepts incoming connections, echoes received bytes |

Both build identically:

```bash
cd examples/esp32           # or examples/esp32/echo-server
idf.py set-target esp32s3
idf.py menuconfig           # set WiFi SSID + password
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

`menuconfig` is a curses UI. WiFi settings live under "Example
Configuration". Save with `S`, quit with `Q`. The chosen values are
written to `sdkconfig` in the example directory — gitignored because
it holds your credentials.

To exit the serial monitor: `Ctrl+]`.

The echo server prints its public key on boot:

```
public key: 25fb5b5427530ae59d13ad54e778cefde687f1e5517a01f0cdbf3b5b1d0040a4
listening on port 49737...
```

Hand that key to any HyperDHT client (JS, C++, Python, Android) to
connect.

---

## Building your own app

Use the echo example as a template. Three things make a project an
ESP-IDF + hyperdht-cpp project:

### 1. Project layout

```
my-esp32-app/
├── CMakeLists.txt
├── sdkconfig.defaults
├── partitions.csv         (optional, for >2 MB flash)
└── main/
    ├── CMakeLists.txt
    └── main.c             (your code)
```

### 2. Root `CMakeLists.txt`

Point ESP-IDF at this repository's `components/` directory so it
picks up `hyperdht` and `libuv-esp32`:

```cmake
cmake_minimum_required(VERSION 3.16)

# Adjust this to the relative path from your project to hyperdht-cpp
set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/../hyperdht-cpp/components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(my-esp32-app)
```

### 3. `main/CMakeLists.txt`

Declare the dependencies your app needs:

```cmake
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES libuv-esp32 hyperdht
                  esp_wifi esp_event esp_netif nvs_flash
)
```

### 4. `sdkconfig.defaults`

Copy `examples/esp32/sdkconfig.defaults` verbatim — it has the
essential knobs:

- `CONFIG_IDF_TARGET="esp32s3"` — target chip
- `CONFIG_SPIRAM=y` + `CONFIG_SPIRAM_MODE_OCT=y` — enable 8 MB octal PSRAM
- `CONFIG_SPIRAM_USE_MALLOC=y` — make `malloc` use PSRAM
- `CONFIG_FREERTOS_UNICORE=y` — single-core mode (library assumption)
- `CONFIG_ESP_MAIN_TASK_STACK_SIZE=32768` — bigger main stack (the
  library + crypto need it)
- `CONFIG_LWIP_MAX_SOCKETS=16` — enough UDP sockets for the DHT
- `CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y` — flash size (adjust to your board)

Without these, things crash on boot or at the first DHT operation.

### 5. Your code (`main.c`)

The library exposes a C API in `include/hyperdht/hyperdht.h` (84
functions, opaque pointers). The echo example in
`examples/esp32/main/main.c` is the canonical starting point — copy
it and modify. Typical flow:

```c
#include <hyperdht/hyperdht.h>

// 1. Bring up WiFi (standard ESP-IDF code, not library-specific)
// 2. hyperdht_create_opts()  -> opts handle
// 3. hyperdht_create(opts)   -> DHT handle
// 4. hyperdht_bind(dht, 0)   -> bind UDP port (0 = ephemeral)
// 5. hyperdht_connect(...)   or hyperdht_server_create()/listen()
// 6. hyperdht_loop_run(dht)  -> never returns; pumps libuv events
```

The library is permanently in **client/leaf mode** on ESP32 (no
"persistent" DHT node transition). It can dial peers and accept
incoming connections, but it never serves DHT queries itself —
that's intentional and saves ~30 % heap.

### 6. Build and flash

```bash
idf.py set-target esp32s3
idf.py menuconfig
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `component 'hyperdht' not found` | `EXTRA_COMPONENT_DIRS` in root `CMakeLists.txt` does not resolve to `<repo>/components`. Use an absolute path to check. |
| WiFi never associates | SSID/password wrong, or the network is 5 GHz only. ESP32 is 2.4 GHz only. |
| Stack overflow panic on boot | Increase `CONFIG_ESP_MAIN_TASK_STACK_SIZE` (default we ship is 32768). |
| Guru meditation in scheduler | `CONFIG_FREERTOS_UNICORE=y` is missing — the library assumes single-core. |
| `assert: PSRAM not initialised` | Board does not have PSRAM, or `CONFIG_SPIRAM=y` is off. |
| Remote peers can't find this device | Wait 30 s after boot — bootstrap + announce propagation. |
| First connection takes 5–30 s | Expected — DHT bootstrap + findPeer + relay handshake. Subsequent connections to the same peer are faster. |
| `Cannot open /dev/ttyACM0` | Either USB cable is power-only, or your user is not in `dialout` group (Path B step B4). |

## Known limitations (ESP32 build)

See `docs/REMAINING-WORK.md` → "ESP32 (`HYPERDHT_EMBEDDED`) — known
issues" for the up-to-date list. Major ones:

- **256-socket OOM risk** under the birthday-paradox holepunch
  strategy (worst-case RAM pressure when peer is behind random NAT).
- **No max-concurrent-clients cap** — currently relies on natural
  resource exhaustion to backpressure.

## References

- Architecture + libuv shim deep-dive: `docs/ESP32-IMPLEMENTATION-PLAN.md`
- C API reference: `include/hyperdht/hyperdht.h`
- Working echo apps: `examples/esp32/` + `examples/esp32/echo-server/`
- Downstream consumer: [mimiclaw](https://github.com/jjacke13/mimiclaw)
  — pocket AI device based on ESP32-S3, plans to integrate this library
