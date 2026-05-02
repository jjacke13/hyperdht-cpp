#ifdef _WIN32

// Wintun-backed TUN implementation. Mirrors nospoon's JS native addon at
// nospoon/native/tun-windows.c — same LoadLibrary + GetProcAddress dance,
// same ring-buffer read/release semantics, same adapter name + GUID-less
// auto-allocated adapter id.

#include "tun_windows.hpp"
#include "wintun/wintun.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace nospoon {

namespace {

constexpr DWORD SESSION_CAPACITY = 0x400000;  // 4 MiB ring buffer (matches JS)

HMODULE g_wintun_dll = nullptr;
WINTUN_CREATE_ADAPTER_FN             pCreate         = nullptr;
WINTUN_OPEN_ADAPTER_FN               pOpenAdapter    = nullptr;
WINTUN_CLOSE_ADAPTER_FN              pClose          = nullptr;
WINTUN_START_SESSION_FN              pStartSession   = nullptr;
WINTUN_END_SESSION_FN                pEndSession     = nullptr;
WINTUN_GET_READ_WAIT_EVENT_FN        pGetReadEvent   = nullptr;
WINTUN_RECEIVE_PACKET_FN             pReceive        = nullptr;
WINTUN_RELEASE_RECEIVE_PACKET_FN     pReleaseReceive = nullptr;
WINTUN_ALLOCATE_SEND_PACKET_FN       pAllocateSend   = nullptr;
WINTUN_SEND_PACKET_FN                pSend           = nullptr;
WINTUN_GET_RUNNING_DRIVER_VERSION_FN pDriverVersion  = nullptr;

bool load_wintun_dll() {
    if (g_wintun_dll) return true;

    // Look for wintun.dll alongside the .exe first; fall back to PATH.
    wchar_t exe_path[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        for (DWORD i = len; i > 0; --i) {
            if (exe_path[i - 1] == L'\\' || exe_path[i - 1] == L'/') {
                exe_path[i] = 0;
                break;
            }
        }
        wchar_t dll_path[MAX_PATH];
        if (swprintf(dll_path, MAX_PATH, L"%swintun.dll", exe_path) > 0) {
            g_wintun_dll = LoadLibraryW(dll_path);
        }
    }
    if (!g_wintun_dll) {
        g_wintun_dll = LoadLibraryW(L"wintun.dll");
    }
    if (!g_wintun_dll) {
        std::fprintf(stderr, "Failed to load wintun.dll (error %lu)\n",
                     GetLastError());
        return false;
    }

#define LOAD(var, name)                                                       \
    var = reinterpret_cast<decltype(var)>(GetProcAddress(g_wintun_dll, name)); \
    if (!var) {                                                               \
        std::fprintf(stderr, "wintun.dll missing function: %s\n", name);      \
        FreeLibrary(g_wintun_dll);                                            \
        g_wintun_dll = nullptr;                                               \
        return false;                                                         \
    }

    LOAD(pCreate,         "WintunCreateAdapter");
    LOAD(pOpenAdapter,    "WintunOpenAdapter");
    LOAD(pClose,          "WintunCloseAdapter");
    LOAD(pStartSession,   "WintunStartSession");
    LOAD(pEndSession,     "WintunEndSession");
    LOAD(pGetReadEvent,   "WintunGetReadWaitEvent");
    LOAD(pReceive,        "WintunReceivePacket");
    LOAD(pReleaseReceive, "WintunReleaseReceivePacket");
    LOAD(pAllocateSend,   "WintunAllocateSendPacket");
    LOAD(pSend,           "WintunSendPacket");
    LOAD(pDriverVersion,  "WintunGetRunningDriverVersion");
#undef LOAD

    return true;
}

}  // namespace

Tun::~Tun() { close(); }

int Tun::open(const std::string& ip_cidr, int mtu) {
    if (!load_wintun_dll()) return -1;

    // Parse "10.0.0.1/24" -> ip + prefix -> dotted netmask.
    auto slash = ip_cidr.find('/');
    if (slash == std::string::npos) {
        std::fprintf(stderr, "Invalid ip_cidr: %s (expected addr/prefix)\n",
                     ip_cidr.c_str());
        return -1;
    }
    std::string ip_addr = ip_cidr.substr(0, slash);
    int prefix = 0;
    try {
        prefix = std::stoi(ip_cidr.substr(slash + 1));
    } catch (...) {
        std::fprintf(stderr, "Invalid prefix in: %s\n", ip_cidr.c_str());
        return -1;
    }
    if (prefix < 0 || prefix > 32) {
        std::fprintf(stderr, "Invalid prefix: %d\n", prefix);
        return -1;
    }
    uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    char netmask[16];
    std::snprintf(netmask, sizeof(netmask), "%u.%u.%u.%u",
                  (mask >> 24) & 0xFFu, (mask >> 16) & 0xFFu,
                  (mask >> 8) & 0xFFu, mask & 0xFFu);

    // Wintun adapter name and tunnel "type" (free-form display name).
    const wchar_t* w_name = L"Nospoon";
    const wchar_t* w_type = L"Nospoon Tunnel";

    // Clean up a stale adapter from a previous crashed run.
    auto stale = pOpenAdapter(w_name);
    if (stale) pClose(stale);

    adapter_ = pCreate(w_name, w_type, nullptr);
    if (!adapter_) {
        std::fprintf(stderr,
                     "WintunCreateAdapter failed (error %lu) — "
                     "must run as Administrator\n",
                     GetLastError());
        return -1;
    }

    DWORD ver = pDriverVersion();
    if (ver) {
        std::fprintf(stderr, "  Wintun driver v%lu.%lu\n",
                     (ver >> 16) & 0xffff, ver & 0xffff);
    }

    // IPv4 address + netmask via netsh. Adapter name is hardcoded "Nospoon"
    // so no quoting/injection concern beyond ip_addr (from local config).
    char cmd[512];
    std::snprintf(cmd, sizeof(cmd),
                  "netsh interface ipv4 set address name=\"Nospoon\" "
                  "source=static addr=%s mask=%s > NUL 2>&1",
                  ip_addr.c_str(), netmask);
    if (std::system(cmd) != 0) {
        std::fprintf(stderr, "Failed: %s\n", cmd);
        pClose(adapter_); adapter_ = nullptr;
        return -1;
    }

    std::snprintf(cmd, sizeof(cmd),
                  "netsh interface ipv4 set subinterface \"Nospoon\" "
                  "mtu=%d store=active > NUL 2>&1",
                  mtu);
    if (std::system(cmd) != 0) {
        std::fprintf(stderr, "Failed: %s\n", cmd);
        pClose(adapter_); adapter_ = nullptr;
        return -1;
    }

    session_ = pStartSession(adapter_, SESSION_CAPACITY);
    if (!session_) {
        std::fprintf(stderr, "WintunStartSession failed (error %lu)\n",
                     GetLastError());
        pClose(adapter_); adapter_ = nullptr;
        return -1;
    }
    read_event_ = pGetReadEvent(session_);

    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_event_) {
        std::fprintf(stderr, "CreateEventW failed (error %lu)\n",
                     GetLastError());
        pEndSession(session_); session_ = nullptr;
        pClose(adapter_);      adapter_ = nullptr;
        return -1;
    }

    mtu_ = mtu;
    name_ = "Nospoon";
    std::fprintf(stderr, "  TUN Nospoon opened (%s, MTU %d)\n",
                 ip_cidr.c_str(), mtu);
    return 0;
}

void Tun::start(uv_loop_t* loop, OnPacketCb on_packet) {
    if (!session_) return;
    on_packet_ = std::move(on_packet);

    uv_async_init(loop, &async_, on_async);
    async_.data = this;
    async_active_ = true;

    running_.store(true);
    worker_ = std::thread([this]() { worker_loop(); });
}

void Tun::worker_loop() {
    HANDLE waits[2] = { static_cast<HANDLE>(read_event_),
                        static_cast<HANDLE>(stop_event_) };
    while (running_.load()) {
        DWORD r = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (r == WAIT_OBJECT_0) {
            if (async_active_) uv_async_send(&async_);
        } else {
            // Stop event signaled, or wait failed — exit either way.
            return;
        }
    }
}

void Tun::on_async(uv_async_t* handle) {
    auto* self = static_cast<Tun*>(handle->data);
    if (!self->session_) return;

    // Wintun's ReceivePacket is single-threaded per session; we only ever
    // call it from the loop thread (here), and only the worker hits the
    // wait event, so no contention.
    while (true) {
        DWORD size = 0;
        BYTE* pkt = pReceive(self->session_, &size);
        if (!pkt) {
            DWORD err = GetLastError();
            if (err == WINTUN_ERROR_HANDLE_EOF) {
                std::fprintf(stderr, "  Wintun session ended by driver\n");
            }
            // ERROR_NO_MORE_ITEMS = ring drained; normal exit from the loop.
            break;
        }
        if (self->on_packet_) {
            self->on_packet_(pkt, static_cast<size_t>(size));
        }
        pReleaseReceive(self->session_, pkt);
    }
}

int Tun::write(const uint8_t* data, size_t len) {
    if (!session_ || !data || len == 0) return -1;
    BYTE* slot = pAllocateSend(session_, static_cast<DWORD>(len));
    if (!slot) return -1;  // Ring full or session ended.
    std::memcpy(slot, data, len);
    pSend(session_, slot);
    return static_cast<int>(len);
}

void Tun::close() {
    if (running_.exchange(false)) {
        if (stop_event_) SetEvent(static_cast<HANDLE>(stop_event_));
        if (worker_.joinable()) worker_.join();
    }
    if (async_active_) {
        uv_close(reinterpret_cast<uv_handle_t*>(&async_), nullptr);
        async_active_ = false;
    }
    if (session_) {
        pEndSession(session_);
        session_ = nullptr;
    }
    if (adapter_) {
        pClose(adapter_);
        adapter_ = nullptr;
    }
    if (stop_event_) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
    }
    read_event_ = nullptr;
}

}  // namespace nospoon

#endif  // _WIN32
