#pragma once
// Windows TUN device backed by Wintun. Same public API as tun_linux.hpp.
// Requires Administrator privileges (Wintun installs its kernel driver
// on the first WintunCreateAdapter call).

#ifndef _WIN32
#error "tun_windows.hpp included on a non-Windows platform"
#endif

#include <uv.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace nospoon {

class Tun {
public:
    using OnPacketCb = std::function<void(const uint8_t* data, size_t len)>;

    Tun() = default;
    ~Tun();

    Tun(const Tun&) = delete;
    Tun& operator=(const Tun&) = delete;

    // Open Wintun adapter "Nospoon", configure IPv4 + MTU via netsh.
    // ip_cidr: "10.0.0.1/24" — IPv4 only at the moment.
    // Returns 0 on success, -1 on error.
    int open(const std::string& ip_cidr, int mtu);

    // Spin up the worker thread that waits on the wintun read event and
    // wakes the libuv loop via uv_async_t. on_packet runs on the loop thread.
    void start(uv_loop_t* loop, OnPacketCb on_packet);

    // Write an IP packet to the adapter. Returns bytes written or -1.
    int write(const uint8_t* data, size_t len);

    // Tear down: stops worker, ends session, closes adapter.
    void close();

    const std::string& name() const { return name_; }
    int mtu() const { return mtu_; }

private:
    static void on_async(uv_async_t* handle);
    void worker_loop();

    // void* to avoid leaking <windows.h> through this header.
    void* adapter_     = nullptr;  // WINTUN_ADAPTER_HANDLE
    void* session_     = nullptr;  // WINTUN_SESSION_HANDLE
    void* read_event_  = nullptr;  // HANDLE owned by session — do not close
    void* stop_event_  = nullptr;  // HANDLE we own; signal to stop worker

    int mtu_ = 1400;
    std::string name_ = "Nospoon";

    uv_async_t async_{};
    bool async_active_ = false;
    OnPacketCb on_packet_;

    std::thread worker_;
    std::atomic<bool> running_{false};
};

}  // namespace nospoon
