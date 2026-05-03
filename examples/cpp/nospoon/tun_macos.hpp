#pragma once
// macOS TUN device backed by the kernel's utun (PF_SYSTEM/com.apple.net.utun_control).
// Same public API as tun_linux.hpp / tun_windows.hpp.

#ifndef __APPLE__
#error "tun_macos.hpp included on a non-macOS platform"
#endif

#include <uv.h>

#include <cstdint>
#include <functional>
#include <string>

namespace nospoon {

class Tun {
public:
    using OnPacketCb = std::function<void(const uint8_t* data, size_t len)>;

    Tun() = default;
    ~Tun();

    Tun(const Tun&) = delete;
    Tun& operator=(const Tun&) = delete;

    // Open utunN, configure IPv4 (+ optional IPv6) + MTU via ifconfig.
    int open(const std::string& ip_cidr, int mtu,
             const std::string& ipv6_cidr = {});

    void start(uv_loop_t* loop, OnPacketCb on_packet);

    // utun frames each packet with a 4-byte protocol-family header — this
    // wrapper transparently prepends/strips it. Caller passes/receives raw
    // IP packets just like the Linux/Windows backends.
    int write(const uint8_t* data, size_t len);

    void close();

    const std::string& name() const { return name_; }
    int mtu() const { return mtu_; }

private:
    static void on_poll(uv_poll_t* handle, int status, int events);

    int fd_ = -1;
    int mtu_ = 1400;
    std::string name_;
    OnPacketCb on_packet_;
    uv_poll_t poll_{};
    bool poll_active_ = false;
};

}  // namespace nospoon
