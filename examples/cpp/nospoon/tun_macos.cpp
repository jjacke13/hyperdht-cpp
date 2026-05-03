#ifdef __APPLE__

// macOS utun backend. Mirrors nospoon/lib/tun-darwin.js (which uses koffi
// to call the same syscalls). The dance:
//   socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
//   ioctl(CTLIOCGINFO) to look up "com.apple.net.utun_control"
//   connect() with sockaddr_ctl{sc_unit=0} → kernel auto-assigns utunN
//   getsockopt(UTUN_OPT_IFNAME) → readable name
// Then ifconfig for IP/MTU, just like the Linux backend uses `ip`.

#include "tun_macos.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nospoon {

namespace {

int open_utun(std::string& name_out) {
    int fd = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        std::perror("socket(PF_SYSTEM)");
        return -1;
    }

    struct ctl_info info{};
    std::strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
    if (::ioctl(fd, CTLIOCGINFO, &info) < 0) {
        std::perror("ioctl(CTLIOCGINFO)");
        ::close(fd);
        return -1;
    }

    struct sockaddr_ctl addr{};
    addr.sc_len     = sizeof(addr);
    addr.sc_family  = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id      = info.ctl_id;
    addr.sc_unit    = 0;  // 0 = let the kernel pick the next free utunN

    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr),
                  sizeof(addr)) < 0) {
        std::perror("connect(utun) — must run as root");
        ::close(fd);
        return -1;
    }

    char ifname[IFNAMSIZ + 1] = {0};
    socklen_t ifname_len = sizeof(ifname) - 1;
    if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
                     ifname, &ifname_len) < 0) {
        std::perror("getsockopt(UTUN_OPT_IFNAME)");
        ::close(fd);
        return -1;
    }
    name_out = ifname;
    return fd;
}

}  // namespace

Tun::~Tun() { close(); }

int Tun::open(const std::string& ip_cidr, int mtu,
              const std::string& ipv6_cidr) {
    fd_ = open_utun(name_);
    if (fd_ < 0) return -1;

    // Parse "10.0.0.1/24" → addr + dotted-netmask (ifconfig wants both).
    auto slash = ip_cidr.find('/');
    std::string ip_addr = (slash != std::string::npos)
                              ? ip_cidr.substr(0, slash) : ip_cidr;
    int prefix = 24;
    if (slash != std::string::npos) {
        prefix = std::atoi(ip_cidr.substr(slash + 1).c_str());
    }
    if (prefix < 0 || prefix > 32) {
        std::fprintf(stderr, "Invalid prefix: %d\n", prefix);
        ::close(fd_); fd_ = -1; return -1;
    }
    uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    char netmask[16];
    std::snprintf(netmask, sizeof(netmask), "%u.%u.%u.%u",
                  (mask >> 24) & 0xff, (mask >> 16) & 0xff,
                  (mask >> 8) & 0xff,  mask & 0xff);

    char cmd[256];

    // utun is a point-to-point interface; pass the same address as both
    // local and "destination" — matches the JS impl and standard utun usage.
    std::snprintf(cmd, sizeof(cmd),
                  "ifconfig %s inet %s %s netmask %s up",
                  name_.c_str(), ip_addr.c_str(), ip_addr.c_str(), netmask);
    if (std::system(cmd) != 0) {
        std::fprintf(stderr, "Failed: %s\n", cmd);
        ::close(fd_); fd_ = -1; return -1;
    }

    if (!ipv6_cidr.empty()) {
        std::snprintf(cmd, sizeof(cmd),
                      "ifconfig %s inet6 %s",
                      name_.c_str(), ipv6_cidr.c_str());
        if (std::system(cmd) != 0) {
            std::fprintf(stderr, "Failed: %s\n", cmd);
            // IPv6 optional — keep going.
        }
    }

    std::snprintf(cmd, sizeof(cmd), "ifconfig %s mtu %d",
                  name_.c_str(), mtu);
    if (std::system(cmd) != 0) {
        std::fprintf(stderr, "Failed: %s\n", cmd);
        ::close(fd_); fd_ = -1; return -1;
    }

    mtu_ = mtu;
    if (ipv6_cidr.empty()) {
        std::fprintf(stderr, "  TUN %s opened (%s, MTU %d)\n",
                     name_.c_str(), ip_cidr.c_str(), mtu);
    } else {
        std::fprintf(stderr, "  TUN %s opened (%s + %s, MTU %d)\n",
                     name_.c_str(), ip_cidr.c_str(), ipv6_cidr.c_str(), mtu);
    }
    return 0;
}

void Tun::start(uv_loop_t* loop, OnPacketCb on_packet) {
    if (fd_ < 0) return;
    on_packet_ = std::move(on_packet);
    uv_poll_init(loop, &poll_, fd_);
    poll_.data = this;
    uv_poll_start(&poll_, UV_READABLE, on_poll);
    poll_active_ = true;
}

void Tun::on_poll(uv_poll_t* handle, int status, int events) {
    if (status < 0) return;
    auto* self = static_cast<Tun*>(handle->data);
    if (!(events & UV_READABLE)) return;

    uint8_t buf[65536];
    auto n = ::read(self->fd_, buf, sizeof(buf));
    if (n <= 4) return;  // header alone, no payload — drop

    // Strip the 4-byte protocol-family prefix and pass the bare IP packet up.
    if (self->on_packet_) {
        self->on_packet_(buf + 4, static_cast<size_t>(n - 4));
    }
}

int Tun::write(const uint8_t* data, size_t len) {
    if (fd_ < 0 || !data || len == 0) return -1;

    // Pick AF from the IP version field; prepend the 4-byte BE header.
    uint8_t version = (data[0] >> 4) & 0x0f;
    uint32_t af_be;
    if (version == 4)      af_be = htonl(AF_INET);
    else if (version == 6) af_be = htonl(AF_INET6);
    else return -1;

    struct iovec iov[2];
    iov[0].iov_base = &af_be;
    iov[0].iov_len  = sizeof(af_be);
    iov[1].iov_base = const_cast<uint8_t*>(data);
    iov[1].iov_len  = len;

    auto n = ::writev(fd_, iov, 2);
    return (n < 4) ? -1 : static_cast<int>(n - 4);
}

void Tun::close() {
    if (poll_active_) {
        uv_poll_stop(&poll_);
        poll_active_ = false;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

}  // namespace nospoon

#endif  // __APPLE__
