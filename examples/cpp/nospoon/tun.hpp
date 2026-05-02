#pragma once
// Platform facade for the TUN device. Both backends expose the same
// nospoon::Tun class with: open(ip_cidr, mtu) → 0/-1,
// start(loop, OnPacketCb), write(data, len), close(), name(), mtu().

#ifdef _WIN32
#include "tun_windows.hpp"
#else
#include "tun_linux.hpp"
#endif
