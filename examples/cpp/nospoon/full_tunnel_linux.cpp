#ifndef _WIN32

// Linux full-tunnel stubs. The current Linux nospoon doesn't manipulate
// the routing table or DNS — peer→peer packet forwarding only. These
// no-ops keep the cross-platform call sites compiling; future work to
// implement properly with iproute2 / systemd-resolved.

#include "full_tunnel.hpp"

namespace nospoon::full_tunnel {

bool enable_server_forwarding(const std::string&, const std::string&,
                              const std::string&) {
    return true;
}

void disable_server_forwarding() {}

bool enable_client_full_tunnel(const std::string&, const std::string&) {
    return true;
}

void add_host_exemption(const std::string&) {}

void disable_client_full_tunnel() {}

}  // namespace nospoon::full_tunnel

#endif  // !_WIN32
