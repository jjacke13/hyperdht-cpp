#pragma once
// Full-tunnel routing/NAT/DNS plumbing.
//
// Linux: stubs (current Linux nospoon doesn't yet do full-tunnel).
// Windows: ports nospoon/lib/full-tunnel-windows.js — split routes,
//          NAT, NRPT DNS, IPv6 leak prevention.
//
// Per-process state is held internally; calls are not reentrant.

#include <string>

namespace nospoon::full_tunnel {

// SERVER: enable IP forwarding on the TUN + outbound interface,
// install a NAT rule mapping `subnet` (e.g. "10.0.0.0/24").
// out_iface may be empty to skip forwarding-flag toggle on it.
// Returns true if forwarding succeeded; NAT might still be unavailable
// (e.g. Windows Home / WMI broken) — that's logged but non-fatal.
bool enable_server_forwarding(const std::string& tun_name,
                              const std::string& subnet,
                              const std::string& out_iface);

void disable_server_forwarding();

// CLIENT: redirect all traffic through the TUN, except a host route
// to remote_host (the DHT server's public IP) which keeps going via
// the original default gateway.
bool enable_client_full_tunnel(const std::string& tun_name,
                               const std::string& remote_host);

// Add another exemption (e.g. a DHT bootstrap node we want reachable
// off-tunnel). No-op if the remote_host is already exempted or
// full-tunnel was never enabled.
void add_host_exemption(const std::string& remote_host);

void disable_client_full_tunnel();

}  // namespace nospoon::full_tunnel
