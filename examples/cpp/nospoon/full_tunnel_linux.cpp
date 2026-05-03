#ifndef _WIN32
#ifndef __APPLE__

// Direct port of nospoon/lib/full-tunnel-linux.js.
//
// Shell-outs use std::system → /bin/sh. The interface names we feed in
// come from validated config (validateInterface caller-side), and IPs come
// from local trusted config. If any of these ever start coming from network
// input, switch to fork+execvp with a real argv array.

#include "full_tunnel.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace nospoon::full_tunnel {

namespace {

// ---------------------------------------------------------------------------
// State (per-process; functions are not reentrant)
// ---------------------------------------------------------------------------

struct ServerState {
    bool active = false;
    std::string iface;    // outbound interface (e.g. eth0)
    std::string source;   // subnet (e.g. 10.0.0.0/24)
    std::string tun_name; // TUN device (e.g. tun0)
};

struct ClientState {
    bool active = false;
    std::string tun_name;
    std::string gateway;        // saved default-gateway IP
    std::string gateway_device; // saved default-gateway interface
    std::vector<std::string> remote_hosts;
    std::string saved_rp_filter;   // value of net.ipv4.conf.all.rp_filter
    std::string saved_resolv_conf; // /etc/resolv.conf contents (resolvconf path)
    std::string dns_method;        // "resolvectl" or "resolvconf"
};

ServerState g_server;
ClientState g_client;

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

// Capture trimmed stdout. Returns "" on failure.
std::string popen_capture(const std::string& cmd) {
    FILE* p = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!p) return {};
    char buf[1024];
    std::string out;
    while (std::fgets(buf, sizeof(buf), p)) out += buf;
    pclose(p);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                            out.back() == ' '  || out.back() == '\t')) {
        out.pop_back();
    }
    return out;
}

// Run a command silently. Returns exit code.
int run(const std::string& cmd) {
    std::string c = cmd + " >/dev/null 2>&1";
    return std::system(c.c_str());
}

// "Strict" run — print to stderr if command fails, return false.
bool run_strict(const std::string& cmd) {
    int rc = run(cmd);
    if (rc != 0) {
        std::fprintf(stderr, "Command failed: %s (exit %d)\n", cmd.c_str(), rc);
        return false;
    }
    return true;
}

bool has_resolvectl() {
    return run("which resolvectl") == 0;
}

struct GatewayInfo {
    std::string gateway;
    std::string device;
    bool valid() const { return !gateway.empty() && !device.empty(); }
};

GatewayInfo get_default_gateway() {
    GatewayInfo gw;
    std::string line = popen_capture("ip route show default");
    if (line.empty()) return gw;
    // Match "via X.X.X.X" and "dev iface".
    std::smatch m;
    std::regex via_re(R"(via\s+(\S+))");
    std::regex dev_re(R"(dev\s+(\S+))");
    if (std::regex_search(line, m, via_re)) gw.gateway = m[1].str();
    if (std::regex_search(line, m, dev_re)) gw.device  = m[1].str();
    return gw;
}

}  // namespace

// =========================================================================
// SERVER: NAT masquerading
// =========================================================================

bool enable_server_forwarding(const std::string& tun_name_arg,
                              const std::string& subnet_arg,
                              const std::string& out_iface_arg) {
    std::string iface = out_iface_arg;
    if (iface.empty()) {
        auto gw = get_default_gateway();
        iface = gw.device;
    }
    if (iface.empty()) {
        std::fprintf(stderr,
            "Cannot detect outgoing interface. Set \"outInterface\" in config.\n");
        return false;
    }

    std::string tun_name = tun_name_arg.empty() ? "tun0" : tun_name_arg;
    std::string source   = subnet_arg.empty()   ? "10.0.0.0/24" : subnet_arg;

    std::fprintf(stderr,
        "Enabling IP forwarding and NAT on %s...\n", iface.c_str());

    if (!run_strict("sysctl -w net.ipv4.ip_forward=1")) return false;
    if (!run_strict("iptables -t nat -A POSTROUTING -s " + source +
                    " -o " + iface + " -j MASQUERADE")) return false;
    if (!run_strict("iptables -A FORWARD -i " + tun_name +
                    " -o " + iface + " -j ACCEPT")) return false;
    if (!run_strict("iptables -A FORWARD -i " + iface +
                    " -o " + tun_name +
                    " -m state --state RELATED,ESTABLISHED -j ACCEPT")) return false;

    std::fprintf(stderr,
        "NAT enabled — clients can access the internet through this server\n");

    g_server = {true, iface, source, tun_name};
    return true;
}

void disable_server_forwarding() {
    if (!g_server.active) return;
    std::fprintf(stderr, "Removing NAT rules...\n");

    run("iptables -t nat -D POSTROUTING -s " + g_server.source +
        " -o " + g_server.iface + " -j MASQUERADE");
    run("iptables -D FORWARD -i " + g_server.tun_name +
        " -o " + g_server.iface + " -j ACCEPT");
    run("iptables -D FORWARD -i " + g_server.iface +
        " -o " + g_server.tun_name +
        " -m state --state RELATED,ESTABLISHED -j ACCEPT");

    g_server = {};
}

// =========================================================================
// CLIENT: split routes + DNS + IPv6 leak prevention
// =========================================================================

bool enable_client_full_tunnel(const std::string& tun_name_arg,
                               const std::string& remote_host) {
    if (remote_host.empty()) {
        std::fprintf(stderr,
            "Cannot determine DHT server address for host route\n");
        return false;
    }
    std::string tun_name = tun_name_arg.empty() ? "tun0" : tun_name_arg;

    auto gw = get_default_gateway();
    if (!gw.valid()) {
        std::fprintf(stderr, "Cannot detect default gateway\n");
        return false;
    }

    g_client.active = true;
    g_client.tun_name = tun_name;
    g_client.gateway = gw.gateway;
    g_client.gateway_device = gw.device;

    std::fprintf(stderr,
        "Routing all traffic through tunnel "
        "(server %s exempted via host route)\n",
        remote_host.c_str());

    // Loosen reverse-path filtering so packets arriving on TUN aren't dropped
    // when their reply path would go via the original gateway.
    g_client.saved_rp_filter =
        popen_capture("sysctl -n net.ipv4.conf.all.rp_filter");
    run_strict("sysctl -w net.ipv4.conf.all.rp_filter=2");

    // Host route: DHT server stays on real gateway.
    if (!run_strict("ip route add " + remote_host + "/32 via " +
                    gw.gateway + " dev " + gw.device)) {
        // Don't fully bail — it might already exist from a previous run.
    }
    g_client.remote_hosts.push_back(remote_host);

    // Split routes: 0.0.0.0/1 + 128.0.0.0/1 cover all of IPv4 with a
    // more-specific match than the existing 0.0.0.0/0 default.
    if (!run_strict("ip route add 0.0.0.0/1 dev " + tun_name)) return false;
    if (!run_strict("ip route add 128.0.0.0/1 dev " + tun_name)) return false;

    // IPv6 blackhole through TUN to prevent leaks (matches WireGuard).
    run("ip -6 route add ::/1 dev " + tun_name);
    run("ip -6 route add 8000::/1 dev " + tun_name);

    // DNS: prefer systemd-resolved on the TUN interface; fall back to
    // overwriting /etc/resolv.conf entirely.
    if (has_resolvectl()) {
        g_client.dns_method = "resolvectl";
        run_strict("resolvectl dns " + tun_name + " 1.1.1.1 8.8.8.8");
        run_strict("resolvectl domain " + tun_name + " '~.'");
        std::fprintf(stderr,
            "DNS set via resolvectl on %s: 1.1.1.1, 8.8.8.8\n",
            tun_name.c_str());
    } else {
        g_client.dns_method = "resolvconf";
        // Save existing resolv.conf for restore.
        std::ifstream in("/etc/resolv.conf");
        if (in.is_open()) {
            std::stringstream buf;
            buf << in.rdbuf();
            g_client.saved_resolv_conf = buf.str();
        }
        std::ofstream out("/etc/resolv.conf");
        if (out.is_open()) {
            out << "# nospoon full-tunnel DNS\n"
                << "nameserver 1.1.1.1\n"
                << "nameserver 8.8.8.8\n";
            std::fprintf(stderr,
                "DNS set via /etc/resolv.conf: 1.1.1.1, 8.8.8.8\n");
        } else {
            std::fprintf(stderr,
                "WARNING: could not write /etc/resolv.conf — DNS unchanged\n");
        }
    }

    std::fprintf(stderr,
        "Full tunnel active — all traffic goes through VPN (kill switch enabled)\n");
    return true;
}

void add_host_exemption(const std::string& remote_host) {
    if (!g_client.active || remote_host.empty() ||
        g_client.gateway.empty() || g_client.gateway_device.empty()) return;
    for (const auto& h : g_client.remote_hosts) {
        if (h == remote_host) return;
    }
    if (run("ip route add " + remote_host + "/32 via " +
            g_client.gateway + " dev " + g_client.gateway_device) == 0) {
        g_client.remote_hosts.push_back(remote_host);
        std::fprintf(stderr,
            "Added host route exemption for %s\n", remote_host.c_str());
    }
}

void disable_client_full_tunnel() {
    if (!g_client.active) return;
    std::fprintf(stderr, "Restoring original routes...\n");

    const std::string& tun = g_client.tun_name;

    run("ip route del 128.0.0.0/1 dev " + tun);
    run("ip route del 0.0.0.0/1 dev " + tun);
    run("ip -6 route del ::/1 dev " + tun);
    run("ip -6 route del 8000::/1 dev " + tun);

    for (const auto& host : g_client.remote_hosts) {
        run("ip route del " + host + "/32 via " + g_client.gateway);
    }

    if (!g_client.saved_rp_filter.empty()) {
        run("sysctl -w net.ipv4.conf.all.rp_filter=" + g_client.saved_rp_filter);
    }

    if (g_client.dns_method == "resolvectl") {
        run("resolvectl revert " + tun);
        std::fprintf(stderr, "DNS restored via resolvectl\n");
    } else if (g_client.dns_method == "resolvconf" &&
               !g_client.saved_resolv_conf.empty()) {
        std::ofstream out("/etc/resolv.conf");
        if (out.is_open()) {
            out << g_client.saved_resolv_conf;
            std::fprintf(stderr, "DNS restored via /etc/resolv.conf\n");
        }
    }

    g_client = {};
}

}  // namespace nospoon::full_tunnel

#endif  // !__APPLE__
#endif  // !_WIN32
