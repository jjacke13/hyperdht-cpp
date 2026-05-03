#ifdef __APPLE__

// Direct port of nospoon/lib/full-tunnel-darwin.js.
//
// Server: sysctl net.inet.ip.forwarding + pfctl NAT (rules injected into
//   /etc/pf.conf so they live in the main ruleset — pf anchors don't NAT
//   forwarded packets).
// Client: route add for split routes (0.0.0.0/1 + 128.0.0.0/1), DNS via
//   networksetup against the discovered network service name, IPv6
//   blackhole, host exemption for the DHT server.

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

struct ServerState {
    bool active = false;
    std::string iface;
    std::string source;
    std::string tun_name;
};

struct ClientState {
    bool active = false;
    std::string tun_name;
    std::string gateway;
    std::vector<std::string> remote_hosts;
    std::string network_service;          // e.g. "Wi-Fi"
    std::vector<std::string> saved_dns;   // DNS we displaced
};

ServerState g_server;
ClientState g_client;

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

int run(const std::string& cmd) {
    std::string c = cmd + " >/dev/null 2>&1";
    return std::system(c.c_str());
}

bool run_strict(const std::string& cmd) {
    int rc = run(cmd);
    if (rc != 0) {
        std::fprintf(stderr, "Command failed: %s (exit %d)\n", cmd.c_str(), rc);
        return false;
    }
    return true;
}

struct GatewayInfo {
    std::string gateway;
    std::string device;
    bool valid() const { return !gateway.empty() && !device.empty(); }
};

GatewayInfo get_default_gateway() {
    GatewayInfo gw;
    std::string out = popen_capture("route -n get default");
    if (out.empty()) return gw;
    std::smatch m;
    std::regex gw_re(R"(gateway:\s*(\S+))");
    std::regex if_re(R"(interface:\s*(\S+))");
    if (std::regex_search(out, m, gw_re)) gw.gateway = m[1].str();
    if (std::regex_search(out, m, if_re)) gw.device  = m[1].str();
    return gw;
}

// macOS DNS lives behind networksetup, keyed by "network service" names
// like "Wi-Fi" or "Ethernet". Walk `networksetup -listallhardwareports` to
// find which service maps to the given device (e.g. "en0" → "Wi-Fi").
std::string get_network_service_for_device(const std::string& device) {
    std::string out = popen_capture("networksetup -listallhardwareports");
    if (out.empty()) return {};
    std::stringstream ss(out);
    std::string line, current_port;
    while (std::getline(ss, line)) {
        std::smatch m;
        std::regex port_re(R"(Hardware Port:\s*(.+?)\s*$)");
        std::regex dev_re(R"(Device:\s*(\S+))");
        if (std::regex_search(line, m, port_re)) current_port = m[1].str();
        else if (std::regex_search(line, m, dev_re) && m[1].str() == device) {
            return current_port;
        }
    }
    return {};
}

std::vector<std::string> get_dns(const std::string& service) {
    std::vector<std::string> out;
    std::string raw = popen_capture("networksetup -getdnsservers \"" + service + "\"");
    if (raw.empty() || raw.find("aren't any") != std::string::npos) return out;
    std::stringstream ss(raw);
    std::string line;
    while (std::getline(ss, line)) {
        // trim
        size_t s = line.find_first_not_of(" \t");
        size_t e = line.find_last_not_of(" \t\r\n");
        if (s == std::string::npos) continue;
        out.push_back(line.substr(s, e - s + 1));
    }
    return out;
}

}  // namespace

// =========================================================================
// SERVER: NAT via pfctl
// =========================================================================

bool enable_server_forwarding(const std::string& tun_name_arg,
                              const std::string& subnet_arg,
                              const std::string& out_iface_arg) {
    std::string iface = out_iface_arg;
    if (iface.empty()) iface = get_default_gateway().device;
    if (iface.empty()) {
        std::fprintf(stderr,
            "Cannot detect outgoing interface. Set \"outInterface\" in config.\n");
        return false;
    }

    std::string tun_name = tun_name_arg.empty() ? "utun0" : tun_name_arg;
    std::string source   = subnet_arg.empty()   ? "10.0.0.0/24" : subnet_arg;

    std::fprintf(stderr,
        "Enabling IP forwarding and NAT on %s...\n", iface.c_str());

    if (!run_strict("sysctl -w net.inet.ip.forwarding=1")) return false;

    // pf anchors won't NAT forwarded packets — rules must live in the main
    // ruleset. Read /etc/pf.conf, inject our nat + pass rules, write to a
    // temp file, load with pfctl -f.
    std::ifstream pfin("/etc/pf.conf");
    if (!pfin.is_open()) {
        std::fprintf(stderr, "Cannot read /etc/pf.conf\n");
        return false;
    }
    std::stringstream pfbuf;
    pfbuf << pfin.rdbuf();
    pfin.close();

    std::string nat_rule = "nat on " + iface + " from " + source +
                            " to any -> (" + iface + ")";
    std::string pass_in  = "pass in quick on "  + tun_name + " all";
    std::string pass_out = "pass out quick on " + iface    + " all";

    // Find last "nat-anchor" line and "load anchor" line.
    std::vector<std::string> lines;
    {
        std::string s;
        std::string raw = pfbuf.str();
        std::stringstream ss(raw);
        while (std::getline(ss, s)) lines.push_back(s);
    }
    int last_nat_anchor = -1, load_anchor = -1;
    std::regex na_re(R"(^nat-anchor\s)");
    std::regex la_re(R"(^load anchor\s)");
    for (size_t i = 0; i < lines.size(); i++) {
        if (std::regex_search(lines[i], na_re)) last_nat_anchor = (int)i;
        if (std::regex_search(lines[i], la_re)) load_anchor     = (int)i;
    }

    std::vector<std::string> result;
    for (size_t i = 0; i < lines.size(); i++) {
        result.push_back(lines[i]);
        if ((int)i == last_nat_anchor) result.push_back(nat_rule);
    }
    int insert_at = (load_anchor >= 0)
        ? (int)(result.size() - (lines.size() - load_anchor))
        : (int)result.size();
    if (insert_at < 0) insert_at = (int)result.size();
    result.insert(result.begin() + insert_at, pass_in);
    result.insert(result.begin() + insert_at + 1, pass_out);

    std::string tmp_path = "/tmp/nospoon-pf.conf";
    {
        std::ofstream out(tmp_path);
        if (!out.is_open()) {
            std::fprintf(stderr, "Cannot write %s\n", tmp_path.c_str());
            return false;
        }
        for (const auto& l : result) out << l << "\n";
    }

    if (!run_strict("pfctl -f " + tmp_path)) {
        std::remove(tmp_path.c_str());
        return false;
    }
    run("pfctl -e");  // enable pf if not already on (returns nonzero if already on)
    std::remove(tmp_path.c_str());

    std::fprintf(stderr,
        "NAT enabled — clients can access the internet through this server\n");

    g_server = {true, iface, source, tun_name};
    return true;
}

void disable_server_forwarding() {
    if (!g_server.active) return;
    std::fprintf(stderr, "Removing NAT rules...\n");
    // Restore original pf.conf (drops our injected rules).
    run("pfctl -f /etc/pf.conf");
    g_server = {};
}

// =========================================================================
// CLIENT: split routes + DNS via networksetup + IPv6 blackhole
// =========================================================================

bool enable_client_full_tunnel(const std::string& tun_name_arg,
                               const std::string& remote_host) {
    if (remote_host.empty()) {
        std::fprintf(stderr,
            "Cannot determine DHT server address for host route\n");
        return false;
    }
    std::string tun_name = tun_name_arg.empty() ? "utun0" : tun_name_arg;

    auto gw = get_default_gateway();
    if (!gw.valid()) {
        std::fprintf(stderr, "Cannot detect default gateway\n");
        return false;
    }

    g_client.active = true;
    g_client.tun_name = tun_name;
    g_client.gateway = gw.gateway;

    std::fprintf(stderr,
        "Routing all traffic through tunnel "
        "(server %s exempted via host route)\n",
        remote_host.c_str());

    if (!run_strict("route add -host " + remote_host + " " + gw.gateway)) {
        // Maybe already added — keep going.
    }
    g_client.remote_hosts.push_back(remote_host);

    if (!run_strict("route add -net 0.0.0.0/1 -interface " + tun_name)) return false;
    if (!run_strict("route add -net 128.0.0.0/1 -interface " + tun_name)) return false;

    // IPv6 blackhole — packets land on TUN, get silently dropped.
    run("route add -inet6 -net ::/1 -interface " + tun_name);
    run("route add -inet6 -net 8000::/1 -interface " + tun_name);

    // DNS via networksetup against the discovered network service.
    std::string service = get_network_service_for_device(gw.device);
    if (!service.empty()) {
        g_client.network_service = service;
        g_client.saved_dns = get_dns(service);
        run("networksetup -setdnsservers \"" + service + "\" 1.1.1.1 8.8.8.8");
        std::fprintf(stderr,
            "DNS set to 1.1.1.1, 8.8.8.8 on '%s'\n", service.c_str());
    }

    std::fprintf(stderr,
        "Full tunnel active — all traffic goes through VPN (kill switch enabled)\n");
    return true;
}

void add_host_exemption(const std::string& remote_host) {
    if (!g_client.active || remote_host.empty() || g_client.gateway.empty()) return;
    for (const auto& h : g_client.remote_hosts) {
        if (h == remote_host) return;
    }
    if (run("route add -host " + remote_host + " " + g_client.gateway) == 0) {
        g_client.remote_hosts.push_back(remote_host);
        std::fprintf(stderr,
            "Added host route exemption for %s\n", remote_host.c_str());
    }
}

void disable_client_full_tunnel() {
    if (!g_client.active) return;
    std::fprintf(stderr, "Restoring original routes...\n");

    const std::string& tun = g_client.tun_name;
    run("route delete -net 128.0.0.0/1 -interface " + tun);
    run("route delete -net 0.0.0.0/1 -interface " + tun);
    run("route delete -inet6 -net ::/1 -interface " + tun);
    run("route delete -inet6 -net 8000::/1 -interface " + tun);

    for (const auto& h : g_client.remote_hosts) {
        run("route delete -host " + h + " " + g_client.gateway);
    }

    if (!g_client.network_service.empty()) {
        std::string args = g_client.saved_dns.empty() ? "Empty" : "";
        for (const auto& d : g_client.saved_dns) {
            if (!args.empty()) args += " ";
            args += d;
        }
        run("networksetup -setdnsservers \"" + g_client.network_service +
            "\" " + args);
        std::fprintf(stderr, "DNS restored\n");
    }

    g_client = {};
}

}  // namespace nospoon::full_tunnel

#endif  // __APPLE__
