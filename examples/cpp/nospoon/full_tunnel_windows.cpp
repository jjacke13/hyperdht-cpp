#ifdef _WIN32

// Direct port of nospoon/lib/full-tunnel-windows.js.
//
// All shell-outs use std::system (which goes through cmd.exe). Adapter
// names and remote_host strings come from a local user-controlled config
// file, so we trust them — but if any of these values ever start coming
// from a network source, switch to CreateProcess with a proper argv array.

#include "full_tunnel.hpp"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace nospoon::full_tunnel {

namespace {

// State for client mode (full-tunnel).
struct ClientState {
    bool active = false;
    std::string tun_name;
    std::string tun_if_index;     // numeric, captured at enable time
    std::string gateway;          // dotted IP of original default gateway
    std::string gateway_if_index; // numeric
    std::vector<std::string> remote_hosts;  // routes we exempted
    std::string nrpt_rule_name;   // for targeted DNS NRPT removal
};

// State for server mode (NAT).
struct ServerState {
    bool active = false;
    std::string tun_name;
    std::string out_iface;
    bool nat_via_netnat = false;
};

ClientState g_client;
ServerState g_server;

// Write a PowerShell snippet to a uniquely-named temp .ps1 file.
// Returns the path; caller must DeleteFileA when done. Empty on failure.
//
// We go through a file rather than `powershell -Command "..."` because the
// cmd.exe → powershell.exe quote-escaping is notoriously fragile (the JS
// impl avoids this by using execFile with a real argv). A temp .ps1 file
// dodges shell-escaping entirely.
std::string write_temp_ps1(const std::string& script) {
    char temp_dir[MAX_PATH];
    if (GetTempPathA(MAX_PATH, temp_dir) == 0) return {};
    char temp_file[MAX_PATH];
    if (GetTempFileNameA(temp_dir, "nsp", 0, temp_file) == 0) return {};
    // GetTempFileNameA created an empty .tmp; rename to .ps1 so PowerShell
    // recognizes it. We just write to a sibling path and delete the .tmp.
    std::string ps1_path = std::string(temp_file) + ".ps1";
    DeleteFileA(temp_file);
    FILE* fp = std::fopen(ps1_path.c_str(), "wb");
    if (!fp) return {};
    std::fwrite(script.data(), 1, script.size(), fp);
    std::fclose(fp);
    return ps1_path;
}

// Run a PowerShell snippet, capture its trimmed stdout (first non-empty
// line, or empty on failure). Stderr is captured into a buffer and emitted
// to our stderr only on failure for visibility.
std::string ps_capture(const std::string& script) {
    auto path = write_temp_ps1(script);
    if (path.empty()) {
        std::fprintf(stderr, "ps_capture: failed to write temp script\n");
        return {};
    }

    // -ExecutionPolicy Bypass so the .ps1 isn't blocked by per-machine policy.
    // Capture stderr as well (2>&1) so a script error explains itself.
    std::string cmd = "powershell -NoProfile -NoLogo -ExecutionPolicy Bypass "
                      "-File \"" + path + "\" 2>&1";

    FILE* pipe = _popen(cmd.c_str(), "r");
    std::string out;
    if (pipe) {
        char buf[512];
        while (std::fgets(buf, sizeof(buf), pipe)) out += buf;
        _pclose(pipe);
    }
    DeleteFileA(path.c_str());

    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                            out.back() == ' '  || out.back() == '\t')) {
        out.pop_back();
    }
    return out;
}

// Run a command silently. Returns std::system() exit code.
int run_silent(const std::string& cmd) {
    std::string c = cmd + " > NUL 2>&1";
    return std::system(c.c_str());
}

// Run a PowerShell snippet without capturing stdout.
int run_ps(const std::string& script) {
    auto path = write_temp_ps1(script);
    if (path.empty()) return -1;
    std::string cmd = "powershell -NoProfile -NoLogo -ExecutionPolicy Bypass "
                      "-File \"" + path + "\" > NUL 2>&1";
    int rc = std::system(cmd.c_str());
    DeleteFileA(path.c_str());
    return rc;
}

// Returns "<gateway>|<ifIndex>" or empty string.
std::string get_default_gateway() {
    return ps_capture(
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "Select-Object -First 1; \"$($r.NextHop)|$($r.InterfaceIndex)\"");
}

std::string get_tun_if_index(const std::string& tun_name) {
    return ps_capture("(Get-NetAdapter -Name '" + tun_name + "').ifIndex");
}

// Split "a|b" into a pair of strings.
bool split_pipe(const std::string& s, std::string& a, std::string& b) {
    auto p = s.find('|');
    if (p == std::string::npos) return false;
    a = s.substr(0, p);
    b = s.substr(p + 1);
    if (a.empty() || b.empty()) return false;
    return true;
}

}  // namespace

// =========================================================================
// SERVER: NAT forwarding
// =========================================================================

bool enable_server_forwarding(const std::string& tun_name_arg,
                              const std::string& subnet_arg,
                              const std::string& out_iface) {
    const std::string tun_name = tun_name_arg.empty() ? "Nospoon" : tun_name_arg;
    const std::string subnet   = subnet_arg.empty()   ? "10.0.0.0/24" : subnet_arg;

    std::fprintf(stderr, "Enabling IP forwarding and NAT...\n");

    if (run_silent("netsh interface ipv4 set interface \"" + tun_name +
                   "\" forwarding=enabled") != 0) {
        std::fprintf(stderr, "Failed to enable forwarding on %s\n", tun_name.c_str());
        return false;
    }
    if (!out_iface.empty()) {
        if (run_silent("netsh interface ipv4 set interface \"" + out_iface +
                       "\" forwarding=enabled") != 0) {
            std::fprintf(stderr, "Failed to enable forwarding on %s\n",
                         out_iface.c_str());
            return false;
        }
    }

    // Try New-NetNat. May fail on Home/broken WMI; non-fatal.
    int nat_rc = run_ps("New-NetNat -Name 'NospoonNAT' "
                        "-InternalIPInterfaceAddressPrefix '" + subnet + "'");
    g_server.nat_via_netnat = (nat_rc == 0);
    if (g_server.nat_via_netnat) {
        std::fprintf(stderr, "NAT enabled via New-NetNat\n");
    } else {
        std::fprintf(stderr,
            "\nWARNING: NAT could not be enabled (MSFT_NetNat WMI class unavailable)\n"
            "         Server will route packets between clients but full-tunnel\n"
            "         internet access will NOT work. Use a Linux server instead.\n\n");
    }

    g_server.active    = true;
    g_server.tun_name  = tun_name;
    g_server.out_iface = out_iface;
    return true;
}

void disable_server_forwarding() {
    if (!g_server.active) return;
    std::fprintf(stderr, "Removing NAT rules...\n");

    if (g_server.nat_via_netnat) {
        run_ps("Remove-NetNat -Name 'NospoonNAT' -Confirm:$false");
    }

    run_silent("netsh interface ipv4 set interface \"" + g_server.tun_name +
               "\" forwarding=disabled");
    if (!g_server.out_iface.empty()) {
        run_silent("netsh interface ipv4 set interface \"" + g_server.out_iface +
                   "\" forwarding=disabled");
    }

    g_server = {};
}

// =========================================================================
// CLIENT: full tunnel (split routes + NRPT DNS + IPv6 blackhole)
// =========================================================================

bool enable_client_full_tunnel(const std::string& tun_name_arg,
                               const std::string& remote_host) {
    if (remote_host.empty()) {
        std::fprintf(stderr, "Cannot determine DHT server address for host route\n");
        return false;
    }
    const std::string tun_name = tun_name_arg.empty() ? "Nospoon" : tun_name_arg;

    std::string gw_combined = get_default_gateway();
    std::string gw_ip, gw_idx;
    if (gw_combined.empty() || !split_pipe(gw_combined, gw_ip, gw_idx)) {
        std::fprintf(stderr,
            "Cannot detect default gateway. PowerShell output was:\n  %s\n",
            gw_combined.empty() ? "(empty)" : gw_combined.c_str());
        return false;
    }

    std::string tun_idx = get_tun_if_index(tun_name);
    if (tun_idx.empty()) {
        std::fprintf(stderr,
            "Cannot find adapter '%s' interface index. PowerShell returned empty.\n",
            tun_name.c_str());
        return false;
    }

    g_client.active           = true;
    g_client.tun_name         = tun_name;
    g_client.tun_if_index     = tun_idx;
    g_client.gateway          = gw_ip;
    g_client.gateway_if_index = gw_idx;

    std::fprintf(stderr,
        "Routing all traffic through tunnel (server %s exempted)\n",
        remote_host.c_str());

    // Host route: DHT server stays on real gateway.
    if (run_silent("route add " + remote_host + " mask 255.255.255.255 " +
                   gw_ip + " metric 1 if " + gw_idx) != 0) {
        std::fprintf(stderr, "Failed to add host route for %s\n", remote_host.c_str());
        return false;
    }
    g_client.remote_hosts.push_back(remote_host);

    // Split-tunnel via TUN: 0.0.0.0/1 + 128.0.0.0/1 cover all of IPv4 with
    // a more-specific match than the existing 0.0.0.0/0 default route.
    if (run_silent("route add 0.0.0.0 mask 128.0.0.0 0.0.0.0 metric 1 if " + tun_idx) != 0 ||
        run_silent("route add 128.0.0.0 mask 128.0.0.0 0.0.0.0 metric 1 if " + tun_idx) != 0) {
        std::fprintf(stderr, "Failed to install split routes\n");
        return false;
    }

    // IPv6 blackhole through TUN to prevent leaks (matches WireGuard).
    run_silent("netsh interface ipv6 add route ::/1 interface=" + tun_idx + " metric=1");
    run_silent("netsh interface ipv6 add route 8000::/1 interface=" + tun_idx + " metric=1");
    std::fprintf(stderr, "IPv6 blackholed through tunnel (leak prevention)\n");

    // DNS via NRPT — capture the auto-generated rule name so we can remove
    // ours specifically without nuking unrelated NRPT rules.
    g_client.nrpt_rule_name = ps_capture(
        "(Add-DnsClientNrptRule -Namespace '.' "
        "-NameServers '1.1.1.1','8.8.8.8' -PassThru).Name");
    run_silent("ipconfig /flushdns");
    std::fprintf(stderr, "DNS set to 1.1.1.1, 8.8.8.8 via NRPT\n");

    std::fprintf(stderr,
        "Full tunnel active — all traffic goes through VPN (kill switch enabled)\n");
    return true;
}

void add_host_exemption(const std::string& remote_host) {
    if (!g_client.active || remote_host.empty()) return;
    for (const auto& h : g_client.remote_hosts) {
        if (h == remote_host) return;  // already exempted
    }
    if (run_silent("route add " + remote_host + " mask 255.255.255.255 " +
                   g_client.gateway + " metric 1 if " +
                   g_client.gateway_if_index) == 0) {
        g_client.remote_hosts.push_back(remote_host);
        std::fprintf(stderr, "Added host route exemption for %s\n",
                     remote_host.c_str());
    }
}

void disable_client_full_tunnel() {
    if (!g_client.active) return;
    std::fprintf(stderr, "Restoring original routes...\n");

    run_silent("route delete 0.0.0.0 mask 128.0.0.0");
    run_silent("route delete 128.0.0.0 mask 128.0.0.0");

    if (!g_client.tun_if_index.empty()) {
        run_silent("netsh interface ipv6 delete route ::/1 interface=" +
                   g_client.tun_if_index);
        run_silent("netsh interface ipv6 delete route 8000::/1 interface=" +
                   g_client.tun_if_index);
    }

    for (const auto& h : g_client.remote_hosts) {
        run_silent("route delete " + h + " mask 255.255.255.255");
    }

    if (!g_client.nrpt_rule_name.empty()) {
        run_ps("Remove-DnsClientNrptRule -Name '" +
               g_client.nrpt_rule_name + "' -Force");
    }
    run_silent("ipconfig /flushdns");
    std::fprintf(stderr, "DNS restored (NRPT rule removed)\n");

    g_client = {};
}

}  // namespace nospoon::full_tunnel

#endif  // _WIN32
