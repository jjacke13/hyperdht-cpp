# NixOS module — runs holesail-py as a systemd service.
#
# Usage in your flake:
#   imports = [ hyperdht-cpp.nixosModules.holesail ];
#   services.holesail = {
#     enable = true;
#     port = 8080;
#     seed = "aaaa...";  # 64 hex chars for stable identity
#   };
{ config, lib, pkgs, ... }:

let
  cfg = config.services.holesail;

  webserverScript = pkgs.writeText "holesail-webserver.py" ''
    from http.server import HTTPServer, BaseHTTPRequestHandler

    HTML = b"""<!DOCTYPE html>
    <html>
    <head><title>hyperdht-cpp</title></head>
    <body style="font-family:monospace;max-width:600px;margin:80px auto;text-align:center">
    <h1>It works!</h1>
    <p>This page is served over a P2P tunnel powered by
    <strong>libhyperdht</strong> (C++) + Python.</p>
    <p>The connection is end-to-end encrypted (Noise IK + SecretStream)
    and traversed your NAT via holepunching.</p>
    <p><code>holesail-py + hyperdht-cpp</code></p>
    </body>
    </html>
    """

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML)
        def log_message(self, *a):
            pass

    HTTPServer(("127.0.0.1", ${toString cfg.port}), H).serve_forever()
  '';
in
{
  options.services.holesail = {
    enable = lib.mkEnableOption "holesail P2P tunnel server";

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Local TCP port to expose over HyperDHT.";
    };

    host = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Local bind address.";
    };

    seed = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        64-character hex seed for deterministic identity.
        Same seed = same connection key across restarts.
        Leave null for a random identity each time.
      '';
    };

    secure = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Reject peers that don't know the seed (recommended).";
    };

    webserver = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Run the built-in demo webserver behind the tunnel.";
      };
    };

    package = lib.mkOption {
      type = lib.types.package;
      description = "The holesail-py package to use.";
    };
  };

  config = lib.mkIf cfg.enable {
    # Built-in webserver
    systemd.services.holesail-webserver = lib.mkIf cfg.webserver.enable {
      description = "Holesail demo webserver";
      wantedBy = [ "multi-user.target" ];
      before = [ "holesail.service" ];
      serviceConfig = {
        Type = "simple";
        DynamicUser = true;
        ExecStart = "${pkgs.python3}/bin/python3 ${webserverScript}";
        Restart = "on-failure";
      };
    };

    # Holesail P2P tunnel
    systemd.services.holesail = {
      description = "Holesail P2P tunnel (hyperdht-cpp)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ]
        ++ lib.optional cfg.webserver.enable "holesail-webserver.service";
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "simple";
        DynamicUser = true;
        ExecStart = let
          args = [ "--live" (toString cfg.port) "--host" cfg.host ]
            ++ lib.optionals (cfg.seed != null) [ "--seed" cfg.seed ]
            ++ lib.optional cfg.secure "--secure";
        in "${cfg.package}/bin/holesail-py ${lib.concatStringsSep " " args}";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
