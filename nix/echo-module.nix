# NixOS module — runs the C++ echo server as a systemd service.
#
# Usage in your flake:
#   imports = [ hyperdht-cpp.nixosModules.echo-server ];
#   services.hyperdht-echo = {
#     enable = true;
#     seed = "aaaa...";       # 64 hex chars for stable identity
#     port = 49800;           # fixed port (0 = random)
#     openFirewall = true;    # open just this UDP port
#   };
{ config, lib, pkgs, ... }:

let
  cfg = config.services.hyperdht-echo;
in
{
  options.services.hyperdht-echo = {
    enable = lib.mkEnableOption "HyperDHT echo server";

    seed = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        64-character hex seed for deterministic identity.
        Same seed = same public key across restarts.
        Leave null for a random identity each time.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 0;
      description = ''
        UDP port for the DHT server socket. Set a fixed port so you
        can open just that port in the firewall. 0 = random.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the DHT port in the firewall.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      description = "The echo-server package to use.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.hyperdht-echo = {
      description = "HyperDHT echo server (hyperdht-cpp)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "simple";
        DynamicUser = true;
        ExecStart = let
          args = lib.optional (cfg.seed != null) cfg.seed
                 ++ lib.optional (cfg.port != 0) (toString cfg.port);
        in "${cfg.package}/bin/echo-server ${lib.concatStringsSep " " args}";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };

    networking.firewall.allowedUDPPorts =
      lib.mkIf (cfg.openFirewall && cfg.port != 0) [ cfg.port ];
  };
}
