# NixOS module — runs the C++ echo server as a systemd service.
#
# Usage in your flake:
#   imports = [ hyperdht-cpp.nixosModules.echo-server ];
#   services.hyperdht-echo = {
#     enable = true;
#     seed = "aaaa...";  # 64 hex chars for stable identity
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
        ExecStart =
          if cfg.seed != null
          then "${cfg.package}/bin/echo-server ${cfg.seed}"
          else "${cfg.package}/bin/echo-server";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
