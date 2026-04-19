{
  description = "hyperdht-cpp — C++ reimplementation of HyperDHT";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    libudx = {
      url = "github:holepunchto/libudx/0420f6267110e919d3fcefb8d5de4385912eb353";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, libudx }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      # ── Packages ─────────────────────────────────────────────────────

      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          hyperdhtLib = import ./nix/lib.nix { inherit pkgs libudx; src = self; };
          shared = hyperdhtLib.mkHyperdht { shared = true; };
        in
        {
          default = hyperdhtLib.mkHyperdht {};
          static  = hyperdhtLib.mkHyperdht {};
          inherit shared;

          holesail = import ./nix/holesail.nix {
            inherit pkgs;
            sharedLib = shared;
            src = self;
          };

          echo-server = import ./nix/echo-server.nix {
            inherit pkgs;
            staticLib = hyperdhtLib.mkHyperdht {};
          };

          server-test = import ./nix/server-test.nix {
            inherit pkgs;
            inherit (hyperdhtLib) sourceFilter libudxPostUnpack;
          };
        }
      );

      # ── Dev shells ───────────────────────────────────────────────────

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          shared = (import ./nix/lib.nix {
            inherit pkgs libudx; src = self;
          }).mkHyperdht { shared = true; };
        in
        {
          # C++ development
          default = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.cmake pkgs.ninja pkgs.pkg-config
              pkgs.gcc14 pkgs.llvmPackages.clang pkgs.git
            ];
            buildInputs = [ pkgs.libsodium pkgs.libuv ];
            shellHook = ''
              echo "hyperdht-cpp dev shell — cmake $(cmake --version | head -1 | awk '{print $3}')"
            '';
          };

          # Python demo (shared lib + python3)
          python = pkgs.mkShell {
            buildInputs = [
              shared
              (pkgs.python3.withPackages (ps: [ ps.qrcode ]))
              pkgs.libuv
            ];
            shellHook = ''
              export LD_LIBRARY_PATH="${shared}/lib:${pkgs.libuv}/lib:$LD_LIBRARY_PATH"
              export HYPERDHT_LIB="${shared}/lib/libhyperdht.so"
              echo "hyperdht-cpp Python shell"
              echo "  libhyperdht.so: ${shared}/lib/libhyperdht.so"
              echo "  python3: $(python3 --version)"
              echo ""
              echo "  cd examples/python"
              echo "  python3 holesail_server.py --live 8080"
            '';
          };
        }
      );

      # ── NixOS module ─────────────────────────────────────────────────

      nixosModules.holesail = { config, lib, pkgs, ... }: {
        imports = [ ./nix/module.nix ];
        config.services.holesail.package = lib.mkDefault
          self.packages.${pkgs.system}.holesail;
      };

      nixosModules.echo-server = { config, lib, pkgs, ... }: {
        imports = [ ./nix/echo-module.nix ];
        config.services.hyperdht-echo.package = lib.mkDefault
          self.packages.${pkgs.system}.echo-server;
      };
    };
}
