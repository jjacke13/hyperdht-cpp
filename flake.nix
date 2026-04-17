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
    let
      mkHyperdht = pkgs: { shared ? false }: pkgs.stdenv.mkDerivation {
        pname = "hyperdht" + (if shared then "-shared" else "");
        version = "0.1.0";
        src = pkgs.lib.cleanSourceWith {
          src = self;
          filter = path: type:
            let baseName = builtins.baseNameOf path; in
            baseName != "build" && baseName != "build-asan" && baseName != "build-fuzz"
            && baseName != "build-shared" && baseName != ".analysis";
        };

        # Symlink libudx source (fetched as a flake input, not git submodule)
        postUnpack = ''
          rm -rf $sourceRoot/deps/libudx
          mkdir -p $sourceRoot/deps
          cp -r ${libudx} $sourceRoot/deps/libudx
        '';

        nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
        buildInputs = [ pkgs.libsodium pkgs.libuv ];

        cmakeFlags = [
          "-DHYPERDHT_BUILD_TESTS=OFF"
          "-DCMAKE_BUILD_TYPE=Release"
        ] ++ (if shared then [ "-DBUILD_SHARED_LIBS=ON" ] else []);

        meta = {
          description = "C++ HyperDHT implementation — wire-compatible with JS HyperDHT";
          license = pkgs.lib.licenses.lgpl3Only;
          platforms = pkgs.lib.platforms.linux;
        };
      };
    in
    {
      packages = forAllSystems (system:
        let pkgs = pkgsFor system; in
        {
          default = mkHyperdht pkgs {};
          static = mkHyperdht pkgs {};
          shared = mkHyperdht pkgs { shared = true; };

          holesail = import ./nix/holesail.nix {
            inherit pkgs;
            sharedLib = mkHyperdht pkgs { shared = true; };
            src = self;
          };

          # Minimal server test binary — for live cross-testing on remote machines.
          # Usage: nix build .#server-test && ./result/bin/test_server_live
          server-test = pkgs.stdenv.mkDerivation {
            pname = "hyperdht-server-test";
            version = "0.1.0";
            src = pkgs.lib.cleanSourceWith {
              src = self;
              filter = path: type:
                let baseName = builtins.baseNameOf path; in
                baseName != "build" && baseName != "build-asan"
                && baseName != "build-debug" && baseName != "build-fuzz"
                && baseName != "build-shared" && baseName != ".analysis";
            };
            postUnpack = ''
              rm -rf $sourceRoot/deps/libudx
              mkdir -p $sourceRoot/deps
              cp -r ${libudx} $sourceRoot/deps/libudx
            '';
            nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
            buildInputs = [ pkgs.libsodium pkgs.libuv pkgs.gtest ];
            cmakeFlags = [
              "-DHYPERDHT_BUILD_TESTS=ON"
              "-DHYPERDHT_DEBUG=ON"
              "-DCMAKE_BUILD_TYPE=Debug"
              "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"
              "-DGTEST_ROOT=${pkgs.gtest}"
            ];
            # Let the default cmake build phase run, then just pick the binary
            buildTargets = [ "test_server_live" ];
            installPhase = ''
              mkdir -p $out/bin
              cp test_server_live $out/bin/
            '';
          };
        }
      );

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          sharedLib = mkHyperdht pkgs { shared = true; };
        in
        {
          # C++ development shell
          default = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.cmake
              pkgs.ninja
              pkgs.pkg-config
              pkgs.gcc14
              pkgs.llvmPackages.clang
              pkgs.git
            ];

            buildInputs = [
              pkgs.libsodium
              pkgs.libuv
            ];

            shellHook = ''
              echo "hyperdht-cpp dev shell — cmake $(cmake --version | head -1 | awk '{print $3}')"
            '';
          };

          # Python demo shell — includes libhyperdht.so + python3
          python = pkgs.mkShell {
            buildInputs = [
              sharedLib
              (pkgs.python3.withPackages (ps: [ ps.qrcode ]))
              pkgs.libuv
            ];

            shellHook = ''
              export LD_LIBRARY_PATH="${sharedLib}/lib:${pkgs.libuv}/lib:$LD_LIBRARY_PATH"
              export HYPERDHT_LIB="${sharedLib}/lib/libhyperdht.so"
              echo "hyperdht-cpp Python shell"
              echo "  libhyperdht.so: ${sharedLib}/lib/libhyperdht.so"
              echo "  python3: $(python3 --version)"
              echo ""
              echo "  Run the holesail demo:"
              echo "    cd examples/python"
              echo "    python3 holesail_server.py --live 8080"
              echo ""
              echo "  Or import directly:"
              echo "    cd examples/python"
              echo "    python3 -c 'from hyperdht import KeyPair; print(KeyPair.generate())'"
            '';
          };
        }
      );

      nixosModules.holesail = { config, lib, pkgs, ... }: {
        imports = [ ./nix/module.nix ];
        config.services.holesail.package = lib.mkDefault
          self.packages.${pkgs.system}.holesail;
      };
    };
}
