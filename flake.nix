{
  description = "hyperdht-cpp — C++ reimplementation of HyperDHT";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    libudx = {
      url = "github:holepunchto/libudx/0420f6267110e919d3fcefb8d5de4385912eb353";
      flake = false;
    };
    nixpkgs-esp-dev = {
      url = "github:mirrexagon/nixpkgs-esp-dev";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, libudx, nixpkgs-esp-dev }:
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

          echo-server-debug = import ./nix/echo-server.nix {
            inherit pkgs;
            staticLib = hyperdhtLib.mkHyperdht { debug = true; };
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

          # Android / Kotlin development (JNI bridge + NDK)
          # Uses buildFHSEnv so Gradle-downloaded binaries (aapt2, etc.)
          # work on NixOS without patching.
          android = let
            # Android SDK requires unfree license acceptance
            androidPkgs = import nixpkgs {
              inherit system;
              config.android_sdk.accept_license = true;
              config.allowUnfree = true;
            };
            androidComposition = androidPkgs.androidenv.composeAndroidPackages {
              platformVersions = [ "34" ];
              ndkVersions = [ "26.3.11579264" ];
              buildToolsVersions = [ "34.0.0" ];
              includeNDK = true;
            };
            androidSdk = androidComposition.androidsdk;
            fhs = pkgs.buildFHSEnv {
              name = "android-fhs";
              targetPkgs = p: [
                p.cmake p.ninja p.pkg-config p.gcc14
                p.jdk21 p.kotlin p.gradle
                androidSdk
                p.libsodium p.libuv
                # Runtime deps for Gradle-downloaded binaries (aapt2, etc.)
                p.glibc p.zlib p.stdenv.cc.cc.lib
              ];
              profile = ''
                export ANDROID_HOME="${androidSdk}/libexec/android-sdk"
                export ANDROID_NDK_HOME="${androidSdk}/libexec/android-sdk/ndk/26.3.11579264"
                export JAVA_HOME="${pkgs.jdk21}"
              '';
            };
          in pkgs.mkShell {
            nativeBuildInputs = [ fhs ];
            shellHook = ''
              echo "hyperdht-cpp Android dev shell (FHS)"
              echo "  Run: android-fhs"
              echo "  Then: cd examples/android && gradle assembleDebug"
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

          # ESP32 development (ESP-IDF + Xtensa toolchain)
          esp32 = let
            espPkgs = import nixpkgs {
              inherit system;
              overlays = [ nixpkgs-esp-dev.overlays.default ];
              config.permittedInsecurePackages = [
                "python3.13-ecdsa-0.19.1"
              ];
            };
          in espPkgs.mkShell {
            buildInputs = [ espPkgs.esp-idf-xtensa ];
            shellHook = ''
              echo "hyperdht-cpp ESP32 dev shell"
              echo "  ESP-IDF: $IDF_PATH"
              echo "  Target:  esp32s3"
              echo ""
              echo "  cd examples/esp32"
              echo "  idf.py set-target esp32s3"
              echo "  idf.py build"
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
