{
  description = "hyperdht-cpp — C++ reimplementation of HyperDHT";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      devShells = forAllSystems (system:
        let pkgs = pkgsFor system; in
        {
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
        }
      );
    };
}
