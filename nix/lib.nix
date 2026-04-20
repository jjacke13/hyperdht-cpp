# Shared builder for the hyperdht C++ library (static + shared).
#
# Returns: { mkHyperdht, sourceFilter, libudxPostUnpack }
{ pkgs, libudx, src }:

let
  sourceFilter = pkgs.lib.cleanSourceWith {
    inherit src;
    filter = path: type:
      let baseName = builtins.baseNameOf path; in
      baseName != "build"
      && baseName != "build-asan"
      && baseName != "build-debug"
      && baseName != "build-fuzz"
      && baseName != "build-shared"
      && baseName != ".analysis";
  };

  libudxPostUnpack = ''
    rm -rf $sourceRoot/deps/libudx
    mkdir -p $sourceRoot/deps
    cp -r ${libudx} $sourceRoot/deps/libudx
  '';
in
{
  inherit sourceFilter libudxPostUnpack;

  mkHyperdht = { shared ? false, debug ? false }: pkgs.stdenv.mkDerivation {
    pname = "hyperdht" + (if shared then "-shared" else "")
                       + (if debug then "-debug" else "");
    version = "0.1.0";
    src = sourceFilter;
    postUnpack = libudxPostUnpack;

    nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
    buildInputs = [ pkgs.libsodium pkgs.libuv ];

    cmakeFlags = [
      "-DHYPERDHT_BUILD_TESTS=OFF"
      (if debug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
    ] ++ pkgs.lib.optional shared "-DBUILD_SHARED_LIBS=ON";

    meta = {
      description = "C++ HyperDHT — wire-compatible with JS HyperDHT";
      license = pkgs.lib.licenses.lgpl3Only;
      platforms = pkgs.lib.platforms.linux;
    };
  };
}
