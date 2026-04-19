# C++ echo server — persistent HyperDHT server that echoes data.
#
# Usage:
#   nix run .#echo-server
#   nix run .#echo-server -- <64-hex-seed>
{ pkgs, staticLib }:

pkgs.stdenv.mkDerivation {
  pname = "hyperdht-echo-server";
  version = "0.1.0";
  src = ../examples/cpp;

  buildInputs = [ staticLib pkgs.libsodium pkgs.libuv ];

  buildPhase = ''
    $CXX -std=c++20 -O2 server.cpp \
      -I${staticLib}/include \
      -L${staticLib}/lib -lhyperdht \
      -lsodium -luv -o echo-server
    $CXX -std=c++20 -O2 client.cpp \
      -I${staticLib}/include \
      -L${staticLib}/lib -lhyperdht \
      -lsodium -luv -o echo-client
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp echo-server $out/bin/
    cp echo-client $out/bin/
  '';
}
