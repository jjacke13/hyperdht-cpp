# Server test binary for live cross-testing on remote machines.
#
# Usage: nix build .#server-test && ./result/bin/test_server_live
{ pkgs, sourceFilter, libudxPostUnpack }:

pkgs.stdenv.mkDerivation {
  pname = "hyperdht-server-test";
  version = "0.3.1";
  src = sourceFilter;
  postUnpack = libudxPostUnpack;

  nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
  buildInputs = [ pkgs.libsodium pkgs.libuv pkgs.gtest ];

  cmakeFlags = [
    "-DHYPERDHT_BUILD_TESTS=ON"
    "-DHYPERDHT_DEBUG=ON"
    "-DCMAKE_BUILD_TYPE=Debug"
    "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"
    "-DGTEST_ROOT=${pkgs.gtest}"
  ];

  buildTargets = [ "test_server_live" ];

  installPhase = ''
    mkdir -p $out/bin
    cp test_server_live $out/bin/
  '';
}
