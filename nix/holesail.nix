# Holesail P2P tunnel server — bundles Python wrapper + libhyperdht.so
#
# Usage:
#   nix run .#holesail -- --live 8080
#   nix run .#holesail -- --live 8080 --seed <64hex> --secure
{ pkgs, sharedLib, src }:

let
  python = pkgs.python3.withPackages (_: []);
in
pkgs.writeShellApplication {
  name = "holesail-py";
  runtimeInputs = [ python pkgs.libuv ];
  text = ''
    export LD_LIBRARY_PATH="${sharedLib}/lib:${pkgs.libuv}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export HYPERDHT_LIB="${sharedLib}/lib/libhyperdht.so"
    export PYTHONPATH="${src}/wrappers/python:${src}/examples/python''${PYTHONPATH:+:$PYTHONPATH}"
    exec python3 "${src}/examples/python/holesail_server.py" "$@"
  '';
}
