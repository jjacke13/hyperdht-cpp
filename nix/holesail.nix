# Holesail P2P tunnel server — built as a proper Python package.
#
# Usage:
#   nix run .#holesail -- --live 8080
{ pkgs, sharedLib, src }:

let
  # The hyperdht Python library (installed via pip-style)
  hyperdhtPython = pkgs.python3Packages.buildPythonPackage {
    pname = "hyperdht";
    version = "0.3.1";
    format = "pyproject";
    src = "${src}/wrappers/python";
    nativeBuildInputs = [ pkgs.python3Packages.setuptools ];
    doCheck = false;
  };
in
pkgs.python3Packages.buildPythonApplication {
  pname = "holesail-py";
  version = "0.1.0";
  format = "other";

  src = "${src}/examples/python";

  propagatedBuildInputs = [ hyperdhtPython ];

  dontBuild = true;

  installPhase =
    let
      python = pkgs.python3.withPackages (_: [ hyperdhtPython ]);
    in ''
      mkdir -p $out/bin $out/lib
      cp holesail_server.py $out/lib/holesail_server.py
      cp webserver.py $out/lib/webserver.py

      cat > $out/bin/holesail-py <<EOF
      #!/bin/sh
      export PYTHONUNBUFFERED=1
      export LD_LIBRARY_PATH="${sharedLib}/lib:${pkgs.libuv}/lib\''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
      export HYPERDHT_LIB="${sharedLib}/lib/libhyperdht.so"
      exec ${python}/bin/python3 $out/lib/holesail_server.py "\$@"
      EOF
      chmod +x $out/bin/holesail-py
    '';

  doCheck = false;
}
