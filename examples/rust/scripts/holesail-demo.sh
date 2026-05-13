#!/usr/bin/env bash
# Demo helper: tunnel a local TCP port over HyperDHT.
#
# Run TWO terminals (both inside `nix develop .#rust`):
#
#   Terminal 1 — local HTTP server:
#     cargo run --release \
#       --manifest-path examples/rust/Cargo.toml \
#       --bin static-http
#
#   Terminal 2 — DHT tunnel:
#     bash examples/rust/scripts/holesail-demo.sh
#
# Override the local port (default 8765) by setting PORT in BOTH
# terminals.

set -euo pipefail

PORT="${PORT:-8765}"

# Best-effort pre-flight — warn if nothing is listening on the port.
# /dev/tcp is a bash builtin, no extra binary needed.
if ! (echo > "/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
    cat <<EOF
  WARNING: nothing is listening on 127.0.0.1:${PORT}.
  Start the static-http demo in another terminal first:
      cargo run --release --manifest-path examples/rust/Cargo.toml --bin static-http
  (or any other server that binds :${PORT})

  Continuing anyway — holesail will retry per peer connection.
EOF
fi

echo "  [demo] launching holesail-server on :${PORT}"
exec cargo run --release \
    --manifest-path examples/rust/Cargo.toml \
    --bin holesail-server -- --live "${PORT}"
