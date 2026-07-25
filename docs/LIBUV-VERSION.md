# libuv version requirement

**hyperdht-cpp requires libuv 1.51.x. Do NOT build against libuv 1.52.0 or
1.52.1** (and no other 1.52.x exists yet — see below). This is not a style
preference; libuv 1.52.0 has a UDP regression that silently breaks established
connections in the field.

The project's Nix flake pins `nixos-25.11` **specifically because it ships
libuv 1.51.0** — this pin is intentional, not incidental. Consumers that build
hyperdht-cpp against a newer nixpkgs (e.g. `nixos-26.05`, which ships libuv
1.52) must override libuv (see "What to do" below).

## The bug

libuv **1.52.0** (PR [#4902](https://github.com/libuv/libuv/pull/4902),
"linux: add MSG_ERRQUEUE ipv4/ipv6 udp support", commit `80a5e3ba`) rewrote
`uv__udp_io()`'s `POLLERR` handling. Before 1.52 a `POLLERR` triggered a normal
`recvmsg`, which consumes and clears the socket's latched error (`sk_err`, via
the kernel's `sock_error()`). In 1.52 `POLLERR` drains **only** the
`MSG_ERRQUEUE`, which is empty on a socket that has not set `IP_RECVERR`.

libudx sets `IP_MTU_DISCOVER = IP_PMTUDISC_PROBE` on its data socket
(`deps/libudx/src/io_posix.c`) — DF bit + active PMTU probing — but does **not**
set `IP_RECVERR`. On a real path with a smaller MTU (mobile / CGNAT / tunnel),
an oversized probe draws an ICMP *fragmentation-needed* onto the socket error
queue → `POLLERR`. Under 1.52 the error is never cleared, so `send()` keeps
failing, no data flows, no RTO fires, and the stream **wedges "connected"
forever with no self-heal**. It is intermittent / NAT-timing / path-MTU
dependent, and does **not** reproduce on clean loopback (all libudx unit tests
pass identically on 1.51 and 1.52).

Same regression class as libuv **[#5030](https://github.com/libuv/libuv/issues/5030)**
(BIND 9 `named` crashes + silent UDP-error suppression), which ISC bisected to
the same commit `80a5e3ba`.

### Blast radius in hyperdht-cpp

*All* UDP in hyperdht-cpp goes through libudx sockets (DHT RPC `client_socket_`
/ `server_socket_`, the holepunch pool sockets, and the data streams), so all
of it is exposed on 1.52. hyperdht-cpp's *own* direct libuv use is timers and
the event loop only (`uv_timer_*`, `uv_loop_*`, `uv_now`), which the bug does
not touch. hyperdht and libudx share one libuv / one `uv_loop_t`, so a single
libuv choice fixes (or breaks) everything.

## Upstream status

- Fixed on the libuv **v1.x** branch by PR [#3250](https://github.com/libuv/libuv/pull/3250)
  (commit `9f0101dcb8`): `POLLERR` again forces a normal recv + a send flush
  (`if (revents & POLLERR) revents |= POLLIN | POLLOUT;`).
- **Not yet released.** Latest tag is **v1.52.1** (crash-guard only, PR #5039 —
  it does NOT include the semantic fix). No v1.52.2 as of 2026-07.
- **libudx** (holepunchto/libudx) still pins libuv **1.51.0** in its own
  `CMakeLists.txt` and has shipped no 1.52-compat change. hyperdht-cpp's build
  ignores that pin (it feeds libudx the system libuv), which is why a consumer's
  nixpkgs bump can silently pull 1.52.

## What to do

- **Default / recommended:** build against **libuv 1.51.x** (nixos-25.11's
  default; matches what libudx targets).
- **If you must build on nixos-26.05 / libuv 1.52** before libuv 1.52.2 ships
  the fix: apply the kept-but-unwired patch
  [`nix/libuv-1.52-udp-pollerr.patch`](../nix/libuv-1.52-udp-pollerr.patch)
  as a libuv override, e.g.

  ```nix
  libuvFixed = pkgs.libuv.overrideAttrs (o: {
    patches = (o.patches or []) ++ [ ./nix/libuv-1.52-udp-pollerr.patch ];
  });
  ```

  and pass `libuvFixed` wherever `pkgs.libuv` is used. The patch is a 3-line
  backport of PR #3250 that applies to 1.52.0/1.52.1; it will fail to apply
  once libuv itself carries the fix (that failure is the signal to drop it).
  The CMake build emits a WARNING when it detects libuv 1.52.0/1.52.1.

## Periodic re-check (do this whenever bumping nixpkgs / libuv)

1. Has **libudx** bumped its libuv pin past 1.51? — `deps/libudx/CMakeLists.txt`
   line ~7 (`fetch_package("github:libuv/libuv@...")`). Check
   holepunchto/libudx `main` for any libuv-1.52 compat commit/issue.
2. Has libuv shipped **>= 1.52.2** including PR #3250? — if yes, drop the pin +
   the patch + this CMake warning and use stock libuv.
3. When either lands: move the flake off the 25.11 pin (or override libuv to
   the fixed version), delete `nix/libuv-1.52-udp-pollerr.patch`, and remove the
   CMakeLists version guard.
