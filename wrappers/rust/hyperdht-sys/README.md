# hyperdht-sys

Raw FFI bindings for [hyperdht-cpp](https://github.com/jjacke13/hyperdht-cpp).

This crate exposes the C API in `include/hyperdht/hyperdht.h` as
`unsafe extern "C"` Rust declarations. It does **not** provide a safe
or idiomatic Rust API — for that, use the `hyperdht` crate which
wraps these bindings in async-friendly types.

## Build

The `build.rs` invokes CMake against the parent project to produce
`libhyperdht.a` and `libudx.a`, then runs `bindgen` against the
public header to generate the FFI declarations.

System dependencies (must be available via `pkg-config`):
- `libsodium`
- `libuv`

Build environment also needs `cmake`, `ninja`, a C++20 compiler, and
`libclang` (for `bindgen`).

The `flake.nix` `rust` dev shell provides all of the above:

```bash
nix develop .#rust
cd wrappers/rust/hyperdht-sys
cargo build
cargo test
```

## Linking

Static linking by default — produces a self-contained `.rlib`
(plus runtime deps `libsodium`, `libuv`, `libstdc++`).

## Versioning

Tracks the parent `hyperdht-cpp` library's `CMakeLists.txt` version.
Currently `0.4.0`.
