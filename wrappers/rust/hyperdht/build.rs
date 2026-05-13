//! Build script for the `hyperdht` safe wrapper.
//!
//! Most of the build heavy-lifting happens in the `hyperdht-sys`
//! build script (it compiles the C library + generates bindings).
//! This script exists solely to forward ASAN link arguments from
//! `hyperdht-sys` into downstream binaries / tests that depend on
//! `hyperdht`.
//!
//! Cargo's `cargo:rustc-link-arg=…` directives apply only to the
//! bins/tests/benches of the *same* package; they don't propagate
//! to downstream packages. So when the user sets `HYPERDHT_ASAN=1`
//! we have to re-emit the same `libasan_preinit.o` + `libasan.so`
//! injection here, otherwise every test binary in `hyperdht/tests/`
//! and the unit-test runner ends up missing the asan runtime.

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=HYPERDHT_ASAN");

    let asan = env::var("HYPERDHT_ASAN")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);
    if !asan {
        return;
    }

    // Mirror the logic from `hyperdht-sys/build.rs`: ask gcc where its
    // libasan_preinit.o + libasan.so live so the paths stay correct
    // across nixpkgs upgrades. The downstream linker (`cc` invoking
    // `ld`) sees these as plain object/library file arguments.
    let preinit = std::process::Command::new("gcc")
        .args(["-print-file-name=libasan_preinit.o"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| std::path::Path::new(s).exists())
        .expect("HYPERDHT_ASAN=1 set but gcc has no libasan_preinit.o");

    let asan_so = std::process::Command::new("gcc")
        .args(["-print-file-name=libasan.so"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| std::path::Path::new(s).exists())
        .expect("HYPERDHT_ASAN=1 set but gcc has no libasan.so");

    let asan_dir = std::path::Path::new(&asan_so)
        .parent()
        .expect("libasan.so has no parent dir")
        .display()
        .to_string();

    println!("cargo:rustc-link-arg={}", preinit);
    println!("cargo:rustc-link-arg=-Wl,--no-as-needed");
    println!("cargo:rustc-link-arg={}", asan_so);
    println!("cargo:rustc-link-arg=-Wl,--as-needed");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", asan_dir);
}
