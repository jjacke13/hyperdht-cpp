//! Build script for `hyperdht-sys`.
//!
//! Two responsibilities:
//!   1. Build the C library (`libhyperdht.a` + `libudx.a`) via CMake.
//!   2. Generate Rust FFI bindings from `hyperdht.h` via bindgen.

use std::env;
use std::path::PathBuf;

fn main() {
    // ---- Locate the project root (4 levels up from this build.rs) ----
    // build.rs lives at: hyperdht-cpp/wrappers/rust/hyperdht-sys/build.rs
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let project_root = manifest_dir
        .parent() // wrappers/rust/
        .and_then(|p| p.parent()) // wrappers/
        .and_then(|p| p.parent()) // hyperdht-cpp/
        .expect("could not find project root from CARGO_MANIFEST_DIR")
        .to_path_buf();

    let header = project_root.join("include/hyperdht/hyperdht.h");
    let include_dir = project_root.join("include");
    let wrapper = manifest_dir.join("wrapper.h");

    // ---- Step 1: Build the C library via CMake ----
    let dst = cmake::Config::new(&project_root)
        .define("HYPERDHT_BUILD_TESTS", "OFF")
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("CMAKE_POSITION_INDEPENDENT_CODE", "ON")
        .build_target("hyperdht")
        .build();

    let build_dir = dst.join("build");

    // Static libs produced: libhyperdht.a, libudx.a
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=hyperdht");
    println!("cargo:rustc-link-lib=static=udx");

    // System deps (resolved via pkg-config in CMake; we link explicitly here)
    println!("cargo:rustc-link-lib=sodium");
    println!("cargo:rustc-link-lib=uv");

    // C++ runtime — hyperdht is C++20
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else if !target.contains("msvc") {
        println!("cargo:rustc-link-lib=stdc++");
    }

    // POSIX glue
    if !target.contains("msvc") {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=m");
    }

    // ---- Step 2: Generate Rust FFI bindings ----
    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-changed={}", wrapper.display());
    println!("cargo:rerun-if-changed=build.rs");

    let bindings = bindgen::Builder::default()
        .header(wrapper.to_str().expect("wrapper path utf-8"))
        .clang_arg(format!("-I{}", include_dir.display()))
        // Allowlist the hyperdht public C API.
        .allowlist_function("hyperdht_.*")
        .allowlist_type("hyperdht_.*")
        .allowlist_type("HYPERDHT_.*")
        .allowlist_var("HYPERDHT_.*")
        // Allowlist the libuv subset our Rust safe-wrapper pump thread uses.
        .allowlist_function("uv_loop_init")
        .allowlist_function("uv_loop_close")
        .allowlist_function("uv_loop_alive")
        .allowlist_function("uv_run")
        .allowlist_function("uv_stop")
        .allowlist_function("uv_async_init")
        .allowlist_function("uv_async_send")
        .allowlist_function("uv_close")
        .allowlist_function("uv_is_closing")
        .allowlist_function("uv_walk")
        .allowlist_function("uv_default_loop")
        .allowlist_type("uv_loop_t")
        .allowlist_type("uv_async_t")
        .allowlist_type("uv_handle_t")
        .allowlist_type("uv_run_mode")
        // Pretty-print constants instead of numeric literals.
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        // Tell cargo to invalidate the build when the header changes.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen generation failed");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("could not write bindings.rs");
}
