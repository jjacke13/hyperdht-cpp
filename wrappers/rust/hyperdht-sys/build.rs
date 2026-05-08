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

    // Optional: ASAN-instrumented build for Phase 2.5 sanitizer runs.
    // Set HYPERDHT_ASAN=1 in the env to force the C library compile
    // with `-fsanitize=address` and have us inject `-lasan` into the
    // final rustc link line.
    let asan = env::var("HYPERDHT_ASAN")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);

    // ---- Step 1: Build the C library via CMake ----
    let mut cfg = cmake::Config::new(&project_root);
    cfg.define("HYPERDHT_BUILD_TESTS", "OFF")
        .define("CMAKE_BUILD_TYPE", if asan { "RelWithDebInfo" } else { "Release" })
        .define("CMAKE_POSITION_INDEPENDENT_CODE", "ON");
    if asan {
        cfg.cflag("-fsanitize=address")
            .cflag("-fno-omit-frame-pointer")
            .cflag("-g")
            .cxxflag("-fsanitize=address")
            .cxxflag("-fno-omit-frame-pointer")
            .cxxflag("-g");
    }
    let dst = cfg.build_target("hyperdht").build();

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

    if asan {
        // ASAN runtime injection.
        //
        // rustc on this system links with `-nodefaultlibs`, which
        // makes gcc skip its auto-add of libasan even when we pass
        // `-fsanitize=address` as a link arg. The fix is to inject
        // the preinit object + the runtime explicitly, in the order
        // gcc would.
        //
        // We resolve the absolute paths via `gcc -print-file-name=…`
        // so this stays robust across nixpkgs upgrades that change
        // the gcc store path.
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

        // Order matters: preinit (provides __asan_init via .preinit_array)
        // must be earliest in the link line so its constructors run first.
        // --no-as-needed forces ld to keep libasan even though preceding
        // .o references appear before it in the rustc-emitted line.
        println!("cargo:rustc-link-arg={}", preinit);
        println!("cargo:rustc-link-arg=-Wl,--no-as-needed");
        println!("cargo:rustc-link-arg={}", asan_so);
        println!("cargo:rustc-link-arg=-Wl,--as-needed");
        // rpath so the resulting binary finds libasan.so at runtime
        // without needing LD_LIBRARY_PATH.
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", asan_dir);
        println!("cargo:rerun-if-env-changed=HYPERDHT_ASAN");
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
