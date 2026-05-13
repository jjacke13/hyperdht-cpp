//! Raw FFI bindings for [hyperdht-cpp](https://github.com/jjacke13/hyperdht-cpp).
//!
//! This crate exposes the C API from `include/hyperdht/hyperdht.h` as
//! `unsafe extern "C"` Rust declarations, generated at build time by
//! [`bindgen`].
//!
//! For a safe, async-friendly Rust API, use the `hyperdht` crate
//! (built on top of this one).
//!
//! # Safety
//!
//! All declared functions are `unsafe`. The thread-safety contract
//! from the C header applies: every call must happen on the same
//! thread that runs the `uv_loop_t` event loop. Calling from a
//! background thread is undefined behavior.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(deref_nullptr)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_transmute)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
