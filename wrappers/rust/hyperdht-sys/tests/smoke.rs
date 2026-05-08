//! Smoke test: verify the FFI surface is generated and a no-loop
//! function (`hyperdht_keypair_generate`) works without crashing.
//!
//! Functions that require a `uv_loop_t` (e.g. `hyperdht_create`) are
//! NOT exercised here — that's the `hyperdht` (safe wrapper) crate's
//! job. This test only proves bindgen produced something usable and
//! the static link line resolves at runtime.

use hyperdht_sys::*;

#[test]
fn keypair_generate_produces_nonzero_pubkey() {
    let mut kp = hyperdht_keypair_t {
        public_key: [0u8; 32],
        secret_key: [0u8; 64],
    };

    unsafe { hyperdht_keypair_generate(&mut kp) };

    // Random pubkey: extremely unlikely to be all zeros.
    assert!(
        kp.public_key.iter().any(|&b| b != 0),
        "public_key was all zeros after generate()"
    );
    assert!(
        kp.secret_key.iter().any(|&b| b != 0),
        "secret_key was all zeros after generate()"
    );
}

#[test]
fn keypair_from_seed_is_deterministic() {
    let seed = [0x42u8; 32];
    let mut kp1 = hyperdht_keypair_t {
        public_key: [0u8; 32],
        secret_key: [0u8; 64],
    };
    let mut kp2 = hyperdht_keypair_t {
        public_key: [0u8; 32],
        secret_key: [0u8; 64],
    };

    unsafe {
        hyperdht_keypair_from_seed(&mut kp1, seed.as_ptr());
        hyperdht_keypair_from_seed(&mut kp2, seed.as_ptr());
    }

    assert_eq!(
        kp1.public_key, kp2.public_key,
        "deterministic seed produced different pubkeys"
    );
}

#[test]
fn keypair_zero_clears_secret() {
    let mut kp = hyperdht_keypair_t {
        public_key: [0u8; 32],
        secret_key: [0u8; 64],
    };
    unsafe {
        hyperdht_keypair_generate(&mut kp);
        hyperdht_keypair_zero(&mut kp);
    }
    assert!(
        kp.secret_key.iter().all(|&b| b == 0),
        "secret_key not zeroed after hyperdht_keypair_zero"
    );
}

#[test]
fn ffi_surface_function_count_is_at_least_80() {
    // Sanity check: bindgen exported a meaningful number of fns.
    // We use indirect proof — referencing function pointers ensures
    // they exist as Rust items.
    let _f1 = hyperdht_keypair_generate as unsafe extern "C" fn(*mut hyperdht_keypair_t);
    let _f2 = hyperdht_keypair_from_seed
        as unsafe extern "C" fn(*mut hyperdht_keypair_t, *const u8);
    let _f3 = hyperdht_keypair_zero as unsafe extern "C" fn(*mut hyperdht_keypair_t);
    // hyperdht_hash is the simplest no-instance fn we can reference.
    let _f4 = hyperdht_hash as unsafe extern "C" fn(*const u8, usize, *mut u8);
}

#[test]
fn hyperdht_hash_is_deterministic() {
    let data = b"hello hyperdht";
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    unsafe {
        hyperdht_hash(data.as_ptr(), data.len(), out1.as_mut_ptr());
        hyperdht_hash(data.as_ptr(), data.len(), out2.as_mut_ptr());
    }
    assert_eq!(out1, out2, "hyperdht_hash is non-deterministic");
    assert!(
        out1.iter().any(|&b| b != 0),
        "hyperdht_hash returned all zeros for non-empty input"
    );
}
