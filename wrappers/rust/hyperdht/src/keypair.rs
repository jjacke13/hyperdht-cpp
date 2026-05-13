//! Ed25519 keypair handling.
//!
//! The `Keypair` type wraps the FFI's `hyperdht_keypair_t`, with the
//! secret key zeroed on `Drop`.

use hyperdht_sys::hyperdht_keypair_t;
use zeroize::Zeroize;

/// Length in bytes of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length in bytes of a seed used to deterministically derive a keypair.
pub const SEED_LEN: usize = 32;

/// An Ed25519 keypair. The secret key is zeroed on `Drop`.
pub struct Keypair {
    inner: hyperdht_keypair_t,
}

impl Keypair {
    /// Generate a fresh random keypair.
    pub fn generate() -> Self {
        let mut inner = hyperdht_keypair_t {
            public_key: [0u8; PUBLIC_KEY_LEN],
            secret_key: [0u8; 64],
        };
        unsafe { hyperdht_sys::hyperdht_keypair_generate(&mut inner) };
        Keypair { inner }
    }

    /// Deterministically derive a keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mut inner = hyperdht_keypair_t {
            public_key: [0u8; PUBLIC_KEY_LEN],
            secret_key: [0u8; 64],
        };
        unsafe { hyperdht_sys::hyperdht_keypair_from_seed(&mut inner, seed.as_ptr()) };
        Keypair { inner }
    }

    /// The public key half.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.inner.public_key)
    }

    /// Pointer to the underlying FFI struct (internal use).
    #[allow(dead_code)] // used by upcoming Server/connect-with-keypair paths
    pub(crate) fn as_ffi(&self) -> *const hyperdht_keypair_t {
        &self.inner as *const _
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        // hyperdht_keypair_zero zeroes the secret_key field.
        unsafe { hyperdht_sys::hyperdht_keypair_zero(&mut self.inner) };
        // Defense in depth — also zeroize via the crate.
        self.inner.secret_key.zeroize();
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public())
            .field("secret", &"<zeroed-on-drop>")
            .finish()
    }
}

/// An Ed25519 public key. 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        PublicKey(bytes)
    }

    /// Borrow the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Try to parse from a 64-character hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut buf = [0u8; PUBLIC_KEY_LEN];
        hex::decode_to_slice(s, &mut buf)?;
        Ok(PublicKey(buf))
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_pair() {
        let kp = Keypair::generate();
        let pk = kp.public();
        assert!(pk.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0x42u8; SEED_LEN];
        let kp1 = Keypair::from_seed(&seed);
        let kp2 = Keypair::from_seed(&seed);
        assert_eq!(kp1.public(), kp2.public());
    }

    #[test]
    fn pubkey_hex_roundtrip() {
        let kp = Keypair::generate();
        let pk = kp.public();
        let hex_str = pk.to_string();
        let parsed = PublicKey::from_hex(&hex_str).unwrap();
        assert_eq!(pk, parsed);
    }
}
