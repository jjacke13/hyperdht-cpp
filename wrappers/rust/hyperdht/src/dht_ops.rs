//! DHT storage and discovery operations: announce, lookup, mutable_put/get.
//!
//! These are the building blocks used by Phase 4's
//! ID-to-pubkey resolution layer (RustDesk integration), but are
//! independently useful for any P2P app that needs DHT-stored records.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use tokio::sync::oneshot;

use crate::error::{HyperDhtError, Result};
use crate::keypair::{Keypair, PublicKey};
use crate::loop_thread::Command;

/// One result row from a DHT `lookup` or `find_peer` query.
#[derive(Debug, Clone)]
pub struct LookupEntry {
    /// The opaque payload that was announced at the target.
    pub value: Vec<u8>,
    /// IP address of the DHT node that returned this record.
    pub from_host: String,
    /// UDP port of the DHT node that returned this record.
    pub from_port: u16,
}

/// A signed mutable record retrieved via `mutable_get`.
#[derive(Debug, Clone)]
pub struct MutableRecord {
    /// Sequence number — monotonically increases with each `mutable_put`.
    pub seq: u64,
    /// The opaque payload.
    pub value: Vec<u8>,
    /// Ed25519 signature over `(seq, value)` by the publisher's keypair.
    pub signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Per-operation contexts (heap-allocated, freed in done callback)
// ---------------------------------------------------------------------------

/// Used by `announce` / `mutable_put` (no per-result callback).
pub(crate) struct PutCtx {
    pub(crate) response: Mutex<Option<oneshot::Sender<Result<()>>>>,
}

/// Used by `lookup` / `find_peer`. Per-reply callback appends results;
/// done callback drains and delivers.
pub(crate) struct LookupCtx {
    pub(crate) results: Mutex<Vec<LookupEntry>>,
    pub(crate) response: Mutex<Option<oneshot::Sender<Result<Vec<LookupEntry>>>>>,
}

/// Used by `mutable_get`. The per-result callback fires zero or one
/// times (the highest-seq winning record). `seen` tracks whether it
/// fired so done can decide between Ok(Some(_)) and Ok(None).
pub(crate) struct MutableGetCtx {
    pub(crate) record: Mutex<Option<MutableRecord>>,
    pub(crate) seen: Arc<AtomicBool>,
    pub(crate) response:
        Mutex<Option<oneshot::Sender<Result<Option<MutableRecord>>>>>,
}

/// Used by `immutable_get`. The per-result `hyperdht_value_cb` fires
/// zero or one times with the verified value bytes. The done callback
/// drains and delivers.
pub(crate) struct ImmutableGetCtx {
    pub(crate) value: Mutex<Option<Vec<u8>>>,
    pub(crate) response: Mutex<Option<oneshot::Sender<Result<Option<Vec<u8>>>>>>,
}

// ---------------------------------------------------------------------------
// Public API on Dht
// ---------------------------------------------------------------------------

impl crate::dht::Dht {
    /// Announce `kp` at the DHT target (JS `announce(target, keyPair, [])`).
    ///
    /// The commit signs a fresh record for each closest node over that node's
    /// per-request token+id, so this takes the keypair (not a pre-signed value)
    /// — a single fixed value cannot verify at any node. Multiple peers can
    /// announce at the same target; `lookup` returns all of them.
    pub async fn announce(&self, target: [u8; 32], kp: &Keypair) -> Result<()> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        // SAFETY: copy the keypair bytes synchronously before crossing the
        // channel (mirrors mutable_put).
        let (pk_bytes, sk_bytes) = unsafe {
            let kp_ffi = &*kp.as_ffi();
            (kp_ffi.public_key, kp_ffi.secret_key)
        };
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::Announce {
            target,
            public_key: pk_bytes,
            secret_key: sk_bytes,
            response: tx,
        })?;
        rx.await?
    }

    /// Look up all values stored at a DHT target.
    ///
    /// Returns once the DHT walk completes. Empty Vec is valid (target
    /// has no announcements).
    pub async fn lookup(&self, target: [u8; 32]) -> Result<Vec<LookupEntry>> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::Lookup {
            target,
            response: tx,
        })?;
        rx.await?
    }

    /// Store a signed mutable value at `target = BLAKE2b(pubkey)`.
    ///
    /// `seq` must monotonically increase across calls — the DHT only
    /// accepts records with strictly higher seq than the existing one.
    pub async fn mutable_put(
        &self,
        kp: &Keypair,
        value: &[u8],
        seq: u64,
    ) -> Result<()> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        // SAFETY: the keypair is alive for the duration of this borrow;
        // we copy the bytes synchronously before crossing the channel.
        let (pk_bytes, sk_bytes) = unsafe {
            let kp_ffi = &*kp.as_ffi();
            (kp_ffi.public_key, kp_ffi.secret_key)
        };
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::MutablePut {
            public_key: pk_bytes,
            secret_key: sk_bytes,
            value: value.to_vec(),
            seq,
            response: tx,
        })?;
        rx.await?
    }

    /// Retrieve the latest signed mutable record for a public key.
    ///
    /// Returns `Ok(None)` if no record was found, `Ok(Some(record))`
    /// with seq >= `min_seq` otherwise.
    pub async fn mutable_get(
        &self,
        public_key: PublicKey,
        min_seq: u64,
    ) -> Result<Option<MutableRecord>> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::MutableGet {
            public_key: *public_key.as_bytes(),
            min_seq,
            response: tx,
        })?;
        rx.await?
    }

    /// Withdraw a previously-announced value from the DHT target.
    ///
    /// `kp` must match the keypair originally used for the `announce`
    /// — DHT nodes verify the signature before evicting their copy.
    /// Use this on graceful shutdown to free DHT capacity instead of
    /// waiting for the announcement to expire.
    pub async fn unannounce(&self, target: [u8; 32], kp: &Keypair) -> Result<()> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        // SAFETY: keypair lives for the duration of this borrow; bytes
        // are copied synchronously before crossing the channel.
        let (pk_bytes, sk_bytes) = unsafe {
            let kp_ffi = &*kp.as_ffi();
            (kp_ffi.public_key, kp_ffi.secret_key)
        };
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::Unannounce {
            target,
            public_key: pk_bytes,
            secret_key: sk_bytes,
            response: tx,
        })?;
        rx.await?
    }

    /// Locate the public addresses of a peer by their public key.
    ///
    /// Each `LookupEntry` is a peer record returned by a DHT node
    /// during the iterative walk. The `value` carries an encoded
    /// address record — useful for diagnostics. For end-to-end
    /// connection, prefer [`Dht::connect`] which uses `find_peer`
    /// internally.
    pub async fn find_peer(&self, public_key: PublicKey) -> Result<Vec<LookupEntry>> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::FindPeer {
            public_key: *public_key.as_bytes(),
            response: tx,
        })?;
        rx.await?
    }

    /// Store a value at `target = BLAKE2b(value)`. Returns the target
    /// hash so callers can advertise it to retrieve via `immutable_get`.
    ///
    /// Immutable records are content-addressed — anyone storing the
    /// same bytes computes the same target. Useful for sharing pinned
    /// chunks (filenames, manifests, public keys).
    pub async fn immutable_put(&self, value: &[u8]) -> Result<[u8; 32]> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        // Compute target = BLAKE2b-256(value) up front so we can
        // return it on success without an extra round trip.
        let mut target = [0u8; 32];
        unsafe {
            hyperdht_sys::hyperdht_hash(value.as_ptr(), value.len(), target.as_mut_ptr());
        }

        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::ImmutablePut {
            value: value.to_vec(),
            response: tx,
        })?;
        rx.await??;
        Ok(target)
    }

    /// Retrieve a content-addressed value by its BLAKE2b-256 target.
    ///
    /// Returns `Ok(None)` if the target is not present on the DHT,
    /// `Ok(Some(bytes))` with the verified value otherwise. The C
    /// library checks `BLAKE2b(value) == target` before invoking the
    /// reply callback, so the value is integrity-checked.
    pub async fn immutable_get(&self, target: [u8; 32]) -> Result<Option<Vec<u8>>> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::ImmutableGet {
            target,
            response: tx,
        })?;
        rx.await?
    }
}
