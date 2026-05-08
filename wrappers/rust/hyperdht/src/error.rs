//! Error types for the safe wrapper.

use thiserror::Error;

/// Result alias for HyperDHT operations.
pub type Result<T> = std::result::Result<T, HyperDhtError>;

/// Errors that can be returned from HyperDHT operations.
#[derive(Debug, Error)]
pub enum HyperDhtError {
    /// The DHT instance has been destroyed; no further operations possible.
    #[error("DHT instance has been destroyed")]
    DhtClosed,

    /// The async operation was cancelled (e.g. its future was dropped).
    #[error("operation cancelled")]
    Cancelled,

    /// The async operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// Could not bind to the requested port.
    #[error("bind failed (port {port}): {reason}")]
    BindFailed {
        /// The port that was attempted.
        port: u16,
        /// Reason from the underlying syscall.
        reason: String,
    },

    /// `connect()` could not locate the peer on the DHT.
    #[error("peer not found")]
    PeerNotFound,

    /// `connect()` reached the peer but the holepunch failed (NAT incompatibility,
    /// usually RANDOM+RANDOM with relay also unavailable).
    #[error("holepunch failed")]
    HolepunchFailed,

    /// `connect()` fell back to the relay path but it also failed.
    #[error("relay failed")]
    RelayFailed,

    /// Generic FFI error returned from the C library.
    ///
    /// `code` is the integer error code from `hyperdht.h` (e.g. `-3` =
    /// `HYPERDHT_ERR_CONNECTION_FAILED`).
    #[error("FFI error {code}: {reason}")]
    Ffi {
        /// The negative integer error code from hyperdht.h.
        code: i32,
        /// Human-readable explanation (from `hyperdht_connect_strerror` where applicable).
        reason: String,
    },

    /// Caller passed an invalid argument.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),

    /// Internal wrapper error (channel closed, thread panic, etc.).
    #[error("internal: {0}")]
    Internal(String),
}

impl HyperDhtError {
    /// Map a hyperdht.h error code to the corresponding `HyperDhtError`.
    #[allow(dead_code)] // used by upcoming connect/listen/destroy paths
    pub(crate) fn from_ffi_code(code: i32, reason: impl Into<String>) -> Self {
        use hyperdht_sys::*;
        // The HYPERDHT_ERR_* constants in hyperdht.h are negative ints.
        // bindgen exposes them as i32 constants.
        match code {
            x if x == HYPERDHT_ERR_DESTROYED as i32 => HyperDhtError::DhtClosed,
            x if x == HYPERDHT_ERR_PEER_NOT_FOUND as i32 => HyperDhtError::PeerNotFound,
            x if x == HYPERDHT_ERR_HOLEPUNCH_FAILED as i32 => HyperDhtError::HolepunchFailed,
            x if x == HYPERDHT_ERR_HOLEPUNCH_TIMEOUT as i32 => HyperDhtError::HolepunchFailed,
            x if x == HYPERDHT_ERR_RELAY_FAILED as i32 => HyperDhtError::RelayFailed,
            x if x == HYPERDHT_ERR_CANCELLED as i32 => HyperDhtError::Cancelled,
            _ => HyperDhtError::Ffi {
                code,
                reason: reason.into(),
            },
        }
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for HyperDhtError {
    fn from(_: tokio::sync::mpsc::error::SendError<T>) -> Self {
        HyperDhtError::DhtClosed
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for HyperDhtError {
    fn from(_: tokio::sync::oneshot::error::RecvError) -> Self {
        // The libuv-side dropped the responder without firing — only
        // happens during DHT teardown.
        HyperDhtError::DhtClosed
    }
}
