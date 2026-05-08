//! Async-friendly Rust wrapper for [hyperdht-cpp](https://github.com/jjacke13/hyperdht-cpp).
//!
//! See the crate-level README for the architecture overview.

#![warn(missing_docs)]

mod dht;
mod error;
mod keypair;
mod loop_thread;
mod options;
mod stream;

pub use dht::Dht;
pub use error::{HyperDhtError, Result};
pub use keypair::{Keypair, PublicKey, PUBLIC_KEY_LEN, SEED_LEN};
pub use options::{ConnectOptions, DhtOptions, ServerOptions};
pub use stream::Stream;
