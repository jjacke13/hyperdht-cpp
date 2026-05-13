//! Options for `Dht::new`, `Dht::connect`, and `Dht::listen`.

use crate::keypair::PublicKey;

/// Options for creating a `Dht` instance.
#[derive(Debug, Clone)]
pub struct DhtOptions {
    /// Bind port (0 = OS picks an ephemeral port).
    pub port: u16,
    /// `true` = ephemeral node (default — most home users), `false` = persistent.
    pub ephemeral: bool,
    /// `true` = bootstrap from the canonical public HyperDHT nodes
    /// (`node{1,2,3}.hyperdht.org:49737`). Default `true`.
    pub use_public_bootstrap: bool,
    /// Optional explicit bootstrap nodes (`["10.0.0.1:49737", ...]`).
    /// Overrides `use_public_bootstrap` when non-empty.
    pub bootstrap_nodes: Vec<String>,
    /// Bind interface (`None` or empty = `0.0.0.0`).
    pub host: Option<String>,
    /// Optional 32-byte seed for deterministic identity (mobile use case).
    pub seed: Option<[u8; 32]>,
    /// Default keep-alive (ms) applied to streams.
    /// `None` = library default (5000ms). `Some(0)` = disabled.
    pub connection_keep_alive_ms: Option<u64>,
}

impl Default for DhtOptions {
    fn default() -> Self {
        DhtOptions {
            port: 0,
            ephemeral: true,
            use_public_bootstrap: true,
            bootstrap_nodes: Vec::new(),
            host: None,
            seed: None,
            connection_keep_alive_ms: None,
        }
    }
}

/// Options for `Dht::connect`.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Cache the underlying UDP socket for reuse on subsequent connects to
    /// the same peer (skips a second holepunch). Default `true` —
    /// strongly recommended for any application that opens multiple
    /// streams to the same peer (e.g. RustDesk's multi-ConnType case).
    pub reusable_socket: bool,

    /// Enable fast-open: opportunistically send 0-RTT data with the
    /// handshake. Default `true`.
    pub fast_open: bool,

    /// Optional pubkey of a third-party node to relay through if
    /// holepunch fails. Default `None` (use any DHT-discovered relay).
    pub relay_through: Option<PublicKey>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        ConnectOptions {
            reusable_socket: true,
            fast_open: true,
            relay_through: None,
        }
    }
}

/// Options for `Dht::listen`.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// Same meaning as `ConnectOptions::reusable_socket` — server-side
    /// caches its socket so reconnecting clients can skip the holepunch.
    /// Default `true`.
    pub reusable_socket: bool,

    /// Share local (LAN) addresses in the handshake reply, enabling
    /// the same-LAN shortcut. Default `true`.
    pub share_local_address: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        ServerOptions {
            reusable_socket: true,
            share_local_address: true,
        }
    }
}
