//! `Server` — accept incoming connections to a published keypair.
//!
//! Created via [`Dht::listen`]. The libuv thread calls
//! `hyperdht_server_listen`; each incoming connection fires the C
//! `on_connection` callback, which inside the libuv thread atomically
//! opens a stream via `hyperdht_stream_open` and pushes the resulting
//! [`Stream`] onto an mpsc channel that [`Server::accept`] drains.

use tokio::sync::{mpsc, oneshot};

use crate::error::{HyperDhtError, Result};
use crate::keypair::PublicKey;
use crate::loop_thread::{AsyncWaker, Command, FirewallCallback, ServerCtxPtr, ServerPtr};
use crate::stream::Stream;

/// A server listening for incoming HyperDHT connections.
///
/// Drop the server (or call [`Server::close`]) to stop accepting and
/// unannounce from the DHT.
pub struct Server {
    /// Channel of incoming streams (sent by the C `on_connection` callback).
    pub(crate) incoming_rx: mpsc::UnboundedReceiver<Stream>,
    /// Pointer to the C `hyperdht_server_t`, used for close.
    pub(crate) server_ptr: ServerPtr,
    /// Pointer to the heap-allocated `ServerCtx`, freed in close cb.
    pub(crate) ctx_ptr: ServerCtxPtr,
    /// Send commands to the libuv thread (close).
    pub(crate) cmd_tx: mpsc::UnboundedSender<Command>,
    /// Wake the libuv loop after sending a command.
    pub(crate) waker: AsyncWaker,
    /// The public key this server is announcing under.
    pub(crate) public_key: PublicKey,
    /// Idempotency flag for close.
    pub(crate) close_sent: bool,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Server {
    /// The keypair this server is listening on.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Receive the next incoming connection. Returns `None` when the
    /// server has been closed (Drop'd or [`Server::close`]'d) and no
    /// further connections will arrive.
    pub async fn accept(&mut self) -> Option<Stream> {
        self.incoming_rx.recv().await
    }

    /// Stop accepting connections and unannounce from the DHT.
    ///
    /// Drop performs the same operation; this method just makes it
    /// awaitable. Note: `accept()` may still return previously-buffered
    /// streams after `close()` is called.
    pub fn close(mut self) {
        self.send_close_once();
        // self drops here; mpsc receiver closes when sender drops.
    }

    /// Install a firewall callback. The callback is invoked from the
    /// libuv thread before the Noise handshake completes; return
    /// `true` to accept, `false` to reject.
    ///
    /// Pass an `Option::None` to detach a previously-installed
    /// callback. The closure must be `Send` because it crosses the
    /// command channel; per-call invocation is single-threaded.
    pub fn set_firewall<F>(&self, cb: F) -> Result<()>
    where
        F: Fn(&PublicKey, &str, u16) -> bool + Send + 'static,
    {
        if self.close_sent {
            return Err(HyperDhtError::DhtClosed);
        }
        let boxed: FirewallCallback = Box::new(cb);
        self.cmd_tx
            .send(Command::ServerSetFirewall {
                server: self.server_ptr,
                ctx: self.ctx_ptr,
                cb: Some(boxed),
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();
        Ok(())
    }

    /// Detach a previously-installed firewall callback.
    pub fn clear_firewall(&self) -> Result<()> {
        if self.close_sent {
            return Err(HyperDhtError::DhtClosed);
        }
        self.cmd_tx
            .send(Command::ServerSetFirewall {
                server: self.server_ptr,
                ctx: self.ctx_ptr,
                cb: None,
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();
        Ok(())
    }

    /// Trigger an explicit re-announce on the DHT (useful after
    /// network changes).
    pub fn refresh(&self) -> Result<()> {
        if self.close_sent {
            return Err(HyperDhtError::DhtClosed);
        }
        self.cmd_tx
            .send(Command::ServerRefresh {
                server: self.server_ptr,
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();
        Ok(())
    }

    /// The server's externally-visible address (NAT-sampled). Returns
    /// `Ok(None)` while the address is not yet known.
    pub async fn address(&self) -> Result<Option<(String, u16)>> {
        if self.close_sent {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::ServerAddress {
                server: self.server_ptr,
                response: tx,
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();
        rx.await?
    }

    /// Resolve once the announcer has completed its first cycle and
    /// the server is fully discoverable on the DHT.
    pub async fn wait_listening(&self) -> Result<()> {
        if self.close_sent {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::ServerWaitListening {
                ctx: self.ctx_ptr,
                signal: tx,
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();
        rx.await.map_err(|_| HyperDhtError::DhtClosed)
    }

    fn send_close_once(&mut self) {
        if self.close_sent {
            return;
        }
        let _ = self.cmd_tx.send(Command::ServerClose {
            server: self.server_ptr,
            ctx: self.ctx_ptr,
        });
        self.waker.wake();
        self.close_sent = true;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.send_close_once();
    }
}

/// Builder helper used by `Dht::listen` after the libuv thread reports
/// successful server creation.
pub(crate) fn build_server(
    incoming_rx: mpsc::UnboundedReceiver<Stream>,
    server_ptr: ServerPtr,
    ctx_ptr: ServerCtxPtr,
    cmd_tx: mpsc::UnboundedSender<Command>,
    waker: AsyncWaker,
    public_key: PublicKey,
) -> Server {
    Server {
        incoming_rx,
        server_ptr,
        ctx_ptr,
        cmd_tx,
        waker,
        public_key,
        close_sent: false,
    }
}
