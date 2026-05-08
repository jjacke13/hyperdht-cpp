//! The `Dht` handle — the user's entry point.
//!
//! Internally owns a dedicated libuv pump thread (see [`loop_thread`])
//! and bridges async tokio operations to the libuv side via channels.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, Mutex};

use crate::error::{HyperDhtError, Result};
use crate::keypair::PublicKey;
use crate::loop_thread::{self, AsyncWaker, Command, Shutdown};
use crate::options::{ConnectOptions, DhtOptions};
use crate::stream::{build_stream, Stream};

/// A HyperDHT instance.
///
/// `Dht` is `Send + Sync`: the underlying libuv loop runs on a
/// dedicated OS thread, and all `&self` operations are thread-safe.
/// You can clone the underlying state and pass references across
/// tokio tasks.
///
/// # Lifecycle
///
/// Creation spawns a dedicated libuv thread. Drop signals shutdown
/// and joins the thread. To wait for shutdown to complete in an
/// async context, call [`Dht::destroy`] explicitly.
pub struct Dht {
    /// Channel for sending commands to the libuv thread.
    cmd_tx: mpsc::UnboundedSender<Command>,
    /// Wakeup handle (lets us pop the libuv loop out of `uv_run`
    /// when a new command arrives).
    waker: AsyncWaker,
    /// Shared shutdown signal.
    shutdown: Arc<Shutdown>,
    /// The pump thread's join handle. `Mutex` because we take it from
    /// `&mut self` in `destroy()` and from `&mut self` in `Drop`.
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// The bound port (cached after init).
    bound_port: u16,
}

impl std::fmt::Debug for Dht {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dht")
            .field("bound_port", &self.bound_port)
            .field("destroyed", &self.shutdown.is_signaled())
            .finish()
    }
}

impl Dht {
    /// Create a new HyperDHT instance.
    ///
    /// Spawns a dedicated OS thread for the libuv event loop. Returns
    /// once the DHT is bound and ready to accept commands.
    pub async fn new(opts: DhtOptions) -> Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let shutdown = Shutdown::new();

        let (join, init_rx) = loop_thread::spawn(opts, cmd_rx, shutdown.clone());

        // Wait for thread to finish initialization.
        let init = init_rx
            .await
            .map_err(|_| HyperDhtError::Internal("loop thread panicked during init".into()))??;

        Ok(Dht {
            cmd_tx,
            waker: init.waker,
            shutdown,
            join: Mutex::new(Some(join)),
            bound_port: init.bound_port,
        })
    }

    /// The port this DHT is bound to.
    pub fn port(&self) -> u16 {
        self.bound_port
    }

    /// Open an encrypted stream to the peer with the given public key.
    ///
    /// `_opts` is currently a placeholder — v0.1 uses the library
    /// defaults (fast_open=true, local_connection=true, no relay).
    /// Future versions will plumb the fields through.
    pub async fn connect(
        &self,
        peer: PublicKey,
        _opts: ConnectOptions,
    ) -> Result<Stream> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }

        let (response_tx, response_rx) = oneshot::channel();
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        let closed = Arc::new(AtomicBool::new(false));

        self.cmd_tx
            .send(Command::Connect {
                peer_pk: *peer.as_bytes(),
                response: response_tx,
                data_tx,
                closed: closed.clone(),
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();

        let stream_ptr = response_rx.await??;

        Ok(build_stream(
            stream_ptr,
            data_rx,
            closed,
            self.cmd_tx.clone(),
            self.waker.clone(),
        ))
    }

    /// Return `true` if [`destroy`] (or `Drop`) has been called.
    pub fn is_destroyed(&self) -> bool {
        self.shutdown.is_signaled()
    }

    /// Destroy the DHT instance, awaiting full teardown.
    ///
    /// After this returns, the libuv thread has exited and all
    /// resources are released. Equivalent to dropping `self` but
    /// awaitable.
    pub async fn destroy(self) -> Result<()> {
        // Take the join handle out of the Mutex so Drop won't double-join.
        let join = {
            let mut guard = self.join.lock().await;
            guard.take()
        };

        // Signal shutdown + wake the loop. The loop thread sees the
        // signal between iterations and breaks out of `uv_run`.
        self.shutdown.signal();
        self.waker.wake();

        if let Some(handle) = join {
            // Joining a std::thread is blocking. Do it on the tokio
            // blocking pool so we don't stall the worker.
            tokio::task::spawn_blocking(move || handle.join())
                .await
                .map_err(|_| HyperDhtError::Internal("join task cancelled".into()))?
                .map_err(|_| HyperDhtError::Internal("loop thread panicked".into()))?;
        }
        // self drops here — cmd_tx closes (already-dead thread, no-op).
        Ok(())
    }

    /// Internal: send a wake signal.
    #[allow(dead_code)]
    pub(crate) fn wake(&self) {
        self.waker.wake();
    }

    /// Internal: send a command to the libuv thread, then wake the loop.
    #[allow(dead_code)]
    pub(crate) fn send_command(&self, cmd: Command) -> Result<()> {
        self.cmd_tx
            .send(cmd)
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();
        Ok(())
    }
}

impl Drop for Dht {
    fn drop(&mut self) {
        // If destroy() was already called, join is None and signal is set.
        self.shutdown.signal();
        self.waker.wake();

        // Take the join handle synchronously. We're in Drop so we
        // can't await; just block. This is the documented "blocking
        // drop" behavior — users wanting non-blocking shutdown should
        // call destroy().await first.
        let handle = if let Ok(mut guard) = self.join.try_lock() {
            guard.take()
        } else {
            // Lock contended — destroy() is running concurrently and
            // will handle the join. Skip.
            return;
        };

        if let Some(handle) = handle {
            // Block the current thread until the loop thread exits.
            // For tokio users this means: don't drop a Dht from inside
            // an async context without await-ing destroy first.
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_bind_destroy_no_bootstrap() {
        let opts = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let dht = Dht::new(opts).await.expect("create dht");
        assert!(dht.port() != 0, "expected ephemeral port to be assigned");
        assert!(!dht.is_destroyed());
        dht.destroy().await.expect("destroy dht");
    }

    #[tokio::test]
    async fn drop_without_destroy_works() {
        let opts = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let dht = Dht::new(opts).await.expect("create dht");
        assert!(dht.port() != 0);
        // Drop runs here at end of scope — should not deadlock.
        drop(dht);
    }

    #[tokio::test]
    async fn connect_to_unknown_peer_fails_gracefully() {
        let opts = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let dht = Dht::new(opts).await.expect("create dht");

        // No DHT to walk → connect should fail (not hang).
        let unknown_peer = PublicKey([0xAA; 32]);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dht.connect(unknown_peer, ConnectOptions::default()),
        )
        .await;

        match result {
            Ok(Err(_)) => { /* expected: returned an error */ }
            Ok(Ok(_)) => panic!("connect to random pubkey should not succeed"),
            Err(_) => panic!("connect should not hang past 10s without bootstrap"),
        }

        dht.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn create_two_instances_concurrent() {
        let opts1 = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let opts2 = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let (dht1, dht2) = tokio::join!(Dht::new(opts1), Dht::new(opts2));
        let dht1 = dht1.expect("create dht1");
        let dht2 = dht2.expect("create dht2");
        assert_ne!(dht1.port(), dht2.port(), "ephemeral ports should differ");
        dht1.destroy().await.unwrap();
        dht2.destroy().await.unwrap();
    }
}
