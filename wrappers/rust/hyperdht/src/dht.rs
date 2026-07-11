//! The `Dht` handle — the user's entry point.
//!
//! Internally owns a dedicated libuv pump thread (see [`loop_thread`])
//! and bridges async tokio operations to the libuv side via channels.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, watch, Mutex};

use crate::error::{HyperDhtError, Result};
use crate::keypair::{Keypair, PublicKey};
use crate::loop_thread::{self, AsyncWaker, Command, DhtFlags, DhtState, Shutdown};
use crate::options::{ConnectOptions, DhtOptions, ServerOptions};
use crate::server::{build_server, Server};
use crate::stream::{build_stream, Stream};

/// One entry in a routing-table snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAddr {
    /// IPv4 dotted-quad host string.
    pub host: String,
    /// UDP port.
    pub port: u16,
}

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
    /// Mirror of the DHT's lifecycle flags (online, persistent, etc.).
    /// Updated by the libuv thread; read lock-free by Rust callers.
    state: Arc<DhtState>,
    /// Subscribe-handle for lifecycle events (bootstrapped, persistent,
    /// online flips). One persistent receiver per Dht; `wait_*` methods
    /// clone via `subscribe()` so multiple awaiters can wait
    /// independently without stealing each other's notifications.
    events_rx: watch::Receiver<DhtFlags>,
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
        let (state, events_rx) = DhtState::new();

        let (join, init_rx) =
            loop_thread::spawn(opts, cmd_rx, shutdown.clone(), state.clone());

        // Wait for thread to finish initialization.
        let init = init_rx
            .await
            .map_err(|_| HyperDhtError::Internal("loop thread panicked during init".into()))??;

        Ok(Dht {
            cmd_tx,
            waker: init.waker,
            shutdown,
            state,
            events_rx,
            join: Mutex::new(Some(join)),
            bound_port: init.bound_port,
        })
    }

    /// The port this DHT is bound to.
    pub fn port(&self) -> u16 {
        self.bound_port
    }

    /// `true` once the DHT has heard from at least one peer (a
    /// reachable bootstrap node responded). Cleared by `suspend`.
    pub fn is_online(&self) -> bool {
        self.state.online.load(Ordering::Relaxed)
    }

    /// `true` once the node has transitioned to a persistent role
    /// (port-preservation NAT confirmed; eligible to serve DHT
    /// traffic on its server socket).
    pub fn is_persistent(&self) -> bool {
        self.state.persistent.load(Ordering::Relaxed)
    }

    /// `true` once the initial bootstrap walk has populated the
    /// routing table. Subsequent reads remain `true` until the DHT
    /// is destroyed.
    pub fn is_bootstrapped(&self) -> bool {
        self.state.bootstrapped.load(Ordering::Relaxed)
    }

    /// `true` if the DHT has dropped below the healthy peer threshold
    /// after a network change.
    pub fn is_degraded(&self) -> bool {
        self.state.degraded.load(Ordering::Relaxed)
    }

    /// `true` between [`suspend`](Self::suspend) and
    /// [`resume`](Self::resume).
    pub fn is_suspended(&self) -> bool {
        self.state.suspended.load(Ordering::Relaxed)
    }

    /// Snapshot the routing table — returns up to 256 known peer
    /// addresses. Mobile apps can persist this and feed it back via
    /// [`add_node`](Self::add_node) on next launch to skip a cold
    /// bootstrap.
    pub async fn nodes_snapshot(&self) -> Result<Vec<NodeAddr>> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::NodesSnapshot { response: tx })?;
        rx.await?
    }

    /// The DHT's externally-visible address as observed via NAT
    /// sampling. Returns `Ok(None)` if the address isn't yet known
    /// (firewalled, fresh start, sampled port mismatch).
    pub async fn remote_address(&self) -> Result<Option<(String, u16)>> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::RemoteAddress { response: tx })?;
        rx.await?
    }

    /// Insert a routing-table entry by `host:port` — used to restore
    /// a snapshot taken via [`nodes_snapshot`](Self::nodes_snapshot)
    /// or to seed a private DHT.
    pub async fn add_node(&self, host: &str, port: u16) -> Result<()> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::AddNode {
            host: host.to_owned(),
            port,
            response: tx,
        })?;
        rx.await?
    }

    /// Suspend background activity (announcer, probes, holepunch
    /// timers) — for mobile apps entering background. Pair with
    /// [`resume`](Self::resume) on foregrounding.
    pub async fn suspend(&self) -> Result<()> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::Suspend { response: tx })?;
        rx.await?
    }

    /// Resume background activity after a [`suspend`](Self::suspend).
    pub async fn resume(&self) -> Result<()> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.send_command_internal(Command::Resume { response: tx })?;
        rx.await?
    }

    /// Resolve once the DHT has finished its initial bootstrap walk.
    ///
    /// Returns immediately if already bootstrapped. Otherwise awaits
    /// the next state flip; resolves with [`HyperDhtError::DhtClosed`]
    /// if the DHT is destroyed before the flip.
    pub async fn wait_bootstrapped(&self) -> Result<()> {
        self.wait_for_flag(|f| f.bootstrapped).await
    }

    /// Resolve once the DHT has heard from at least one peer (`is_online`).
    pub async fn wait_online(&self) -> Result<()> {
        self.wait_for_flag(|f| f.online).await
    }

    /// Resolve once the DHT has transitioned to a persistent role.
    pub async fn wait_persistent(&self) -> Result<()> {
        self.wait_for_flag(|f| f.persistent).await
    }

    async fn wait_for_flag<F>(&self, predicate: F) -> Result<()>
    where
        F: Fn(&DhtFlags) -> bool,
    {
        // Subscribe a fresh receiver so multiple awaiters don't steal
        // each other's `changed()` notifications.
        let mut rx = self.events_rx.clone();
        loop {
            // borrow_and_update returns the current value AND clears
            // the "changed" flag, so the subsequent `changed().await`
            // only fires on a fresh flip.
            let satisfied = predicate(&*rx.borrow_and_update());
            if satisfied {
                return Ok(());
            }
            if self.is_destroyed() {
                return Err(HyperDhtError::DhtClosed);
            }
            match rx.changed().await {
                Ok(()) => continue,
                Err(_) => return Err(HyperDhtError::DhtClosed),
            }
        }
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

        let (stream_ptr, ctx_ptr) = response_rx.await??;

        Ok(build_stream(
            stream_ptr,
            ctx_ptr,
            data_rx,
            closed,
            self.cmd_tx.clone(),
            self.waker.clone(),
        ))
    }

    /// Start listening for incoming connections on the given keypair.
    ///
    /// Each accepted connection becomes a [`Stream`] returned by
    /// [`Server::accept`]. Drop the [`Server`] (or call
    /// [`Server::close`]) to stop listening and unannounce.
    pub async fn listen(&self, kp: Keypair, opts: ServerOptions) -> Result<Server> {
        if self.is_destroyed() {
            return Err(HyperDhtError::DhtClosed);
        }

        let public_key = kp.public();

        // SAFETY: Keypair::as_ffi returns a valid pointer; we read
        // the bytes synchronously, before the keypair could be freed.
        let (pk_bytes, sk_bytes) = unsafe {
            let kp_ffi = &*kp.as_ffi();
            (kp_ffi.public_key, kp_ffi.secret_key)
        };

        let (response_tx, response_rx) = oneshot::channel();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();

        self.cmd_tx
            .send(Command::ServerListen {
                public_key: pk_bytes,
                secret_key: sk_bytes,
                share_local_address: opts.share_local_address,
                reusable_socket: opts.reusable_socket,
                incoming_tx,
                response: response_tx,
                new_stream_cmd_tx: self.cmd_tx.clone(),
                new_stream_waker: self.waker.clone(),
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();

        let (server_ptr, ctx_ptr) = response_rx.await??;

        // The keypair was copied bytewise into the command; we can drop
        // it now (zeroing happens in Drop).
        drop(kp);

        Ok(build_server(
            incoming_rx,
            server_ptr,
            ctx_ptr,
            self.cmd_tx.clone(),
            self.waker.clone(),
            public_key,
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
    pub(crate) fn send_command_internal(&self, cmd: Command) -> Result<()> {
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
    async fn listen_returns_server_with_correct_pubkey() {
        use crate::keypair::Keypair;

        let opts = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let dht = Dht::new(opts).await.expect("create dht");

        let kp = Keypair::generate();
        let expected_pk = kp.public();

        let server = dht
            .listen(kp, ServerOptions::default())
            .await
            .expect("listen");

        assert_eq!(server.public_key(), expected_pk);
        // Drop server first, then dht (close order matters for clean teardown).
        drop(server);
        dht.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn dht_op_methods_compile_and_return_errors_on_isolated_node() {
        // With no bootstrap, DHT ops have no peers to walk. Most should
        // return quickly (success or known error) — the point of this
        // test is to verify the call paths are wired through the libuv
        // thread + callback bridge without hanging.
        let opts = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let dht = Dht::new(opts).await.expect("create dht");

        let target = [0xABu8; 32];

        // Lookup with no DHT to walk → should complete quickly with empty result.
        let lookup = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dht.lookup(target),
        )
        .await
        .expect("lookup did not hang");
        assert!(lookup.is_ok(), "lookup returned err: {:?}", lookup);

        // Announce with no DHT → completes (might be Ok with 0 peers reached, or err).
        let announce_kp = crate::keypair::Keypair::generate();
        let announce = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dht.announce(target, &announce_kp),
        )
        .await
        .expect("announce did not hang");
        // Don't assert success — can be Ok(()) or Err(_). Just verify completion.
        let _ = announce;

        dht.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn mutable_get_returns_none_for_unknown_key() {
        use crate::keypair::Keypair;
        let opts = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let dht = Dht::new(opts).await.expect("create dht");

        let kp = Keypair::generate();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dht.mutable_get(kp.public(), 0),
        )
        .await
        .expect("mutable_get did not hang");
        match result {
            Ok(None) => { /* expected */ }
            Ok(Some(_)) => panic!("mutable_get returned a record we never put"),
            Err(_) => { /* also acceptable on isolated node */ }
        }

        dht.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn state_inspectors_return_without_blocking() {
        let opts = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let dht = Dht::new(opts).await.expect("create dht");

        // The inspectors must answer instantly without going
        // through the command channel. We don't assert specific
        // truth values for is_online / is_persistent because the
        // C library updates them based on internal heuristics
        // that vary by platform; just confirm the calls return.
        let _ = dht.is_online();
        let _ = dht.is_persistent();
        let _ = dht.is_bootstrapped();
        assert!(!dht.is_suspended());

        // Async one-shots resolve immediately even on an isolated node.
        let snapshot = dht.nodes_snapshot().await.expect("snapshot");
        // With no bootstrap and no peers, the routing table only
        // contains our self-entry (or is empty).
        assert!(snapshot.len() <= 1);

        let addr = dht.remote_address().await.expect("remote address call");
        // Isolated node has no NAT samples → None.
        assert!(addr.is_none());

        dht.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn wait_for_flag_unblocks_when_dht_destroyed() {
        // wait_persistent on an isolated node never flips the flag;
        // dropping the DHT must unblock the waiter with DhtClosed.
        let opts = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let dht = Dht::new(opts).await.expect("create dht");
        let events_rx = dht.events_rx.clone();

        // Spawn a waiter that uses the same predicate machinery as
        // wait_persistent, but operates on a cloned receiver so we
        // can drop the dht without moving it.
        let waiter = tokio::spawn(async move {
            let mut rx = events_rx;
            // Receiver returns Err on Sender drop → loop exits.
            loop {
                if rx.borrow_and_update().persistent {
                    return Ok::<(), HyperDhtError>(());
                }
                if rx.changed().await.is_err() {
                    return Err(HyperDhtError::DhtClosed);
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        dht.destroy().await.unwrap();

        // Waiter should resolve quickly with an error once the
        // watch::Sender (held by DhtState) is dropped during teardown.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            waiter,
        )
        .await;
        assert!(
            result.is_ok(),
            "wait_for_flag did not unblock within 3s of dht destroy"
        );
    }

    #[tokio::test]
    async fn add_node_and_suspend_resume_round_trip() {
        let opts = DhtOptions {
            use_public_bootstrap: false,
            ..Default::default()
        };
        let dht = Dht::new(opts).await.expect("create dht");

        // 127.0.0.1:1 won't respond to anything but the call should
        // succeed at the syscall level (host is parseable).
        dht.add_node("127.0.0.1", 1).await.expect("add_node");

        dht.suspend().await.expect("suspend");
        assert!(dht.is_suspended());
        dht.resume().await.expect("resume");
        assert!(!dht.is_suspended());

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
