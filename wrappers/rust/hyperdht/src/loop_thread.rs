//! The dedicated libuv pump thread.
//!
//! This module is the heart of the wrapper. It owns the `uv_loop_t`,
//! the `hyperdht_t*`, and a `uv_async_t` wakeup handle. Tokio tasks
//! send commands via an mpsc channel; the thread drains them between
//! `uv_run` cycles. The wakeup handle is woken (via `uv_async_send`)
//! whenever a new command arrives, so the loop unblocks immediately.

use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use hyperdht_sys::*;
use tokio::sync::{mpsc, oneshot, watch};

use crate::error::{HyperDhtError, Result};
use crate::options::DhtOptions;

// ============================================================================
// Send wrappers around raw libuv/hyperdht pointers
// ============================================================================

/// `*mut uv_async_t` wrapped Send/Sync (uv_async_send is the only
/// thread-safe libuv API; we never deref this pointer outside the
/// loop thread).
#[derive(Clone, Copy)]
pub(crate) struct AsyncPtr(*mut uv_async_t);
unsafe impl Send for AsyncPtr {}
unsafe impl Sync for AsyncPtr {}

#[derive(Clone)]
pub(crate) struct AsyncWaker {
    ptr: AsyncPtr,
}

impl AsyncWaker {
    /// Wake the libuv loop. Idempotent (multiple wakes coalesce).
    pub(crate) fn wake(&self) {
        unsafe { uv_async_send(self.ptr.0) };
    }
}

/// `*mut hyperdht_stream_t` Send-wrapped. Streams are owned by the
/// libuv thread; the Rust `Stream` only sends commands referencing
/// the pointer.
#[derive(Clone, Copy)]
pub(crate) struct StreamPtr(pub(crate) *mut hyperdht_stream_t);
unsafe impl Send for StreamPtr {}
unsafe impl Sync for StreamPtr {}

/// `*mut hyperdht_server_t` Send-wrapped (server lifetime is tied to
/// the DHT instance and to the Server handle).
#[derive(Clone, Copy)]
pub(crate) struct ServerPtr(pub(crate) *mut hyperdht_server_t);
unsafe impl Send for ServerPtr {}
unsafe impl Sync for ServerPtr {}

/// `*mut c_void` for a heap-allocated `ServerCtx` box, freed in the
/// `hyperdht_server_close` callback.
#[derive(Clone, Copy)]
pub(crate) struct ServerCtxPtr(pub(crate) *mut c_void);
unsafe impl Send for ServerCtxPtr {}
unsafe impl Sync for ServerCtxPtr {}

/// `*mut c_void` for a heap-allocated `StreamCtx` box (lives while
/// the underlying C stream lives, freed in `on_close_cb`). Used to
/// install secondary callbacks like UDP datagrams.
#[derive(Clone, Copy)]
pub(crate) struct StreamCtxPtr(pub(crate) *mut c_void);
unsafe impl Send for StreamCtxPtr {}
unsafe impl Sync for StreamCtxPtr {}

// ============================================================================
// Shared shutdown signal
// ============================================================================

pub(crate) struct Shutdown {
    flag: AtomicBool,
}

impl Shutdown {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Shutdown {
            flag: AtomicBool::new(false),
        })
    }

    pub(crate) fn signal(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_signaled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

// ============================================================================
// Shared mirror of the DHT's lifecycle flags
//
// The C library's `hyperdht_is_online` etc. are documented as
// loop-thread-only. To expose them as cheap sync inspectors on the
// public Rust API, we keep an atomic mirror: the pump thread refreshes
// it each iteration and event callbacks bump it instantly.
// ============================================================================

pub(crate) struct DhtState {
    pub(crate) online: AtomicBool,
    pub(crate) persistent: AtomicBool,
    pub(crate) bootstrapped: AtomicBool,
    pub(crate) degraded: AtomicBool,
    pub(crate) suspended: AtomicBool,
    /// `watch::Sender` writes (online, persistent, bootstrapped) so
    /// awaiters can `recv().await` the next flip without polling.
    /// Wrapped in `Mutex` only because `watch::Sender` requires `&mut`
    /// to call `send`; contention is negligible (libuv thread only).
    events: std::sync::Mutex<watch::Sender<DhtFlags>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DhtFlags {
    pub online: bool,
    pub persistent: bool,
    pub bootstrapped: bool,
    pub degraded: bool,
    pub suspended: bool,
}

impl DhtState {
    pub(crate) fn new() -> (Arc<Self>, watch::Receiver<DhtFlags>) {
        let (tx, rx) = watch::channel(DhtFlags::default());
        let state = Arc::new(DhtState {
            online: AtomicBool::new(false),
            persistent: AtomicBool::new(false),
            bootstrapped: AtomicBool::new(false),
            degraded: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            events: std::sync::Mutex::new(tx),
        });
        (state, rx)
    }

    /// Read the current C-side flags into this mirror. Must be called
    /// from the libuv thread (matches the C contract).
    fn refresh_from(&self, dht: *mut hyperdht_t) {
        let flags = unsafe {
            DhtFlags {
                online: hyperdht_is_online(dht) != 0,
                persistent: hyperdht_is_persistent(dht) != 0,
                bootstrapped: hyperdht_is_bootstrapped(dht) != 0,
                degraded: hyperdht_is_degraded(dht) != 0,
                suspended: hyperdht_is_suspended(dht) != 0,
            }
        };
        self.online.store(flags.online, Ordering::Relaxed);
        self.persistent.store(flags.persistent, Ordering::Relaxed);
        self.bootstrapped
            .store(flags.bootstrapped, Ordering::Relaxed);
        self.degraded.store(flags.degraded, Ordering::Relaxed);
        self.suspended.store(flags.suspended, Ordering::Relaxed);
        if let Ok(events) = self.events.lock() {
            // send_replace returns the previous value; we don't care.
            // Awaiters of changed() will only wake if the new value
            // differs from the last observed one.
            let _ = events.send_replace(flags);
        }
    }
}

// ============================================================================
// Commands sent from tokio side to the libuv thread
// ============================================================================

pub(crate) enum Command {
    /// Just wake the loop (used when shutdown is requested).
    #[allow(dead_code)] // reserved for explicit wake outside command flow
    Wake,

    /// Initiate a connect to a remote peer. The libuv thread calls
    /// `hyperdht_connect_and_open_stream` and delivers the resulting
    /// stream pointer (or error) via `response`.
    Connect {
        peer_pk: [u8; 32],
        /// Sender for delivering the open stream pointer + ctx pointer
        /// (the latter is needed to install datagram callbacks later).
        response: oneshot::Sender<Result<(StreamPtr, StreamCtxPtr)>>,
        /// Sender for incoming data chunks (saved into `StreamCtx`,
        /// dispatched from the C `on_data` callback).
        data_tx: mpsc::UnboundedSender<Bytes>,
        /// Set when on_close fires.
        closed: Arc<AtomicBool>,
    },

    /// Write data to a stream.
    StreamWrite {
        stream: StreamPtr,
        data: Bytes,
    },

    /// Close a stream.
    StreamClose {
        stream: StreamPtr,
    },

    /// Enable datagram reception on a stream — installs the C
    /// callback and stores the user's tokio mpsc sender in StreamCtx.
    StreamEnableDatagrams {
        stream: StreamPtr,
        ctx: StreamCtxPtr,
        tx: mpsc::UnboundedSender<Bytes>,
        response: oneshot::Sender<Result<()>>,
    },

    /// Send an unreliable encrypted datagram on a stream. Reports
    /// the FFI return code via `response`.
    StreamSendUdp {
        stream: StreamPtr,
        data: Vec<u8>,
        response: oneshot::Sender<Result<()>>,
    },

    /// Fire-and-forget variant — never reports back, drops on
    /// pressure rather than blocking.
    StreamTrySendUdp {
        stream: StreamPtr,
        data: Vec<u8>,
    },

    /// Create a server and start listening on the given keypair.
    ServerListen {
        public_key: [u8; 32],
        secret_key: [u8; 64],
        share_local_address: bool,
        reusable_socket: bool,
        /// Sender for incoming streams (one per accepted connection).
        incoming_tx: mpsc::UnboundedSender<crate::stream::Stream>,
        /// Reply channel for the server pointer + ctx pointer (for close).
        response: oneshot::Sender<Result<(ServerPtr, ServerCtxPtr)>>,
        /// Cmd sender given to each new Stream (so writes/closes route
        /// back to the libuv thread). Cloned from the Dht's cmd_tx.
        new_stream_cmd_tx: mpsc::UnboundedSender<Command>,
        /// Waker given to each new Stream.
        new_stream_waker: AsyncWaker,
    },

    /// Close a server.
    ServerClose {
        server: ServerPtr,
        ctx: ServerCtxPtr,
    },

    /// Install (or remove) a firewall callback on a server. Pass
    /// `cb=None` to detach.
    ServerSetFirewall {
        server: ServerPtr,
        ctx: ServerCtxPtr,
        cb: Option<FirewallCallback>,
    },

    /// Subscribe to the next "listening" event for a server. The
    /// libuv thread fires the oneshot after the announcer's first
    /// cycle completes (or immediately if it already has).
    ServerWaitListening {
        ctx: ServerCtxPtr,
        signal: oneshot::Sender<()>,
    },

    /// Trigger an explicit re-announce on a server.
    ServerRefresh {
        server: ServerPtr,
    },

    /// Get the server's NAT-sampled public address.
    ServerAddress {
        server: ServerPtr,
        response: oneshot::Sender<Result<Option<(String, u16)>>>,
    },

    /// Announce a keypair at a target on the DHT. The commit signs a fresh
    /// record per node, so this carries the keypair (not a pre-signed value).
    Announce {
        target: [u8; 32],
        public_key: [u8; 32],
        secret_key: [u8; 64],
        response: oneshot::Sender<Result<()>>,
    },

    /// Look up values stored at a target. Returns all matching peer
    /// records collected during the iterative DHT walk.
    Lookup {
        target: [u8; 32],
        response: oneshot::Sender<Result<Vec<crate::dht_ops::LookupEntry>>>,
    },

    /// Store a signed mutable value at target=BLAKE2b(pubkey).
    MutablePut {
        public_key: [u8; 32],
        secret_key: [u8; 64],
        value: Vec<u8>,
        seq: u64,
        response: oneshot::Sender<Result<()>>,
    },

    /// Retrieve the latest signed mutable value for a public key.
    MutableGet {
        public_key: [u8; 32],
        min_seq: u64,
        response:
            oneshot::Sender<Result<Option<crate::dht_ops::MutableRecord>>>,
    },

    /// Withdraw a previously-announced value from a target. Requires
    /// the same keypair as the original announce.
    Unannounce {
        target: [u8; 32],
        public_key: [u8; 32],
        secret_key: [u8; 64],
        response: oneshot::Sender<Result<()>>,
    },

    /// Resolve a peer's network address records by their public key.
    /// Returns peer records collected during the iterative DHT walk.
    FindPeer {
        public_key: [u8; 32],
        response: oneshot::Sender<Result<Vec<crate::dht_ops::LookupEntry>>>,
    },

    /// Store a content-addressed value (target = BLAKE2b(value)).
    ImmutablePut {
        value: Vec<u8>,
        response: oneshot::Sender<Result<()>>,
    },

    /// Retrieve a content-addressed value by its BLAKE2b target.
    ImmutableGet {
        target: [u8; 32],
        response: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },

    /// Snapshot the routing table (host:port pairs).
    NodesSnapshot {
        response: oneshot::Sender<Result<Vec<crate::dht::NodeAddr>>>,
    },

    /// Get the public-facing host:port (NAT-sampled). Returns None if
    /// the DHT hasn't observed enough samples yet.
    RemoteAddress {
        response: oneshot::Sender<Result<Option<(String, u16)>>>,
    },

    /// Insert a routing-table entry at runtime.
    AddNode {
        host: String,
        port: u16,
        response: oneshot::Sender<Result<()>>,
    },

    /// Suspend the DHT (mobile background transition).
    Suspend {
        response: oneshot::Sender<Result<()>>,
    },

    /// Resume the DHT after a suspend.
    Resume {
        response: oneshot::Sender<Result<()>>,
    },
}

// ============================================================================
// Init result reported back to Dht::new
// ============================================================================

pub(crate) struct InitResult {
    pub bound_port: u16,
    pub waker: AsyncWaker,
}

// ============================================================================
// Per-stream state, lives on the heap, freed in on_close
// ============================================================================

struct StreamCtx {
    /// `Some` until on_open fires (client-side connect path) or until
    /// on_close fires before that (failure). `None` for server-accepted
    /// streams (open is observed synchronously).
    response: Mutex<Option<oneshot::Sender<Result<(StreamPtr, StreamCtxPtr)>>>>,

    /// Stored by on_connect_cb (client path) so on_open_cb can deliver
    /// it via `response`. The C SecretStream header exchange isn't
    /// complete until on_open fires; writing before that drops bytes
    /// (see CLAUDE.md gotcha #7).
    pending_stream: Mutex<Option<StreamPtr>>,

    /// Sender for incoming data chunks (delivered to the Rust `Stream`'s
    /// AsyncRead via the corresponding `Receiver`).
    data_tx: mpsc::UnboundedSender<Bytes>,

    /// Sender for incoming unreliable datagrams. `None` until the
    /// user calls `Stream::enable_datagrams`. Set on the libuv thread
    /// inside the matching command dispatcher.
    udp_tx: Mutex<Option<mpsc::UnboundedSender<Bytes>>>,

    /// Flipped to `true` by on_close.
    closed: Arc<AtomicBool>,
}

/// Boxed user-supplied firewall callback. Called from the libuv thread
/// inside the C `hyperdht_firewall_cb`; must return `true` to accept
/// the connection or `false` to reject it.
pub(crate) type FirewallCallback =
    Box<dyn Fn(&crate::keypair::PublicKey, &str, u16) -> bool + Send + 'static>;

/// One-shot signal that a server has finished its first announcer
/// cycle (i.e. is ready to be discovered). Optional — `None` until
/// `wait_listening()` subscribes for the first time.
pub(crate) type ListeningWaiter = oneshot::Sender<()>;

/// Per-server state. Owned by `hyperdht_server_listen` as userdata,
/// freed in `hyperdht_server_close`'s callback. Stays on the libuv
/// thread for its entire lifetime — never sent across threads.
struct ServerCtx {
    /// DHT pointer needed to call `hyperdht_stream_open` from within
    /// the on_connection callback.
    dht: *mut hyperdht_t,
    /// Sender for newly-accepted streams.
    incoming_tx: mpsc::UnboundedSender<crate::stream::Stream>,
    /// Cloned from the loop's command sender, given to each new Stream
    /// so writes/closes route back to the libuv thread.
    cmd_tx: mpsc::UnboundedSender<Command>,
    /// Same — given to each Stream for waking the loop.
    waker: AsyncWaker,
    /// User-supplied firewall callback. Single-threaded (libuv only),
    /// no synchronisation needed beyond raw pointer access.
    firewall: Option<FirewallCallback>,
    /// One-shot subscribers to the "first announcer cycle done" event.
    /// Multiple awaiters can subscribe; they are all fired when the C
    /// `on_listening` event lands.
    listening_waiters: Vec<ListeningWaiter>,
    /// `true` once the C `on_listening` hook has fired. New
    /// `ServerWaitListening` requests resolve immediately.
    already_listening: bool,
}

// ============================================================================
// Spawn the pump thread
// ============================================================================

pub(crate) fn spawn(
    opts: DhtOptions,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    shutdown: Arc<Shutdown>,
    state: Arc<DhtState>,
) -> (
    std::thread::JoinHandle<()>,
    oneshot::Receiver<Result<InitResult>>,
) {
    let (init_tx, init_rx) = oneshot::channel();

    let join = std::thread::Builder::new()
        .name("hyperdht-loop".to_string())
        .spawn(move || run(opts, cmd_rx, shutdown, state, init_tx))
        .expect("spawn hyperdht-loop thread");

    (join, init_rx)
}

// ============================================================================
// Pump thread main
// ============================================================================

fn run(
    opts: DhtOptions,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    shutdown: Arc<Shutdown>,
    state: Arc<DhtState>,
    init_tx: oneshot::Sender<Result<InitResult>>,
) {
    // ---- libuv loop ----
    let mut loop_storage: Box<uv_loop_t> = Box::new(unsafe { std::mem::zeroed() });
    let loop_ptr: *mut uv_loop_t = &mut *loop_storage;

    let rc = unsafe { uv_loop_init(loop_ptr) };
    if rc != 0 {
        let _ = init_tx.send(Err(HyperDhtError::Internal(format!(
            "uv_loop_init failed: {}",
            rc
        ))));
        return;
    }

    // ---- async wakeup handle ----
    let mut async_storage: Box<uv_async_t> = Box::new(unsafe { std::mem::zeroed() });
    let async_ptr: *mut uv_async_t = &mut *async_storage;

    let rc = unsafe { uv_async_init(loop_ptr, async_ptr, Some(noop_async_cb)) };
    if rc != 0 {
        unsafe { uv_loop_close(loop_ptr) };
        let _ = init_tx.send(Err(HyperDhtError::Internal(format!(
            "uv_async_init failed: {}",
            rc
        ))));
        return;
    }

    let waker = AsyncWaker {
        ptr: AsyncPtr(async_ptr),
    };

    // ---- build hyperdht_opts_t ----
    let host_cstr = opts
        .host
        .as_deref()
        .and_then(|s| CString::new(s).ok());
    let bootstrap_cstrs: Vec<CString> = opts
        .bootstrap_nodes
        .iter()
        .filter_map(|s| CString::new(s.as_str()).ok())
        .collect();
    let bootstrap_ptrs: Vec<*const ::std::os::raw::c_char> =
        bootstrap_cstrs.iter().map(|c| c.as_ptr()).collect();

    let mut c_opts: hyperdht_opts_t = unsafe { std::mem::zeroed() };
    unsafe { hyperdht_opts_default(&mut c_opts) };
    c_opts.port = opts.port;
    c_opts.ephemeral = if opts.ephemeral { 1 } else { 0 };
    c_opts.use_public_bootstrap = if opts.use_public_bootstrap { 1 } else { 0 };
    c_opts.host = match host_cstr.as_ref() {
        Some(c) => c.as_ptr(),
        None => ptr::null(),
    };
    if !bootstrap_ptrs.is_empty() {
        c_opts.nodes = bootstrap_ptrs.as_ptr();
        c_opts.nodes_len = bootstrap_ptrs.len();
    }
    if let Some(seed) = &opts.seed {
        c_opts.seed.copy_from_slice(seed);
        c_opts.seed_is_set = 1;
    }
    c_opts.connection_keep_alive = opts.connection_keep_alive_ms.unwrap_or(u64::MAX);

    // ---- create DHT ----
    let dht = unsafe { hyperdht_create(loop_ptr, &c_opts) };
    if dht.is_null() {
        unsafe {
            uv_close(async_ptr as *mut uv_handle_t, None);
            uv_run(loop_ptr, uv_run_mode::UV_RUN_DEFAULT);
            uv_loop_close(loop_ptr);
        }
        let _ = init_tx.send(Err(HyperDhtError::Internal(
            "hyperdht_create returned null".into(),
        )));
        return;
    }

    // ---- bind ----
    let rc = unsafe { hyperdht_bind(dht, opts.port) };
    if rc != 0 {
        unsafe {
            hyperdht_destroy(dht, None, ptr::null_mut());
            uv_close(async_ptr as *mut uv_handle_t, None);
            uv_run(loop_ptr, uv_run_mode::UV_RUN_DEFAULT);
            hyperdht_free(dht);
            uv_loop_close(loop_ptr);
        }
        let _ = init_tx.send(Err(HyperDhtError::BindFailed {
            port: opts.port,
            reason: format!("hyperdht_bind returned {}", rc),
        }));
        return;
    }

    let bound_port = unsafe { hyperdht_port(dht) };

    drop(host_cstr);
    drop(bootstrap_cstrs);

    state.refresh_from(dht);

    // ---- report success ----
    if init_tx
        .send(Ok(InitResult {
            bound_port,
            waker: waker.clone(),
        }))
        .is_err()
    {
        teardown(dht, async_ptr, loop_ptr);
        return;
    }

    // ---- pump loop ----
    loop {
        loop {
            match cmd_rx.try_recv() {
                Ok(cmd) => dispatch_command(dht, cmd, &state),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    shutdown.signal();
                    break;
                }
            }
        }

        if shutdown.is_signaled() {
            break;
        }

        let active = unsafe { uv_run(loop_ptr, uv_run_mode::UV_RUN_ONCE) };
        // Refresh state after each loop tick so flips like "we just
        // got bootstrapped" or "first persistent transition" become
        // visible to user-side reads without a wait.
        state.refresh_from(dht);
        if active == 0 {
            break;
        }
    }

    teardown(dht, async_ptr, loop_ptr);
}

fn dispatch_command(
    dht: *mut hyperdht_t,
    cmd: Command,
    state: &Arc<DhtState>,
) {
    match cmd {
        Command::Wake => { /* handled by the surrounding loop */ }

        Command::Connect {
            peer_pk,
            response,
            data_tx,
            closed,
        } => {
            // Allocate per-stream context. Lives until on_close fires
            // (success path) or on_connect with error (failure path).
            let ctx = Box::new(StreamCtx {
                response: Mutex::new(Some(response)),
                pending_stream: Mutex::new(None),
                data_tx,
                udp_tx: Mutex::new(None),
                closed,
            });
            let userdata = Box::into_raw(ctx) as *mut c_void;

            let rc = unsafe {
                hyperdht_connect_and_open_stream(
                    dht,
                    peer_pk.as_ptr(),
                    Some(on_connect_cb),
                    Some(on_open_cb),
                    Some(on_data_cb),
                    Some(on_close_cb),
                    userdata,
                )
            };

            if rc != 0 {
                // Synchronous error — reclaim the box and respond.
                let mut ctx = unsafe { Box::from_raw(userdata as *mut StreamCtx) };
                if let Some(tx) = ctx.response.get_mut().unwrap().take() {
                    let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                        rc,
                        "hyperdht_connect_and_open_stream returned error",
                    )));
                }
                // ctx drops here.
            }
        }

        Command::StreamWrite { stream, data } => {
            unsafe {
                hyperdht_stream_write(stream.0, data.as_ptr(), data.len());
            }
            // The Bytes is dropped after the call. libudx copies the data
            // internally before returning, so this is safe.
        }

        Command::StreamClose { stream } => {
            unsafe { hyperdht_stream_close(stream.0) };
            // on_close will eventually fire and free the StreamCtx.
        }

        Command::StreamEnableDatagrams {
            stream,
            ctx,
            tx,
            response,
        } => {
            // Install the sender into StreamCtx, then register the C
            // callback (using the same ctx pointer as userdata so the
            // callback can locate the sender).
            let stream_ctx = unsafe { &*(ctx.0 as *const StreamCtx) };
            if let Ok(mut slot) = stream_ctx.udp_tx.lock() {
                *slot = Some(tx);
            }
            let rc = unsafe {
                hyperdht_stream_set_on_udp_message(
                    stream.0,
                    Some(on_stream_udp_msg_cb),
                    ctx.0,
                )
            };
            if rc == 0 {
                let _ = response.send(Ok(()));
            } else {
                // Detach on failure so we don't dangle a sender.
                if let Ok(mut slot) = stream_ctx.udp_tx.lock() {
                    *slot = None;
                }
                let _ = response.send(Err(HyperDhtError::from_ffi_code(
                    rc,
                    "hyperdht_stream_set_on_udp_message failed",
                )));
            }
        }

        Command::StreamSendUdp {
            stream,
            data,
            response,
        } => {
            let rc = unsafe {
                hyperdht_stream_send_udp(stream.0, data.as_ptr(), data.len())
            };
            if rc == 0 {
                let _ = response.send(Ok(()));
            } else {
                let _ = response.send(Err(HyperDhtError::from_ffi_code(
                    rc,
                    "hyperdht_stream_send_udp failed",
                )));
            }
        }

        Command::StreamTrySendUdp { stream, data } => {
            // Best-effort — discard the rc. The C variant returns
            // 0 on submission and negative on hard failure; we don't
            // surface either.
            unsafe {
                hyperdht_stream_try_send_udp(stream.0, data.as_ptr(), data.len());
            }
        }

        Command::ServerListen {
            public_key,
            secret_key,
            share_local_address: _share_local, // server-side default in C++; no FFI knob
            reusable_socket,
            incoming_tx,
            response,
            new_stream_cmd_tx,
            new_stream_waker,
        } => {
            let server = unsafe { hyperdht_server_create(dht) };
            if server.is_null() {
                let _ = response.send(Err(HyperDhtError::Internal(
                    "hyperdht_server_create returned null".into(),
                )));
                return;
            }

            unsafe {
                hyperdht_server_set_reusable_socket(
                    server,
                    if reusable_socket { 1 } else { 0 },
                );
            }

            // Allocate the per-server context box. Stays alive until
            // hyperdht_server_close fires its callback.
            let ctx = Box::new(ServerCtx {
                dht,
                incoming_tx,
                cmd_tx: new_stream_cmd_tx,
                waker: new_stream_waker,
                firewall: None,
                listening_waiters: Vec::new(),
                already_listening: false,
            });
            let ctx_ptr = Box::into_raw(ctx) as *mut c_void;

            // Wire the "listening" event to fan out one-shot signals
            // queued via Command::ServerWaitListening.
            unsafe {
                hyperdht_server_on_listening(server, Some(on_server_listening_cb), ctx_ptr);
            }

            let kp = hyperdht_keypair_t {
                public_key,
                secret_key,
            };

            let rc = unsafe {
                hyperdht_server_listen(
                    server,
                    &kp,
                    Some(on_server_connection_cb),
                    ctx_ptr,
                )
            };

            if rc != 0 {
                drop(unsafe { Box::from_raw(ctx_ptr as *mut ServerCtx) });
                let _ = response.send(Err(HyperDhtError::from_ffi_code(
                    rc,
                    "hyperdht_server_listen failed",
                )));
                return;
            }

            let _ = response.send(Ok((ServerPtr(server), ServerCtxPtr(ctx_ptr))));
        }

        Command::ServerClose { server, ctx } => {
            unsafe {
                hyperdht_server_close(server.0, Some(on_server_closed_cb), ctx.0);
            }
        }

        Command::ServerSetFirewall { server, ctx, cb } => {
            // SAFETY: ServerCtx pointer is valid until on_server_closed_cb;
            // we're on the libuv thread, which is the only thread that
            // accesses the box. No synchronisation needed.
            let server_ctx = unsafe { &mut *(ctx.0 as *mut ServerCtx) };
            server_ctx.firewall = cb;
            // If cb is Some, install our trampoline; if None, detach.
            unsafe {
                if server_ctx.firewall.is_some() {
                    hyperdht_server_set_firewall(
                        server.0,
                        Some(on_server_firewall_cb),
                        ctx.0,
                    );
                } else {
                    hyperdht_server_set_firewall(server.0, None, std::ptr::null_mut());
                }
            }
        }

        Command::ServerWaitListening { ctx, signal } => {
            let server_ctx = unsafe { &mut *(ctx.0 as *mut ServerCtx) };
            if server_ctx.already_listening {
                let _ = signal.send(());
            } else {
                server_ctx.listening_waiters.push(signal);
            }
        }

        Command::ServerRefresh { server } => {
            unsafe { hyperdht_server_refresh(server.0) };
        }

        Command::ServerAddress { server, response } => {
            let mut host = [0i8; 46];
            let mut port: u16 = 0;
            let rc = unsafe {
                hyperdht_server_address(
                    server.0,
                    host.as_mut_ptr() as *mut _,
                    &mut port,
                )
            };
            if rc != 0 {
                let _ = response.send(Ok(None));
            } else {
                let bytes: Vec<u8> = host
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as u8)
                    .collect();
                let s = String::from_utf8_lossy(&bytes).into_owned();
                let _ = response.send(Ok(Some((s, port))));
            }
        }

        Command::Announce {
            target,
            public_key,
            secret_key,
            response,
        } => {
            use crate::dht_ops::PutCtx;
            let kp = hyperdht_keypair_t {
                public_key,
                secret_key,
            };
            let ctx = Box::new(PutCtx {
                response: Mutex::new(Some(response)),
            });
            let userdata = Box::into_raw(ctx) as *mut c_void;
            // No relay addresses / bump for a bare DHT announce.
            let rc = unsafe {
                hyperdht_announce(
                    dht,
                    target.as_ptr(),
                    &kp,
                    std::ptr::null(),
                    0,
                    0,
                    Some(on_put_done_cb),
                    userdata,
                )
            };
            if rc != 0 {
                let mut ctx = unsafe { Box::from_raw(userdata as *mut PutCtx) };
                if let Ok(slot) = ctx.response.get_mut() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                            rc,
                            "hyperdht_announce returned error",
                        )));
                    }
                }
            }
        }

        Command::Lookup { target, response } => {
            use crate::dht_ops::LookupCtx;
            let ctx = Box::new(LookupCtx {
                results: Mutex::new(Vec::new()),
                response: Mutex::new(Some(response)),
            });
            let userdata = Box::into_raw(ctx) as *mut c_void;
            let rc = unsafe {
                hyperdht_lookup(
                    dht,
                    target.as_ptr(),
                    Some(on_lookup_reply_cb),
                    Some(on_lookup_done_cb),
                    userdata,
                )
            };
            if rc != 0 {
                let mut ctx = unsafe { Box::from_raw(userdata as *mut LookupCtx) };
                if let Ok(slot) = ctx.response.get_mut() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                            rc,
                            "hyperdht_lookup returned error",
                        )));
                    }
                }
            }
        }

        Command::MutablePut {
            public_key,
            secret_key,
            value,
            seq,
            response,
        } => {
            use crate::dht_ops::PutCtx;
            let kp = hyperdht_keypair_t {
                public_key,
                secret_key,
            };
            let ctx = Box::new(PutCtx {
                response: Mutex::new(Some(response)),
            });
            let userdata = Box::into_raw(ctx) as *mut c_void;
            let rc = unsafe {
                hyperdht_mutable_put(
                    dht,
                    &kp,
                    value.as_ptr(),
                    value.len(),
                    seq,
                    Some(on_put_done_cb),
                    userdata,
                )
            };
            if rc != 0 {
                let mut ctx = unsafe { Box::from_raw(userdata as *mut PutCtx) };
                if let Ok(slot) = ctx.response.get_mut() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                            rc,
                            "hyperdht_mutable_put returned error",
                        )));
                    }
                }
            }
        }

        Command::MutableGet {
            public_key,
            min_seq,
            response,
        } => {
            use crate::dht_ops::MutableGetCtx;
            let ctx = Box::new(MutableGetCtx {
                record: Mutex::new(None),
                seen: Arc::new(AtomicBool::new(false)),
                response: Mutex::new(Some(response)),
            });
            let userdata = Box::into_raw(ctx) as *mut c_void;
            let rc = unsafe {
                hyperdht_mutable_get(
                    dht,
                    public_key.as_ptr(),
                    min_seq,
                    Some(on_mutable_reply_cb),
                    Some(on_mutable_done_cb),
                    userdata,
                )
            };
            if rc != 0 {
                let mut ctx = unsafe { Box::from_raw(userdata as *mut MutableGetCtx) };
                if let Ok(slot) = ctx.response.get_mut() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                            rc,
                            "hyperdht_mutable_get returned error",
                        )));
                    }
                }
            }
        }

        Command::Unannounce {
            target,
            public_key,
            secret_key,
            response,
        } => {
            use crate::dht_ops::PutCtx;
            let kp = hyperdht_keypair_t {
                public_key,
                secret_key,
            };
            let ctx = Box::new(PutCtx {
                response: Mutex::new(Some(response)),
            });
            let userdata = Box::into_raw(ctx) as *mut c_void;
            let rc = unsafe {
                hyperdht_unannounce(
                    dht,
                    target.as_ptr(),
                    &kp,
                    Some(on_put_done_cb),
                    userdata,
                )
            };
            if rc != 0 {
                let mut ctx = unsafe { Box::from_raw(userdata as *mut PutCtx) };
                if let Ok(slot) = ctx.response.get_mut() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                            rc,
                            "hyperdht_unannounce returned error",
                        )));
                    }
                }
            }
        }

        Command::FindPeer {
            public_key,
            response,
        } => {
            use crate::dht_ops::LookupCtx;
            let ctx = Box::new(LookupCtx {
                results: Mutex::new(Vec::new()),
                response: Mutex::new(Some(response)),
            });
            let userdata = Box::into_raw(ctx) as *mut c_void;
            let rc = unsafe {
                hyperdht_find_peer(
                    dht,
                    public_key.as_ptr(),
                    Some(on_lookup_reply_cb),
                    Some(on_lookup_done_cb),
                    userdata,
                )
            };
            if rc != 0 {
                let mut ctx = unsafe { Box::from_raw(userdata as *mut LookupCtx) };
                if let Ok(slot) = ctx.response.get_mut() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                            rc,
                            "hyperdht_find_peer returned error",
                        )));
                    }
                }
            }
        }

        Command::ImmutablePut { value, response } => {
            use crate::dht_ops::PutCtx;
            let ctx = Box::new(PutCtx {
                response: Mutex::new(Some(response)),
            });
            let userdata = Box::into_raw(ctx) as *mut c_void;
            let rc = unsafe {
                hyperdht_immutable_put(
                    dht,
                    value.as_ptr(),
                    value.len(),
                    Some(on_put_done_cb),
                    userdata,
                )
            };
            if rc != 0 {
                let mut ctx = unsafe { Box::from_raw(userdata as *mut PutCtx) };
                if let Ok(slot) = ctx.response.get_mut() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                            rc,
                            "hyperdht_immutable_put returned error",
                        )));
                    }
                }
            }
        }

        Command::ImmutableGet { target, response } => {
            use crate::dht_ops::ImmutableGetCtx;
            let ctx = Box::new(ImmutableGetCtx {
                value: Mutex::new(None),
                response: Mutex::new(Some(response)),
            });
            let userdata = Box::into_raw(ctx) as *mut c_void;
            let rc = unsafe {
                hyperdht_immutable_get(
                    dht,
                    target.as_ptr(),
                    Some(on_immutable_reply_cb),
                    Some(on_immutable_done_cb),
                    userdata,
                )
            };
            if rc != 0 {
                let mut ctx = unsafe { Box::from_raw(userdata as *mut ImmutableGetCtx) };
                if let Ok(slot) = ctx.response.get_mut() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                            rc,
                            "hyperdht_immutable_get returned error",
                        )));
                    }
                }
            }
        }

        Command::NodesSnapshot { response } => {
            use crate::dht::NodeAddr;
            const CAP: usize = 256;
            const STRIDE: usize = HYPERDHT_HOST_STRIDE as usize;
            let mut hosts_flat: Vec<u8> = vec![0u8; CAP * STRIDE];
            let mut ports: Vec<u16> = vec![0u16; CAP];
            let n = unsafe {
                hyperdht_to_array(
                    dht,
                    hosts_flat.as_mut_ptr() as *mut ::std::os::raw::c_char,
                    ports.as_mut_ptr(),
                    CAP,
                )
            };
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let start = i * STRIDE;
                let end = start + STRIDE;
                let slice = &hosts_flat[start..end];
                let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                let host = String::from_utf8_lossy(&slice[..nul]).into_owned();
                out.push(NodeAddr {
                    host,
                    port: ports[i],
                });
            }
            let _ = response.send(Ok(out));
        }

        Command::RemoteAddress { response } => {
            let mut host = [0i8; 46];
            let mut port: u16 = 0;
            let rc = unsafe {
                hyperdht_remote_address(dht, host.as_mut_ptr() as *mut _, &mut port)
            };
            if rc != 0 {
                let _ = response.send(Ok(None));
            } else {
                let bytes: Vec<u8> = host
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as u8)
                    .collect();
                let s = String::from_utf8_lossy(&bytes).into_owned();
                let _ = response.send(Ok(Some((s, port))));
            }
        }

        Command::AddNode {
            host,
            port,
            response,
        } => {
            let host_c = match CString::new(host) {
                Ok(c) => c,
                Err(_) => {
                    let _ = response.send(Err(HyperDhtError::InvalidArgument(
                        "host contained NUL byte",
                    )));
                    return;
                }
            };
            let rc = unsafe { hyperdht_add_node(dht, host_c.as_ptr(), port) };
            if rc == 0 {
                let _ = response.send(Ok(()));
            } else {
                let _ = response.send(Err(HyperDhtError::from_ffi_code(
                    rc,
                    "hyperdht_add_node returned error",
                )));
            }
        }

        Command::Suspend { response } => {
            unsafe { hyperdht_suspend(dht) };
            // Refresh state synchronously so the caller's next
            // is_suspended() observes the new value without waiting
            // for the next loop tick.
            state.refresh_from(dht);
            let _ = response.send(Ok(()));
        }

        Command::Resume { response } => {
            unsafe { hyperdht_resume(dht) };
            state.refresh_from(dht);
            let _ = response.send(Ok(()));
        }
    }
}

fn teardown(dht: *mut hyperdht_t, async_ptr: *mut uv_async_t, loop_ptr: *mut uv_loop_t) {
    unsafe {
        // 1. Schedule DHT destruction (async, drains over next uv_run cycles).
        hyperdht_destroy(dht, None, ptr::null_mut());
        // 2. Schedule async wakeup handle close.
        uv_close(async_ptr as *mut uv_handle_t, None);

        // 3. Give hyperdht a bounded number of iterations to drain its
        //    own teardown gracefully (close streams, stop announcer/probe
        //    timers, etc.).
        for _ in 0..100 {
            let active = uv_run(loop_ptr, uv_run_mode::UV_RUN_NOWAIT);
            if active == 0 {
                break;
            }
        }

        // 4. If anything is still open (streams mid-close, stuck timers,
        //    UDX retransmits waiting for ACK), force-close every remaining
        //    handle. This is the standard libuv shutdown idiom.
        uv_walk(loop_ptr, Some(force_close_handle_cb), ptr::null_mut());

        // 5. Drain the close callbacks scheduled by uv_walk.
        uv_run(loop_ptr, uv_run_mode::UV_RUN_DEFAULT);

        // 6. Now safe to free the DHT and close the loop.
        hyperdht_free(dht);
        let rc = uv_loop_close(loop_ptr);
        if rc != 0 {
            tracing::warn!(rc, "uv_loop_close returned non-zero");
        }
    }
}

/// `uv_walk` callback: force-close every open handle.
extern "C" fn force_close_handle_cb(handle: *mut uv_handle_t, _arg: *mut c_void) {
    unsafe {
        if !handle.is_null() && uv_is_closing(handle) == 0 {
            uv_close(handle, None);
        }
    }
}

// ============================================================================
// C callbacks (fire on the libuv thread)
// ============================================================================

extern "C" fn noop_async_cb(_handle: *mut uv_async_t) {
    // Wakeup is the signal — no per-call work needed.
}

extern "C" fn on_connect_cb(
    err: c_int,
    stream: *mut hyperdht_stream_t,
    userdata: *mut c_void,
) {
    if err != 0 {
        // Connect failed → stream was never opened → reclaim box now.
        let mut ctx = unsafe { Box::from_raw(userdata as *mut StreamCtx) };
        if let Ok(slot) = ctx.response.get_mut() {
            if let Some(tx) = slot.take() {
                let _ = tx.send(Err(HyperDhtError::from_ffi_code(err, "connect failed")));
            }
        }
        return;
    }

    // Success — store the stream pointer. Don't deliver yet; wait for
    // on_open_cb so the SecretStream header exchange has completed
    // (otherwise the user's first write goes into the void —
    // CLAUDE.md gotcha #7).
    let ctx = unsafe { &*(userdata as *const StreamCtx) };
    let mut pending = match ctx.pending_stream.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    *pending = Some(StreamPtr(stream));
}

extern "C" fn on_open_cb(userdata: *mut c_void) {
    // SecretStream header exchange is complete — stream is now safe to
    // write to. For client-connect path, deliver the stream pointer now.
    // For server-accept path, response is None (already delivered);
    // this is a no-op.
    let ctx = unsafe { &*(userdata as *const StreamCtx) };
    let stream_ptr = match ctx.pending_stream.lock() {
        Ok(mut g) => g.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    let mut response_guard = match ctx.response.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let (Some(ptr), Some(tx)) = (stream_ptr, response_guard.take()) {
        // Hand back both the stream pointer and the ctx pointer (the
        // latter doubles as userdata for any secondary callbacks the
        // user installs later — e.g. datagrams).
        let ctx_ptr = StreamCtxPtr(userdata);
        let _ = tx.send(Ok((ptr, ctx_ptr)));
    }
}

extern "C" fn on_data_cb(data: *const u8, len: usize, userdata: *mut c_void) {
    let ctx = unsafe { &*(userdata as *const StreamCtx) };
    if len == 0 {
        return;
    }
    // SAFETY: hyperdht guarantees data is valid for `len` bytes for the
    // duration of this callback.
    let chunk = Bytes::copy_from_slice(unsafe { std::slice::from_raw_parts(data, len) });
    let _ = ctx.data_tx.send(chunk);
}

extern "C" fn on_close_cb(userdata: *mut c_void) {
    // Reclaim the box. Dropping it closes the data sender (rx returns
    // None → AsyncRead returns EOF) and decrements the closed Arc.
    let mut ctx = unsafe { Box::from_raw(userdata as *mut StreamCtx) };
    ctx.closed.store(true, Ordering::SeqCst);

    // If on_open never fired but on_close did, surface the failure to
    // any caller still awaiting connect (otherwise it would hang
    // forever on the oneshot).
    if let Ok(slot) = ctx.response.get_mut() {
        if let Some(tx) = slot.take() {
            let _ = tx.send(Err(HyperDhtError::Internal(
                "stream closed before SecretStream header exchange (on_open) completed".into(),
            )));
        }
    }

    drop(ctx);
}

/// Server-side callback: a peer just connected. Atomically open a
/// stream on this connection and deliver it to the Server's incoming
/// channel.
extern "C" fn on_server_connection_cb(
    conn: *const hyperdht_connection_t,
    userdata: *mut c_void,
) {
    let server_ctx = unsafe { &*(userdata as *const ServerCtx) };

    if conn.is_null() {
        return;
    }

    // Allocate a per-stream context (no response — server streams open
    // synchronously via hyperdht_stream_open's return value).
    let (data_tx, data_rx) = mpsc::unbounded_channel::<Bytes>();
    let closed = Arc::new(AtomicBool::new(false));

    let stream_ctx = Box::new(StreamCtx {
        response: Mutex::new(None),
        pending_stream: Mutex::new(None),
        data_tx,
        udp_tx: Mutex::new(None),
        closed: closed.clone(),
    });
    let stream_ctx_ptr = Box::into_raw(stream_ctx) as *mut c_void;

    let stream_ptr = unsafe {
        hyperdht_stream_open(
            server_ctx.dht,
            conn,
            Some(on_open_cb),
            Some(on_data_cb),
            Some(on_close_cb),
            stream_ctx_ptr,
        )
    };

    if stream_ptr.is_null() {
        // Open failed — reclaim the box.
        drop(unsafe { Box::from_raw(stream_ctx_ptr as *mut StreamCtx) });
        return;
    }

    // Build the Rust Stream and deliver via the Server's mpsc channel.
    let stream = crate::stream::build_stream(
        StreamPtr(stream_ptr),
        StreamCtxPtr(stream_ctx_ptr),
        data_rx,
        closed,
        server_ctx.cmd_tx.clone(),
        server_ctx.waker.clone(),
    );

    // If the Server handle was dropped, this send fails silently —
    // we have no way to "un-open" the stream now, so let it dangle
    // until DHT teardown closes it.
    let _ = server_ctx.incoming_tx.send(stream);
}

/// Server-close callback: free the ServerCtx box.
extern "C" fn on_server_closed_cb(userdata: *mut c_void) {
    if userdata.is_null() {
        return;
    }
    let ctx = unsafe { Box::from_raw(userdata as *mut ServerCtx) };
    // Dropping the listening_waiters Vec drops each oneshot::Sender,
    // signalling Err to any awaiter still parked on .await.
    drop(ctx);
}

/// Firewall trampoline: forwards the C call to the user's Rust
/// closure stored in ServerCtx. Returns 0 to accept, 1 to reject.
extern "C" fn on_server_firewall_cb(
    remote_pk: *const u8,
    peer_host: *const ::std::os::raw::c_char,
    peer_port: u16,
    userdata: *mut c_void,
) -> c_int {
    let server_ctx = unsafe { &*(userdata as *const ServerCtx) };
    let cb = match server_ctx.firewall.as_ref() {
        Some(cb) => cb,
        None => return 0, // accept by default if no callback installed
    };

    // SAFETY: hyperdht guarantees both pointers are valid for the
    // duration of this call.
    let mut pk = [0u8; 32];
    if !remote_pk.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(remote_pk, pk.as_mut_ptr(), 32) };
    }
    let pk = crate::keypair::PublicKey(pk);
    let host = if peer_host.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(peer_host) }
            .to_string_lossy()
            .into_owned()
    };

    if cb(&pk, &host, peer_port) {
        0 // accept
    } else {
        1 // reject
    }
}

/// `on_listening` trampoline: marks the server as listening and
/// fires every queued one-shot waiter.
extern "C" fn on_server_listening_cb(userdata: *mut c_void) {
    if userdata.is_null() {
        return;
    }
    let server_ctx = unsafe { &mut *(userdata as *mut ServerCtx) };
    server_ctx.already_listening = true;
    for tx in server_ctx.listening_waiters.drain(..) {
        let _ = tx.send(());
    }
}

// ============================================================================
// DHT op callbacks (announce / lookup / mutable_put / mutable_get)
// ============================================================================

extern "C" fn on_put_done_cb(err: c_int, userdata: *mut c_void) {
    use crate::dht_ops::PutCtx;
    let mut ctx = unsafe { Box::from_raw(userdata as *mut PutCtx) };
    if let Ok(slot) = ctx.response.get_mut() {
        if let Some(tx) = slot.take() {
            if err == 0 {
                let _ = tx.send(Ok(()));
            } else {
                let _ = tx.send(Err(HyperDhtError::from_ffi_code(err, "DHT op failed")));
            }
        }
    }
}

extern "C" fn on_lookup_reply_cb(
    value: *const u8,
    len: usize,
    from_host: *const ::std::os::raw::c_char,
    from_port: u16,
    userdata: *mut c_void,
) {
    use crate::dht_ops::{LookupCtx, LookupEntry};
    let ctx = unsafe { &*(userdata as *const LookupCtx) };
    let value_vec = if value.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(value, len) }.to_vec()
    };
    let host = if from_host.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(from_host) }
            .to_string_lossy()
            .into_owned()
    };
    if let Ok(mut results) = ctx.results.lock() {
        results.push(LookupEntry {
            value: value_vec,
            from_host: host,
            from_port,
        });
    }
}

extern "C" fn on_lookup_done_cb(err: c_int, userdata: *mut c_void) {
    use crate::dht_ops::LookupCtx;
    let mut ctx = unsafe { Box::from_raw(userdata as *mut LookupCtx) };
    let results = ctx.results.get_mut().map(std::mem::take).unwrap_or_default();
    if let Ok(slot) = ctx.response.get_mut() {
        if let Some(tx) = slot.take() {
            if err == 0 {
                let _ = tx.send(Ok(results));
            } else {
                let _ = tx.send(Err(HyperDhtError::from_ffi_code(err, "lookup failed")));
            }
        }
    }
}

extern "C" fn on_mutable_reply_cb(
    seq: u64,
    value: *const u8,
    len: usize,
    signature: *const u8,
    userdata: *mut c_void,
) {
    use crate::dht_ops::{MutableGetCtx, MutableRecord};
    let ctx = unsafe { &*(userdata as *const MutableGetCtx) };
    let value_vec = if value.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(value, len) }.to_vec()
    };
    let mut sig = [0u8; 64];
    if !signature.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(signature, sig.as_mut_ptr(), 64) };
    }
    if let Ok(mut record) = ctx.record.lock() {
        // Keep the highest-seq record we've seen.
        match &*record {
            Some(prev) if prev.seq >= seq => {}
            _ => {
                *record = Some(MutableRecord {
                    seq,
                    value: value_vec,
                    signature: sig,
                });
            }
        }
    }
    ctx.seen.store(true, Ordering::SeqCst);
}

extern "C" fn on_mutable_done_cb(err: c_int, userdata: *mut c_void) {
    use crate::dht_ops::MutableGetCtx;
    let mut ctx = unsafe { Box::from_raw(userdata as *mut MutableGetCtx) };
    let record = ctx.record.get_mut().map(std::mem::take).unwrap_or(None);
    if let Ok(slot) = ctx.response.get_mut() {
        if let Some(tx) = slot.take() {
            if err == 0 {
                let _ = tx.send(Ok(record));
            } else {
                let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                    err,
                    "mutable_get failed",
                )));
            }
        }
    }
}

extern "C" fn on_immutable_reply_cb(value: *const u8, len: usize, userdata: *mut c_void) {
    use crate::dht_ops::ImmutableGetCtx;
    let ctx = unsafe { &*(userdata as *const ImmutableGetCtx) };
    if value.is_null() || len == 0 {
        return;
    }
    // SAFETY: hyperdht guarantees value/len validity for this call.
    let bytes = unsafe { std::slice::from_raw_parts(value, len) }.to_vec();
    if let Ok(mut slot) = ctx.value.lock() {
        // First reply wins (value is content-addressed and verified by
        // the C library, so any further replies must hold the same bytes).
        if slot.is_none() {
            *slot = Some(bytes);
        }
    }
}

/// Datagram trampoline: forwards each unreliable encrypted datagram
/// to the user's tokio mpsc receiver. Drops the bytes silently if
/// `enable_datagrams` was never called or the receiver was dropped.
extern "C" fn on_stream_udp_msg_cb(
    data: *const u8,
    len: usize,
    userdata: *mut c_void,
) {
    let ctx = unsafe { &*(userdata as *const StreamCtx) };
    if data.is_null() || len == 0 {
        return;
    }
    // SAFETY: hyperdht guarantees data is valid for `len` bytes for
    // the duration of this callback.
    let bytes = Bytes::copy_from_slice(unsafe { std::slice::from_raw_parts(data, len) });
    let tx_guard = match ctx.udp_tx.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(tx) = tx_guard.as_ref() {
        let _ = tx.send(bytes);
    }
}

extern "C" fn on_immutable_done_cb(err: c_int, userdata: *mut c_void) {
    use crate::dht_ops::ImmutableGetCtx;
    let mut ctx = unsafe { Box::from_raw(userdata as *mut ImmutableGetCtx) };
    let value = ctx.value.get_mut().map(std::mem::take).unwrap_or(None);
    if let Ok(slot) = ctx.response.get_mut() {
        if let Some(tx) = slot.take() {
            if err == 0 {
                let _ = tx.send(Ok(value));
            } else {
                let _ = tx.send(Err(HyperDhtError::from_ffi_code(
                    err,
                    "immutable_get failed",
                )));
            }
        }
    }
}
