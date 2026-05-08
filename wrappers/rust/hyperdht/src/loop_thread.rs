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
use tokio::sync::{mpsc, oneshot};

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
        /// Sender for delivering the open stream pointer on success.
        response: oneshot::Sender<Result<StreamPtr>>,
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
    /// `Some` until on_connect fires (client-side connect path); on_connect
    /// takes the sender out and delivers the stream pointer (or an error).
    /// `None` for server-accepted streams (open is synchronous).
    response: Mutex<Option<oneshot::Sender<Result<StreamPtr>>>>,

    /// Sender for incoming data chunks (delivered to the Rust `Stream`'s
    /// AsyncRead via the corresponding `Receiver`).
    data_tx: mpsc::UnboundedSender<Bytes>,

    /// Flipped to `true` by on_close.
    closed: Arc<AtomicBool>,
}

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
}

// ============================================================================
// Spawn the pump thread
// ============================================================================

pub(crate) fn spawn(
    opts: DhtOptions,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    shutdown: Arc<Shutdown>,
) -> (
    std::thread::JoinHandle<()>,
    oneshot::Receiver<Result<InitResult>>,
) {
    let (init_tx, init_rx) = oneshot::channel();

    let join = std::thread::Builder::new()
        .name("hyperdht-loop".to_string())
        .spawn(move || run(opts, cmd_rx, shutdown, init_tx))
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
                Ok(cmd) => dispatch_command(dht, cmd),
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
        if active == 0 {
            break;
        }
    }

    teardown(dht, async_ptr, loop_ptr);
}

fn dispatch_command(dht: *mut hyperdht_t, cmd: Command) {
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
                data_tx,
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
            });
            let ctx_ptr = Box::into_raw(ctx) as *mut c_void;

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
    }
}

fn teardown(dht: *mut hyperdht_t, async_ptr: *mut uv_async_t, loop_ptr: *mut uv_loop_t) {
    unsafe {
        hyperdht_destroy(dht, None, ptr::null_mut());
        uv_close(async_ptr as *mut uv_handle_t, None);
        uv_run(loop_ptr, uv_run_mode::UV_RUN_DEFAULT);
        hyperdht_free(dht);
        let rc = uv_loop_close(loop_ptr);
        if rc != 0 {
            tracing::warn!(rc, "uv_loop_close returned non-zero");
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
        // We have exclusive access via Box, so Mutex::get_mut is fine.
        if let Ok(slot) = ctx.response.get_mut() {
            if let Some(tx) = slot.take() {
                let _ = tx.send(Err(HyperDhtError::from_ffi_code(err, "connect failed")));
            }
        }
        return;
    }

    // Success — deliver the stream pointer.
    let ctx = unsafe { &*(userdata as *const StreamCtx) };
    let mut guard = match ctx.response.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(tx) = guard.take() {
        let _ = tx.send(Ok(StreamPtr(stream)));
    }
}

extern "C" fn on_open_cb(_userdata: *mut c_void) {
    // No-op. Could log "header exchange complete" if desired.
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
    let ctx = unsafe { Box::from_raw(userdata as *mut StreamCtx) };
    ctx.closed.store(true, Ordering::SeqCst);
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
        data_tx,
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
    drop(ctx);
}
