//! The dedicated libuv pump thread.
//!
//! This module is the heart of the wrapper. It owns the `uv_loop_t`,
//! the `hyperdht_t*`, and a `uv_async_t` wakeup handle. Tokio tasks
//! send commands via an mpsc channel; the thread drains them between
//! `uv_run` cycles. The wakeup handle is woken (via `uv_async_send`)
//! whenever a new command arrives, so the loop unblocks immediately.
//!
//! # Lifetime contract
//!
//! Every `Dht` handle owns one of these threads. The thread runs
//! until [`Shutdown::shutdown`] is set AND `uv_async_send` wakes the
//! loop. The teardown sequence is:
//!
//! 1. `hyperdht_destroy` — schedules DHT cleanup
//! 2. `uv_close` on the async wakeup handle
//! 3. `uv_run(UV_RUN_DEFAULT)` — drains all pending closes
//! 4. `hyperdht_free` — releases DHT memory
//! 5. `uv_loop_close` — releases the loop

use std::ffi::CString;
use std::os::raw::c_int;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hyperdht_sys::*;
use tokio::sync::{mpsc, oneshot};

use crate::error::{HyperDhtError, Result};
use crate::options::DhtOptions;

/// A command sent from a tokio task to the libuv thread.
#[allow(dead_code)] // variants populated incrementally as features are added
pub(crate) enum Command {
    /// Just wake the loop (used when shutdown is requested).
    Wake,
}

/// A thread-safe wrapper around a `uv_async_t*` that lets tokio tasks
/// wake the libuv loop from any thread.
///
/// `uv_async_send` is documented as thread-safe by libuv.
#[derive(Clone)]
pub(crate) struct AsyncWaker {
    ptr: AsyncPtr,
}

#[derive(Clone, Copy)]
struct AsyncPtr(*mut uv_async_t);

// SAFETY: uv_async_send is the one libuv API documented as thread-safe;
// we only ever pass `ptr` to that function from outside the loop thread.
unsafe impl Send for AsyncPtr {}
unsafe impl Sync for AsyncPtr {}

impl AsyncWaker {
    /// Wake the libuv loop. Idempotent (multiple wakes coalesce).
    pub(crate) fn wake(&self) {
        unsafe { uv_async_send(self.ptr.0) };
    }
}

/// Shared shutdown signal between the tokio side and the loop thread.
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

/// What the loop thread reports back to `Dht::new` after initialization.
pub(crate) struct InitResult {
    /// The bound port (after `hyperdht_bind`).
    pub bound_port: u16,
    /// Wakeup handle for the loop thread.
    pub waker: AsyncWaker,
}

/// Spawn the dedicated libuv pump thread.
///
/// Returns the join handle plus what the thread initialized to. Errors
/// out via the `init_tx` channel if cmake/bind fails.
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

/// The thread main. Initializes libuv + DHT, reports back, then runs
/// the pump loop until shutdown.
fn run(
    opts: DhtOptions,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    shutdown: Arc<Shutdown>,
    init_tx: oneshot::Sender<Result<InitResult>>,
) {
    // ---- Allocate libuv loop on the heap (must outlive any borrowed pointers) ----
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

    // ---- Allocate the async wakeup handle ----
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

    // ---- Build hyperdht_opts_t from DhtOptions ----
    // Strings (host, bootstrap nodes) need to outlive hyperdht_create.
    // The C API documents these as borrowed only during the call.
    let host_cstr = opts.host.as_deref().map(|s| CString::new(s).ok()).flatten();
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
    if let Some(ms) = opts.connection_keep_alive_ms {
        c_opts.connection_keep_alive = ms;
    } else {
        // UINT64_MAX sentinel = "use C++ default"
        c_opts.connection_keep_alive = u64::MAX;
    }

    // ---- Create the DHT instance ----
    let dht = unsafe { hyperdht_create(loop_ptr, &c_opts) };
    if dht.is_null() {
        unsafe {
            uv_close(async_ptr as *mut uv_handle_t, None);
            // Drain the pending close
            uv_run(loop_ptr, uv_run_mode::UV_RUN_DEFAULT);
            uv_loop_close(loop_ptr);
        }
        let _ = init_tx.send(Err(HyperDhtError::Internal(
            "hyperdht_create returned null".into(),
        )));
        return;
    }

    // ---- Bind the UDP socket ----
    let rc = unsafe { hyperdht_bind(dht, opts.port) };
    if rc != 0 {
        // Bind failed: clean up.
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

    // Drop the C strings now — hyperdht_create only borrowed them.
    drop(host_cstr);
    drop(bootstrap_cstrs);

    // ---- Report success back to the tokio side ----
    if init_tx
        .send(Ok(InitResult {
            bound_port,
            waker: waker.clone(),
        }))
        .is_err()
    {
        // Tokio side dropped the receiver before we initialized.
        // Tear down and exit.
        teardown(dht, async_ptr, loop_ptr);
        return;
    }

    // ---- Pump loop ----
    loop {
        // Drain pending commands. try_recv is non-blocking and works
        // outside a tokio runtime.
        loop {
            match cmd_rx.try_recv() {
                Ok(Command::Wake) => { /* explicit wake; no-op handler */ }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Tokio side dropped the sender — same as shutdown.
                    shutdown.signal();
                    break;
                }
            }
        }

        if shutdown.is_signaled() {
            break;
        }

        // Run libuv. UV_RUN_ONCE blocks until next event. The async
        // wakeup fires when tokio side calls waker.wake(), so this
        // unblocks promptly when commands arrive.
        let active = unsafe { uv_run(loop_ptr, uv_run_mode::UV_RUN_ONCE) };
        if active == 0 {
            // No more handles — nothing keeps the loop alive. Shouldn't
            // happen while async_handle is open, but break defensively.
            break;
        }
    }

    teardown(dht, async_ptr, loop_ptr);
}

/// Tear down DHT + libuv handles + the loop.
fn teardown(dht: *mut hyperdht_t, async_ptr: *mut uv_async_t, loop_ptr: *mut uv_loop_t) {
    unsafe {
        // Schedule DHT destruction (async).
        hyperdht_destroy(dht, None, ptr::null_mut());

        // Schedule async handle close.
        uv_close(async_ptr as *mut uv_handle_t, None);

        // Drain everything.
        uv_run(loop_ptr, uv_run_mode::UV_RUN_DEFAULT);

        // Now safe to free DHT memory.
        hyperdht_free(dht);

        // Close the loop itself.
        let rc = uv_loop_close(loop_ptr);
        if rc != 0 {
            // Should not happen if we drained properly; log and continue.
            tracing::warn!(rc, "uv_loop_close returned non-zero");
        }
    }
}

/// No-op callback for the async wakeup handle. The wakeup itself is
/// what we need; the data is already in the cmd channel.
extern "C" fn noop_async_cb(_handle: *mut uv_async_t) {
    // Intentionally empty.
}

#[allow(dead_code)] // used in upcoming bind/connect/listen plumbing
fn _link_check() -> c_int {
    0
}
