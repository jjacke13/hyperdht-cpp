//! Encrypted, ordered stream — the data path after a successful connect.
//!
//! Implements [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`] over
//! the libuv thread. Reads are delivered through an unbounded mpsc
//! channel (bytes copied from the C `on_data` callback). Writes are
//! sent as commands to the libuv thread, which calls
//! `hyperdht_stream_write`.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use crate::error::{HyperDhtError, Result};
use crate::loop_thread::{AsyncWaker, Command, StreamCtxPtr, StreamPtr};

/// An encrypted, ordered, bidirectional stream to a remote peer.
///
/// Implements [`AsyncRead`] and [`AsyncWrite`] for use with tokio.
/// Drop the stream to close it gracefully.
pub struct Stream {
    /// The underlying C stream pointer. Used for writes/close commands
    /// dispatched to the libuv thread.
    pub(crate) stream_ptr: StreamPtr,

    /// The associated `StreamCtx` heap pointer. Required as `userdata`
    /// when installing secondary callbacks (e.g. datagram receive).
    pub(crate) ctx_ptr: StreamCtxPtr,

    /// Channel of incoming data chunks (copied from the C on_data callback).
    pub(crate) rx: mpsc::UnboundedReceiver<Bytes>,

    /// Set by the on_close C callback when the stream finishes closing.
    pub(crate) closed: Arc<AtomicBool>,

    /// Send commands (writes, close) to the libuv thread.
    pub(crate) cmd_tx: mpsc::UnboundedSender<Command>,

    /// Wake the libuv thread after sending a command.
    pub(crate) waker: AsyncWaker,

    /// Partial chunk being drained into the caller's buffer.
    pub(crate) current_chunk: Option<Bytes>,

    /// Set when we've sent the close command (so Drop is idempotent).
    pub(crate) close_sent: bool,

    /// Set after `enable_datagrams` to prevent double-installation.
    pub(crate) datagrams_enabled: bool,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish()
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Drain `current_chunk` first if present.
        if let Some(chunk) = self.current_chunk.as_mut() {
            let space = buf.remaining();
            if space == 0 {
                return Poll::Ready(Ok(()));
            }
            let take = std::cmp::min(space, chunk.len());
            buf.put_slice(&chunk[..take]);
            // Advance the chunk in-place.
            *chunk = chunk.slice(take..);
            if chunk.is_empty() {
                self.current_chunk = None;
            }
            return Poll::Ready(Ok(()));
        }

        // Try to recv the next chunk.
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                // Sender dropped → stream closed → EOF.
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(chunk)) => {
                self.current_chunk = Some(chunk);
                // Recurse via re-polling self.
                self.poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        // Send a write command. v0.1: unbounded — bytes pile up if the
        // libuv thread is slow. Backpressure is a v0.2 feature
        // (hyperdht_stream_write_with_drain).
        let cmd = Command::StreamWrite {
            stream: self.stream_ptr,
            data: Bytes::copy_from_slice(buf),
        };
        if self.cmd_tx.send(cmd).is_err() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "DHT closed",
            )));
        }
        self.waker.wake();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // libudx flushes implicitly; we have no buffer to drain.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.close_sent {
            let _ = self.cmd_tx.send(Command::StreamClose {
                stream: self.stream_ptr,
            });
            self.waker.wake();
            self.close_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // Idempotent close — if shutdown wasn't called, send close now.
        if !self.close_sent {
            let _ = self.cmd_tx.send(Command::StreamClose {
                stream: self.stream_ptr,
            });
            self.waker.wake();
            self.close_sent = true;
        }
        // The C side will free the StreamCtx box in its on_close callback.
    }
}

#[allow(dead_code)] // helper for connect()
pub(crate) fn build_stream(
    stream_ptr: StreamPtr,
    ctx_ptr: StreamCtxPtr,
    rx: mpsc::UnboundedReceiver<Bytes>,
    closed: Arc<AtomicBool>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    waker: AsyncWaker,
) -> Stream {
    Stream {
        stream_ptr,
        ctx_ptr,
        rx,
        closed,
        cmd_tx,
        waker,
        current_chunk: None,
        close_sent: false,
        datagrams_enabled: false,
    }
}

impl Stream {
    /// Install the datagram receive channel and return the receiver.
    ///
    /// Each `Bytes` payload is one decrypted, unordered, unreliable
    /// datagram (mirrors `hyperdht_stream_set_on_udp_message`). May
    /// only be called once per stream.
    pub async fn enable_datagrams(&mut self) -> Result<mpsc::UnboundedReceiver<Bytes>> {
        if self.datagrams_enabled {
            return Err(HyperDhtError::InvalidArgument(
                "datagrams already enabled on this stream",
            ));
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::StreamEnableDatagrams {
                stream: self.stream_ptr,
                ctx: self.ctx_ptr,
                tx,
                response: resp_tx,
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();
        resp_rx.await??;
        self.datagrams_enabled = true;
        Ok(rx)
    }

    /// Send an unreliable encrypted datagram. Returns once the C
    /// library has accepted the submission for transmission. Errors
    /// when the stream is closed or the underlying UDX socket is
    /// applying backpressure.
    pub async fn send_datagram(&self, payload: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(HyperDhtError::DhtClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::StreamSendUdp {
                stream: self.stream_ptr,
                data: payload.to_vec(),
                response: tx,
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();
        rx.await?
    }

    /// Best-effort variant — drops the payload if UDX is applying
    /// backpressure. Never blocks past command dispatch.
    pub fn try_send_datagram(&self, payload: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(HyperDhtError::DhtClosed);
        }
        self.cmd_tx
            .send(Command::StreamTrySendUdp {
                stream: self.stream_ptr,
                data: payload.to_vec(),
            })
            .map_err(|_| HyperDhtError::DhtClosed)?;
        self.waker.wake();
        Ok(())
    }
}

/// Map a `tokio::sync::mpsc::error::SendError` to an io::Error.
#[allow(dead_code)]
pub(crate) fn map_send_err<T>(_: tokio::sync::mpsc::error::SendError<T>) -> HyperDhtError {
    HyperDhtError::DhtClosed
}
