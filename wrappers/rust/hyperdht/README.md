# hyperdht

Async-friendly Rust wrapper for [hyperdht-cpp](https://github.com/jjacke13/hyperdht-cpp).

Built on top of [`hyperdht-sys`](../hyperdht-sys), this crate provides
safe, idiomatic Rust types over the C FFI: `Dht`, `Server`, `Stream`,
`Keypair`, with `tokio::io::AsyncRead + AsyncWrite` for streams.

## Architecture

A dedicated OS thread runs `uv_run` permanently for the lifetime of
each `Dht` handle. Tokio tasks send commands via mpsc channels;
results return via oneshot channels. The libuv thread is woken via
`uv_async_send` whenever a new command arrives.

This design concentrates all FFI/lifetime/threading complexity in one
crate where it can be tested and debugged in isolation.

## Quick start

```rust,ignore
use hyperdht::{Dht, DhtOptions, Keypair, ConnectOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dht = Dht::new(DhtOptions::default()).await?;

    // Server side
    let kp = Keypair::generate();
    println!("Listening as {}", hex::encode(kp.public().as_bytes()));
    let mut server = dht.listen(kp, Default::default()).await?;
    while let Some(stream) = server.accept().await {
        tokio::spawn(handle_session(stream));
    }
    Ok(())
}
```

## Crate status

Work-in-progress. See `RUSTDESK-INTEGRATION-PLAN.md` in the repo root
for the implementation roadmap.
