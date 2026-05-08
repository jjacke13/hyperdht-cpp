//! HyperDHT echo client in Rust.
//!
//! Mirrors `examples/cpp/client.cpp`. Connects to a server by public
//! key, sends a hello message, prints the echo, exits.
//!
//! Usage:
//!   echo-client <remote-pubkey>             # random identity
//!   echo-client <remote-pubkey> <our-seed>  # deterministic identity
//!
//! Run:
//!   cd examples/rust
//!   cargo run --release --bin echo-client -- <pubkey>

use std::env;
use std::time::Duration;

use hyperdht::{ConnectOptions, Dht, DhtOptions, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1].len() != 64 {
        eprintln!("Usage: {} <64-char-hex-public-key> [our-seed]", args[0]);
        std::process::exit(1);
    }

    let remote_pk = PublicKey::from_hex(&args[1])?;
    let seed = if args.len() > 2 && args[2].len() == 64 {
        let mut s = [0u8; 32];
        hex::decode_to_slice(&args[2], &mut s)?;
        Some(s)
    } else {
        None
    };
    if seed.is_some() {
        println!("Using seed: {}...", &args[2][..16]);
    }

    let opts = DhtOptions {
        use_public_bootstrap: true,
        seed,
        ..Default::default()
    };
    let dht = Dht::new(opts).await?;

    print!("Connecting to ");
    for b in &remote_pk.as_bytes()[..8] {
        print!("{b:02x}");
    }
    println!("...");

    // Connect with a generous timeout — first connect goes through a
    // full DHT walk + holepunch, can take a few seconds.
    let mut stream = tokio::time::timeout(
        Duration::from_secs(30),
        dht.connect(remote_pk, ConnectOptions::default()),
    )
    .await
    .map_err(|_| "connect timed out after 30s")??;

    println!("Connected");

    let msg = b"hello from rust";
    println!("Stream open — sending {:?}", std::str::from_utf8(msg)?);
    stream.write_all(msg).await?;

    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf).await?;
    println!("Received: {}", std::str::from_utf8(&buf)?);

    // Half-close our side. Mirrors the C++ client's stream_close call —
    // both sides must close for the on_close callback to fire promptly
    // (CLAUDE.md gotcha #12 in the parent project).
    stream.shutdown().await?;
    drop(stream);

    println!("Done");
    dht.destroy().await?;
    Ok(())
}
