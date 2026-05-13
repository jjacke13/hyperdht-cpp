//! Persistent HyperDHT echo server in Rust.
//!
//! Mirrors `examples/cpp/server.cpp`. Accepts connections from any
//! peer that knows our public key and echoes back whatever they send.
//!
//! Usage:
//!   echo-server                       # random keypair
//!   echo-server <64-char-hex-seed>    # deterministic identity
//!   echo-server <seed> <port>         # deterministic identity, fixed port
//!
//! Run:
//!   cd examples/rust
//!   cargo run --release --bin echo-server -- [seed] [port]

use std::env;

use hyperdht::{Dht, DhtOptions, Keypair, Server, ServerOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (seed, port) = parse_args();

    let opts = DhtOptions {
        port,
        use_public_bootstrap: true,
        seed,
        ..Default::default()
    };

    let dht = Dht::new(opts).await?;
    println!("DHT port: {}", dht.port());

    let kp = match seed {
        Some(seed) => Keypair::from_seed(&seed),
        None => Keypair::generate(),
    };
    let pubkey = kp.public();
    println!("Public key: {}", pubkey);
    println!();

    let server = dht.listen(kp, ServerOptions::default()).await?;
    println!("Listening... (Ctrl+C to stop)");
    println!();

    // Run the accept loop. Ctrl+C tears it down.
    tokio::select! {
        _ = accept_loop(server) => {}
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down...");
        }
    }

    dht.destroy().await?;
    Ok(())
}

async fn accept_loop(mut server: Server) {
    while let Some(stream) = server.accept().await {
        tokio::spawn(handle_session(stream));
    }
}

async fn handle_session(mut stream: hyperdht::Stream) {
    println!("Connection accepted");
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                println!("  Stream closed by peer");
                return;
            }
            Ok(n) => {
                println!("  Received {} bytes — echoing back", n);
                if let Err(e) = stream.write_all(&buf[..n]).await {
                    eprintln!("  Write error: {e}");
                    return;
                }
            }
            Err(e) => {
                eprintln!("  Read error: {e}");
                return;
            }
        }
    }
}

fn parse_args() -> (Option<[u8; 32]>, u16) {
    let mut seed = None;
    let mut port = 0u16;

    for arg in env::args().skip(1) {
        if arg.len() == 64 {
            // 64 hex chars = seed
            let mut s = [0u8; 32];
            if hex::decode_to_slice(&arg, &mut s).is_ok() {
                seed = Some(s);
                continue;
            }
        }
        if let Ok(p) = arg.parse::<u16>() {
            port = p;
        }
    }

    (seed, port)
}
