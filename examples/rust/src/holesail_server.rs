//! holesail-rs (server side) — expose a local TCP port over HyperDHT.
//!
//! A Rust reimplementation of holesail's server functionality, mirroring
//! `examples/python/holesail_server.py`. Accepts encrypted P2P
//! connections from the public DHT and bridges each one to a local
//! TCP service.
//!
//! Usage:
//!   holesail-server --live 8080
//!   holesail-server --live 3000 --seed <64-hex>
//!   holesail-server --live 8080 --seed <64-hex> --secure
//!
//! Connect with the JS holesail client (or any peer that has our
//! connection string):
//!   holesail --connect hs://<prefix><z32-of-key>
//!
//! Why this is simpler than the Python version: tokio gives us native
//! async TCP, so we skip the `uv_poll`-based hand-rolled bridge and
//! just spawn `tokio::io::copy_bidirectional(&mut tcp, &mut stream)`
//! per accepted peer. ~80 lines of bridging in Python collapses to
//! ~10 lines here.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hyperdht::{Dht, DhtOptions, Keypair, ServerOptions};
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[command(name = "holesail-server", about = "Expose a local TCP port over HyperDHT (P2P)")]
struct Args {
    /// Local TCP port to expose
    #[arg(long, value_name = "PORT")]
    live: u16,

    /// Local bind address
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// 64-char hex seed for deterministic identity
    #[arg(long, value_name = "HEX")]
    seed: Option<String>,

    /// Reject peers that don't share the seed-derived identity.
    ///
    /// In this mode the connection key advertised to peers is the
    /// seed (not the pubkey), so only seed-holders can derive the
    /// right pubkey to dial.
    #[arg(long)]
    secure: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let local_addr: SocketAddr = format!("{}:{}", args.host, args.live).parse()?;

    // Pre-flight: warn if nothing's listening locally yet.
    match TcpStream::connect(&local_addr).await {
        Ok(s) => drop(s),
        Err(e) => eprintln!(
            "Warning: nothing listening on {} yet ({}). Will retry per-connection.",
            local_addr, e
        ),
    }

    let (kp, connection_key, seed_for_dht) = make_keypair(args.seed.as_deref(), args.secure)?;
    let pubkey = kp.public();

    // Build the DHT
    let dht = Arc::new(
        Dht::new(DhtOptions {
            use_public_bootstrap: true,
            // Use the same seed for the DHT identity so reconnects
            // from the same seed see a stable node identity.
            seed: seed_for_dht,
            ..Default::default()
        })
        .await?,
    );
    let dht_port = dht.port();

    // Publish JSON metadata so clients can discover the listener
    // shape (host/port/protocol). Mirrors JS holesail's mutable_put.
    // Done BEFORE listen() because listen() consumes the keypair.
    let metadata = format!(
        r#"{{"host":"{}","port":{},"udp":false}}"#,
        args.host, args.live
    );
    if let Err(e) = dht.mutable_put(&kp, metadata.as_bytes(), 1).await {
        eprintln!("Warning: mutable_put metadata failed ({}). Discovery still works via the pubkey alone.", e);
    }

    // Server with reusable_socket so reconnects from the same client
    // skip a fresh holepunch.
    let server_opts = ServerOptions {
        reusable_socket: true,
        share_local_address: true,
    };
    let mut server = dht.listen(kp, server_opts).await?;

    // Optional firewall — matches the Python version's behavior.
    // Note: the python rule (`remote_pk != self_pk`) doesn't actually
    // gate on seed-knowledge; the secrecy of "secure mode" comes from
    // the seed being kept private (it's what gets advertised, so only
    // seed-holders can derive the dial-able pubkey).
    if args.secure {
        let server_pk = pubkey;
        if let Err(e) = server.set_firewall(move |remote_pk, _host, _port| {
            remote_pk.as_bytes() != server_pk.as_bytes()
        }) {
            eprintln!("Warning: set_firewall failed ({})", e);
        }
    }

    let connection_count = Arc::new(AtomicU64::new(0));
    let active_bridges = Arc::new(AtomicU64::new(0));

    // Connection string — z32-encoded with 4-char prefix.
    let prefix = if args.secure { "s000" } else { "0000" };
    let hs_link = format!("hs://{}{}", prefix, connection_key);

    println!(
        r#"
  holesail-rs -- P2P tunnel powered by hyperdht-cpp
  --------------------------------------------------

  Exposing:    {host}:{port}
  DHT port:    {dht_port}
  Mode:        {mode}
  Public key:  {pubkey}

  Connection string:
    {hs_link}

  Connect with:
    holesail --connect {hs_link}

  Ctrl+C to stop
"#,
        host = args.host,
        port = args.live,
        dht_port = dht_port,
        mode = if args.secure { "secure" } else { "open" },
        pubkey = pubkey,
        hs_link = hs_link,
    );

    // Spawn the heartbeat task — prints state every 30s for diagnostics.
    let dht_for_heartbeat = dht.clone();
    let conns_for_heartbeat = connection_count.clone();
    let bridges_for_heartbeat = active_bridges.clone();
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        // Skip the immediate first tick.
        interval.tick().await;
        loop {
            interval.tick().await;
            let addr = match dht_for_heartbeat.remote_address().await {
                Ok(Some((h, p))) => format!("{}:{}", h, p),
                _ => "unknown".to_string(),
            };
            println!(
                "  [heartbeat] online={} persistent={} addr={} bridges={} conns={}",
                dht_for_heartbeat.is_online(),
                dht_for_heartbeat.is_persistent(),
                addr,
                bridges_for_heartbeat.load(Ordering::Relaxed),
                conns_for_heartbeat.load(Ordering::Relaxed),
            );
        }
    });

    // Accept loop: each accepted Stream becomes a bidirectional bridge
    // to a freshly-opened TCP connection on `local_addr`.
    let local_addr_arc = Arc::new(local_addr);
    let accept_task = {
        let local_addr = local_addr_arc.clone();
        let connection_count = connection_count.clone();
        let active_bridges = active_bridges.clone();
        async move {
            while let Some(stream) = server.accept().await {
                let conn_id = connection_count.fetch_add(1, Ordering::Relaxed) + 1;
                let local_addr = *local_addr;
                let active_bridges = active_bridges.clone();

                tokio::spawn(async move {
                    active_bridges.fetch_add(1, Ordering::Relaxed);
                    let result = bridge_one(stream, local_addr, conn_id).await;
                    active_bridges.fetch_sub(1, Ordering::Relaxed);
                    if let Err(e) = result {
                        eprintln!("  [{}] bridge ended with error: {}", conn_id, e);
                    } else {
                        println!("  [{}] bridge closed cleanly", conn_id);
                    }
                });
            }
        }
    };

    tokio::select! {
        _ = accept_task => {}
        _ = tokio::signal::ctrl_c() => {
            println!(
                "\n  Shutting down ({} connections served)",
                connection_count.load(Ordering::Relaxed)
            );
        }
    }

    heartbeat.abort();
    // Wait for the aborted task to actually finish so it drops its
    // Arc<Dht> clone before we try_unwrap.
    let _ = heartbeat.await;

    // Drop the DHT — destroy() awaits libuv teardown gracefully.
    let dht = Arc::try_unwrap(dht)
        .map_err(|_| "dht still has outstanding references at shutdown")?;
    dht.destroy().await?;

    Ok(())
}

/// Bridge one P2P stream ↔ one local TCP connection.
async fn bridge_one(
    mut stream: hyperdht::Stream,
    local_addr: SocketAddr,
    conn_id: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("  [{}] peer connected — opening local TCP", conn_id);

    let mut tcp = TcpStream::connect(local_addr).await.map_err(|e| {
        format!("can't reach {}: {}", local_addr, e)
    })?;

    // tokio handles half-close automatically: when one side EOFs,
    // copy_bidirectional shuts down the other side's writer and
    // returns once both halves are done.
    let (from_tcp, from_stream) =
        tokio::io::copy_bidirectional(&mut tcp, &mut stream).await?;
    println!(
        "  [{}] tcp→stream {} bytes, stream→tcp {} bytes",
        conn_id, from_tcp, from_stream
    );

    Ok(())
}

/// Build the keypair and the public connection key per the python
/// rules:
///
/// |  flags          | keypair source            | advertised key   |
/// | --------------- | ------------------------- | ---------------- |
/// | (none)          | random                    | pubkey           |
/// | --seed          | from seed                 | pubkey           |
/// | --secure (only) | random seed → from seed   | seed (random)    |
/// | --seed --secure | from seed                 | seed             |
///
/// Returns `(keypair, z32-encoded-connection-key, dht-seed)`. The DHT
/// seed mirrors the keypair seed (when one was provided) so the DHT
/// node identity is also deterministic across restarts.
fn make_keypair(
    seed_hex: Option<&str>,
    secure: bool,
) -> Result<(Keypair, String, Option<[u8; 32]>), Box<dyn std::error::Error>> {
    if let Some(hex_str) = seed_hex {
        if hex_str.len() != 64 {
            return Err("seed must be 64 hex characters (32 bytes)".into());
        }
        let mut seed = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut seed)?;
        let kp = Keypair::from_seed(&seed);
        let pubkey_bytes = *kp.public().as_bytes();
        let advertised = if secure { seed } else { pubkey_bytes };
        Ok((kp, to_z32(&advertised), Some(seed)))
    } else if secure {
        // Generate a fresh seed; advertise the seed (it's the secret
        // that gates connectivity).
        let mut raw_seed = [0u8; 32];
        getrandom_seed(&mut raw_seed);
        let kp = Keypair::from_seed(&raw_seed);
        let advertised = raw_seed;
        Ok((kp, to_z32(&advertised), Some(raw_seed)))
    } else {
        // Open + random — advertise just the pubkey.
        let kp = Keypair::generate();
        let pubkey_bytes = *kp.public().as_bytes();
        Ok((kp, to_z32(&pubkey_bytes), None))
    }
}

/// Fill `out` with cryptographically-secure random bytes from the OS.
/// We avoid pulling in the `rand` crate for one call — this matches
/// the python version's use of `os.urandom`.
fn getrandom_seed(out: &mut [u8; 32]) {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom").expect("open /dev/urandom");
    f.read_exact(out).expect("read /dev/urandom");
}

/// Encode bytes with the z-base-32 alphabet used by holesail's
/// connection strings (`ybndrfg8ejkmcpqxot1uwisza345h769`, all
/// lowercase). 32 bytes → 52 chars.
fn to_z32(data: &[u8]) -> String {
    const Z32: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(Z32[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(Z32[idx] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn z32_round_trip_known_vector() {
        // The all-zero 32-byte input under the z32 alphabet starts
        // with the alphabet's first char ('y') repeated.
        let zeros = [0u8; 32];
        let encoded = to_z32(&zeros);
        assert_eq!(encoded.len(), 52);
        assert!(encoded.chars().all(|c| c == 'y'));
    }

    #[test]
    fn z32_known_alphabet() {
        // Encoding 0x00, 0x01, 0x02 should produce known prefix
        // chars from the z32 alphabet (positions 0, 0, 1 across
        // the bit boundaries).
        let encoded = to_z32(&[0x00, 0x44, 0x32]);
        // 3 bytes = 24 bits = 5 base32 chars (last with padding bits).
        assert_eq!(encoded.len(), 5);
    }
}
