//! Cancel-safety tests.
//!
//! Drops in-flight futures (connect, lookup, announce, mutable_get,
//! datagram waiting) before they resolve. The wrapper must NOT crash,
//! leak, or UAF — every C-side context box should be reclaimed
//! exactly once on its done/close callback regardless of whether
//! the Rust caller is still listening.
//!
//! Run under AddressSanitizer for the strongest signal:
//!
//! ```bash
//! RUSTFLAGS="-Zsanitizer=address" \
//!   cargo +nightly test --target x86_64-unknown-linux-gnu \
//!   --test drop_midflight
//! ```

use hyperdht::{Dht, DhtOptions, Keypair, PublicKey};

fn isolated_opts() -> DhtOptions {
    DhtOptions {
        use_public_bootstrap: false,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_pending_connect_does_not_leak() {
    let dht = Dht::new(isolated_opts()).await.expect("create dht");

    // Connect to a random pubkey — no peers, will fail eventually.
    // We drop the future before it resolves.
    let pk = PublicKey::from_bytes([0xAB; 32]);
    {
        let fut = dht.connect(pk, Default::default());
        // Race the drop against the libuv thread's processing.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(fut);
    }
    // Give the C side a moment to walk through its on_close path.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    dht.destroy().await.expect("destroy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_pending_lookup_does_not_leak() {
    let dht = Dht::new(isolated_opts()).await.expect("create dht");

    {
        let fut = dht.lookup([0xCDu8; 32]);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(fut);
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    dht.destroy().await.expect("destroy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_pending_announce_does_not_leak() {
    let dht = Dht::new(isolated_opts()).await.expect("create dht");

    {
        let fut = dht.announce([0xEFu8; 32], b"value");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(fut);
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    dht.destroy().await.expect("destroy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_pending_mutable_get_does_not_leak() {
    let dht = Dht::new(isolated_opts()).await.expect("create dht");

    let kp = Keypair::generate();
    {
        let fut = dht.mutable_get(kp.public(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(fut);
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    dht.destroy().await.expect("destroy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_pending_immutable_get_does_not_leak() {
    let dht = Dht::new(isolated_opts()).await.expect("create dht");

    {
        let fut = dht.immutable_get([0x42u8; 32]);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(fut);
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    dht.destroy().await.expect("destroy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_dht_with_listener_pending() {
    // Create a DHT, start a server, drop the listener, then destroy.
    let dht = Dht::new(isolated_opts()).await.expect("create dht");

    let kp = Keypair::generate();
    let server = dht
        .listen(kp, Default::default())
        .await
        .expect("listen");
    drop(server);

    dht.destroy().await.expect("destroy");
}
