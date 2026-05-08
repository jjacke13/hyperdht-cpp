//! Concurrency stress tests.
//!
//! Spawns multiple Dht instances and DHT operations in parallel to
//! validate that the dedicated-libuv-thread architecture doesn't
//! serialise everything by accident, and that there's no shared
//! global state corruption.

use std::sync::Arc;

use hyperdht::{Dht, DhtOptions};
use tokio::task::JoinSet;

fn isolated_opts() -> DhtOptions {
    DhtOptions {
        use_public_bootstrap: false,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn eight_concurrent_dht_instances() {
    let mut set = JoinSet::new();
    for _ in 0..8 {
        set.spawn(async move {
            let dht = Dht::new(isolated_opts()).await.expect("create dht");
            assert!(dht.port() != 0);
            dht.destroy().await.expect("destroy");
        });
    }
    while let Some(res) = set.join_next().await {
        res.expect("task panic");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_lookups_on_one_dht() {
    let dht = Arc::new(Dht::new(isolated_opts()).await.expect("create dht"));

    let mut set = JoinSet::new();
    for i in 0u8..16 {
        let dht = dht.clone();
        set.spawn(async move {
            let mut target = [0u8; 32];
            target[0] = i;
            // No DHT to walk → completes quickly with empty Vec.
            let _ = dht.lookup(target).await;
        });
    }
    while let Some(res) = set.join_next().await {
        res.expect("task panic");
    }

    let dht = Arc::try_unwrap(dht).expect("only ref left");
    dht.destroy().await.expect("destroy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_state_inspectors() {
    let dht = Arc::new(Dht::new(isolated_opts()).await.expect("create dht"));

    let mut set = JoinSet::new();
    for _ in 0..32 {
        let dht = dht.clone();
        set.spawn(async move {
            // Sync inspectors must be cheap and correct under contention.
            for _ in 0..100 {
                let _ = dht.is_online();
                let _ = dht.is_persistent();
                let _ = dht.is_bootstrapped();
                let _ = dht.is_suspended();
                let _ = dht.port();
            }
        });
    }
    while let Some(res) = set.join_next().await {
        res.expect("task panic");
    }

    let dht = Arc::try_unwrap(dht).expect("only ref left");
    dht.destroy().await.expect("destroy");
}
