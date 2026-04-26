// HyperDHT bootstrap + network events — bootstrap walk, refresh, interface
// watcher, network-change/update/persistent fan-out.
//
// Split from src/dht.cpp. See dht.cpp for the JS flow map overview.

#include "hyperdht/dht.hpp"

#include <algorithm>
#include <cstdio>

#include "hyperdht/debug.hpp"
#include "hyperdht/query.hpp"

namespace hyperdht {

// ---------------------------------------------------------------------------
// §2: on_bootstrapped — register the "bootstrap walk finished" callback.
//
// JS: .analysis/js/dht-rpc/index.js:404 (`this.emit('ready')`). In JS this
// fires at most once, after `_bootstrap()` flips `bootstrapped = true`.
// C++ preserves the same once-only semantic and additionally fires the
// callback synchronously if the walk has already completed by the time
// the caller installs the hook.
// ---------------------------------------------------------------------------

void HyperDHT::on_bootstrapped(BootstrappedCallback cb) {
    on_bootstrapped_ = std::move(cb);
    if (on_bootstrapped_ && socket_ && socket_->is_bootstrapped()) {
        // Walk already finished — fire immediately so callers don't
        // miss the event due to late registration.
        auto once = std::move(on_bootstrapped_);
        once();
    }
}

// ---------------------------------------------------------------------------
// §2: start_bootstrap_walk — one-shot FIND_NODE(our_id) seeded from
// `opts_.bootstrap`. On success the RpcSocket is flagged bootstrapped.
//
// JS: .analysis/js/dht-rpc/index.js:379-433 (`_bootstrap`).
//     .analysis/js/dht-rpc/index.js:965-979 (`_backgroundQuery`).
//
// C++ diffs from JS:
//   - JS uses the async-iterator `_resolveBootstrapNodes()` to DNS-resolve
//     hostnames and fall back between pinned IP / DNS lookup. C++ expects
//     pre-resolved IPs in `opts_.bootstrap`; no async resolve step.
//   - JS's `_bootstrap` also drives the quick NAT heuristic (PING_NAT on
//     the first responder) and loops up to twice if NAT sampling is
//     pending. C++ currently runs a single pass — NAT detection is a §15
//     follow-up.
// ---------------------------------------------------------------------------

void HyperDHT::start_bootstrap_walk() {
    // Target = our own id (JS `_backgroundQuery(this.table.id)`). Walking
    // toward ourselves fills the routing table with the k closest nodes
    // to us, which is what every downstream query depends on.
    auto target = socket_->table().id();

    auto q = query::Query::create(*socket_, target, messages::CMD_FIND_NODE);
    q->set_internal(true);

    // JS `_backgroundQuery:968`: `Math.min(concurrency, Math.max(2,
    // concurrency/8))`. With the default concurrency=10 that collapses to
    // `max(2, 1) = 2`. Keeping background queries narrow prevents the
    // bootstrap traffic from hogging the congestion window.
    const int background_concurrency =
        std::max(2, query::DEFAULT_CONCURRENCY / 8);
    q->set_concurrency(background_concurrency);

    // Seed the walk from the supplied bootstrap list. `add_bootstrap`
    // inserts with a zeroed id so the pop-loop always visits them even
    // though they never land in `closest_replies_`. Matches JS's
    // `_resolveBootstrapNodes -> _addPending(node, null)` flow.
    for (const auto& addr : opts_.bootstrap) {
        q->add_bootstrap(addr);
    }

    DHT_LOG("  [dht] bootstrap: walking with %zu seed node(s), concurrency=%d\n",
            opts_.bootstrap.size(), background_concurrency);

    // Capture alive sentinel so the on_done lambda is a no-op if the DHT
    // has been destroyed by the time the walk finishes.
    std::weak_ptr<bool> weak_alive = alive_;
    q->on_done([this, weak_alive](const std::vector<query::QueryReply>& closest) {
        if (weak_alive.expired()) return;
        // JS `_bootstrap:402` — flip the flag, then emit `ready`.
        socket_->set_bootstrapped(true);
        DHT_LOG("  [dht] bootstrap: walk complete, %zu closest replies, "
                "routing table size=%zu\n",
                closest.size(), socket_->table().size());

        // Drop our strong ref BEFORE firing the user callback. This way,
        // if the user's `on_bootstrapped` callback re-enters HyperDHT
        // (e.g. calls `destroy()` or starts a new query), it never sees
        // a non-null `bootstrap_query_` after the walk has conceptually
        // finished. The Query itself is pinned for the duration of this
        // callback by Query's internal `shared_from_this()` self-capture,
        // so dropping our reference here is safe.
        bootstrap_query_.reset();

        if (on_bootstrapped_) {
            auto once = std::move(on_bootstrapped_);
            once();
        }
    });

    bootstrap_query_ = q;
    q->start();
}

// ---------------------------------------------------------------------------
// §2: refresh — periodic background FIND_NODE walk against a random
// routing-table entry, falling back to our own id if the table is empty.
//
// JS: .analysis/js/dht-rpc/index.js:435-438 (`refresh`).
//
// C++ diffs from JS:
//   - JS attaches a noop error handler to the stream (`.on('error', noop)`).
//     C++ Query has no error channel at this layer — failures are silent
//     by design.
//   - JS does NOT gate on bootstrapped; neither do we. An unbootstrapped
//     refresh will find zero seeds and complete immediately, which is
//     harmless.
// ---------------------------------------------------------------------------

void HyperDHT::refresh() {
    if (destroyed_ || !bound_) return;

    // JS: `const node = this.table.random();
    //       ...backgroundQuery(node ? node.id : this.table.id)`.
    routing::NodeId target;
    if (auto* rnd = socket_->table().random()) {
        target = rnd->id;
    } else {
        target = socket_->table().id();
    }

    auto q = query::Query::create(*socket_, target, messages::CMD_FIND_NODE);
    q->set_internal(true);
    const int background_concurrency =
        std::max(2, query::DEFAULT_CONCURRENCY / 8);
    q->set_concurrency(background_concurrency);

    DHT_LOG("  [dht] refresh: background query, table size=%zu\n",
            socket_->table().size());

    std::weak_ptr<bool> weak_alive = alive_;
    // Capture the query so we can locate-and-erase it from refresh_queries_
    // when it finishes. Using a raw Query* here is safe because the shared
    // ptr is owned by refresh_queries_ for the duration.
    query::Query* q_raw = q.get();
    q->on_done([this, weak_alive, q_raw](const std::vector<query::QueryReply>&) {
        // Belt-and-suspenders: both the alive sentinel and the explicit
        // destroyed_ flag must allow the erase. If the DHT has been
        // destroyed mid-refresh, `refresh_queries_` has already been
        // cleared by `destroy()` and touching it is a no-op, but we
        // skip it entirely to keep the lambda body defensively inert.
        if (weak_alive.expired() || destroyed_) return;
        // Prune the completed query from the retention list so long-lived
        // DHTs don't grow an unbounded refresh history.
        auto& rq = refresh_queries_;
        rq.erase(std::remove_if(rq.begin(), rq.end(),
                                [q_raw](const std::shared_ptr<query::Query>& p) {
                                    return p.get() == q_raw;
                                }),
                 rq.end());
    });

    refresh_queries_.push_back(q);
    q->start();
}

// ---------------------------------------------------------------------------
// §15: network-change / network-update / persistent event fan-out.
//
// JS: .analysis/js/dht-rpc/index.js:596-599 (`_onnetworkchange` emits
//     both `network-change` and `network-update`).
//     .analysis/js/hyperdht/index.js:64-75 (HyperDHT subscribes to all
//     three events to auto-refresh servers + spin up persistent store).
// ---------------------------------------------------------------------------

void HyperDHT::fire_network_change() {
    if (destroyed_) return;
    DHT_LOG("  [dht] network-change: refreshing %zu listening server(s)\n",
            servers_.size());

    // JS hyperdht/index.js:68-70 — refresh every listening server so it
    // re-announces on the new network topology.
    for (auto& srv : servers_) {
        if (srv) srv->refresh();
    }

    // Fire the user's hook.
    if (on_network_change_) {
        on_network_change_();
    }

    // JS always emits `network-update` immediately after `network-change`
    // (dht-rpc/index.js:596-599 emits both in the same call frame).
    fire_network_update();
}

void HyperDHT::fire_network_update() {
    if (destroyed_) return;

    // JS hyperdht/index.js:72-75 — only poke servers while we're online.
    if (is_online()) {
        for (auto& srv : servers_) {
            if (srv) srv->notify_online();
        }
    }

    if (on_network_update_) {
        on_network_update_();
    }
}

void HyperDHT::fire_persistent() {
    if (destroyed_) return;
    DHT_LOG("  [dht] persistent: node has transitioned ephemeral -> persistent\n");

    // JS: index.js:867 — re-bootstrap after ID change so the routing table
    // is populated with nodes close to our new address-based ID.
    if (socket_->is_bootstrapped()) {
        refresh();
    }

    // JS: index.js:72-74 — `on('network-update', () => { for (const server of this.listening) server.notifyOnline() })`
    // After the persistent transition, traffic switches from client_socket_
    // to server_socket_ (different port). Servers must fully re-announce
    // (not just refresh) so relay connections are rebuilt on the new socket
    // and relay addresses point to the new port. notify_online() resets
    // has_reannounced_ so build_relays() runs fresh with new peer addresses.
    for (auto& srv : servers_) {
        if (srv) srv->notify_online();
    }

    if (on_persistent_) {
        on_persistent_();
    }
}

// ---------------------------------------------------------------------------
// §15: libudx interface event watcher lifecycle.
//
// libudx `udx_interface_event_t` (deps/libudx/src/udx.c:2796-2905) wraps
// `uv_interface_addresses()` behind a periodic `uv_timer_t` that diffs
// the current interface list against the previous one and invokes the
// callback when the set changes. Matches JS `udx.watchNetworkInterfaces()`
// in `dht-rpc/lib/io.js:39`.
//
// Frequency: 5 seconds, same cadence as the RpcSocket background tick —
// slow enough to be free, fast enough to react to WiFi / VPN toggles.
// ---------------------------------------------------------------------------

static constexpr uint64_t INTERFACE_POLL_MS = 5000;

void HyperDHT::start_interface_watcher() {
    if (interface_watcher_ != nullptr) return;  // Already running

    interface_watcher_ = new udx_interface_event_t;
    interface_watcher_->data = this;

    int rc = udx_interface_event_init(socket_->udx_handle(),
                                      interface_watcher_,
                                      on_udx_interface_close);
    if (rc != 0) {
        DHT_LOG("  [dht] network-change: udx_interface_event_init failed: %d\n", rc);
        delete interface_watcher_;
        interface_watcher_ = nullptr;
        return;
    }

    rc = udx_interface_event_start(interface_watcher_,
                                   on_udx_interface_event,
                                   INTERFACE_POLL_MS);
    if (rc != 0) {
        DHT_LOG("  [dht] network-change: udx_interface_event_start failed: %d\n", rc);
        // Null the user data BEFORE the async close so the close callback
        // (which runs on a later loop iteration) cannot dispatch against a
        // partially-constructed HyperDHT if destroy() runs before drain.
        interface_watcher_->data = nullptr;
        // Close the handle — its close callback will free our allocation.
        udx_interface_event_close(interface_watcher_);
        interface_watcher_ = nullptr;  // Ownership transferred to the close cb
        return;
    }

    interface_watcher_active_ = true;
    DHT_LOG("  [dht] network-change: watcher started (%lu ms poll)\n",
            static_cast<unsigned long>(INTERFACE_POLL_MS));
}

void HyperDHT::stop_interface_watcher() {
    if (interface_watcher_ == nullptr) return;
    if (interface_watcher_active_) {
        udx_interface_event_stop(interface_watcher_);
        interface_watcher_active_ = false;
    }
    // Null the data pointer so any pending callback is a no-op.
    interface_watcher_->data = nullptr;
    // Do NOT call udx_interface_event_close() here — the udx_t teardown
    // (triggered by socket_->close()) will close all attached interface
    // events automatically (libudx/src/udx.c:1879). Calling close manually
    // AND letting teardown close it causes the close callback to fire after
    // the udx_t is freed -> use-after-free in ref_dec(event->udx).
    //
    // Trade-off accepted: the `udx_interface_event_t` heap struct leaks
    // ~232 bytes per HyperDHT instance at process exit, because libudx
    // teardown closes its listener handles but our `on_udx_interface_close`
    // deleter never fires in that path. Fixable only by patching libudx
    // to invoke the user close callback from its teardown loop. Since
    // the leak is bounded per process lifetime (one per HyperDHT)
    // and not per-operation, we accept it.
    interface_watcher_ = nullptr;
}

void HyperDHT::on_udx_interface_event(udx_interface_event_t* handle, int status) {
    if (handle->data == nullptr) return;  // DHT is tearing down.
    if (status != 0) return;  // Error — libudx couldn't enumerate.
    auto* self = static_cast<HyperDHT*>(handle->data);
    self->fire_network_change();
}

void HyperDHT::on_udx_interface_close(udx_interface_event_t* handle) {
    // handle is heap-allocated in start_interface_watcher(). The close
    // callback fires asynchronously after udx_interface_event_close().
    // We must NOT dereference handle->data (the HyperDHT*) here —
    // the HyperDHT may already be destroyed by the time this fires.
    if (handle) delete handle;
}

}  // namespace hyperdht
