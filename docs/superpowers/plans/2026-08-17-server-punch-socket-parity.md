# Server Per-Session Punch Socket (JS Parity) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The server side of every holepunch session acquires a fresh ephemeral UDP socket (like JS `Holepuncher`), and the handshake reply, NAT sampling, round replies, fast-mode ping, probes, probe echo, and the punched UDX stream all ride that socket — eliminating the main-socket concentration that field evidence implicates in the C++-server-only punch failures.

**Architecture:** Reuse the client-proven `holepunch::PoolSocket` (sampler + request + probe machinery) as the server's per-session punch socket, adding inbound-request dispatch and reply sending. The handshake reply is transmitted from the punch socket (JS `server.js:481` `{ socket: h.puncher.socket }`), which makes the relay observe the punch-socket mapping and forward all subsequent PEER_HOLEPUNCH rounds to it — so rounds bypass the main-socket Router entirely and arrive at the pool socket, exactly like JS (`req.socket === p.socket`, server.js:509).

**Tech Stack:** C++20, libuv, libudx, GoogleTest. Build/test via `nix develop --command bash -c "..."`.

## Why (evidence, 2026-08-17)

- Same box (Pi5), same router: **nospoon-js server = phone connected every time for months; nospoon-cpp server = intermittent/failing, fast-mode-only** (handoff line 14, §Q parity note).
- Client code exonerated: nospoon-**js** client fails identically against the cpp server (2026-08-05 control).
- Network exonerated: holesail-js punches from the most hostile client network tested (2026-08-05), and probes are byte-identical (1×`0x00`, TTL 64/5).
- Fast-mode-only success = server→client works, client→server inbound-to-`:58475` doesn't. The punch needs a NEW inbound flow on the busiest, oldest UDP mapping on the box; JS gives every session a virgin mapping.

## Global Constraints

- **TDD mandatory:** every task = failing test first, red verified, then implement, then green. Red-check EVERY fix (a red-check that won't go red = redundant fix).
- **Build/test only via** `nix develop --command bash -c "cmake --build build ... && ctest ..."`. Bash cwd persists between calls — use absolute paths.
- **Full suite gate:** `ctest -E 'LiveServer|test_server_live'` in `build/` must stay 100%. ASAN suite (`build-asan/`) has **137 pre-existing leak failures** — the gate is "no NEW failures"; compare per-binary, not suite-wide.
- **cpp-reviewer agent MUST review** the complete diff before final commit series is declared done.
- **Commit format** `<type>: <description>`, no attribution trailers, commit locally after each task, **never push without the user's explicit ask**.
- **Wire format frozen:** no message encoding changes. Old clients must interop with the new server unchanged.
- **ESP32/EMBEDDED:** `HYPERDHT_EMBEDDED` builds keep today's main-socket punch path. All new punch-socket code is `#ifndef HYPERDHT_EMBEDDED` (or runtime no-op when creation is skipped).
- **JS refs required:** every behavioral decision cites the JS file:line it mirrors (reference tree: `.analysis/js/hyperdht/lib/`).
- `docs/TODO.md` is the single source of truth — update it as tasks land.

## Design Decisions (spec)

1. **Punch socket = `holepunch::PoolSocket`** (holepunch.hpp:148), NOT `socket_pool::SocketRef`. It already has: bind on ephemeral port, NAT sampler fed by responses (`handle_message` RESPONSE_ID branch), `request()` with retries/RTT-EMA, `send_probe`/`send_probe_ttl`, probe callback (`on_holepunch_probe`), close lifecycle hardened for GrapheneOS. The client (`PunchState`, holepunch.cpp:1557) already uses it directly rather than `SocketPool::acquire()` — the server mirrors that existing, field-proven divergence from JS's `_socketPool.acquire()` (socket-pool.js:37-40). No linger/reuse in v1 (JS's own acquire has `// TODO: Enable socket reuse`).
2. **Creation at handshake time** (JS `server.js:436` creates the puncher in `_addHandshake`), for firewalled servers only (JS gate: `ourRemoteAddr || this._neverPunch` → no puncher, server.js:430). Sampling (`discover_pool_addresses`, holepunch.hpp:231 = JS `nat.autoSample()`, nat.js:25-79) starts immediately so it has settled by round 1.
3. **Handshake reply rides the punch socket** (JS server.js:481: `return { socket: h.puncher && h.puncher.socket, noise: h.reply }`). This is what seeds the relay's observation → the relay forwards all rounds to the punch mapping (router.js:214 uses its observation verbatim). Dedup resends (server.cpp:470) and async-firewall queued replies (server.cpp:651) must use it too.
4. **Rounds arrive ON the punch socket** and are handled there — `PoolSocket` gains `on_request` + `reply`. The main-socket Router's server-side PEER_HOLEPUNCH branch stays (relay duty for others + old-client LAN/direct paths) but our own firewalled sessions stop using it.
5. **`analyze()` await restored** (JS server.js:518-519): a round arriving before pool sampling settles is parked; `discover_pool_addresses`'s `on_done` drains parked rounds. **Server-side `_reopen()` (holepuncher.js:154-160) is explicitly OUT OF SCOPE v1** — unstable-after-sampling aborts (JS would try up to 3 fresh sockets first). Documented divergence; TODO entry.
6. **Payload NAT state from the pool sampler** (JS server.js:590,594: `p.nat.firewall`, `p.nat.addresses`): fast-mode ping gate + destination, freeze, round replies. The round-arrival feed `p.nat.add(req.to, req.from)` (server.js:509-511) happens in the pool request handler.
7. **Probe echo per punch socket**, non-initiator semantics (holepuncher.js:123-127: echo back from the arrival socket, never mark connected). The main-socket probe listener (server.cpp:208-214) STAYS — the client LAN-shortcut ping targets the server port and needs its echo.
8. **Stream adoption is already socket-generic**: `udx_stream_init(socket_.udx_handle(), ...)` (server.cpp:721) binds to the udx_t instance; PoolSocket shares it (PoolSocket ctor takes `udx_t*`); `on_raw_stream_firewall(stream, socket, from)` (server.hpp:348) delivers the arrival socket and `ConnectionInfo.udx_socket` carries it out. Task 5 verifies rather than builds.
9. **Lifetime:** `ServerConnection` holds `std::shared_ptr<holepunch::PoolSocket>`. On successful adoption the stream's `RawStreamCtx` takes a second reference so session GC can't kill a live connection's socket; the socket dies when the last reference drops (session clear on failure, stream finalize on success). This is Finding-J territory — ASAN-gated tests required.
10. **Handshake `addresses4` goes to JS shape** (server.js: one `ourRemoteAddr` + local addresses): `[dht_->remote_address()] + LAN`, replacing the sampler-dump + port-rewrite hack (server.cpp:491-502) that produced `addr[0]==addr[1]` duplicates in field logs.

## Interop matrix (why this is safe to ship server-side only)

| client | old cpp server | new cpp server |
|---|---|---|
| old cpp / JS / Android | rounds via main socket | handshake reply from pool → relay observes pool → rounds+probes to pool. Client-side logic unchanged: it already targets the relay-observed `peerAddress` (CLAUDE.md gotcha 19) and payload addresses. |
| LAN shortcut | main-socket echo | unchanged (main listener stays) |
| non-firewalled server | direct, no puncher | unchanged (no pool socket created) |

## File Structure

- Modify: `include/hyperdht/holepunch.hpp` (PoolSocket: `on_request`, `reply`)
- Modify: `src/holepunch.cpp` (PoolSocket REQUEST_ID branch + reply; ~40 lines)
- Modify: `include/hyperdht/router.hpp` + `src/router.cpp` (handshake server-entry: pass `from_address`, reply_fn gains socket override)
- Modify: `src/rpc_handlers.cpp` (RelayFn honors socket override)
- Modify: `include/hyperdht/server_connection.hpp` (punch_socket member + parked rounds)
- Modify: `src/server.cpp` (the bulk: creation, deferred rounds, payload source, ping/probe/echo rerouting, lifetime)
- Modify: `include/hyperdht/server.hpp` (handler signatures)
- Test: `test/test_pool_socket_requests.cpp` (new), `test/test_server.cpp`, `test/test_server_punch_socket.cpp` (new)

---

### Task 1: Handshake `addresses4` → JS shape (standalone parity fix)

**Files:**
- Modify: `src/server.cpp:486-513` (the `our_addrs` build inside the handshake reply)
- Test: `test/test_server.cpp`

**Interfaces:**
- Consumes: `dht_->remote_address()` (existing, `std::optional<compact::Ipv4Address>`), `dht_->local_addresses_now()` (existing).
- Produces: handshake reply `addresses4` = `[remote_address?] + LAN`, no duplicates, no port-rewrite loop. Round payloads (`server.cpp:1226`) are NOT touched by this task.

- [ ] **Step 1: Write the failing test** — in `test/test_server.cpp`, next to the existing handshake-reply tests (grep `addresses4` there for the harness pattern):

```cpp
// JS server.js builds addresses4 as [ourRemoteAddr] + local addresses —
// ONE public entry from dht.remoteAddress(), never a sampler dump. The old
// sampler-dump + port-rewrite produced duplicate entries (field log
// 2026-08-17: "Server addr[0]: :58475 addr[1]: :58475").
TEST_F(ServerHandshake, Addresses4IsRemoteAddressPlusLanWithoutDuplicates) {
    auto reply = do_handshake_and_decode_reply();  // existing fixture helper
    ASSERT_FALSE(reply.addresses4.empty());
    std::set<std::pair<std::string, uint16_t>> seen;
    for (const auto& a : reply.addresses4) {
        auto key = std::make_pair(a.host_string(), a.port);
        EXPECT_TRUE(seen.insert(key).second)
            << "duplicate addresses4 entry " << a.host_string() << ":" << a.port;
    }
    // Exactly one non-RFC1918 entry (the dht remote_address), rest LAN.
    int public_count = 0;
    for (const auto& a : reply.addresses4)
        if (!is_private_host(a.host_string())) public_count++;
    EXPECT_LE(public_count, 1);
}
```

Adapt fixture names to what `test/test_server.cpp` actually uses (read the file first; if no reply-decoding helper exists, add one that drives `on_peer_handshake` with a canned Noise msg1 the existing tests already construct).

- [ ] **Step 2: Run to verify it fails** — `nix develop --command bash -c "cmake --build /home/jacke/Desktop/repos/hyperdht-cpp/build --target test_server && /home/jacke/Desktop/repos/hyperdht-cpp/build/test_server --gtest_filter='*Addresses4Is*'"` — expect FAIL (duplicates present today whenever the sampler holds >1 entry; if the harness only ever yields one sampler entry, seed a second via `socket_.nat_sampler().add(...)` in the test).

- [ ] **Step 3: Implement** — replace `server.cpp:491-502` with:

```cpp
    // JS server.js: addresses4 = [ourRemoteAddr] + our local addresses —
    // dht.remoteAddress() is the single public entry; never a sampler dump.
    // (The old sampler-dump needed a port-rewrite hack because the shared
    // sampler holds pre-persistent-transition ports, and it produced
    // duplicate entries. Round payloads use the per-session punch socket's
    // sampler — see Task 4 — so nothing needs the dump anymore.)
    std::vector<compact::Ipv4Address> our_addrs;
    if (auto ra = dht_ ? dht_->remote_address() : std::nullopt) {
        our_addrs.push_back(*ra);
    }
```

Keep the existing `share_local_address` LAN-append block (server.cpp:503-513) unchanged after it. If `dht_` is null (unit harness), `our_addrs` may be empty — check downstream consumers of `our_addrs` in this function tolerate empty (they do today for the firewalled path; verify the `matched=fallback` client path uses `addresses4[0]` only when non-empty — connect.cpp:704-736).

- [ ] **Step 4: Run test + the server suite** — same filter, then `--gtest_filter='ServerHandshake.*'` and full `test_server`. Expect PASS, no regressions. Fix any test asserting the old sampler-dump shape (update the assertion, cite server.js in a comment).

- [ ] **Step 5: Commit** — `git add src/server.cpp test/test_server.cpp && git commit -m "fix: handshake addresses4 is remoteAddress + LAN, not a sampler dump"`

---

### Task 2: PoolSocket inbound requests + replies

**Files:**
- Modify: `include/hyperdht/holepunch.hpp` (PoolSocket public API, after `on_holepunch_probe` at ~line 180)
- Modify: `src/holepunch.cpp` (`PoolSocket::handle_message` — add REQUEST_ID branch; new `PoolSocket::reply`)
- Test: `test/test_pool_socket_requests.cpp` (new; register in CMakeLists.txt next to the other test targets)

**Interfaces:**
- Produces (Task 4 consumes):

```cpp
// holepunch.hpp — inside class PoolSocket, public:
using OnRequestCallback = std::function<void(const messages::Request& req,
                                             const compact::Ipv4Address& from)>;
void on_request(OnRequestCallback cb) { on_request_ = std::move(cb); }
// Encode + send a Response from THIS socket. resp.from.addr is the UDP
// destination (same convention as RpcSocket::reply, rpc.cpp:557-571).
void reply(const messages::Response& resp);
```

- [ ] **Step 1: Failing test** — new file `test/test_pool_socket_requests.cpp`. Harness: one uv loop, one `udx_t`, a plain sender udx socket, one `PoolSocket` (pattern: copy the loop/udx setup from `test/test_holepunch.cpp`'s pool-socket tests — read that file first).

```cpp
TEST_F(PoolSocketRequests, InboundRequestDispatchesAndReplyRoundTrips) {
    messages::Request req;
    req.tid = 777;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.internal = false;
    req.to.addr = pool_addr();          // wire `to` = the pool socket's addr
    req.value = std::vector<uint8_t>{1, 2, 3};

    std::optional<messages::Request> got;
    pool_->on_request([&](const messages::Request& r, const compact::Ipv4Address& from) {
        got = r;
        messages::Response resp;
        resp.tid = r.tid;
        resp.from.addr = from;          // destination, per RpcSocket::reply convention
        resp.value = std::vector<uint8_t>{9};
        pool_->reply(resp);
    });

    send_from_plain_socket(messages::encode_request(req), pool_addr());
    run_loop_until([&] { return got.has_value(); });
    ASSERT_TRUE(got);
    EXPECT_EQ(got->tid, 777);
    EXPECT_EQ(got->command, messages::CMD_PEER_HOLEPUNCH);

    run_loop_until([&] { return plain_socket_received_response(); });
    EXPECT_EQ(received_response().tid, 777);
}

TEST_F(PoolSocketRequests, RequestFeedsNatSampler) {
    // wire `to` field = our external address as the sender saw us
    // (JS server.js:510 p.nat.add(req.to, req.from)).
    messages::Request req;
    req.tid = 1;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.to.addr = compact::Ipv4Address::from_string("203.0.113.7", 4242);
    pool_->on_request([](const messages::Request&, const compact::Ipv4Address&) {});
    send_from_plain_socket(messages::encode_request(req), pool_addr());
    run_loop_until([&] { return pool_->nat_sampler().sampled() > 0; });
    EXPECT_GE(pool_->nat_sampler().sampled(), 1u);
}
```

- [ ] **Step 2: Verify red** — `on_request` doesn't exist → compile failure counts as red for the first test; for the sampler test, red after stubbing.

- [ ] **Step 3: Implement** — in `PoolSocket::handle_message`, after the RESPONSE_ID branch:

```cpp
    if (type == messages::REQUEST_ID) {
        if (!on_request_) return;   // no consumer wired — drop, like unknown traffic
        char h2[INET_ADDRSTRLEN];
        uv_ip4_name(addr, h2, sizeof(h2));
        auto from = Ipv4Address::from_string(h2, ntohs(addr->sin_port));
        // JS server.js:509-511: rounds arriving on the punch socket feed the
        // sampler — wire `to` = our external address as the sender observed it.
        nat_sampler_.add(req.to.addr, from);
        auto cb = on_request_;   // copy — handler may reset during dispatch
        cb(req, from);
        return;
    }
```

And `PoolSocket::reply` (mirror `send_probe`'s SendCtx pattern, holepunch.cpp:1104-1120, but with the encoded buffer):

```cpp
void PoolSocket::reply(const messages::Response& resp) {
    if (closing_) return;
    auto buf = messages::encode_response(resp);
    struct SendCtx { udx_socket_send_t req{}; std::vector<uint8_t> buf; };
    auto* ctx = new SendCtx;
    ctx->buf = std::move(buf);
    ctx->req.data = ctx;
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                  static_cast<unsigned int>(ctx->buf.size()));
    struct sockaddr_in dest{};
    uv_ip4_addr(resp.from.addr.host_string().c_str(), resp.from.addr.port, &dest);
    udx_socket_send(&ctx->req, socket_, &uv_buf, 1,
                    reinterpret_cast<const struct sockaddr*>(&dest),
                    [](udx_socket_send_t* r, int) {
                        delete static_cast<SendCtx*>(r->data);
                    });
}
```

Add `OnRequestCallback on_request_;` to the private members. Clear it in `close()` (next to `on_probe_` — check how close handles callbacks; mirror).

- [ ] **Step 4: Green** — both tests + full `test_holepunch` (PoolSocket regressions).

- [ ] **Step 5: Commit** — `git commit -m "feat: PoolSocket accepts inbound requests and sends replies"`

---

### Task 3: Handshake reply via an arbitrary socket (router plumbing)

**Files:**
- Modify: `include/hyperdht/router.hpp:103-111` (server-entry handshake callback types)
- Modify: `src/router.cpp:212-320` (`handle_peer_handshake` server branch)
- Modify: `src/rpc_handlers.cpp:158-183` (RelayFn honors the socket)
- Modify: `include/hyperdht/server.hpp` + `src/server.cpp:191-199,421-470,642-651` (handler signature: reply_fn gains socket, handler gains `from_address`)
- Test: `test/test_router.cpp` (or wherever `handle_peer_handshake` is tested — grep first)

**Interfaces:**
- Produces (Task 4 consumes): the server's `on_peer_handshake` entry becomes

```cpp
// Router::HandlerEntry
std::function<void(const std::vector<uint8_t>& noise,
                   const compact::Ipv4Address& client_addr,
                   const compact::Ipv4Address& from_addr,   // NEW: relay/UDP source
                   HandshakeReplyFn reply_fn)> on_peer_handshake;
// NEW type: bytes + optional egress socket (nullptr = today's main-socket path)
using HandshakeReplyFn =
    std::function<void(std::vector<uint8_t> reply_noise, udx_socket_t* via)>;
```

and `rpc_handlers.cpp`'s RelayFn becomes `std::function<void(const messages::Request&, udx_socket_t*)>` calling `socket_.udp_send_on(buf, req.to.addr, via ? via : socket_.active_socket())` — add a thin `RpcSocket::udp_send_via(buf, to, udx_socket_t*)` public wrapper if `udp_send_on` is private (check rpc.hpp; it is declared at rpc.hpp:263-264 — public, reuse directly).

- [ ] **Step 1: Failing test** — drive `Router::handle_peer_handshake` with a FROM_RELAY request whose registered server entry replies with a non-null `via`; assert the RelayFn lambda received that socket pointer:

```cpp
TEST(RouterHandshake, ServerReplyPropagatesEgressSocket) {
    udx_socket_t fake_socket{};   // never sent through — pointer identity only
    udx_socket_t* seen = reinterpret_cast<udx_socket_t*>(0x1);
    Router router;
    Router::HandlerEntry entry;
    entry.on_peer_handshake = [&](const std::vector<uint8_t>&,
                                  const compact::Ipv4Address&,
                                  const compact::Ipv4Address&,
                                  Router::HandshakeReplyFn reply) {
        reply({0xAA}, &fake_socket);
    };
    router.set(target, std::move(entry));   // use the existing registration API — grep Router::set
    router.handle_peer_handshake(make_from_relay_request(target),
        /*reply=*/[](const messages::Response&) { FAIL() << "FROM_RELAY must use relay fn"; },
        /*relay=*/[&](const messages::Request&, udx_socket_t* via) { seen = via; },
        /*closer=*/[](const announce::TargetKey&) { return std::vector<routing::NodeInfo>{}; });
    EXPECT_EQ(seen, &fake_socket);
}
```

(Adapt registration + request-builder helpers from the existing router tests — read them first. The FROM_RELAY builder exists for the current tests.)

- [ ] **Step 2: Red** — compile failure (signature) = red.

- [ ] **Step 3: Implement** — thread `via` through router.cpp's reply lambda (the captured `reply`/`relay` calls at router.cpp:284/316 pass it), change RelayFn signature at rpc_handlers.cpp:166-169 to `[this](const messages::Request& req, udx_socket_t* via) { auto buf = messages::encode_request(req); socket_.udp_send_on(buf, req.to.addr, via ? via : socket_.active_socket()); }`. Update ALL call sites: `handle_peer_handshake`'s pure-relay path passes `nullptr`, `handle_peer_holepunch`'s RelayFn likewise (grep every `relay(` in router.cpp). Server side: `Server::on_peer_handshake` signature gains `from_address` + new reply type; the dedup resend (server.cpp:470) and async-firewall queued senders (server.cpp:642-651) store/call the new two-arg reply — for now pass `nullptr` everywhere in server.cpp (Task 4 flips it). The FROM_CLIENT direct branch keeps plain `reply(resp)` (JS: no puncher socket for direct/open — server.js:394-397).

- [ ] **Step 4: Green** — router tests + `test_server` + full suite (`ctest -E 'LiveServer|test_server_live'`). This task touches every handshake path; the suite is the regression net.

- [ ] **Step 5: Commit** — `git commit -m "refactor: handshake reply can egress via a caller-chosen socket"`

---

### Task 4: Server punch socket — creation, deferred rounds, payload source, ping/probes

**Files:**
- Modify: `include/hyperdht/server_connection.hpp` (members)
- Modify: `src/server.cpp` (handshake path ~:1100-1160; `on_peer_holepunch` :1169-1490; puncher wiring :1350-1362; fast-mode :1289)
- Test: `test/test_server_punch_socket.cpp` (new)

**Interfaces:**
- Consumes: Task 2 (`PoolSocket::on_request`/`reply`), Task 3 (`HandshakeReplyFn` with `via`), existing `discover_pool_addresses(pool, table, relay_addr, on_done)` (holepunch.hpp:231).
- Produces (Task 5 consumes): `ServerConnection::punch_socket` (`std::shared_ptr<holepunch::PoolSocket>`), and `Server::process_holepunch_round(ServerConnection& conn, const messages::Request& req, std::function<void(const messages::Response&)> respond)` — the socket-agnostic refactor of today's `on_peer_holepunch` body.

**ServerConnection additions:**

```cpp
    // Per-session punch socket (JS Holepuncher: dht._socketPool.acquire(),
    // holepuncher.js:14). Null on: EMBEDDED builds, non-firewalled servers,
    // LAN/direct sessions. Second ref taken by RawStreamCtx on adoption.
    std::shared_ptr<holepunch::PoolSocket> punch_socket;
    bool punch_sampling_done = false;
    // Rounds parked until sampling settles (JS `await p.analyze(false)`,
    // server.js:518). Drained by discover's on_done; bounded (drop past 8).
    std::vector<std::pair<messages::Request, compact::Ipv4Address>> parked_rounds;
```

- [ ] **Step 1: Failing tests** (new file; harness reuses the `test_server.cpp` fixture — real Server on a real loop, plain udx sender socket):

```cpp
// (a) Firewalled handshake creates a punch socket and replies FROM it.
TEST_F(ServerPunchSocket, HandshakeReplyEgressesFromPunchSocket) {
    auto reply_pkt = do_relayed_handshake();          // FROM_RELAY, like existing tests
    auto& conn = server_connection(last_hp_id());
    ASSERT_TRUE(conn.punch_socket);
    EXPECT_NE(udp_source_port(reply_pkt), server_main_port());
    EXPECT_EQ(udp_source_port(reply_pkt), local_port_of(conn.punch_socket));
}

// (b) A round arriving before sampling settles is parked, then answered
//     after on_done — and the answer carries the POOL sampler's state.
TEST_F(ServerPunchSocket, RoundDeferredUntilPoolSamplingSettles) {
    auto& conn = do_relayed_handshake_and_get_conn();
    send_round1_to(conn.punch_socket);                // encoded PEER_HOLEPUNCH FROM_RELAY
    pump_loop_ms(50);
    EXPECT_FALSE(round_reply_received());             // parked
    complete_pool_sampling(conn);                     // drive discover's on_done
    run_loop_until([&] { return round_reply_received(); });
    auto payload = decrypt_round_reply();
    EXPECT_EQ(payload.firewall, conn.punch_socket->nat_sampler().firewall());
}

// (c) Fast-mode ping leaves the punch socket, not the main socket.
TEST_F(ServerPunchSocket, FastModePingEgressesFromPunchSocket) {
    auto& conn = complete_round1_with_matching_remote_address();
    EXPECT_EQ(udp_source_port(last_probe_at_client()), local_port_of(conn.punch_socket));
}

// (d) EMBEDDED / non-firewalled: no punch socket, old path intact.
TEST_F(ServerPunchSocket, NonFirewalledServerCreatesNoPunchSocket) {
    make_server_non_firewalled();
    auto& conn = do_direct_handshake_and_get_conn();
    EXPECT_FALSE(conn.punch_socket);
}
```

(The encode/decrypt helpers all exist in today's server tests — `SecurePayload`, round encoding via `holepunch::encode_holepunch_msg`. `complete_pool_sampling` = send fake PING responses to the pool socket for the discover tids, or expose a test hook `Server::finish_punch_sampling_for_test(hp_id)` — prefer the fake-responses route, it exercises the real path; the discover pings leave the pool socket toward routing-table nodes seeded by the fixture.)

- [ ] **Step 2: Red** — members don't exist; compile red, then assert red for (b)/(c).

- [ ] **Step 3: Implement**, in this order:
  1. **Creation** in the handshake path (where `connections_[hp_id]` is finalized, near server.cpp:1114), gated `#ifndef HYPERDHT_EMBEDDED` and on the firewalled/relayed branch (the same condition that today selects `FIREWALL_UNKNOWN` + holepunch info in the reply — grep `holepunch` info build in the reply construction):

```cpp
#ifndef HYPERDHT_EMBEDDED
    if (!has_remote_address) {   // firewalled ⇒ punching possible (JS server.js:430)
        conn.punch_socket = std::make_shared<holepunch::PoolSocket>(
            socket_.loop(), socket_.udx_handle(), &socket_);
        if (conn.punch_socket->bind() == 0) {
            auto weak = std::weak_ptr<bool>(alive_);
            uint32_t id = hp_id;
            holepunch::discover_pool_addresses(
                *conn.punch_socket, socket_.routing_table(), from_address,
                [this, weak, id](bool) {
                    if (auto a = weak.lock(); !a || !*a) return;
                    on_punch_sampling_done(id);
                });
        } else {
            conn.punch_socket.reset();   // bind failed → fall back to main-socket path
        }
    }
#endif
```

     (`socket_.routing_table()` — verify the accessor name in rpc.hpp; grep `routing_table\(\)`. `from_address` = the relay, now available per Task 3.)
  2. **Reply via pool**: the handshake `reply_fn(bytes, conn.punch_socket ? conn.punch_socket->socket_handle() : nullptr)`; same for the dedup resend (server.cpp:470) and async-firewall queued senders (:651) — both must look up the connection's punch socket at send time.
  3. **Round intake**: `conn.punch_socket->on_request(...)` → decode `PEER_HOLEPUNCH` value → if `hp_msg.id` mismatch or command mismatch, drop; else if `!conn.punch_sampling_done` → park (bound 8, drop-oldest); else `process_holepunch_round(conn, req, respond)` where `respond` wraps `punch_socket->reply`. `on_punch_sampling_done(id)` sets the flag and drains `parked_rounds` in order.
  4. **Refactor** today's `on_peer_holepunch` body (:1169-1490) into `process_holepunch_round(conn, req, respond)`: identical logic with three substitutions — sampler = `conn.punch_socket ? conn.punch_socket->nat_sampler() : socket_.nat_sampler()` (one local reference used everywhere: add/freeze/firewall/addresses — this removes the "analyze is a no-op" special-casing comment at :1192, now genuinely settled by the deferral); fast-mode ping (:1289) and puncher `set_send_fn` (:1355-57) send via `conn.punch_socket ? conn.punch_socket->send_probe(addr) : socket_.send_probe(addr)`. The old Router-driven `on_peer_holepunch` entry becomes a thin wrapper that builds `respond` from its `reply_fn` and calls `process_holepunch_round` — old clients / main-socket arrivals keep working.
  5. **Token gate note**: `is_relay(from)` (announcer gate) now sees the relay's source address as observed by the POOL socket. Same host, and the lenient multi-generation gate matches by address — add `DHT_LOG` on gate miss including which socket the round arrived on (the one-glance field check).
- [ ] **Step 4: Green** — new file + `test_server` + full suite + **ASAN `test_server_punch_socket` + `test_server`** (compare failures against pristine per the 137-known rule).
- [ ] **Step 5: Commit** — `git commit -m "feat: server holepunch sessions ride a per-session punch socket (JS parity)"`

---

### Task 5: Probe echo, adoption, and socket lifetime across the stream handover

**Files:**
- Modify: `src/server.cpp` (echo wiring at punch-socket creation; `RawStreamCtx` + adoption path ~:113-180, :348+; `clear_session`)
- Test: `test/test_server_punch_socket.cpp` (extend)

**Interfaces:**
- Consumes: Task 4's `conn.punch_socket`.
- Produces: `RawStreamCtx` gains `std::shared_ptr<holepunch::PoolSocket> punch_socket_ref;` (set at adoption, freed at stream finalize).

- [ ] **Step 1: Failing tests**:

```cpp
// (a) Non-initiator echo: a 1-byte probe hitting the punch socket is echoed
//     back from the SAME socket (holepuncher.js:123-127).
TEST_F(ServerPunchSocket, ProbeToPunchSocketIsEchoedFromIt) {
    auto& conn = do_relayed_handshake_and_get_conn();
    send_probe_to(local_port_of(conn.punch_socket));
    run_loop_until([&] { return client_received_probe(); });
    EXPECT_EQ(udp_source_port(last_client_probe()), local_port_of(conn.punch_socket));
}

// (b) Adoption via the punch socket: a UDX SYN for the pre-created raw
//     stream id arriving on the punch socket emits a connection whose
//     udx_socket is the punch socket.
TEST_F(ServerPunchSocket, StreamAdoptionUsesPunchSocket) {
    auto& conn = complete_rounds_to_punching();
    connect_client_udx_stream_to(local_port_of(conn.punch_socket), conn.local_udx_id);
    run_loop_until([&] { return connection_emitted(); });
    EXPECT_EQ(emitted_info().udx_socket, conn.punch_socket->socket_handle());
}

// (c) Lifetime: session GC after successful adoption must NOT close the
//     socket under the live stream; stream finalize frees it. Failed punch:
//     clear_session closes it. ASAN is the real assert here.
TEST_F(ServerPunchSocket, SessionClearKeepsAdoptedSocketAliveUntilStreamCloses) {
    auto& conn = adopt_stream();
    auto weak = std::weak_ptr<holepunch::PoolSocket>(conn.punch_socket);
    clear_session(last_hp_id());
    EXPECT_FALSE(weak.expired());          // stream ctx still holds it
    close_client_stream_and_drain();
    EXPECT_TRUE(weak.expired());
}
TEST_F(ServerPunchSocket, FailedPunchSessionClearClosesPunchSocket) {
    auto& conn = do_relayed_handshake_and_get_conn();
    auto weak = std::weak_ptr<holepunch::PoolSocket>(conn.punch_socket);
    clear_session(last_hp_id());
    drain_loop();
    EXPECT_TRUE(weak.expired());
}
```

- [ ] **Step 2: Red** — (a)/(b) fail (no echo wired, `udx_socket` is main); (c) red via `weak.expired()` behavior.
- [ ] **Step 3: Implement** — at punch-socket creation add `conn.punch_socket->on_holepunch_probe([weak_pool = std::weak_ptr(conn.punch_socket)](const compact::Ipv4Address& from) { if (auto p = weak_pool.lock()) p->send_probe(from); });` (echo, never mark connected — server is non-initiator). Adoption: in the emit path where `ConnectionInfo` is filled from the firewall callback, stash `conn.punch_socket` into the stream's `RawStreamCtx` (`ctx->punch_socket_ref = conn.punch_socket;`) so the finalize callback's `delete ctx` drops the last ref after the stream is done; verify `on_raw_stream_firewall` passes the arrival socket through unmodified (it already does — `ConnectionInfo.udx_socket`, server.hpp:59). `clear_session`: `conn.punch_socket.reset()` (its dtor/close is safe — PoolSocket close is uv-close-based; verify `~PoolSocket` vs explicit `close()` semantics and call `close()` first if the dtor requires it — read holepunch.cpp `PoolSocket::~PoolSocket`).
- [ ] **Step 4: Green + ASAN** — this task is the Finding-J-risk one: run `build-asan/test_server_punch_socket` and diff any leak against the pristine baseline method (worktree compare if unsure).
- [ ] **Step 5: Commit** — `git commit -m "feat: punch-socket probe echo, stream adoption, and handover-safe lifetime"`

---

### Task 6: Integration, review, docs

**Files:**
- Modify: `docs/TODO.md` (close the Q parity note item; add the v1 scope-outs), `CLAUDE.md` gotchas if warranted
- Test: everything

- [ ] **Step 1: Full suites** — release `ctest -E 'LiveServer|test_server_live'` = 100%; ASAN suite failure count == 137 baseline (no new).
- [ ] **Step 2: Live local cross-test** — `build-debug/` server + client on localhost (recipes in memory `live_test_recipes`): full connect through handshake→rounds→punch→stream echo; confirm in DHT_LOG that rounds arrived on the pool socket and the stream rode it.
- [ ] **Step 3: JS interop check** — JS client (`test/js` one-liner from live_test_recipes) → C++ server on the public DHT if network allows; otherwise defer to field validation and say so explicitly.
- [ ] **Step 4: cpp-reviewer** — full diff review; fix CRITICAL/HIGH before proceeding.
- [ ] **Step 5: docs** — TODO.md: mark the Q parity note item implemented; add "server-side `_reopen()` not ported (v1 scope-out)" and "punch-socket relay-gate observation (is_relay source addr via pool socket) — watch in field" entries. Update `docs/TODO.md` §B if cpp-reviewer confirms any deliberate divergence worth recording.
- [ ] **Step 6: Final commit** — `git commit -m "docs: record server punch-socket parity landing + v1 scope-outs"`. **Do not push** — field validation first (user's hostile network is the test bed; baseline to beat: 0/29 connects in 24h from the laptop, fast-mode-only successes).

## Risk register

| risk | mitigation |
|---|---|
| Session GC closes the socket under a live stream (Finding-J class) | Task 5 lifetime tests + ASAN gate; refcount split (conn ref vs stream-ctx ref) |
| Deferred round vs session-timer race (session GC'd while rounds parked) | park bound + `clear_session` drops `parked_rounds`; weak alive sentinel on discover callback |
| Old-client interop breakage | wire format untouched; client targets relay-observed address by design; Task 6 JS interop + field validation |
| `is_relay` gate misses when relay's source mapping toward pool differs | lenient multi-generation gate already in place; DHT_LOG on miss (one-glance field check) |
| ESP32 build break | `#ifndef HYPERDHT_EMBEDDED` gate; compile-check the embedded config in Task 6 |
| Sampling never settles (all discover pings dropped) | discover's `on_done(false)` still fires (retry-then-resolve, nat.js:63-78 parity) → rounds drain with UNKNOWN → JS-identical abort path |
