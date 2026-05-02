// PEER_HOLEPUNCH implementation — UDP NAT traversal driver.
// Runs the 4 strategies (consistent/random combinations), drives the
// 2-round PEER_HOLEPUNCH exchange over a DHT relay, fires UDP probes,
// and hands the resulting socket + remote address to the UDX stream.
//
// =========================================================================
// JS FLOW MAP — how this file maps to the JavaScript reference
// =========================================================================
//
// C++ function                        Line  JS file                   JS lines
// ──────────────────────────────────── ────  ────────────────────────  ────────
// SecurePayload::SecurePayload         95   secure-payload.js          6-11
// SecurePayload::encrypt              101   secure-payload.js         31-45
// SecurePayload::decrypt              116   secure-payload.js         13-29
// SecurePayload::token                133   secure-payload.js         47-51
// encode_holepunch_payload            148   messages.js              254-302
// decode_holepunch_payload            187   messages.js              254-302
// try_direct_connect                  231   connect.js               212-221
//
// Holepuncher class                   253   holepuncher.js            13-310
// Holepuncher::punch                  309   holepuncher.js           161-212
// Holepuncher::send_probe             374   holepuncher.js            77-79
// Holepuncher::open_session           382   holepuncher.js            81-83
// Holepuncher::on_message             391   holepuncher.js           124-146
// Holepuncher::consistent_probe       442   holepuncher.js           215-231
// Holepuncher::random_probes          475   holepuncher.js           234-244
// Holepuncher::analyze                535   holepuncher.js            85-93
// Holepuncher::destroy                559   holepuncher.js           297-310
// Holepuncher::open_birthday_sockets  607   holepuncher.js           271-276
// Holepuncher::keep_alive_random_nat  654   holepuncher.js           247-269
//
// PoolSocket class                    712   socket-pool.js           104-217
// PoolSocket::request                 806   (lightweight RPC sender; no JS equivalent —
//                                           JS uses dht.request({socket}) instead)
// discover_pool_addresses             927   nat.js                    25-79
//
// encode_holepunch_msg               1006   messages.js               58-120
// decode_holepunch_msg               1028   messages.js               58-120
//
// PunchState struct                  1065   connect.js                57-93
// holepunch_connect                  1156   connect.js  205-316 (holepunch fn)
//                                                       555-629 (probeRound)
//                                                       631-711 (roundPunch)
//   ├─ discover_pool_addresses       1228   nat.js                    25-79
//   ├─ Round 1 (probe exchange)      1257   connect.js               557-629
//   │  ├─ fast-open probe            1369   connect.js               557
//   │  ├─ post-Round1 probe          1403   connect.js               582-591
//   │  └─ analyze delay              1406   connect.js               607-614
//   └─ Round 2 (punch exchange)      1432   connect.js               631-711
//      ├─ NAT freeze                 1438   connect.js               634
//      ├─ send punching=true         1472   connect.js               687-699
//      └─ puncher->punch()           1542   connect.js               705
//
// local_addresses                    1579   holepuncher.js           337-354
// match_address                      1613   holepuncher.js           356-386
// =========================================================================

#include "hyperdht/holepunch.hpp"

#include "hyperdht/async_utils.hpp"
#include "hyperdht/debug.hpp"
#include "hyperdht/dht_messages.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>

namespace hyperdht {
namespace holepunch {

using compact::State;
using compact::Uint;
using compact::Buffer;
using compact::Fixed32;
using compact::Ipv4Addr;
using compact::Ipv4Address;
using compact::Array;

// ---------------------------------------------------------------------------
// SecurePayload — XSalsa20-Poly1305 envelope for the holepunch payload,
// keyed by `holepunchSecret = BLAKE2b(NS_PEER_HOLEPUNCH, handshake_hash)`.
//
// JS: .analysis/js/hyperdht/lib/secure-payload.js:5-52 (HolepunchPayload)
//
// C++ diffs from JS:
//   - JS uses crypto_secretbox_open_easy with subarrays into a single
//     buffer (secure-payload.js:13-29). We allocate a fresh plaintext
//     vector to keep ownership obvious.
//   - The `token` helper hashes the host string with BLAKE2b keyed by
//     a per-instance random secret — same as JS (secure-payload.js:47-51).
// ---------------------------------------------------------------------------

SecurePayload::SecurePayload(const std::array<uint8_t, 32>& key)
    : shared_secret_(key) {
    // Generate a random local secret for token generation
    randombytes_buf(local_secret_.data(), 32);
}

SecurePayload::~SecurePayload() {
    // H28: zero secrets on destruction
    sodium_memzero(shared_secret_.data(), 32);
    sodium_memzero(local_secret_.data(), 32);
}

std::vector<uint8_t> SecurePayload::encrypt(const uint8_t* data, size_t len) {
    // Output: nonce(24) + ciphertext(len + 16)
    std::vector<uint8_t> out(24 + len + crypto_secretbox_MACBYTES);

    // Random nonce
    randombytes_buf(out.data(), 24);

    // Encrypt: crypto_secretbox_easy(cipher, msg, msg_len, nonce, key)
    crypto_secretbox_easy(out.data() + 24,
                          data, len,
                          out.data(),  // nonce
                          shared_secret_.data());
    return out;
}

std::optional<std::vector<uint8_t>> SecurePayload::decrypt(const uint8_t* data, size_t len) {
    if (len < 24 + crypto_secretbox_MACBYTES) return std::nullopt;

    const uint8_t* nonce = data;
    const uint8_t* ciphertext = data + 24;
    size_t ct_len = len - 24;

    std::vector<uint8_t> plaintext(ct_len - crypto_secretbox_MACBYTES);

    int rc = crypto_secretbox_open_easy(plaintext.data(),
                                         ciphertext, ct_len,
                                         nonce,
                                         shared_secret_.data());
    if (rc != 0) return std::nullopt;
    return plaintext;
}

std::array<uint8_t, 32> SecurePayload::token(const std::string& host) {
    std::array<uint8_t, 32> out{};
    crypto_generichash(out.data(), 32,
                       reinterpret_cast<const uint8_t*>(host.data()), host.size(),
                       local_secret_.data(), 32);
    return out;
}

// ---------------------------------------------------------------------------
// HolepunchPayload encoding — the encrypted payload exchanged inside
// PEER_HOLEPUNCH messages (firewall, addresses, tokens, punching state).
//
// JS: .analysis/js/hyperdht/lib/messages.js:254-302 (holepunchPayload codec)
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_holepunch_payload(const HolepunchPayload& p) {
    uint32_t flags = 0;
    if (p.connected) flags |= 1;
    if (p.punching) flags |= 2;
    if (!p.addresses.empty()) flags |= 4;
    if (p.remote_address.has_value()) flags |= 8;
    if (p.token.has_value()) flags |= 16;
    if (p.remote_token.has_value()) flags |= 32;

    State state;
    Uint::preencode(state, flags);
    Uint::preencode(state, p.error);
    Uint::preencode(state, p.firewall);
    Uint::preencode(state, p.round);
    if (!p.addresses.empty()) {
        Array<Ipv4Addr, Ipv4Address>::preencode(state, p.addresses);
    }
    if (p.remote_address.has_value()) Ipv4Addr::preencode(state, *p.remote_address);
    if (p.token.has_value()) Fixed32::preencode(state, *p.token);
    if (p.remote_token.has_value()) Fixed32::preencode(state, *p.remote_token);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, flags);
    Uint::encode(state, p.error);
    Uint::encode(state, p.firewall);
    Uint::encode(state, p.round);
    if (!p.addresses.empty()) {
        Array<Ipv4Addr, Ipv4Address>::encode(state, p.addresses);
    }
    if (p.remote_address.has_value()) Ipv4Addr::encode(state, *p.remote_address);
    if (p.token.has_value()) Fixed32::encode(state, *p.token);
    if (p.remote_token.has_value()) Fixed32::encode(state, *p.remote_token);

    return buf;
}

HolepunchPayload decode_holepunch_payload(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    HolepunchPayload p;

    uint32_t flags = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;

    p.connected = (flags & 1) != 0;
    p.punching = (flags & 2) != 0;
    p.error = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;
    p.firewall = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;
    if (p.firewall > 3) { state.error = true; return p; }  // M7: validate range
    p.round = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;

    if (flags & 4) {
        p.addresses = Array<Ipv4Addr, Ipv4Address>::decode(state);
        if (state.error) return p;
    }
    if (flags & 8) {
        p.remote_address = Ipv4Addr::decode(state);
        if (state.error) return p;
    }
    if (flags & 16) {
        p.token = Fixed32::decode(state);
        if (state.error) return p;
    }
    if (flags & 32) {
        p.remote_token = Fixed32::decode(state);
        if (state.error) return p;
    }

    return p;
}

// ---------------------------------------------------------------------------
// OPEN firewall shortcut — if the server says it's OPEN, skip holepunching
// and use the first advertised address directly.
//
// JS: .analysis/js/hyperdht/lib/connect.js:212-221 (FIREWALL.OPEN branch
//     inside holepunch())
// ---------------------------------------------------------------------------

bool try_direct_connect(const peer_connect::HandshakeResult& hs,
                        HolepunchResult& result) {
    if (!hs.success) return false;

    // If remote firewall is OPEN, we can connect directly
    if (hs.remote_payload.firewall == peer_connect::FIREWALL_OPEN) {
        if (!hs.remote_payload.addresses4.empty()) {
            result.success = true;
            result.address = hs.remote_payload.addresses4[0];
            result.firewall = peer_connect::FIREWALL_OPEN;
            return true;
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// Holepuncher — drives the UDP probe loop once the relay-side handshake
// has agreed on firewalls and addresses. Picks one of four strategies
// based on the (local, remote) firewall combination.
//
// JS: .analysis/js/hyperdht/lib/holepuncher.js:12-323 (Holepuncher class)
//
// C++ diffs from JS:
//   - JS owns its socket via `dht._socketPool.acquire()` inside the
//     constructor (holepuncher.js:14). C++ takes the socket pool by
//     pointer and lets the caller (holepunch_connect) supply probe
//     send functions, so the puncher itself is socket-agnostic.
//   - JS coalesces OPEN into CONSISTENT (holepuncher.js:333-335). C++
//     does the same by treating any non-RANDOM firewall as consistent.
//   - All async sleeps in JS (`_sleeper.pause`) become uv_timer reschedules.
// ---------------------------------------------------------------------------

Holepuncher::Holepuncher(uv_loop_t* loop, bool is_initiator,
                         socket_pool::SocketPool* pool,
                         PunchStats* stats)
    : loop_(loop), is_initiator_(is_initiator), pool_(pool), stats_(stats) {
    punch_timer_ = new uv_timer_t;
    uv_timer_init(loop, punch_timer_);
    punch_timer_->data = this;
}

Holepuncher::~Holepuncher() {
    // M10: clear callbacks on all holders to prevent lingering SocketRefs
    // from calling back into destroyed Holepuncher during pool linger period
    for (auto* h : holders_) {
        h->on_holepunch_message = nullptr;
    }
    stop();
    if (punch_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        // Timer outlives us — null the back-pointer so callbacks don't dereference
        punch_timer_->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(punch_timer_),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        punch_timer_ = nullptr;
    }
}

void Holepuncher::close(std::function<void()> on_closed) {
    stop();
    closing_ = true;
    if (!punch_timer_ || uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        if (on_closed) on_closed();
        return;
    }

    struct CloseCtx { std::function<void()> cb; };
    auto* ctx = new CloseCtx{std::move(on_closed)};
    punch_timer_->data = ctx;

    uv_close(reinterpret_cast<uv_handle_t*>(punch_timer_), [](uv_handle_t* h) {
        auto* ctx = static_cast<CloseCtx*>(reinterpret_cast<uv_timer_t*>(h)->data);
        if (ctx) {
            if (ctx->cb) ctx->cb();
            delete ctx;
        }
        delete reinterpret_cast<uv_timer_t*>(h);
    });
    punch_timer_ = nullptr;
}

// JS: holepuncher.js:161-212 (_punch — picks strategy from firewall combo)
bool Holepuncher::punch() {
    using namespace peer_connect;

    if (connected_) return true;

    // Determine strategy based on firewall combo.
    // Treat UNKNOWN as CONSISTENT — we don't know our NAT type yet, but
    // the standard 10-round probe is the safest default.
    bool local_consistent = (local_firewall_ != FIREWALL_RANDOM);
    bool remote_consistent = (remote_firewall_ != FIREWALL_RANDOM);

    if (local_consistent && remote_consistent) {
        // CONSISTENT+CONSISTENT or OPEN+CONSISTENT: 10 rounds, 1s apart
        if (stats_) stats_->punches_consistent++;
        punching_ = true;
        punch_round_ = 0;
        consistent_probe();
        return true;
    }

    if (local_consistent && remote_firewall_ == FIREWALL_RANDOM) {
        // CONSISTENT+RANDOM: 1750 probes to random ports
        // JS: roundPunch rate-limits random punches
        if (stats_ && !stats_->can_random_punch(uv_now(loop_))) {
            DHT_LOG("  [hp] Random punch throttled (active=%d, limit=%d)\n",
                    stats_->random_punches, stats_->random_punch_limit);
            return false;
        }
        if (stats_) stats_->punches_random++;
        increment_randomized();
        punching_ = true;
        random_probes_left_ = RANDOM_PROBES_COUNT;
        random_probes();
        return true;
    }

    if (local_firewall_ == FIREWALL_RANDOM && remote_consistent) {
        // RANDOM+CONSISTENT: birthday paradox — acquire up to 256 sockets
        auto* vr = verified_remote();
        if (!vr || !pool_) return false;

        // JS: roundPunch rate-limits random punches
        if (stats_ && !stats_->can_random_punch(uv_now(loop_))) {
            DHT_LOG("  [hp] Random punch throttled (active=%d, limit=%d)\n",
                    stats_->random_punches, stats_->random_punch_limit);
            return false;
        }
        if (stats_) stats_->punches_random++;
        increment_randomized();
        punching_ = true;
        open_birthday_sockets();
        return true;
    }

    // RANDOM+RANDOM: impossible
    return false;
}

void Holepuncher::stop() {
    punching_ = false;
    if (punch_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        uv_timer_stop(punch_timer_);
    }
}

void Holepuncher::send_probe(const compact::Ipv4Address& addr) {
    if (send_fn_) {
        DHT_LOG("  [hp] Sending probe to %s:%u\n",
                addr.host_string().c_str(), addr.port);
        send_fn_(addr);
    }
}

void Holepuncher::open_session(const compact::Ipv4Address& addr) {
    if (send_ttl_fn_) {
        DHT_LOG("  [hp] openSession (TTL=5) to %s:%u\n",
                addr.host_string().c_str(), addr.port);
        send_ttl_fn_(addr, 5);  // HOLEPUNCH_TTL = 5
    }
}

// JS: holepuncher.js:124-146 (_onholepunchmessage)
void Holepuncher::on_message(const compact::Ipv4Address& from,
                             udx_socket_t* recv_socket,
                             socket_pool::SocketRef* ref) {
    DHT_LOG("  [hp] PROBE RECEIVED from %s:%u!\n",
            from.host_string().c_str(), from.port);
    if (connected_ || destroyed_) return;

    // JS: non-initiator echoes probe back, does NOT set connected (holepuncher.js:125-128)
    if (!is_initiator_) {
        send_probe(from);
        return;
    }

    // Initiator: probe echo received → connection established
    connected_ = true;
    punching_ = false;
    if (punch_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        uv_timer_stop(punch_timer_);
    }

    // Release all holders except the winning one (JS: holepuncher.js:135-140)
    if (ref && !holders_.empty()) {
        for (auto* h : holders_) {
            if (h != ref) h->release();
        }
        holders_.clear();
        holders_.push_back(ref);
    }

    decrement_randomized();

    auto cb = std::move(on_connect_);
    if (cb) {
        HolepunchResult result;
        result.success = true;
        result.address = from;
        result.firewall = remote_firewall_;
        result.socket = recv_socket;  // JS: onconnect(ref.socket, port, host)
        cb(result);
    }
}

// ---------------------------------------------------------------------------
// CONSISTENT+CONSISTENT: 10 rounds, 1s apart.
//
// JS: .analysis/js/hyperdht/lib/holepuncher.js:215-231 (_consistentProbe)
//
// C++ diffs: JS uses an async while-loop with await sleeper.pause(1000);
// we re-schedule the same function via uv_timer_start to drive each round.
// ---------------------------------------------------------------------------

void Holepuncher::consistent_probe() {
    if (!punching_ || connected_ || punch_round_ >= 10) {
        if (punching_ && !connected_) {
            punching_ = false;
        }
        return;
    }

    // JS: non-initiator waits 1s before first round (holepuncher.js:217)
    // Gives initiator's openSession time to prime NAT
    if (!is_initiator_ && punch_round_ == 0) {
        punch_round_++;
        uv_timer_start(punch_timer_, on_punch_timer, 1000, 0);
        return;
    }

    // Send probes, filtering unverified addrs (JS: holepuncher.js:224)
    for (const auto& ra : remote_addresses_) {
        if (!ra.verified && (punch_round_ & 3) != 0) continue;
        if (ra.addr.port == 0) continue;
        send_probe(ra.addr);
    }

    punch_round_++;
    uv_timer_start(punch_timer_, on_punch_timer, 1000, 0);
}

// ---------------------------------------------------------------------------
// CONSISTENT+RANDOM: 1750 probes to random ports, 20ms apart.
//
// JS: .analysis/js/hyperdht/lib/holepuncher.js:234-244 (_randomProbes)
// ---------------------------------------------------------------------------

void Holepuncher::random_probes() {
    if (!punching_ || connected_) return;
    if (random_probes_left_ <= 0) {
        punching_ = false;  // Exhausted — stop, don't fall through to consistent_probe
        return;
    }

    // Send probe to a random port on the remote host
    if (!remote_addresses_.empty()) {
        auto addr = remote_addresses_[0].addr;
        // Random port between 1000-65535
        uint16_t random_port = static_cast<uint16_t>(1000 + randombytes_uniform(64536));
        auto probe_addr = Ipv4Address::from_string(addr.host_string(), random_port);
        send_probe(probe_addr);
    }

    random_probes_left_--;

    // Schedule next probe in 20ms
    uv_timer_start(punch_timer_, on_punch_timer, 20, 0);
}

// ---------------------------------------------------------------------------
// NAT stability analysis (JS: analyze, _unstable, _reopen)
//
// JS: .analysis/js/hyperdht/lib/holepuncher.js:85-93 (analyze)
//     .analysis/js/hyperdht/lib/holepuncher.js:95-102 (_unstable)
//     .analysis/js/hyperdht/lib/holepuncher.js:152-160 (_reopen)
// ---------------------------------------------------------------------------

bool Holepuncher::is_unstable() const {
    // JS: _unstable() — holepuncher.js:88-93
    // Returns true if:
    //   - Both local AND remote are RANDOM
    //   - Local firewall is UNKNOWN
    using namespace peer_connect;
    if (remote_firewall_ >= FIREWALL_RANDOM && local_firewall_ >= FIREWALL_RANDOM)
        return true;
    if (local_firewall_ == FIREWALL_UNKNOWN)
        return true;
    return false;
}

void Holepuncher::increment_randomized() {
    if (!randomized_) {
        randomized_ = true;
        if (stats_) stats_->random_punches++;
    }
}

void Holepuncher::decrement_randomized() {
    if (randomized_) {
        randomized_ = false;
        if (stats_) {
            stats_->last_random_punch = uv_now(loop_);
            stats_->random_punches--;
        }
    }
}

void Holepuncher::analyze(bool allow_reopen, OnAnalyzeDone on_done) {
    // JS: analyze(allowReopen) — holepuncher.js:62-72
    // Checks NAT stability. If unstable and allowed to reopen,
    // calls on_reset_ so the caller can destroy NAT sampler,
    // acquire a fresh socket, re-sample, and call analyze() again.

    if (is_unstable()) {
        if (!allow_reopen || reopen_count_ >= MAX_REOPENS || is_done() || punching_) {
            if (on_done) on_done(false);
            return;
        }
        reopen_count_++;
        // Signal caller to reset and retry (JS: _reopen → _reset)
        if (on_reset_) {
            on_reset_();
        }
        if (on_done) on_done(false);
        return;
    }

    // Stable — good to proceed
    if (on_done) on_done(true);
}

void Holepuncher::destroy() {
    if (destroyed_) return;
    destroyed_ = true;
    punching_ = false;

    // Clear holepunch callbacks on holders before releasing — prevents
    // lingering SocketRef from calling back into destroyed Holepuncher
    for (auto* h : holders_) {
        h->on_holepunch_message = nullptr;
        h->release();
    }
    holders_.clear();

    // Stop timer
    if (punch_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        uv_timer_stop(punch_timer_);
    }

    // Fire abort if not connected (JS: holepuncher.js:185-188)
    // NOTE: on_abort_ must not delete this Holepuncher synchronously.
    // The caller should use shared_ptr or deferred cleanup.
    if (!connected_) {
        decrement_randomized();
        auto cb = std::move(on_abort_);
        if (cb) cb();
    }

    // Break circular refs AFTER abort fires: these closures capture
    // PunchState shared_ptr, and PunchState owns us → cycle.
    send_fn_ = nullptr;
    send_ttl_fn_ = nullptr;
    on_connect_ = nullptr;
    on_abort_ = nullptr;
}

// ---------------------------------------------------------------------------
// RANDOM+CONSISTENT: Birthday paradox — open up to 256 sockets so one of
// our random source ports collides with the remote's expected mapping.
//
// JS: .analysis/js/hyperdht/lib/holepuncher.js:271-276 (_openBirthdaySockets)
//     .analysis/js/hyperdht/lib/holepuncher.js:247-269 (_keepAliveRandomNat)
//
// C++ diffs: JS bursts all 256 acquisitions in a single while-loop and
// awaits each `holepunch(...)` send. C++ acquires one socket per timer
// tick to avoid blocking the loop, then enters the cycling phase via
// `keep_alive_random_nat`.
// ---------------------------------------------------------------------------

void Holepuncher::open_birthday_sockets() {
    if (!punching_ || is_done() || !pool_) return;

    auto* vr = verified_remote();
    if (!vr) {
        punching_ = false;
        return;
    }

    // Acquire one socket per timer tick to avoid blocking the loop
    if (holders_.size() < static_cast<size_t>(BIRTHDAY_SOCKETS)) {
        auto* ref = pool_->acquire();
        if (ref) {
            // Attach holepunch message handler to this socket
            ref->on_holepunch_message =
                [this](const uint8_t*, size_t, const compact::Ipv4Address& from,
                       socket_pool::SocketRef* r) {
                    on_message(from, r->socket(), r);
                };
            holders_.push_back(ref);

            // Send low-TTL probe from this new socket (JS: holepuncher.js:273-275)
            if (send_ttl_fn_) {
                send_ttl_fn_(vr->addr, HOLEPUNCH_TTL);
            }
        }
    }

    if (holders_.size() < static_cast<size_t>(BIRTHDAY_SOCKETS)) {
        // More sockets to acquire — schedule next tick
        uv_timer_start(punch_timer_, on_punch_timer, 0, 0);
    } else {
        // All sockets acquired — start keepAliveRandomNat cycling
        birthday_index_ = 0;
        low_ttl_rounds_ = 1;
        random_probes_left_ = RANDOM_PROBES_COUNT;
        // Small delay before cycling (JS: await _sleeper.pause(100))
        uv_timer_start(punch_timer_, on_punch_timer, 100, 0);
    }
}

// ---------------------------------------------------------------------------
// RANDOM+CONSISTENT: Cycle through birthday sockets sending probes.
//
// JS: .analysis/js/hyperdht/lib/holepuncher.js:247-269 (_keepAliveRandomNat)
// ---------------------------------------------------------------------------

void Holepuncher::keep_alive_random_nat() {
    if (!punching_ || is_done()) return;
    if (random_probes_left_ <= 0) {
        punching_ = false;
        if (!connected_) destroy();
        return;
    }

    auto* vr = verified_remote();
    if (!vr || holders_.empty()) {
        punching_ = false;
        return;
    }

    // Cycle through sockets (JS: holepuncher.js:254-266)
    if (birthday_index_ >= holders_.size()) {
        birthday_index_ = 0;
        if (low_ttl_rounds_ > 0) low_ttl_rounds_--;
    }

    // Send probe from current birthday socket
    auto* ref = holders_[birthday_index_++];
    if (ref && !ref->is_closed()) {
        if (send_ttl_fn_) {
            // JS: first full cycle uses low TTL, subsequent use default
            int ttl = (low_ttl_rounds_ > 0) ? HOLEPUNCH_TTL : DEFAULT_TTL;
            send_ttl_fn_(vr->addr, ttl);
        }
    }

    random_probes_left_--;
    uv_timer_start(punch_timer_, on_punch_timer, RANDOM_PROBE_INTERVAL_MS, 0);
}

void Holepuncher::on_punch_timer(uv_timer_t* timer) {
    auto* self = static_cast<Holepuncher*>(timer->data);
    if (!self || self->is_done()) return;

    // Determine which strategy phase we're in
    if (!self->holders_.empty() &&
        self->holders_.size() < static_cast<size_t>(BIRTHDAY_SOCKETS) &&
        self->local_firewall_ == peer_connect::FIREWALL_RANDOM) {
        // Still acquiring birthday sockets
        self->open_birthday_sockets();
    } else if (!self->holders_.empty() &&
               self->holders_.size() >= static_cast<size_t>(BIRTHDAY_SOCKETS)) {
        // Birthday sockets acquired — cycling keepAlive
        self->keep_alive_random_nat();
    } else if (self->random_probes_left_ > 0) {
        self->random_probes();
    } else {
        self->consistent_probe();
    }
}

// ---------------------------------------------------------------------------
// PoolSocket — lightweight UDP socket for holepunch probing.
//
// JS: .analysis/js/hyperdht/lib/socket-pool.js (SocketPool.acquire — JS
//     manages a pool of UDX sockets keyed by port and hands them out
//     via ref-counted handles). C++ has a simpler single-socket model
//     inside the puncher — the pool socket is created per holepunch_connect
//     invocation, lives for the duration of the punch, and is released
//     when PunchState is destroyed.
// ---------------------------------------------------------------------------

PoolSocket::PoolSocket(uv_loop_t* loop, udx_t* udx)
    : loop_(loop), socket_(new udx_socket_t{}) {
    udx_socket_init(udx, socket_, nullptr);
    socket_->data = this;
    next_tid_ = static_cast<uint16_t>(randombytes_uniform(0xFFFF));
}

PoolSocket::~PoolSocket() {
    if (!closing_) close();
}

int PoolSocket::bind() {
    struct sockaddr_in addr{};
    uv_ip4_addr("0.0.0.0", 0, &addr);
    int rc = udx_socket_bind(socket_, reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (rc == 0) {
        bound_ = true;
        udx_socket_recv_start(socket_, on_recv);
    }
    return rc;
}

void PoolSocket::on_recv(udx_socket_t* s, ssize_t nread,
                          const uv_buf_t* buf, const struct sockaddr* addr) {
    if (nread <= 0 || !addr) return;
    auto* self = static_cast<PoolSocket*>(s->data);
    if (!self || self->closing_) return;
    self->handle_message(reinterpret_cast<const uint8_t*>(buf->base),
                         static_cast<size_t>(nread),
                         reinterpret_cast<const struct sockaddr_in*>(addr));
}

void PoolSocket::handle_message(const uint8_t* data, size_t len,
                                 const struct sockaddr_in* addr) {
    char host[INET_ADDRSTRLEN];
    uv_ip4_name(addr, host, sizeof(host));
    DHT_LOG("  [pool] Recv %zu bytes from %s:%u (type=0x%02x)\n",
            len, host, ntohs(addr->sin_port), len > 0 ? data[0] : 0);

    // 1-byte probe → holepunch callback.
    // Copy before invoking — the handler may clear on_probe_ during execution
    // (PunchState::complete resets it to break circular refs → UB if we call
    // on_probe_ directly and it's destroyed mid-call).
    if (len == 1 && data[0] == 0x00) {
        auto cb = on_probe_;
        if (cb) {
            char host[INET_ADDRSTRLEN];
            uv_ip4_name(addr, host, sizeof(host));
            auto from = Ipv4Address::from_string(host, ntohs(addr->sin_port));
            cb(from);
        }
        return;
    }

    // Try to decode as RPC message
    if (len < 2) return;
    messages::Request req;
    messages::Response resp;
    auto type = messages::decode_message(data, len, req, resp);

    if (type == messages::RESPONSE_ID) {
        // Feed NAT sampler: resp.from.addr = wire `to` field = our external address
        char host[INET_ADDRSTRLEN];
        uv_ip4_name(addr, host, sizeof(host));
        auto remote_addr = Ipv4Address::from_string(host, ntohs(addr->sin_port));
        nat_sampler_.add(resp.from.addr, remote_addr);

        // Match TID → call response callback
        for (auto it = inflight_.begin(); it != inflight_.end(); ++it) {
            if ((*it)->tid == resp.tid) {
                auto* inf = *it;
                inflight_.erase(it);
                if (inf->timer) {
                    uv_timer_stop(inf->timer);
                    inf->timer->data = nullptr;  // Prevent timeout callback from using freed inf
                    uv_close(reinterpret_cast<uv_handle_t*>(inf->timer),
                             [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
                }
                auto cb = std::move(inf->on_response);
                delete inf;
                if (cb) cb(resp);
                return;
            }
        }
    }
}

void PoolSocket::request(const messages::Request& req,
                          rpc::OnResponseCallback on_response,
                          rpc::OnTimeoutCallback on_timeout) {
    auto* inf = new Inflight;
    inf->tid = next_tid_++;
    inf->on_response = std::move(on_response);
    inf->on_timeout = std::move(on_timeout);

    // Encode request with our TID
    messages::Request msg = req;
    msg.tid = inf->tid;
    auto buf = messages::encode_request(msg);

    // Send from pool socket
    struct SendCtx {
        udx_socket_send_t req{};
        std::vector<uint8_t> buf;
    };
    auto* ctx = new SendCtx;
    ctx->buf = std::move(buf);
    ctx->req.data = ctx;
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(ctx->buf.data()),
                                    (ctx->buf.size() <= UINT_MAX
                                        ? static_cast<unsigned int>(ctx->buf.size())
                                        : 0u));
    struct sockaddr_in dest{};
    uv_ip4_addr(req.to.addr.host_string().c_str(), req.to.addr.port, &dest);
    DHT_LOG("  [pool] Sending request (tid=%u, cmd=%u, %zu bytes) to %s:%u\n",
            inf->tid, msg.command, ctx->buf.size(),
            req.to.addr.host_string().c_str(), req.to.addr.port);
    int rc = udx_socket_send(&ctx->req, socket_, &uv_buf, 1,
                    reinterpret_cast<const struct sockaddr*>(&dest),
                    [](udx_socket_send_t* r, int status) {
                        if (status < 0) {
                            DHT_LOG("  [pool] Send failed: %d\n", status);
                        }
                        delete static_cast<SendCtx*>(r->data);
                    });
    if (rc < 0) {
        DHT_LOG("  [pool] udx_socket_send returned: %d\n", rc);
    }

    // Timeout (2s, no retries — matches JS {retry: false}).
    // The timer callback must remove the Inflight from the vector before
    // freeing it — otherwise handle_message iterates a dangling pointer.
    inf->pool = this;
    inf->timer = new uv_timer_t;
    uv_timer_init(loop_, inf->timer);
    inf->timer->data = inf;
    uv_timer_start(inf->timer, [](uv_timer_t* t) {
        auto* inf = static_cast<Inflight*>(t->data);
        // Remove from vector BEFORE freeing
        auto& vec = inf->pool->inflight_;
        vec.erase(std::remove(vec.begin(), vec.end(), inf), vec.end());
        auto timeout_cb = std::move(inf->on_timeout);
        uv_close(reinterpret_cast<uv_handle_t*>(t),
                 [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        uint16_t tid = inf->tid;
        delete inf;
        if (timeout_cb) timeout_cb(tid);
    }, 2000, 0);

    inflight_.push_back(inf);
}

void PoolSocket::send_probe(const Ipv4Address& to) {
    if (closing_) return;
    struct SendCtx {
        udx_socket_send_t req{};
        uint8_t buf = 0x00;
    };
    auto* ctx = new SendCtx;
    ctx->req.data = ctx;
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(&ctx->buf), 1);
    struct sockaddr_in dest{};
    uv_ip4_addr(to.host_string().c_str(), to.port, &dest);
    udx_socket_send(&ctx->req, socket_, &uv_buf, 1,
                    reinterpret_cast<const struct sockaddr*>(&dest),
                    [](udx_socket_send_t* r, int) {
                        delete static_cast<SendCtx*>(r->data);
                    });
}

void PoolSocket::send_probe_ttl(const Ipv4Address& to, int ttl) {
    if (closing_) return;
    struct SendCtx {
        udx_socket_send_t req{};
        uint8_t buf = 0x00;
    };
    auto* ctx = new SendCtx;
    ctx->req.data = ctx;
    uv_buf_t uv_buf = uv_buf_init(reinterpret_cast<char*>(&ctx->buf), 1);
    struct sockaddr_in dest{};
    uv_ip4_addr(to.host_string().c_str(), to.port, &dest);
    udx_socket_send_ttl(&ctx->req, socket_, &uv_buf, 1,
                        reinterpret_cast<const struct sockaddr*>(&dest), ttl,
                        [](udx_socket_send_t* r, int) {
                            delete static_cast<SendCtx*>(r->data);
                        });
}

void PoolSocket::close() {
    if (closing_) return;
    closing_ = true;
    socket_->data = nullptr;
    // Clean up inflight
    for (auto* inf : inflight_) {
        if (inf->timer && !uv_is_closing(reinterpret_cast<uv_handle_t*>(inf->timer))) {
            uv_timer_stop(inf->timer);
            inf->timer->data = nullptr;  // H6: null before delete to prevent dangling
            uv_close(reinterpret_cast<uv_handle_t*>(inf->timer),
                     [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
        }
        delete inf;
    }
    inflight_.clear();
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(socket_))) {
        // Socket is heap-allocated — free it in the close callback so it
        // survives until libuv has finished processing (QUEUE_REMOVE etc.)
        uv_close(reinterpret_cast<uv_handle_t*>(socket_),
                 [](uv_handle_t* h) { delete reinterpret_cast<udx_socket_t*>(h); });
        socket_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// discover_pool_addresses — PING DHT nodes from pool socket for NAT discovery.
//
// JS: .analysis/js/nat-sampler/index.js (Nat.autoSample, invoked from
//     Holepuncher constructor at holepuncher.js:20 — fires background PINGs
//     to populate the NatSampler before the first punch round). C++ makes
//     this explicit as a synchronous PING campaign before Round 1.
// ---------------------------------------------------------------------------

void discover_pool_addresses(
    PoolSocket& pool,
    const routing::RoutingTable& table,
    const compact::Ipv4Address& relay_addr,
    const compact::Ipv4Address& peer_addr,
    std::function<void(bool)> on_done) {

    struct DiscoverCtx {
        PoolSocket* pool;
        std::function<void(bool)> on_done;
        int pending = 0;
        bool done = false;
    };
    auto ctx = std::make_shared<DiscoverCtx>();
    ctx->pool = &pool;
    ctx->on_done = std::move(on_done);

    auto finish = [ctx]() {
        if (ctx->done) return;
        if (--ctx->pending <= 0) {
            ctx->done = true;
            bool ok = ctx->pool->nat_sampler().sampled() >= 2;
            if (ctx->on_done) ctx->on_done(ok);
        }
    };

    // Pick up to 6 DHT nodes for PING (JS: nat.autoSample with 4+ nodes).
    // Include the server's announce address so our pool socket establishes
    // a direct NAT mapping with the server's IP. This is critical for
    // NAT-to-NAT: when the server's puncher probes us later, our NAT
    // already has a pinhole for the server's IP (from the PING response).
    // JS gets this implicitly because its autoSample runs later (during
    // analyze() after findPeer), when the routing table already contains
    // the server. Our discover runs earlier, so we add it explicitly.
    std::vector<compact::Ipv4Address> targets;
    targets.push_back(relay_addr);
    targets.push_back(peer_addr);  // Server's announce address

    // Use routing table nodes if available
    auto closest = table.closest(routing::NodeId{}, 20);
    int skip = closest.size() >= 8 ? 5 : 0;
    for (size_t i = skip; i < closest.size() && targets.size() < 5; i++) {
        targets.push_back(Ipv4Address::from_string(closest[i]->host, closest[i]->port));
    }

    // Fallback: use bootstrap nodes when routing table is sparse
    if (targets.size() < 4) {
        static const char* bootstrap[] = {
            "88.99.3.86", "142.93.90.113", "138.68.147.8"  // Public HyperDHT bootstrap
        };
        for (const auto& host : bootstrap) {
            if (targets.size() >= 5) break;
            targets.push_back(Ipv4Address::from_string(host, 49737));
        }
    }

    ctx->pending = static_cast<int>(targets.size()) + 1;  // +1 for initial decrement

    for (const auto& target : targets) {
        messages::Request ping;
        ping.command = messages::CMD_PING;
        ping.internal = true;
        ping.to.addr = target;

        pool.request(ping,
            [ctx, finish](const messages::Response&) { finish(); },
            [ctx, finish](uint16_t) { finish(); });
    }

    finish();  // Decrement initial +1
}

// ---------------------------------------------------------------------------
// PEER_HOLEPUNCH message encoding — outer wrapper that sits in req.value
// for PEER_HOLEPUNCH, carrying mode + id + encrypted payload + peer addr.
//
// JS: .analysis/js/hyperdht/lib/messages.js:58-120 (exports.holepunch)
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_holepunch_msg(const HolepunchMessage& m) {
    State state;
    uint8_t flags = m.peer_address.has_value() ? 1 : 0;
    Uint::preencode(state, flags);
    Uint::preencode(state, m.mode);
    Uint::preencode(state, m.id);
    Buffer::preencode(state, m.payload.data(), m.payload.size());
    if (m.peer_address.has_value()) Ipv4Addr::preencode(state, *m.peer_address);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, flags);
    Uint::encode(state, m.mode);
    Uint::encode(state, m.id);
    Buffer::encode(state, m.payload.data(), m.payload.size());
    if (m.peer_address.has_value()) Ipv4Addr::encode(state, *m.peer_address);

    return buf;
}

HolepunchMessage decode_holepunch_msg(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    HolepunchMessage m;

    uint64_t flags_raw = Uint::decode(state);                             // M6
    if (state.error || flags_raw > 0xFF) { state.error = true; return m; }
    uint8_t flags = static_cast<uint8_t>(flags_raw);

    uint64_t mode_raw = Uint::decode(state);                             // M6
    if (state.error || mode_raw > 0xFF) { state.error = true; return m; }
    m.mode = static_cast<uint32_t>(mode_raw);

    uint64_t id_raw = Uint::decode(state);                               // M6
    if (state.error || id_raw > UINT32_MAX) { state.error = true; return m; }
    m.id = static_cast<uint32_t>(id_raw);

    auto payload_result = Buffer::decode(state);
    if (state.error) return m;
    if (!payload_result.is_null()) {
        m.payload.assign(payload_result.data, payload_result.data + payload_result.len);
    }

    if (flags & 1) {
        m.peer_address = Ipv4Addr::decode(state);
    }
    return m;
}

// ---------------------------------------------------------------------------
// PunchState — shared state for the async holepunch flow.
//
// C++-only construct. JS tracks the equivalent state inline on the
// connect closure (`c.puncher`, `c.payload`, `c.round`, etc. from
// connect.js:57-93). C++ needs an explicit shared_ptr to thread state
// through the nested response/timeout lambdas, since we don't have
// async/await's closed-over stack frame.
// ---------------------------------------------------------------------------

namespace {

constexpr uint64_t HOLEPUNCH_TIMEOUT_MS = 15000;  // 15 seconds overall

struct PunchState {
    std::shared_ptr<SecurePayload> secure;
    std::shared_ptr<Holepuncher> puncher;
    std::shared_ptr<PoolSocket> pool;  // JS: dht._socketPool.acquire()
    std::shared_ptr<async_utils::Sleeper> sleeper;  // For probe retry delay
    OnHolepunchCallback on_done;
    rpc::RpcSocket* socket = nullptr;
    std::unique_ptr<async_utils::UvTimer> timeout;  // RAII holepunch timeout
    bool completed = false;
    int round = 0;
    bool retried_unknown = false;  // JS: retry flag in probeRound

    void complete(const HolepunchResult& result) {
        if (completed) return;
        completed = true;

        // Destroy puncher (stops timer, releases holders, clears callbacks).
        // Don't call close() — destroy() handles cleanup, and close()
        // can race with other handle closures during teardown.
        if (puncher) {
            puncher->destroy();
        }

        // Cancel sleeper timer
        if (sleeper) sleeper->cancel();

        // Close pool socket on FAILURE only. On success, the caller needs the
        // pool socket alive for udx_stream_connect — the HolepunchResult.socket
        // raw pointer must remain valid. Clear the probe callback to break the
        // circular reference (pool callback → state → pool) so the PunchState
        // can be destroyed when all other refs drop.
        if (pool && !result.success) {
            pool->close();
        } else if (pool) {
            pool->on_holepunch_probe(nullptr);  // Break circular ref
        }

        // Clear probe listener on main socket
        if (socket) socket->on_holepunch_probe(nullptr);

        // Stop and close timeout timer (RAII handles cleanup)
        timeout.reset();

        auto cb = std::move(on_done);
        if (cb) cb(result);
    }
};

}  // anonymous namespace

// ---------------------------------------------------------------------------
// holepunch_connect — full 2-round relay exchange + UDP probe flow.
//
// JS: .analysis/js/hyperdht/lib/connect.js:205-316 (holepunch — top level)
//     .analysis/js/hyperdht/lib/connect.js:555-629 (probeRound — round 1)
//     .analysis/js/hyperdht/lib/connect.js:631-711 (roundPunch  — round 2)
//     .analysis/js/hyperdht/lib/connect.js:505-553 (updateHolepunch — relay
//        send/recv with payload encrypt/decrypt)
//
// C++ diffs from JS:
//   - JS schedules an async pipeline of probeRound → roundPunch via
//     await. C++ uses a PunchState shared_ptr threaded through nested
//     response/timeout lambdas plus an overall 15s timeout timer.
//   - C++ derives `holepunchSecret` here (BLAKE2b(NS_PEER_HOLEPUNCH,
//     handshake_hash)). JS computes the same value inside NoiseWrap.final()
//     and passes it via `c.payload = new SecurePayload(hs.holepunchSecret)`.
//   - C++ runs `discover_pool_addresses` (PINGs from the pool socket) to
//     learn the pool socket's external address before round 1 — JS does
//     this lazily inside `Nat.autoSample()` started from the puncher ctor.
//   - JS uses a `Sleeper` for the UNKNOWN-firewall delay (connect.js:594-597).
//     C++ uses `async_utils::Sleeper::pause` which is the same idea.
//   - JS calls `puncher.openSession(serverAddress)` from probeRound BEFORE
//     sending round 1 (connect.js:556-559). C++ ports that as the
//     `fast_open` low-TTL probe issued from the pool socket.
//   - Round 2 in JS is sent via `c.dht._router.peerHolepunch` from the
//     puncher's socket. C++ sends it from the main RPC socket because
//     the relay routing context (token, node IDs) lives there; probes
//     still come from the pool socket.
// ---------------------------------------------------------------------------

void holepunch_connect(rpc::RpcSocket& socket,
                       const peer_connect::HandshakeResult& hs_result,
                       const compact::Ipv4Address& relay_addr,
                       const compact::Ipv4Address& peer_addr,
                       uint32_t holepunch_id,
                       uint32_t local_firewall,
                       const std::vector<compact::Ipv4Address>& local_addresses,
                       OnHolepunchCallback on_done,
                       bool fast_open,
                       udx_socket_t** pool_handle_out,
                       std::shared_ptr<void>* pool_keepalive_out) {

    // Derive holepunchSecret from handshake hash
    // holepunchSecret = BLAKE2b-256(NS_PEER_HOLEPUNCH, key=handshake_hash)
    const auto& ns_hp = dht_messages::ns_peer_holepunch();
    std::array<uint8_t, 32> holepunch_secret{};
    crypto_generichash(holepunch_secret.data(), 32,
                       ns_hp.data(), 32,
                       hs_result.handshake_hash.data(), 64);

    auto state = std::make_shared<PunchState>();
    state->secure = std::make_shared<SecurePayload>(holepunch_secret);
    state->sleeper = std::make_shared<async_utils::Sleeper>(socket.loop());
    state->on_done = std::move(on_done);
    state->socket = &socket;

    // Create pool socket (JS: dht._socketPool.acquire())
    state->pool = std::make_shared<PoolSocket>(socket.loop(), socket.udx_handle());
    state->pool->bind();

    // Expose pool socket to caller so the rawStream firewall callback can
    // set socket_keepalive when the server replies via the pool socket.
    if (pool_handle_out)
        *pool_handle_out = state->pool->socket_handle();
    if (pool_keepalive_out)
        *pool_keepalive_out = state->pool;

    // Create puncher EARLY — matching JS connect.js:258.
    // JS creates the Holepuncher (which acquires a pool socket) BEFORE
    // sending the handshake. The puncher's probe listener must exist
    // before the fast-open probe so it can catch the echo. When the
    // server has a public IP, the TTL=5 probe arrives, the server echoes
    // it, and the puncher detects it → connected without holepunch rounds.
    auto puncher = std::make_shared<Holepuncher>(socket.loop(), true);
    puncher->set_local_firewall(local_firewall);
    puncher->set_send_fn([state](const Ipv4Address& addr) {
        if (state->pool) state->pool->send_probe(addr);
    });
    puncher->set_send_ttl_fn([state](const Ipv4Address& addr, int ttl) {
        if (state->pool) state->pool->send_probe_ttl(addr, ttl);
    });
    puncher->on_connect([state](const HolepunchResult& result) {
        auto augmented = result;
        augmented.socket_keepalive = state->pool;
        state->complete(augmented);
    });
    state->puncher = puncher;

    // Listen for probes on pool socket (matching JS holepuncher.js:225).
    state->pool->on_holepunch_probe([state](const Ipv4Address& from) {
        if (state->puncher) state->puncher->on_message(from,
            state->pool ? state->pool->socket_handle() : nullptr);
    });

    // Fast-open: TTL=5 probe to server's announced address.
    // JS: probeRound calls `c.puncher.openSession(serverAddress)` before
    // Round 1 (connect.js:557). If the server is reachable (public IP),
    // the probe arrives, the server echoes it, and the puncher detects
    // the echo → connected without holepunch rounds.
    if (fast_open && peer_addr.port != 0) {
        DHT_LOG("  [hp] fast-open: low-TTL probe to %s:%u (from pool)\n",
                peer_addr.host_string().c_str(), peer_addr.port);
        state->pool->send_probe_ttl(peer_addr, 5);  // HOLEPUNCH_TTL = 5
    }

    // Compute target hash (reused for both rounds)
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32,
                       hs_result.remote_public_key.data(), 32,
                       nullptr, 0);

    // Discover pool socket's external address via PINGs (JS: nat.autoSample())
    discover_pool_addresses(*state->pool, socket.table(), relay_addr, peer_addr,
        [state, target, relay_addr, peer_addr, holepunch_id,
         local_addresses](bool addr_ok) {

        if (state->completed) return;

        // Use pool socket's discovered addresses if available, else fall back to main
        auto pool_addrs = state->pool->addresses();
        auto& addrs = pool_addrs.empty() ? local_addresses : pool_addrs;

        // Use pool socket's firewall classification (not the main socket's).
        // JS: holepuncher.js uses its own nat.firewall for holepunch rounds,
        // which is sampled from the pool socket's PING responses.
        auto pool_fw = state->pool->nat_sampler().firewall();

        // Update puncher with pool socket's classification now that we know it
        state->puncher->set_local_firewall(pool_fw);

        DHT_LOG("  [hp] Pool NAT: fw=%u, %zu addrs (discovered=%s)\n",
                pool_fw, pool_addrs.size(),
                addr_ok ? "yes" : "no");

    // -----------------------------------------------------------------------
    // Round 1: probe exchange — send our firewall info, get server's
    // -----------------------------------------------------------------------
    HolepunchPayload probe;
    probe.error = peer_connect::ERROR_NONE;
    probe.firewall = pool_fw;
    probe.round = 0;
    probe.addresses = addrs;
    probe.remote_address = peer_addr;

    auto probe_bytes = encode_holepunch_payload(probe);
    auto encrypted_probe = state->secure->encrypt(probe_bytes.data(), probe_bytes.size());

    HolepunchMessage hp_msg;
    hp_msg.mode = peer_connect::MODE_FROM_CLIENT;
    hp_msg.id = holepunch_id;
    hp_msg.payload = std::move(encrypted_probe);
    hp_msg.peer_address = peer_addr;

    messages::Request req;
    req.to.addr = relay_addr;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.target = target;
    req.value = encode_holepunch_msg(hp_msg);

    DHT_LOG( "  [hp] Sending round 1 to relay %s:%u (id=%u, peer=%s:%u)\n",
            relay_addr.host_string().c_str(), relay_addr.port,
            holepunch_id,
            peer_addr.host_string().c_str(), peer_addr.port);

    // Send Round 1 from POOL socket — JS sends holepunch rounds via
    // c.puncher.socket (connect.js:505-516, updateHolepunch). The relay
    // sets peerAddress = req.from, so using the pool socket ensures the
    // server sees the same address as our probes. Using the main socket
    // would cause a port mismatch on NAT.
    state->pool->request(req,
        [state, relay_addr, peer_addr, holepunch_id, target, pool_fw]
        (const messages::Response& resp) {
            if (state->completed) return;

            if (!resp.value.has_value() || resp.value->empty()) {
                DHT_LOG( "  [hp] Round 1: no response value\n");
                state->complete({});
                return;
            }
            DHT_LOG( "  [hp] Round 1: got response (%zu bytes)\n",
                    resp.value->size());

            auto hp_resp = decode_holepunch_msg(resp.value->data(), resp.value->size());
            if (hp_resp.payload.empty()) {
                DHT_LOG( "  [hp] Round 1: empty payload in decoded msg\n");
                state->complete({});
                return;
            }
            DHT_LOG( "  [hp] Round 1: payload %zu bytes, peerAddr=%s\n",
                    hp_resp.payload.size(),
                    hp_resp.peer_address.has_value()
                        ? (hp_resp.peer_address->host_string() + ":" +
                           std::to_string(hp_resp.peer_address->port)).c_str()
                        : "none");

            // Decrypt server's round 1 response
            auto decrypted = state->secure->decrypt(
                hp_resp.payload.data(), hp_resp.payload.size());
            if (!decrypted) {
                // C2: abort on decrypt failure — never fall back to
                // unauthenticated peerAddress (MITM vector)
                DHT_LOG( "  [hp] Round 1: decrypt FAILED — aborting (no fallback)\n");
                state->complete({});
                return;
            }

            auto server_r1 = decode_holepunch_payload(decrypted->data(), decrypted->size());
            DHT_LOG( "  [hp] Round 1 server: fw=%u err=%u round=%u "
                    "addrs=%zu punching=%d connected=%d token=%s\n",
                    server_r1.firewall, server_r1.error, server_r1.round,
                    server_r1.addresses.size(),
                    server_r1.punching ? 1 : 0, server_r1.connected ? 1 : 0,
                    server_r1.token.has_value() ? "yes" : "no");

            if (server_r1.error != peer_connect::ERROR_NONE) {
                DHT_LOG( "  [hp] Round 1: server error %u\n", server_r1.error);
                state->complete({});
                return;
            }

            // JS: probeRound (connect.js:593-598) — sleeper.pause(1000)
            //     when remoteFirewall is UNKNOWN
            // If remote firewall is UNKNOWN, treat as CONSISTENT but delay
            // Round 2 by 1s to give the server time to sample its own NAT.
            // This is the fix for the NAT-to-NAT failure.
            uint32_t effective_remote_fw = server_r1.firewall;
            bool delay_round2 = false;
            if (effective_remote_fw == peer_connect::FIREWALL_UNKNOWN) {
                DHT_LOG("  [hp] Server firewall UNKNOWN, treating as CONSISTENT (1s delay)\n");
                effective_remote_fw = peer_connect::FIREWALL_CONSISTENT;
                delay_round2 = true;
            }

            // JS: abort if both sides are RANDOM (impossible to punch)
            if (effective_remote_fw >= peer_connect::FIREWALL_RANDOM &&
                pool_fw >= peer_connect::FIREWALL_RANDOM) {
                DHT_LOG("  [hp] Both sides RANDOM — cannot holepunch\n");
                state->complete({});
                return;
            }

            // Collect server's addresses (from payload + relay peerAddress)
            std::vector<Ipv4Address> server_addrs = server_r1.addresses;
            if (hp_resp.peer_address.has_value()) {
                server_addrs.push_back(*hp_resp.peer_address);
            }
            for (size_t i = 0; i < server_addrs.size(); i++) {
                DHT_LOG("  [hp] Server addr[%zu]: %s:%u\n", i,
                        server_addrs[i].host_string().c_str(), server_addrs[i].port);
            }
            if (server_addrs.empty()) {
                state->complete({});
                return;
            }

            // If server is OPEN, direct connect — no probing needed
            if (server_r1.firewall == peer_connect::FIREWALL_OPEN) {
                HolepunchResult result;
                result.success = true;
                result.firewall = peer_connect::FIREWALL_OPEN;
                result.address = server_addrs[0];
                state->complete(result);
                return;
            }

            // Puncher was created early (before fast-open probe). Now update
            // it with server addresses from Round 1 response.
            state->puncher->set_remote_firewall(effective_remote_fw);
            std::string verified_host;
            if (!server_addrs.empty()) verified_host = server_addrs[0].host_string();
            state->puncher->update_remote(server_addrs, verified_host);

            // JS parity (connect.js:600-621): analyze() stability check
            //
            //   stable = await puncher.analyze(false)
            //   if (!stable) stable = await puncher.analyze(true)    // allow_reopen
            //   if (still UNKNOWN on either side) → abort PROBE_TIMEOUT
            //
            // Our Holepuncher::analyze() is synchronous (no `await` over
            // nat.analyzing — our pool socket discovery already completed
            // the NAT sampling before we got here). It returns `true` when
            // both sides are classified and we are NOT in a double-RANDOM
            // dead-end. Without it, an UNKNOWN local NAT would walk into
            // Round 2 and waste the full holepunch timeout.
            //
            // The reopen path (`analyze(true)`) signals `on_reset_` — not
            // currently wired from holepunch_connect, so in practice the
            // fallback just re-checks and aborts. Wiring a pool-socket
            // reset here would be a future improvement.
            bool stable_ok = false;
            state->puncher->analyze(false, [&stable_ok](bool s) { stable_ok = s; });
            if (!stable_ok) {
                state->puncher->analyze(true, [&stable_ok](bool s) { stable_ok = s; });
            }
            if (!stable_ok) {
                DHT_LOG("  [hp] NAT unstable after analyze() — abort\n");
                state->complete({});
                return;
            }

            // JS: probeRound:582-591 — if the server's address from the
            // Round 1 payload differs from the announce address and the
            // firewall isn't RANDOM, send an openSession (TTL=5) probe.
            // The server's puncher (created during _addHandshake) echoes
            // ALL probes on its pool socket. If the echo arrives back
            // before Round 2, we connect without holepunch rounds.
            // Post-Round1 probe: send to server's pool address so the
            // server's puncher echoes it. If NAT conditions allow, the
            // echo arrives before Round 2 → connected without holepunch
            // rounds (matching JS probeRound:582-591).
            if (effective_remote_fw < peer_connect::FIREWALL_RANDOM &&
                !server_addrs.empty()) {
                DHT_LOG("  [hp] Post-Round1 probe to %s:%u\n",
                        server_addrs[0].host_string().c_str(),
                        server_addrs[0].port);
                state->puncher->send_probe(server_addrs[0]);
            }

            // Start overall timeout (RAII — auto-cleaned by PunchState destructor)
            state->timeout = std::make_unique<async_utils::UvTimer>(
                state->socket->loop());
            state->timeout->start([state]() {
                state->complete({});  // Timeout — fail
            }, HOLEPUNCH_TIMEOUT_MS);

            // -------------------------------------------------------------------
            // Round 2: punch exchange — tell server to start probing
            // Delayed by 1s if server firewall was UNKNOWN (gives server time)
            // -------------------------------------------------------------------

            // Use our main RPC socket's external address (from relay response).
            // The server probes this address. We send probes from both main
            // and pool sockets to maximize NAT punch chances.
            Ipv4Address our_addr = resp.from.addr;

            auto send_round2 = [state, relay_addr, peer_addr,
                                holepunch_id, target, pool_fw,
                                server_addrs, server_r1, our_addr]() {
            if (state->completed) return;

            // JS: c.puncher.nat.freeze() — prevent NAT updates during punch
            state->pool->nat_sampler().freeze();
            DHT_LOG("  [hp] Our pool address (from relay): %s:%u\n",
                    our_addr.host_string().c_str(), our_addr.port);

            HolepunchPayload punch;
            punch.error = peer_connect::ERROR_NONE;
            punch.firewall = pool_fw;
            punch.round = 1;
            punch.punching = true;
            punch.addresses.push_back(our_addr);

            // Generate our token for address verification
            punch.token = state->secure->token(server_addrs[0].host_string());
            // Echo back the server's token
            if (server_r1.token.has_value()) {
                punch.remote_token = server_r1.token;
            }

            auto punch_bytes = encode_holepunch_payload(punch);
            auto encrypted_punch = state->secure->encrypt(
                punch_bytes.data(), punch_bytes.size());

            HolepunchMessage hp_msg2;
            hp_msg2.mode = peer_connect::MODE_FROM_CLIENT;
            hp_msg2.id = holepunch_id;
            hp_msg2.payload = std::move(encrypted_punch);
            hp_msg2.peer_address = peer_addr;

            messages::Request req2;
            req2.to.addr = relay_addr;
            req2.command = messages::CMD_PEER_HOLEPUNCH;
            req2.target = target;
            req2.value = encode_holepunch_msg(hp_msg2);

            DHT_LOG( "  [hp] Sending round 2 (punching=true) to %s:%u\n",
                    relay_addr.host_string().c_str(), relay_addr.port);

            // JS: openSession BEFORE sending round 2 (connect.js:557)
            // Prime our NAT mapping with low-TTL probe
            if (!server_addrs.empty()) {
                state->puncher->open_session(server_addrs[0]);
            }

            // Round 2 also sent from pool socket — same rationale as Round 1.
            // JS: connect.js:505-516 (updateHolepunch) uses c.puncher.socket.
            // PoolSocket::request() handles encoding, TID, and timeout.
            state->pool->request(req2,
                [state, server_addrs](const messages::Response& r2resp) {
                    if (state->completed) return;

                    // Decode round 2 response to check for errors
                    if (r2resp.value.has_value() && !r2resp.value->empty()) {
                        auto r2_msg = decode_holepunch_msg(
                            r2resp.value->data(), r2resp.value->size());
                        if (!r2_msg.payload.empty()) {
                            auto r2_dec = state->secure->decrypt(
                                r2_msg.payload.data(), r2_msg.payload.size());
                            if (r2_dec) {
                                auto r2_pay = decode_holepunch_payload(
                                    r2_dec->data(), r2_dec->size());
                                DHT_LOG(
                                    "  [hp] Round 2 server: fw=%u err=%u "
                                    "punching=%d connected=%d addrs=%zu\n",
                                    r2_pay.firewall, r2_pay.error,
                                    r2_pay.punching ? 1 : 0,
                                    r2_pay.connected ? 1 : 0,
                                    r2_pay.addresses.size());

                                if (r2_pay.error != peer_connect::ERROR_NONE) {
                                    state->complete({});
                                    return;
                                }

                                // JS: updateRemote with Round 2 addresses
                                // Server may report its holepunch socket address
                                // which differs from its main socket address in Round 1
                                if (!r2_pay.addresses.empty() && state->puncher) {
                                    std::string verified;
                                    if (!r2_pay.addresses.empty())
                                        verified = r2_pay.addresses[0].host_string();
                                    state->puncher->update_remote(
                                        r2_pay.addresses, verified);
                                    DHT_LOG("  [hp] Updated puncher addresses from Round 2 (%zu addrs)\n",
                                            r2_pay.addresses.size());
                                }
                            }
                        }
                    }
                },
                [state](uint16_t) {
                    DHT_LOG( "  [hp] Round 2: TIMEOUT (relay)\n");
                    // Timeout is OK — probing is already in progress
                });

            // Start probing IMMEDIATELY after sending Round 2 — don't wait
            // for relay response. JS: roundPunch calls punch() right after
            // sending the update, not in the response callback.
            state->puncher->punch();
            };  // end send_round2 lambda

            // Dispatch Round 2 with appropriate delay.
            // JS: between Round 1 response and Round 2, connect.js calls
            // `await c.puncher.analyze(false)` which waits for the client's
            // NAT sampling (~200-400ms). This delay also gives the SERVER's
            // puncher time to complete its own autoSample. Without it, the
            // server's punch() → analyze() returns UNKNOWN → abort → no probes.
            // JS: between Round 1 and Round 2, connect.js calls
            // `await c.puncher.analyze(false)` which yields to the event loop.
            // During this yield, the post-Round1 probe echo may arrive and
            // complete the connection (via puncher on_connect) — skipping
            // Round 2 entirely. We replicate this with a polling check:
            // yield 50ms at a time (up to 500ms), checking if the probe
            // connected us. libuv processes I/O between timer callbacks.
            if (delay_round2) {
                DHT_LOG("  [hp] Delaying Round 2 by 1s (server fw was UNKNOWN)\n");
                state->sleeper->pause(1000, send_round2);
            } else {
                // Delay 500ms before Round 2, matching JS analyze() wait.
                // During this time, the post-Round1 probe echo may arrive
                // and complete the connection, skipping Round 2.
                auto sr2 = std::make_shared<std::function<void()>>(
                    std::move(send_round2));
                state->sleeper->pause(500, [state, sr2]() {
                    if (state->completed) return;  // Probe connected us!
                    (*sr2)();
                });
            }
        },
        [state](uint16_t) {
            DHT_LOG( "  [hp] Round 1: TIMEOUT (no response from relay)\n");
            state->complete({});
        });
    });  // end discover_pool_addresses callback
}

// ---------------------------------------------------------------------------
// localAddresses — enumerate non-internal local IPv4 interfaces.
//
// JS: .analysis/js/hyperdht/lib/holepuncher.js:337-354 (localAddresses)
// ---------------------------------------------------------------------------

std::vector<Ipv4Address> local_addresses(uint16_t port) {
    std::vector<Ipv4Address> addrs;

    uv_interface_address_t* info = nullptr;
    int count = 0;
    int rc = uv_interface_addresses(&info, &count);
    if (rc != 0) {
        addrs.push_back(Ipv4Address::from_string("127.0.0.1", port));
        return addrs;
    }

    for (int i = 0; i < count; i++) {
        if (info[i].address.address4.sin_family != AF_INET) continue;
        if (info[i].is_internal) continue;

        char ip[INET_ADDRSTRLEN];
        uv_ip4_name(&info[i].address.address4, ip, sizeof(ip));
        addrs.push_back(Ipv4Address::from_string(ip, port));
    }

    uv_free_interface_addresses(info, count);

    if (addrs.empty()) {
        addrs.push_back(Ipv4Address::from_string("127.0.0.1", port));
    }
    return addrs;
}

// ---------------------------------------------------------------------------
// matchAddress — find best LAN address match by IP prefix.
//
// JS: .analysis/js/hyperdht/lib/holepuncher.js:356-386 (matchAddress)
// ---------------------------------------------------------------------------

std::optional<Ipv4Address> match_address(
    const std::vector<Ipv4Address>& my_addresses,
    const std::vector<Ipv4Address>& remote_addresses) {

    if (remote_addresses.empty()) return std::nullopt;

    int best_segment = 0;
    const Ipv4Address* best_addr = nullptr;

    for (const auto& local : my_addresses) {
        for (const auto& remote : remote_addresses) {
            // Compare octets (JS: split('.') and compare segments)
            if (local.host[0] != remote.host[0]) continue;

            // 1-octet match
            if (best_segment < 1) {
                best_segment = 1;
                best_addr = &remote;
            }

            if (local.host[1] != remote.host[1]) continue;

            // 2-octet match
            if (best_segment < 2) {
                best_segment = 2;
                best_addr = &remote;
            }

            if (local.host[2] != remote.host[2]) continue;

            // 3-octet match — immediate return (best possible).
            // Copy by value so callers don't depend on remote_addresses lifetime.
            return remote;
        }
    }

    if (best_addr) return *best_addr;
    return std::nullopt;
}

}  // namespace holepunch
}  // namespace hyperdht
