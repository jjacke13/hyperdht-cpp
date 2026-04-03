#include "hyperdht/holepunch.hpp"

#include "hyperdht/debug.hpp"
#include "hyperdht/dht_messages.hpp"

#include <sodium.h>

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
// SecurePayload
// ---------------------------------------------------------------------------

SecurePayload::SecurePayload(const std::array<uint8_t, 32>& key)
    : shared_secret_(key) {
    // Generate a random local secret for token generation
    randombytes_buf(local_secret_.data(), 32);
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
// HolepunchPayload encoding
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
// OPEN firewall shortcut
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
// Holepuncher
// ---------------------------------------------------------------------------

Holepuncher::Holepuncher(uv_loop_t* loop, bool is_initiator)
    : loop_(loop), is_initiator_(is_initiator) {
    punch_timer_ = new uv_timer_t;
    uv_timer_init(loop, punch_timer_);
    punch_timer_->data = this;
}

Holepuncher::~Holepuncher() {
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
        punching_ = true;
        punch_round_ = 0;
        consistent_probe();
        return true;
    }

    if (local_consistent && remote_firewall_ == FIREWALL_RANDOM) {
        // CONSISTENT+RANDOM: 1750 probes to random ports
        punching_ = true;
        random_probes_left_ = 1750;
        random_probes();
        return true;
    }

    if (local_firewall_ == FIREWALL_RANDOM && remote_consistent) {
        // RANDOM+CONSISTENT: would need birthday sockets
        // Simplified: try consistent probe (may work if NAT is somewhat predictable)
        punching_ = true;
        punch_round_ = 0;
        consistent_probe();
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
        DHT_LOG( "  [hp] Sending probe to %s:%u\n",
                addr.host_string().c_str(), addr.port);
        send_fn_(addr);
    }
}

void Holepuncher::on_message(const compact::Ipv4Address& from) {
    DHT_LOG( "  [hp] PROBE RECEIVED from %s:%u!\n",
            from.host_string().c_str(), from.port);
    if (connected_) return;

    connected_ = true;
    punching_ = false;
    if (punch_timer_ && !uv_is_closing(reinterpret_cast<uv_handle_t*>(punch_timer_))) {
        uv_timer_stop(punch_timer_);
    }

    // Move-and-call: prevent reentrancy if callback destroys us
    auto cb = std::move(on_connect_);
    if (cb) {
        HolepunchResult result;
        result.success = true;
        result.address = from;
        result.firewall = remote_firewall_;
        cb(result);
    }
}

// ---------------------------------------------------------------------------
// CONSISTENT+CONSISTENT: 10 rounds, 1s apart
// ---------------------------------------------------------------------------

void Holepuncher::consistent_probe() {
    if (!punching_ || connected_ || punch_round_ >= 10) {
        if (punching_ && !connected_) {
            punching_ = false;
            // Failed after 10 rounds
        }
        return;
    }

    // Send probe to each known remote address
    for (const auto& addr : remote_addresses_) {
        send_probe(addr);
    }

    punch_round_++;

    // Schedule next round in 1 second
    uv_timer_start(punch_timer_, on_punch_timer, 1000, 0);
}

// ---------------------------------------------------------------------------
// CONSISTENT+RANDOM: 1750 probes to random ports, 20ms apart
// ---------------------------------------------------------------------------

void Holepuncher::random_probes() {
    if (!punching_ || connected_) return;
    if (random_probes_left_ <= 0) {
        punching_ = false;  // Exhausted — stop, don't fall through to consistent_probe
        return;
    }

    // Send probe to a random port on the remote host
    if (!remote_addresses_.empty()) {
        auto addr = remote_addresses_[0];
        // Random port between 1000-65535
        uint16_t random_port = static_cast<uint16_t>(1000 + randombytes_uniform(64536));
        auto probe_addr = Ipv4Address::from_string(addr.host_string(), random_port);
        send_probe(probe_addr);
    }

    random_probes_left_--;

    // Schedule next probe in 20ms
    uv_timer_start(punch_timer_, on_punch_timer, 20, 0);
}

void Holepuncher::on_punch_timer(uv_timer_t* timer) {
    auto* self = static_cast<Holepuncher*>(timer->data);
    if (!self) return;

    if (self->random_probes_left_ > 0) {
        self->random_probes();
    } else {
        self->consistent_probe();
    }
}

// ---------------------------------------------------------------------------
// PEER_HOLEPUNCH message encoding
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

    uint8_t flags = static_cast<uint8_t>(Uint::decode(state));
    if (state.error) return m;
    m.mode = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return m;
    m.id = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return m;

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
// PunchState — shared state for the async holepunch flow
// ---------------------------------------------------------------------------

namespace {

constexpr uint64_t HOLEPUNCH_TIMEOUT_MS = 15000;  // 15 seconds overall

struct PunchState {
    std::shared_ptr<SecurePayload> secure;
    std::shared_ptr<Holepuncher> puncher;
    OnHolepunchCallback on_done;
    rpc::RpcSocket* socket = nullptr;
    uv_timer_t* timeout = nullptr;
    bool completed = false;

    void complete(const HolepunchResult& result) {
        if (completed) return;
        completed = true;

        // Stop probing
        if (puncher) puncher->stop();

        // Clear probe listener
        if (socket) socket->on_holepunch_probe(nullptr);

        // Stop and close timeout timer
        if (timeout && !uv_is_closing(reinterpret_cast<uv_handle_t*>(timeout))) {
            uv_timer_stop(timeout);
            timeout->data = nullptr;
            uv_close(reinterpret_cast<uv_handle_t*>(timeout),
                     [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
            timeout = nullptr;
        }

        auto cb = std::move(on_done);
        if (cb) cb(result);
    }
};

}  // anonymous namespace

// ---------------------------------------------------------------------------
// holepunch_connect — full 2-round relay + UDP probe flow
// ---------------------------------------------------------------------------

void holepunch_connect(rpc::RpcSocket& socket,
                       const peer_connect::HandshakeResult& hs_result,
                       const compact::Ipv4Address& relay_addr,
                       const compact::Ipv4Address& peer_addr,
                       uint32_t holepunch_id,
                       uint32_t local_firewall,
                       const std::vector<compact::Ipv4Address>& local_addresses,
                       OnHolepunchCallback on_done) {

    // Derive holepunchSecret from handshake hash
    // holepunchSecret = BLAKE2b-256(NS_PEER_HOLEPUNCH, key=handshake_hash)
    const auto& ns_hp = dht_messages::ns_peer_holepunch();
    std::array<uint8_t, 32> holepunch_secret{};
    crypto_generichash(holepunch_secret.data(), 32,
                       ns_hp.data(), 32,
                       hs_result.handshake_hash.data(), 64);

    auto state = std::make_shared<PunchState>();
    state->secure = std::make_shared<SecurePayload>(holepunch_secret);
    state->on_done = std::move(on_done);
    state->socket = &socket;

    // Compute target hash (reused for both rounds)
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32,
                       hs_result.remote_public_key.data(), 32,
                       nullptr, 0);

    // -----------------------------------------------------------------------
    // Round 1: probe exchange — send our firewall info, get server's
    // -----------------------------------------------------------------------
    // Get our public address from the RPC socket's perspective.
    // This is the address DHT nodes see us as (from response `to` field).
    // Without NAT sampling, we use the socket's local address as a placeholder —
    // the relay will provide our real address to the server via peerAddress.
    HolepunchPayload probe;
    probe.error = peer_connect::ERROR_NONE;
    probe.firewall = local_firewall;
    probe.round = 0;
    probe.addresses = local_addresses;

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

    socket.request(req,
        [state, &socket, relay_addr, peer_addr, holepunch_id, target, local_firewall]
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
                DHT_LOG( "  [hp] Round 1: decrypt FAILED\n");
                // Decrypt failed — use peerAddress from relay as fallback
                if (hp_resp.peer_address.has_value()) {
                    HolepunchResult result;
                    result.success = true;
                    result.address = *hp_resp.peer_address;
                    state->complete(result);
                }  else {
                    state->complete({});
                }
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

            // Collect server's addresses (from payload + relay peerAddress)
            std::vector<Ipv4Address> server_addrs = server_r1.addresses;
            if (hp_resp.peer_address.has_value()) {
                server_addrs.push_back(*hp_resp.peer_address);
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

            // -------------------------------------------------------------------
            // Set up the Holepuncher
            // -------------------------------------------------------------------
            auto puncher = std::make_shared<Holepuncher>(socket.loop(), true);
            puncher->set_local_firewall(local_firewall);
            puncher->set_remote_firewall(server_r1.firewall);
            puncher->set_remote_addresses(server_addrs);

            // Wire probe sending through the SAME RpcSocket
            puncher->set_send_fn([&socket](const Ipv4Address& addr) {
                socket.send_probe(addr);
            });

            // When we detect an incoming probe → success
            puncher->on_connect([state](const HolepunchResult& result) {
                state->complete(result);
            });

            state->puncher = puncher;

            // Register probe listener on the RPC socket (same socket as RPC traffic)
            socket.on_holepunch_probe([state](const Ipv4Address& from) {
                if (state->puncher) {
                    state->puncher->on_message(from);
                }
            });

            // Start overall timeout
            auto* timer = new uv_timer_t;
            uv_timer_init(socket.loop(), timer);
            auto timeout_state = state;  // prevent shared_ptr from dying
            timer->data = new std::shared_ptr<PunchState>(timeout_state);
            state->timeout = timer;

            uv_timer_start(timer, [](uv_timer_t* t) {
                auto* sp = static_cast<std::shared_ptr<PunchState>*>(t->data);
                if (sp && *sp) {
                    (*sp)->complete({});  // Timeout — fail
                }
                delete sp;
                t->data = nullptr;
            }, HOLEPUNCH_TIMEOUT_MS, 0);

            // -------------------------------------------------------------------
            // Round 2: punch exchange — tell server to start probing
            // -------------------------------------------------------------------

            // Our public address: the relay response `to` field tells us how
            // the relay sees us. The server needs this to know WHERE to probe.
            Ipv4Address our_addr = resp.from.addr;
            DHT_LOG( "  [hp] Our address (from relay): %s:%u\n",
                    our_addr.host_string().c_str(), our_addr.port);

            HolepunchPayload punch;
            punch.error = peer_connect::ERROR_NONE;
            punch.firewall = local_firewall;
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

            socket.request(req2,
                [state, puncher, server_addrs](const messages::Response& r2resp) {
                    if (state->completed) return;

                    // Decode round 2 response to check for errors
                    bool server_punching = false;
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
                                server_punching = r2_pay.punching;
                            }
                        }
                    }

                    // Start our probing (opens NAT holes for the server)
                    puncher->punch();

                    // Report success immediately — the caller should connect
                    // the UDX stream now. UDX SYN retries + our probes will
                    // open the NAT from both sides. We don't wait for a [0x00]
                    // probe back because the server may connect its stream
                    // (and stop probing) before we detect one.
                    HolepunchResult result;
                    result.success = true;
                    result.firewall = server_addrs.empty() ? 0 : 0;
                    result.address = server_addrs[0];
                    state->complete(result);
                },
                [state, puncher, server_addrs](uint16_t) {
                    DHT_LOG( "  [hp] Round 2: TIMEOUT\n");
                    // Round 2 timeout — still try probing and report address
                    if (!state->completed) {
                        puncher->punch();
                        HolepunchResult result;
                        result.success = true;
                        result.address = server_addrs[0];
                        state->complete(result);
                    }
                });
        },
        [state](uint16_t) {
            DHT_LOG( "  [hp] Round 1: TIMEOUT (no response from relay)\n");
            state->complete({});
        });
}

}  // namespace holepunch
}  // namespace hyperdht
