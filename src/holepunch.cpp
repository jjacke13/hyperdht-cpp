#include "hyperdht/holepunch.hpp"

#include <sodium.h>

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
    uv_timer_init(loop, &punch_timer_);
    punch_timer_.data = this;
}

Holepuncher::~Holepuncher() {
    stop();
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&punch_timer_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&punch_timer_), nullptr);
    }
}

bool Holepuncher::punch() {
    using namespace peer_connect;

    if (connected_) return true;

    // Determine strategy based on firewall combo
    bool local_consistent = (local_firewall_ == FIREWALL_CONSISTENT || local_firewall_ == FIREWALL_OPEN);
    bool remote_consistent = (remote_firewall_ == FIREWALL_CONSISTENT || remote_firewall_ == FIREWALL_OPEN);

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
    uv_timer_stop(&punch_timer_);
}

void Holepuncher::send_probe(const compact::Ipv4Address& addr) {
    // The actual UDP send would need a socket — for now this is a placeholder.
    // In the full implementation, this sends 1 byte [0x00] via udx_socket_send.
    // The caller (RpcSocket or a dedicated punch socket) handles the actual send.
    (void)addr;
}

void Holepuncher::on_message(const compact::Ipv4Address& from) {
    if (connected_) return;

    connected_ = true;
    punching_ = false;
    uv_timer_stop(&punch_timer_);

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
    uv_timer_start(&punch_timer_, on_punch_timer, 1000, 0);
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
    uv_timer_start(&punch_timer_, on_punch_timer, 20, 0);
}

void Holepuncher::on_punch_timer(uv_timer_t* timer) {
    auto* self = static_cast<Holepuncher*>(timer->data);

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
// holepunch_connect — full relay round-trip
// ---------------------------------------------------------------------------

void holepunch_connect(rpc::RpcSocket& socket,
                       const peer_connect::HandshakeResult& hs_result,
                       const compact::Ipv4Address& relay_addr,
                       uint32_t holepunch_id,
                       OnHolepunchCallback on_done) {

    // Derive holepunchSecret from handshake hash
    // holepunchSecret = BLAKE2b-256(NS_PEER_HOLEPUNCH, handshake_hash)
    // NS_PEER_HOLEPUNCH = namespace('hyperswarm/dht', [4,5,6,0,1])[4]
    uint8_t ns_hash[32];
    const char* name = "hyperswarm/dht";
    crypto_generichash(ns_hash, 32,
                       reinterpret_cast<const uint8_t*>(name), std::strlen(name),
                       nullptr, 0);
    uint8_t ns_input[33];
    std::memcpy(ns_input, ns_hash, 32);
    ns_input[32] = 1;  // PEER_HOLEPUNCH command = 1
    std::array<uint8_t, 32> ns_peer_holepunch{};
    crypto_generichash(ns_peer_holepunch.data(), 32, ns_input, 33, nullptr, 0);

    std::array<uint8_t, 32> holepunch_secret{};
    crypto_generichash(holepunch_secret.data(), 32,
                       ns_peer_holepunch.data(), 32,
                       hs_result.handshake_hash.data(), 64);

    auto secure = std::make_shared<SecurePayload>(holepunch_secret);

    // Build probe round payload
    HolepunchPayload probe;
    probe.error = peer_connect::ERROR_NONE;
    probe.firewall = peer_connect::FIREWALL_UNKNOWN;
    probe.round = 0;
    probe.connected = false;
    probe.punching = false;
    // We don't know our addresses yet — send empty

    auto probe_bytes = encode_holepunch_payload(probe);
    auto encrypted_probe = secure->encrypt(probe_bytes.data(), probe_bytes.size());

    // Wrap in PEER_HOLEPUNCH message
    HolepunchMessage hp_msg;
    hp_msg.mode = peer_connect::MODE_FROM_CLIENT;
    hp_msg.id = holepunch_id;
    hp_msg.payload = std::move(encrypted_probe);

    auto hp_value = encode_holepunch_msg(hp_msg);

    // Compute target hash
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32,
                       hs_result.remote_public_key.data(), 32,
                       nullptr, 0);

    // Send PEER_HOLEPUNCH via relay
    messages::Request req;
    req.to.addr = relay_addr;
    req.command = messages::CMD_PEER_HOLEPUNCH;
    req.target = target;
    req.value = std::move(hp_value);

    socket.request(req,
        [secure, on_done, &socket, relay_addr, holepunch_id, target, hs_result]
        (const messages::Response& resp) {
            if (!resp.value.has_value() || resp.value->empty()) {
                HolepunchResult fail;
                fail.success = false;
                on_done(fail);
                return;
            }

            // Decode PEER_HOLEPUNCH response
            auto hp_resp = decode_holepunch_msg(resp.value->data(), resp.value->size());
            if (hp_resp.payload.empty()) {
                HolepunchResult fail;
                on_done(fail);
                return;
            }

            // Decrypt the holepunch payload
            auto decrypted = secure->decrypt(hp_resp.payload.data(), hp_resp.payload.size());
            if (!decrypted) {
                HolepunchResult fail;
                on_done(fail);
                return;
            }

            auto server_probe = decode_holepunch_payload(decrypted->data(), decrypted->size());

            // Check server's response
            if (server_probe.error != peer_connect::ERROR_NONE) {
                HolepunchResult fail;
                on_done(fail);
                return;
            }

            // If server has addresses, try to connect directly
            if (!server_probe.addresses.empty()) {
                HolepunchResult result;
                result.success = true;
                result.firewall = server_probe.firewall;
                // Pick the first address (could be smarter about this)
                result.address = server_probe.addresses[0];
                on_done(result);
                return;
            }

            // If we got a peerAddress from the relay, use that
            if (hp_resp.peer_address.has_value()) {
                HolepunchResult result;
                result.success = true;
                result.firewall = server_probe.firewall;
                result.address = *hp_resp.peer_address;
                on_done(result);
                return;
            }

            // No address found
            HolepunchResult fail;
            on_done(fail);
        },
        [on_done](uint16_t) {
            HolepunchResult fail;
            on_done(fail);
        });
}

}  // namespace holepunch
}  // namespace hyperdht
