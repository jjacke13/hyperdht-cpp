#include "hyperdht/peer_connect.hpp"

#include <sodium.h>

#include <cstring>

namespace hyperdht {
namespace peer_connect {

using compact::State;
using compact::Uint;
using compact::Buffer;
using compact::Ipv4Addr;
using compact::Ipv4Address;
using compact::Array;

// Real HyperDHT prologue: NS_PEER_HANDSHAKE
// BLAKE2b-256(BLAKE2b-256("hyperswarm/dht") || 0x00)
static std::array<uint8_t, 32> compute_prologue() {
    uint8_t ns_hash[32];
    const char* name = "hyperswarm/dht";
    crypto_generichash(ns_hash, 32,
                       reinterpret_cast<const uint8_t*>(name), std::strlen(name),
                       nullptr, 0);
    uint8_t ns_input[33];
    std::memcpy(ns_input, ns_hash, 32);
    ns_input[32] = 0;  // PEER_HANDSHAKE command = 0

    std::array<uint8_t, 32> result{};
    crypto_generichash(result.data(), 32, ns_input, 33, nullptr, 0);
    return result;
}

static const auto PROLOGUE = compute_prologue();

// ---------------------------------------------------------------------------
// NoisePayload encoding
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_noise_payload(const NoisePayload& p) {
    State state;

    // version + flags + error + firewall (4 varints, typically 4 bytes)
    Uint::preencode(state, p.version);
    uint32_t flags = 0;
    if (!p.addresses4.empty()) flags |= 2;
    if (p.udx.has_value()) flags |= 8;
    if (p.has_secret_stream) flags |= 16;
    Uint::preencode(state, flags);
    Uint::preencode(state, p.error);
    Uint::preencode(state, p.firewall);

    if (!p.addresses4.empty()) {
        Array<Ipv4Addr, Ipv4Address>::preencode(state, p.addresses4);
    }
    if (p.udx.has_value()) {
        // udxInfo: version(uint) + features(uint) + id(uint) + seq(uint)
        Uint::preencode(state, p.udx->version);
        Uint::preencode(state, p.udx->reusable_socket ? 1u : 0u);
        Uint::preencode(state, p.udx->id);
        Uint::preencode(state, p.udx->seq);
    }
    if (p.has_secret_stream) {
        Uint::preencode(state, 1u);  // secretStream version
    }

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, p.version);
    Uint::encode(state, flags);
    Uint::encode(state, p.error);
    Uint::encode(state, p.firewall);

    if (!p.addresses4.empty()) {
        Array<Ipv4Addr, Ipv4Address>::encode(state, p.addresses4);
    }
    if (p.udx.has_value()) {
        Uint::encode(state, p.udx->version);
        Uint::encode(state, p.udx->reusable_socket ? 1u : 0u);
        Uint::encode(state, p.udx->id);
        Uint::encode(state, p.udx->seq);
    }
    if (p.has_secret_stream) {
        Uint::encode(state, 1u);
    }

    return buf;
}

NoisePayload decode_noise_payload(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    NoisePayload p;

    p.version = static_cast<uint32_t>(Uint::decode(state));
    if (state.error || p.version != 1) return p;

    uint32_t flags = static_cast<uint32_t>(Uint::decode(state));
    p.error = static_cast<uint32_t>(Uint::decode(state));
    p.firewall = static_cast<uint32_t>(Uint::decode(state));

    if (flags & 1) {
        // holepunch info — skip for now (read id + relays)
        auto hp_id = static_cast<uint32_t>(Uint::decode(state));
        auto relays = Array<Ipv4Addr, Ipv4Address>::decode(state);  // relayInfo is 2x ipv4
        (void)hp_id;
        (void)relays;
    }
    if (flags & 2) {
        p.addresses4 = Array<Ipv4Addr, Ipv4Address>::decode(state);
    }
    if (flags & 4) {
        // addresses6 — skip
        auto addrs6 = Array<Ipv4Addr, Ipv4Address>::decode(state);
        (void)addrs6;
    }
    if (flags & 8) {
        UdxInfo info;
        info.version = static_cast<uint32_t>(Uint::decode(state));
        uint32_t features = static_cast<uint32_t>(Uint::decode(state));
        info.reusable_socket = (features & 1) != 0;
        info.id = static_cast<uint32_t>(Uint::decode(state));
        info.seq = static_cast<uint32_t>(Uint::decode(state));
        p.udx = info;
    }
    if (flags & 16) {
        auto ss_version = static_cast<uint32_t>(Uint::decode(state));
        (void)ss_version;
        p.has_secret_stream = true;
    }
    // flags & 32: relayThrough — skip
    // flags & 64: relayAddresses — skip

    return p;
}

// ---------------------------------------------------------------------------
// Handshake message encoding (DHT RPC value wrapper)
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_handshake_msg(const HandshakeMessage& m) {
    State state;

    uint8_t flags = 0;
    if (m.peer_address.has_value()) flags |= 1;
    if (m.relay_address.has_value()) flags |= 2;

    Uint::preencode(state, flags);
    Uint::preencode(state, m.mode);
    Buffer::preencode(state, m.noise.data(), m.noise.size());
    if (m.peer_address.has_value()) Ipv4Addr::preencode(state, *m.peer_address);
    if (m.relay_address.has_value()) Ipv4Addr::preencode(state, *m.relay_address);

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, flags);
    Uint::encode(state, m.mode);
    Buffer::encode(state, m.noise.data(), m.noise.size());
    if (m.peer_address.has_value()) Ipv4Addr::encode(state, *m.peer_address);
    if (m.relay_address.has_value()) Ipv4Addr::encode(state, *m.relay_address);

    return buf;
}

HandshakeMessage decode_handshake_msg(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    HandshakeMessage m;

    uint8_t flags = static_cast<uint8_t>(Uint::decode(state));
    m.mode = static_cast<uint32_t>(Uint::decode(state));

    auto noise_result = Buffer::decode(state);
    if (!noise_result.is_null()) {
        m.noise.assign(noise_result.data, noise_result.data + noise_result.len);
    }

    if (flags & 1) {
        m.peer_address = Ipv4Addr::decode(state);
    }
    if (flags & 2) {
        m.relay_address = Ipv4Addr::decode(state);
    }

    return m;
}

// ---------------------------------------------------------------------------
// PEER_HANDSHAKE — initiate Noise IK through DHT relay
// ---------------------------------------------------------------------------

void peer_handshake(rpc::RpcSocket& socket,
                    const compact::Ipv4Address& relay_addr,
                    const noise::Keypair& our_keypair,
                    const noise::PubKey& remote_pubkey,
                    uint32_t our_udx_id,
                    OnHandshakeCallback on_done) {

    // Create Noise IK initiator with real prologue
    auto* noise_ik = new noise::NoiseIK(true, our_keypair,
                                         PROLOGUE.data(), PROLOGUE.size(),
                                         &remote_pubkey);

    // Build noisePayload for msg1
    NoisePayload payload;
    payload.version = 1;
    payload.error = ERROR_NONE;
    payload.firewall = FIREWALL_UNKNOWN;
    payload.udx = UdxInfo{1, false, our_udx_id, 0};
    payload.has_secret_stream = true;

    auto payload_bytes = encode_noise_payload(payload);

    // Encrypt payload inside Noise msg1
    auto noise_msg1 = noise_ik->send(payload_bytes.data(), payload_bytes.size());

    // Wrap in handshake message
    HandshakeMessage hs_msg;
    hs_msg.mode = MODE_FROM_CLIENT;
    hs_msg.noise = std::move(noise_msg1);

    auto hs_value = encode_handshake_msg(hs_msg);

    // Compute target = BLAKE2b-256(remote_pubkey)
    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, remote_pubkey.data(), 32, nullptr, 0);

    // Send as DHT RPC request
    messages::Request req;
    req.to.addr = relay_addr;
    req.command = messages::CMD_PEER_HANDSHAKE;
    req.target = target;
    req.value = std::move(hs_value);

    socket.request(req,
        [noise_ik, on_done](const messages::Response& resp) {
            HandshakeResult result;

            if (!resp.value.has_value() || resp.value->empty()) {
                result.success = false;
                on_done(result);
                delete noise_ik;
                return;
            }

            // Decode handshake message wrapper
            auto hs_resp = decode_handshake_msg(resp.value->data(), resp.value->size());
            if (hs_resp.noise.empty()) {
                result.success = false;
                on_done(result);
                delete noise_ik;
                return;
            }

            // Process Noise msg2
            auto decrypted = noise_ik->recv(hs_resp.noise.data(), hs_resp.noise.size());
            if (!decrypted.has_value() || !noise_ik->is_complete()) {
                result.success = false;
                on_done(result);
                delete noise_ik;
                return;
            }

            // Decode the noisePayload from msg2
            result.remote_payload = decode_noise_payload(
                decrypted->data(), decrypted->size());

            result.success = (result.remote_payload.error == ERROR_NONE);
            result.tx_key = noise_ik->tx_key();
            result.rx_key = noise_ik->rx_key();
            result.handshake_hash = noise_ik->handshake_hash();

            // Remote public key is the one we connected to
            // (we already know it since IK pattern pre-shares it)
            // but we could also extract from noise_ik->rs if needed

            on_done(result);
            delete noise_ik;
        },
        [noise_ik, on_done](uint16_t) {
            HandshakeResult result;
            result.success = false;
            on_done(result);
            delete noise_ik;
        });
}

}  // namespace peer_connect
}  // namespace hyperdht
