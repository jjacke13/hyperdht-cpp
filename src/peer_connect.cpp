// PEER_HANDSHAKE implementation — sends the initiator Noise msg1 to a
// relay DHT node, awaits the responder msg2, and produces a handshake
// result (keys, hash, encrypted payload) for the holepunch stage.
//
// Input validation: relay_count in NoisePayload capped at 128.

#include "hyperdht/peer_connect.hpp"

#include <sodium.h>

#include <cstring>
#include <memory>

namespace hyperdht {
namespace peer_connect {

using compact::State;
using compact::Uint;
using compact::Buffer;
using compact::Fixed32;
using compact::Ipv4Addr;
using compact::Ipv4Address;
using compact::Ipv6Addr;
using compact::Ipv6Address;
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

static const std::array<uint8_t, 32>& prologue() {
    static const auto value = compute_prologue();
    return value;
}

// ---------------------------------------------------------------------------
// NoisePayload encoding — the inner payload that travels inside the
// Noise IK ciphertext (peer firewall, addresses, UDX info, relay hints).
//
// JS: .analysis/js/hyperdht/lib/messages.js:156-226 (noisePayload codec)
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_noise_payload(const NoisePayload& p) {
    State state;

    // version + flags + error + firewall (4 varints, typically 4 bytes)
    Uint::preencode(state, p.version);
    uint32_t flags = 0;
    if (p.holepunch.has_value()) flags |= 1;
    if (!p.addresses4.empty()) flags |= 2;
    if (!p.addresses6.empty()) flags |= 4;
    if (p.udx.has_value()) flags |= 8;
    if (p.has_secret_stream) flags |= 16;
    if (p.relay_through.has_value()) flags |= 32;
    if (!p.relay_addresses.empty()) flags |= 64;
    Uint::preencode(state, flags);
    Uint::preencode(state, p.error);
    Uint::preencode(state, p.firewall);

    if (p.holepunch.has_value()) {
        Uint::preencode(state, p.holepunch->id);
        Uint::preencode(state, static_cast<uint64_t>(p.holepunch->relays.size()));
        for (const auto& ri : p.holepunch->relays) {
            Ipv4Addr::preencode(state, ri.relay_address);
            Ipv4Addr::preencode(state, ri.peer_address);
        }
    }
    if (!p.addresses4.empty()) {
        Array<Ipv4Addr, Ipv4Address>::preencode(state, p.addresses4);
    }
    if (!p.addresses6.empty()) {
        Array<Ipv6Addr, Ipv6Address>::preencode(state, p.addresses6);
    }
    if (p.udx.has_value()) {
        Uint::preencode(state, p.udx->version);
        Uint::preencode(state, p.udx->reusable_socket ? 1u : 0u);
        Uint::preencode(state, p.udx->id);
        Uint::preencode(state, p.udx->seq);
    }
    if (p.has_secret_stream) {
        Uint::preencode(state, 1u);
    }
    if (p.relay_through.has_value()) {
        Uint::preencode(state, p.relay_through->version);
        Uint::preencode(state, 0u);  // flags (reserved, always 0)
        Fixed32::preencode(state, p.relay_through->public_key);
        Fixed32::preencode(state, p.relay_through->token);
    }
    if (!p.relay_addresses.empty()) {
        Array<Ipv4Addr, Ipv4Address>::preencode(state, p.relay_addresses);
    }

    std::vector<uint8_t> buf(state.end);
    state.buffer = buf.data();
    state.start = 0;

    Uint::encode(state, p.version);
    Uint::encode(state, flags);
    Uint::encode(state, p.error);
    Uint::encode(state, p.firewall);

    if (p.holepunch.has_value()) {
        Uint::encode(state, p.holepunch->id);
        Uint::encode(state, static_cast<uint64_t>(p.holepunch->relays.size()));
        for (const auto& ri : p.holepunch->relays) {
            Ipv4Addr::encode(state, ri.relay_address);
            Ipv4Addr::encode(state, ri.peer_address);
        }
    }
    if (!p.addresses4.empty()) {
        Array<Ipv4Addr, Ipv4Address>::encode(state, p.addresses4);
    }
    if (!p.addresses6.empty()) {
        Array<Ipv6Addr, Ipv6Address>::encode(state, p.addresses6);
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
    if (p.relay_through.has_value()) {
        Uint::encode(state, p.relay_through->version);
        Uint::encode(state, 0u);  // flags
        Fixed32::encode(state, p.relay_through->public_key);
        Fixed32::encode(state, p.relay_through->token);
    }
    if (!p.relay_addresses.empty()) {
        Array<Ipv4Addr, Ipv4Address>::encode(state, p.relay_addresses);
    }

    return buf;
}

NoisePayload decode_noise_payload(const uint8_t* data, size_t len) {
    State state = State::for_decode(data, len);
    NoisePayload p;

    p.version = static_cast<uint32_t>(Uint::decode(state));
    if (state.error || p.version != 1) {
        p.error = ERROR_VERSION_MISMATCH;
        return p;
    }

    uint32_t flags = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;
    p.error = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;
    p.firewall = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return p;

    if (flags & 1) {
        // holepunchInfo: { id: uint, relays: array of { relayAddress: ipv4, peerAddress: ipv4 } }
        HolepunchInfo hp;
        hp.id = static_cast<uint32_t>(Uint::decode(state));
        if (state.error) return p;
        auto relay_count = static_cast<uint32_t>(Uint::decode(state));
        if (state.error) return p;
        if (relay_count > 128) { state.error = true; return p; }  // C4: cap relay count
        for (uint32_t i = 0; i < relay_count && !state.error; i++) {
            RelayInfo ri;
            ri.relay_address = Ipv4Addr::decode(state);
            if (state.error) return p;
            ri.peer_address = Ipv4Addr::decode(state);
            if (state.error) return p;
            hp.relays.push_back(ri);
        }
        p.holepunch = hp;
    }
    if (flags & 2) {
        p.addresses4 = Array<Ipv4Addr, Ipv4Address>::decode(state);
        if (state.error) return p;
    }
    if (flags & 4) {
        p.addresses6 = Array<Ipv6Addr, Ipv6Address>::decode(state);
        if (state.error) return p;
    }
    if (flags & 8) {
        UdxInfo info;
        info.version = static_cast<uint32_t>(Uint::decode(state));
        if (state.error) return p;
        uint32_t features = static_cast<uint32_t>(Uint::decode(state));
        if (state.error) return p;
        info.reusable_socket = (features & 1) != 0;
        info.id = static_cast<uint32_t>(Uint::decode(state));
        if (state.error) return p;
        info.seq = static_cast<uint32_t>(Uint::decode(state));
        if (state.error) return p;
        p.udx = info;
    }
    if (flags & 16) {
        auto ss_version = static_cast<uint32_t>(Uint::decode(state));
        if (state.error) return p;
        (void)ss_version;
        p.has_secret_stream = true;
    }
    if (flags & 32) {
        RelayThroughInfo rt;
        rt.version = static_cast<uint32_t>(Uint::decode(state));
        if (state.error) return p;
        Uint::decode(state);  // flags (reserved)
        if (state.error) return p;
        rt.public_key = Fixed32::decode(state);
        if (state.error) return p;
        rt.token = Fixed32::decode(state);
        if (state.error) return p;
        p.relay_through = rt;
    }
    if (flags & 64) {
        p.relay_addresses = Array<Ipv4Addr, Ipv4Address>::decode(state);
        if (state.error) return p;
    }

    return p;
}

// ---------------------------------------------------------------------------
// Handshake message encoding (DHT RPC value wrapper).
//
// JS: .analysis/js/hyperdht/lib/messages.js:30-55 (exports.handshake)
//
// This is the outer wrapper that sits in `req.value` for PEER_HANDSHAKE.
// It carries the Noise message bytes plus optional peer/relay addresses
// used by the relaying node, with a `mode` discriminator for from-client
// vs from-relay direction.
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
    if (state.error) return m;
    m.mode = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return m;

    auto noise_result = Buffer::decode(state);
    if (state.error) return m;
    if (!noise_result.is_null()) {
        m.noise.assign(noise_result.data, noise_result.data + noise_result.len);
    }

    if (flags & 1) {
        m.peer_address = Ipv4Addr::decode(state);
        if (state.error) return m;
    }
    if (flags & 2) {
        m.relay_address = Ipv4Addr::decode(state);
        if (state.error) return m;
    }

    return m;
}

// ---------------------------------------------------------------------------
// PEER_HANDSHAKE — initiate Noise IK through a DHT relay node.
//
// JS: .analysis/js/hyperdht/lib/noise-wrap.js:13-52 (NoiseWrap class)
//     .analysis/js/hyperdht/lib/connect.js:386-449 (connectThroughNode —
//        builds noisePayload, calls handshake.send, sends via _router)
//
// C++ diffs from JS:
//   - JS NoiseWrap stores per-connection state on a class instance;
//     we capture a shared_ptr<NoiseIK> in the response/timeout lambdas.
//   - JS computes `holepunchSecret` inside `NoiseWrap.final()`
//     (noise-wrap.js:36-38); we leave that derivation to holepunch_connect
//     so the handshake module stays free of holepunch knowledge.
//   - JS sends the request through `dht._router.peerHandshake` which adds
//     mode-flipping for relay forwarding. The C++ socket goes direct, so
//     we always emit `MODE_FROM_CLIENT`.
// ---------------------------------------------------------------------------

// Validate a PEER_HANDSHAKE reply. Shared by both peer_handshake overloads.
// Mirrors the JS validation chain:
//   router.js:63-71  — reply rejected (BAD_HANDSHAKE_REPLY) unless
//     hs.mode === REPLY && to.host === res.from.host &&
//     to.port === res.from.port && hs.noise
//   connect.js:425-436 — after Noise completes: version !== 1 →
//     SERVER_INCOMPATIBLE, error !== NONE → SERVER_ERROR, !udx →
//     SERVER_ERROR. All three are TERMINAL (whole connect fails, no
//     relay retry); the router.js checks above are per-attempt.
static HandshakeResult validate_handshake_response(
        const messages::Response& resp,
        const compact::Ipv4Address& relay_addr,
        noise::NoiseIK& noise_ik,
        const noise::PubKey& remote_pubkey) {
    HandshakeResult result;  // success=false, terminal=false

    if (!resp.value.has_value() || resp.value->empty()) return result;

    // Decode errors leave mode=MODE_FROM_CLIENT / empty noise, so they
    // fall into the checks below (JS `!hs` → BAD_HANDSHAKE_REPLY).
    auto hs_resp = decode_handshake_msg(resp.value->data(), resp.value->size());

    // JS router.js:65 — hs.mode !== REPLY.
    if (hs_resp.mode != MODE_REPLY) return result;

    // JS router.js:66-67 — the reply must come from the exact address we
    // sent the request to. The RPC layer matches responses to inflight
    // requests by tid ONLY (rpc.cpp find_inflight) — it never compares the
    // UDP source against the request's destination, so any host that
    // guesses the 16-bit tid could answer. resp.remote_addr is the actual
    // UDP source (transport-layer field set by the receive path); note
    // resp.from is the wire `to` field — the responder's view of OUR
    // address — not the sender's address.
    if (resp.remote_addr != relay_addr) return result;

    // JS router.js:68 — !hs.noise.
    if (hs_resp.noise.empty()) return result;

    auto decrypted = noise_ik.recv(hs_resp.noise.data(), hs_resp.noise.size());
    if (!decrypted.has_value() || !noise_ik.is_complete()) return result;

    result.remote_payload = decode_noise_payload(
        decrypted->data(), decrypted->size());

    // From here on the payload came from the Noise-authenticated server —
    // failures are terminal (JS destroys the connect, no relay retry).
    // JS connect.js:425-428 — payload.version !== 1 → SERVER_INCOMPATIBLE.
    if (result.remote_payload.version != 1) {
        result.terminal = true;
        return result;
    }
    // JS connect.js:429-432 — payload.error !== NONE → SERVER_ERROR.
    if (result.remote_payload.error != ERROR_NONE) {
        result.terminal = true;
        return result;
    }
    // JS connect.js:433-436 — !payload.udx → SERVER_ERROR.
    if (!result.remote_payload.udx.has_value()) {
        result.terminal = true;
        return result;
    }

    result.success = true;
    result.tx_key = noise_ik.tx_key();
    result.rx_key = noise_ik.rx_key();
    result.handshake_hash = noise_ik.handshake_hash();
    result.remote_public_key = remote_pubkey;
    // JS `router.js:46-78`: serverAddress = hs.peerAddress || to.
    // The relay's observation of where the server replied from —
    // the fresh address. Used downstream as Round 1's
    // `remote_address` field which triggers the server's
    // fast-mode punch (server.js:530-538).
    result.server_address = hs_resp.peer_address;
    // connect-6 — JS `clientAddress: res.to` (router.js:77): our address as
    // the relay observed it. `resp.from` IS the wire `to` field (see
    // messages.hpp Response docs).
    result.client_address = resp.from.addr;
    return result;
}

void peer_handshake(rpc::RpcSocket& socket,
                    const compact::Ipv4Address& relay_addr,
                    const noise::Keypair& our_keypair,
                    const noise::PubKey& remote_pubkey,
                    uint32_t our_udx_id,
                    uint32_t firewall,
                    const std::vector<compact::Ipv4Address>& addresses4,
                    OnHandshakeCallback on_done) {
    // Identical to the relayThrough overload with relay_through absent
    // (flag bit 32 unset → byte-identical wire output).
    peer_handshake(socket, relay_addr, our_keypair, remote_pubkey,
                   our_udx_id, /*reusable_socket=*/false, firewall,
                   addresses4, std::nullopt, std::move(on_done));
}

// Overload with relayThrough in the Noise payload (Phase E)
void peer_handshake(rpc::RpcSocket& socket,
                    const compact::Ipv4Address& relay_addr,
                    const noise::Keypair& our_keypair,
                    const noise::PubKey& remote_pubkey,
                    uint32_t our_udx_id,
                    bool reusable_socket,
                    uint32_t firewall,
                    const std::vector<compact::Ipv4Address>& addresses4,
                    const std::optional<RelayThroughInfo>& relay_through,
                    OnHandshakeCallback on_done) {
    // Create Noise IK initiator with real prologue
    auto noise_ik = std::make_shared<noise::NoiseIK>(true, our_keypair,
                                                      prologue().data(), prologue().size(),
                                                      &remote_pubkey);

    // Build noisePayload for msg1
    NoisePayload payload;
    payload.version = 1;
    payload.error = ERROR_NONE;
    payload.firewall = firewall;
    payload.addresses4 = addresses4;
    // connect-3 — JS connect.js:406: udx.reusableSocket = c.reusableSocket.
    payload.udx = UdxInfo{1, reusable_socket, our_udx_id, 0};
    payload.has_secret_stream = true;
    payload.relay_through = relay_through;  // Phase E: include relayThrough

    auto payload_bytes = encode_noise_payload(payload);
    auto noise_msg1 = noise_ik->send(payload_bytes.data(), payload_bytes.size());

    HandshakeMessage hs_msg;
    hs_msg.mode = MODE_FROM_CLIENT;
    hs_msg.noise = std::move(noise_msg1);
    auto hs_value = encode_handshake_msg(hs_msg);

    std::array<uint8_t, 32> target{};
    crypto_generichash(target.data(), 32, remote_pubkey.data(), 32, nullptr, 0);

    messages::Request req;
    req.to.addr = relay_addr;
    req.command = messages::CMD_PEER_HANDSHAKE;
    req.target = target;
    req.value = std::move(hs_value);

    socket.request(req,
        [noise_ik, on_done, remote_pubkey, relay_addr](const messages::Response& resp) {
            on_done(validate_handshake_response(resp, relay_addr, *noise_ik,
                                                remote_pubkey));
        },
        [on_done](uint16_t) {
            on_done(HandshakeResult{});  // success=false, terminal=false
        });
}

}  // namespace peer_connect
}  // namespace hyperdht
