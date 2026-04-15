// Server-side connection state machine — handles an incoming
// PEER_HANDSHAKE as Noise IK responder, runs PEER_HOLEPUNCH, then
// establishes the UDX stream and SecretStream for the application.
//
// =========================================================================
// JS FLOW MAP — how this file maps to the JavaScript reference
// =========================================================================
//
// C++ function                       Line  JS file (server.js)       JS lines
// ─────────────────────────────────── ────  ────────────────────────  ────────
// handle_handshake                    112  server.js                237-388
//   ├─ Noise IK responder             121  noise-wrap.js             29-67
//   ├─ Client payload decrypt         131  server.js                246-261
//   ├─ Firewall hook                  144  server.js                350-358
//   ├─ Version + udx checks           157  server.js                359-363
//   ├─ Build server NoisePayload      179  server.js                369-388
//   └─ Derive holepunchSecret         219  server.js                437
//
// handle_holepunch                    255  server.js                483-600
//   ├─ Outer message decode           265  server.js                484-490
//   ├─ Payload decrypt                276  server.js                492-493
//   ├─ Token echo verification        317  server.js                505-506
//   ├─ Remote state update            314  server.js                513-516
//   └─ Build encrypted response       333  server.js                586-600
// =========================================================================

#include "hyperdht/server_connection.hpp"

#include <sodium.h>

#include <cstdio>
#include <cstring>

#include "hyperdht/dht_messages.hpp"

namespace hyperdht {
namespace server_connection {

ServerConnection::~ServerConnection() {
    if (raw_stream) {
        udx_stream_destroy(raw_stream);
        // The finalize callback (set during init) will delete the memory
        raw_stream = nullptr;
    }
}

ServerConnection::ServerConnection(ServerConnection&& other) noexcept
    : id(other.id), round(other.round),
      tx_key(other.tx_key), rx_key(other.rx_key),
      handshake_hash(other.handshake_hash),
      remote_public_key(other.remote_public_key),
      remote_payload(std::move(other.remote_payload)),
      reply_noise(std::move(other.reply_noise)),
      secure(std::move(other.secure)),
      local_udx_id(other.local_udx_id),
      raw_stream(other.raw_stream),
      our_firewall(other.our_firewall),
      our_addresses(std::move(other.our_addresses)),
      firewalled(other.firewalled),
      has_error(other.has_error),
      error_code(other.error_code),
      puncher(std::move(other.puncher)),
      created_at(other.created_at) {
    other.raw_stream = nullptr;  // Transfer ownership
}

ServerConnection& ServerConnection::operator=(ServerConnection&& other) noexcept {
    if (this != &other) {
        if (raw_stream) udx_stream_destroy(raw_stream);
        id = other.id;
        round = other.round;
        tx_key = other.tx_key;
        rx_key = other.rx_key;
        handshake_hash = other.handshake_hash;
        remote_public_key = other.remote_public_key;
        remote_payload = std::move(other.remote_payload);
        reply_noise = std::move(other.reply_noise);
        secure = std::move(other.secure);
        local_udx_id = other.local_udx_id;
        raw_stream = other.raw_stream;
        other.raw_stream = nullptr;
        our_firewall = other.our_firewall;
        our_addresses = std::move(other.our_addresses);
        firewalled = other.firewalled;
        has_error = other.has_error;
        error_code = other.error_code;
        puncher = std::move(other.puncher);
        created_at = other.created_at;
    }
    return *this;
}

// ---------------------------------------------------------------------------
// handle_handshake — Noise IK responder + build NoisePayload reply
//
// JS: .analysis/js/hyperdht/lib/server.js:237-388 (_addHandshake — the
//                                                  recv→firewall→error→
//                                                  payload→handshake.send block)
//     .analysis/js/hyperdht/lib/noise-wrap.js (createHandshake helper)
//
// C++ diffs from JS:
//   - Synchronous (no Promise) — firewall callback is sync; JS awaits.
//   - `has_remote_address` flag mirrors JS `dht.remoteAddress()` check:
//     when true, reports FIREWALL_OPEN and omits holepunch relays.
//   - Holepunch secret derivation lives at the bottom of this fn rather
//     than in the caller (JS: `new SecurePayload(h.holepunchSecret)`
//     server.js:435).
//   - relay_addresses are inserted into the response payload; JS does
//     this at server.js:368.
// ---------------------------------------------------------------------------

std::optional<ServerConnection> handle_handshake(
    const noise::Keypair& server_keypair,
    const std::vector<uint8_t>& noise_msg1,
    const compact::Ipv4Address& client_address,
    int holepunch_id,
    const std::vector<compact::Ipv4Address>& our_addresses,
    const std::vector<peer_connect::RelayInfo>& relay_infos,
    FirewallFn firewall,
    bool has_remote_address,
    const std::optional<peer_connect::RelayThroughInfo>& relay_through) {

    ServerConnection conn;
    conn.id = holepunch_id;
    conn.our_addresses = our_addresses;

    // Step 1: Create Noise IK responder
    // Responder doesn't know the remote's static key ahead of time (learns from msg1)
    const auto& prol = dht_messages::ns_peer_handshake();
    noise::NoiseIK noise_ik(false, server_keypair, prol.data(), prol.size());

    // Step 2: Receive Noise msg1 — decrypts client's payload
    auto decrypted = noise_ik.recv(noise_msg1.data(), noise_msg1.size());
    if (!decrypted.has_value()) {
        return std::nullopt;
    }

    // Decode client's NoisePayload
    conn.remote_payload = peer_connect::decode_noise_payload(
        decrypted->data(), decrypted->size());

    // Extract client's public key from the Noise handshake
    conn.remote_public_key = noise_ik.remote_public_key();

    // Step 3: Firewall check
    if (firewall) {
        bool rejected = firewall(conn.remote_public_key,
                                  conn.remote_payload, client_address);
        if (rejected) {
            conn.firewalled = true;
            conn.has_error = true;
            conn.error_code = peer_connect::ERROR_ABORTED;
            // Still need to send a reply (with error) so the client doesn't hang
        }
    }

    // Step 4: Determine error code
    if (!conn.has_error) {
        if (conn.remote_payload.version != 1) {
            conn.error_code = peer_connect::ERROR_VERSION_MISMATCH;
            conn.has_error = true;
        } else if (!conn.remote_payload.udx.has_value()) {
            conn.error_code = peer_connect::ERROR_ABORTED;
            conn.has_error = true;
        }
    }

    // Step 5: Assign UDX stream ID (random)
    uint32_t udx_id;
    randombytes_buf(&udx_id, sizeof(udx_id));
    conn.local_udx_id = udx_id;

    // Step 6: Determine our firewall status
    // JS: server.js:271 — `const ourRemoteAddr = this.dht.remoteAddress()`
    // JS: server.js:358 — firewall reported based on remoteAddress presence
    // If we have a public address (has_remote_address), report OPEN.
    // Otherwise report CONSISTENT (we're behind NAT but port-stable).
    if (has_remote_address) {
        conn.our_firewall = peer_connect::FIREWALL_OPEN;
    } else {
        conn.our_firewall = our_addresses.empty()
            ? peer_connect::FIREWALL_UNKNOWN
            : peer_connect::FIREWALL_CONSISTENT;
    }

    // Step 7: Build our response NoisePayload
    peer_connect::NoisePayload response;
    response.version = 1;
    response.error = conn.error_code;
    response.firewall = conn.our_firewall;
    response.addresses4 = our_addresses;
    response.has_secret_stream = true;

    if (!conn.has_error) {
        response.udx = peer_connect::UdxInfo{
            1,     // version
            false, // reusableSocket (simplified for now)
            conn.local_udx_id,
            0      // seq
        };

        // JS: server.js:358 — `holepunch: ourRemoteAddr ? null : { id, relays }`
        // If we have a public address, omit holepunch info → client connects
        // directly using our addresses4 (no holepunch rounds needed).
        if (!has_remote_address) {
            peer_connect::HolepunchInfo hp_info;
            hp_info.id = static_cast<uint32_t>(holepunch_id);
            for (const auto& ri : relay_infos) {
                hp_info.relays.push_back(ri);
            }
            response.holepunch = hp_info;
        }

        // relayAddresses — JS: relayAddresses.length ? relayAddresses : null
        for (const auto& ri : relay_infos) {
            response.relay_addresses.push_back(ri.relay_address);
        }

        // Phase E: include relayThrough if server is configured for blind relay
        // JS: server.js:367 — relayThrough: relayThrough ? { publicKey, token } : null
        response.relay_through = relay_through;
    }

    // Step 8: Encode and encrypt our response via Noise msg2
    auto payload_bytes = peer_connect::encode_noise_payload(response);
    auto noise_msg2 = noise_ik.send(payload_bytes.data(), payload_bytes.size());

    if (!noise_ik.is_complete()) {
        return std::nullopt;
    }

    conn.reply_noise = std::move(noise_msg2);

    // Step 9: Extract transport keys and handshake hash
    conn.tx_key = noise_ik.tx_key();
    conn.rx_key = noise_ik.rx_key();
    conn.handshake_hash = noise_ik.handshake_hash();

    // Step 10: Derive holepunch secret (for PEER_HOLEPUNCH encryption)
    if (!conn.has_error) {
        const auto& ns_hp = dht_messages::ns_peer_holepunch();
        std::array<uint8_t, 32> hp_secret{};
        crypto_generichash(hp_secret.data(), 32,
                           ns_hp.data(), 32,
                           conn.handshake_hash.data(), 64);
        conn.secure = std::make_unique<holepunch::SecurePayload>(hp_secret);
    }

    return conn;
}

// ---------------------------------------------------------------------------
// handle_holepunch — server-side PEER_HOLEPUNCH processing
//
// JS: .analysis/js/hyperdht/lib/server.js:483-600 (_onpeerholepunch body —
//     decrypt → check error → update round → analyze → fast-path ping →
//     decide to punch → encrypt response)
//     .analysis/js/hyperdht/lib/server.js:602-623 (_abort — error response)
//
// C++ diffs from JS:
//   - No `p.analyze(false/true)` step. We treat client.punching as
//     authoritative ("they say they're punching → we should punch too").
//   - Token echo verification matches JS: `echoed = isServerRelay &&
//     remoteToken && equals(token, remoteToken)` (server.js:506).
//   - Always returns a response (JS does too unless we _abort with null).
// ---------------------------------------------------------------------------

HolepunchReply handle_holepunch(
    ServerConnection& conn,
    const std::vector<uint8_t>& value,
    const compact::Ipv4Address& client_address,
    uint32_t our_firewall,
    const std::vector<compact::Ipv4Address>& our_addresses,
    bool is_server_relay) {

    HolepunchReply reply;

    if (!conn.secure) {
        return reply;  // No holepunch secret — cannot process
    }

    // Decode the PEER_HOLEPUNCH message wrapper
    auto hp_msg = holepunch::decode_holepunch_msg(value.data(), value.size());
    if (hp_msg.payload.empty()) {
        return reply;
    }

    // Decrypt the holepunch payload
    auto decrypted = conn.secure->decrypt(hp_msg.payload.data(), hp_msg.payload.size());
    if (!decrypted) {
        return reply;
    }

    // Parse the client's holepunch payload
    auto client_hp = holepunch::decode_holepunch_payload(
        decrypted->data(), decrypted->size());

    // Check for client error
    if (client_hp.error != peer_connect::ERROR_NONE) {
        if (client_hp.round >= static_cast<uint32_t>(conn.round)) {
            conn.round = static_cast<int>(client_hp.round);
        }
        // Client is aborting — build error response matching JS _abort()
        holepunch::HolepunchPayload resp;
        resp.error = peer_connect::ERROR_ABORTED;
        resp.firewall = peer_connect::FIREWALL_UNKNOWN;
        resp.round = static_cast<uint32_t>(conn.round);
        auto resp_bytes = holepunch::encode_holepunch_payload(resp);
        auto encrypted = conn.secure->encrypt(resp_bytes.data(), resp_bytes.size());

        holepunch::HolepunchMessage resp_msg;
        resp_msg.mode = peer_connect::MODE_FROM_SERVER;
        resp_msg.id = 0;
        resp_msg.payload = std::move(encrypted);
        resp_msg.peer_address = client_address;

        reply.value = holepunch::encode_holepunch_msg(resp_msg);
        return reply;
    }

    // Update round
    if (client_hp.round >= static_cast<uint32_t>(conn.round)) {
        conn.round = static_cast<int>(client_hp.round);
    }

    // Extract client's info
    reply.remote_firewall = client_hp.firewall;
    reply.remote_addresses = client_hp.addresses;

    // Generate our token for the client's address
    auto our_token = conn.secure->token(client_address.host_string());

    // JS: echoed = isServerRelay && !!remoteToken && equals(token, remoteToken)
    // If the client echoed our token, their address is verified (they're at peerAddress)
    bool echoed = is_server_relay &&
                  client_hp.remote_token.has_value() &&
                  (our_token == *client_hp.remote_token);
    reply.address_verified = echoed;

    // If client is punching → we should start probing too
    if (client_hp.punching && !client_hp.addresses.empty()) {
        reply.should_punch = true;
    }

    // Build response payload
    holepunch::HolepunchPayload resp;
    resp.error = peer_connect::ERROR_NONE;
    resp.firewall = our_firewall;
    resp.round = static_cast<uint32_t>(conn.round);
    resp.punching = reply.should_punch;
    resp.connected = false;
    resp.addresses = our_addresses;
    // remote_address is always null in JS server responses
    // JS: token only returned if request came from a known relay (isServerRelay)
    if (is_server_relay) {
        resp.token = our_token;
    }
    if (client_hp.token.has_value()) {
        resp.remote_token = client_hp.token;
    }

    auto resp_bytes = holepunch::encode_holepunch_payload(resp);
    auto encrypted = conn.secure->encrypt(resp_bytes.data(), resp_bytes.size());

    holepunch::HolepunchMessage resp_msg;
    resp_msg.mode = peer_connect::MODE_FROM_SERVER;
    resp_msg.id = 0;
    resp_msg.payload = std::move(encrypted);
    resp_msg.peer_address = client_address;

    reply.value = holepunch::encode_holepunch_msg(resp_msg);
    return reply;
}

}  // namespace server_connection
}  // namespace hyperdht
