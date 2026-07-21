// Router implementation — forward table for incoming PEER_HANDSHAKE
// and PEER_HOLEPUNCH. Maps target hash → ForwardEntry (the Server
// instance that listens at that key).
//
// JS: .analysis/js/hyperdht/lib/router.js:20-249 (whole Router class)
//
// C++ diffs from JS:
//   - JS uses xache `Cache` with TTL-based eviction. C++ uses a plain
//     std::unordered_map keyed by 32-byte target.
//   - JS Router both forwards AND originates client requests
//     (peerHandshake / peerHolepunch). C++ Router forwards only; client-side
//     origination lives in src/peer_connect.cpp.
//   - Both onpeerhandshake halves are ported: the server-host half (entry has
//     handlers) and the else half — a pure relay forwarding on behalf of an
//     announce-populated ForwardEntry.relay (see relay_peer_handshake /
//     relay_peer_holepunch below).
//   - Server-host FROM_SECOND_RELAY relays the FROM_SERVER reply to the
//     embedded relayAddress (the first relay), dropping it when absent
//     (router.js:118-126).

#include "hyperdht/router.hpp"

#include <cstring>

#include "hyperdht/debug.hpp"
#include "hyperdht/holepunch.hpp"

namespace hyperdht {
namespace router {

namespace {

using compact::Ipv4Address;

// Re-encode the original request toward `to` with a new value, preserving
// tid / command / target and omitting token + id. Mirrors JS io.js:425-429
// (Request.relay → _encodeRequest with token=null). ponytail: id is left
// unset to match the existing server-host relay-back path; a non-ephemeral
// relay would include it in JS, but the tid alone routes the reply home.
messages::Request make_relay_request(const messages::Request& req,
                                     const Ipv4Address& to,
                                     std::vector<uint8_t> value) {
    messages::Request out;
    out.tid = req.tid;
    out.to.addr = to;
    out.command = req.command;
    out.target = req.target;
    out.internal = false;
    out.value = std::move(value);
    return out;
}

// The else half of JS onpeerhandshake (router.js:128-171) — a node that is
// NOT the server host for this target, acting as a pure relay.
bool relay_peer_handshake(const messages::Request& req,
                          const peer_connect::HandshakeMessage& hs,
                          const std::optional<Ipv4Address>& relay_addr,
                          const Router::ReplyFn& reply,
                          const Router::RelayFn& relay,
                          const Router::CloserNodesFn& closer_nodes,
                          const announce::TargetKey& target) {
    if (hs.noise.empty()) return false;  // JS: `if (!noise) return`

    switch (hs.mode) {
        case peer_connect::MODE_FROM_CLIENT: {
            // JS router.js:130-148
            if (!relay_addr && !hs.relay_address) {
                // No relay known — help the client route closer to the target.
                // JS:135 `req.reply(null, { token: false, closerNodes: true })`.
                messages::Response resp;
                resp.tid = req.tid;
                resp.from.addr = req.from.addr;
                if (closer_nodes) resp.closer_nodes = closer_nodes(target);
                reply(resp);
                return true;
            }
            // JS:145 relay to `relayAddress || relay`.
            const Ipv4Address& dest =
                hs.relay_address ? *hs.relay_address : *relay_addr;
            peer_connect::HandshakeMessage fwd;
            fwd.mode = peer_connect::MODE_FROM_RELAY;
            fwd.noise = hs.noise;
            fwd.peer_address = req.from.addr;  // JS peerAddress: req.from
            // relayAddress: null
            relay(make_relay_request(req, dest,
                    peer_connect::encode_handshake_msg(fwd)));
            return true;
        }
        case peer_connect::MODE_FROM_RELAY: {
            // JS router.js:149-161 — forward on to a second relay.
            if (!relay_addr) return false;  // JS: `if (!relay || !noise) return`
            peer_connect::HandshakeMessage fwd;
            fwd.mode = peer_connect::MODE_FROM_SECOND_RELAY;
            fwd.noise = hs.noise;
            fwd.peer_address = hs.peer_address;  // keep incoming peerAddress
            fwd.relay_address = req.from.addr;   // JS relayAddress: req.from
            relay(make_relay_request(req, *relay_addr,
                    peer_connect::encode_handshake_msg(fwd)));
            return true;
        }
        case peer_connect::MODE_FROM_SERVER: {
            // JS router.js:162-169 — bounce the server's reply to the client.
            if (!hs.peer_address) return false;  // JS: `if (!peerAddress || !noise) return`
            peer_connect::HandshakeMessage rep;
            rep.mode = peer_connect::MODE_REPLY;
            rep.noise = hs.noise;
            rep.peer_address = req.from.addr;  // JS peerAddress: req.from (the server)
            // relayAddress: null
            messages::Response resp;
            resp.tid = req.tid;
            resp.from.addr = *hs.peer_address;  // JS `{ to: peerAddress }` (the client)
            resp.value = peer_connect::encode_handshake_msg(rep);
            reply(resp);
            return true;
        }
        default:
            return false;
    }
}

// The FROM_CLIENT / FROM_SERVER cases of JS onpeerholepunch (router.js:212-247)
// that are NOT gated on the server-host handler. FROM_RELAY needs the handler
// and is served by handle_peer_holepunch's server-host branch.
bool relay_peer_holepunch(const messages::Request& req,
                          const holepunch::HolepunchMessage& hp,
                          const std::optional<Ipv4Address>& relay_addr,
                          const Router::ReplyFn& reply,
                          const Router::RelayFn& relay) {
    switch (hp.mode) {
        case peer_connect::MODE_FROM_CLIENT: {
            // JS router.js:213-219 — relay to `peerAddress || relay`.
            if (!hp.peer_address && !relay_addr) return false;
            const Ipv4Address& dest =
                hp.peer_address ? *hp.peer_address : *relay_addr;
            holepunch::HolepunchMessage fwd;
            fwd.mode = peer_connect::MODE_FROM_RELAY;
            fwd.id = hp.id;
            fwd.payload = hp.payload;
            fwd.peer_address = req.from.addr;  // JS peerAddress: req.from
            relay(make_relay_request(req, dest,
                    holepunch::encode_holepunch_msg(fwd)));
            return true;
        }
        case peer_connect::MODE_FROM_SERVER: {
            // JS router.js:239-246 — reply to `peerAddress` (falls back to
            // req.from via io.js reply()'s `opts.to || this.from`).
            holepunch::HolepunchMessage rep;
            rep.mode = peer_connect::MODE_REPLY;
            rep.id = hp.id;
            rep.payload = hp.payload;
            rep.peer_address = req.from.addr;  // JS peerAddress: req.from
            messages::Response resp;
            resp.tid = req.tid;
            resp.from.addr = hp.peer_address ? *hp.peer_address : req.from.addr;
            resp.value = holepunch::encode_holepunch_msg(rep);
            reply(resp);
            return true;
        }
        default:
            return false;  // FROM_RELAY without a server host → nothing (JS)
    }
}

}  // namespace

void Router::set(const announce::TargetKey& target, ForwardEntry entry) {
    forwards_[target] = std::move(entry);
}

ForwardEntry* Router::get(const announce::TargetKey& target) {
    auto it = forwards_.find(target);
    if (it == forwards_.end()) return nullptr;
    return &it->second;
}

void Router::remove(const announce::TargetKey& target) {
    forwards_.erase(target);
}

bool Router::has(const announce::TargetKey& target) const {
    return forwards_.count(target) > 0;
}

const std::vector<uint8_t>* Router::record(const announce::TargetKey& target) const {
    auto it = forwards_.find(target);
    if (it == forwards_.end()) return nullptr;
    if (it->second.record.empty()) return nullptr;
    return &it->second.record;
}

void Router::clear() {
    forwards_.clear();
}

// ---------------------------------------------------------------------------
// Handle incoming PEER_HANDSHAKE
//
// JS: .analysis/js/hyperdht/lib/router.js:81-172 (onpeerhandshake)
//
// Two halves, matching JS:
//   - is_server (entry has on_peer_handshake): the local Server answers.
//       FROM_CLIENT → REPLY; FROM_RELAY → relay back FROM_SERVER to req.from
//       (router.js:110-117); FROM_SECOND_RELAY → relay back FROM_SERVER to
//       the embedded relayAddress (the first relay), or drop when absent
//       (router.js:118-126).
//   - else (pure relay, entry has only ForwardEntry.relay, or no entry):
//       relay_peer_handshake() above — FROM_CLIENT → FROM_RELAY toward the
//       relay (or a closerNodes reply when none is known), FROM_RELAY →
//       FROM_SECOND_RELAY, FROM_SERVER → REPLY bounced to the client.
// ---------------------------------------------------------------------------

bool Router::handle_peer_handshake(const messages::Request& req,
                                   ReplyFn reply, RelayFn relay,
                                   CloserNodesFn closer_nodes) {
    if (!req.target.has_value() || !req.value.has_value()) {
        DHT_LOG( "  [router] HS: missing target=%d value=%d\n",
                req.target.has_value() ? 1 : 0, req.value.has_value() ? 1 : 0);
        return false;
    }

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    auto* entry = get(target);
    const bool is_server = entry && entry->on_peer_handshake;
    std::optional<compact::Ipv4Address> relay_addr =
        entry ? entry->relay : std::nullopt;

    // Decode the handshake message to extract noise bytes + peerAddress
    auto hs_msg = peer_connect::decode_handshake_msg(
        req.value->data(), req.value->size());

    if (!is_server) {
        // Not the server host for this target — act as a pure relay.
        // JS router.js:128-171 (the else half of onpeerhandshake).
        DHT_LOG( "  [router] HS: relay path, mode=%u, have_relay=%d (size=%zu)\n",
                hs_msg.mode, relay_addr.has_value() ? 1 : 0, forwards_.size());
        return relay_peer_handshake(req, hs_msg, relay_addr,
                                    reply, relay, closer_nodes, target);
    }

    DHT_LOG( "  [router] HS: target FOUND, noise=%zu bytes, mode=%u\n",
            hs_msg.noise.size(), hs_msg.mode);

    // Validate: noise bytes must be non-empty
    if (hs_msg.noise.empty()) return false;
    // Accept all valid incoming modes (FROM_CLIENT=0, FROM_RELAY=2, FROM_SECOND_RELAY=3)
    if (hs_msg.mode != peer_connect::MODE_FROM_CLIENT &&
        hs_msg.mode != peer_connect::MODE_FROM_RELAY &&
        hs_msg.mode != peer_connect::MODE_FROM_SECOND_RELAY) return false;

    // The client's address (FROM_RELAY: from the peerAddress field; FROM_CLIENT: from the packet)
    auto client_addr = hs_msg.peer_address.value_or(req.from.addr);
    auto incoming_mode = hs_msg.mode;
    // FROM_SECOND_RELAY: the first relay's address, embedded by the second
    // relay (router.js:156 `relayAddress: req.from`).
    auto relay_address = hs_msg.relay_address;

    // Capture only the fields we need (avoid copying the full Request with its value vector)
    auto req_tid = req.tid;
    auto req_from = req.from.addr;
    auto req_command = req.command;
    auto req_target = req.target;

    // Call the server's handler. It will call reply_fn with the Noise msg2.
    entry->on_peer_handshake(
        hs_msg.noise, client_addr,
        [req_tid, req_from, req_command, req_target, relay_address,
         reply, relay, client_addr, incoming_mode](std::vector<uint8_t> reply_noise) {
            DHT_LOG( "  [router] reply_fn called, noise=%zu bytes, incoming_mode=%u\n",
                    reply_noise.size(), incoming_mode);

            if (incoming_mode == peer_connect::MODE_FROM_CLIENT) {
                // Direct connection: send RESPONSE with mode=REPLY to the client
                peer_connect::HandshakeMessage resp_msg;
                resp_msg.mode = peer_connect::MODE_REPLY;
                resp_msg.noise = std::move(reply_noise);

                messages::Response resp;
                resp.tid = req_tid;
                resp.from.addr = req_from;
                resp.value = peer_connect::encode_handshake_msg(resp_msg);

                reply(resp);
            } else {
                // FROM_RELAY / FROM_SECOND_RELAY: send REQUEST back with
                // mode=FROM_SERVER. The relay node converts this to a RESPONSE
                // for the original client. TID is preserved.
                //
                // FROM_RELAY goes back to req.from (router.js:110-117).
                // FROM_SECOND_RELAY goes to the embedded relayAddress — the
                // FIRST relay, not req.from (the second relay); dropped when
                // absent (router.js:118-126 `if (!relayAddress) return`).
                if (incoming_mode == peer_connect::MODE_FROM_SECOND_RELAY &&
                    !relay_address) {
                    return;
                }
                peer_connect::HandshakeMessage relay_msg;
                relay_msg.mode = peer_connect::MODE_FROM_SERVER;
                relay_msg.noise = std::move(reply_noise);
                relay_msg.peer_address = client_addr;

                messages::Request relay_req;
                relay_req.tid = req_tid;
                relay_req.to.addr =
                    incoming_mode == peer_connect::MODE_FROM_SECOND_RELAY
                        ? *relay_address   // Back to the first relay
                        : req_from;        // Back to relay node
                relay_req.command = req_command;
                relay_req.target = req_target;
                relay_req.internal = false;
                relay_req.value = peer_connect::encode_handshake_msg(relay_msg);

                relay(relay_req);
            }
        });

    return true;
}

// ---------------------------------------------------------------------------
// Handle incoming PEER_HOLEPUNCH
//
// JS: .analysis/js/hyperdht/lib/router.js:202-248 (onpeerholepunch)
//
// JS dispatches on `mode` (single switch, only FROM_RELAY needs the handler):
//   - FROM_CLIENT: relay to peerAddress or the known forward relay
//   - FROM_RELAY:  call state.onpeerholepunch then relay back FROM_SERVER
//   - FROM_SERVER: req.reply with REPLY mode + the embedded peerAddress
// C++: when this node is the server host (entry has on_peer_holepunch), the
// existing server-host path handles it (and short-circuits FROM_CLIENT to a
// direct reply — the collapsed relay==server case). Otherwise a pure relay
// forwards via relay_peer_holepunch() above (FROM_CLIENT / FROM_SERVER only).
// ---------------------------------------------------------------------------

bool Router::handle_peer_holepunch(const messages::Request& req,
                                   ReplyFn reply, RelayFn relay) {
    if (!req.target.has_value() || !req.value.has_value()) return false;

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    auto* entry = get(target);
    std::optional<compact::Ipv4Address> relay_addr =
        entry ? entry->relay : std::nullopt;

    // Decode the holepunch message to determine the mode
    auto hp_msg = holepunch::decode_holepunch_msg(req.value->data(), req.value->size());

    if (!entry || !entry->on_peer_holepunch) {
        // Not the server host — act as a pure relay (JS router.js:212-247, the
        // FROM_CLIENT / FROM_SERVER cases that aren't gated on the handler).
        return relay_peer_holepunch(req, hp_msg, relay_addr, reply, relay);
    }

    auto incoming_mode = hp_msg.mode;
    auto client_addr = hp_msg.peer_address.value_or(req.from.addr);

    // Capture only needed fields (avoid copying the full Request)
    auto req_tid = req.tid;
    auto req_from = req.from.addr;
    auto req_command = req.command;
    auto req_target = req.target;

    // Pass the raw value and client address to the server's handler.
    // The handler decrypts/processes and calls reply_fn with the reply value.
    // NOTE: The callback returns a fully-encoded HolepunchMessage. The router
    // decodes it to overwrite the mode field (FROM_SERVER or REPLY) and
    // peerAddress, then re-encodes. This is asymmetric with the handshake path
    // (which returns raw Noise bytes) but functionally correct.
    entry->on_peer_holepunch(
        *req.value, client_addr, req.from.addr, req.to.addr,
        [req_tid, req_from, req_command, req_target,
         reply, relay, client_addr, incoming_mode](std::vector<uint8_t> reply_value) {
            if (incoming_mode == peer_connect::MODE_FROM_CLIENT) {
                // Direct: send RESPONSE to client with mode=REPLY
                auto hp_reply = holepunch::decode_holepunch_msg(
                    reply_value.data(), reply_value.size());
                hp_reply.mode = peer_connect::MODE_REPLY;
                hp_reply.peer_address = std::nullopt;

                messages::Response resp;
                resp.tid = req_tid;
                resp.from.addr = req_from;
                resp.value = holepunch::encode_holepunch_msg(hp_reply);
                reply(resp);
            } else {
                // FROM_RELAY: send REQUEST back to relay with mode=FROM_SERVER
                auto hp_relay = holepunch::decode_holepunch_msg(
                    reply_value.data(), reply_value.size());
                hp_relay.mode = peer_connect::MODE_FROM_SERVER;
                hp_relay.peer_address = client_addr;

                messages::Request relay_req;
                relay_req.tid = req_tid;
                relay_req.to.addr = req_from;
                relay_req.command = req_command;
                relay_req.target = req_target;
                relay_req.internal = false;
                relay_req.value = holepunch::encode_holepunch_msg(hp_relay);

                relay(relay_req);
            }
        });

    return true;
}

}  // namespace router
}  // namespace hyperdht
