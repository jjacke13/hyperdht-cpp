#include "hyperdht/rpc_handlers.hpp"

#include <cassert>

namespace hyperdht {
namespace rpc {

RpcHandlers::RpcHandlers(RpcSocket& socket, router::Router* router)
    : socket_(socket), router_(router) {}

void RpcHandlers::install() {
    socket_.on_request([this](const messages::Request& req) {
        handle(req);
    });
}

void RpcHandlers::handle(const messages::Request& req) {
    static int req_count = 0;
    if (++req_count <= 5 || !req.internal) {
        fprintf(stderr, "  [handlers] req #%d: int=%d cmd=%u from %s:%u\n",
                req_count, req.internal ? 1 : 0, req.command,
                req.from.addr.host_string().c_str(), req.from.addr.port);
    }
    if (req.internal) {
        switch (req.command) {
            case messages::CMD_PING:      handle_ping(req); break;
            case messages::CMD_PING_NAT:  handle_ping_nat(req); break;
            case messages::CMD_FIND_NODE: handle_find_node(req); break;
            case messages::CMD_DOWN_HINT: handle_down_hint(req); break;
            default: break;
        }
    } else {
        fprintf(stderr, "  [handlers] ext cmd=%u from %s:%u\n",
                req.command, req.from.addr.host_string().c_str(), req.from.addr.port);
        switch (req.command) {
            case messages::CMD_PEER_HANDSHAKE:
                if (router_) {
                    router_->handle_peer_handshake(req,
                        [this](const messages::Response& resp) { socket_.reply(resp); },
                        [this](const messages::Request& req) {
                            auto buf = messages::encode_request(req);
                            socket_.udp_send(buf, req.to.addr);
                        });
                }
                break;
            case messages::CMD_PEER_HOLEPUNCH:
                if (router_) {
                    router_->handle_peer_holepunch(req,
                        [this](const messages::Response& resp) { socket_.reply(resp); },
                        [this](const messages::Request& req) {
                            auto buf = messages::encode_request(req);
                            socket_.udp_send(buf, req.to.addr);
                        });
                }
                break;
            case messages::CMD_FIND_PEER:  handle_find_peer(req); break;
            case messages::CMD_LOOKUP:     handle_lookup(req); break;
            case messages::CMD_ANNOUNCE:   handle_announce(req); break;
            case messages::CMD_UNANNOUNCE: handle_unannounce(req); break;
            default: break;
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: build a response with our ID, token, and closer nodes
// ---------------------------------------------------------------------------

messages::Response RpcHandlers::make_query_response(const messages::Request& req) {
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    resp.id = socket_.table().id();
    resp.token = socket_.token_store().create(req.from.addr.host_string());

    if (req.target.has_value()) {
        routing::NodeId target{};
        std::copy(req.target->begin(), req.target->end(), target.begin());

        auto closest = socket_.table().closest(target);
        for (const auto* node : closest) {
            resp.closer_nodes.push_back(
                compact::Ipv4Address::from_string(node->host, node->port));
        }
    }

    return resp;
}

// ---------------------------------------------------------------------------
// PING — reply with our node ID and a token for the sender
// ---------------------------------------------------------------------------

void RpcHandlers::handle_ping(const messages::Request& req) {
    auto resp = make_query_response(req);
    resp.closer_nodes.clear();  // PING doesn't return closer nodes
    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// PING_NAT — reply to the sender's specified port (for NAT detection)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_ping_nat(const messages::Request& req) {
    if (!req.value.has_value() || req.value->size() < 2) return;

    uint16_t port = static_cast<uint16_t>((*req.value)[0])
                  | (static_cast<uint16_t>((*req.value)[1]) << 8);
    if (port == 0) return;

    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = compact::Ipv4Address::from_string(
        req.from.addr.host_string(), port);

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// FIND_NODE — return the k closest nodes to the target
// ---------------------------------------------------------------------------

void RpcHandlers::handle_find_node(const messages::Request& req) {
    auto resp = make_query_response(req);
    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// DOWN_HINT — remove a reportedly-down node from our routing table
// ---------------------------------------------------------------------------

void RpcHandlers::handle_down_hint(const messages::Request& req) {
    // No reply needed for DOWN_HINT (fire-and-forget)
    (void)req;
}

// ---------------------------------------------------------------------------
// FIND_PEER — return a single stored peer record for the target
// ---------------------------------------------------------------------------

void RpcHandlers::handle_find_peer(const messages::Request& req) {
    if (!req.target.has_value()) return;

    auto resp = make_query_response(req);

    // Look up the target in our announce store
    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    // Check Router first (self-announcing servers)
    if (router_) {
        const auto* rec = router_->record(target);
        if (rec) {
            resp.value = *rec;
            socket_.reply(resp);
            return;
        }
    }

    // Fall back to announce store
    auto peers = store_.get(target);
    if (!peers.empty()) {
        resp.value = peers.back().value;
    }

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// LOOKUP — return all stored peer records for the target (up to 20)
// ---------------------------------------------------------------------------

void RpcHandlers::handle_lookup(const messages::Request& req) {
    if (!req.target.has_value()) return;

    auto resp = make_query_response(req);

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    auto peers = store_.get(target);
    if (peers.size() > announce::MAX_PEERS_PER_TARGET) {
        peers.resize(announce::MAX_PEERS_PER_TARGET);
    }

    if (!peers.empty()) {
        // Encode all peer values as a length-prefixed array.
        // Format: varint(count) + [varint(len) + value_bytes]...
        compact::State state;
        compact::Uint::preencode(state, static_cast<uint64_t>(peers.size()));
        for (const auto& p : peers) {
            compact::Buffer::preencode(state, p.value.data(), p.value.size());
        }

        std::vector<uint8_t> buf(state.end);
        state.buffer = buf.data();
        state.start = 0;

        compact::Uint::encode(state, static_cast<uint64_t>(peers.size()));
        for (const auto& p : peers) {
            compact::Buffer::encode(state, p.value.data(), p.value.size());
        }

        if (!state.error) {
            resp.value = std::move(buf);
        }
    }

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// ANNOUNCE — validate token and store peer announcement
// ---------------------------------------------------------------------------

void RpcHandlers::handle_announce(const messages::Request& req) {
    if (!req.target.has_value()) return;
    if (!req.token.has_value()) return;

    // Validate token: must match what we issued for this sender
    if (!socket_.token_store().validate(
            req.from.addr.host_string(), *req.token)) {
        return;  // Silently reject invalid token
    }

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    // Store the announcement
    assert(socket_.loop() != nullptr);
    announce::PeerAnnouncement ann;
    ann.from = req.from.addr;
    ann.value = req.value.value_or(std::vector<uint8_t>{});
    ann.created_at = uv_now(socket_.loop());
    ann.ttl = announce::DEFAULT_TTL_MS;

    store_.put(target, ann);

    // Reply with no closer nodes (JS: { token: false, closerNodes: false })
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    resp.id = socket_.table().id();

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// UNANNOUNCE — validate token and remove peer announcement
// ---------------------------------------------------------------------------

void RpcHandlers::handle_unannounce(const messages::Request& req) {
    if (!req.target.has_value()) return;
    if (!req.token.has_value()) return;

    // Validate token
    if (!socket_.token_store().validate(
            req.from.addr.host_string(), *req.token)) {
        return;
    }

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    // Remove the announcement from this sender
    store_.remove(target, req.from.addr);

    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    resp.id = socket_.table().id();

    socket_.reply(resp);
}

}  // namespace rpc
}  // namespace hyperdht
