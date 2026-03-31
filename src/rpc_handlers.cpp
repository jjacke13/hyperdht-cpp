#include "hyperdht/rpc_handlers.hpp"

namespace hyperdht {
namespace rpc {

RpcHandlers::RpcHandlers(RpcSocket& socket) : socket_(socket) {}

void RpcHandlers::install() {
    socket_.on_request([this](const messages::Request& req) {
        handle(req);
    });
}

void RpcHandlers::handle(const messages::Request& req) {
    switch (req.command) {
        case messages::CMD_PING:
            handle_ping(req);
            break;
        case messages::CMD_FIND_NODE:
            handle_find_node(req);
            break;
        case messages::CMD_DOWN_HINT:
            handle_down_hint(req);
            break;
        default:
            // Unknown command — ignore (HyperDHT commands handled separately)
            break;
    }
}

// ---------------------------------------------------------------------------
// PING — reply with our node ID and a token for the sender
// ---------------------------------------------------------------------------

void RpcHandlers::handle_ping(const messages::Request& req) {
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;  // Reply to sender's address
    resp.id = socket_.table().id();

    // Include a token for the sender
    resp.token = socket_.token_store().create(req.from.addr.host_string());

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// FIND_NODE — return the k closest nodes to the target
// ---------------------------------------------------------------------------

void RpcHandlers::handle_find_node(const messages::Request& req) {
    messages::Response resp;
    resp.tid = req.tid;
    resp.from.addr = req.from.addr;
    resp.id = socket_.table().id();

    // Include a token for the sender
    resp.token = socket_.token_store().create(req.from.addr.host_string());

    // Find closest nodes to the target
    if (req.target.has_value()) {
        // Convert target to NodeId
        routing::NodeId target{};
        std::copy(req.target->begin(), req.target->end(), target.begin());

        auto closest = socket_.table().closest(target);
        for (const auto* node : closest) {
            resp.closer_nodes.push_back(
                compact::Ipv4Address::from_string(node->host, node->port));
        }
    }

    socket_.reply(resp);
}

// ---------------------------------------------------------------------------
// DOWN_HINT — remove a reportedly-down node from our routing table
// ---------------------------------------------------------------------------

void RpcHandlers::handle_down_hint(const messages::Request& req) {
    // The "value" field contains the address of the node reported as down.
    // For now, we don't act on this — we'd need to verify before removing.
    // A more robust implementation would ping the reported node first.

    // No reply needed for DOWN_HINT (fire-and-forget)
}

}  // namespace rpc
}  // namespace hyperdht
