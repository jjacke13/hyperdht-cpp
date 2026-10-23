#pragma once

#include "hyperdht/peer_connect.hpp"

#include <memory>

namespace hyperdht::peer_connect {

struct HandshakeRequest;

std::shared_ptr<const HandshakeRequest> prepare_handshake(
    const noise::Keypair& our_keypair, const noise::PubKey& remote_pubkey,
    uint32_t our_udx_id, bool reusable_socket, uint32_t firewall,
    const std::vector<compact::Ipv4Address>& addresses4,
    const std::optional<RelayThroughInfo>& relay_through);

void peer_handshake(rpc::RpcSocket& socket,
                    const compact::Ipv4Address& relay_addr,
                    std::shared_ptr<const HandshakeRequest> request,
                    OnHandshakeCallback on_done);

}  // namespace hyperdht::peer_connect
