#include "hyperdht/dht.hpp"

#include <sodium.h>

#include <cstdio>

#include "hyperdht/holepunch.hpp"
#include "hyperdht/peer_connect.hpp"

namespace hyperdht {

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

HyperDHT::HyperDHT(uv_loop_t* loop, DhtOptions opts)
    : loop_(loop), opts_(std::move(opts)) {

    // Generate default keypair if not provided
    auto zero_pk = noise::PubKey{};
    if (opts_.default_keypair.public_key == zero_pk) {
        opts_.default_keypair = noise::generate_keypair();
    }

    // Create RPC socket with our public key as node ID
    routing::NodeId our_id{};
    std::copy(opts_.default_keypair.public_key.begin(),
              opts_.default_keypair.public_key.end(),
              our_id.begin());

    socket_ = std::make_unique<rpc::RpcSocket>(loop_, our_id);
    handlers_ = std::make_unique<rpc::RpcHandlers>(*socket_, &router_);
    handlers_->install();
}

HyperDHT::~HyperDHT() {
    if (!destroyed_) {
        destroy();
    }
}

// ---------------------------------------------------------------------------
// bind
// ---------------------------------------------------------------------------

int HyperDHT::bind() {
    if (bound_) return 0;
    int rc = socket_->bind(opts_.port);
    if (rc == 0) bound_ = true;
    return rc;
}

void HyperDHT::ensure_bound() {
    if (!bound_) bind();
}

// ---------------------------------------------------------------------------
// connect — client connection to a remote peer
// ---------------------------------------------------------------------------

void HyperDHT::connect(const noise::PubKey& remote_public_key,
                        ConnectCallback on_done) {
    connect(remote_public_key, opts_.default_keypair, std::move(on_done));
}

void HyperDHT::connect(const noise::PubKey& remote_public_key,
                        const noise::Keypair& keypair,
                        ConnectCallback on_done) {
    if (destroyed_) {
        on_done(-1, {});
        return;
    }
    ensure_bound();
    do_connect(remote_public_key, keypair, std::move(on_done));
}

void HyperDHT::do_connect(const noise::PubKey& remote_pk,
                           const noise::Keypair& keypair,
                           ConnectCallback on_done) {

    // State shared across the async pipeline
    struct ConnState {
        noise::PubKey remote_pk;
        noise::Keypair keypair;
        ConnectCallback on_done;
        compact::Ipv4Address relay_addr;
        peer_connect::HandshakeResult hs_result;
        std::shared_ptr<query::Query> query;
        std::weak_ptr<bool> alive;  // Sentinel — expired if HyperDHT destroyed
        rpc::RpcSocket* socket = nullptr;  // Raw pointer, guarded by alive
        bool found = false;
        uint32_t our_udx_id = 0;

        void complete(int err, const ConnectResult& result = {}) {
            auto cb = std::move(on_done);
            on_done = nullptr;  // Prevent double invocation
            if (cb) cb(err, result);
        }
    };

    auto state = std::make_shared<ConnState>();
    state->remote_pk = remote_pk;
    state->keypair = keypair;
    state->on_done = std::move(on_done);
    state->alive = alive_;
    state->socket = socket_.get();

    // Generate random UDX stream ID
    randombytes_buf(&state->our_udx_id, sizeof(state->our_udx_id));

    // Step 1: findPeer
    state->query = dht_ops::find_peer(*socket_, remote_pk,
        [state](const query::QueryReply& reply) {
            if (reply.value.has_value() && !reply.value->empty() && !state->found) {
                state->found = true;
                state->relay_addr = reply.from_addr;
            }
        },
        [state](const std::vector<query::QueryReply>&) {
            state->query.reset();

            if (state->alive.expired() || !state->found) {
                state->complete(-2);
                return;
            }

            // Step 2: PEER_HANDSHAKE
            peer_connect::peer_handshake(*state->socket, state->relay_addr,
                state->keypair, state->remote_pk, state->our_udx_id,
                [state](const peer_connect::HandshakeResult& hs) {
                    if (state->alive.expired() || !hs.success) {
                        state->complete(-3);
                        return;
                    }
                    state->hs_result = hs;

                    // Check for direct connect (OPEN firewall)
                    holepunch::HolepunchResult hp_result;
                    if (holepunch::try_direct_connect(hs, hp_result)) {
                        ConnectResult result;
                        result.success = true;
                        result.tx_key = hs.tx_key;
                        result.rx_key = hs.rx_key;
                        result.handshake_hash = hs.handshake_hash;
                        result.remote_public_key = hs.remote_public_key;
                        result.peer_address = hp_result.address;
                        result.local_udx_id = state->our_udx_id;
                        if (hs.remote_payload.udx.has_value()) {
                            result.remote_udx_id = hs.remote_payload.udx->id;
                        }
                        state->complete(0, result);
                        return;
                    }

                    // JS: if no holepunch info (server is OPEN or unreachable
                    // for holepunching), try direct connect using addresses
                    if (!hs.remote_payload.holepunch.has_value() ||
                        hs.remote_payload.holepunch->relays.empty()) {
                        // Use first address from the server's payload
                        if (!hs.remote_payload.addresses4.empty()) {
                            ConnectResult result;
                            result.success = true;
                            result.tx_key = hs.tx_key;
                            result.rx_key = hs.rx_key;
                            result.handshake_hash = hs.handshake_hash;
                            result.remote_public_key = hs.remote_public_key;
                            result.peer_address = hs.remote_payload.addresses4[0];
                            result.local_udx_id = state->our_udx_id;
                            if (hs.remote_payload.udx.has_value()) {
                                result.remote_udx_id = hs.remote_payload.udx->id;
                            }
                            state->complete(0, result);
                        } else {
                            state->complete(-4);
                        }
                        return;
                    }

                    auto& hp_info = *hs.remote_payload.holepunch;

                    // Use handshake relay if in holepunch relay list
                    auto hp_relay = hp_info.relays[0].relay_address;
                    auto hp_peer = hp_info.relays[0].peer_address;
                    for (const auto& r : hp_info.relays) {
                        if (r.relay_address.host_string() == state->relay_addr.host_string() &&
                            r.relay_address.port == state->relay_addr.port) {
                            hp_relay = r.relay_address;
                            hp_peer = r.peer_address;
                            break;
                        }
                    }

                    auto fw = state->socket->nat_sampler().firewall();
                    auto addrs = state->socket->nat_sampler().addresses();

                    holepunch::holepunch_connect(*state->socket, hs,
                        hp_relay, hp_peer, hp_info.id, fw, addrs,
                        [state](const holepunch::HolepunchResult& hp) {
                            if (state->alive.expired() || !hp.success) {
                                state->complete(-5);
                                return;
                            }

                            ConnectResult result;
                            result.success = true;
                            result.tx_key = state->hs_result.tx_key;
                            result.rx_key = state->hs_result.rx_key;
                            result.handshake_hash = state->hs_result.handshake_hash;
                            result.remote_public_key = state->hs_result.remote_public_key;
                            result.peer_address = hp.address;
                            result.local_udx_id = state->our_udx_id;
                            if (state->hs_result.remote_payload.udx.has_value()) {
                                result.remote_udx_id = state->hs_result.remote_payload.udx->id;
                            }
                            state->complete(0, result);
                        });
                });
        });
}

// ---------------------------------------------------------------------------
// create_server
// ---------------------------------------------------------------------------

server::Server* HyperDHT::create_server() {
    ensure_bound();
    auto srv = std::make_unique<server::Server>(*socket_, router_);
    auto* ptr = srv.get();
    servers_.push_back(std::move(srv));
    return ptr;
}

// ---------------------------------------------------------------------------
// DHT operations (thin wrappers)
// ---------------------------------------------------------------------------

std::shared_ptr<query::Query> HyperDHT::find_peer(
    const noise::PubKey& public_key,
    query::OnReplyCallback on_reply,
    query::OnDoneCallback on_done) {
    ensure_bound();
    return dht_ops::find_peer(*socket_, public_key,
                               std::move(on_reply), std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::lookup(
    const routing::NodeId& target,
    query::OnReplyCallback on_reply,
    query::OnDoneCallback on_done) {
    ensure_bound();
    return dht_ops::lookup(*socket_, target,
                            std::move(on_reply), std::move(on_done));
}

std::shared_ptr<query::Query> HyperDHT::announce(
    const routing::NodeId& target,
    const std::vector<uint8_t>& value,
    query::OnDoneCallback on_done) {
    ensure_bound();
    return dht_ops::announce(*socket_, target, value, std::move(on_done));
}

// ---------------------------------------------------------------------------
// destroy
// ---------------------------------------------------------------------------

void HyperDHT::destroy(std::function<void()> on_done) {
    if (destroyed_) {
        if (on_done) on_done();
        return;
    }
    destroyed_ = true;
    *alive_ = false;

    // Close all servers (don't clear vector yet — let ~HyperDHT handle deallocation
    // after the event loop processes the close callbacks)
    for (auto& srv : servers_) {
        srv->close();
    }

    // Clear router
    router_.clear();

    // Close socket
    if (socket_) {
        socket_->close();
    }

    if (on_done) on_done();
}

}  // namespace hyperdht
