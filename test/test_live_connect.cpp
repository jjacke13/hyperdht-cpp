// Live connection test against a real nospoon server on the HyperDHT network.
//
// Pipeline:
//   1. findPeer — iterative walk to find the server's announcement
//   2. PEER_HANDSHAKE — Noise IK through DHT relay
//   3. PEER_HOLEPUNCH — 2-round relay + UDP probe exchange
//   4. UDX stream connect + SecretStreamDuplex (full-duplex wrapper)
//
// This test dogfoods `SecretStreamDuplex` — the wrapper that replaces
// ~120 lines of inline framing/encrypt/decrypt glue from earlier revisions
// with `duplex.start()` + event callbacks (`on_connect`, `on_message`).
//
// Requires network access. Skipped if bootstrap nodes are unreachable.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sodium.h>
#include <udx.h>
#include <uv.h>

#include "hyperdht/compact.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/holepunch.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/peer_connect.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/secret_stream.hpp"

using namespace hyperdht;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string to_hex(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; i++) {
        out.push_back(h[data[i] >> 4]);
        out.push_back(h[data[i] & 0x0F]);
    }
    return out;
}

static std::array<uint8_t, 32> hex_to_key(const char* hex) {
    std::array<uint8_t, 32> key{};
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        std::sscanf(hex + 2 * i, "%02x", &byte);
        key[i] = static_cast<uint8_t>(byte);
    }
    return key;
}

// ---------------------------------------------------------------------------
// Shared state for the async pipeline
// ---------------------------------------------------------------------------

struct PipelineState {
    // findPeer
    bool find_done = false;
    bool found_server = false;
    compact::Ipv4Address relay_addr;
    std::shared_ptr<query::Query> query;

    // handshake
    bool handshake_done = false;
    peer_connect::HandshakeResult hs_result;
    uint32_t our_udx_id = 0;

    // holepunch
    bool holepunch_done = false;
    bool holepunch_success = false;
    compact::Ipv4Address peer_addr;  // punched address

    // stream
    bool stream_connected = false;
    bool duplex_connected = false;         // SecretStreamDuplex on_connect fired
    bool message_received = false;         // at least one decrypted message
    std::vector<uint8_t> first_message;    // first decrypted payload
    rpc::RpcSocket* rpc = nullptr;
    secret_stream::SecretStreamDuplex* duplex = nullptr;

    // UDX stream (raw C, shared socket)
    udx_stream_t* stream = nullptr;
};

// ---------------------------------------------------------------------------
// Full pipeline: findPeer → handshake → holepunch → stream → SecretStream
// ---------------------------------------------------------------------------

TEST(LiveConnect, FullPipeline) {
    // Server key must be provided via SERVER_KEY env var
    const char* key_env = std::getenv("SERVER_KEY");
    if (!key_env || strlen(key_env) != 64) {
        GTEST_SKIP() << "Set SERVER_KEY=<64-hex-chars> to run this test";
    }
    const auto server_pk = hex_to_key(key_env);

    auto kp = noise::generate_keypair();  // Random keypair for each run
    printf("  Our pubkey: %s\n", to_hex(kp.public_key.data(), 32).c_str());

    uv_loop_t loop;
    uv_loop_init(&loop);

    routing::NodeId our_id{};
    std::copy(kp.public_key.begin(), kp.public_key.end(), our_id.begin());

    rpc::RpcSocket rpc_socket(&loop, our_id);
    rpc_socket.bind(0);
    printf("  Bound to port %u\n", rpc_socket.port());

    PipelineState state;
    state.our_udx_id = randombytes_uniform(UINT32_MAX);
    state.rpc = &rpc_socket;

    // Overall timeout (45s — stream connect may take a bit)
    uv_timer_t timeout;
    uv_timer_init(&loop, &timeout);
    timeout.data = &rpc_socket;
    uv_timer_start(&timeout, [](uv_timer_t* t) {
        printf("  TIMEOUT — giving up\n");
        auto* r = static_cast<rpc::RpcSocket*>(t->data);
        r->close();
        uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
    }, 45000, 0);

    // -----------------------------------------------------------------------
    // Helper: clean shutdown
    // -----------------------------------------------------------------------
    auto shutdown = [&]() {
        uv_timer_stop(&timeout);
        uv_close(reinterpret_cast<uv_handle_t*>(&timeout), nullptr);
        if (state.stream) {
            udx_stream_destroy(state.stream);
        }
        rpc_socket.close();
    };

    // -----------------------------------------------------------------------
    // Step 4: UDX stream + SecretStreamDuplex
    //
    // We used to hand-roll the header send/receive + decrypt loop inline
    // (~120 lines). Now the Duplex wrapper does all of it internally:
    //   - Automatic header frame send on `start()`
    //   - State-machine frame parser (header first, then data frames)
    //   - `on_connect` when both sides exchange headers
    //   - `on_message` per decrypted application payload
    // -----------------------------------------------------------------------
    auto start_stream = [&](const holepunch::HolepunchResult& hp_result) {
        state.peer_addr = hp_result.address;

        uint32_t server_udx_id = state.hs_result.remote_payload.udx.has_value()
            ? state.hs_result.remote_payload.udx->id : 1;

        printf("  Step 4: UDX stream connect (us=%u -> server=%u) to %s:%u...\n",
               state.our_udx_id, server_udx_id,
               hp_result.address.host_string().c_str(), hp_result.address.port);

        // Use the socket that received the holepunch probe (may be the main
        // RPC socket OR a pool socket — both share the same udx_t handle).
        udx_socket_t* punch_socket = hp_result.socket
            ? hp_result.socket : rpc_socket.socket_handle();

        state.stream = new udx_stream_t;
        udx_stream_init(rpc_socket.udx_handle(), state.stream, state.our_udx_id,
            nullptr, nullptr);

        // Connect to server's UDX stream ID through the punched hole.
        struct sockaddr_in dest{};
        uv_ip4_addr(hp_result.address.host_string().c_str(),
                     hp_result.address.port, &dest);
        udx_stream_connect(state.stream, punch_socket,
                           server_udx_id,
                           reinterpret_cast<const struct sockaddr*>(&dest));

        // Wrap the UDX stream in a SecretStreamDuplex. The Duplex takes
        // over `stream->data` and installs its own read/close callbacks
        // when `start()` is called.
        secret_stream::DuplexHandshake hs{};
        hs.tx_key = state.hs_result.tx_key;
        hs.rx_key = state.hs_result.rx_key;
        hs.handshake_hash = state.hs_result.handshake_hash;
        hs.public_key = kp.public_key;
        hs.remote_public_key = state.hs_result.remote_public_key;
        hs.is_initiator = true;

        state.duplex = new secret_stream::SecretStreamDuplex(
            state.stream, hs, &loop, secret_stream::DuplexOptions{});

        printf("  Our stream ID: %s\n",
               to_hex(state.duplex->local_id().data(), 8).c_str());

        state.duplex->on_connect([&]() {
            state.duplex_connected = true;
            printf("  SecretStreamDuplex CONNECTED — encrypted channel up\n");
        });

        state.duplex->on_message([&](const uint8_t* data, size_t len) {
            if (!state.message_received) {
                state.message_received = true;
                state.first_message.assign(data, data + len);
                std::string s(reinterpret_cast<const char*>(data), len);
                printf("  MESSAGE RECEIVED (%zu bytes): %s\n", len, s.c_str());
            }
        });

        state.duplex->on_close([&](int err) {
            printf("  Duplex closed (err=%d)\n", err);
        });

        state.duplex->start();  // sends header, installs read callback
    };

    // -----------------------------------------------------------------------
    // Step 1: findPeer
    // -----------------------------------------------------------------------
    printf("  Step 1: findPeer...\n");
    state.query = dht_ops::find_peer(rpc_socket, server_pk,
        [&](const query::QueryReply& reply) {
            if (reply.value.has_value() && !reply.value->empty()) {
                state.found_server = true;
                state.relay_addr = reply.from_addr;
                printf("  Found server! Relay: %s:%u\n",
                       reply.from_addr.host_string().c_str(),
                       reply.from_addr.port);
            }
        },
        [&](const std::vector<query::QueryReply>&) {
            state.find_done = true;
            if (!state.found_server) {
                printf("  Server not found\n");
                shutdown();
                return;
            }

            // Step 2: PEER_HANDSHAKE
            printf("  Step 2: PEER_HANDSHAKE via %s:%u...\n",
                   state.relay_addr.host_string().c_str(),
                   state.relay_addr.port);

            peer_connect::peer_handshake(rpc_socket, state.relay_addr,
                kp, server_pk, state.our_udx_id,
                [&](const peer_connect::HandshakeResult& hs) {
                    state.handshake_done = true;
                    state.hs_result = hs;

                    if (!hs.success) {
                        printf("  Handshake FAILED\n");
                        shutdown();
                        return;
                    }
                    printf("  Handshake SUCCESS (server fw=%u, udx_id=%u)\n",
                           hs.remote_payload.firewall,
                           hs.remote_payload.udx.has_value()
                               ? hs.remote_payload.udx->id : 0);

                    // Step 3: PEER_HOLEPUNCH
                    if (!hs.remote_payload.holepunch.has_value() ||
                        hs.remote_payload.holepunch->relays.empty()) {
                        printf("  No holepunch relays\n");
                        shutdown();
                        return;
                    }

                    auto& hp_info = *hs.remote_payload.holepunch;

                    // Use handshake relay if available in holepunch relays
                    compact::Ipv4Address hp_relay = hp_info.relays[0].relay_address;
                    compact::Ipv4Address hp_peer = hp_info.relays[0].peer_address;
                    for (const auto& r : hp_info.relays) {
                        if (r.relay_address.host_string() == state.relay_addr.host_string() &&
                            r.relay_address.port == state.relay_addr.port) {
                            hp_relay = r.relay_address;
                            hp_peer = r.peer_address;
                            break;
                        }
                    }

                    printf("  Step 3: PEER_HOLEPUNCH via %s:%u...\n",
                           hp_relay.host_string().c_str(), hp_relay.port);

                    // Use NAT sampler's firewall type and addresses
                    auto fw = rpc_socket.nat_sampler().firewall();
                    auto addrs = rpc_socket.nat_sampler().addresses();
                    printf("  NAT sampler: fw=%u, %zu addrs, %d samples\n",
                           fw, addrs.size(), rpc_socket.nat_sampler().sampled());

                    holepunch::holepunch_connect(
                        rpc_socket, hs, hp_relay, hp_peer, hp_info.id,
                        fw, addrs,
                        [&](const holepunch::HolepunchResult& result) {
                            state.holepunch_done = true;
                            state.holepunch_success = result.success;

                            if (!result.success) {
                                printf("  HOLEPUNCH FAILED\n");
                                shutdown();
                                return;
                            }
                            printf("  HOLEPUNCH SUCCESS! %s:%u\n",
                                   result.address.host_string().c_str(),
                                   result.address.port);

                            // Step 4: connect stream + exchange headers
                            start_stream(result);

                            // Give the stream 10 seconds to exchange headers, then shut down
                            uv_timer_stop(&timeout);
                            timeout.data = &state;
                            uv_timer_start(&timeout, [](uv_timer_t* t) {
                                printf("  Stream timeout — stopping\n");
                                auto* st = static_cast<PipelineState*>(t->data);
                                if (st->stream) {
                                    udx_stream_destroy(st->stream);
                                    st->stream = nullptr;
                                }
                                if (st->rpc) st->rpc->close();
                                uv_close(reinterpret_cast<uv_handle_t*>(t), nullptr);
                            }, 10000, 0);
                        });
                });
        });

    uv_run(&loop, UV_RUN_DEFAULT);

    // Assertions
    if (!state.find_done) {
        GTEST_SKIP() << "Network unreachable";
    }

    EXPECT_TRUE(state.found_server) << "Server not found on DHT";
    if (state.found_server) {
        EXPECT_TRUE(state.hs_result.success) << "Handshake should succeed";
    }
    if (state.hs_result.success) {
        EXPECT_TRUE(state.holepunch_success) << "Holepunch should succeed";
    }
    if (state.holepunch_success) {
        EXPECT_TRUE(state.duplex_connected)
            << "SecretStreamDuplex should fire on_connect";
        EXPECT_TRUE(state.message_received)
            << "Server should send at least one encrypted message";
    }

    delete state.duplex;
    if (state.stream) {
        udx_stream_destroy(state.stream);
        delete state.stream;
        state.stream = nullptr;
    }
    uv_run(&loop, UV_RUN_NOWAIT);  // Process close callbacks
    uv_loop_close(&loop);
}
