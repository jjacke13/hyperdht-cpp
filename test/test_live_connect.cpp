// Live connection test against a real nospoon server on the HyperDHT network.
//
// Pipeline:
//   1. findPeer — iterative walk to find the server's announcement
//   2. PEER_HANDSHAKE — Noise IK through DHT relay
//   3. PEER_HOLEPUNCH — 2-round relay + UDP probe exchange
//   4. UDX stream connect + SecretStream header exchange
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
    bool header_sent = false;
    bool header_received = false;
    std::vector<uint8_t> recv_buf;
    rpc::RpcSocket* rpc = nullptr;
    secret_stream::SecretStream* ss = nullptr;

    // UDX stream (raw C, shared socket)
    udx_stream_t* stream = nullptr;
};

// ---------------------------------------------------------------------------
// Full pipeline: findPeer → handshake → holepunch → stream → SecretStream
// ---------------------------------------------------------------------------

TEST(LiveConnect, FullPipeline) {
    const auto server_pk = hex_to_key(
        "a6f03a2523211223325a092c3c172fcc8d395341a9092162b040adefa908149e");

    noise::Seed seed{};
    seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);
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
    // Step 4: UDX stream + SecretStream (called after holepunch success)
    // -----------------------------------------------------------------------
    auto start_stream = [&](const holepunch::HolepunchResult& hp_result) {
        state.peer_addr = hp_result.address;

        uint32_t server_udx_id = state.hs_result.remote_payload.udx.has_value()
            ? state.hs_result.remote_payload.udx->id : 1;

        printf("  Step 4: UDX stream connect (us=%u -> server=%u) to %s:%u...\n",
               state.our_udx_id, server_udx_id,
               hp_result.address.host_string().c_str(), hp_result.address.port);

        // Create UDX stream using the SAME udx + socket as RPC
        state.stream = new udx_stream_t;
        udx_stream_init(rpc_socket.udx_handle(), state.stream, state.our_udx_id,
            nullptr, nullptr);
        state.stream->data = &state;

        // Connect to server's UDX stream ID through the punched hole
        struct sockaddr_in dest{};
        uv_ip4_addr(hp_result.address.host_string().c_str(),
                     hp_result.address.port, &dest);
        udx_stream_connect(state.stream, rpc_socket.socket_handle(),
                           server_udx_id,
                           reinterpret_cast<const struct sockaddr*>(&dest));

        // Create SecretStream (we are the initiator)
        auto* ss = new secret_stream::SecretStream(
            state.hs_result.tx_key, state.hs_result.rx_key,
            state.hs_result.handshake_hash, true);
        state.ss = ss;

        printf("  Our stream ID: %s\n",
               to_hex(ss->local_id().data(), 8).c_str());

        // Send our SecretStream header
        auto header_msg = ss->create_header_message();
        printf("  Sending SecretStream header (%zu bytes)...\n", header_msg.size());

        // Keep header buffer alive until write completes
        auto* header_buf = new std::vector<uint8_t>(std::move(header_msg));
        uv_buf_t uv_buf = uv_buf_init(
            reinterpret_cast<char*>(header_buf->data()),
            static_cast<unsigned int>(header_buf->size()));

        // udx_stream_write_t has a flexible array member — must be heap-allocated
        auto* wreq = static_cast<udx_stream_write_t*>(
            calloc(1, sizeof(udx_stream_write_t) + sizeof(udx_stream_write_buf_t)));

        struct WriteCtx { std::vector<uint8_t>* buf; PipelineState* state; };
        wreq->data = new WriteCtx{header_buf, &state};

        int wrc = udx_stream_write(wreq, state.stream, &uv_buf, 1,
            [](udx_stream_write_t* req, int status, int) {
                auto* ctx = static_cast<WriteCtx*>(req->data);
                if (status >= 0) {
                    ctx->state->header_sent = true;
                    printf("  SecretStream header SENT\n");
                } else {
                    printf("  SecretStream header write FAILED: %d\n", status);
                }
                delete ctx->buf;
                delete ctx;
                free(req);
            });

        if (wrc < 0) {
            printf("  udx_stream_write failed: %d\n", wrc);
            delete header_buf;
            delete static_cast<WriteCtx*>(wreq->data);
            free(wreq);
        }

        // Start reading — wait for server's SecretStream header
        udx_stream_read_start(state.stream,
            [](udx_stream_t* s, ssize_t nread, const uv_buf_t* buf) {
                auto* st = static_cast<PipelineState*>(s->data);
                if (nread <= 0) {
                    if (nread < 0) {
                        printf("  Stream read error: %zd\n", nread);
                    }
                    return;
                }

                printf("  Received %zd bytes from server\n", nread);
                st->recv_buf.insert(st->recv_buf.end(),
                    reinterpret_cast<const uint8_t*>(buf->base),
                    reinterpret_cast<const uint8_t*>(buf->base) + nread);

                // SecretStream header = 3 bytes (uint24_le length) + 56 bytes payload
                if (!st->header_received && st->recv_buf.size() >= 59) {
                    uint32_t len = secret_stream::read_uint24_le(st->recv_buf.data());
                    printf("  Server header length field: %u (expect 56)\n", len);

                    if (len == secret_stream::ID_HEADER_BYTES &&
                        st->recv_buf.size() >= 3 + len) {
                        bool ok = st->ss->receive_header(
                            st->recv_buf.data() + 3, len);
                        if (ok) {
                            st->header_received = true;
                            printf("  SecretStream header RECEIVED and VERIFIED!\n");
                            printf("  ENCRYPTED CHANNEL ESTABLISHED!\n");

                            // Try to decrypt any remaining data
                            size_t consumed = 3 + len;
                            if (st->recv_buf.size() > consumed) {
                                size_t remaining = st->recv_buf.size() - consumed;
                                printf("  %zu additional bytes after header\n",
                                       remaining);

                                // Check for a framed message
                                if (remaining >= 3) {
                                    uint32_t msg_len = secret_stream::read_uint24_le(
                                        st->recv_buf.data() + consumed);
                                    printf("  Next message length: %u\n", msg_len);

                                    if (remaining >= 3 + msg_len) {
                                        auto decrypted = st->ss->decrypt(
                                            st->recv_buf.data() + consumed + 3,
                                            msg_len);
                                        if (decrypted) {
                                            printf("  Decrypted %zu bytes: %s\n",
                                                   decrypted->size(),
                                                   to_hex(decrypted->data(),
                                                          std::min(decrypted->size(),
                                                                   size_t(32))).c_str());
                                        }
                                    }
                                }
                            }
                        } else {
                            printf("  SecretStream header verification FAILED\n");
                            printf("  Expected remote ID: %s\n",
                                   to_hex(st->ss->remote_id().data(), 8).c_str());
                            printf("  Got: %s\n",
                                   to_hex(st->recv_buf.data() + 3, 8).c_str());
                        }
                    }
                }
            });
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
        EXPECT_TRUE(state.header_sent) << "Should send SecretStream header";
        EXPECT_TRUE(state.header_received) << "Should receive SecretStream header";
    }

    delete state.ss;
    if (state.stream) {
        // Stream was already destroyed in shutdown or we need to clean up
    }
    uv_loop_close(&loop);
}
