// End-to-end loopback tests for dhttop-1 (client unannounce) and dhttop-6
// (announce with clear). A persistent server + handlers holds the announce
// store; a client drives dht_ops::lookup_and_unannounce / announce(clear).
//
// The UNANNOUNCE request is signed per-reply (target, reply token, replying
// node id). If either the signature or token were wrong the server would
// silently drop the request and the record would NOT be removed — so asserting
// the record disappears proves the signature+token were valid and accepted.

#include <gtest/gtest.h>

#include <array>
#include <algorithm>
#include <cstring>
#include <string>

#include <sodium.h>
#include <uv.h>

#include "hyperdht/announce_sig.hpp"
#include "hyperdht/dht.hpp"
#include "hyperdht/dht_messages.hpp"
#include "hyperdht/dht_ops.hpp"
#include "hyperdht/noise_wrap.hpp"
#include "hyperdht/rpc.hpp"
#include "hyperdht/rpc_handlers.hpp"
#include "hyperdht/hyperdht.h"

using namespace hyperdht;
using namespace hyperdht::rpc;
using namespace hyperdht::messages;
using namespace hyperdht::compact;
using namespace hyperdht::routing;

TEST(Unannounce, PersistentNodeClearsItsOwnCachedKeyBeforeLookup) {
    uv_loop_t loop{};
    ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        HyperDHT node(&loop);
        ASSERT_EQ(node.bind(), 0);
        // libudx reads the watcher after on_close; the fixture frees it after draining.
        std::unique_ptr<udx_interface_event_t> watcher(node.socket().udx_handle()->listeners);
        ASSERT_NE(watcher, nullptr);
        ASSERT_EQ(watcher->next, nullptr);
        watcher->on_close = nullptr;
        // The loopback node simulates a public persistent storage node.
        auto address = Ipv4Address::from_string("127.0.0.1", node.port());
        for (int i = 1; i <= 3; ++i) {
            node.socket().nat_sampler().add(address,
                Ipv4Address::from_string("10.0.0." + std::to_string(i), 49737));
            node.socket().ring_sampler().add(address.host_string(), address.port);
        }
        node.socket().force_check_persistent();
        RpcSocket client(&loop, {}), other(&loop, {});
        ASSERT_EQ(client.bind(0, "127.0.0.1"), 0);
        ASSERT_EQ(other.bind(0, "127.0.0.1"), 0);
        noise::Seed seed{};
        seed.fill(1); const auto topic = noise::generate_keypair(seed);
        seed.fill(2); const auto first = noise::generate_keypair(seed);
        seed.fill(3); const auto second = noise::generate_keypair(seed);
        NodeId target{};
        crypto_generichash(target.data(), target.size(), topic.public_key.data(),
            topic.public_key.size(), nullptr, 0);
        uv_timer_t timeout{};
        bool cleaned = false, checked = false;
        auto cleanup = [&] {
            if (cleaned) return;
            cleaned = true;
            node.destroy(); client.close(); other.close();
            // Drain the stopped interface watcher while its UDX owner is alive.
            udx_teardown(node.socket().udx_handle());
            uv_close(reinterpret_cast<uv_handle_t*>(&timeout), nullptr);
        };
        std::function<void()> expire = cleanup;
        ASSERT_EQ(uv_timer_init(&loop, &timeout), 0);
        timeout.data = &expire;
        uv_timer_start(&timeout, [](uv_timer_t* t) {
            (*static_cast<std::function<void()>*>(t->data))();
        }, 2000, 0);
        auto announce = [&](RpcSocket& sender, const noise::Keypair& kp,
                            std::function<void(const Response&)> done) {
            Request req;
            req.to.addr = address; req.command = CMD_ANNOUNCE; req.target = target;
            req.token = node.socket().token_store().create("127.0.0.1");
            dht_messages::AnnounceMessage ann;
            dht_messages::PeerRecord peer; peer.public_key = kp.public_key; ann.peer = peer;
            ann.signature = announce_sig::sign_announce(target, node.socket().table().id(),
                req.token->data(), req.token->size(), ann, kp);
            req.value = dht_messages::encode_announce_msg(ann);
            sender.request(req, std::move(done), [&](uint16_t) { cleanup(); });
        };
        announce(client, first, [&](const Response&) {
            announce(other, second, [&](const Response&) {
                auto clear = node.lookup_and_unannounce(topic.public_key, first, {}, {});
                if (clear) clear->destroy();
                Request lookup;
                lookup.to.addr = address; lookup.command = CMD_LOOKUP; lookup.target = target;
                client.request(lookup, [&](const Response& response) {
                    checked = true;
                    EXPECT_TRUE(response.value.has_value());
                    if (response.value) {
                        const auto result = dht_messages::decode_lookup_reply(
                            response.value->data(), response.value->size());
                        EXPECT_EQ(result.peers.size(), 1u);
                        if (result.peers.size() == 1) {
                            const auto peer = dht_messages::decode_peer_record(
                                result.peers[0].data(), result.peers[0].size());
                            EXPECT_EQ(peer.public_key, second.public_key);
                        }
                    }
                    cleanup();
                }, [&](uint16_t) { cleanup(); });
            });
        });
        uv_run(&loop, UV_RUN_DEFAULT);
        EXPECT_TRUE(checked);
    }
    uv_run(&loop, UV_RUN_DEFAULT);
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

// Transition an RpcSocket to persistent (so it serves LOOKUP/ANNOUNCE/
// UNANNOUNCE). Copied from test_rpc_handlers.cpp's helper.
static void make_persistent(RpcSocket& socket) {
    auto our_addr = Ipv4Address::from_string("127.0.0.1", socket.port());
    for (int i = 1; i <= 3; i++) {
        auto from = Ipv4Address::from_string("10.0.0." + std::to_string(i), 49737);
        socket.nat_sampler().add(our_addr, from);
        socket.ring_sampler().add(our_addr.host_string(), our_addr.port);
    }
    socket.force_check_persistent();
}

// Seed `client`'s routing table with `server` so a query walks to it (and
// never reaches the public bootstrap nodes).
static void add_server_to_table(RpcSocket& client, RpcSocket& server) {
    auto server_addr = Ipv4Address::from_string("127.0.0.1", server.port());
    Node node;
    node.id = compute_peer_id(server_addr);
    node.host = "127.0.0.1";
    node.port = server.port();
    node.added = client.tick();
    node.pinged = client.tick();
    node.seen = client.tick();
    client.table().add(node);
}

// Sign an announce/unannounce value for our key at a target.
static std::vector<uint8_t> signed_announce(
    const noise::Keypair& kp,
    const std::array<uint8_t, 32>& target,
    const std::array<uint8_t, 32>& node_id,
    const std::array<uint8_t, 32>& token,
    const std::vector<Ipv4Address>& relays = {}) {
    dht_messages::AnnounceMessage ann;
    dht_messages::PeerRecord peer;
    peer.public_key = kp.public_key;
    peer.relay_addresses = relays;
    ann.peer = peer;
    ann.signature = announce_sig::sign_announce(
        target, node_id, token.data(), token.size(), ann, kp);
    return dht_messages::encode_announce_msg(ann);
}

class TargetUnannounce : public ::testing::TestWithParam<int> {};

TEST_P(TargetUnannounce, UsesTargetAndPreservesUnrelatedLocalState) {
    // 0/1: target APIs, 2: own target, 3: listener, 4/5: legacy APIs,
    // 6: ephemeral cleanup guard, 7: legacy topic belonging to another key.
    const int mode = GetParam();
    const bool legacy = mode == 4 || mode == 5 || mode == 7;
    const bool convenience = mode == 1 || mode == 5;
    const bool own_target = mode == 2 || mode == 4 || mode == 5;
    uv_loop_t loop{};
    ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        HyperDHT node(&loop);
        ASSERT_EQ(node.bind(), 0);
        std::unique_ptr<udx_interface_event_t> watcher(node.socket().udx_handle()->listeners);
        ASSERT_NE(watcher, nullptr);
        ASSERT_EQ(watcher->next, nullptr);
        watcher->on_close = nullptr;  // Same drained watcher ownership as the local-cache fixture above.
        node.socket().set_ephemeral(false);
        RpcSocket relay(&loop, {});
        ASSERT_EQ(relay.bind(0, "127.0.0.1"), 0);
        relay.set_ephemeral(false);  // Storage commands must reach the simulated persistent peer.
        add_server_to_table(node.socket(), relay);
        const auto relay_addr = Ipv4Address::from_string("127.0.0.1", relay.port());
        const auto relay_id = compute_peer_id(relay_addr);
        const auto node_addr = Ipv4Address::from_string("127.0.0.1", node.port());
        noise::Seed seed{};
        seed.fill(0x61); const auto first = noise::generate_keypair(seed);
        seed.fill(0x62); const auto second = noise::generate_keypair(seed);
        seed.fill(0x63); const auto topic = noise::generate_keypair(seed);
        const auto input = own_target ? first.public_key : topic.public_key;
        NodeId target{};
        target.fill(0x93);
        if (own_target || mode == 3 || mode == 7)
            crypto_generichash(target.data(), target.size(), input.data(), input.size(), nullptr, 0);
        auto pump = [&](auto ready) {
            const auto deadline = uv_hrtime() + 2000000000ULL;
            while (!ready() && uv_hrtime() < deadline) { uv_run(&loop, UV_RUN_NOWAIT); uv_sleep(1); }
            EXPECT_TRUE(ready());
        };
        auto call = [&](Request req) {
            std::optional<Response> result;
            req.to.addr = node_addr;
            relay.request(req, [&](const Response& r) { result = r; }, [](uint16_t) {});
            pump([&] { return result.has_value(); });
            return result.value_or(Response{});
        };
        for (const auto* kp : {&first, &second}) {
            Request req;
            req.command = CMD_ANNOUNCE;
            req.target = target;
            req.token = node.socket().token_store().create("127.0.0.1");
            req.value = signed_announce(*kp, target, node.socket().table().id(), *req.token);
            call(req);
        }
        dht_messages::PeerRecord forward_peer;
        forward_peer.public_key = own_target ? first.public_key : topic.public_key;
        router::ForwardEntry entry;
        entry.record = dht_messages::encode_peer_record(forward_peer);
        entry.relay = Ipv4Address::from_string("192.0.2.1", 49737);
        if (mode == 3)
            entry.on_peer_handshake = [](const auto&, const auto&, const auto&, bool,
                                         router::HandshakeReplyFn) {};
        node.router().set(target, std::move(entry));
        auto local_keys = [&] {
            Request req;
            req.command = CMD_LOOKUP;
            req.target = target;
            const auto response = call(req);
            std::vector<noise::PubKey> keys;
            if (response.value) {
                const auto records = dht_messages::decode_lookup_reply(response.value->data(), response.value->size());
                for (const auto& value : records.peers)
                    keys.push_back(dht_messages::decode_peer_record(value.data(), value.size()).public_key);
            }
            return keys;
        };
        const auto before = local_keys();
        EXPECT_EQ(std::count(before.begin(), before.end(), first.public_key), 1);
        EXPECT_EQ(std::count(before.begin(), before.end(), second.public_key), 1);
        std::optional<Request> lookup, withdrawal;
        relay.on_request([&](const Request& req) {
            EXPECT_EQ(req.target, target);
            if (req.command == CMD_LOOKUP) lookup = req;
            else if (req.command == CMD_UNANNOUNCE) withdrawal = req;
            else ADD_FAILURE() << "Unexpected query command " << req.command;
        });
        int completions = 0, replies = 0;
        auto on_done = [&](int error, const std::vector<query::QueryReply>& closest) {
            ++completions;
            EXPECT_EQ(error, query::QUERY_OK);
            EXPECT_EQ(closest.size(), 1u);
        };
        auto on_reply = [&](const query::QueryReply& reply) {
            ++replies;
            EXPECT_EQ(reply.from_id, relay_id);
            EXPECT_TRUE(reply.token.has_value());
        };
        auto done = [&] { ++completions; };
        std::shared_ptr<query::Query> q;
        auto start_lookup = [&]<typename Dht>(Dht& dht) {
            if (legacy) return dht.lookup_and_unannounce(input, first, on_reply, on_done);
            // Parent fallback demonstrates that its convenience API hashes the topic again.
            if constexpr (requires { dht.lookup_and_unannounce_target(target, first, on_reply, on_done); })
                return dht.lookup_and_unannounce_target(target, first, on_reply, on_done);
            else return dht.lookup_and_unannounce(target, first, on_reply, on_done);
        };
        auto start_void = [&]<typename Dht>(Dht& dht) {
            if (legacy) dht.unannounce(input, first, done);
            else if constexpr (requires { dht.unannounce_target(target, first, done); })
                dht.unannounce_target(target, first, done);
            else dht.unannounce(target, first, done);
        };
        if (mode == 6) node.socket().set_ephemeral(true);
        if (convenience) start_void(node);
        else q = start_lookup(node);
        const bool keep_forward = !own_target;
        EXPECT_EQ(node.router().get(target) != nullptr, keep_forward);
        if (mode == 3) ASSERT_TRUE(node.router().get(target)->on_peer_handshake);
        node.socket().set_ephemeral(false);  // Inspect the cache even for the ephemeral guard.
        const auto after = local_keys();
        EXPECT_EQ(std::count(after.begin(), after.end(), first.public_key), mode == 6 ? 1 : 0);
        EXPECT_EQ(std::count(after.begin(), after.end(), second.public_key), 1);
        pump([&] { return lookup.has_value(); });
        ASSERT_TRUE(lookup);
        EXPECT_EQ(completions, 0);
        dht_messages::PeerRecord peer;
        peer.public_key = first.public_key;
        dht_messages::LookupRawReply records;
        records.peers.push_back(dht_messages::encode_peer_record(peer));
        const auto token = relay.token_store().create(lookup->from.addr.host_string());
        Response response;
        response.tid = lookup->tid;
        response.from.addr = lookup->from.addr;
        response.id = relay_id;
        response.token = token;
        response.value = dht_messages::encode_lookup_reply(records);
        relay.reply(response, lookup->from_server);
        pump([&] { return withdrawal.has_value(); });
        if (!withdrawal || !withdrawal->value) {
            ADD_FAILURE() << "No withdrawal: replies=" << replies << " completions=" << completions;
            if (q) q->destroy();
            node.destroy(); relay.close();
            udx_teardown(node.socket().udx_handle());
            uv_run(&loop, UV_RUN_DEFAULT);
            EXPECT_EQ(uv_loop_close(&loop), 0);
            return;
        }
        EXPECT_EQ(withdrawal->token, token);
        const auto ann = dht_messages::decode_announce_msg(withdrawal->value->data(), withdrawal->value->size());
        ASSERT_TRUE(ann.peer && ann.signature);
        EXPECT_EQ(ann.peer->public_key, first.public_key);
        EXPECT_TRUE(announce_sig::verify_announce(dht_messages::ns_unannounce(), target,
            relay_id, token.data(), token.size(), ann, *ann.signature, first.public_key));
        for (int i = 0; i < 25; ++i) { uv_run(&loop, UV_RUN_NOWAIT); uv_sleep(1); }
        EXPECT_EQ(completions, 0) << "Completion must await the withdrawal ACK";
        response = {};
        response.tid = withdrawal->tid;
        response.from.addr = withdrawal->from.addr;
        response.id = relay_id;
        relay.reply(response, withdrawal->from_server);
        pump([&] { return completions != 0; });
        EXPECT_EQ(completions, 1);
        EXPECT_EQ(replies, convenience ? 0 : 1);
        if (q) { q->destroy(); q.reset(); }
        node.destroy();
        relay.close();
        udx_teardown(node.socket().udx_handle());
        uv_run(&loop, UV_RUN_DEFAULT);
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

INSTANTIATE_TEST_SUITE_P(TargetCleanupAndAck, TargetUnannounce, ::testing::Range(0, 8));

// Shared harness: PING → get token → announce → run body → drain loop.
struct Harness {
    uv_loop_t loop;
    RpcSocket* server = nullptr;
    RpcSocket* client = nullptr;
    RpcHandlers* handlers = nullptr;
    std::array<uint8_t, 32> token{};
    std::array<uint8_t, 32> server_id{};
    std::array<uint8_t, 32> target{};
    bool cleaned = false;
    uv_timer_t timer{};

    void cleanup() {
        if (cleaned) return;
        cleaned = true;
        server->close();
        client->close();
        uv_close(reinterpret_cast<uv_handle_t*>(&timer), nullptr);
    }
};

TEST(Unannounce, RemovesRecordEndToEnd) {
    Harness h;
    uv_loop_init(&h.loop);

    NodeId sid{}; sid.fill(0x11);
    RpcSocket server(&h.loop, sid);
    server.bind(0);
    make_persistent(server);
    RpcHandlers handlers(server);
    handlers.install();

    NodeId cid{}; cid.fill(0x22);
    RpcSocket client(&h.loop, cid);
    client.bind(0);
    add_server_to_table(client, server);

    h.server = &server; h.client = &client; h.handlers = &handlers;
    h.target.fill(0xA5);

    noise::Seed seed{}; seed.fill(0x42);
    auto kp = noise::generate_keypair(seed);

    bool announce_stored = false;
    bool unannounce_done = false;
    bool store_empty_after = false;

    // Timeout guard.
    uv_timer_init(&h.loop, &h.timer);
    h.timer.data = &h;
    uv_timer_start(&h.timer, [](uv_timer_t* t) {
        static_cast<Harness*>(t->data)->cleanup();
    }, 3000, 0);

    // Phase 1: PING to obtain a token.
    // Fetch a token via FIND_PEER — PING no longer carries a token (JS parity,
    // dht-rpc index.js:641 sendReply(0,null,false,false)). The server is
    // persistent, so FIND_PEER returns both token and id.
    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping.command = CMD_FIND_PEER;
    ping.internal = false;
    ping.target = h.target;

    announce::TargetKey key{};
    std::copy(h.target.begin(), h.target.end(), key.begin());

    client.request(ping,
        [&](const Response& resp) {
            ASSERT_TRUE(resp.token.has_value());
            ASSERT_TRUE(resp.id.has_value());
            h.token = *resp.token;
            h.server_id = *resp.id;

            // Phase 2: signed ANNOUNCE at the target.
            Request ann;
            ann.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
            ann.command = CMD_ANNOUNCE;
            ann.target = h.target;
            ann.token = h.token;
            ann.value = signed_announce(kp, h.target, h.server_id, h.token);

            client.request(ann,
                [&](const Response&) {
                    announce_stored = (handlers.store().get(key).size() == 1);
                    ASSERT_TRUE(announce_stored) << "record must be stored first";

                    // Phase 3: lookup + unannounce our record.
                    dht_ops::lookup_and_unannounce(
                        client, h.target, kp,
                        /*on_reply=*/nullptr,
                        /*user_commit=*/nullptr,
                        [&](int /*error*/, const std::vector<query::QueryReply>&) {
                            unannounce_done = true;
                            store_empty_after =
                                handlers.store().get(key).empty();
                            h.cleanup();
                        });
                },
                [&](uint16_t) { h.cleanup(); });
        },
        [&](uint16_t) { h.cleanup(); });

    uv_run(&h.loop, UV_RUN_DEFAULT);
    uv_loop_close(&h.loop);

    EXPECT_TRUE(announce_stored) << "announce should store one record";
    EXPECT_TRUE(unannounce_done) << "lookup_and_unannounce should complete";
    EXPECT_TRUE(store_empty_after)
        << "UNANNOUNCE (valid sig+token) should remove the record from the store";
}

TEST(Announce, ClearRoutesThroughUnannounceThenAnnounces) {
    Harness h;
    uv_loop_init(&h.loop);

    NodeId sid{}; sid.fill(0x33);
    RpcSocket server(&h.loop, sid);
    server.bind(0);
    make_persistent(server);
    RpcHandlers handlers(server);
    handlers.install();

    NodeId cid{}; cid.fill(0x44);
    RpcSocket client(&h.loop, cid);
    client.bind(0);
    add_server_to_table(client, server);

    h.server = &server; h.client = &client; h.handlers = &handlers;
    h.target.fill(0x5A);

    noise::Seed seed{}; seed.fill(0x77);
    auto kp = noise::generate_keypair(seed);

    // A distinctive relay address marks the NEW announce so we can tell it
    // apart from the stale record.
    auto new_relay = Ipv4Address::from_string("9.9.9.9", 1234);

    bool stale_stored = false;
    bool clear_done = false;
    bool final_is_new = false;

    uv_timer_init(&h.loop, &h.timer);
    h.timer.data = &h;
    uv_timer_start(&h.timer, [](uv_timer_t* t) {
        static_cast<Harness*>(t->data)->cleanup();
    }, 3000, 0);

    // Fetch a token via FIND_PEER — PING no longer carries a token (JS parity,
    // dht-rpc index.js:641 sendReply(0,null,false,false)). The server is
    // persistent, so FIND_PEER returns both token and id.
    Request ping;
    ping.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
    ping.command = CMD_FIND_PEER;
    ping.internal = false;
    ping.target = h.target;

    announce::TargetKey key{};
    std::copy(h.target.begin(), h.target.end(), key.begin());

    client.request(ping,
        [&](const Response& resp) {
            ASSERT_TRUE(resp.token.has_value() && resp.id.has_value());
            h.token = *resp.token;
            h.server_id = *resp.id;

            // Store a STALE record (no relays) for our key.
            Request ann;
            ann.to.addr = Ipv4Address::from_string("127.0.0.1", server.port());
            ann.command = CMD_ANNOUNCE;
            ann.target = h.target;
            ann.token = h.token;
            ann.value = signed_announce(kp, h.target, h.server_id, h.token);

            client.request(ann,
                [&](const Response&) {
                    stale_stored = (handlers.store().get(key).size() == 1);
                    ASSERT_TRUE(stale_stored);

                    // announce(clear): removes the stale record, then announces
                    // the NEW record (distinctive relay). The commit now signs a
                    // fresh record PER node over that node's LOOKUP token+id, so
                    // we just hand it the keypair + relay list.
                    dht_ops::announce(
                        client, h.target, kp, {new_relay}, /*bump=*/0,
                        [&](int /*error*/, const std::vector<query::QueryReply>&) {
                            clear_done = true;
                            auto recs = handlers.store().get(key);
                            if (recs.size() == 1) {
                                auto pr = dht_messages::decode_peer_record(
                                    recs[0].value.data(), recs[0].value.size());
                                final_is_new =
                                    pr.relay_addresses.size() == 1 &&
                                    pr.relay_addresses[0].port == new_relay.port;
                            }
                            h.cleanup();
                        },
                        /*clear_keypair=*/&kp);
                },
                [&](uint16_t) { h.cleanup(); });
        },
        [&](uint16_t) { h.cleanup(); });

    uv_run(&h.loop, UV_RUN_DEFAULT);
    uv_loop_close(&h.loop);

    EXPECT_TRUE(stale_stored) << "stale record should be stored first";
    EXPECT_TRUE(clear_done) << "announce(clear) should complete";
    EXPECT_TRUE(final_is_new)
        << "after clear+announce the store should hold exactly the NEW record";
}

class CUnannounceTarget : public ::testing::TestWithParam<int> {};

TEST_P(CUnannounceTarget, TopicSignatureAndCompletionWaitForAck) {
    // Exact arbitrary target, legacy own public key, legacy different topic key.
    const int mode = GetParam();
    uv_loop_t loop{};
    ASSERT_EQ(uv_loop_init(&loop), 0);
    {
        RpcSocket relay(&loop, {});
        ASSERT_EQ(relay.bind(0, "127.0.0.1"), 0);
        relay.set_ephemeral(false);
        const auto addr = Ipv4Address::from_string("127.0.0.1", relay.port());
        const auto id = compute_peer_id(addr);
        uint8_t seed[32] = {0x61};
        hyperdht_keypair_t kp;
        hyperdht_keypair_from_seed(&kp, seed);
        std::array<uint8_t, 32> input{};
        std::copy_n(kp.public_key, 32, input.begin());
        if (mode == 2) input.fill(0x93);
        NodeId target{};
        target.fill(0x93);
        if (mode != 0) target = dht_ops::hash_public_key(input.data(), input.size());
        std::optional<Request> lookup, withdrawal;
        relay.on_request([&](const Request& req) {
            EXPECT_EQ(req.target, target);
            if (req.command == CMD_LOOKUP) lookup = req;
            else if (req.command == CMD_UNANNOUNCE) withdrawal = req;
            else ADD_FAILURE() << "Unexpected query command " << req.command;
        });
        hyperdht_opts_t opts;
        hyperdht_opts_default(&opts);
        opts.host = "127.0.0.1";
        auto* client = hyperdht_create(&loop, &opts);
        ASSERT_NE(client, nullptr);
        ASSERT_EQ(hyperdht_bind(client, 0), 0);
        ASSERT_EQ(hyperdht_add_node(client, "127.0.0.1", relay.port()), 0);
        auto pump = [&](auto ready) {
            const auto deadline = uv_hrtime() + 2000000000ULL;
            while (!ready() && uv_hrtime() < deadline) { uv_run(&loop, UV_RUN_NOWAIT); uv_sleep(1); }
            EXPECT_TRUE(ready());
        };
        int completions = 0;
        auto done = +[](int error, void* ud) { EXPECT_EQ(error, 0); ++*static_cast<int*>(ud); };
        EXPECT_EQ((mode == 0 ? hyperdht_unannounce_target : hyperdht_unannounce)
            (client, mode == 0 ? target.data() : input.data(), &kp, done, &completions), 0);
        pump([&] { return lookup.has_value(); });
        ASSERT_TRUE(lookup);
        EXPECT_EQ(completions, 0);
        dht_messages::PeerRecord peer;
        std::copy_n(kp.public_key, 32, peer.public_key.begin());
        dht_messages::LookupRawReply records;
        records.peers.push_back(dht_messages::encode_peer_record(peer));
        const auto token = relay.token_store().create(lookup->from.addr.host_string());
        Response response;
        response.tid = lookup->tid;
        response.from.addr = lookup->from.addr;
        response.id = id;
        response.token = token;
        response.value = dht_messages::encode_lookup_reply(records);
        relay.reply(response, lookup->from_server);
        pump([&] { return withdrawal.has_value(); });
        ASSERT_TRUE(withdrawal && withdrawal->value);
        EXPECT_EQ(withdrawal->token, token);
        const auto ann = dht_messages::decode_announce_msg(withdrawal->value->data(), withdrawal->value->size());
        ASSERT_TRUE(ann.peer && ann.signature);
        EXPECT_EQ(ann.peer->public_key, peer.public_key);
        EXPECT_TRUE(announce_sig::verify_announce(dht_messages::ns_unannounce(), target,
            id, token.data(), token.size(), ann, *ann.signature, peer.public_key));
        for (int i = 0; i < 25; ++i) { uv_run(&loop, UV_RUN_NOWAIT); uv_sleep(1); }
        EXPECT_EQ(completions, 0) << "Completion must await the withdrawal ACK";
        response = {};
        response.tid = withdrawal->tid;
        response.from.addr = withdrawal->from.addr;
        response.id = id;
        relay.reply(response, withdrawal->from_server);
        pump([&] { return completions != 0; });
        EXPECT_EQ(completions, 1);
        hyperdht_destroy(client, nullptr, nullptr);
        relay.close();
        uv_run(&loop, UV_RUN_DEFAULT);
        EXPECT_EQ(completions, 1);
        hyperdht_free(client);
        hyperdht_keypair_zero(&kp);
    }
    EXPECT_EQ(uv_loop_close(&loop), 0);
}

INSTANTIATE_TEST_SUITE_P(CFacade, CUnannounceTarget, ::testing::Range(0, 3));

TEST(CUnannounceTarget, RejectsNullInputsWithoutCallbacks) {
    uint8_t target[32] = {0x42};
    hyperdht_keypair_t kp{};
    EXPECT_EQ(hyperdht_unannounce_target(nullptr, target, &kp, nullptr, nullptr), -1);
    uv_loop_t loop{};
    ASSERT_EQ(uv_loop_init(&loop), 0);
    auto* client = hyperdht_create(&loop, nullptr);
    ASSERT_NE(client, nullptr);
    int completions = 0;
    auto done = +[](int, void* ud) { ++*static_cast<int*>(ud); };
    EXPECT_EQ(hyperdht_unannounce_target(client, nullptr, &kp, done, &completions), -1);
    EXPECT_EQ(hyperdht_unannounce_target(client, target, nullptr, done, &completions), -1);
    EXPECT_EQ(completions, 0);
    hyperdht_destroy(client, nullptr, nullptr);
    uv_run(&loop, UV_RUN_DEFAULT);
    hyperdht_free(client);
    EXPECT_EQ(completions, 0);
    EXPECT_EQ(uv_loop_close(&loop), 0);
}
