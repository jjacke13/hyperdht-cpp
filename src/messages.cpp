#include "hyperdht/messages.hpp"

#include <cstring>

namespace hyperdht {
namespace messages {

using compact::State;
using compact::Uint;
using compact::Uint16;
using compact::Fixed32;
using compact::Buffer;
using compact::Ipv4Addr;
using compact::Array;

// ---------------------------------------------------------------------------
// Encode Request
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_request(const Request& req) {
    uint8_t flags = 0;
    if (req.id.has_value()) flags |= FLAG_HAS_ID;
    if (req.token.has_value()) flags |= FLAG_HAS_TOKEN;
    if (req.internal) flags |= FLAG_INTERNAL;
    if (req.target.has_value()) flags |= FLAG_HAS_TARGET;
    if (req.value.has_value()) flags |= FLAG_HAS_VALUE;

    // Preencode to compute size
    State state;
    Uint::preencode(state, flags);
    Uint16::preencode(state, req.tid);
    Ipv4Addr::preencode(state, req.to.addr);
    if (req.id.has_value()) Fixed32::preencode(state, *req.id);
    if (req.token.has_value()) Fixed32::preencode(state, *req.token);
    Uint::preencode(state, req.command);
    if (req.target.has_value()) Fixed32::preencode(state, *req.target);
    if (req.value.has_value()) {
        Buffer::preencode(state, req.value->data(), req.value->size());
    }

    // Allocate: 1 byte for type + encoded body
    std::vector<uint8_t> buf(1 + state.end);
    buf[0] = REQUEST_ID;

    state.buffer = buf.data() + 1;
    state.start = 0;
    // state.end already set from preencode

    Uint::encode(state, flags);
    Uint16::encode(state, req.tid);
    Ipv4Addr::encode(state, req.to.addr);
    if (req.id.has_value()) Fixed32::encode(state, *req.id);
    if (req.token.has_value()) Fixed32::encode(state, *req.token);
    Uint::encode(state, req.command);
    if (req.target.has_value()) Fixed32::encode(state, *req.target);
    if (req.value.has_value()) {
        Buffer::encode(state, req.value->data(), req.value->size());
    }

    return buf;
}

// ---------------------------------------------------------------------------
// Encode Response
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_response(const Response& resp) {
    uint8_t flags = 0;
    if (resp.id.has_value()) flags |= RESP_FLAG_HAS_ID;
    if (resp.token.has_value()) flags |= RESP_FLAG_HAS_TOKEN;
    if (!resp.closer_nodes.empty()) flags |= RESP_FLAG_HAS_CLOSER;
    if (resp.error.has_value()) flags |= RESP_FLAG_HAS_ERROR;
    if (resp.value.has_value()) flags |= RESP_FLAG_HAS_VALUE;

    State state;
    Uint::preencode(state, flags);
    Uint16::preencode(state, resp.tid);
    Ipv4Addr::preencode(state, resp.from.addr);
    if (resp.id.has_value()) Fixed32::preencode(state, *resp.id);
    if (resp.token.has_value()) Fixed32::preencode(state, *resp.token);
    if (!resp.closer_nodes.empty()) {
        Array<Ipv4Addr, compact::Ipv4Address>::preencode(state, resp.closer_nodes);
    }
    if (resp.error.has_value()) Uint::preencode(state, *resp.error);
    if (resp.value.has_value()) {
        Buffer::preencode(state, resp.value->data(), resp.value->size());
    }

    std::vector<uint8_t> buf(1 + state.end);
    buf[0] = RESPONSE_ID;

    state.buffer = buf.data() + 1;
    state.start = 0;

    Uint::encode(state, flags);
    Uint16::encode(state, resp.tid);
    Ipv4Addr::encode(state, resp.from.addr);
    if (resp.id.has_value()) Fixed32::encode(state, *resp.id);
    if (resp.token.has_value()) Fixed32::encode(state, *resp.token);
    if (!resp.closer_nodes.empty()) {
        Array<Ipv4Addr, compact::Ipv4Address>::encode(state, resp.closer_nodes);
    }
    if (resp.error.has_value()) Uint::encode(state, *resp.error);
    if (resp.value.has_value()) {
        Buffer::encode(state, resp.value->data(), resp.value->size());
    }

    return buf;
}

// ---------------------------------------------------------------------------
// Decode Request
// ---------------------------------------------------------------------------

bool decode_request(const uint8_t* data, size_t len, Request& req) {
    State state = State::for_decode(data, len);

    req.flags = static_cast<uint8_t>(Uint::decode(state));
    if (state.error) return false;

    req.tid = Uint16::decode(state);
    if (state.error) return false;

    req.to.addr = Ipv4Addr::decode(state);
    if (state.error) return false;

    if (req.flags & FLAG_HAS_ID) {
        req.id = Fixed32::decode(state);
        if (state.error) return false;
    }

    if (req.flags & FLAG_HAS_TOKEN) {
        req.token = Fixed32::decode(state);
        if (state.error) return false;
    }

    req.internal = (req.flags & FLAG_INTERNAL) != 0;

    req.command = static_cast<uint32_t>(Uint::decode(state));
    if (state.error) return false;

    if (req.flags & FLAG_HAS_TARGET) {
        req.target = Fixed32::decode(state);
        if (state.error) return false;
    }

    if (req.flags & FLAG_HAS_VALUE) {
        auto result = Buffer::decode(state);
        if (state.error) return false;
        if (!result.is_null()) {
            req.value = std::vector<uint8_t>(result.data, result.data + result.len);
        } else {
            req.value = std::vector<uint8_t>{};
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Decode Response
// ---------------------------------------------------------------------------

bool decode_response(const uint8_t* data, size_t len, Response& resp) {
    State state = State::for_decode(data, len);

    resp.flags = static_cast<uint8_t>(Uint::decode(state));
    if (state.error) return false;

    resp.tid = Uint16::decode(state);
    if (state.error) return false;

    resp.from.addr = Ipv4Addr::decode(state);
    if (state.error) return false;

    if (resp.flags & RESP_FLAG_HAS_ID) {
        resp.id = Fixed32::decode(state);
        if (state.error) return false;
    }

    if (resp.flags & RESP_FLAG_HAS_TOKEN) {
        resp.token = Fixed32::decode(state);
        if (state.error) return false;
    }

    if (resp.flags & RESP_FLAG_HAS_CLOSER) {
        resp.closer_nodes = Array<Ipv4Addr, compact::Ipv4Address>::decode(state);
        if (state.error) return false;
    }

    if (resp.flags & RESP_FLAG_HAS_ERROR) {
        resp.error = static_cast<uint32_t>(Uint::decode(state));
        if (state.error) return false;
    }

    if (resp.flags & RESP_FLAG_HAS_VALUE) {
        auto result = Buffer::decode(state);
        if (state.error) return false;
        if (!result.is_null()) {
            resp.value = std::vector<uint8_t>(result.data, result.data + result.len);
        } else {
            resp.value = std::vector<uint8_t>{};
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Decode Message (auto-detect type)
// ---------------------------------------------------------------------------

uint8_t decode_message(const uint8_t* data, size_t len,
                       Request& req, Response& resp) {
    if (len < 2) return 0;

    uint8_t type = data[0];
    if (type == REQUEST_ID) {
        if (decode_request(data + 1, len - 1, req)) return REQUEST_ID;
    } else if (type == RESPONSE_ID) {
        if (decode_response(data + 1, len - 1, resp)) return RESPONSE_ID;
    }
    return 0;
}

}  // namespace messages
}  // namespace hyperdht
