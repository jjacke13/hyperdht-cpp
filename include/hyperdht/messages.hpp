#pragma once

// DHT RPC message encoding/decoding.
// Wire format: [type_byte] [compact-encoded fields]
//   Request  type = 0x03 (version 3)
//   Response type = 0x13 (version 3)

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "hyperdht/compact.hpp"

namespace hyperdht {
namespace messages {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint8_t VERSION = 0x03;        // Protocol version 3
constexpr uint8_t REQUEST_ID = 0x03;     // (0b0000 << 4) | VERSION
constexpr uint8_t RESPONSE_ID = 0x13;    // (0b0001 << 4) | VERSION

// Request flag bits
constexpr uint8_t FLAG_HAS_ID = 1;
constexpr uint8_t FLAG_HAS_TOKEN = 2;
constexpr uint8_t FLAG_INTERNAL = 4;
constexpr uint8_t FLAG_HAS_TARGET = 8;
constexpr uint8_t FLAG_HAS_VALUE = 16;

// Response flag bits (same for id, token, value; different for closerNodes, error)
constexpr uint8_t RESP_FLAG_HAS_ID = 1;
constexpr uint8_t RESP_FLAG_HAS_TOKEN = 2;
constexpr uint8_t RESP_FLAG_HAS_CLOSER = 4;
constexpr uint8_t RESP_FLAG_HAS_ERROR = 8;
constexpr uint8_t RESP_FLAG_HAS_VALUE = 16;

// dht-rpc base commands (FLAG_INTERNAL set — distinguished from HyperDHT by internal flag)
constexpr uint32_t CMD_PING = 0;
constexpr uint32_t CMD_PING_NAT = 1;
constexpr uint32_t CMD_FIND_NODE = 2;
constexpr uint32_t CMD_DOWN_HINT = 3;
constexpr uint32_t CMD_DELAYED_PING = 4;  // Value: 4-byte LE uint32 delayMs; server replies after delayMs ms

// HyperDHT commands (FLAG_INTERNAL clear — same command IDs, different namespace)
constexpr uint32_t CMD_PEER_HANDSHAKE = 0;
constexpr uint32_t CMD_PEER_HOLEPUNCH = 1;
constexpr uint32_t CMD_FIND_PEER = 2;
constexpr uint32_t CMD_LOOKUP = 3;
constexpr uint32_t CMD_ANNOUNCE = 4;
constexpr uint32_t CMD_UNANNOUNCE = 5;
constexpr uint32_t CMD_MUTABLE_PUT = 6;
constexpr uint32_t CMD_MUTABLE_GET = 7;
constexpr uint32_t CMD_IMMUTABLE_PUT = 8;
constexpr uint32_t CMD_IMMUTABLE_GET = 9;

// HyperDHT error codes (used in response error field)
constexpr uint32_t ERR_NONE = 0;
constexpr uint32_t ERR_SEQ_REUSED = 16;    // Mutable: same seq, different value
constexpr uint32_t ERR_SEQ_TOO_LOW = 17;   // Mutable: seq goes backwards

// ---------------------------------------------------------------------------
// Address — IPv4 host:port
// ---------------------------------------------------------------------------

struct Address {
    compact::Ipv4Address addr;  // host + port
};

// ---------------------------------------------------------------------------
// Request message
// ---------------------------------------------------------------------------

struct Request {
    uint8_t flags = 0;
    uint16_t tid = 0;
    Address to;                                        // Wire-encoded destination address
    Address from;                                      // Actual sender (set by receive path)

    // Optional fields (present based on flags)
    std::optional<std::array<uint8_t, 32>> id;       // FLAG_HAS_ID
    std::optional<std::array<uint8_t, 32>> token;    // FLAG_HAS_TOKEN
    uint32_t command = 0;
    std::optional<std::array<uint8_t, 32>> target;   // FLAG_HAS_TARGET
    std::optional<std::vector<uint8_t>> value;        // FLAG_HAS_VALUE
    bool internal = false;                             // FLAG_INTERNAL

    // Transport-layer field (not wire-encoded): true if this request was
    // received on the server socket. Used for ID suppression in replies —
    // JS only includes the node ID when `!ephemeral && socket === serverSocket`.
    bool from_server = false;
};

// ---------------------------------------------------------------------------
// Response message
// ---------------------------------------------------------------------------

struct Response {
    uint8_t flags = 0;
    uint16_t tid = 0;
    Address from;

    // Optional fields (present based on flags)
    std::optional<std::array<uint8_t, 32>> id;       // RESP_FLAG_HAS_ID
    std::optional<std::array<uint8_t, 32>> token;    // RESP_FLAG_HAS_TOKEN
    std::vector<compact::Ipv4Address> closer_nodes;   // RESP_FLAG_HAS_CLOSER
    std::optional<uint32_t> error;                     // RESP_FLAG_HAS_ERROR
    std::optional<std::vector<uint8_t>> value;         // RESP_FLAG_HAS_VALUE
};

// ---------------------------------------------------------------------------
// Encode/Decode
// ---------------------------------------------------------------------------

// Encode a request to bytes (prepends REQUEST_ID byte)
std::vector<uint8_t> encode_request(const Request& req);

// Encode a response to bytes (prepends RESPONSE_ID byte)
std::vector<uint8_t> encode_response(const Response& resp);

// Decode a message. Returns the type byte and populates the appropriate struct.
// Returns 0 on error, REQUEST_ID or RESPONSE_ID on success.
uint8_t decode_message(const uint8_t* data, size_t len,
                       Request& req, Response& resp);

// Decode a request from compact-encoded bytes (after type byte)
bool decode_request(const uint8_t* data, size_t len, Request& req);

// Decode a response from compact-encoded bytes (after type byte)
bool decode_response(const uint8_t* data, size_t len, Response& resp);

}  // namespace messages
}  // namespace hyperdht
