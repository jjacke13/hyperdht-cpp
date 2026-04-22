#pragma once
// Length-prefixed framing over HyperDHT encrypted streams.
// Wire format: [4 bytes big-endian length][payload]
// Keepalive:   [00 00 00 00] (zero-length frame, every 25s)

#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

namespace nospoon {

// Encode: prepend 4B big-endian length header
inline std::vector<uint8_t> frame_encode(const uint8_t* data, size_t len) {
    std::vector<uint8_t> out(4 + len);
    out[0] = static_cast<uint8_t>((len >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((len >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(len & 0xFF);
    if (len > 0) std::memcpy(out.data() + 4, data, len);
    return out;
}

// Zero-length keepalive frame
inline std::vector<uint8_t> frame_keepalive() {
    return {0, 0, 0, 0};
}

// Streaming frame decoder: feed bytes, emit complete frames
class FrameDecoder {
public:
    using OnFrameCb = std::function<void(const uint8_t* data, size_t len)>;

    void feed(const uint8_t* data, size_t len, OnFrameCb on_frame) {
        buf_.insert(buf_.end(), data, data + len);

        while (buf_.size() >= 4) {
            uint32_t frame_len = (static_cast<uint32_t>(buf_[0]) << 24) |
                                 (static_cast<uint32_t>(buf_[1]) << 16) |
                                 (static_cast<uint32_t>(buf_[2]) << 8) |
                                 static_cast<uint32_t>(buf_[3]);

            if (frame_len == 0) {
                // Keepalive — consume header, skip
                buf_.erase(buf_.begin(), buf_.begin() + 4);
                continue;
            }

            if (buf_.size() < 4 + frame_len) break;  // Incomplete

            on_frame(buf_.data() + 4, frame_len);
            buf_.erase(buf_.begin(), buf_.begin() + 4 + frame_len);
        }
    }

    void reset() { buf_.clear(); }

private:
    std::vector<uint8_t> buf_;
};

}  // namespace nospoon
