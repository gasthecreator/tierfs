// Wire encoding and framing shared by backend and client. See proto/PROTOCOL.md.
//
// Why big-endian and manual byte shifts instead of casting a struct onto the
// buffer? Casting depends on the CPU's byte order, padding and alignment, and
// is undefined behaviour in C++ when misaligned. Shifting bytes is portable.
#pragma once

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <climits>

namespace tierfs {

constexpr uint16_t PROTO_VERSION = 2;         // filesystem (tree) protocol
constexpr uint16_t DEVICE_PROTO_VERSION = 3;  // device storage protocol (encrypted chunks and manifests)
constexpr uint32_t MAX_FRAME = 16u << 20;
constexpr uint32_t MAX_READ = 1u << 20;

enum MsgType : uint8_t {
    MSG_HELLO = 0x01,
    MSG_STAT = 0x02,
    MSG_READDIR = 0x03,
    MSG_READ = 0x04,
    // device protocol (v3)
    MSG_DEV_INFO = 0x10,
    MSG_DEV_BIND = 0x11,
    MSG_DEV_HAS_CHUNKS = 0x12,
    MSG_DEV_PUT_CHUNK = 0x13,
    MSG_DEV_GET_CHUNK = 0x14,
    MSG_DEV_PUT_MANIFEST = 0x15,
    MSG_DEV_GET_MANIFEST = 0x16,
    MSG_DEV_LIST_MANIFESTS = 0x17,
    MSG_DEV_AUDIT = 0x18,
    MSG_DEV_DELETE_MANIFESTS = 0x19,   // garbage collection (ADR-0010): only on a device that accepts deletions
    MSG_DEV_GC_STATUS = 0x1A,
    MSG_DEV_SWEEP = 0x1B,
    MSG_REPLY_FLAG = 0x80,
    MSG_ERROR = 0xFF,
};

struct Writer {
    std::vector<uint8_t> b;
    void u8(uint8_t v) { b.push_back(v); }
    void u16(uint16_t v) { u8(v >> 8); u8(v & 0xff); }
    void u32(uint32_t v) { u16(v >> 16); u16(v & 0xffff); }
    void u64(uint64_t v) { u32(v >> 32); u32(v & 0xffffffffu); }
    void i32(int32_t v) { u32(static_cast<uint32_t>(v)); }
    void i64(int64_t v) { u64(static_cast<uint64_t>(v)); }
    void str(const std::string& s) {
        if (s.size() > 0xffff) throw std::length_error("string too long");
        u16(static_cast<uint16_t>(s.size()));
        b.insert(b.end(), s.begin(), s.end());
    }
    void bytes(const uint8_t* p, size_t n) { b.insert(b.end(), p, p + n); }
    // u32 length + data (for blobs bigger than a u16-prefixed string allows)
    void blob(const uint8_t* p, size_t n) { u32(static_cast<uint32_t>(n)); bytes(p, n); }
};

// Reader never reads past the buffer: every accessor checks first and throws,
// so a malicious or corrupt message cannot cause an out-of-bounds read.
struct Reader {
    const uint8_t* p;
    size_t n;
    size_t pos = 0;
    Reader(const uint8_t* p_, size_t n_) : p(p_), n(n_) {}
    explicit Reader(const std::vector<uint8_t>& v) : p(v.data()), n(v.size()) {}

    size_t remaining() const { return n - pos; }
    void need(size_t k) const {
        if (n - pos < k) throw std::runtime_error("short message");
    }
    uint8_t u8() { need(1); return p[pos++]; }
    uint16_t u16() { uint16_t hi = u8(); return static_cast<uint16_t>((hi << 8) | u8()); }
    uint32_t u32() { uint32_t hi = u16(); return (hi << 16) | u16(); }
    uint64_t u64() { uint64_t hi = u32(); return (hi << 32) | u32(); }
    int32_t i32() { return static_cast<int32_t>(u32()); }
    int64_t i64() { return static_cast<int64_t>(u64()); }
    std::vector<uint8_t> blob(size_t max) {
        uint32_t n = u32();
        if (n > max) throw std::runtime_error("blob too large");
        need(n);
        std::vector<uint8_t> v(p + pos, p + pos + n);
        pos += n;
        return v;
    }
    std::string str() {
        size_t len = u16();
        need(len);
        std::string s(reinterpret_cast<const char*>(p + pos), len);
        pos += len;
        return s;
    }
};

// ---- blocking socket I/O --------------------------------------------------

// Absolute deadlines (steady-clock milliseconds; 0 = none). A socket timeout
// alone restarts on every byte, so a link that trickles one byte at a time can
// hold a request open forever and freeze whatever app is waiting on the file.
// A deadline bounds the WHOLE transfer.
inline int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count();
}

// 1 = ready, -1 = deadline passed (errno EAGAIN) or error.
inline int wait_fd(int fd, short events, int64_t deadline_ms) {
    if (deadline_ms == 0) return 1;
    for (;;) {
        int64_t rem = deadline_ms - now_ms();
        if (rem <= 0) { errno = EAGAIN; return -1; }
        pollfd p{fd, events, 0};
        int r = poll(&p, 1, static_cast<int>(std::min<int64_t>(rem, INT_MAX)));
        if (r > 0) return 1;
        if (r == 0) { errno = EAGAIN; return -1; }
        if (errno != EINTR) return -1;
    }
}

// Returns 1 on success, 0 on clean EOF before any byte, -1 on error
// (errno set; EAGAIN/EWOULDBLOCK means the timeout/deadline expired).
inline int read_full(int fd, void* buf, size_t n, int64_t deadline_ms = 0) {
    auto* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < n) {
        if (wait_fd(fd, POLLIN, deadline_ms) < 0) return -1;
        ssize_t r = ::read(fd, p + got, n - got);
        if (r > 0) {
            got += static_cast<size_t>(r);
        } else if (r == 0) {
            if (got == 0) return 0;
            errno = ECONNRESET;
            return -1;
        } else if (errno != EINTR) {
            return -1;
        }
    }
    return 1;
}

inline bool write_full(int fd, const void* buf, size_t n, int64_t deadline_ms = 0) {
    auto* p = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < n) {
        if (wait_fd(fd, POLLOUT, deadline_ms) < 0) return false;
        ssize_t r = ::write(fd, p + sent, n - sent);
        if (r > 0) sent += static_cast<size_t>(r);
        else if (r < 0 && errno != EINTR) return false;
    }
    return true;
}

struct Frame {
    uint8_t type = 0;
    uint32_t id = 0;
    std::vector<uint8_t> payload;
};

inline bool send_frame(int fd, uint8_t type, uint32_t id,
                       const std::vector<uint8_t>& payload, int64_t deadline_ms = 0) {
    uint64_t len = 5 + static_cast<uint64_t>(payload.size());
    if (len > MAX_FRAME) { errno = EMSGSIZE; return false; }
    Writer w;
    w.b.reserve(4 + len);
    w.u32(static_cast<uint32_t>(len));
    w.u8(type);
    w.u32(id);
    w.bytes(payload.data(), payload.size());
    return write_full(fd, w.b.data(), w.b.size(), deadline_ms);
}

// 1 = got a frame, 0 = peer closed cleanly, -1 = error (errno set).
inline int recv_frame(int fd, Frame& f, int64_t deadline_ms = 0) {
    uint8_t hdr[4];
    int r = read_full(fd, hdr, 4, deadline_ms);
    if (r <= 0) return r;
    uint32_t len = (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16) |
                   (uint32_t(hdr[2]) << 8) | uint32_t(hdr[3]);
    if (len < 5 || len > MAX_FRAME) { errno = EPROTO; return -1; }
    std::vector<uint8_t> body(len);
    r = read_full(fd, body.data(), len, deadline_ms);
    if (r <= 0) { if (r == 0) errno = ECONNRESET; return -1; }
    f.type = body[0];
    f.id = (uint32_t(body[1]) << 24) | (uint32_t(body[2]) << 16) |
           (uint32_t(body[3]) << 8) | uint32_t(body[4]);
    f.payload.assign(body.begin() + 5, body.end());
    return 1;
}

}  // namespace tierfs
