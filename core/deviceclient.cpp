#include "deviceclient.hpp"

#include "crypto.hpp"
#include "net.hpp"
#include "wire.hpp"

namespace tierfs {
namespace {

// Same rule as the filesystem client: slower than this counts as "unreachable".
constexpr uint64_t MIN_RATE_BYTES_PER_SEC = 256 * 1024;

void put_hash(Writer& w, const std::string& hex) {
    auto b = crypto::from_hex(hex);
    if (!b || b->size() != 32) { for (int i = 0; i < 32; i++) w.u8(0); return; }
    w.bytes(b->data(), 32);
}
std::string get_hash(Reader& r) {
    r.need(32);
    std::string h = crypto::to_hex(r.p + r.pos, 32);
    r.pos += 32;
    return h;
}

}  // namespace

DeviceClient::DeviceClient(std::string host, uint16_t port, int timeout_ms, crypto::Bytes pairing_secret)
    : host_(std::move(host)), port_(std::to_string(port)), timeout_ms_(timeout_ms > 0 ? timeout_ms : 3000), psk_(std::move(pairing_secret)) {}

DeviceClient::~DeviceClient() { drop_connection(); }

void DeviceClient::drop_connection() {
    ch_.reset();
    if (fd_ >= 0) close(fd_);
    fd_ = -1;
}

void DeviceClient::disconnect() {
    std::lock_guard<std::mutex> lk(mu_);
    drop_connection();
}

bool DeviceClient::tx(uint8_t type, uint32_t id, const std::vector<uint8_t>& payload, int64_t deadline) {
    return ch_ ? ch_->send(type, id, payload, deadline) : send_frame(fd_, type, id, payload, deadline);
}

int DeviceClient::rx(Frame& f, int64_t deadline) { return ch_ ? ch_->recv(f, deadline) : recv_frame(fd_, f, deadline); }

bool DeviceClient::ensure_connected(DevRes* why) {
    if (fd_ >= 0) return true;
    int fd = connect_with_deadline(host_, port_, timeout_ms_);
    if (fd < 0) { why->err = EHOSTUNREACH; why->msg = "cannot reach the device"; return false; }
    Writer w;
    w.u16(DEVICE_PROTO_VERSION);
    Frame resp;
    uint32_t id = next_id_++;
    int64_t deadline = now_ms() + timeout_ms_;
    if (!psk_.empty()) {   // a paired device: authenticate and encrypt first; the v3 messages then run inside the channel
        std::string cwhy;
        ch_ = chan::connect_secure(fd, psk_, deadline, &cwhy);
        if (!ch_) {
            close(fd);
            why->err = EACCES;
            why->msg = "authentication with the device failed: " + cwhy;
            return false;
        }
    }
    fd_ = fd;
    if (!tx(MSG_HELLO, id, w.b, deadline) || rx(resp, deadline) != 1) {
        drop_connection();
        why->err = EIO;
        why->msg = "handshake with the device failed";
        return false;
    }
    if (resp.type == MSG_ERROR) {
        drop_connection();
        try {
            Reader r(resp.payload);
            why->err = r.i32();
            why->msg = r.str();
        } catch (...) { why->err = EPROTO; }
        if (why->err <= 0) why->err = EPROTO;
        return false;
    }
    if (resp.type != (MSG_HELLO | MSG_REPLY_FLAG) || resp.id != id) {
        drop_connection();
        why->err = EPROTO;
        why->msg = "unexpected handshake reply";
        return false;
    }
    return true;
}

// One request/response. A server ERROR is an answer (connection stays up); an I/O failure
// drops the connection and retries once on a fresh one, but only if the old one had been idle
// (every device operation is idempotent, so a repeat is harmless).
DevRes DeviceClient::call(uint8_t type, const std::vector<uint8_t>& payload, std::vector<uint8_t>& reply, uint64_t expect_bytes) {
    std::lock_guard<std::mutex> lk(mu_);
    DevRes res;
    for (int attempt = 0; attempt < 2; attempt++) {
        bool had_conn = fd_ >= 0;
        res = DevRes();
        if (!ensure_connected(&res)) return res;
        uint32_t id = next_id_++;
        int64_t deadline = now_ms() + timeout_ms_ + static_cast<int64_t>((expect_bytes + payload.size()) * 1000 / MIN_RATE_BYTES_PER_SEC);
        Frame resp;
        bool ok = tx(type, id, payload, deadline) && rx(resp, deadline) == 1 && resp.id == id;
        if (ok) {
            if (resp.type == MSG_ERROR) {
                try {
                    Reader r(resp.payload);
                    res.err = r.i32();
                    res.msg = r.str();
                } catch (...) { res.err = EPROTO; res.msg = "malformed error reply"; }
                if (res.err <= 0) res.err = EIO;
                return res;
            }
            if (resp.type != (type | MSG_REPLY_FLAG)) {
                drop_connection();
                res.err = EPROTO;
                res.msg = "unexpected reply type";
                return res;
            }
            reply = std::move(resp.payload);
            return res;
        }
        int e = errno;
        drop_connection();
        res.err = (e == EAGAIN || e == EWOULDBLOCK) ? ETIMEDOUT : EIO;
        res.msg = res.err == ETIMEDOUT ? "the device did not answer in time" : "connection to the device failed";
        if (!had_conn) return res;
    }
    return res;
}

DevRes DeviceClient::info(DevInfo& out) {
    std::vector<uint8_t> rep;
    DevRes r = call(MSG_DEV_INFO, {}, rep, 0);
    if (!r.ok()) return r;
    try {
        Reader rd(rep);
        out.device_id = rd.str();
        out.epoch = rd.u64();
        out.seq = rd.u64();
        out.volume_id = rd.str();
        out.free_bytes = rd.u64();
    } catch (...) { return {EPROTO, "malformed reply"}; }
    return r;
}

DevRes DeviceClient::bind(const std::string& volume_id) {
    Writer w;
    w.str(volume_id);
    std::vector<uint8_t> rep;
    return call(MSG_DEV_BIND, w.b, rep, 0);
}

DevRes DeviceClient::has_chunks(const std::vector<std::string>& ids, std::vector<bool>& out) {
    out.clear();
    for (size_t off = 0; off < ids.size() || off == 0; off += 1024) {   // the device caps one request at 1024 ids
        Writer w;
        size_t n = std::min<size_t>(1024, ids.size() - std::min(off, ids.size()));
        w.u32(static_cast<uint32_t>(n));
        for (size_t i = 0; i < n; i++) w.str(ids[off + i]);
        std::vector<uint8_t> rep;
        DevRes r = call(MSG_DEV_HAS_CHUNKS, w.b, rep, 0);
        if (!r.ok()) return r;
        try {
            Reader rd(rep);
            uint32_t got = rd.u32();
            if (got != n) return {EPROTO, "wrong number of answers"};
            for (uint32_t i = 0; i < got; i++) out.push_back(rd.u8() != 0);
        } catch (...) { return {EPROTO, "malformed reply"}; }
        if (ids.empty()) break;
    }
    return DevRes();
}

DevRes DeviceClient::put_chunk(const std::string& chunk_id, const std::vector<uint8_t>& blob, PutChunkReply& out) {
    Writer w;
    w.str(chunk_id);
    put_hash(w, crypto::sha256_hex(blob.data(), blob.size()));
    w.blob(blob.data(), blob.size());
    std::vector<uint8_t> rep;
    DevRes r = call(MSG_DEV_PUT_CHUNK, w.b, rep, 0);
    if (!r.ok()) return r;
    try {
        Reader rd(rep);
        out.existed = rd.u8() != 0;
        out.sha256_hex = get_hash(rd);
    } catch (...) { return {EPROTO, "malformed reply"}; }
    return r;
}

DevRes DeviceClient::get_chunk(const std::string& chunk_id, std::vector<uint8_t>& out) {
    Writer w;
    w.str(chunk_id);
    std::vector<uint8_t> rep;
    DevRes r = call(MSG_DEV_GET_CHUNK, w.b, rep, MAX_CHUNK_BLOB);
    if (!r.ok()) return r;
    try {
        Reader rd(rep);
        out = rd.blob(MAX_CHUNK_BLOB);
    } catch (...) { return {EPROTO, "malformed reply"}; }
    return r;
}

DevRes DeviceClient::put_manifest(const std::string& file_id, int64_t version, const std::vector<uint8_t>& blob,
                                  const std::vector<std::string>& chunk_ids, PutManifestReply& out) {
    Writer w;
    w.str(file_id);
    w.i64(version);
    put_hash(w, crypto::sha256_hex(blob.data(), blob.size()));
    w.blob(blob.data(), blob.size());
    w.u32(static_cast<uint32_t>(chunk_ids.size()));
    for (const auto& c : chunk_ids) w.str(c);
    if (w.b.size() + 5 > MAX_FRAME) return {EMSGSIZE, "manifest too large for one request (file too big for protocol v3)"};
    std::vector<uint8_t> rep;
    DevRes r = call(MSG_DEV_PUT_MANIFEST, w.b, rep, 0);
    if (!r.ok()) return r;
    try {
        Reader rd(rep);
        out.existed = rd.u8() != 0;
        out.seq = rd.u64();
        out.sha256_hex = get_hash(rd);
    } catch (...) { return {EPROTO, "malformed reply"}; }
    return r;
}

DevRes DeviceClient::get_manifest(const std::string& file_id, int64_t version, std::vector<uint8_t>& out) {
    Writer w;
    w.str(file_id);
    w.i64(version);
    std::vector<uint8_t> rep;
    DevRes r = call(MSG_DEV_GET_MANIFEST, w.b, rep, MAX_MANIFEST_BLOB);
    if (!r.ok()) return r;
    try {
        Reader rd(rep);
        out = rd.blob(MAX_MANIFEST_BLOB);
    } catch (...) { return {EPROTO, "malformed reply"}; }
    return r;
}

DevRes DeviceClient::list_manifests(uint64_t since, uint32_t max, ListReply& out) {
    Writer w;
    w.u64(since);
    w.u32(max);
    std::vector<uint8_t> rep;
    DevRes r = call(MSG_DEV_LIST_MANIFESTS, w.b, rep, 0);
    if (!r.ok()) return r;
    try {
        Reader rd(rep);
        out.epoch = rd.u64();
        out.seq = rd.u64();
        uint32_t n = rd.u32();
        out.entries.clear();
        for (uint32_t i = 0; i < n; i++) {   // no reserve(n): the count comes from the network
            ManifestEntry e;
            e.seq = rd.u64();
            e.file_id = rd.str();
            e.version = rd.i64();
            e.sha256_hex = get_hash(rd);
            out.entries.push_back(std::move(e));
        }
    } catch (...) { return {EPROTO, "malformed reply"}; }
    return r;
}

DevRes DeviceClient::audit(const std::vector<AuditItem>& items, std::vector<AuditOut>& out) {
    out.clear();
    if (items.size() > MAX_AUDIT_ITEMS) return {EMSGSIZE, "too many items in one audit"};
    Writer w;
    w.u32(static_cast<uint32_t>(items.size()));
    for (const auto& a : items) {
        if (a.nonce.size() != 32) return {EINVAL, "audit nonce must be 32 bytes"};
        w.u8(a.kind);
        w.str(a.id);
        w.i64(a.version);
        w.bytes(a.nonce.data(), 32);
    }
    std::vector<uint8_t> rep;
    DevRes r = call(MSG_DEV_AUDIT, w.b, rep, items.size() * MAX_CHUNK_BLOB / 16);
    if (!r.ok()) return r;
    try {
        Reader rd(rep);
        uint32_t n = rd.u32();
        if (n != items.size()) return {EPROTO, "wrong number of audit answers"};
        for (uint32_t i = 0; i < n; i++) {
            AuditOut o;
            o.status = rd.u8();
            std::string h = get_hash(rd);
            if (o.status == 0) o.response_hex = h;
            out.push_back(std::move(o));
        }
    } catch (...) { return {EPROTO, "malformed reply"}; }
    return r;
}

}  // namespace tierfs
