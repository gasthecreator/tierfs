// tierfs-device: the reference storage device (device protocol v3, see proto/PROTOCOL.md).
// It stores encrypted chunks and manifests; it never sees keys or plaintext.
//
// Usage: tierfs-device <store-dir> [port=9100] [bind-addr=127.0.0.1]
//                      [--faults=a,b,slow=N] [--insecure-allow-network]
//
// SECURITY: there is no authentication or TLS yet. Anyone who can connect could upload
// junk under a chunk id they have seen on the wire. So it refuses any bind address except
// loopback unless --insecure-allow-network is given (for experiments on a trusted LAN).
// The Mac verifies every stored blob before trusting it, but pairing + mutual TLS must land
// before a device is ever exposed for real.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "../core/crypto.hpp"
#include "../core/devicestore.hpp"
#include "../core/wire.hpp"

using namespace tierfs;
using crypto::Bytes;

static DeviceStore* g_store;
static std::atomic<int> g_conns{0};
constexpr int MAX_CONNECTIONS = 64;
static int g_idle_s = 120;   // TIERFS_DEVICE_IDLE_S overrides (tests)

static bool reply(int fd, uint8_t type, uint32_t id, const Writer& w) { return send_frame(fd, type | MSG_REPLY_FLAG, id, w.b); }
static bool reply_err(int fd, uint32_t id, int err, const std::string& msg) {
    Writer w;
    w.i32(err);
    w.str(msg.size() > 200 ? msg.substr(0, 200) : msg);
    return send_frame(fd, MSG_ERROR, id, w.b);
}

static void put_hash(Writer& w, const std::string& hex) {
    auto b = crypto::from_hex(hex);
    if (!b || b->size() != 32) { for (int i = 0; i < 32; i++) w.u8(0); return; }
    w.bytes(b->data(), 32);
}
static std::string get_hash(Reader& r) {
    r.need(32);
    std::string h = crypto::to_hex(r.p + r.pos, 32);
    r.pos += 32;
    return h;
}
static void put_info(Writer& w, const DevInfo& i) {
    w.str(i.device_id);
    w.u64(i.epoch);
    w.u64(i.seq);
    w.str(i.volume_id);
    w.u64(i.free_bytes);
}

// One request. Returns false to close the connection.
static bool handle(int fd, const Frame& f, Reader& r) {
    DeviceFaults faults = g_store->faults();
    switch (f.type) {
        case MSG_DEV_INFO: {
            Writer w;
            put_info(w, g_store->info());
            return reply(fd, f.type, f.id, w);
        }
        case MSG_DEV_BIND: {
            std::string msg;
            int rc = g_store->bind_volume(r.str(), &msg);
            if (rc) return reply_err(fd, f.id, rc, msg);
            return reply(fd, f.type, f.id, Writer());
        }
        case MSG_DEV_HAS_CHUNKS: {
            uint32_t n = r.u32();
            if (n > 1024) return reply_err(fd, f.id, EMSGSIZE, "too many ids in one request");
            std::vector<std::string> ids;
            for (uint32_t i = 0; i < n; i++) ids.push_back(r.str());
            auto have = g_store->has_chunks(ids);
            Writer w;
            w.u32(n);
            for (bool h : have) w.u8(h ? 1 : 0);
            return reply(fd, f.type, f.id, w);
        }
        case MSG_DEV_PUT_CHUNK: {
            std::string id = r.str();
            std::string claimed = get_hash(r);
            Bytes blob = r.blob(MAX_CHUNK_BLOB);
            PutChunkOut o = g_store->put_chunk(id, blob, claimed);
            if (o.err) return reply_err(fd, f.id, o.err, o.msg);
            if (faults.drop_connection_after_put) return false;   // executed, but the ack is lost
            Writer w;
            w.u8(o.existed ? 1 : 0);
            put_hash(w, o.sha256_hex);
            return reply(fd, f.type, f.id, w);
        }
        case MSG_DEV_GET_CHUNK: {
            Bytes out;
            std::string msg;
            int rc = g_store->get_chunk(r.str(), out, &msg);
            if (rc) return reply_err(fd, f.id, rc, msg);
            Writer w;
            w.blob(out.data(), out.size());
            return reply(fd, f.type, f.id, w);
        }
        case MSG_DEV_PUT_MANIFEST: {
            std::string file_id = r.str();
            int64_t version = r.i64();
            std::string claimed = get_hash(r);
            Bytes blob = r.blob(MAX_MANIFEST_BLOB);
            uint32_t n = r.u32();
            if (n > MAX_MANIFEST_CHUNKS) return reply_err(fd, f.id, EMSGSIZE, "too many chunks");
            std::vector<std::string> ids;
            for (uint32_t i = 0; i < n; i++) ids.push_back(r.str());   // each str() is bounds-checked: a lying count cannot over-read
            PutManifestOut o = g_store->put_manifest(file_id, version, blob, claimed, ids);
            if (o.err) return reply_err(fd, f.id, o.err, o.msg);
            if (faults.drop_connection_after_put) return false;
            Writer w;
            w.u8(o.existed ? 1 : 0);
            w.u64(o.seq);
            put_hash(w, o.sha256_hex);
            return reply(fd, f.type, f.id, w);
        }
        case MSG_DEV_GET_MANIFEST: {
            std::string file_id = r.str();
            int64_t version = r.i64();
            Bytes out;
            std::string msg;
            int rc = g_store->get_manifest(file_id, version, out, &msg);
            if (rc) return reply_err(fd, f.id, rc, msg);
            Writer w;
            w.blob(out.data(), out.size());
            return reply(fd, f.type, f.id, w);
        }
        case MSG_DEV_LIST_MANIFESTS: {
            uint64_t since = r.u64();
            uint32_t max = r.u32();
            std::vector<ManifestEntry> es;
            DevInfo info;
            g_store->list_manifests(since, max, es, &info);
            Writer w;
            w.u64(info.epoch);
            w.u64(info.seq);
            w.u32(static_cast<uint32_t>(es.size()));
            for (auto& e : es) {
                w.u64(e.seq);
                w.str(e.file_id);
                w.i64(e.version);
                put_hash(w, e.sha256_hex);
            }
            return reply(fd, f.type, f.id, w);
        }
        case MSG_DEV_AUDIT: {
            uint32_t n = r.u32();
            if (n > MAX_AUDIT_ITEMS) return reply_err(fd, f.id, EMSGSIZE, "too many audit items");
            std::vector<AuditItem> items;
            for (uint32_t i = 0; i < n; i++) {
                AuditItem a;
                a.kind = r.u8();
                if (a.kind > 1) return reply_err(fd, f.id, EINVAL, "bad audit kind");
                a.id = r.str();
                a.version = r.i64();
                r.need(32);
                a.nonce.assign(r.p + r.pos, r.p + r.pos + 32);
                r.pos += 32;
                items.push_back(std::move(a));
            }
            auto outs = g_store->audit(items);
            Writer w;
            w.u32(static_cast<uint32_t>(outs.size()));
            for (auto& o : outs) {
                w.u8(o.status);
                if (o.status == 0) put_hash(w, o.response_hex);
                else for (int i = 0; i < 32; i++) w.u8(0);
            }
            return reply(fd, f.type, f.id, w);
        }
        default:
            return reply_err(fd, f.id, ENOSYS, "unknown message type");
    }
}

static void serve(int fd) {
    timeval tv{g_idle_s, 0};   // an idle or stalled connection must not hold a thread forever
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    bool greeted = false;
    Frame f;
    for (;;) {
        if (recv_frame(fd, f) <= 0) break;
        try {
            Reader r(f.payload);
            if (f.type == MSG_HELLO) {
                if (r.u16() != DEVICE_PROTO_VERSION) {
                    reply_err(fd, f.id, EPROTO, "this is a device server (protocol 3)");
                    break;
                }
                Writer w;
                w.u16(DEVICE_PROTO_VERSION);
                w.str("tierfs-device");
                greeted = true;
                if (!reply(fd, f.type, f.id, w)) break;
            } else if (!greeted) {
                reply_err(fd, f.id, EPROTO, "HELLO required first");
                break;
            } else if (!handle(fd, f, r)) {
                break;
            }
        } catch (const std::exception& ex) {   // malformed payload: say so and hang up
            reply_err(fd, f.id, EPROTO, ex.what());
            break;
        }
    }
    close(fd);
    g_conns--;
}

int main(int argc, char** argv) {
    std::vector<std::string> pos;
    std::string faults_csv;
    bool insecure = false;
    if (const char* e = getenv("TIERFS_DEVICE_FAULTS")) faults_csv = e;
    if (const char* e = getenv("TIERFS_DEVICE_IDLE_S")) g_idle_s = atoi(e) > 0 ? atoi(e) : 120;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a.compare(0, 9, "--faults=") == 0) faults_csv = a.substr(9);
        else if (a == "--insecure-allow-network") insecure = true;
        else pos.push_back(a);
    }
    if (pos.empty()) {
        fprintf(stderr, "usage: %s <store-dir> [port] [bind-addr] [--faults=...] [--insecure-allow-network]\n", argv[0]);
        return 2;
    }
    int port = pos.size() > 1 ? atoi(pos[1].c_str()) : 9100;
    std::string bind_addr = pos.size() > 2 ? pos[2] : "127.0.0.1";
    if (!insecure && bind_addr != "127.0.0.1") {
        fprintf(stderr, "refusing to listen on %s: there is no authentication yet. "
                        "Use 127.0.0.1, or pass --insecure-allow-network on a network you trust.\n", bind_addr.c_str());
        return 2;
    }
    DeviceFaults faults;
    std::string ferr;
    if (!DeviceFaults::parse(faults_csv, &faults, &ferr)) { fprintf(stderr, "%s\n", ferr.c_str()); return 2; }

    std::string err;
    auto store = DeviceStore::open(pos[0], &err);
    if (!store) { fprintf(stderr, "cannot open store: %s\n", err.c_str()); return 1; }
    store->set_faults(faults);
    g_store = store.get();

    signal(SIGPIPE, SIG_IGN);
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr) != 1) { fprintf(stderr, "bad bind address\n"); return 2; }
    if (bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 || listen(ls, 32) != 0) { perror("bind/listen"); return 1; }
    DevInfo i = store->info();
    fprintf(stderr, "tierfs-device %s on %s:%d (epoch %llu, seq %llu%s%s)\n", i.device_id.c_str(), bind_addr.c_str(), port,
            (unsigned long long)i.epoch, (unsigned long long)i.seq, faults_csv.empty() ? "" : ", FAULTS: ", faults_csv.c_str());
    for (;;) {
        int c = accept(ls, nullptr, nullptr);
        if (c < 0) continue;
        if (g_conns.load() >= MAX_CONNECTIONS) { close(c); continue; }   // shed load instead of exhausting threads
        g_conns++;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        std::thread(serve, c).detach();
    }
}
