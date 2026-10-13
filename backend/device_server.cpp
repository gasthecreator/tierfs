// tierfs-device: the reference storage device (device protocol v3, see proto/PROTOCOL.md).
// It stores encrypted chunks and manifests; it never sees keys or plaintext.
//
// Usage: tierfs-device <store-dir> [port=9100] [bind-addr=127.0.0.1]
//                      [--faults=a,b,slow=N] [--insecure-allow-network] [--allow-delete]
//        tierfs-device <store-dir> --show-pairing-code     print the pairing code (creating the secret on first use) and exit
//        tierfs-device <store-dir> --new-pairing-code      replace the pairing secret (every Mac must pair again) and exit
//
// SECURITY: a device is either PAIRED or open.
//   * Paired (the store holds pairing.key): every connection must complete the authenticated, encrypted handshake of protocol
//     version 4 (docs/adr/0009); plaintext clients are refused. Such a device may listen on any address.
//   * Open (no pairing.key): plaintext protocol version 3 with no authentication. Anyone who can connect could upload junk
//     under a chunk id they have seen on the wire, so it refuses any bind address except loopback unless
//     --insecure-allow-network is given (for experiments on a trusted LAN).
// Deleting (garbage collection, ADR-0010) is accepted only by a paired device, or by an open one started with --allow-delete.
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
#include <fstream>
#include <thread>

#include <fcntl.h>
#include <sys/stat.h>

#include "../core/crypto.hpp"
#include "../core/devicestore.hpp"
#include "../core/securechannel.hpp"
#include "../core/wire.hpp"

using namespace tierfs;
using crypto::Bytes;

static DeviceStore* g_store;
static std::optional<Bytes> g_psk;      // the pairing secret, if this device is paired
static int64_t g_handshake_ms = 10000;  // a peer that has not finished the handshake by then is dropped (slow-loris)

// One client connection, plain (open device) or sealed (paired device).
struct Conn {
    int fd;
    std::unique_ptr<chan::Channel> ch;
    bool send(uint8_t type, uint32_t id, const Bytes& payload) { return ch ? ch->send(type, id, payload) : send_frame(fd, type, id, payload); }
    int recv(Frame& f) { return ch ? ch->recv(f) : recv_frame(fd, f); }
};
static std::atomic<int> g_conns{0};
constexpr int MAX_CONNECTIONS = 64;
static int g_idle_s = 120;   // TIERFS_DEVICE_IDLE_S overrides (tests)

static bool reply(Conn& c, uint8_t type, uint32_t id, const Writer& w) { return c.send(type | MSG_REPLY_FLAG, id, w.b); }
static bool reply_err(Conn& c, uint32_t id, int err, const std::string& msg) {
    Writer w;
    w.i32(err);
    w.str(msg.size() > 200 ? msg.substr(0, 200) : msg);
    return c.send(MSG_ERROR, id, w.b);
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
static bool handle(Conn& c, const Frame& f, Reader& r) {
    DeviceFaults faults = g_store->faults();
    switch (f.type) {
        case MSG_DEV_INFO: {
            Writer w;
            put_info(w, g_store->info());
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_BIND: {
            std::string msg;
            int rc = g_store->bind_volume(r.str(), &msg);
            if (rc) return reply_err(c, f.id, rc, msg);
            return reply(c, f.type, f.id, Writer());
        }
        case MSG_DEV_HAS_CHUNKS: {
            uint32_t n = r.u32();
            if (n > 1024) return reply_err(c, f.id, EMSGSIZE, "too many ids in one request");
            std::vector<std::string> ids;
            for (uint32_t i = 0; i < n; i++) ids.push_back(r.str());
            auto have = g_store->has_chunks(ids);
            Writer w;
            w.u32(n);
            for (bool h : have) w.u8(h ? 1 : 0);
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_PUT_CHUNK: {
            std::string id = r.str();
            std::string claimed = get_hash(r);
            Bytes blob = r.blob(MAX_CHUNK_BLOB);
            PutChunkOut o = g_store->put_chunk(id, blob, claimed);
            if (o.err) return reply_err(c, f.id, o.err, o.msg);
            if (faults.drop_connection_after_put) return false;   // executed, but the ack is lost
            Writer w;
            w.u8(o.existed ? 1 : 0);
            put_hash(w, o.sha256_hex);
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_GET_CHUNK: {
            Bytes out;
            std::string msg;
            int rc = g_store->get_chunk(r.str(), out, &msg);
            if (rc) return reply_err(c, f.id, rc, msg);
            Writer w;
            w.blob(out.data(), out.size());
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_PUT_MANIFEST: {
            std::string file_id = r.str();
            int64_t version = r.i64();
            std::string claimed = get_hash(r);
            Bytes blob = r.blob(MAX_MANIFEST_BLOB);
            uint32_t n = r.u32();
            if (n > MAX_MANIFEST_CHUNKS) return reply_err(c, f.id, EMSGSIZE, "too many chunks");
            std::vector<std::string> ids;
            for (uint32_t i = 0; i < n; i++) ids.push_back(r.str());   // each str() is bounds-checked: a lying count cannot over-read
            PutManifestOut o = g_store->put_manifest(file_id, version, blob, claimed, ids);
            if (o.err) return reply_err(c, f.id, o.err, o.msg);
            if (faults.drop_connection_after_put) return false;
            Writer w;
            w.u8(o.existed ? 1 : 0);
            w.u64(o.seq);
            put_hash(w, o.sha256_hex);
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_GET_MANIFEST: {
            std::string file_id = r.str();
            int64_t version = r.i64();
            Bytes out;
            std::string msg;
            int rc = g_store->get_manifest(file_id, version, out, &msg);
            if (rc) return reply_err(c, f.id, rc, msg);
            Writer w;
            w.blob(out.data(), out.size());
            return reply(c, f.type, f.id, w);
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
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_AUDIT: {
            uint32_t n = r.u32();
            if (n > MAX_AUDIT_ITEMS) return reply_err(c, f.id, EMSGSIZE, "too many audit items");
            std::vector<AuditItem> items;
            for (uint32_t i = 0; i < n; i++) {
                AuditItem a;
                a.kind = r.u8();
                if (a.kind > 1) return reply_err(c, f.id, EINVAL, "bad audit kind");
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
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_DELETE_MANIFESTS: {
            uint32_t n = r.u32();
            if (n < 1 || n > MAX_DELETE_ITEMS) return reply_err(c, f.id, EMSGSIZE, "between 1 and 64 manifests per request");
            std::vector<std::pair<std::string, int64_t>> items;
            for (uint32_t i = 0; i < n; i++) {
                std::string fid = r.str();
                int64_t ver = r.i64();
                items.emplace_back(std::move(fid), ver);
            }
            DeleteManifestsOut o = g_store->delete_manifests(items);
            if (o.err) return reply_err(c, f.id, o.err, o.msg);
            Writer w;
            w.u64(o.seq);
            w.u32(static_cast<uint32_t>(o.deleted.size()));
            for (uint8_t d : o.deleted) w.u8(d);
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_GC_STATUS: {
            GcStatus g = g_store->gc_status();
            Writer w;
            w.u8(g.deletions_allowed ? 1 : 0);
            w.u32(g.manifests);
            w.u32(g.manifests_without_refs);
            w.u64(g.chunks);
            w.u64(g.chunk_bytes);
            w.u64(g.unreferenced_chunks);
            w.u64(g.unreferenced_bytes);
            w.u64(g.manifests_deleted);
            w.u64(g.chunks_deleted);
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_SWEEP: {
            uint64_t min_age = r.u64();
            uint32_t max_chunks = r.u32();
            uint8_t dry = r.u8();
            if (dry > 1) return reply_err(c, f.id, EINVAL, "bad flag");
            SweepOut o = g_store->sweep(min_age, max_chunks, dry == 1);
            if (o.err) return reply_err(c, f.id, o.err, o.msg);
            Writer w;
            w.u64(o.chunks_deleted);
            w.u64(o.bytes_deleted);
            w.u64(o.chunks_left);
            w.u64(o.strays_removed);
            return reply(c, f.type, f.id, w);
        }
        default:
            return reply_err(c, f.id, ENOSYS, "unknown message type");
    }
}

static void serve(int fd) {
    timeval tv{g_idle_s, 0};   // an idle or stalled connection must not hold a thread forever
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    Conn c{fd, nullptr};
    if (g_psk) {  // a paired device speaks only the authenticated channel
        std::string why;
        int first = -1;
        auto lookup = [](const Bytes& id) -> std::optional<Bytes> {
            if (g_psk && id == chan::key_id(*g_psk)) return g_psk;
            return std::nullopt;
        };
        c.ch = chan::accept_secure(fd, lookup, now_ms() + g_handshake_ms, &why, &first);
        if (!c.ch) {
            if (first == MSG_HELLO) {  // a plaintext client: tell it plainly what is needed, then hang up
                Writer w;
                w.i32(EPERM);
                w.str("this device is paired: authentication is required (pair this Mac with it first)");
                send_frame(fd, MSG_ERROR, 0, w.b, now_ms() + 2000);
            }
            close(fd);
            g_conns--;
            return;
        }
    }
    bool greeted = false;
    Frame f;
    for (;;) {
        if (c.recv(f) <= 0) break;
        try {
            Reader r(f.payload);
            if (f.type == MSG_HELLO) {
                if (r.u16() != DEVICE_PROTO_VERSION) {
                    reply_err(c, f.id, EPROTO, "this is a device server (protocol 3)");
                    break;
                }
                Writer w;
                w.u16(DEVICE_PROTO_VERSION);
                w.str("tierfs-device");
                greeted = true;
                if (!reply(c, f.type, f.id, w)) break;
            } else if (!greeted) {
                reply_err(c, f.id, EPROTO, "HELLO required first");
                break;
            } else if (!handle(c, f, r)) {
                break;
            }
        } catch (const std::exception& ex) {   // malformed payload: say so and hang up
            reply_err(c, f.id, EPROTO, ex.what());
            break;
        }
    }
    close(fd);
    g_conns--;
}

// ---- the pairing secret: <store>/pairing.key, 64 hex characters, mode 0600 ----
static std::optional<Bytes> load_pairing(const std::string& store, std::string* err) {
    std::string path = store + "/pairing.key";
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) return std::nullopt;  // not paired
    if (!S_ISREG(st.st_mode) || (st.st_mode & 077) != 0) {
        *err = path + " must be a regular file readable only by its owner (chmod 600)";
        return std::nullopt;
    }
    std::ifstream f(path);
    std::string hex;
    std::getline(f, hex);
    auto raw = crypto::from_hex(hex);
    if (!raw || raw->size() != chan::PSK_LEN) {
        *err = path + " does not hold 64 hex characters";
        return std::nullopt;
    }
    return raw;
}

static bool write_pairing(const std::string& store, const Bytes& secret, bool replace, std::string* err) {
    std::string path = store + "/pairing.key", tmp = path + ".new";
    unlink(tmp.c_str());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        *err = "cannot create " + tmp + ": " + strerror(errno);
        return false;
    }
    std::string hex = crypto::to_hex(secret.data(), secret.size()) + "\n";
    bool ok = write(fd, hex.data(), hex.size()) == static_cast<ssize_t>(hex.size()) && fcntl(fd, F_FULLFSYNC) != -1;
    close(fd);
    if (!ok) {
        unlink(tmp.c_str());
        *err = "cannot write " + tmp;
        return false;
    }
    struct stat st;
    if (!replace && lstat(path.c_str(), &st) == 0) {
        unlink(tmp.c_str());
        *err = path + " already exists";
        return false;
    }
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        *err = "cannot move " + tmp + " into place";
        return false;
    }
    return true;
}

static void print_pairing(const Bytes& secret) {
    crypto::SecretKey k(secret.data());
    printf(
        "PAIRING CODE (type it on the Mac with: tierctl pair <host:port> --store keychain):\n\n    %s\n\nkey id: %s\n"
        "Anyone who has this code can act as the Mac towards this device. Do not photograph it or send it anywhere.\n",
        crypto::encode_recovery(k).c_str(), chan::key_id_hex(secret).c_str());
}

int main(int argc, char** argv) {
    std::vector<std::string> pos;
    std::string faults_csv;
    bool insecure = false, show_code = false, new_code = false, allow_delete = false;
    if (const char* e = getenv("TIERFS_DEVICE_FAULTS")) faults_csv = e;
    if (const char* e = getenv("TIERFS_DEVICE_IDLE_S")) g_idle_s = atoi(e) > 0 ? atoi(e) : 120;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a.compare(0, 9, "--faults=") == 0) faults_csv = a.substr(9);
        else if (a == "--insecure-allow-network") insecure = true;
        else if (a == "--allow-delete")
            allow_delete = true;
        else if (a == "--show-pairing-code")
            show_code = true;
        else if (a == "--new-pairing-code")
            new_code = true;
        else pos.push_back(a);
    }
    if (pos.empty()) {
        fprintf(stderr, "usage: %s <store-dir> [port] [bind-addr] [--faults=...] [--insecure-allow-network] [--allow-delete]\n", argv[0]);
        return 2;
    }
    if (show_code || new_code) {  // pairing management: no server, no store needed beyond the directory
        std::string perr;
        mkdir(pos[0].c_str(), 0700);
        auto existing = load_pairing(pos[0], &perr);
        if (!perr.empty()) {
            fprintf(stderr, "%s\n", perr.c_str());
            return 1;
        }
        if (new_code && existing) fprintf(stderr, "replacing the pairing secret: every Mac must pair again\n");
        if (new_code || !existing) {
            Bytes secret = crypto::random_bytes(chan::PSK_LEN);
            if (secret.size() != chan::PSK_LEN) {
                fprintf(stderr, "the system random generator failed\n");
                return 1;
            }
            if (!write_pairing(pos[0], secret, new_code, &perr)) {
                fprintf(stderr, "%s\n", perr.c_str());
                return 1;
            }
            existing = secret;
        }
        print_pairing(*existing);
        return 0;
    }
    std::string perr;
    g_psk = load_pairing(pos[0], &perr);
    if (!perr.empty()) {
        fprintf(stderr, "%s\n", perr.c_str());
        return 1;
    }
    if (const char* e = getenv("TIERFS_DEVICE_HANDSHAKE_MS")) g_handshake_ms = std::max(50, atoi(e));
    int port = pos.size() > 1 ? atoi(pos[1].c_str()) : 9100;
    std::string bind_addr = pos.size() > 2 ? pos[2] : "127.0.0.1";
    if (!g_psk && !insecure && bind_addr != "127.0.0.1") {
        fprintf(stderr,
                "refusing to listen on %s: this device is not paired, so it has no authentication. "
                "Pair it (tierfs-device <store> --show-pairing-code), use 127.0.0.1, or pass --insecure-allow-network on a network you trust.\n",
                bind_addr.c_str());
        return 2;
    }
    DeviceFaults faults;
    std::string ferr;
    if (!DeviceFaults::parse(faults_csv, &faults, &ferr)) { fprintf(stderr, "%s\n", ferr.c_str()); return 2; }

    std::string err;
    auto store = DeviceStore::open(pos[0], &err);
    if (!store) { fprintf(stderr, "cannot open store: %s\n", err.c_str()); return 1; }
    store->set_faults(faults);
    // Deleting is allowed only for a Mac that proved it knows the pairing secret, or when the operator says so (loopback experiments, tests).
    store->set_deletions_allowed(g_psk.has_value() || allow_delete);
    if (const char* e = getenv("TIERFS_DEVICE_MIN_SWEEP_AGE")) store->set_min_sweep_age(strtoull(e, nullptr, 10));
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
    fprintf(stderr, "tierfs-device %s on %s:%d (epoch %llu, seq %llu, %s%s%s%s)\n", i.device_id.c_str(), bind_addr.c_str(), port,
            (unsigned long long)i.epoch, (unsigned long long)i.seq,
            g_psk ? "PAIRED, authenticated channel required" : "NOT PAIRED: plaintext, loopback only",
            (g_psk || allow_delete) ? ", deletions accepted" : "", faults_csv.empty() ? "" : ", FAULTS: ", faults_csv.c_str());
    for (;;) {
        int c = accept(ls, nullptr, nullptr);
        if (c < 0) continue;
        if (g_conns.load() >= MAX_CONNECTIONS) { close(c); continue; }   // shed load instead of exhausting threads
        g_conns++;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        std::thread(serve, c).detach();
    }
}
