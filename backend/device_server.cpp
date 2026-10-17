// tierfs-device: the reference storage device (device protocol v3, see proto/PROTOCOL.md).
// It stores encrypted chunks and manifests; it never sees keys or plaintext.
//
// Usage: tierfs-device <store-dir> [port=9100] [bind-addr=127.0.0.1]
//                      [--faults=a,b,slow=N] [--insecure-allow-network] [--allow-delete] [--advertise[=NAME]]
//        tierfs-device <store-dir> --show-pairing-code     print the pairing code (creating the secret on first use) and exit
//        tierfs-device <store-dir> --new-pairing-code      replace the pairing secret (every Mac must pair again) and exit
//
// SECURITY: a device is either PAIRED or open.
//   * Paired (the store holds pairing.key): every connection must complete the authenticated, encrypted handshake of protocol
//     version 4 (docs/adr/0009); plaintext clients are refused. Such a device may listen on any address.
//   * Open (no pairing.key): plaintext protocol version 3 with no authentication. Anyone who can connect could upload junk
//     under a chunk id they have seen on the wire, so it refuses any bind address except loopback unless
//     --insecure-allow-network is given (for experiments on a trusted LAN).
// --advertise announces a PAIRED device on the local network (Bonjour, ADR-0013) so a Mac can find it again when its address changes; an unpaired
// device refuses.
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
#include <memory>
#include <thread>

#include <fcntl.h>
#include <sys/stat.h>

#include "../core/crypto.hpp"
#include "../core/devicestore.hpp"
#include "../core/fsutil.hpp"
#include "../core/pairings.hpp"
#include "../core/discovery.hpp"
#include "../core/securechannel.hpp"
#include "../core/wire.hpp"

using namespace tierfs;
using crypto::Bytes;

static DeviceStore* g_store;
static bool g_paired = false;           // started with at least one pairing: speaks only the authenticated channel
static std::string g_store_dir;         // where the pairings are read from (at each handshake, and when a connection's file changes)
static int64_t g_handshake_ms = 10000;  // a peer that has not finished the handshake by then is dropped (slow-loris)

// One client connection, plain (open device) or sealed (paired device).
struct Conn {
    int fd;
    std::unique_ptr<chan::Channel> ch;
    std::optional<pairing::Entry> entry;  // which pairing this (paired) connection authenticated with
    // A revoked pairing ends its connections at their next request; a changed one (its right to delete) takes effect at once.
    bool still_valid() {
        if (!entry) return true;
        auto e = pairing::refresh(*entry);
        if (!e) return false;
        entry = e;
        return true;
    }
    // A paired connection may delete only if its pairing says so; an open device's connections follow the store's own flag (--allow-delete).
    bool may_not_delete() const { return entry && !entry->allow_delete; }
    bool send(uint8_t type, uint32_t id, const Bytes& payload) { return ch ? ch->send(type, id, payload) : send_frame(fd, type, id, payload); }
    int recv(Frame& f) { return ch ? ch->recv(f) : recv_frame(fd, f); }
};
static std::atomic<int> g_conns{0};
constexpr int MAX_CONNECTIONS = 64;
static int g_idle_s = 120;   // TIERFS_DEVICE_IDLE_S overrides (tests)

static const char* NO_DELETE_RIGHT = "this pairing may not delete (add it with --pairing-allow-delete, or use the primary pairing)";

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
    if (!c.still_valid()) return false;  // this Mac's pairing was revoked
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
            if (c.may_not_delete()) return reply_err(c, f.id, EPERM, NO_DELETE_RIGHT);
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
            w.u8(g.deletions_allowed && !c.may_not_delete() ? 1 : 0);
            w.u32(g.manifests);
            w.u32(g.manifests_without_refs);
            w.u64(g.chunks);
            w.u64(g.chunk_bytes);
            w.u64(g.unreferenced_chunks);
            w.u64(g.unreferenced_bytes);
            w.u64(g.manifests_deleted);
            w.u64(g.chunks_deleted);
            w.u64(g.trash_files);  // (added in ADR-0017; a client that predates it ignores what follows)
            w.u64(g.trash_bytes);
            w.i64(g.trash_retention_s);
            return reply(c, f.type, f.id, w);
        }
        case MSG_DEV_SWEEP: {
            if (c.may_not_delete()) return reply_err(c, f.id, EPERM, NO_DELETE_RIGHT);
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
    Conn c{fd, nullptr, std::nullopt};
    if (g_paired) {  // a paired device speaks only the authenticated channel
        std::string why;
        int first = -1;
        std::optional<pairing::Entry> picked;
        auto lookup = [&picked](const Bytes& id) -> std::optional<Bytes> {
            picked = pairing::find(g_store_dir, id);  // read now: a Mac revoked a moment ago is refused
            if (picked) return picked->secret;
            return std::nullopt;
        };
        c.ch = chan::accept_secure(fd, lookup, now_ms() + g_handshake_ms, &why, &first);
        if (c.ch) c.entry = picked;
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

// ---- the pairings (core/pairings.*): <store>/pairing.key (the original) and <store>/pairings/<keyid>.key (one per Mac)

static void print_pairing(const pairing::Entry& e) {
    crypto::SecretKey k(e.secret.data());
    printf(
        "PAIRING CODE (type it on the Mac with: tierctl pair <host:port> --store keychain):\n\n    %s\n\nkey id: %s\nlabel: %s, %s\n"
        "Anyone who has this code can act as the Mac towards this device. Do not photograph it or send it anywhere.\n",
        crypto::encode_recovery(k).c_str(), e.key_id.c_str(), e.label.c_str(), e.allow_delete ? "may delete (garbage collection)" : "may not delete");
}

int main(int argc, char** argv) {
    std::vector<std::string> pos;
    std::string faults_csv;
    bool insecure = false, show_code = false, new_code = false, allow_delete = false, advertise = false;
    std::string adv_name, add_label, revoke_id;
    bool add_pairing = false, pairing_delete = false, list_pairings = false, revoke = false;
    bool list_trash = false, restore_trash = false, empty_trash = false;
    int64_t restore_window = 0, trash_days = -1;
    std::string lock_dir;
    if (const char* e = getenv("TIERFS_DEVICE_FAULTS")) faults_csv = e;
    if (const char* e = getenv("TIERFS_DEVICE_IDLE_S")) g_idle_s = atoi(e) > 0 ? atoi(e) : 120;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a.compare(0, 9, "--faults=") == 0) faults_csv = a.substr(9);
        else if (a == "--insecure-allow-network") insecure = true;
        else if (a == "--allow-delete")
            allow_delete = true;
        else if (a == "--advertise")
            advertise = true;
        else if (a.compare(0, 12, "--advertise=") == 0) {
            advertise = true;
            adv_name = a.substr(12);
        } else if (a == "--add-pairing" || a.compare(0, 14, "--add-pairing=") == 0) {
            add_pairing = true;
            add_label = a.size() > 14 ? a.substr(14) : "";
        } else if (a == "--pairing-allow-delete")
            pairing_delete = true;
        else if (a == "--list-pairings")
            list_pairings = true;
        else if (a.compare(0, 11, "--lock-dir=") == 0)
            lock_dir = a.substr(11);
        else if (a.compare(0, 13, "--trash-days=") == 0)
            trash_days = atoll(a.c_str() + 13);
        else if (a == "--list-trash")
            list_trash = true;
        else if (a == "--restore-trash" || a.compare(0, 16, "--restore-trash=") == 0) {
            restore_trash = true;
            restore_window = a.size() > 16 ? atoll(a.c_str() + 16) : 0;
        } else if (a == "--empty-trash")
            empty_trash = true;
        else if (a.compare(0, 17, "--revoke-pairing=") == 0) {
            revoke = true;
            revoke_id = a.substr(17);
        } else if (a == "--show-pairing-code")
            show_code = true;
        else if (a == "--new-pairing-code")
            new_code = true;
        else pos.push_back(a);
    }
    if (pos.empty()) {
        fprintf(
            stderr,
            "usage: %s <store-dir> [port] [bind-addr] [--faults=...] [--insecure-allow-network] [--allow-delete] [--advertise[=NAME]] "
            "[--lock-dir=DIR]\n"
            "       %s <store-dir> --show-pairing-code | --new-pairing-code | --add-pairing=LABEL [--pairing-allow-delete] | --list-pairings | "
            "--revoke-pairing=KEYID\n"
            "       %s <store-dir> --list-trash | --restore-trash[=SECONDS] | --empty-trash   (stop the device first); --trash-days=N when serving\n",
            argv[0], argv[0], argv[0]);
        return 2;
    }
    if (add_pairing || list_pairings || revoke) {  // pairing management for several Macs (ADR-0016): no server
        std::string perr;
        if (add_pairing) {
            if (add_label.empty()) {
                fprintf(stderr, "give the Mac a name: --add-pairing=\"Gideon's MacBook\"\n");
                return 2;
            }
            auto e = pairing::add(pos[0], add_label, pairing_delete, &perr);
            if (!e) {
                fprintf(stderr, "%s\n", perr.c_str());
                return 1;
            }
            print_pairing(*e);
            return 0;
        }
        if (revoke) {
            if (!pairing::revoke(pos[0], revoke_id, &perr)) {
                fprintf(stderr, "%s\n", perr.c_str());
                return 1;
            }
            printf("revoked %s: that Mac can no longer connect (an open connection ends at its next request)\n", revoke_id.c_str());
            return 0;
        }
        std::vector<std::string> problems;
        auto all = pairing::list(pos[0], &problems);
        for (auto& e : all)
            printf("%s  %-40s  %s%s\n", e.key_id.c_str(), e.label.c_str(), e.allow_delete ? "may delete" : "may not delete",
                   e.primary ? "  (the original pairing.key)" : "");
        if (all.empty()) printf("no pairings: this device is open (loopback only)\n");
        for (auto& pr : problems) printf("PROBLEM: %s\n", pr.c_str());
        return problems.empty() ? 0 : 1;
    }
    if (list_trash || restore_trash || empty_trash) {  // the trash (ADR-0017): needs the device stopped (the store is locked while it runs)
        std::string terr;
        auto st = DeviceStore::open(pos[0], &terr, lock_dir);
        if (!st) {
            fprintf(stderr, "cannot open store: %s\n", terr.c_str());
            return 1;
        }
        if (empty_trash) {
            uint64_t n = st->trash_purge(0, true);
            printf("emptied the trash: %llu file(s) removed for good\n", (unsigned long long)n);
            return 0;
        }
        if (restore_trash) {
            TrashRestoreOut r = st->trash_restore(restore_window);
            printf("restored %llu chunk(s) and %llu manifest(s); %llu skipped\n", (unsigned long long)r.chunks, (unsigned long long)r.manifests,
                   (unsigned long long)r.skipped);
            for (auto& n : r.notes) printf("  %s\n", n.c_str());
            return r.skipped && r.chunks + r.manifests == 0 ? 1 : 0;
        }
        TrashStats ts = st->trash_stats();
        printf("trash: %llu chunk(s) (%llu bytes), %llu manifest(s) (%llu bytes); kept %lld day(s) after deletion\n", (unsigned long long)ts.chunks,
               (unsigned long long)ts.chunk_bytes, (unsigned long long)ts.manifests, (unsigned long long)ts.manifest_bytes,
               (long long)(st->trash_retention() / 86400));
        if (ts.oldest) printf("oldest put there at unix time %lld, newest at %lld\n", (long long)ts.oldest, (long long)ts.newest);
        return 0;
    }
    if (show_code || new_code) {  // the original single pairing (pairing.key): shown, created if missing, or replaced
        std::string perr;
        std::vector<std::string> problems;
        std::optional<pairing::Entry> existing;
        for (auto& e : pairing::list(pos[0], &problems))
            if (e.primary) existing = e;
        if (!problems.empty()) {
            for (auto& pr : problems) fprintf(stderr, "%s\n", pr.c_str());
            return 1;
        }
        if (new_code && existing) fprintf(stderr, "replacing the pairing secret: every Mac must pair again\n");
        if (new_code || !existing) {
            existing = pairing::set_primary(pos[0], new_code, &perr);
            if (!existing) {
                fprintf(stderr, "%s\n", perr.c_str());
                return 1;
            }
        }
        print_pairing(*existing);
        return 0;
    }
    // An unreadable or loose pairing file must never turn a paired device into an open one: refuse to start.
    g_store_dir = pos[0];
    std::vector<std::string> problems;
    auto entries = pairing::list(pos[0], &problems);
    if (!problems.empty()) {
        for (auto& pr : problems) fprintf(stderr, "%s\n", pr.c_str());
        return 1;
    }
    g_paired = !entries.empty();
    if (const char* e = getenv("TIERFS_DEVICE_HANDSHAKE_MS")) g_handshake_ms = std::max(50, atoi(e));
    int port = pos.size() > 1 ? atoi(pos[1].c_str()) : 9100;
    std::string bind_addr = pos.size() > 2 ? pos[2] : "127.0.0.1";
    if (!g_paired && !insecure && bind_addr != "127.0.0.1") {
        fprintf(stderr,
                "refusing to listen on %s: this device is not paired, so it has no authentication. "
                "Pair it (tierfs-device <store> --show-pairing-code), use 127.0.0.1, or pass --insecure-allow-network on a network you trust.\n",
                bind_addr.c_str());
        return 2;
    }
    if (advertise && !g_paired) {  // an unauthenticated device is never invited onto the network
        fprintf(stderr,
                "refusing to advertise: this device is not paired, so it has no authentication (tierfs-device <store> --show-pairing-code)\n");
        return 2;
    }
    if (advertise && adv_name.empty()) adv_name = discovery::default_instance_name();
    DeviceFaults faults;
    std::string ferr;
    if (!DeviceFaults::parse(faults_csv, &faults, &ferr)) { fprintf(stderr, "%s\n", ferr.c_str()); return 2; }

    std::string err;
    auto store = DeviceStore::open(pos[0], &err, lock_dir);
    if (!store) { fprintf(stderr, "cannot open store: %s\n", err.c_str()); return 1; }
    store->set_faults(faults);
    {  // how long deleted things are kept before they are really removed (ADR-0017): --trash-days, else TIERFS_DEVICE_TRASH_SECONDS (tests), else 7
       // days
        int64_t keep = DEFAULT_TRASH_RETENTION;
        if (const char* e = getenv("TIERFS_DEVICE_TRASH_SECONDS")) keep = atoll(e);
        if (trash_days >= 0) keep = std::min<int64_t>(trash_days, 3650) * 86400;
        store->set_trash_retention(keep);
        store->trash_purge();  // what has been there long enough goes now, and again every hour
    }
    // Deleting is allowed only for a Mac that proved it knows the pairing secret, or when the operator says so (loopback experiments, tests).
    store->set_deletions_allowed(g_paired || allow_delete);  // (which pairing may actually delete is decided per connection)
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
            g_paired ? ("PAIRED, authenticated channel required, " + std::to_string(entries.size()) + " PAIRING(S)").c_str()
                     : "NOT PAIRED: plaintext, loopback only",
            (g_paired || allow_delete) ? ", deletions accepted for pairings that may delete" : "",
            faults_csv.empty() ? "" : ", FAULTS: ", faults_csv.c_str());
    std::thread([] {
        for (;;) {
            sleep(3600);
            g_store->trash_purge();
        }
    }).detach();
    std::vector<std::unique_ptr<discovery::Advertiser>>
        announcers;   // live as long as the server: the device disappears from the network when it stops
    if (advertise) {  // one announcement per pairing, each with its own key id, so each Mac finds the device by the key id it holds
        bool first = true;
        for (auto& e : entries) {
            discovery::Advert ad;
            ad.paired = true;
            ad.key_id = e.key_id;
            std::string name = first ? adv_name : adv_name + " (" + e.label + ")", aerr;
            if (name.size() > 63) name.resize(63);
            auto a = discovery::Advertiser::start(name, static_cast<uint16_t>(port), ad, &aerr);
            if (!a) {
                fprintf(stderr, "cannot advertise on the network: %s\n", aerr.c_str());
                return 1;
            }
            fprintf(stderr, "advertising as \"%s\" (%s) with key id %s%s\n", a->name().c_str(), discovery::SERVICE_TYPE, ad.key_id.c_str(),
                    bind_addr == "127.0.0.1" ? "; NOTE: it listens on 127.0.0.1 only, so other machines cannot reach it" : "");
            announcers.push_back(std::move(a));
            first = false;
        }
    }
    for (;;) {
        int c = accept(ls, nullptr, nullptr);
        if (c < 0) continue;
        if (g_conns.load() >= MAX_CONNECTIONS) { close(c); continue; }   // shed load instead of exhausting threads
        g_conns++;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        std::thread(serve, c).detach();
    }
}
