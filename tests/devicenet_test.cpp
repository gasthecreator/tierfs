// End-to-end tests of the device protocol: a real tierfs-device process, the real client,
// real encryption. Also hostile clients, misbehaving devices, and operational failures.
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <thread>

#include "../core/crypto.hpp"
#include "../core/deviceclient.hpp"
#include "../core/net.hpp"
#include "../core/wire.hpp"

extern char** environ;
using namespace tierfs;
using crypto::Bytes;
namespace fs = std::filesystem;

static int failures = 0;
static bool failfast() {   // the mutation runner stops a test at its first failure
    static const bool f = getenv("TIERFS_TEST_FAILFAST") != nullptr;
    return f;
}
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            printf("FAIL  line %d: %s\n", __LINE__, #cond);                        \
            failures++;                                                            \
            if (failfast()) { fflush(stdout); _exit(1); }                          \
        } else printf("PASS  %s\n", #cond);                                        \
    } while (0)


// Safe element access for assertions: a failed earlier check must not become a crash that hides it.
template <class T> static const T& at(const std::vector<T>& v, size_t i) { static const T dummy{}; return i < v.size() ? v[i] : dummy; }
static bool atb(const std::vector<bool>& v, size_t i) { return i < v.size() && v[i]; }
static bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }
static std::string tmpdir() {
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-devnet-XXXXXX";
    std::vector<char> b(t.begin(), t.end());
    b.push_back(0);
    return mkdtemp(b.data());
}
static Bytes pattern(size_t n, uint8_t seed) {
    Bytes v(n);
    for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(seed + i * 41 + (i >> 8));
    return v;
}
static const uint16_t PORT = getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9301;   // (the other tests here use PORT + 1 .. + 3)
static const std::string VOL = "volume-net-test";
static const std::string FID = "0123456789abcdef0123456789abcdef";

static const crypto::Keys& keys() {
    static crypto::Keys k(crypto::SecretKey::random());
    return k;
}
struct Sealed { std::string id; Bytes blob; Bytes plain; };
static Sealed seal(const Bytes& plain) {
    Sealed s;
    s.plain = plain;
    s.id = crypto::chunk_id(keys(), plain.data(), plain.size());
    s.blob = crypto::seal_chunk(keys(), VOL, s.id, plain.data(), plain.size());
    return s;
}
static Sealed seal_conflicting(const Bytes& plain, int variant) {   // different bytes under the same chunk id
    Sealed s;
    s.plain = plain;
    s.id = crypto::chunk_id(keys(), plain.data(), plain.size());
    s.blob = crypto::seal_chunk(keys(), "conflict-" + std::to_string(variant), s.id, plain.data(), plain.size());
    return s;
}
static AuditItem chunk_audit(const std::string& id, uint32_t n) {
    AuditItem a;
    a.kind = 0; a.id = id; a.nonce = crypto::audit_nonce(keys(), id, n);
    return a;
}
static std::string expected(const std::string& id, uint32_t n, const Bytes& blob) {
    return crypto::audit_response_hex(crypto::audit_nonce(keys(), id, n), blob.data(), blob.size());
}

struct Server {
    pid_t pid = 0;
    std::string dir;
    uint16_t port = PORT;
    bool start(const std::string& store, std::vector<std::string> extra = {}, const char* bind_addr = "127.0.0.1", bool wait_ready = true,
               std::vector<std::string> env_extra = {}) {
        stop();
        dir = store;
        std::vector<std::string> a = {"tierfs-device", store, std::to_string(port), bind_addr};
        a.insert(a.end(), extra.begin(), extra.end());
        std::vector<char*> av;
        for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
        av.push_back(nullptr);
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
        // Server diagnostics normally vanish; TIERFS_SERVER_LOG keeps them (the TSan run reads them).
        if (const char* lg = getenv("TIERFS_SERVER_LOG")) posix_spawn_file_actions_addopen(&fa, 2, lg, O_WRONLY | O_CREAT | O_APPEND, 0644);
        else posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
        const char* path = getenv("TIERFS_DEVICE_SERVER") ? getenv("TIERFS_DEVICE_SERVER") : "./build/tierfs-device";
        std::vector<std::string> env;
        for (char** e = environ; *e; e++) env.push_back(*e);
        for (auto& e : env_extra) env.push_back(e);
        std::vector<char*> envp;
        for (auto& e : env) envp.push_back(const_cast<char*>(e.c_str()));
        envp.push_back(nullptr);
        int rc = posix_spawn(&pid, path, &fa, nullptr, av.data(), envp.data());
        posix_spawn_file_actions_destroy(&fa);
        if (rc != 0) return false;
        if (!wait_ready) return true;
        for (int i = 0; i < 100; i++) {
            DeviceClient c("127.0.0.1", port, 300);
            DevInfo info;
            if (c.info(info).ok()) return true;
            int st;
            if (waitpid(pid, &st, WNOHANG) == pid) { pid = 0; return false; }
            usleep(50000);
        }
        return false;
    }
    void stop() {
        if (!pid) return;
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        pid = 0;
    }
    ~Server() { stop(); }
};

// Raw access for hostile-client tests.
struct Raw {
    int fd;
    explicit Raw(uint16_t port) : fd(connect_with_deadline("127.0.0.1", std::to_string(port), 1000)) {}
    ~Raw() { if (fd >= 0) close(fd); }
    bool hello(uint16_t v = DEVICE_PROTO_VERSION) {
        Writer w;
        w.u16(v);
        Frame r;
        return send_frame(fd, MSG_HELLO, 1, w.b) && recv_frame(fd, r, now_ms() + 1000) == 1 && r.type == (MSG_HELLO | MSG_REPLY_FLAG);
    }
    // Sends a request and returns the error code of the reply (0 for a normal reply, -1 if the server hung up).
    int send_recv(uint8_t type, const Writer& w, int* reply_type = nullptr) {
        Frame r;
        if (!send_frame(fd, type, 2, w.b, now_ms() + 1000)) return -1;
        if (recv_frame(fd, r, now_ms() + 2000) != 1) return -1;
        if (reply_type) *reply_type = r.type;
        if (r.type == MSG_ERROR) { Reader rd(r.payload); return rd.i32(); }
        return 0;
    }
};

// A device that handshakes properly and then answers one byte at a time: every byte is "in time",
// the whole reply is not.
static void trickle_device(int lfd, std::atomic<bool>* stop) {
    while (!*stop) {
        pollfd p{lfd, POLLIN, 0};
        if (poll(&p, 1, 100) <= 0) continue;
        int fd = accept(lfd, nullptr, nullptr);
        if (fd < 0) continue;
        Frame f;
        if (recv_frame(fd, f) == 1) {
            Writer w;
            w.u16(DEVICE_PROTO_VERSION);
            w.str("trickle");
            send_frame(fd, f.type | MSG_REPLY_FLAG, f.id, w.b);
        }
        if (recv_frame(fd, f) == 1) {
            Writer body;
            body.str("deadbeefdeadbeefdeadbeefdeadbeef"); body.u64(1); body.u64(0); body.str(""); body.u64(1000);
            Writer fr;
            fr.u32(5 + static_cast<uint32_t>(body.b.size()));
            fr.u8(f.type | MSG_REPLY_FLAG);
            fr.u32(f.id);
            fr.bytes(body.b.data(), body.b.size());
            for (uint8_t b : fr.b) {
                if (write(fd, &b, 1) != 1) break;
                usleep(120000);
            }
        }
        close(fd);
    }
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    std::string root = tmpdir();
    Server srv;

    {
        printf("== the whole Mac-to-device exchange, with real encryption\n");
        std::string store = root + "/s1";
        CHECK(srv.start(store));
        DeviceClient c("127.0.0.1", PORT, 2000);
        DevInfo info;
        CHECK(c.info(info).ok() && info.device_id.size() == 32 && info.seq == 0 && info.volume_id.empty());
        CHECK(c.bind(VOL).ok() && c.bind(VOL).ok());
        DevRes other = c.bind("some-other-volume");
        CHECK(other.err == EPERM && has(other.msg, "different volume"));

        // a 3-chunk file: 2 full chunks and a tail
        std::vector<Sealed> chunks;
        for (int i = 0; i < 3; i++) chunks.push_back(seal(pattern(i < 2 ? (1u << 20) : 123456, static_cast<uint8_t>(10 + i))));
        std::vector<std::string> ids;
        for (auto& s : chunks) ids.push_back(s.id);
        std::vector<bool> have;
        CHECK(c.has_chunks(ids, have).ok() && have == std::vector<bool>({false, false, false}));
        for (auto& s : chunks) {
            PutChunkReply pr;
            CHECK(c.put_chunk(s.id, s.blob, pr).ok() && !pr.existed && pr.sha256_hex == crypto::sha256_hex(s.blob.data(), s.blob.size()));
        }
        CHECK(c.has_chunks(ids, have).ok() && have == std::vector<bool>({true, true, true}));

        crypto::Manifest m;
        m.file_id = FID; m.version = 1; m.path = "/Users/me/Documents/report.pdf"; m.mode = 0100644; m.mtime = 1700000000;
        m.size = (2u << 20) + 123456; m.file_hmac = std::string(64, 'c');
        for (auto& s : chunks) m.chunks.push_back({s.id, static_cast<uint32_t>(s.plain.size())});
        Bytes mblob = crypto::seal_manifest(keys(), VOL, m);
        PutManifestReply mr;
        CHECK(c.put_manifest(FID, 1, mblob, ids, mr).ok() && !mr.existed && mr.seq == 1);

        ListReply lr;
        CHECK(c.list_manifests(0, 100, lr).ok() && lr.entries.size() == 1 && lr.seq == 1 && lr.epoch == info.epoch);
        CHECK(at(lr.entries, 0).file_id == FID && at(lr.entries, 0).sha256_hex == crypto::sha256_hex(mblob.data(), mblob.size()));

        // the Mac reads everything back and decrypts it: this is what a recall will do
        Bytes got;
        crypto::Manifest back;
        CHECK(c.get_manifest(FID, 1, got).ok() && crypto::open_manifest(keys(), VOL, FID, 1, got.data(), got.size(), back) == crypto::OpenError::Ok && back == m);
        int good = 0;
        for (auto& s : chunks) {
            Bytes blob, plain;
            if (c.get_chunk(s.id, blob).ok() && crypto::open_chunk(keys(), VOL, s.id, blob.data(), blob.size(), plain) == crypto::OpenError::Ok && plain == s.plain) good++;
        }
        CHECK(good == 3);

        // an audit: the device proves it holds the exact bytes by answering from its disk
        std::vector<AuditItem> items;
        for (auto& s : chunks) items.push_back(chunk_audit(s.id, 0));
        std::vector<AuditOut> outs;
        CHECK(c.audit(items, outs).ok() && outs.size() == 3);
        int proven = 0;
        for (size_t i = 0; i < 3; i++) proven += at(outs, i).status == 0 && at(outs, i).response_hex == expected(chunks[i].id, 0, chunks[i].blob);
        CHECK(proven == 3);

        // lost-ack retries are harmless: the original is kept and the Mac is told what the device holds
        Sealed resealed = seal_conflicting(chunks[0].plain, 1);
        PutChunkReply again;
        CHECK(resealed.blob != chunks[0].blob && c.put_chunk(resealed.id, resealed.blob, again).ok() && again.existed &&
              again.sha256_hex == crypto::sha256_hex(chunks[0].blob.data(), chunks[0].blob.size()));
        PutManifestReply mdup;
        CHECK(c.put_manifest(FID, 1, crypto::seal_manifest(keys(), VOL, m), ids, mdup).ok() && mdup.existed && mdup.seq == 1);

        // refusals travel as errno + reason
        PutManifestReply none;
        DevRes missing = c.put_manifest("ffffffffffffffffffffffffffffffff", 1, mblob, {std::string(64, 'a')}, none);
        CHECK(missing.err == ENOENT && has(missing.msg, "not present"));
        PutChunkReply pc;
        CHECK(c.put_chunk("../../etc/passwd", chunks[0].blob, pc).err == EINVAL);
        Bytes dummy;
        CHECK(c.get_chunk(std::string(64, 'a'), dummy).err == ENOENT);
        CHECK(c.get_manifest(FID, 7, dummy).err == ENOENT);

        // the client survives the server dropping an idle connection
        c.disconnect();
        CHECK(c.info(info).ok() && info.seq == 1);

        // data really is on the device's disk, encrypted: no plaintext, no path name
        std::string shard = store + "/chunks/" + chunks[0].id.substr(0, 2) + "/" + chunks[0].id + ".blob";
        CHECK(fs::exists(shard));
        std::string mf = store + "/manifests/" + FID + "/1.mf";
        Bytes disk;
        { FILE* f = fopen(mf.c_str(), "rb"); disk.resize(fs::file_size(mf)); fread(disk.data(), 1, disk.size(), f); fclose(f); }
        CHECK(std::search(disk.begin(), disk.end(), m.path.begin(), m.path.end()) == disk.end());
    }

    {
        printf("== an acknowledgement lost on the way back\n");
        std::string store = root + "/s2";
        CHECK(srv.start(store, {"--faults=drop_connection_after_put"}));
        Sealed s = seal(pattern(5000, 70));
        DeviceClient c("127.0.0.1", PORT, 1500);
        PutChunkReply pr;
        DevRes r = c.put_chunk(s.id, s.blob, pr);
        CHECK(!r.ok());                                              // the Mac never saw an ack...
        CHECK(srv.start(store));                                     // ...the device restarts healthy...
        DeviceClient c2("127.0.0.1", PORT, 1500);
        std::vector<bool> have;
        CHECK(c2.has_chunks({s.id}, have).ok() && atb(have, 0));          // ...and the chunk WAS stored
        Sealed again = seal(s.plain);
        CHECK(c2.put_chunk(again.id, again.blob, pr).ok() && pr.existed);   // so the retry is "existed" and the data is safe
        Bytes blob, plain;
        CHECK(c2.get_chunk(s.id, blob).ok() && crypto::open_chunk(keys(), VOL, s.id, blob.data(), blob.size(), plain) == crypto::OpenError::Ok);
    }

    {
        printf("== a lying, rotting or confused device cannot fool the Mac\n");
        for (const char* fault : {"lie_ack_chunk", "corrupt_on_store", "truncate_on_store", "swap_get"}) {
            std::string store = root + "/s3_" + fault;
            CHECK(srv.start(store, {std::string("--faults=") + fault}));
            DeviceClient c("127.0.0.1", PORT, 2000);
            Sealed a = seal(pattern(20000, 80)), b = seal(pattern(20000, 81));
            PutChunkReply pr;
            CHECK(c.put_chunk(a.id, a.blob, pr).ok() && c.put_chunk(b.id, b.blob, pr).ok());   // every one of these devices says "stored"
            std::vector<AuditOut> outs;
            CHECK(c.audit({chunk_audit(a.id, 0)}, outs).ok());
            std::string f = fault;
            if (f == "swap_get") {
                Bytes got, plain;
                CHECK(c.get_chunk(a.id, got).ok() && got != a.blob);
                CHECK(crypto::open_chunk(keys(), VOL, a.id, got.data(), got.size(), plain) == crypto::OpenError::AuthFailed);
                CHECK(at(outs, 0).response_hex == expected(a.id, 0, a.blob));   // (this fault only affects GET; the audit is honest)
            } else {
                CHECK(at(outs, 0).status == 1 || at(outs, 0).response_hex != expected(a.id, 0, a.blob));   // the audit exposes it
                Bytes got;
                DevRes g = c.get_chunk(a.id, got);
                CHECK(!g.ok());                                               // and a download is refused, never served wrong
            }
        }
        {   // slow device: the client's deadline turns it into an error instead of a hang
            std::string store = root + "/s3_slow";
            CHECK(srv.start(store, {"--faults=slow=900"}));
            DeviceClient fast("127.0.0.1", PORT, 400);
            Sealed s = seal(pattern(1000, 90));
            PutChunkReply pr;
            auto t0 = std::chrono::steady_clock::now();
            DevRes r = fast.put_chunk(s.id, s.blob, pr);
            double took = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            CHECK(r.err == ETIMEDOUT && took < 0.7);   // one attempt, not a pointless second one on a fresh connection
            DeviceClient patient("127.0.0.1", PORT, 3000);
            CHECK(patient.put_chunk(s.id, s.blob, pr).ok());                  // same request, enough patience
        }
        {   // full disk
            std::string store = root + "/s3_full";
            CHECK(srv.start(store, {"--faults=enospc"}));
            DeviceClient c("127.0.0.1", PORT, 2000);
            Sealed s = seal(pattern(1000, 91));
            PutChunkReply pr;
            CHECK(c.put_chunk(s.id, s.blob, pr).err == ENOSPC);
            std::vector<bool> have;
            CHECK(c.has_chunks({s.id}, have).ok() && !atb(have, 0));              // nothing half-recorded
        }
        {   // a rolled-back device is visible: same epoch, sequence goes down
            std::string store = root + "/s3_roll", snap = root + "/s3_roll_snap";
            CHECK(srv.start(store));
            Sealed s = seal(pattern(2000, 92));
            {
                DeviceClient c("127.0.0.1", PORT, 2000);
                PutChunkReply pr;
                PutManifestReply mr;
                c.put_chunk(s.id, s.blob, pr);
                c.put_manifest(FID, 1, pattern(100, 1), {s.id}, mr);
                c.put_manifest("11111111111111111111111111111111", 1, pattern(100, 2), {s.id}, mr);
            }
            srv.stop();
            fs::copy(store, snap, fs::copy_options::recursive);
            CHECK(srv.start(store));
            uint64_t epoch, seq_before;
            {
                DeviceClient c("127.0.0.1", PORT, 2000);
                PutManifestReply mr;
                c.put_manifest("22222222222222222222222222222222", 1, pattern(100, 3), {s.id}, mr);
                DevInfo i;
                c.info(i);
                epoch = i.epoch; seq_before = i.seq;
            }
            srv.stop();
            fs::remove_all(store);
            fs::copy(snap, store, fs::copy_options::recursive);
            CHECK(srv.start(store));
            DeviceClient c("127.0.0.1", PORT, 2000);
            DevInfo after;
            CHECK(c.info(after).ok() && after.epoch == epoch && after.seq < seq_before && seq_before == 3 && after.seq == 2);
        }
    }

    {
        printf("== hostile clients\n");
        CHECK(srv.start(root + "/s4"));
        {   Raw r(PORT);
            Writer w;
            int rc = r.send_recv(MSG_DEV_INFO, w);
            CHECK(rc == EPROTO);                                         // request before HELLO refused
        }
        {   Raw r(PORT);
            Writer w;
            w.u16(2);                                                   // a filesystem-protocol client
            Frame f;
            send_frame(r.fd, MSG_HELLO, 1, w.b);
            CHECK(recv_frame(r.fd, f, now_ms() + 1000) == 1 && f.type == MSG_ERROR);
        }
        {   Raw r(PORT);
            CHECK(r.hello());
            Writer w;
            CHECK(r.send_recv(0x55, w) == ENOSYS);                      // unknown request type
        }
        {   Raw r(PORT);
            CHECK(r.hello());
            Writer w;
            w.u32(0xFFFFFFFFu);                                          // HAS_CHUNKS claiming 4 billion ids
            CHECK(r.send_recv(MSG_DEV_HAS_CHUNKS, w) == EMSGSIZE);
        }
        {   Raw r(PORT);
            CHECK(r.hello());
            Writer w;
            w.str(std::string(64, 'a'));
            w.u8(1); w.u8(2);                                            // PUT_CHUNK cut short
            CHECK(r.send_recv(MSG_DEV_PUT_CHUNK, w) == EPROTO);
        }
        {   Raw r(PORT);
            CHECK(r.hello());
            Writer w;
            w.str(std::string(64, 'a'));
            for (int i = 0; i < 32; i++) w.u8(0);
            w.u32(0x7FFFFFFFu);                                          // blob length far beyond the data and the limit
            CHECK(r.send_recv(MSG_DEV_PUT_CHUNK, w) == EPROTO);
        }
        {   Raw r(PORT);
            CHECK(r.hello());
            Writer w;
            w.str(FID); w.i64(1);
            for (int i = 0; i < 32; i++) w.u8(0);
            w.blob(reinterpret_cast<const uint8_t*>("x"), 1);
            w.u32(1000000);                                              // claims a million chunk ids, supplies none
            CHECK(r.send_recv(MSG_DEV_PUT_MANIFEST, w) == EPROTO);
        }
        {   Raw r(PORT);
            CHECK(r.hello());
            Writer w;
            w.str(FID); w.i64(1);
            for (int i = 0; i < 32; i++) w.u8(0);
            w.blob(reinterpret_cast<const uint8_t*>("x"), 1);
            w.u32(0xFFFFFFFFu);                                          // claims four billion chunk ids
            CHECK(r.send_recv(MSG_DEV_PUT_MANIFEST, w) == EMSGSIZE);
        }
        {   Raw r(PORT);
            CHECK(r.hello());
            Writer w;
            w.u32(65);                                                   // too many audit items
            CHECK(r.send_recv(MSG_DEV_AUDIT, w) == EMSGSIZE);
        }
        {   Raw r(PORT);
            CHECK(r.hello());
            Writer w;
            w.u32(1); w.u8(9); w.str("x"); w.i64(0);
            for (int i = 0; i < 32; i++) w.u8(0);
            CHECK(r.send_recv(MSG_DEV_AUDIT, w) == EINVAL);              // audit kind that does not exist
        }
        {   Raw r(PORT);                                                 // an absurd frame length: connection dropped, nothing allocated
            uint8_t huge[4] = {0xFF, 0xFF, 0xFF, 0xF0};
            write(r.fd, huge, 4);
            Frame f;
            CHECK(recv_frame(r.fd, f, now_ms() + 1000) != 1);
        }
        {   // path-like names never reach the filesystem
            DeviceClient c("127.0.0.1", PORT, 1000);
            Bytes out;
            for (const char* id : {"../../../../etc/passwd", "..", "a/b", "%2e%2e"}) CHECK(c.get_chunk(id, out).err == EINVAL);
            CHECK(c.get_manifest("../..", 1, out).err == EINVAL);
        }
        {   // idle connections cannot exhaust the server
            std::vector<std::unique_ptr<Raw>> idle;
            for (int i = 0; i < 80; i++) idle.push_back(std::make_unique<Raw>(PORT));
            usleep(300000);
            int closed = 0;
            for (auto& r : idle) {
                uint8_t b;
                pollfd p{r->fd, POLLIN, 0};
                if (poll(&p, 1, 0) == 1 && recv(r->fd, &b, 1, MSG_PEEK) == 0) closed++;
            }
            CHECK(closed >= 10);                                         // the cap (64) sheds the surplus immediately
            idle.clear();
            usleep(200000);
        }
        DeviceClient c("127.0.0.1", PORT, 2000);
        DevInfo info;
        CHECK(c.info(info).ok());                                        // and it is still serving after all of that
    }

    {
        printf("== the server refuses to listen where it has no authentication\n");
        Server s;
        s.port = PORT + 1;   // its own port: the probe must not be answered by some other server
        CHECK(!s.start(root + "/s5", {}, "0.0.0.0", true));              // exits with an error instead of listening
        CHECK(s.start(root + "/s5", {"--insecure-allow-network"}, "0.0.0.0", false));
        usleep(500000);
        int st;
        CHECK(waitpid(s.pid, &st, WNOHANG) == 0);                        // still running: the explicit flag was honoured
        s.stop();
        CHECK(!s.start(root + "/s5", {"--faults=nonsense"}));            // bad fault names are an error, not silently ignored
    }

    {
        printf("== concurrent clients\n");
        CHECK(srv.start(root + "/s6"));
        std::atomic<int> okc{0};
        Sealed shared = seal(pattern(3000, 100));
        std::atomic<int> stored{0}, existed{0};
        std::vector<std::thread> th;
        for (int t = 0; t < 6; t++)
            th.emplace_back([&, t] {
                DeviceClient c("127.0.0.1", PORT, 3000);
                for (int i = 0; i < 5; i++) {
                    Sealed s = seal(pattern(4000, static_cast<uint8_t>(110 + t * 7 + i)));
                    PutChunkReply pr;
                    okc += c.put_chunk(s.id, s.blob, pr).ok();
                    Sealed again = seal_conflicting(shared.plain, t * 10 + i);   // everyone uploads the same chunk, differently sealed
                    PutChunkReply sr;
                    if (c.put_chunk(again.id, again.blob, sr).ok()) (sr.existed ? existed : stored)++;
                }
            });
        for (auto& x : th) x.join();
        CHECK(okc == 30 && stored == 1 && existed == 29);                // one winner among 30 racing uploads of one chunk
    }

    {
        printf("== garbage collection over the wire: refused unless the device accepts deletions, then exact\n");
        std::string store = root + "/gc1";
        Sealed a = seal(pattern(4000, 81)), b = seal(pattern(4100, 82)), c3 = seal(pattern(4200, 83));
        Bytes mb1 = pattern(300, 84), mb2 = pattern(310, 85);
        const std::string F2 = "fedcba9876543210fedcba9876543210";
        {
            CHECK(srv.start(store));   // an open device with no --allow-delete
            DeviceClient c("127.0.0.1", PORT, 2000);
            PutChunkReply pr;
            CHECK(c.put_chunk(a.id, a.blob, pr).ok() && c.put_chunk(b.id, b.blob, pr).ok() && c.put_chunk(c3.id, c3.blob, pr).ok());
            PutManifestReply mr;
            CHECK(c.put_manifest(FID, 1, mb1, {a.id, b.id}, mr).ok() && c.put_manifest(F2, 1, mb2, {b.id}, mr).ok());
            GcStatus g;
            CHECK(c.gc_status(g).ok() && !g.deletions_allowed && g.manifests == 2 && g.chunks == 3 && g.unreferenced_chunks == 1 && g.manifests_without_refs == 0 &&
                  g.chunk_bytes == a.blob.size() + b.blob.size() + c3.blob.size() && g.unreferenced_bytes == c3.blob.size() && g.manifests_deleted == 0 && g.chunks_deleted == 0);
            std::vector<uint8_t> del;
            DevRes r = c.delete_manifests({{FID, 1}}, del);
            CHECK(r.err == EPERM && has(r.msg, "does not accept deletions") && del.empty());
            SweepOut so;
            r = c.sweep(0, 100, false, so);
            CHECK(r.err == EPERM && has(r.msg, "does not accept deletions"));
            Bytes out;
            CHECK(c.get_manifest(FID, 1, out).ok() && c.get_chunk(c3.id, out).ok());   // nothing happened
        }
        {
            CHECK(srv.start(store, {"--allow-delete"}, "127.0.0.1", true, {"TIERFS_DEVICE_MIN_SWEEP_AGE=0"}));
            DeviceClient c("127.0.0.1", PORT, 2000);
            GcStatus g;
            CHECK(c.gc_status(g).ok() && g.deletions_allowed);
            DevInfo before;
            CHECK(c.info(before).ok());
            SweepOut dry;
            CHECK(c.sweep(0, 100, true, dry).ok() && dry.chunks_deleted == 1 && dry.bytes_deleted == c3.blob.size() && dry.chunks_left == 0);
            Bytes out;
            CHECK(c.get_chunk(c3.id, out).ok());                                       // a dry run deletes nothing
            std::vector<uint8_t> del;
            uint64_t seq = 0;
            CHECK(c.delete_manifests({{FID, 1}, {FID, 9}}, del, &seq).ok() && del == std::vector<uint8_t>({1, 0}) && seq == before.seq + 1);
            DevInfo after;
            CHECK(c.info(after).ok() && after.seq == before.seq + 1);
            CHECK(c.get_manifest(FID, 1, out).err == ENOENT && c.get_manifest(F2, 1, out).ok());
            SweepOut so;
            CHECK(c.sweep(0, 100, false, so).ok() && so.chunks_deleted == 2 && so.bytes_deleted == a.blob.size() + c3.blob.size() && so.chunks_left == 0);
            CHECK(c.get_chunk(a.id, out).err == ENOENT && c.get_chunk(c3.id, out).err == ENOENT && c.get_chunk(b.id, out).ok());   // b is still listed by F2 v1
            CHECK(c.gc_status(g).ok() && g.manifests == 1 && g.chunks == 1 && g.manifests_deleted == 1 && g.chunks_deleted == 2 && g.chunk_bytes == b.blob.size() && g.unreferenced_bytes == 0 &&
                  g.unreferenced_chunks == 0);
            // limits
            CHECK(c.delete_manifests({}, del).err == EMSGSIZE);
            CHECK(c.delete_manifests(std::vector<std::pair<std::string, int64_t>>(65, {FID, 1}), del).err == EMSGSIZE);
            CHECK(c.delete_manifests(std::vector<std::pair<std::string, int64_t>>(64, {FID, 7}), del).ok() && del.size() == 64);   // exactly the limit is fine
            CHECK(c.delete_manifests({{"short", 1}}, del).err == EINVAL && c.delete_manifests({{FID, 0}}, del).err == EINVAL);
            CHECK(c.sweep(0, 0, false, so).err == EINVAL);
            // hostile frames
            {   Raw r(PORT);
                CHECK(r.hello());
                Writer w;
                w.u32(0);
                CHECK(r.send_recv(MSG_DEV_DELETE_MANIFESTS, w) == EMSGSIZE);
            }
            {   Raw r(PORT);
                CHECK(r.hello());
                Writer w;
                w.u32(65);
                CHECK(r.send_recv(MSG_DEV_DELETE_MANIFESTS, w) == EMSGSIZE);
            }            {   // a leftover file no row describes is removed by a sweep and counted in the answer
                std::string stray_dir = store + "/chunks/ab";
                fs::create_directories(stray_dir);
                { std::ofstream f(stray_dir + "/" + std::string(64, 'c') + ".blob"); f << "x"; }
                SweepOut st;
                CHECK(c.sweep(0, 10, false, st).ok() && st.strays_removed == 1 && st.chunks_deleted == 0 && !fs::exists(stray_dir + "/" + std::string(64, 'c') + ".blob"));
            }
            {   Raw r(PORT);
                CHECK(r.hello());
                Writer w;
                w.u32(3);                                                // claims three items, supplies none
                CHECK(r.send_recv(MSG_DEV_DELETE_MANIFESTS, w) == EPROTO);
            }
            {   Raw r(PORT);
                CHECK(r.hello());
                Writer w;
                w.u64(0); w.u32(10); w.u8(2);                            // a "dry run" flag that is neither 0 nor 1
                CHECK(r.send_recv(MSG_DEV_SWEEP, w) == EINVAL);
            }
            {   Raw r(PORT);
                CHECK(r.hello());
                Writer w;
                w.u64(0);                                                // a sweep request cut short
                CHECK(r.send_recv(MSG_DEV_SWEEP, w) == EPROTO);
            }
            CHECK(c.info(after).ok());                                   // still serving
        }
        {   // the age floor is the operator's: a request for less is raised to it
            CHECK(srv.start(store, {"--allow-delete"}, "127.0.0.1", true, {"TIERFS_DEVICE_MIN_SWEEP_AGE=3600"}));
            DeviceClient c("127.0.0.1", PORT, 2000);
            Sealed young = seal(pattern(4300, 86));
            PutChunkReply pr;
            CHECK(c.put_chunk(young.id, young.blob, pr).ok());
            SweepOut so;
            CHECK(c.sweep(0, 100, false, so).ok() && so.chunks_deleted == 0 && so.chunks_left == 1);
            Bytes out;
            CHECK(c.get_chunk(young.id, out).ok());
        }
        srv.stop();
    }

    {
        printf("== limits\n");
        CHECK(srv.start(root + "/s7"));
        DeviceClient c("127.0.0.1", PORT, 3000);
        Sealed s = seal(pattern(2000, 120));
        PutChunkReply pr;
        c.put_chunk(s.id, s.blob, pr);
        std::vector<std::string> many(300000, s.id);                     // a manifest listing more chunks than one frame can carry
        PutManifestReply mr;
        CHECK(c.put_manifest(FID, 1, pattern(100, 1), many, mr).err == EMSGSIZE);
        std::vector<std::string> ids(5000, s.id);                        // 5000 entries is fine
        CHECK(c.put_manifest(FID, 1, pattern(100, 1), ids, mr).ok());
        std::vector<bool> have;
        std::vector<std::string> lots(3000, s.id);                       // has_chunks pages itself past the 1024-per-request cap
        CHECK(c.has_chunks(lots, have).ok() && have.size() == 3000 && atb(have, 2999));
        CHECK(c.has_chunks({}, have).ok() && have.empty());
        std::vector<AuditOut> ao;
        AuditItem bad_nonce = chunk_audit(s.id, 0);
        bad_nonce.nonce.resize(31);
        CHECK(c.audit({bad_nonce}, ao).err == EINVAL);                   // refused before anything is sent
        CHECK(c.audit(std::vector<AuditItem>(65, chunk_audit(s.id, 0)), ao).err == EMSGSIZE);
    }

    {
        printf("== idle connections are dropped after the idle timeout\n");
        Server s2;
        s2.port = PORT + 2;
        CHECK(s2.start(root + "/s8", {}, "127.0.0.1", true, {"TIERFS_DEVICE_IDLE_S=1"}));
        Raw r(PORT + 2);
        CHECK(r.hello());
        usleep(1800000);   // say nothing for longer than the 1 s timeout
        Writer w;
        CHECK(r.send_recv(MSG_DEV_INFO, w) == -1);    // the server has hung up on us
        DeviceClient c("127.0.0.1", PORT + 2, 2000);
        DevInfo i;
        CHECK(c.info(i).ok());                         // and still serves everyone else
    }

    {
        printf("== a device that trickles its reply cannot hold a request open\n");
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT + 3);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        bind(lfd, (sockaddr*)&addr, sizeof addr);
        listen(lfd, 4);
        std::atomic<bool> stop{false};
        std::thread t(trickle_device, lfd, &stop);
        DeviceClient c("127.0.0.1", PORT + 3, 500);
        DevInfo i;
        auto t0 = std::chrono::steady_clock::now();
        DevRes r = c.info(i);
        double took = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        printf("      err=%d after %.2fs (the reply needed ~5 s)\n", r.err, took);
        CHECK(r.err == ETIMEDOUT && took < 1.5);
        stop = true;
        t.join();
        close(lfd);
    }

    srv.stop();
    fs::remove_all(root);
    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
