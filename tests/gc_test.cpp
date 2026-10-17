// Tests of garbage collection (ADR-0010): real files, two real device processes, a real ledger, real encryption.
// What is checked throughout: versions the rules keep are always still readable and verified, bytes only the forgotten versions needed
// are gone from the devices, shared chunks survive, and nothing is deleted unless the ledger decided it first.
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <spawn.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <atomic>
#include <functional>
#include <mutex>
#include <thread>

#include "../core/gc.hpp"
#include "../core/net.hpp"

extern char** environ;
using namespace tierfs;
using crypto::Bytes;
namespace fs = std::filesystem;

static int failures = 0;
static bool failfast() {
    static const bool f = getenv("TIERFS_TEST_FAILFAST") != nullptr;
    return f;
}
#define CHECK(cond)                                         \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("FAIL  line %d: %s\n", __LINE__, #cond); \
            failures++;                                     \
            if (failfast()) {                               \
                fflush(stdout);                             \
                _exit(1);                                   \
            }                                               \
        } else                                              \
            printf("PASS  %s\n", #cond);                    \
    } while (0)

static bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }
static std::string tmpdir() {
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-gctest-XXXXXX";
    std::vector<char> b(t.begin(), t.end());
    b.push_back(0);
    return mkdtemp(b.data());
}
static Bytes pattern(size_t n, uint8_t seed) {
    Bytes v(n);
    for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(seed + i * 43 + (i >> 8) + (i >> 20) * 11);
    return v;
}
static void spit(const std::string& p, const Bytes& b) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}
static size_t count_files(const std::string& dir) {
    size_t n = 0;
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(dir, ec)) n += e.is_regular_file();
    return n;
}

static const uint16_t PORT = getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9511;
static const uint16_t PA = PORT, PB = PORT + 1;
static const size_t MiB = 1u << 20;

struct Server {
    pid_t pid = 0;
    uint16_t port;
    explicit Server(uint16_t p) : port(p) {}
    bool start(const std::string& store, std::vector<std::string> extra = {"--allow-delete"}) {
        stop();
        std::vector<std::string> a = {"tierfs-device", store, std::to_string(port), "127.0.0.1"};
        a.insert(a.end(), extra.begin(), extra.end());
        std::vector<char*> av;
        for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
        av.push_back(nullptr);
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
        posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
        const char* path = getenv("TIERFS_DEVICE_SERVER") ? getenv("TIERFS_DEVICE_SERVER") : "./build/tierfs-device";
        int rc = posix_spawn(&pid, path, &fa, nullptr, av.data(), environ);
        posix_spawn_file_actions_destroy(&fa);
        if (rc != 0) return false;
        for (int i = 0; i < 100; i++) {
            DeviceClient c("127.0.0.1", port, 300);
            DevInfo info;
            if (c.info(info).ok()) return true;
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

// A scripted device: it answers HELLO, INFO and BIND like any other, records every other request, and answers those through `custom` (or
// with the error `gc_errno`: ENOSYS is what an older device looks like, EIO a broken one).
struct FakeDevice {
    using Handler = std::function<bool(const Frame&, Writer&, uint8_t& reply_type)>;  // true: handled
    int lfd = -1;
    uint16_t port = 0;
    int gc_errno;
    std::string device_id, volume_id;
    Handler custom;
    std::atomic<bool> stop{false};
    std::thread th;
    std::mutex mu;
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> seen;  // (type, payload) of every request after BIND
    FakeDevice(uint16_t p, int err, std::string id, std::string vol, Handler h = nullptr)
        : port(p), gc_errno(err), device_id(std::move(id)), volume_id(std::move(vol)), custom(std::move(h)) {
        lfd = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        bind(lfd, reinterpret_cast<sockaddr*>(&sa), sizeof sa);
        listen(lfd, 8);
        th = std::thread([this] {
            while (!stop) {
                pollfd pf{lfd, POLLIN, 0};
                if (poll(&pf, 1, 100) != 1) continue;
                int c = accept(lfd, nullptr, nullptr);
                if (c < 0) continue;
                serve(c);
                close(c);
            }
        });
    }
    ~FakeDevice() {
        stop = true;
        if (th.joinable()) th.join();
        close(lfd);
    }
    int count(uint8_t type) {
        std::lock_guard<std::mutex> g(mu);
        int n = 0;
        for (auto& x : seen) n += x.first == type;
        return n;
    }
    std::vector<std::vector<uint8_t>> payloads(uint8_t type) {
        std::lock_guard<std::mutex> g(mu);
        std::vector<std::vector<uint8_t>> out;
        for (auto& x : seen)
            if (x.first == type) out.push_back(x.second);
        return out;
    }
    void serve(int c) {
        for (;;) {
            Frame f;
            if (recv_frame(c, f, now_ms() + 2000) != 1) return;
            Writer w;
            uint8_t type = f.type | MSG_REPLY_FLAG;
            if (f.type == MSG_HELLO) {
                w.u16(DEVICE_PROTO_VERSION);
                w.str("fake");
            } else if (f.type == MSG_DEV_INFO) {
                w.str(device_id);
                w.u64(7);
                w.u64(0);
                w.str(volume_id);
                w.u64(1ull << 30);
            } else if (f.type == MSG_DEV_BIND) {
            } else {
                {
                    std::lock_guard<std::mutex> g(mu);
                    seen.emplace_back(f.type, f.payload);
                }
                if (!(custom && custom(f, w, type))) {
                    w = Writer();
                    type = MSG_ERROR;
                    w.i32(gc_errno);
                    w.str(gc_errno == ENOSYS ? "unknown message type" : "disk on fire");
                }
            }
            if (!send_frame(c, type, f.id, w.b, now_ms() + 2000)) return;
        }
    }
};

struct World {
    std::string root = tmpdir();
    crypto::SecretKey master = crypto::SecretKey::random();
    std::unique_ptr<crypto::Keys> keys = std::make_unique<crypto::Keys>(master);
    std::unique_ptr<Ledger> L;
    std::unique_ptr<Replicator> R;
    std::unique_ptr<GarbageCollector> G;
    Server sa{PA}, sb{PB};
    std::unique_ptr<DeviceClient> da, db;
    std::string ida, idb, dir_a, dir_b;
    int64_t now_ = static_cast<int64_t>(time(nullptr));
    DeviceMap devs;
    std::map<std::string, std::vector<Bytes>> versions;  // file_id -> the bytes of each version, index = version - 1
    GcConfig cfg;

    explicit World(bool allow_delete_b = true) {
        fs::create_directories(root + "/files");
        dir_a = root + "/devA";
        dir_b = root + "/devB";
        sa.start(dir_a);
        sb.start(dir_b, allow_delete_b ? std::vector<std::string>{"--allow-delete"} : std::vector<std::string>{});
        da = std::make_unique<DeviceClient>("127.0.0.1", PA, 3000);
        db = std::make_unique<DeviceClient>("127.0.0.1", PB, 3000);
        std::string err;
        L = Ledger::open(root + "/ledger", &err);
        L->set_clock([this] { return now_; });
        L->set_meta("recovery_acked", "1");
        L->set_meta("test_prefix", "/testdata/");
        L->ensure_reserve(1 << 20);
        R = std::make_unique<Replicator>(*L, *keys, L->volume_id());
        R->attach(*da, "device-a", "B", &ida);
        R->attach(*db, "device-b", "B", &idb);
        devs = {{ida, da.get()}, {idb, db.get()}};
        cfg.keep_versions = 2;
        cfg.rules.min_weight = 2.0;
        cfg.rules.max_audit_age = 600;
        cfg.rules.grace_seconds = 3600;
        cfg.rules.deleted_retention_seconds = 30 * 86400;
        cfg.sweep_min_age = 0;
        make_gc();
    }
    ~World() {
        G.reset();
        R.reset();
        L.reset();
        da.reset();
        db.reset();
        dc.reset();
        sa.stop();
        sb.stop();
        sc.stop();
        fs::remove_all(root);
    }
    // A third real device (class B), for tests where the copies of different versions sit on different devices.
    Server sc{static_cast<uint16_t>(PORT + 4)};
    std::unique_ptr<DeviceClient> dc;
    std::string idc, dir_c;
    void add_device_c() {
        dir_c = root + "/devC";
        sc.start(dir_c);
        dc = std::make_unique<DeviceClient>("127.0.0.1", PORT + 4, 3000);
        R->attach(*dc, "device-c", "B", &idc);
        devs[idc] = dc.get();
    }
    void close_ledger() {
        G.reset();
        R.reset();
        L.reset();
    }
    void open_ledger() {
        std::string err;
        L = Ledger::open(root + "/ledger", &err);
        L->set_clock([this] { return now_; });
        R = std::make_unique<Replicator>(*L, *keys, L->volume_id());
        make_gc();
    }
    void make_gc() { G = std::make_unique<GarbageCollector>(*L, *R, *keys, cfg); }

    // 2.5 MiB: the first chunk is the same in every version of every file (so it is shared), the others depend on the seed.
    static Bytes content(uint8_t seed, uint8_t shared = 1) {
        Bytes b = pattern(MiB, shared), x = pattern(MiB, seed), y = pattern(MiB / 2, static_cast<uint8_t>(seed + 100));
        b.insert(b.end(), x.begin(), x.end());
        b.insert(b.end(), y.begin(), y.end());
        return b;
    }
    std::string path(const std::string& name) const { return root + "/files/" + name; }
    // A new file at version 1, replicated to both devices.
    std::string add(const std::string& name, uint8_t seed, uint8_t shared = 1) {
        Bytes data = content(seed, shared);
        spit(path(name), data);
        struct stat st;
        stat(path(name).c_str(), &st);
        std::string fid = L->track_file("/testdata/" + name, data.size(), st.st_mtimespec.tv_sec, 0644);
        versions[fid] = {data};
        replicate_all(fid, name);
        return fid;
    }
    // The next version of the file, replicated to the devices named (default both).
    void edit(const std::string& fid, const std::string& name, uint8_t seed, bool a = true, bool b = true) {
        Bytes data = content(seed);
        spit(path(name), data);
        struct stat st;
        stat(path(name).c_str(), &st);
        auto f = L->get_file(fid);
        L->note_local_modified(fid, data.size(), st.st_mtimespec.tv_sec);
        versions[fid].push_back(data);
        if (a) R->replicate(*da, ida, fid, path(name));
        if (b) R->replicate(*db, idb, fid, path(name));
    }
    // Tiny files (one chunk), for tests that need many versions cheaply.
    std::string add_small(const std::string& name, uint8_t seed) {
        Bytes data = pattern(100, seed);
        spit(path(name), data);
        struct stat st;
        stat(path(name).c_str(), &st);
        std::string fid = L->track_file("/testdata/" + name, data.size(), st.st_mtimespec.tv_sec, 0644);
        versions[fid] = {data};
        replicate_all(fid, name);
        return fid;
    }
    void edit_small(const std::string& fid, const std::string& name, uint8_t seed, bool a = true, bool b = true) {
        Bytes data = pattern(100, seed);
        spit(path(name), data);
        struct stat st;
        stat(path(name).c_str(), &st);
        L->note_local_modified(fid, data.size(), st.st_mtimespec.tv_sec);
        versions[fid].push_back(data);
        if (a) R->replicate(*da, ida, fid, path(name));
        if (b) R->replicate(*db, idb, fid, path(name));
    }
    // The detail text of the newest event of a kind, read through a second connection.
    std::string event_detail(const std::string& kind) {
        sqlite3* db = nullptr;
        sqlite3_open((root + "/ledger/ledger.db").c_str(), &db);
        sqlite3_stmt* st = nullptr;
        std::string out;
        sqlite3_prepare_v2(db, ("SELECT detail FROM events WHERE kind='" + kind + "' ORDER BY seq DESC LIMIT 1").c_str(), -1, &st, nullptr);
        if (sqlite3_step(st) == SQLITE_ROW) out = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
        sqlite3_close(db);
        return out;
    }
    void replicate_all(const std::string& fid, const std::string& name) {
        bool x = R->replicate(*da, ida, fid, path(name)).ok, y = R->replicate(*db, idb, fid, path(name)).ok;
        if (!x || !y) printf("      (setup: replication failed)\n");
    }
    // The version, fetched from the device and verified end to end.
    bool intact(const std::string& fid, int64_t version, DeviceClient& dev) {
        Bytes got;
        Res r = R->fetch_version(dev, fid, version, [&](const uint8_t* p, size_t n) {
            got.insert(got.end(), p, p + n);
            return true;
        });
        return r.ok && got == versions[fid][static_cast<size_t>(version - 1)];
    }
    bool listed(DeviceClient& dev, const std::string& fid, int64_t version) {
        Bytes out;
        return dev.get_manifest(fid, version, out).ok();
    }
    size_t chunks_on(const std::string& dir) { return count_files(dir + "/chunks"); }
    size_t manifests_on(const std::string& dir) { return count_files(dir + "/manifests"); }
    // Two hours later: the audits are stale and the grace period for old versions is over.
    void later(int64_t seconds = 7200) { now_ += seconds; }
};

// The child of a crash test: opens the ledger the parent left behind and runs one pass, dying where TIERFS_CRASH_AT says.
//   gc_test --child <master hex> <ledger dir> <port a> <id a> <port b> <id b> <now>
static int child_main(char** argv) {
    crypto::Bytes m = *crypto::from_hex(argv[2]);
    crypto::Keys keys{crypto::SecretKey(m.data())};
    std::string err;
    auto L = Ledger::open(argv[3], &err);
    if (!L) return 3;
    int64_t now_ = atoll(argv[8]);
    L->set_clock([&] { return now_; });
    Replicator R(*L, keys, L->volume_id());
    DeviceClient da("127.0.0.1", static_cast<uint16_t>(atoi(argv[4])), 3000), db("127.0.0.1", static_cast<uint16_t>(atoi(argv[6])), 3000);
    DeviceMap devs = {{argv[5], &da}, {argv[7], &db}};
    GcConfig cfg;
    cfg.keep_versions = 2;
    cfg.rules.grace_seconds = 3600;
    cfg.sweep_min_age = 0;
    GarbageCollector G(*L, R, keys, cfg);
    G.run(devs);
    return 0;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc >= 9 && std::string(argv[1]) == "--child") return child_main(argv);
    setenv("TIERFS_DEVICE_MIN_SWEEP_AGE", "0", 1);  // the devices here have no age floor: the tests control age through the request

    {
        printf("== a file edited five times keeps its newest two versions, and the devices give the rest back\n");
        World w;
        std::string fid = w.add("big.bin", 10);
        for (uint8_t s = 20; s < 24; s++) w.edit(fid, "big.bin", s);
        CHECK(w.L->get_file(fid)->current_version == 5);
        CHECK(w.manifests_on(w.dir_a) == 5 && w.manifests_on(w.dir_b) == 5 && w.chunks_on(w.dir_a) == 1 + 2 * 5 && w.chunks_on(w.dir_b) == 1 + 2 * 5);
        // too soon: the grace period protects every old version, so there is nothing to decide
        GcReport soon = w.G->run(w.devs);
        CHECK(soon.candidates == 0 && soon.decided == 0 && soon.manifests_deleted() == 0 && soon.chunks_swept() == 0);
        w.later();
        uint64_t events = w.L->event_count();
        GcReport plan = w.G->plan(w.devs);  // read-only
        CHECK(plan.dry_run && plan.candidates == 3 && plan.owed_total == 0 && w.L->event_count() == events && w.L->pruned_count() == 0);
        CHECK(w.manifests_on(w.dir_a) == 5 && w.chunks_on(w.dir_b) == 11);
        CHECK(has(format_gc_report(plan).c_str(), "plan only") && has(format_gc_report(plan).c_str(), "versions the rules would let go of: 3"));
        GcReport r = w.G->run(w.devs);
        CHECK(r.candidates == 3 && r.decided == 3 && r.audited >= 1 && r.refused.empty() && r.manifests_deleted() == 6 && r.owed_total == 0);
        CHECK(r.chunks_swept() == 12 && r.bytes_swept() > 0);  // two private chunks per forgotten version, on each device
        CHECK(w.manifests_on(w.dir_a) == 2 && w.manifests_on(w.dir_b) == 2 && w.chunks_on(w.dir_a) == 5 &&
              w.chunks_on(w.dir_b) == 5);  // the shared chunk and v4, v5 stay
        for (int v = 1; v <= 3; v++) CHECK(!w.listed(*w.da, fid, v) && !w.listed(*w.db, fid, v));
        for (int v = 4; v <= 5; v++) CHECK(w.intact(fid, v, *w.da) && w.intact(fid, v, *w.db));  // what is kept still verifies, byte for byte
        CHECK(w.L->pruned_count() == 3 && w.L->pending_prunes(100).empty() && w.L->fsck().empty());
        CHECK(has(w.event_detail("version.pruned").c_str(), "older than the newest 2 committed versions"));
        for (const auto& p : {std::pair<DeviceClient*, std::string>{w.da.get(), w.ida},
                              {w.db.get(), w.idb}}) {  // the ledger's view of each device moved with its commit sequence
            DevInfo di;
            CHECK(p.first->info(di).ok() && w.L->get_device(p.second)->last_seq == static_cast<int64_t>(di.seq) && di.seq > 5);
        }
        for (const auto& p : {std::pair<DeviceClient*, std::string>{w.da.get(), w.ida}, {w.db.get(), w.idb}}) {
            ReconcileReport rc = w.R->reconcile(*p.first, p.second, false);
            CHECK(rc.ok && rc.adopted.empty() && rc.manifests_missing.empty() && rc.chunks_missing.empty() && rc.pruned_leftovers.empty() &&
                  rc.replicas_checked == 2);
        }
        CHECK(has(format_gc_report(r).c_str(), "decided now: 3") && has(format_gc_report(r).c_str(), "manifests deleted 3"));
        // nothing more to do, and doing it again changes nothing
        events = w.L->event_count();
        GcReport again = w.G->run(w.devs);
        CHECK(again.candidates == 0 && again.decided == 0 && again.manifests_deleted() == 0 && again.chunks_swept() == 0 &&
              w.L->event_count() == events);
        // the file keeps working: a new version is replicated and the old ones are forgotten in turn
        w.edit(fid, "big.bin", 40);
        w.later();
        GcReport next = w.G->run(w.devs);
        CHECK(next.decided == 1 && next.manifests_deleted() == 2 && w.manifests_on(w.dir_a) == 2 && w.intact(fid, 5, *w.da) &&
              w.intact(fid, 6, *w.db) && !w.listed(*w.da, fid, 4));
        CHECK(w.L->fsck().empty());
    }

    {
        printf("== a garbage collection can be undone from the device's trash (ADR-0017)\n");
        World w;
        std::string fid = w.add("big.bin", 10);
        for (uint8_t s = 20; s < 24; s++) w.edit(fid, "big.bin", s);
        w.later();
        GcReport r = w.G->run(w.devs);
        CHECK(r.decided == 3 && r.manifests_deleted() == 6 && r.chunks_swept() == 12);
        GcStatus gs;
        CHECK(w.da->gc_status(gs).ok() && gs.trash_retention_s == 7 * 86400 && gs.trash_files > 0 && gs.trash_bytes > 0);
        // the files are kept on the device, outside the live store
        CHECK(w.manifests_on(w.dir_a) == 2 && w.chunks_on(w.dir_a) == 5 && fs::exists(w.dir_a + "/trash/chunks") &&
              fs::exists(w.dir_a + "/trash/manifests"));
        // the operator stops the device, looks, restores, starts it again
        w.sa.stop();
        auto run = [&](const std::string& args) {
            std::string cmd = std::string(getenv("TIERFS_DEVICE_SERVER") ? getenv("TIERFS_DEVICE_SERVER") : "./build/tierfs-device") + " '" +
                              w.dir_a + "' " + args + " 2>&1";
            FILE* f = popen(cmd.c_str(), "r");
            std::string out;
            char buf[512];
            while (f && fgets(buf, sizeof buf, f)) out += buf;
            int st = f ? pclose(f) : -1;
            return std::make_pair(WIFEXITED(st) ? WEXITSTATUS(st) : -1, out);
        };
        auto listed = run("--list-trash");
        CHECK(listed.first == 0 && has(listed.second.c_str(), "trash: 6 chunk(s)") && has(listed.second.c_str(), "3 manifest(s)") &&
              has(listed.second.c_str(), "kept 7 day(s)"));
        auto restored = run("--restore-trash");
        CHECK(restored.first == 0 && has(restored.second.c_str(), "restored 6 chunk(s) and 3 manifest(s); 0 skipped"));
        CHECK(w.manifests_on(w.dir_a) == 5 && w.chunks_on(w.dir_a) == 11);  // exactly as before the collection
        CHECK(w.sa.start(w.dir_a));
        for (int v = 1; v <= 5; v++) CHECK(w.listed(*w.da, fid, v) && w.intact(fid, v, *w.da));
        CHECK(w.da->gc_status(gs).ok() && gs.trash_files == 0);
        // emptying the trash is for good
        CHECK(w.db->gc_status(gs).ok() && gs.trash_files > 0);
        w.sb.stop();
        auto emptied_b = std::make_pair(0, std::string());
        {
            std::string cmd = std::string(getenv("TIERFS_DEVICE_SERVER") ? getenv("TIERFS_DEVICE_SERVER") : "./build/tierfs-device") + " '" +
                              w.dir_b + "' --empty-trash 2>&1";
            FILE* f = popen(cmd.c_str(), "r");
            char buf[512];
            while (f && fgets(buf, sizeof buf, f)) emptied_b.second += buf;
            int st = f ? pclose(f) : -1;
            emptied_b.first = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        }
        CHECK(emptied_b.first == 0 && has(emptied_b.second.c_str(), "emptied the trash: 12 file(s) removed for good"));
        CHECK(!fs::exists(w.dir_b + "/trash/chunks") || fs::is_empty(w.dir_b + "/trash/chunks"));
        // a device with --trash-days=0 deletes for good at once
        CHECK(w.sb.start(w.dir_b, {"--allow-delete"}));
        w.sa.stop();
        CHECK(w.sa.start(w.dir_a, {"--trash-days=0"}));
        w.edit(fid, "big.bin", 50);
        w.later();
        GcReport r2 = w.G->run(w.devs);
        CHECK(r2.manifests_deleted() > 0 && w.da->gc_status(gs).ok() && gs.trash_retention_s == 0 && gs.trash_files == 0);
        CHECK(w.L->fsck().empty());
    }

    {
        printf("== a device that is away keeps owing its deletions; one that comes back with a forgotten manifest is not trusted with it\n");
        World w;
        std::string fid = w.add("away.bin", 10);
        for (uint8_t s = 20; s < 23; s++) w.edit(fid, "away.bin", s);  // v1..v4
        w.later();
        // device B is down when the Mac wants to prove the newer version is safe: nothing may be decided with only one device vouching
        w.sb.stop();
        GcReport blind = w.G->run(w.devs);
        CHECK(blind.candidates == 2 && blind.decided == 0 && blind.refused.size() == 2 && has(blind.refused[0].c_str(), "recent audit") &&
              w.L->pruned_count() == 0);
        CHECK(w.manifests_on(w.dir_a) == 4 && w.chunks_on(w.dir_a) == 1 + 2 * 4);
        w.sb.start(w.dir_b);
        // the Mac decides, then B goes away before it is asked to delete
        int stops = 0;
        w.G->on_step = [&](const char* step) {
            if (std::string(step) == "decided") {
                stops++;
                w.sb.stop();
            }
        };
        GcReport half = w.G->run(w.devs);
        w.G->on_step = nullptr;
        CHECK(stops == 1 && half.decided == 2 && half.manifests_deleted() == 2 && half.owed_total == 2);  // A's two; B still owes two
        CHECK(w.L->pending_prunes(100).size() == 2 && w.L->pending_prunes(100)[0].device_id == w.idb);
        CHECK(w.manifests_on(w.dir_a) == 2 && w.manifests_on(w.dir_b) == 4 && w.chunks_on(w.dir_a) == 5 && w.chunks_on(w.dir_b) == 9);
        GcReport mid = w.G->plan(w.devs);  // B is still away: the plan says who owes what
        bool plan_a = false, plan_b = false;
        for (auto& d : mid.devices) {
            if (d.device_id == w.ida) plan_a = d.reachable && d.owed == 0;
            if (d.device_id == w.idb) plan_b = !d.reachable && d.owed == 2 && has(d.note.c_str(), "cannot reach it");
        }
        CHECK(mid.owed_total == 2 && plan_a && plan_b && has(format_gc_report(mid).c_str(), "not reachable") &&
              has(format_gc_report(half).c_str(), "deletions still owed by devices: 2"));
        bool b_unreachable = false;
        for (auto& d : half.devices)
            if (d.device_id == w.idb) b_unreachable = !d.reachable && d.owed == 2 && has(d.note.c_str(), "cannot reach it") && d.chunks_swept == 0;
        CHECK(b_unreachable);
        // B is back, with the manifests it should have lost: reconcile does not adopt them; the next run finishes the job
        w.sb.start(w.dir_b);
        ReconcileReport rc = w.R->reconcile(*w.db, w.idb, false);
        CHECK(rc.ok && rc.pruned_leftovers.size() == 2 && rc.adopted.empty() && rc.manifests_missing.empty() && w.L->pending_prunes(100).size() == 2);
        GcReport fin = w.G->run(w.devs);
        CHECK(fin.decided == 0 && fin.manifests_deleted() == 2 && fin.owed_total == 0 && w.manifests_on(w.dir_b) == 2 && w.chunks_on(w.dir_b) == 5);
        CHECK(w.intact(fid, 3, *w.db) && w.intact(fid, 4, *w.db) && w.L->fsck().empty());
    }

    {
        printf("== a run that stops half way is simply continued: decisions first, then deletions, one device at a time\n");
        World w;
        std::string fid = w.add("crashy.bin", 10);
        for (uint8_t s = 20; s < 23; s++) w.edit(fid, "crashy.bin", s);
        w.later();
        struct Stop {};
        w.G->on_step = [](const char* step) {
            if (std::string(step) == "decided") throw Stop();
        };
        bool stopped = false;
        try {
            w.G->run(w.devs);
        } catch (const Stop&) {
            stopped = true;
        }
        CHECK(stopped && w.L->pruned_count() == 2 && w.L->pending_prunes(100).size() == 4 && w.manifests_on(w.dir_a) == 4 &&
              w.manifests_on(w.dir_b) == 4);  // decided, nothing deleted yet
        int done = 0;
        w.G->on_step = [&](const char* step) {
            if (std::string(step) == "device_done" && ++done == 1) throw Stop();
        };
        stopped = false;
        try {
            w.G->run(w.devs);
        } catch (const Stop&) {
            stopped = true;
        }
        CHECK(stopped && w.L->pending_prunes(100).size() == 2);  // the first device was fully served, the second not at all
        size_t served = (w.manifests_on(w.dir_a) == 2) + (w.manifests_on(w.dir_b) == 2);
        CHECK(served == 1);
        w.G->on_step = nullptr;
        GcReport fin = w.G->run(w.devs);
        CHECK(fin.decided == 0 && fin.manifests_deleted() == 2 && fin.owed_total == 0 && w.manifests_on(w.dir_a) == 2 &&
              w.manifests_on(w.dir_b) == 2);
        CHECK(w.chunks_on(w.dir_a) == 5 && w.chunks_on(w.dir_b) == 5 && w.intact(fid, 3, *w.da) && w.intact(fid, 4, *w.db) && w.L->fsck().empty());
    }

    {
        printf("== a deleted file goes after its retention period; chunks other files share stay\n");
        World w;
        std::string gone = w.add("gone.bin", 10), keep = w.add("keep.bin", 30);  // the first chunk is shared by both
        w.edit(gone, "gone.bin", 11);
        CHECK(w.chunks_on(w.dir_a) == 1 + 2 * 3);  // shared + gone v1 + gone v2 + keep v1
        CHECK(w.L->retire_file(gone, "the user deleted it").ok);
        w.later(10 * 86400);
        GcReport early = w.G->run(w.devs);
        CHECK(early.candidates == 0 && early.decided == 0 && w.manifests_on(w.dir_a) == 3);  // still inside the undelete window
        w.later(25 * 86400);
        GcReport r = w.G->run(w.devs);
        CHECK(r.candidates == 2 && r.decided == 2 && r.manifests_deleted() == 4 && r.chunks_swept() == 8);
        CHECK(has(w.event_detail("version.pruned").c_str(), "the file was deleted and its retention period is over") &&
              has(w.event_detail("version.pruned").c_str(), "(file deleted: /testdata/gone.bin)"));
        CHECK(w.manifests_on(w.dir_a) == 1 && w.manifests_on(w.dir_b) == 1 && w.chunks_on(w.dir_a) == 3 &&
              w.chunks_on(w.dir_b) == 3);  // shared chunk + keep's two
        CHECK(w.intact(keep, 1, *w.da) && w.intact(keep, 1, *w.db));
        Res un = w.L->undelete_file(gone);
        CHECK(!un.ok &&
              w.L->fsck().empty());  // (it still has its local bytes, so undelete refuses for that reason; the pruned case is in ledger_test)
        GcReport again = w.G->run(w.devs);
        CHECK(again.candidates == 0 && again.manifests_deleted() == 0);
    }

    {
        printf("== nothing is forgotten unless a newer version is safely held\n");
        World w;
        w.cfg.keep_versions = 1;
        w.make_gc();
        std::string fid = w.add("thin.bin", 10);
        w.edit(fid, "thin.bin", 20, /*a=*/true, /*b=*/false);  // v2 reaches only device A
        w.later();
        GcReport r = w.G->run(w.devs);
        CHECK(r.candidates == 0 && r.decided == 0 && r.manifests_deleted() == 0 && w.L->pruned_count() == 0 && w.manifests_on(w.dir_a) == 2 &&
              w.manifests_on(w.dir_b) == 1);
        CHECK(w.intact(fid, 1, *w.db) && w.intact(fid, 1, *w.da));
        w.R->replicate(*w.db, w.idb, fid, w.path("thin.bin"));  // now both have v2
        w.later();
        GcReport ok = w.G->run(w.devs);
        CHECK(ok.candidates == 1 && ok.decided == 1 && ok.manifests_deleted() == 2 && w.manifests_on(w.dir_a) == 1 && w.manifests_on(w.dir_b) == 1);
        CHECK(w.intact(fid, 2, *w.da) && w.intact(fid, 2, *w.db));
        // the newer version is on both devices, but one of them no longer has it: the audit finds out and nothing is decided
        std::string fid2 = w.add("rot.bin", 50);
        w.edit(fid2, "rot.bin", 60);
        w.later();
        std::string cid = w.L->get_chunks(fid2, 2)[1].chunk_id;
        std::string blob = w.dir_b + "/chunks/" + cid.substr(0, 2) + "/" + cid + ".blob";
        int fd = ::open(blob.c_str(), O_RDWR);
        uint8_t byte = 0;
        if (fd >= 0) {
            pread(fd, &byte, 1, 100);
            byte ^= 0x40;
            pwrite(fd, &byte, 1, 100);
            close(fd);
        }
        GcReport rot = w.G->run(w.devs);
        bool refused_rot = false;
        for (auto& x : rot.refused)
            if (has(x.c_str(), fid2.substr(0, 8).c_str())) refused_rot = true;
        CHECK(rot.decided == 0 && refused_rot && !w.L->is_version_pruned(fid2, 1) && w.listed(*w.da, fid2, 1) && w.listed(*w.db, fid2, 1));
    }

    {
        printf("== a device that does not accept deletions is left alone, and the debt stays\n");
        World w(/*allow_delete_b=*/false);
        std::string fid = w.add("refuse.bin", 10);
        for (uint8_t s = 20; s < 23; s++) w.edit(fid, "refuse.bin", s);
        w.later();
        GcReport r = w.G->run(w.devs);
        CHECK(r.decided == 2 && r.manifests_deleted() == 2 && r.owed_total == 2 && w.manifests_on(w.dir_a) == 2 && w.manifests_on(w.dir_b) == 4 &&
              w.chunks_on(w.dir_b) == 9);
        bool noted = false;
        for (auto& d : r.devices)
            if (d.device_id == w.idb)
                noted = d.note.compare(0, 27, "it does not accept deletion") == 0 && d.manifests_deleted == 0 && d.chunks_swept == 0;
        CHECK(noted && has(format_gc_report(r).c_str(), "does not accept deletions"));
        w.sb.start(w.dir_b);  // restarted with --allow-delete
        GcReport fin = w.G->run(w.devs);
        CHECK(fin.decided == 0 && fin.manifests_deleted() == 2 && fin.owed_total == 0 && w.manifests_on(w.dir_b) == 2 && w.chunks_on(w.dir_b) == 5);
    }

    {
        printf("== a device that is not the one the ledger knows is never asked to delete\n");
        World w;
        std::string fid = w.add("swap.bin", 10);
        for (uint8_t s = 20; s < 23; s++) w.edit(fid, "swap.bin", s);
        w.later();
        int swapped = 0;
        w.G->on_step = [&](const char* step) {
            if (std::string(step) == "decided" && !swapped++) {  // after the decision, device B is replaced by a different (empty) one
                w.sb.stop();
                w.sb.start(w.root + "/other-device");
            }
        };
        GcReport r = w.G->run(w.devs);
        w.G->on_step = nullptr;
        bool refused = false;
        for (auto& d : r.devices)
            if (d.device_id == w.idb) refused = !d.reachable && has(d.note.c_str(), "not the device the ledger expects") && d.manifests_deleted == 0;
        CHECK(swapped == 1 && refused && r.owed_total == 2 && w.manifests_on(w.dir_a) == 2 && w.manifests_on(w.dir_b) == 4);
        GcReport plan = w.G->plan(w.devs);
        bool plan_refused = false;
        for (auto& d : plan.devices)
            if (d.device_id == w.idb) plan_refused = !d.reachable && has(d.note.c_str(), "not the device the ledger expects");
        CHECK(plan_refused);
    }

    {
        printf("== a device that stored manifests before chunk lists existed is brought up to date before it is swept\n");
        World w;
        std::string fid = w.add("old.bin", 10);
        for (uint8_t s = 20; s < 23; s++) w.edit(fid, "old.bin", s);
        w.later();
        w.sa.stop();
        {  // make device A look like a version 1 store: manifests without their lists
            sqlite3* db = nullptr;
            sqlite3_open((w.dir_a + "/device.db").c_str(), &db);
            CHECK(sqlite3_exec(db, "DELETE FROM manifest_refs; DELETE FROM refs_done;", nullptr, nullptr, nullptr) == SQLITE_OK);
            sqlite3_close(db);
        }
        w.sa.start(w.dir_a);
        GcStatus st;
        CHECK(w.da->gc_status(st).ok() && st.manifests == 4 && st.manifests_without_refs == 4);
        GcReport plan = w.G->plan(w.devs);
        bool planned = false;
        for (auto& d : plan.devices)
            if (d.device_id == w.ida) planned = has(d.note.c_str(), "need their chunk lists re-sent") && d.chunks_swept == 0;
        CHECK(planned && w.manifests_on(w.dir_a) == 4);  // a plan changes nothing, even there
        GcReport r = w.G->run(w.devs);
        uint32_t sent = 0;
        for (auto& d : r.devices)
            if (d.device_id == w.ida) sent = d.chunk_lists_sent;
        CHECK(sent == 2 && r.decided == 2 && r.manifests_deleted() == 4 &&
              r.chunks_swept() ==
                  8);  // the two manifests that remain get their lists (the deleted ones need none); 2 versions x 2 private chunks x 2 devices
        CHECK(w.manifests_on(w.dir_a) == 2 && w.chunks_on(w.dir_a) == 5 && w.intact(fid, 3, *w.da) && w.intact(fid, 4, *w.da) && w.L->fsck().empty());
        GcStatus st2;
        CHECK(w.da->gc_status(st2).ok() && st2.manifests_without_refs == 0);
    }

    {
        printf("== with chunk lists switched off an old store is reported, not swept\n");
        World w;
        w.cfg.prepare = false;
        w.make_gc();
        std::string fid = w.add("noprep.bin", 10);
        for (uint8_t s = 20; s < 23; s++) w.edit(fid, "noprep.bin", s);
        w.later();
        w.sa.stop();
        {
            sqlite3* db = nullptr;
            sqlite3_open((w.dir_a + "/device.db").c_str(), &db);
            sqlite3_exec(db, "DELETE FROM manifest_refs; DELETE FROM refs_done;", nullptr, nullptr, nullptr);
            sqlite3_close(db);
        }
        w.sa.start(w.dir_a);
        GcReport r = w.G->run(w.devs);
        bool noted = false;
        for (auto& d : r.devices)
            if (d.device_id == w.ida) noted = has(d.note.c_str(), "need their chunk lists") && d.chunks_swept == 0 && d.chunk_lists_sent == 0;
        CHECK(noted && r.chunks_swept() == 4 && w.chunks_on(w.dir_a) == 9);  // only B was swept
    }

    {
        printf("== more deletions than one request carries are sent in batches\n");
        World w;
        std::string fid = w.add_small("many.bin", 1);
        for (int i = 2; i <= 70; i++) w.edit_small(fid, "many.bin", static_cast<uint8_t>(i));
        CHECK(w.L->get_file(fid)->current_version == 70 && w.manifests_on(w.dir_a) == 70);
        w.later();
        GcReport r = w.G->run(w.devs);
        CHECK(r.candidates == 68 && r.decided == 68 && r.manifests_deleted() == 136 && r.owed_total == 0);
        CHECK(w.manifests_on(w.dir_a) == 2 && w.manifests_on(w.dir_b) == 2 && w.chunks_on(w.dir_a) == 2 && w.chunks_on(w.dir_b) == 2);
        CHECK(w.intact(fid, 69, *w.da) && w.intact(fid, 70, *w.db) && w.L->fsck().empty());
    }

    {
        printf("== a long list of refusals is cut short in the report, not in the work\n");
        World w;
        w.cfg.keep_versions = 1;
        w.make_gc();
        for (int i = 0; i < 25; i++) {
            std::string name = "f" + std::to_string(i) + ".bin";
            std::string fid = w.add_small(name, static_cast<uint8_t>(i));
            w.edit_small(fid, name, static_cast<uint8_t>(100 + i));
        }
        w.later();
        w.sb.stop();  // only one device can vouch for anything: every decision is refused
        GcReport r = w.G->run(w.devs);
        CHECK(r.candidates == 25 && r.decided == 0 && r.refused.size() == 20 && w.L->pruned_count() == 0);
        CHECK(has(format_gc_report(r).c_str(), "refused: ") && has(r.refused[0].c_str(), "recent audit"));
    }

    {
        printf("== a manifest the Mac cannot read never gets a chunk list, so its chunks are never swept\n");
        World w;
        std::string fid = w.add("foreign.bin", 10);
        for (uint8_t s = 20; s < 23; s++) w.edit(fid, "foreign.bin", s);
        w.later();
        // a manifest from someone else's keys, listing a chunk this volume uses
        std::string shared_chunk = w.L->get_chunks(fid, 4)[0].chunk_id;
        const std::string alien = "abababababababababababababababab";
        Bytes junk = pattern(200, 77);
        PutManifestReply pr;
        CHECK(w.da->put_manifest(alien, 1, junk, {shared_chunk}, pr).ok());
        w.sa.stop();
        {  // and every manifest on A loses its list (an old store)
            sqlite3* db = nullptr;
            sqlite3_open((w.dir_a + "/device.db").c_str(), &db);
            CHECK(sqlite3_exec(db, "DELETE FROM manifest_refs; DELETE FROM refs_done;", nullptr, nullptr, nullptr) == SQLITE_OK);
            sqlite3_close(db);
        }
        w.sa.start(w.dir_a);
        size_t chunks_before = w.chunks_on(w.dir_a);
        GcReport r = w.G->run(w.devs);
        GcDeviceReport a;
        for (auto& d : r.devices)
            if (d.device_id == w.ida) a = d;
        CHECK(a.chunk_lists_sent == 2 && a.manifests_deleted == 2 && a.chunks_swept == 0 &&
              has(a.note.c_str(), "could not be given a chunk list"));  // v3, v4 re-listed; the alien one cannot be
        CHECK(w.chunks_on(w.dir_a) == chunks_before && w.listed(*w.da, alien, 1));
        GcStatus st;
        CHECK(w.da->gc_status(st).ok() && st.manifests_without_refs == 1);
        // B had no such problem and was swept
        CHECK(w.chunks_on(w.dir_b) == 5 && w.intact(fid, 4, *w.da) && w.intact(fid, 4, *w.db));
    }

    {
        printf("== a device that cannot or will not delete is reported, and the others carry on\n");
        World w;
        std::string fid = w.add_small("odd.bin", 1);
        for (int i = 2; i <= 4; i++) w.edit_small(fid, "odd.bin", static_cast<uint8_t>(i));  // v1..v4
        FakeDevice old_dev(PORT + 2, ENOSYS, "11111111111111111111111111111111", w.L->volume_id());
        FakeDevice sick_dev(PORT + 3, EIO, "22222222222222222222222222222222", w.L->volume_id());
        DeviceClient old_c("127.0.0.1", PORT + 2, 1500), sick_c("127.0.0.1", PORT + 3, 1500);
        w.L->register_device(old_dev.device_id, "old", "B");
        w.L->register_device(sick_dev.device_id, "sick", "B");
        for (auto* id : {&old_dev.device_id, &sick_dev.device_id})
            for (int64_t v = 1; v <= 4; v++) {
                w.L->set_replica(fid, v, *id, ReplicaState::PENDING);
                w.L->set_replica(fid, v, *id, ReplicaState::UPLOADED);
                w.L->set_replica(fid, v, *id, ReplicaState::COMMITTED, 100 + v);
            }
        DeviceMap devs = w.devs;
        devs[old_dev.device_id] = &old_c;
        devs[sick_dev.device_id] = &sick_c;
        w.later();
        GcReport plan = w.G->plan(devs);
        bool p_old = false, p_sick = false;
        for (auto& d : plan.devices) {
            if (d.device_id == old_dev.device_id) p_old = d.reachable && has(d.note.c_str(), "too old to collect garbage");
            if (d.device_id == sick_dev.device_id) p_sick = d.reachable && has(d.note.c_str(), "cannot ask its status: disk on fire");
        }
        CHECK(p_old && p_sick);
        GcReport r = w.G->run(devs);
        bool o = false, k = false;
        for (auto& d : r.devices) {
            if (d.device_id == old_dev.device_id)
                o = d.reachable && d.owed == 2 && d.manifests_deleted == 0 && d.chunks_swept == 0 && has(d.note.c_str(), "too old to delete");
            if (d.device_id == sick_dev.device_id)
                k = d.reachable && d.owed == 2 && d.manifests_deleted == 0 && d.chunks_swept == 0 &&
                    has(d.note.c_str(), "deleting failed: disk on fire");
        }
        CHECK(o && k && r.decided == 2 && r.owed_total == 4 && old_dev.count(MSG_DEV_DELETE_MANIFESTS) >= 1 &&
              sick_dev.count(MSG_DEV_DELETE_MANIFESTS) >= 1);
        CHECK(r.manifests_deleted() == 4 && w.manifests_on(w.dir_a) == 2 && w.manifests_on(w.dir_b) == 2 &&
              w.L->pending_prunes(100).size() == 4);  // A and B were served regardless
        // a device that is not connected at all is a note, not a crash
        DeviceMap with_null = devs;
        with_null[old_dev.device_id] = nullptr;
        GcReport nul = w.G->run(with_null);
        bool absent = false;
        for (auto& d : nul.devices)
            if (d.device_id == old_dev.device_id) absent = !d.reachable && d.note == "not connected";
        CHECK(absent);
        GcReport nulplan = w.G->plan(with_null);
        absent = false;
        for (auto& d : nulplan.devices)
            if (d.device_id == old_dev.device_id) absent = !d.reachable && d.note == "not connected";
        CHECK(absent);
    }

    {
        printf("== every answer a device can give to the sweep, and what each does to the report\n");
        World w;
        const std::string FAKE_ID = "33333333333333333333333333333333";
        w.L->register_device(FAKE_ID, "fake", "B");
        auto status = [](Writer& wr, bool allowed, uint32_t refless, uint64_t unref) {
            wr.u8(allowed ? 1 : 0);
            wr.u32(5);
            wr.u32(refless);
            wr.u64(20);
            wr.u64(2000);
            wr.u64(unref);
            wr.u64(unref * 100);
            wr.u64(0);
            wr.u64(0);
        };
        auto sweep_ok = [](Writer& wr) {
            wr.u64(1);
            wr.u64(10);
            wr.u64(5);
            wr.u64(2);
        };  // one chunk, 10 bytes, 5 left, 2 strays: every round
        auto run_against = [&](FakeDevice& fk, bool plan, GcDeviceReport* out) {
            DeviceClient c("127.0.0.1", fk.port, 1500);
            DeviceMap m = {{FAKE_ID, &c}};
            GcReport r = plan ? w.G->plan(m) : w.G->run(m);
            for (auto& d : r.devices)
                if (d.device_id == FAKE_ID) *out = d;
            return r;
        };
        auto be_gc = [&](GcConfig c) {
            w.cfg = c;
            w.make_gc();
        };
        GcConfig base = w.cfg;
        base.sweep_min_age = 777;
        base.sweep_chunks = 555;
        base.sweep_rounds = 3;
        be_gc(base);
        const uint16_t FP = PORT + 2;

        {  // a device that does not allow deletions is not swept, and says so
            FakeDevice fk(FP, EIO, FAKE_ID, w.L->volume_id(), [&](const Frame& f, Writer& wr, uint8_t& type) {
                if (f.type == MSG_DEV_GC_STATUS) {
                    status(wr, false, 0, 9);
                    return true;
                }
                return false;
            });
            GcDeviceReport d;
            run_against(fk, false, &d);
            CHECK(d.reachable && !d.deletions_allowed && d.note.compare(0, 27, "it does not accept deletion") == 0 && fk.count(MSG_DEV_SWEEP) == 0 &&
                  d.status.unreferenced_chunks == 9);
            CHECK(!d.status.deletions_allowed && d.chunks_swept == 0);
        }
        {  // a device that needs its chunk lists but cannot list its manifests
            FakeDevice fk(FP, EIO, FAKE_ID, w.L->volume_id(), [&](const Frame& f, Writer& wr, uint8_t& type) {
                if (f.type == MSG_DEV_GC_STATUS) {
                    status(wr, true, 3, 9);
                    return true;
                }
                return false;  // LIST_MANIFESTS fails
            });
            GcDeviceReport d;
            run_against(fk, false, &d);
            CHECK(d.note == "cannot list its manifests: disk on fire" && d.chunk_lists_sent == 0 && fk.count(MSG_DEV_SWEEP) == 0);
            GcDeviceReport dp;
            run_against(fk, true, &dp);  // a plan does not try
            CHECK(has(dp.note.c_str(), "need their chunk lists re-sent") && has(dp.note.c_str(), "a real run does that") &&
                  fk.count(MSG_DEV_LIST_MANIFESTS) == 1 && fk.count(MSG_DEV_SWEEP) == 0);
        }
        {  // chunk lists switched off
            GcConfig c = base;
            c.prepare = false;
            be_gc(c);
            FakeDevice fk(FP, EIO, FAKE_ID, w.L->volume_id(), [&](const Frame& f, Writer& wr, uint8_t& type) {
                if (f.type == MSG_DEV_GC_STATUS) {
                    status(wr, true, 3, 9);
                    return true;
                }
                return false;
            });
            GcDeviceReport d;
            run_against(fk, false, &d);
            CHECK(d.note == "3 manifest(s) need their chunk lists re-sent before it can be swept" && fk.count(MSG_DEV_LIST_MANIFESTS) == 0 &&
                  fk.count(MSG_DEV_SWEEP) == 0);
            be_gc(base);
        }
        {  // the lists are sent (there is nothing to send), the device is happy at the second look, and the sweep runs for as many rounds as allowed
            std::atomic<int> statuses{0};
            FakeDevice fk(FP, EIO, FAKE_ID, w.L->volume_id(), [&](const Frame& f, Writer& wr, uint8_t& type) {
                if (f.type == MSG_DEV_GC_STATUS) {
                    status(wr, true, statuses++ == 0 ? 3 : 0, 9);
                    return true;
                }
                if (f.type == MSG_DEV_LIST_MANIFESTS) {
                    wr.u64(7);
                    wr.u64(0);
                    wr.u32(0);
                    return true;
                }
                if (f.type == MSG_DEV_SWEEP) {
                    sweep_ok(wr);
                    return true;
                }
                return false;
            });
            GcDeviceReport d;
            run_against(fk, false, &d);
            auto reqs = fk.payloads(MSG_DEV_SWEEP);
            CHECK(d.note.empty() && d.deletions_allowed && d.status.manifests_without_refs == 0 && d.status.unreferenced_chunks == 9 &&
                  d.chunk_lists_sent == 0);                                                                  // the second look is the one kept
            CHECK(reqs.size() == 3 && d.chunks_swept == 3 && d.bytes_swept == 30 && d.strays_removed == 6);  // 3 rounds, summed
            std::vector<uint8_t> first_req = reqs.empty() ? std::vector<uint8_t>(13, 0) : reqs[0];
            Reader rd(first_req);
            uint64_t age = rd.u64();
            uint32_t maxc = rd.u32();
            uint8_t dry = rd.u8();
            CHECK(age == 777 && maxc == 555 && dry == 0);
            // a plan asks once, and asks for a dry run
            int before = fk.count(MSG_DEV_SWEEP);
            statuses = 1;
            GcDeviceReport dp;
            GcReport rp = run_against(fk, true, &dp);
            auto reqs2 = fk.payloads(MSG_DEV_SWEEP);
            Reader rd2(reqs2.back());
            rd2.u64();
            rd2.u32();
            CHECK(fk.count(MSG_DEV_SWEEP) == before + 1 && rd2.u8() == 1 && dp.chunks_swept == 1);
            CHECK(has(format_gc_report(rp).c_str(), "that a sweep would take 1") && !has(format_gc_report(rp).c_str(), "decided now"));
            // with no rounds allowed at all, one is still made
            GcConfig c = base;
            c.sweep_rounds = 0;
            be_gc(c);
            before = fk.count(MSG_DEV_SWEEP);
            GcDeviceReport d0;
            run_against(fk, false, &d0);
            CHECK(fk.count(MSG_DEV_SWEEP) == before + 1 && d0.chunks_swept == 1);
            be_gc(base);
        }
        {  // the second look fails
            std::atomic<int> statuses{0};
            FakeDevice fk(FP, EIO, FAKE_ID, w.L->volume_id(), [&](const Frame& f, Writer& wr, uint8_t& type) {
                if (f.type == MSG_DEV_GC_STATUS) {
                    if (statuses++ == 0) {
                        status(wr, true, 2, 9);
                        return true;
                    }
                    return false;
                }
                if (f.type == MSG_DEV_LIST_MANIFESTS) {
                    wr.u64(7);
                    wr.u64(0);
                    wr.u32(0);
                    return true;
                }
                return false;
            });
            GcDeviceReport d;
            run_against(fk, false, &d);
            CHECK(d.note == "cannot ask its status again" && fk.count(MSG_DEV_SWEEP) == 0);
        }
        {  // lists could not be given to every manifest
            FakeDevice fk(FP, EIO, FAKE_ID, w.L->volume_id(), [&](const Frame& f, Writer& wr, uint8_t& type) {
                if (f.type == MSG_DEV_GC_STATUS) {
                    status(wr, true, 1, 9);
                    return true;
                }
                if (f.type == MSG_DEV_LIST_MANIFESTS) {
                    wr.u64(7);
                    wr.u64(0);
                    wr.u32(0);
                    return true;
                }
                return false;
            });
            GcDeviceReport d;
            run_against(fk, false, &d);
            CHECK(has(d.note.c_str(), "1 manifest(s) could not be given a chunk list") && fk.count(MSG_DEV_SWEEP) == 0);
        }
        {  // a sweep that fails
            FakeDevice fk(FP, EIO, FAKE_ID, w.L->volume_id(), [&](const Frame& f, Writer& wr, uint8_t& type) {
                if (f.type == MSG_DEV_GC_STATUS) {
                    status(wr, true, 0, 9);
                    return true;
                }
                return false;
            });
            GcDeviceReport d;
            run_against(fk, false, &d);
            CHECK(d.note == "sweep failed: disk on fire" && d.chunks_swept == 0 && fk.count(MSG_DEV_SWEEP) == 1);
        }
        {  // chunk lists are counted only for manifests the device really already holds and accepted
            crypto::Manifest m;
            m.file_id = "44444444444444444444444444444444";
            m.version = 1;
            m.path = "/testdata/x";
            m.size = 0;
            Bytes blob = crypto::seal_manifest(*w.keys, w.L->volume_id(), m);
            std::string sha = crypto::sha256_hex(blob.data(), blob.size());
            for (int mode = 0; mode < 2; mode++) {  // 0: the device says "new" (not existed); 1: it refuses
                std::atomic<int> statuses{0};
                FakeDevice fk(FP, EIO, FAKE_ID, w.L->volume_id(), [&](const Frame& f, Writer& wr, uint8_t& type) {
                    if (f.type == MSG_DEV_GC_STATUS) {
                        status(wr, true, 1, 9);
                        return true;
                    }
                    if (f.type == MSG_DEV_LIST_MANIFESTS) {
                        wr.u64(7);
                        wr.u64(1);
                        wr.u32(1);
                        wr.u64(1);
                        wr.str(m.file_id);
                        wr.i64(1);
                        auto raw = *crypto::from_hex(sha);
                        wr.bytes(raw.data(), raw.size());
                        return true;
                    }
                    if (f.type == MSG_DEV_GET_MANIFEST) {
                        wr.blob(blob.data(), blob.size());
                        return true;
                    }
                    if (f.type == MSG_DEV_PUT_MANIFEST && mode == 0) {
                        wr.u8(0);
                        wr.u64(1);
                        auto raw = *crypto::from_hex(sha);
                        wr.bytes(raw.data(), raw.size());
                        return true;
                    }
                    return false;  // mode 1: an error
                });
                GcDeviceReport d;
                run_against(fk, false, &d);
                CHECK(fk.count(MSG_DEV_PUT_MANIFEST) == 1 && d.chunk_lists_sent == 0);
            }
        }
    }

    {
        printf("== the order of the work: decisions, then each device, then the sweep; and sweeping can be switched off\n");
        World w;
        std::string fid = w.add("order.bin", 10);
        for (uint8_t s = 20; s < 23; s++) w.edit(fid, "order.bin", s);
        w.later();
        std::vector<std::string> steps;
        w.G->on_step = [&](const char* step) { steps.push_back(step); };
        w.cfg.sweep = false;
        w.make_gc();
        w.G->on_step = [&](const char* step) { steps.push_back(step); };
        GcReport r = w.G->run(w.devs);
        CHECK(steps == std::vector<std::string>({"decided", "device_done", "device_done", "deleted"}));
        CHECK(r.decided == 2 && r.manifests_deleted() == 4 && r.chunks_swept() == 0 && w.manifests_on(w.dir_a) == 2 && w.chunks_on(w.dir_a) == 9 &&
              w.chunks_on(w.dir_b) == 9);   // nothing swept
        GcReport plan = w.G->plan(w.devs);  // the plan sees what a sweep would take
        CHECK(plan.chunks_swept() == 8 && plan.bytes_swept() > 0 && has(format_gc_report(plan).c_str(), "that a sweep would take 4") &&
              !has(format_gc_report(plan).c_str(), "decided now"));
        CHECK(w.chunks_on(w.dir_a) == 9);
        w.cfg.sweep = true;
        w.make_gc();
        GcReport again = w.G->run(w.devs);
        CHECK(again.decided == 0 && again.chunks_swept() == 8 && w.chunks_on(w.dir_a) == 5 && w.chunks_on(w.dir_b) == 5);
        CHECK(has(format_gc_report(again).c_str(), "swept 4") && has(format_gc_report(again).c_str(), "decided now: 0"));
    }

    {
        printf("== the audit that makes a decision possible goes to the devices that hold the NEWER version, and only those\n");
        World w;
        w.cfg.keep_versions = 1;
        w.make_gc();
        w.add_device_c();
        std::string fid = w.add_small("sel.bin", 1);               // v1 on A and B
        w.edit_small(fid, "sel.bin", 2, /*a=*/false, /*b=*/true);  // v2 on B ...
        w.R->replicate(*w.dc, w.idc, fid, w.path("sel.bin"));      // ... and C
        // two more records of v2: a device the Mac is not connected to, and one whose copy is gone
        w.L->register_device("ghost1", "ghost1", "B");
        w.L->register_device("ghost2", "ghost2", "B");
        w.L->set_replica(fid, 2, "ghost1", ReplicaState::PENDING);
        w.L->set_replica(fid, 2, "ghost1", ReplicaState::UPLOADED);
        w.L->set_replica(fid, 2, "ghost1", ReplicaState::COMMITTED, 50);
        w.L->set_replica(fid, 2, "ghost2", ReplicaState::PENDING);
        w.L->set_replica(fid, 2, "ghost2", ReplicaState::MISSING);
        DeviceMap devs = w.devs;
        devs["ghost2"] = w.da.get();  // connected (to something), but its replica is not COMMITTED
        w.later();
        GcReport r = w.G->run(devs);
        CHECK(r.candidates == 1 && r.decided == 1 && r.audited == 2 && r.refused.empty());  // B and C, nothing else
        CHECK(w.L->is_version_pruned(fid, 1));
        // a deleted file never needs an audit: when it is refused (here: not deleted long enough) nothing is audited
        std::string gone = w.add_small("gone2.bin", 9);
        w.edit_small(gone, "gone2.bin", 10);
        CHECK(w.L->retire_file(gone, "test").ok);
        w.later(86400);
        GcReport g = w.G->run(devs);
        CHECK(g.audited == 0 && g.decided == 0 && g.candidates == 0);
    }

    {
        printf("== deletions go out in batches of at most 64, each batch recorded as it is confirmed\n");
        World w;
        std::string fid = w.add_small("batchy.bin", 1);
        for (int i = 2; i <= 70; i++) w.edit_small(fid, "batchy.bin", static_cast<uint8_t>(i));
        const std::string FAKE_ID = "66666666666666666666666666666666";
        w.L->register_device(FAKE_ID, "fake", "B");
        for (int64_t v = 1; v <= 70; v++) {  // the scripted device holds a copy of every version (as far as the ledger knows)
            w.L->set_replica(fid, v, FAKE_ID, ReplicaState::PENDING);
            w.L->set_replica(fid, v, FAKE_ID, ReplicaState::UPLOADED);
            w.L->set_replica(fid, v, FAKE_ID, ReplicaState::COMMITTED, 1000 + v);
        }
        FakeDevice fk(PORT + 2, EIO, FAKE_ID, w.L->volume_id(), [&](const Frame& f, Writer& wr, uint8_t& type) {
            if (f.type == MSG_DEV_DELETE_MANIFESTS) {
                Reader rd(f.payload);
                uint32_t n = rd.u32();
                wr.u64(99);
                wr.u32(n);
                for (uint32_t i = 0; i < n; i++) wr.u8(1);
                return true;
            }
            if (f.type == MSG_DEV_GC_STATUS) {
                wr.u8(1);
                wr.u32(2);
                wr.u32(0);
                wr.u64(2);
                wr.u64(200);
                wr.u64(0);
                wr.u64(0);
                wr.u64(0);
                wr.u64(0);
                return true;
            }
            return false;
        });
        DeviceClient fc("127.0.0.1", PORT + 2, 1500);
        DeviceMap devs = w.devs;
        devs[FAKE_ID] = &fc;
        w.later();
        GcReport r = w.G->run(devs);
        auto reqs = fk.payloads(MSG_DEV_DELETE_MANIFESTS);
        std::vector<uint32_t> sizes;
        std::vector<int64_t> versions;
        for (auto& pl : reqs) {
            Reader rd(pl);
            uint32_t n = rd.u32();
            sizes.push_back(n);
            for (uint32_t i = 0; i < n; i++) {
                rd.str();
                versions.push_back(rd.i64());
            }
        }
        CHECK(sizes == std::vector<uint32_t>({64, 4}) && versions.size() == 68);
        bool each_once = true;
        for (size_t i = 0; i < versions.size(); i++) each_once = each_once && versions[i] == static_cast<int64_t>(i + 1);
        CHECK(each_once && r.decided == 68 && r.owed_total == 0 && r.manifests_deleted() == 68 * 3);
        // the engine noted where the device got to (its commit sequence moved)
        CHECK(w.L->pending_prunes(10).empty() && w.L->get_device(FAKE_ID)->last_seq >= 0);
    }

    {
        printf("== a pass that dies is continued from what the ledger recorded\n");
        for (const char* point : {"gc.after_decide", "gc.after_delete_batch"}) {
            World w;
            std::string fid = w.add("die.bin", 10);
            for (uint8_t s = 20; s < 23; s++) w.edit(fid, "die.bin", s);
            w.later();
            int64_t now_at_crash = w.now_;
            w.close_ledger();
            std::vector<std::string> env;
            for (char** x = environ; *x; x++) env.push_back(*x);
            env.push_back(std::string("TIERFS_CRASH_AT=") + point);
            std::vector<char*> envp;
            for (auto& x : env) envp.push_back(const_cast<char*>(x.c_str()));
            envp.push_back(nullptr);
            std::string hex = crypto::to_hex(w.master.data(), 32), ledger = w.root + "/ledger", pa = std::to_string(PA), pb = std::to_string(PB),
                        nowstr = std::to_string(now_at_crash);
            std::vector<std::string> a = {"gc_test", "--child", hex, ledger, pa, w.ida, pb, w.idb, nowstr};
            std::vector<char*> av;
            for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
            av.push_back(nullptr);
            char self[1024];
            uint32_t sz = sizeof self;
            _NSGetExecutablePath(self, &sz);
            pid_t pid = 0;
            int rc = posix_spawn(&pid, self, nullptr, nullptr, av.data(), envp.data());
            int st = 0;
            if (rc == 0) waitpid(pid, &st, 0);
            CHECK(rc == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 137);  // it died where it was told to
            w.open_ledger();
            size_t left = w.manifests_on(w.dir_a) + w.manifests_on(w.dir_b);
            if (std::string(point) == "gc.after_decide")
                CHECK(w.L->pruned_count() == 2 && left == 8 && w.L->pending_prunes(100).size() == 4);  // decided; nothing deleted yet
            else
                CHECK(w.L->pruned_count() == 2 && left == 6 &&
                      w.L->pending_prunes(100).size() == 2);  // the first device's batch was deleted and recorded; the second device's was not
            GcReport r = w.G->run(w.devs);
            CHECK(r.decided == 0 && w.manifests_on(w.dir_a) == 2 && w.manifests_on(w.dir_b) == 2 && w.chunks_on(w.dir_a) == 5 &&
                  w.chunks_on(w.dir_b) == 5);
            CHECK(w.intact(fid, 3, *w.da) && w.intact(fid, 4, *w.db) && w.L->fsck().empty());
        }
    }

    {
        printf("== the client refuses answers that do not add up, and sends exactly what it was asked to\n");
        const std::string FAKE_ID = "77777777777777777777777777777777";
        const std::string VOL = "volume-x";
        const std::string F1 = "0123456789abcdef0123456789abcdef", F2 = "fedcba9876543210fedcba9876543210";
        int mode = 0;
        FakeDevice fk(PORT + 2, EIO, FAKE_ID, VOL, [&](const Frame& f, Writer& wr, uint8_t& type) {
            if (f.type == MSG_DEV_DELETE_MANIFESTS) {
                Reader rd(f.payload);
                uint32_t n = rd.u32();
                wr.u64(99);
                if (mode == 1) {
                    wr.u32(n + 1);
                    for (uint32_t i = 0; i <= n; i++) wr.u8(1);
                }  // one answer too many
                else if (mode == 2) {
                    wr.u32(n);
                    for (uint32_t i = 0; i < n; i++) wr.u8(2);
                }  // an answer that is neither 0 nor 1
                else if (mode == 3) {
                    wr.u32(n);
                }  // the answers are missing
                else if (mode == 4) {
                    wr.u32(n);
                    for (uint32_t i = 0; i + 1 < n; i++) wr.u8(1);
                }  // all but the last answer are there
                else {
                    wr.u32(n);
                    for (uint32_t i = 0; i < n; i++) wr.u8(i % 2);
                }
                return true;
            }
            if (f.type == MSG_DEV_GC_STATUS) {
                wr.u8(mode == 2 ? 2 : 1);
                wr.u32(11);
                wr.u32(12);
                wr.u64(13);
                wr.u64(14);
                wr.u64(15);
                wr.u64(16);
                wr.u64(17);
                wr.u64(18);
                if (mode == 3) wr.b.resize(wr.b.size() - 4);  // cut short
                return true;
            }
            if (f.type == MSG_DEV_SWEEP) {
                wr.u64(21);
                wr.u64(22);
                wr.u64(23);
                if (mode != 3) wr.u64(24);
                return true;
            }
            return false;
        });
        DeviceClient c("127.0.0.1", PORT + 2, 1500);
        std::vector<uint8_t> del;
        uint64_t seq = 0;
        mode = 0;
        DevRes r = c.delete_manifests({{F1, 3}, {F2, 4}, {F1, 5}}, del, &seq);
        CHECK(r.ok() && del == std::vector<uint8_t>({0, 1, 0}) && seq == 99);
        CHECK(c.delete_manifests({{F1, 3}}, del).ok() && del == std::vector<uint8_t>({0}));  // the sequence is optional
        {                                                                                    // what went out, in order
            auto reqs = fk.payloads(MSG_DEV_DELETE_MANIFESTS);
            Reader rd(reqs[0]);
            uint32_t n = rd.u32();
            std::string a = rd.str();
            int64_t av = rd.i64();
            std::string b = rd.str();
            int64_t bv = rd.i64();
            std::string c3 = rd.str();
            int64_t cv = rd.i64();
            CHECK(n == 3 && a == F1 && av == 3 && b == F2 && bv == 4 && c3 == F1 && cv == 5);
        }
        mode = 1;
        r = c.delete_manifests({{F1, 3}}, del);
        CHECK(!r.ok() && r.err == EPROTO && r.msg == "wrong number of deletion answers" && del.empty());
        mode = 2;
        r = c.delete_manifests({{F1, 3}}, del);
        CHECK(!r.ok() && r.err == EPROTO && r.msg == "bad deletion answer" && del.empty());
        mode = 3;
        r = c.delete_manifests({{F1, 3}}, del, &seq);
        CHECK(!r.ok() && r.err == EPROTO && r.msg == "malformed reply" && del.empty());
        mode = 4;
        r = c.delete_manifests({{F1, 3}, {F2, 4}, {F1, 5}}, del, &seq);
        CHECK(!r.ok() && r.err == EPROTO && r.msg == "malformed reply" && del.empty());  // what had been read is not left behind
        mode = 0;
        CHECK(c.delete_manifests({}, del).err == EMSGSIZE &&
              c.delete_manifests(std::vector<std::pair<std::string, int64_t>>(64, {F1, 1}), del).ok() &&
              c.delete_manifests(std::vector<std::pair<std::string, int64_t>>(65, {F1, 1}), del).err == EMSGSIZE);
        // the status: every field lands in its own place
        mode = 0;
        GcStatus g;
        CHECK(c.gc_status(g).ok() && g.deletions_allowed && g.manifests == 11 && g.manifests_without_refs == 12 && g.chunks == 13 &&
              g.chunk_bytes == 14 && g.unreferenced_chunks == 15 && g.unreferenced_bytes == 16 && g.manifests_deleted == 17 &&
              g.chunks_deleted == 18);
        mode = 2;
        r = c.gc_status(g);
        CHECK(!r.ok() && r.err == EPROTO && r.msg == "bad status");
        mode = 3;
        r = c.gc_status(g);
        CHECK(!r.ok() && r.err == EPROTO && r.msg == "malformed reply");
        // the sweep: what is asked, and what comes back
        mode = 0;
        SweepOut so;
        CHECK(c.sweep(111, 222, true, so).ok() && so.chunks_deleted == 21 && so.bytes_deleted == 22 && so.chunks_left == 23 &&
              so.strays_removed == 24);
        CHECK(c.sweep(333, 444, false, so).ok());
        {
            auto reqs = fk.payloads(MSG_DEV_SWEEP);
            Reader r1(reqs[0]), r2(reqs[1]);
            uint64_t a1 = r1.u64();
            uint32_t m1 = r1.u32();
            uint8_t d1 = r1.u8();
            uint64_t a2 = r2.u64();
            uint32_t m2 = r2.u32();
            uint8_t d2 = r2.u8();
            CHECK(a1 == 111 && m1 == 222 && d1 == 1 && a2 == 333 && m2 == 444 && d2 == 0);
        }
        mode = 3;
        r = c.sweep(1, 1, false, so);
        CHECK(!r.ok() && r.err == EPROTO && r.msg == "malformed reply");
    }

    {
        printf("== the limits of one run are respected and the rest is done by the next\n");
        World w;
        w.cfg.max_decisions = 1;
        w.cfg.sweep_chunks = 1;
        w.cfg.sweep_rounds = 1;
        w.make_gc();
        std::string fid = w.add("lim.bin", 10);
        for (uint8_t s = 20; s < 24; s++) w.edit(fid, "lim.bin", s);  // v1..v5
        w.later();
        GcReport r1 = w.G->run(w.devs);
        CHECK(r1.candidates == 1 && r1.decided == 1 && r1.manifests_deleted() == 2 && r1.chunks_swept() == 2 &&
              w.chunks_on(w.dir_a) == 1 + 2 * 4 + 1);  // one chunk per device and round
        int runs = 1;
        for (; runs < 20; runs++) {
            w.later();
            GcReport r = w.G->run(w.devs);
            if (r.candidates == 0 && r.chunks_swept() == 0) break;
        }
        CHECK(runs < 20 && w.manifests_on(w.dir_a) == 2 && w.manifests_on(w.dir_b) == 2 && w.chunks_on(w.dir_a) == 5 && w.chunks_on(w.dir_b) == 5);
        CHECK(w.intact(fid, 4, *w.da) && w.intact(fid, 5, *w.db) && w.L->fsck().empty());
    }

    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
