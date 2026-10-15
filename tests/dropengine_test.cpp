// Tests of the drop-local engine: the code that makes local bytes go away. Real files, two real device
// processes, a real ledger, real encryption. The invariant checked throughout: the original bytes always
// exist somewhere recoverable (at the original path, in quarantine, or provably on verified replicas), and
// nothing is deleted unless every rule holds.
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <thread>

#include "../core/dropengine.hpp"

extern char** environ;
using namespace tierfs;
using crypto::Bytes;
namespace fs = std::filesystem;

static int failures = 0;
// TIERFS_TEST_FAILFAST=1 stops at the first failing check (used by the mutation script: a mutant is
// "killed" the moment anything fails, so there is no point finishing the run).
static bool failfast() { static const bool f = getenv("TIERFS_TEST_FAILFAST") != nullptr; return f; }
// _exit skips destructors, so a fail-fast exit must release any RAM disk this test created by hand.
static void release_ramdisks() {
    char cmd[160];
    snprintf(cmd, sizeof cmd, "for v in /Volumes/tierfsram%d; do hdiutil detach \"$v\" -force >/dev/null 2>&1; done", static_cast<int>(getpid()));
    (void)!system(cmd);
}
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            printf("FAIL  line %d: %s\n", __LINE__, #cond);                        \
            failures++;                                                            \
            if (failfast()) { fflush(stdout); release_ramdisks(); _exit(1); }      \
        } else printf("PASS  %s\n", #cond);                                        \
    } while (0)

template <class T> static const T& at(const std::vector<T>& v, size_t i) { static const T dummy{}; return i < v.size() ? v[i] : dummy; }
static bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }
static std::string tmpdir() {
    char t[] = "/tmp/tierfs-droptest-XXXXXX";
    return mkdtemp(t);
}
static Bytes pattern(size_t n, uint8_t seed) {
    Bytes v(n);
    for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(seed + i * 43 + (i >> 8) + (i >> 20) * 11);
    return v;
}
static Bytes slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
static void spit(const std::string& p, const Bytes& b) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}
static std::string slurp_text(const std::string& p) { Bytes b = slurp(p); return std::string(b.begin(), b.end()); }
static bool exists(const std::string& p) { struct stat st; return lstat(p.c_str(), &st) == 0; }
static size_t count_entries(const std::string& dir) {
    size_t n = 0;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir, ec)) { (void)e; n++; }
    return n;
}

struct Server {
    pid_t pid = 0;
    uint16_t port;
    explicit Server(uint16_t p) : port(p) {}
    bool start(const std::string& store) {
        stop();
        std::vector<std::string> a = {"tierfs-device", store, std::to_string(port), "127.0.0.1"};
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

// Counts freeze/unfreeze and can refuse, to check the engine's discipline.
struct CountGate : FileGate {
    int freezes = 0, unfreezes = 0;
    bool allow = true;
    bool frozen = false;
    bool freeze(const FileRec&, std::string* why) override {
        if (!allow) { *why = "file is open for writing"; return false; }
        freezes++;
        frozen = true;
        return true;
    }
    void unfreeze(const FileRec&) override { unfreezes++; frozen = false; }
};

// A small RAM disk: a REAL second volume, so the "never rename across volumes" rule can be tested for real.
struct RamDisk {
    std::string dev, mount;
    bool ok = false;
    RamDisk() {
        std::string name = "tierfsram" + std::to_string(getpid());
        FILE* f = popen("hdiutil attach -nomount ram://16384 2>/dev/null", "r");
        char buf[256] = {0};
        if (f && fgets(buf, sizeof buf, f)) dev = buf;
        if (f) pclose(f);
        dev = dev.substr(0, dev.find_first_of(" \t\n"));
        if (dev.empty()) return;
        std::string cmd = "diskutil erasevolume HFS+ " + name + " " + dev + " >/dev/null 2>&1";
        if (system(cmd.c_str()) == 0) { mount = "/Volumes/" + name; ok = exists(mount); }
        if (!ok) release();
    }
    void release() { if (!dev.empty()) { std::string c = "hdiutil detach " + dev + " -force >/dev/null 2>&1"; (void)!system(c.c_str()); dev.clear(); } ok = false; }
    ~RamDisk() { release(); }
};

static const uint16_t PA = 9501, PB = 9502;
static const size_t MiB = 1u << 20;
static int g_world_counter = 0;

struct World {
    std::string root = tmpdir();
    crypto::SecretKey master = crypto::SecretKey::random();
    std::unique_ptr<crypto::Keys> keys = std::make_unique<crypto::Keys>(master);
    std::unique_ptr<Ledger> L;
    std::unique_ptr<Replicator> R;
    std::unique_ptr<DropEngine> E;
    Server sa{PA}, sb{PB};
    std::unique_ptr<DeviceClient> da, db;
    std::string ida, idb, consent;
    int64_t now_ = static_cast<int64_t>(time(nullptr));
    DeviceMap devs;
    std::map<std::string, Bytes> originals;
    DropPolicy policy;
    int n_ = 0;   // which device directories belong to this world

    World() {
        int n = n_ = ++g_world_counter;
        fs::create_directories(root + "/files");
        sa.start(root + "/devA" + std::to_string(n));
        sb.start(root + "/devB" + std::to_string(n));
        da = std::make_unique<DeviceClient>("127.0.0.1", PA, 3000);
        db = std::make_unique<DeviceClient>("127.0.0.1", PB, 3000);
        open_ledger();
        L->set_meta("recovery_acked", "1");
        L->set_meta("test_prefix", "/testdata/");
        L->ensure_reserve(1 << 20);
        consent = L->create_consent("/testdata/", 30 * 86400, "test");
        R->attach(*da, "device-a", "B", &ida);
        R->attach(*db, "device-b", "B", &idb);
        devs = {{ida, da.get()}, {idb, db.get()}};
    }
    ~World() { E.reset(); R.reset(); L.reset(); da.reset(); db.reset(); sa.stop(); sb.stop(); fs::remove_all(root); }

    void open_ledger() {
        std::string err;
        L = Ledger::open(root + "/ledger", &err);
        if (!L) return;
        L->set_clock([this] { return now_; });
        R = std::make_unique<Replicator>(*L, *keys, L->volume_id());
        std::string files = root + "/files";
        E = std::make_unique<DropEngine>(*L, *R, *keys, L->volume_id(), policy, root + "/quarantine",
                                         [files](const FileRec& f) { return files + "/" + f.path.substr(f.path.rfind('/') + 1); });
        if (!devs.empty()) {   // pointers stay valid across a ledger restart
            devs = {{ida, da.get()}, {idb, db.get()}};
        }
    }
    void close_ledger() { E.reset(); R.reset(); L.reset(); }

    std::string path(const std::string& name) const { return root + "/files/" + name; }
    std::string qroot() const { return root + "/quarantine"; }
    std::string track(const std::string& name, const char* logical_dir = "/testdata/") {
        struct stat st;
        stat(path(name).c_str(), &st);
        return L->track_file(std::string(logical_dir) + name, static_cast<uint64_t>(st.st_size), st.st_mtimespec.tv_sec, st.st_mode & 0777);
    }
    // A file that is on disk and replicated to both devices.
    std::string ready(const std::string& name, size_t size, uint8_t seed) {
        Bytes data = pattern(size, seed);
        originals[name] = data;
        spit(path(name), data);
        std::string fid = track(name);
        bool a = R->replicate(*da, ida, fid, path(name)).ok;
        bool b = R->replicate(*db, idb, fid, path(name)).ok;
        if (!a || !b) printf("      (setup: replication failed)\n");
        return fid;
    }
    // Where the bytes are right now: the original path, else any quarantine directory.
    std::optional<Bytes> bytes_somewhere(const std::string& name) {
        if (exists(path(name))) return slurp(path(name));
        std::error_code ec;
        for (auto& d : fs::directory_iterator(qroot(), ec))
            if (exists(d.path().string() + "/object")) return slurp(d.path().string() + "/object");
        return std::nullopt;
    }
    bool data_safe(const std::string& name) { auto b = bytes_somewhere(name); return b && *b == originals[name]; }
    bool remote_intact(const std::string& fid, DeviceClient& dev, const std::string& name) {
        Bytes got;
        Res r = R->fetch_version(dev, fid, L->get_file(fid)->current_version, [&](const uint8_t* p, size_t n) { got.insert(got.end(), p, p + n); return true; });
        return r.ok && got == originals[name];
    }
    // Rot one chunk of the file's first version on a device.
    void rot(const std::string& fid, int dev_index, size_t off = 100) {
        std::string cid = L->get_chunks(fid, 1)[0].chunk_id;
        std::string dir = root + (dev_index == 0 ? "/devA" : "/devB") + std::to_string(n_);
        std::string blob = dir + "/chunks/" + cid.substr(0, 2) + "/" + cid + ".blob";
        int fd = ::open(blob.c_str(), O_RDWR);
        uint8_t b = 0;
        if (fd >= 0) { pread(fd, &b, 1, static_cast<off_t>(off)); b ^= 0x40; pwrite(fd, &b, 1, static_cast<off_t>(off)); close(fd); }
    }
    // Nothing happened: still REPLICATED, bytes in place, no intent, nothing quarantined.
    bool untouched(const std::string& fid, const std::string& name) {
        auto f = L->get_file(fid);
        return f && f->state == FileState::REPLICATED && f->local_present && L->open_intents().empty() && L->list_quarantine().empty() &&
               exists(path(name)) && slurp(path(name)) == originals[name] && (!exists(qroot()) || count_entries(qroot()) == 0) && L->fsck().empty();
    }
};

static bool spawn_helper(const World& w, std::vector<std::string> args, const char* crash_point) {
    std::vector<std::string> e;
    for (char** x = environ; *x; x++) e.push_back(*x);
    e.push_back(std::string("TIERFS_CRASH_AT=") + crash_point);
    e.push_back("TIERFS_TEST_MASTER=" + crypto::to_hex(w.master.data(), 32));
    e.push_back("TIERFS_FAKE_NOW=" + std::to_string(w.now_));
    std::vector<char*> envp;
    for (auto& x : e) envp.push_back(const_cast<char*>(x.c_str()));
    envp.push_back(nullptr);
    std::vector<std::string> a = {"drop_helper", args[0], w.root + "/ledger", w.root + "/files", w.root + "/quarantine",
                                  std::to_string(PA), w.ida, std::to_string(PB), w.idb};
    a.insert(a.end(), args.begin() + 1, args.end());
    std::vector<char*> av;
    for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
    av.push_back(nullptr);
    const char* h = getenv("TIERFS_DROP_HELPER") ? getenv("TIERFS_DROP_HELPER") : "./build/drop_helper";
    pid_t pid;
    if (posix_spawn(&pid, h, nullptr, nullptr, av.data(), envp.data()) != 0) return false;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 137;
}

int main() {
    signal(SIGPIPE, SIG_IGN);

    {
        printf("== a drop moves the file into quarantine; everything is recorded and still recoverable\n");
        World w;
        std::string fid = w.ready("a", 2 * MiB + MiB / 2, 1);
        CountGate gate;
        DropOutcome o = w.E->drop(fid, w.consent, w.devs, &gate);
        CHECK(o.ok && !o.intent_id.empty() && o.replicas_audited == 2 && o.audits_failed == 0);
        CHECK(gate.freezes == 1 && gate.unfreezes == 1 && !gate.frozen);
        CHECK(!exists(w.path("a")));                                                                 // gone from where it was
        std::string qobj = w.E->quarantine_object(o.intent_id);
        CHECK(exists(qobj) && slurp(qobj) == w.originals["a"]);                                      // ... but held, byte for byte
        std::string note = slurp_text(w.E->quarantine_dir(o.intent_id) + "/meta");
        CHECK(has(note, "logical_path=/testdata/a") && has(note, ("file_id=" + fid).c_str()) && has(note, "version=1"));   // readable even without the ledger
        auto f = w.L->get_file(fid);
        CHECK(f->state == FileState::OFFLOADED && !f->local_present);
        auto q = w.L->get_quarantine(o.intent_id);
        CHECK(q && q->state == QuarantineState::HELD && q->held_at == w.now_);
        CHECK(w.L->open_intents().empty() && w.L->fsck().empty());
        CHECK(w.remote_intact(fid, *w.da, "a") && w.remote_intact(fid, *w.db, "a"));                  // and both devices can give it back
        DropOutcome again = w.E->drop(fid, w.consent, w.devs, &gate);
        CHECK(!again.ok && has(again.why, "not REPLICATED"));
        CHECK(gate.freezes == 1);                                                                    // a refused request never even froze it
    }

    {
        printf("== every refusal leaves everything exactly as it was\n");
        {   World w;   // one device is not enough: weight 1.0 < 2.0
            std::string fid = w.ready("one", MiB + 5, 2);
            DeviceMap only_a{{w.ida, w.da.get()}};
            DropOutcome o = w.E->drop(fid, w.consent, only_a);
            CHECK(!o.ok && has(o.why, "insufficient replica weight") && w.untouched(fid, "one"));
        }
        {   World w;   // a device whose copy has rotted fails its audit
            std::string fid = w.ready("rot", MiB + 5, 3);
            w.rot(fid, 1);
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && o.audits_failed == 1 && has(o.why, "insufficient replica weight") && w.untouched(fid, "rot"));
            std::optional<ReplicaState> rot_state;                                                       // (look the device up by id: the ledger lists replicas in id order, which is random)
            for (auto& r : w.L->get_replicas(fid, 1)) if (r.device_id == w.idb) rot_state = r.state;
            CHECK(rot_state && *rot_state == ReplicaState::AUDIT_FAILED);                                // and it is recorded against that device
        }
        {   World w;   // another name for the same bytes: the quarantine would share them with a live name (ADR-0011)
            std::string fid = w.ready("lnk", MiB + 5, 6);
            CHECK(link(w.path("lnk").c_str(), w.path("lnk.second").c_str()) == 0);
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && has(o.why, "other hard links (1 more name(s))") && w.untouched(fid, "lnk") && exists(w.path("lnk.second")));
            CHECK(link(w.path("lnk").c_str(), w.path("lnk.third").c_str()) == 0);
            o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && has(o.why, "other hard links (2 more name(s))"));
            CHECK(unlink(w.path("lnk.second").c_str()) == 0 && unlink(w.path("lnk.third").c_str()) == 0);
            o = w.E->drop(fid, w.consent, w.devs);   // with its other names gone it is an ordinary file again
            CHECK(o.ok && !exists(w.path("lnk")) && w.data_safe("lnk"));
        }
        {   World w;   // consent: wrong, then expired
            std::string fid = w.ready("c", MiB + 5, 4);
            CHECK(!w.E->drop(fid, "no-such-consent", w.devs).ok && w.untouched(fid, "c"));
            std::string shortc = w.L->create_consent("/testdata/", 10, "short");
            w.now_ += 60;
            DropOutcome o = w.E->drop(fid, shortc, w.devs);
            CHECK(!o.ok && has(o.why, "consent expired") && w.untouched(fid, "c"));
        }
        {   World w;   // gates
            std::string fid = w.ready("g", MiB + 5, 5);
            w.L->set_meta("recovery_acked", "0");
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && has(o.why, "recovery phrase") && w.untouched(fid, "g"));
            w.L->set_meta("recovery_acked", "1");
            w.L->release_reserve();
            CHECK(!w.E->drop(fid, w.consent, w.devs).ok && w.untouched(fid, "g"));
            w.L->ensure_reserve(1 << 20);
            // outside the test prefix and no backup acknowledged
            spit(w.path("outside"), pattern(MiB, 6));
            w.originals["outside"] = pattern(MiB, 6);
            std::string oid = w.track("outside", "/home/user/");
            CHECK(w.R->replicate(*w.da, w.ida, oid, w.path("outside")).ok && w.R->replicate(*w.db, w.idb, oid, w.path("outside")).ok);
            std::string wide = w.L->create_consent("/home/", 3600, "x");
            DropOutcome od = w.E->drop(oid, wide, w.devs);
            CHECK(!od.ok && has(od.why, "backup not acknowledged") && exists(w.path("outside")) && w.L->list_quarantine().empty());
        }
        {   World w;   // a device that is no longer trusted
            std::string fid = w.ready("s", MiB + 5, 7);
            DevInfo di;
            w.da->info(di);
            w.L->observe_device(w.ida, di.epoch, di.seq - 1);                                          // looks rolled back
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && w.L->get_file(fid)->state != FileState::DROPPING && exists(w.path("s")) && w.L->list_quarantine().empty());
        }
        {   World w;   // states other than REPLICATED
            w.originals["l"] = pattern(MiB, 8);
            spit(w.path("l"), w.originals["l"]);
            std::string lid = w.track("l");                                                            // still LOCAL
            CHECK(!w.E->drop(lid, w.consent, w.devs).ok && exists(w.path("l")));
            std::string gone = w.ready("gone", MiB, 9);
            DropOutcome ok1 = w.E->drop(gone, w.consent, w.devs);
            CHECK(ok1.ok);
            DropOutcome twice = w.E->drop(gone, w.consent, w.devs);
            CHECK(!twice.ok && has(twice.why, "OFFLOADED"));
            CHECK(!w.E->drop("no-such-file", w.consent, w.devs).ok);
        }
        {   World w;   // a writer holds the file: the gate refuses and the engine never goes on
            std::string fid = w.ready("busy", MiB + 5, 10);
            CountGate gate;
            gate.allow = false;
            DropOutcome o = w.E->drop(fid, w.consent, w.devs, &gate);
            CHECK(!o.ok && has(o.why, "cannot freeze") && has(o.why, "open for writing") && gate.freezes == 0 && gate.unfreezes == 0 && w.untouched(fid, "busy"));
        }
        {   World w;   // the quarantine area cannot be created (a plain file is in the way): the ledger's claim is withdrawn
            std::string fid = w.ready("nq", MiB + 5, 11);
            spit(w.qroot(), pattern(10, 1));                                                            // "quarantine" is a file, not a directory
            CountGate gate;
            DropOutcome o = w.E->drop(fid, w.consent, w.devs, &gate);
            CHECK(!o.ok && has(o.why, "quarantine area"));
            auto f = w.L->get_file(fid);
            CHECK(f->state == FileState::REPLICATED && f->local_present && exists(w.path("nq")) && slurp(w.path("nq")) == w.originals["nq"]);
            CHECK(w.L->open_intents().empty() && w.L->list_quarantine().empty() && w.L->fsck().empty() && gate.unfreezes == 1);
        }
    }

    {
        printf("== the quarantine must be on the same volume as the file, or the move could not be atomic\n");
        RamDisk ram;
        if (!ram.ok) {
            printf("      (skipped: could not create a RAM disk)\n");
        } else {
            World w;
            std::string fid = w.ready("xv", MiB + 5, 12);
            std::string files = w.root + "/files";
            DropEngine other(*w.L, *w.R, *w.keys, w.L->volume_id(), w.policy, ram.mount + "/q",
                             [files](const FileRec& f) { return files + "/" + f.path.substr(f.path.rfind('/') + 1); });
            struct stat a, b;
            stat(w.path("xv").c_str(), &a);
            stat(ram.mount.c_str(), &b);
            CHECK(a.st_dev != b.st_dev);                                                                  // it really is another filesystem
            DropOutcome o = other.drop(fid, w.consent, w.devs);
            CHECK(!o.ok && has(o.why, "different volume"));
            auto f = w.L->get_file(fid);
            CHECK(f->state == FileState::REPLICATED && f->local_present && exists(w.path("xv")) && slurp(w.path("xv")) == w.originals["xv"]);
            CHECK(w.L->open_intents().empty() && w.L->list_quarantine().empty() && w.L->fsck().empty());
            CHECK(count_entries(ram.mount + "/q") == 0);                                                   // and nothing was copied there
        }
    }

    {
        printf("== the local bytes are verified against the plan, because a missed modification would be destroyed\n");
        struct Case { const char* name; const char* what; };
        {   World w;   // same size, one byte different, but the filesystem layer never told the ledger
            std::string fid = w.ready("m", 2 * MiB + 77, 20);
            int64_t gen = w.L->get_file(fid)->generation;
            { int fd = ::open(w.path("m").c_str(), O_WRONLY); uint8_t b = 0x99; pwrite(fd, &b, 1, 5 * 1000 + 3); close(fd); }
            Bytes edited = slurp(w.path("m"));
            CountGate gate;
            DropOutcome o = w.E->drop(fid, w.consent, w.devs, &gate);
            CHECK(!o.ok && o.file_changed && has(o.why, "not what was replicated"));
            CHECK(slurp(w.path("m")) == edited && w.L->list_quarantine().empty() && w.L->open_intents().empty());   // the edit survives
            auto f = w.L->get_file(fid);
            CHECK(f->state == FileState::LOCAL && f->generation > gen && gate.unfreezes == 1);                  // and the ledger now knows the version is stale
        }
        {   World w;   // a change in the LAST chunk: checking only the beginning of the file would miss it
            std::string fid = w.ready("late", 3 * MiB + 9, 26);
            { int fd = ::open(w.path("late").c_str(), O_WRONLY); uint8_t b = 0x5a; pwrite(fd, &b, 1, 3 * MiB + 5); close(fd); }
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && o.file_changed && has(o.why, "chunk 3") && exists(w.path("late")) && w.L->list_quarantine().empty());
        }
        {   World w;   // truncated
            std::string fid = w.ready("t", 2 * MiB + 77, 21);
            truncate(w.path("t").c_str(), MiB);
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && o.file_changed && has(o.why, "size") && exists(w.path("t")) && w.L->get_file(fid)->state == FileState::LOCAL);
        }
        {   World w;   // appended to
            std::string fid = w.ready("g", MiB + 77, 22);
            { std::ofstream f(w.path("g"), std::ios::binary | std::ios::app); f << "more"; }
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && o.file_changed && w.L->get_file(fid)->state == FileState::LOCAL && exists(w.path("g")));
        }
        {   World w;   // replaced by a symlink to identical content: not followed
            std::string fid = w.ready("sl", MiB + 77, 23);
            std::string target = w.root + "/elsewhere";
            spit(target, w.originals["sl"]);
            unlink(w.path("sl").c_str());
            symlink(target.c_str(), w.path("sl").c_str());
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && has(o.why, "not a regular file") && w.L->get_file(fid)->state == FileState::REPLICATED && w.L->list_quarantine().empty());
            CHECK(exists(target));
        }
        {   World w;   // deleted behind our back
            std::string fid = w.ready("d", MiB + 77, 24);
            unlink(w.path("d").c_str());
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && w.L->list_quarantine().empty() && w.L->open_intents().empty());
        }
        {   World w;   // touched (same bytes, new mtime) is fine: the CONTENT is what must match, and it does
            std::string fid = w.ready("touch", MiB + 77, 25);
            utimbuf t{1234567, 1234567};
            utime(w.path("touch").c_str(), &t);
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(o.ok && w.L->get_file(fid)->state == FileState::OFFLOADED);
        }
    }

    {
        printf("== a race after verification is caught by the last identity check before the move\n");
        for (const char* when : {"audited", "before_rename"}) {
            World w;
            std::string fid = w.ready("r", 2 * MiB + 9, 30);
            Bytes rewritten = pattern(2 * MiB + 9, 31);
            w.E->on_step = [&](const char* s) { if (!strcmp(s, when)) spit(w.path("r"), rewritten); };   // a writer got in despite everything
            CountGate gate;
            DropOutcome o = w.E->drop(fid, w.consent, w.devs, &gate);
            CHECK(!o.ok && o.file_changed && has(o.why, "modified after it was verified"));
            CHECK(slurp(w.path("r")) == rewritten);                                                        // the newer content was NOT moved away
            auto f = w.L->get_file(fid);
            CHECK(f->state == FileState::LOCAL && f->local_present && w.L->open_intents().empty() && w.L->list_quarantine().empty());
            CHECK((!exists(w.qroot()) || count_entries(w.qroot()) == 0) && w.L->fsck().empty() && gate.unfreezes == 1);
        }
        {   World w;   // replaced by a different file with identical bytes, size AND modification time: only the inode differs
            std::string fid = w.ready("inode", MiB + 9, 34);
            w.E->on_step = [&](const char* s) {
                if (!strcmp(s, "before_rename")) {
                    struct stat st;
                    stat(w.path("inode").c_str(), &st);
                    spit(w.path("inode.new"), w.originals["inode"]);
                    struct timespec ts[2] = {st.st_mtimespec, st.st_mtimespec};
                    utimensat(AT_FDCWD, w.path("inode.new").c_str(), ts, 0);
                    rename(w.path("inode.new").c_str(), w.path("inode").c_str());
                }
            };
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && has(o.why, "modified after it was verified") && exists(w.path("inode")) && w.L->list_quarantine().empty());
        }
        {   World w;   // replaced by a different file with IDENTICAL bytes: a new inode is still not "the file we verified"
            std::string fid = w.ready("swap", MiB + 9, 32);
            w.E->on_step = [&](const char* s) {
                if (!strcmp(s, "before_rename")) { spit(w.path("swap.new"), w.originals["swap"]); rename(w.path("swap.new").c_str(), w.path("swap").c_str()); }
            };
            DropOutcome o = w.E->drop(fid, w.consent, w.devs);
            CHECK(!o.ok && has(o.why, "modified after it was verified") && exists(w.path("swap")) && w.L->list_quarantine().empty());
        }
    }

    {
        printf("== crash injection: the process dies at each step of a drop; the data is never lost and recovery converges\n");
        struct Point { const char* name; const char* expect; };   // expect: where recovery must leave things
        for (Point p : {Point{"ledger.drop.before_commit", "intact"}, Point{"ledger.drop.after_commit", "intact"}, Point{"drop.after_meta", "intact"},
                        Point{"drop.after_rename", "dropped"}, Point{"drop.after_sync", "dropped"}, Point{"ledger.complete.before_commit", "dropped"},
                        Point{"ledger.complete.after_commit", "dropped"}}) {
            printf("   -- %s\n", p.name);
            World w;
            std::string fid = w.ready("f", 3 * MiB + 321, 40);
            w.close_ledger();
            CHECK(spawn_helper(w, {"drop", w.consent, fid}, p.name));                                    // dies at the crash point
            w.open_ledger();
            CHECK(w.L && w.L->fsck().empty());
            CHECK(w.data_safe("f"));                                                                      // THE invariant: the bytes exist, intact, somewhere
            RecoveryReport rr = w.E->recover(w.devs);
            CHECK(rr.problems.empty());
            CHECK(w.L->fsck().empty() && w.L->open_intents().empty() && w.data_safe("f"));
            auto f = w.L->get_file(fid);
            if (!strcmp(p.expect, "intact")) {
                CHECK(f->state == FileState::REPLICATED && f->local_present && exists(w.path("f")) && w.L->list_quarantine().empty());
                CHECK(!exists(w.qroot()) || count_entries(w.qroot()) == 0);                              // no half-made quarantine left behind
                CountGate gate;
                CHECK(w.E->drop(fid, w.consent, w.devs, &gate).ok);                                      // and a fresh attempt works
            } else {
                CHECK(f->state == FileState::OFFLOADED && !f->local_present && !exists(w.path("f")));
                auto qs = w.L->list_quarantine();
                CHECK(qs.size() == 1 && at(qs, 0).state == QuarantineState::HELD);
                CHECK(slurp(w.E->quarantine_object(at(qs, 0).intent_id)) == w.originals["f"]);
            }
            CHECK(w.remote_intact(fid, *w.da, "f") && w.remote_intact(fid, *w.db, "f"));
        }
    }

    {
        printf("== after the move, if the ledger will not complete (evidence went stale), the bytes are put back\n");
        World w;
        std::string fid = w.ready("stale", 2 * MiB + 5, 36);
        w.E->on_step = [&](const char* s) { if (!strcmp(s, "before_rename")) w.now_ += 1000; };      // minutes pass between the audit and the move
        DropOutcome o = w.E->drop(fid, w.consent, w.devs);
        CHECK(!o.ok && has(o.why, "restored") && has(o.why, "refused to complete"));
        auto f = w.L->get_file(fid);
        CHECK(f->state == FileState::REPLICATED && f->local_present && exists(w.path("stale")) && slurp(w.path("stale")) == w.originals["stale"]);
        CHECK(w.L->open_intents().empty() && w.L->list_quarantine().empty() && (!exists(w.qroot()) || count_entries(w.qroot()) == 0) && w.L->fsck().empty());
        w.E->on_step = nullptr;
        CHECK(w.E->drop(fid, w.consent, w.devs).ok);                                                   // and with fresh evidence it goes through
    }

    {
        printf("== a replica that rots during the crash window stops recovery from completing the drop\n");
        World w;
        std::string fid = w.ready("win", 2 * MiB + 5, 37);
        w.close_ledger();
        CHECK(spawn_helper(w, {"drop", w.consent, fid}, "drop.after_sync"));                           // bytes are in quarantine, the ledger still says DROPPING
        w.open_ledger();
        w.rot(fid, 1);                                                                                  // meanwhile a device's copy goes bad
        RecoveryReport rr = w.E->recover(w.devs);                                                       // recovery re-audits instead of trusting what it saw before the crash
        CHECK(rr.problems.empty() && rr.actions.size() == 1 && has(rr.actions[0], "restored"));
        auto f = w.L->get_file(fid);
        CHECK(f->state == FileState::REPLICATED && f->local_present && exists(w.path("win")) && slurp(w.path("win")) == w.originals["win"]);
        CHECK(w.L->list_quarantine().empty() && w.L->open_intents().empty() && w.L->fsck().empty());
    }

    {
        printf("== recovery refuses to guess when the evidence is odd\n");
        auto begin_only = [](World& w, const std::string& fid, std::string* intent) {   // ledger says DROPPING, nothing moved yet
            DropEngine& e = *w.E;
            size_t a = 0, f = 0;
            (void)e; (void)a; (void)f;
            for (auto& kv : w.devs) w.R->audit_replica(*kv.second, kv.first, fid, 1);
            Res bd = w.L->begin_drop(fid, 1, w.L->get_file(fid)->generation, w.consent, 2.0, 300);
            *intent = bd.id;
            return bd.ok;
        };
        {   World w;   // the file exists in BOTH places
            std::string fid = w.ready("both", MiB + 1, 50);
            std::string intent;
            CHECK(begin_only(w, fid, &intent));
            fs::create_directories(w.E->quarantine_dir(intent));
            spit(w.E->quarantine_object(intent), w.originals["both"]);
            RecoveryReport rr = w.E->recover(w.devs);
            CHECK(rr.problems.size() == 1 && has(rr.problems[0], "BOTH"));
            CHECK(w.L->get_file(fid)->state == FileState::DROPPING && exists(w.path("both")) && w.L->fsck().empty());   // left alone for a human
        }
        {   World w;   // gone from both places, replicas verify: the ledger is made truthful, loudly
            std::string fid = w.ready("lost", MiB + 1, 51);
            std::string intent;
            CHECK(begin_only(w, fid, &intent));
            unlink(w.path("lost").c_str());
            RecoveryReport rr = w.E->recover(w.devs);
            CHECK(rr.problems.size() == 2 && has(at(rr.problems, 0), "GONE") && has(at(rr.problems, 0), "replicas verify"));
            CHECK(has(at(rr.problems, 1), "quarantined bytes are missing"));                                   // the new quarantine record holds nothing: said so too
            CHECK(w.L->get_file(fid)->state == FileState::OFFLOADED && w.remote_intact(fid, *w.da, "lost"));
        }
        {   World w;   // gone from both places AND the replicas cannot be reached: possible loss, never papered over
            std::string fid = w.ready("lost2", MiB + 1, 52);
            std::string intent;
            CHECK(begin_only(w, fid, &intent));
            unlink(w.path("lost2").c_str());
            w.now_ += 10000;                                                                              // the audits are no longer fresh
            RecoveryReport rr = w.E->recover(DeviceMap{});                                                // and no device is reachable
            CHECK(rr.problems.size() == 1 && has(rr.problems[0], "DATA LOSS"));
            CHECK(w.L->get_file(fid)->state == FileState::DROPPING);                                      // the ledger does not claim what it cannot prove
        }
        {   World w;   // moved, but the replicas can no longer be verified: the bytes come BACK
            std::string fid = w.ready("back", MiB + 1, 53);
            std::string intent;
            CHECK(begin_only(w, fid, &intent));
            fs::create_directories(w.E->quarantine_dir(intent));
            rename(w.path("back").c_str(), w.E->quarantine_object(intent).c_str());
            w.now_ += 10000;                                                                              // audit evidence went stale
            RecoveryReport rr = w.E->recover(DeviceMap{});                                                // and nothing can be re-audited
            CHECK(rr.problems.empty() && rr.actions.size() == 1 && has(rr.actions[0], "restored"));
            CHECK(exists(w.path("back")) && slurp(w.path("back")) == w.originals["back"] && w.L->get_file(fid)->state == FileState::REPLICATED);
            CHECK(w.L->list_quarantine().empty() && w.L->fsck().empty());
        }
        {   World w;   // bytes still at origin but changed since the crash: noticed, not blessed
            std::string fid = w.ready("chg", MiB + 1, 54);
            std::string intent;
            CHECK(begin_only(w, fid, &intent));
            { int fd = ::open(w.path("chg").c_str(), O_WRONLY); uint8_t b = 0x77; pwrite(fd, &b, 1, 9); close(fd); }
            RecoveryReport rr = w.E->recover(w.devs);
            CHECK(rr.actions.size() == 1 && has(rr.actions[0], "modified"));
            CHECK(w.L->get_file(fid)->state == FileState::LOCAL && exists(w.path("chg")));
        }
    }

    {
        printf("== purge: bytes are deleted only after the retention period, fresh evidence, and a recorded intent\n");
        {   World w;
            std::string fid = w.ready("p", 2 * MiB + 11, 60);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            CHECK(d.ok);
            PurgeOutcome early = w.E->purge(d.intent_id, w.devs, false);                                  // the same moment
            CHECK(!early.ok && has(early.why, "has not elapsed") && exists(w.E->quarantine_object(d.intent_id)));
            CHECK(w.L->get_quarantine(d.intent_id)->state == QuarantineState::HELD);
            w.now_ += 8 * 86400;
            PurgeOutcome done = w.E->purge(d.intent_id, w.devs, false);
            CHECK(done.ok && done.replicas_audited == 2 && done.audits_failed == 0);
            CHECK(!exists(w.E->quarantine_dir(d.intent_id)) && !exists(w.path("p")));                      // really gone
            CHECK(w.L->get_quarantine(d.intent_id)->state == QuarantineState::PURGED && w.L->get_file(fid)->state == FileState::OFFLOADED);
            CHECK(w.remote_intact(fid, *w.da, "p") && w.remote_intact(fid, *w.db, "p") && w.L->fsck().empty());   // the data lives on the devices, verified
            PurgeOutcome again = w.E->purge(d.intent_id, w.devs, false);
            CHECK(!again.ok);
        }
        {   World w;   // an emergency may skip the waiting
            std::string fid = w.ready("e", MiB + 1, 61);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            PurgeOutcome em = w.E->purge(d.intent_id, w.devs, true);
            CHECK(em.ok && !exists(w.E->quarantine_dir(d.intent_id)));
        }
        {   World x;   // ... never the evidence (a separate world: they share the device ports)
            std::string fid2 = x.ready("e2", MiB + 1, 62);
            DropOutcome d2 = x.E->drop(fid2, x.consent, x.devs);
            x.rot(fid2, 1);                                                                                 // one replica rots while the bytes sit in quarantine
            PurgeOutcome refused = x.E->purge(d2.intent_id, x.devs, true);
            CHECK(!refused.ok && refused.audits_failed == 1 && has(refused.why, "insufficient replica weight"));
            CHECK(exists(x.E->quarantine_object(d2.intent_id)) && slurp(x.E->quarantine_object(d2.intent_id)) == x.originals["e2"]);   // still held
            CHECK(x.L->get_quarantine(d2.intent_id)->state == QuarantineState::HELD);
        }
        {   World w;   // both replicas fail: the file is AT_RISK and the quarantine is all that is left
            std::string fid = w.ready("ar", MiB + 1, 63);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            w.rot(fid, 0);
            w.rot(fid, 1);
            w.now_ += 8 * 86400;
            PurgeOutcome p = w.E->purge(d.intent_id, w.devs, false);
            CHECK(!p.ok && p.audits_failed == 2);
            CHECK(w.L->get_file(fid)->state == FileState::AT_RISK && exists(w.E->quarantine_object(d.intent_id)));
            CHECK(w.data_safe("ar"));
            RestoreOutcome r = w.E->restore(d.intent_id, "all replicas failed");                            // the way out
            CHECK(r.ok && r.bytes_verified && exists(w.path("ar")) && slurp(w.path("ar")) == w.originals["ar"]);
            auto f = w.L->get_file(fid);
            CHECK(f->state == FileState::LOCAL && f->local_present && w.L->fsck().empty());                  // no committed replica left: replicate again
        }
        {   World w;   // a file that was hydrated again no longer needs its quarantine
            std::string fid = w.ready("hy", MiB + 1, 64);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            CHECK(w.L->begin_hydrate(fid).ok);
            spit(w.path("hy"), w.originals["hy"]);                                                           // (the recall writes the bytes back)
            CHECK(w.L->complete_hydrate(fid).ok);
            w.now_ += 8 * 86400;
            PurgeOutcome p = w.E->purge(d.intent_id, w.devs, false);
            CHECK(p.ok && exists(w.path("hy")) && !exists(w.E->quarantine_dir(d.intent_id)));
        }
    }

    {
        printf("== crash injection around purge and restore\n");
        for (const char* point : {"ledger.purge.before_commit", "ledger.purge.after_commit", "purge.after_begin", "purge.after_unlink"}) {
            printf("   -- %s\n", point);
            World w;
            std::string fid = w.ready("pc", MiB + 5, 70);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            w.now_ += 8 * 86400;
            w.close_ledger();
            CHECK(spawn_helper(w, {"purge", d.intent_id}, point));
            w.open_ledger();
            CHECK(w.L->fsck().empty() && w.remote_intact(fid, *w.da, "pc"));                                // the data is on the devices whatever happened
            bool before = !strcmp(point, "ledger.purge.before_commit");
            if (before) CHECK(exists(w.E->quarantine_object(d.intent_id)));                                   // refused or not begun: bytes untouched
            RecoveryReport rr = w.E->recover(w.devs);
            CHECK(rr.problems.empty() && w.L->fsck().empty());
            auto q = w.L->get_quarantine(d.intent_id);
            if (before) {
                CHECK(q->state == QuarantineState::HELD && exists(w.E->quarantine_object(d.intent_id)));      // nothing was decided
                CHECK(w.E->purge(d.intent_id, w.devs, false).ok);
            } else {
                CHECK(q->state == QuarantineState::PURGED && !exists(w.E->quarantine_dir(d.intent_id)));       // an interrupted purge is finished, not abandoned halfway
            }
        }
        for (const char* point : {"ledger.restore.before_commit", "restore.after_begin", "restore.after_rename"}) {
            printf("   -- %s\n", point);
            World w;
            std::string fid = w.ready("rc", MiB + 5, 71);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            w.close_ledger();
            CHECK(spawn_helper(w, {"restore", d.intent_id}, point));
            w.open_ledger();
            CHECK(w.L->fsck().empty() && w.data_safe("rc"));                                                  // still safe wherever it is
            RecoveryReport rr = w.E->recover(w.devs);
            CHECK(rr.problems.empty() && w.L->fsck().empty() && w.data_safe("rc"));
            auto q = w.L->get_quarantine(d.intent_id);
            if (!strcmp(point, "ledger.restore.before_commit")) {
                CHECK(q->state == QuarantineState::HELD);                                                    // nothing was decided
            } else {
                CHECK(q->state == QuarantineState::RESTORED && exists(w.path("rc")) && !exists(w.E->quarantine_dir(d.intent_id)));
                CHECK(w.L->get_file(fid)->state == FileState::REPLICATED && w.L->get_file(fid)->local_present);
            }
        }
    }

    {
        printf("== restore: bytes come back, honestly labelled, and never over something else\n");
        {   World w;
            std::string fid = w.ready("r1", 2 * MiB + 3, 80);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            RestoreOutcome r = w.E->restore(d.intent_id, "changed my mind");
            CHECK(r.ok && r.bytes_verified);
            CHECK(exists(w.path("r1")) && slurp(w.path("r1")) == w.originals["r1"] && !exists(w.E->quarantine_dir(d.intent_id)));
            auto f = w.L->get_file(fid);
            CHECK(f->state == FileState::REPLICATED && f->local_present && w.L->get_quarantine(d.intent_id)->state == QuarantineState::RESTORED);
            CHECK(w.L->fsck().empty());
            CHECK(!w.E->restore(d.intent_id, "again").ok);                                                   // once
            CHECK(w.E->drop(fid, w.consent, w.devs).ok);                                                      // and it can be dropped again
        }
        {   World w;   // somebody made a new file at the old path in the meantime
            std::string fid = w.ready("r2", MiB + 3, 81);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            spit(w.path("r2"), pattern(50, 9));                                                              // a different file now lives there
            RestoreOutcome r = w.E->restore(d.intent_id, "x");
            CHECK(!r.ok && has(r.why, "occupied"));
            CHECK(slurp(w.path("r2")) == pattern(50, 9));                                                    // never overwritten
            CHECK(exists(w.E->quarantine_object(d.intent_id)) && w.L->get_quarantine(d.intent_id)->state == QuarantineState::RESTORING);
            RecoveryReport rr = w.E->recover(w.devs);
            CHECK(rr.problems.size() == 1);                                                                   // a human has to decide
            unlink(w.path("r2").c_str());
            RecoveryReport rr2 = w.E->recover(w.devs);                                                        // once the path is free, recovery finishes it
            CHECK(rr2.problems.empty() && exists(w.path("r2")) && slurp(w.path("r2")) == w.originals["r2"]);
            CHECK(w.L->get_quarantine(d.intent_id)->state == QuarantineState::RESTORED && w.L->fsck().empty());
        }
        {   World w;   // the quarantined bytes themselves rotted: they come back, but are not vouched for
            std::string fid = w.ready("r3", MiB + 3, 82);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            { int fd = ::open(w.E->quarantine_object(d.intent_id).c_str(), O_RDWR); uint8_t b = 0x13; pwrite(fd, &b, 1, 7); close(fd); }
            int64_t gen = w.L->get_file(fid)->generation;
            RestoreOutcome r = w.E->restore(d.intent_id, "x");
            CHECK(r.ok && !r.bytes_verified);
            auto f = w.L->get_file(fid);
            CHECK(f->state == FileState::LOCAL && f->generation == gen + 1 && f->local_present);             // data again, with everything prepared for the old bytes voided
        }
        {   World w;   // restoring something that was already deleted
            std::string fid = w.ready("r4", MiB + 3, 83);
            DropOutcome d = w.E->drop(fid, w.consent, w.devs);
            w.now_ += 8 * 86400;
            CHECK(w.E->purge(d.intent_id, w.devs, false).ok);
            RestoreOutcome r = w.E->restore(d.intent_id, "too late");
            CHECK(!r.ok && !exists(w.path("r4")));
            CHECK(!w.E->restore("no-such-intent", "x").ok);
        }
    }

    {
        printf("== a whole life: replicate, drop, wait, purge, and the data is still there\n");
        World w;
        std::string fid = w.ready("life", 4 * MiB + 99, 90);
        DropOutcome d = w.E->drop(fid, w.consent, w.devs);
        CHECK(d.ok);
        w.now_ += 3 * 86400;
        CHECK(!w.E->purge(d.intent_id, w.devs, false).ok);                                                    // day 3: too early
        w.now_ += 5 * 86400;
        CHECK(w.E->purge(d.intent_id, w.devs, false).ok);                                                     // day 8: allowed, and re-verified first
        CHECK(!exists(w.path("life")) && w.L->get_file(fid)->state == FileState::OFFLOADED);
        CHECK(w.remote_intact(fid, *w.da, "life") && w.remote_intact(fid, *w.db, "life"));
        // survivor of everything: one device may now die and the data is still recoverable
        w.sa.stop();
        DeviceClient dead("127.0.0.1", PA, 500);
        Bytes got;
        CHECK(!w.R->fetch_version(dead, fid, 1, [&](const uint8_t* p, size_t n) { got.insert(got.end(), p, p + n); return true; }).ok);
        CHECK(w.remote_intact(fid, *w.db, "life"));
        CHECK(w.L->fsck().empty());
    }

    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
