// Tests of the tiering policy layer: space levels, which files are chosen and why, the approval handshake, and
// execution through the real drop engine with real device servers. Nothing runs unless the user approved exactly that plan.
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

#include "../core/policy.hpp"

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
// TIERFS_TEST_TMP / TIERFS_TEST_PORT let several copies of this test run side by side (the parallel mutation runner).
static std::string tmpdir() {
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-policytest-XXXXXX";
    std::vector<char> buf(t.begin(), t.end());
    buf.push_back(0);
    return mkdtemp(buf.data());
}
static uint16_t port_base() { return getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9511; }
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

static const uint16_t PA = port_base(), PB = static_cast<uint16_t>(port_base() + 1);
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

    explicit World(const char* cls_b = "B") {
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
        R->attach(*db, "device-b", cls_b, &idb);
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

struct FakeProbe : SpaceProbe {
    uint64_t total = 200ull << 30, avail = 100ull << 30;
    int snaps = 0;
    SpaceInfo measure() override { SpaceInfo s; s.total = total; s.avail_raw = avail; s.avail_important = avail; return s; }
    int local_snapshots() override { return snaps; }
};
struct CountNotifier : Notifier {
    int calls = 0;
    SpaceLevel last = SpaceLevel::OK;
    void low_space(const SpaceStatus& s, const TierPlan&) override { calls++; last = s.level; }
};

static TierPolicy base_policy() {
    TierPolicy p;
    p.roots = {"/testdata/"};
    p.exclude = {"/.git/"};
    p.min_size = MiB;
    p.min_idle_seconds = 30 * 86400;
    p.replicate_idle_seconds = 7 * 86400;
    p.consent_ttl = 3600;
    return p;
}
static std::unique_ptr<PolicyEngine> make_pe(World& w, FakeProbe& probe, const TierPolicy& pol, Notifier* n = nullptr) {
    std::string files = w.root + "/files";
    return std::make_unique<PolicyEngine>(*w.L, *w.R, *w.E, probe, pol,
                                          [files](const FileRec& f) { return files + "/" + f.path.substr(f.path.rfind('/') + 1); }, n);
}
static const PlanEntry* find_entry(const TierPlan& p, const std::string& file_id) {
    for (auto& e : p.entries) if (e.file_id == file_id) return &e;
    return nullptr;
}
// Is there a HELD quarantine object whose bytes are the original of `name`? (looks at every one: there can be several)
static bool held_matches(World& w, const std::string& name) {
    for (auto& q : w.L->list_quarantine(QuarantineState::HELD)) {
        std::string obj = w.E->quarantine_object(q.intent_id);
        if (exists(obj) && slurp(obj) == w.originals[name]) return true;
    }
    return false;
}
static std::string put(World& w, const std::string& name, size_t size, uint8_t seed, const char* dir = "/testdata/") {
    Bytes d = pattern(size, seed);
    w.originals[name] = d;
    spit(w.path(name), d);
    return w.track(name, dir);
}

int main() {
    signal(SIGPIPE, SIG_IGN);

    {
        printf("== free-space levels: the larger of an absolute size and a fraction of the volume\n");
        TierPolicy p = base_policy();   // low: max(20 GiB, 15%), critical: max(8 GiB, 5%)
        SpaceInfo s;
        s.total = 200ull << 30;         // 15% = 30 GiB, 5% = 10 GiB
        s.avail_raw = s.avail_important = 31ull << 30;
        CHECK(PolicyEngine::level_for(s, p) == SpaceLevel::OK);
        s.avail_raw = s.avail_important = 29ull << 30;
        CHECK(PolicyEngine::level_for(s, p) == SpaceLevel::LOW);
        s.avail_raw = s.avail_important = 11ull << 30;
        CHECK(PolicyEngine::level_for(s, p) == SpaceLevel::LOW);
        s.avail_raw = s.avail_important = 9ull << 30;
        CHECK(PolicyEngine::level_for(s, p) == SpaceLevel::CRITICAL);
        s.total = 2000ull << 30;        // on a big disk the absolute floors win... until the fraction is larger
        s.avail_raw = s.avail_important = 150ull << 30;
        CHECK(PolicyEngine::level_for(s, p) == SpaceLevel::LOW);   // 15% of 2000 GiB = 300 GiB
        // the OS's "important usage" figure wins over the raw one (purgeable space is not a shortage)
        s.total = 200ull << 30; s.avail_raw = 5ull << 30; s.avail_important = 60ull << 30;
        CHECK(PolicyEngine::level_for(s, p) == SpaceLevel::OK);
        s.avail_important = 0;          // no answer from the OS: fall back to raw
        CHECK(PolicyEngine::level_for(s, p) == SpaceLevel::CRITICAL);
        // the absolute floors matter on a small volume (the fractions would be tiny)
        s.total = 10ull << 30; s.avail_raw = s.avail_important = 12ull << 30;
        CHECK(PolicyEngine::level_for(s, p) == SpaceLevel::LOW);        // 15% = 1.5 GiB, but the 20 GiB floor applies
        s.avail_raw = s.avail_important = 7ull << 30;
        CHECK(PolicyEngine::level_for(s, p) == SpaceLevel::CRITICAL);   // 5% = 0.5 GiB, but the 8 GiB floor applies
        FakeProbe probe;
        World w;
        auto pe = make_pe(w, probe, p);
        probe.avail = 33ull << 30;   // above the low threshold (30 GiB) but below the target (37.5 GiB): fine, nothing to do
        CHECK(pe->space().level == SpaceLevel::OK && pe->space().need_bytes == 0);
        probe.avail = 25ull << 30;
        SpaceStatus st = pe->space();
        CHECK(st.level == SpaceLevel::LOW && st.low_threshold == (30ull << 30) && st.need_bytes == static_cast<uint64_t>(30.0 * 1.25 * (1ull << 30)) - (25ull << 30));
        probe.avail = 100ull << 30;
        CHECK(pe->space().need_bytes == 0 && pe->space().level == SpaceLevel::OK);
    }

    {
        printf("== plan: only cold, big-enough, managed, not-excluded files, biggest-and-coldest first\n");
        World w;
        FakeProbe probe;
        std::string big = put(w, "big", 3 * MiB, 1), mid = put(w, "mid", 2 * MiB, 2), small = put(w, "small", 1000, 3), hot = put(w, "hot", 2 * MiB, 4);
        std::string outside = put(w, "outside", 2 * MiB, 5, "/elsewhere/"), git = put(w, "git", 2 * MiB, 6, "/testdata/.git/");
        std::string sibling = put(w, "sib", 2 * MiB, 7, "/testdata2/");   // "/testdata2/" must not match root "/testdata/"
        w.now_ += 40 * 86400;
        w.L->touch_access(hot, w.now_ - 86400);
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(100 * MiB, false);
        CHECK(p.entries.size() == 2 && at(p.entries, 0).file_id == big && at(p.entries, 1).file_id == mid);
        CHECK(!find_entry(p, small) && !find_entry(p, hot) && !find_entry(p, outside) && !find_entry(p, git) && !find_entry(p, sibling));
        CHECK(p.bytes_total == 5 * MiB && p.bytes_to_replicate == 5 * MiB && at(p.entries, 0).needs_replication);
        CHECK(p.skipped["too small"] == 1 && p.skipped["not cold enough"] == 1 && p.skipped["excluded path"] == 1 && p.skipped["outside the managed folders"] == 2);
        CHECK(p.digest == PolicyEngine::compute_digest(p) && p.digest.size() == 64);
        // the same plan again has the same content (and digest): the digest is about content, not luck
        TierPlan p2 = pe->plan(100 * MiB, false);
        CHECK(p2.digest == p.digest);
        // stops as soon as the need is met; says what it left out
        TierPlan few = pe->plan(MiB, false);
        CHECK(few.entries.size() == 1 && at(few.entries, 0).file_id == big && few.skipped["eligible, but not needed to reach the target"] == 1);
        // a shortfall is announced, not hidden
        bool shortfall = false;
        for (auto& wn : p.warnings) if (has(wn.c_str(), "would free only")) shortfall = true;
        CHECK(shortfall);
        // nothing needed: nothing chosen, and nothing even examined
        CHECK(pe->plan(0, false).entries.empty() && pe->plan(0, false).skipped.empty());
        // ranking: more idle beats less idle at equal size
        w.L->touch_access(big, w.now_ - 35 * 86400);   // big: idle 35d
        w.L->touch_access(mid, w.now_ - 31 * 86400);   // mid: idle 31d
        TierPlan r = pe->plan(100 * MiB, false);
        CHECK(at(r.entries, 0).file_id == big);        // 3 MiB * 35 > 2 MiB * 31
        TierPlan r2 = pe->plan(100 * MiB, false);
        CHECK(r.digest == r2.digest);
        {   // idle boundary: exactly the threshold counts as cold, one second less does not; the later of mtime/access wins
            std::string edge = put(w, "edge", 2 * MiB, 9);
            int64_t m = w.L->get_file(edge)->mtime;
            w.now_ = m + 30 * 86400;
            CHECK(find_entry(pe->plan(1000 * MiB, false), edge));
            w.now_ = m + 30 * 86400 - 1;
            CHECK(!find_entry(pe->plan(1000 * MiB, false), edge));
            w.now_ = m + 5 * 86400;
            w.L->touch_access(edge, 1);                                  // an ancient access time must not hide a recent write
            CHECK(!find_entry(pe->plan(1000 * MiB, false), edge));
            w.now_ += 40 * 86400;
            w.L->touch_access(edge, w.now_);                             // ... nor an old write hide a recent read
            CHECK(!find_entry(pe->plan(1000 * MiB, false), edge));
        }
        w.L->touch_access(big, w.now_ - 20 * 86400);   // not cold any more: only mid is left
        TierPlan flip = pe->plan(100 * MiB, false);
        CHECK(flip.entries.size() == 1 && at(flip.entries, 0).file_id == mid);
    }

    {
        printf("== ranking is size x idle days, not either alone\n");
        World w;
        FakeProbe probe;
        std::string a = put(w, "a", 2 * MiB, 1), b = put(w, "b", 3 * MiB, 2), c = put(w, "c", 8 * MiB, 3);
        w.now_ += 60 * 86400;
        w.L->touch_access(b, w.now_ - 35 * 86400);   // 3 * 35 = 105
        w.L->touch_access(c, w.now_ - 40 * 86400);   // 8 * 40 = 320;  a: 2 * 60 = 120
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(1000 * MiB, false);
        CHECK(p.entries.size() == 3 && at(p.entries, 0).file_id == c && at(p.entries, 1).file_id == a && at(p.entries, 2).file_id == b);
        // a file that was replicated already is not counted as needing a copy
        std::string r = w.ready("r", 2 * MiB, 7);
        w.now_ += 40 * 86400;
        TierPlan q = pe->plan(1000 * MiB, false);
        CHECK(find_entry(q, r) && !find_entry(q, r)->needs_replication && q.bytes_to_replicate == q.bytes_total - 2 * MiB);
    }

    {
        printf("== roots match whole path prefixes; bookkeeping is never touched; classification details\n");
        World w;
        FakeProbe probe;
        std::string in = put(w, "in", 2 * MiB, 1), sib = put(w, "sib", 2 * MiB, 2, "/testdata2/"), deep = put(w, "deep", 2 * MiB, 3, "/x/testdata/");
        std::string book = put(w, "book", 2 * MiB, 4, "/testdata/.tierfs/");
        w.now_ += 40 * 86400;
        TierPolicy pol = base_policy();
        pol.roots = {"/testdata"};      // given without the trailing slash
        pol.exclude = {};
        auto pe = make_pe(w, probe, pol);
        TierPlan p = pe->plan(1000 * MiB, false);
        CHECK(find_entry(p, in) && !find_entry(p, sib) && !find_entry(p, deep) && !find_entry(p, book));
        CHECK(find_entry(p, in)->root == "/testdata/");
        // the plan never includes a file that is mid-drop (state DROPPING, bytes still present)
        std::string mid = w.ready("mid", 2 * MiB, 5);
        bool candidate_mid_drop = true;
        w.E->on_step = [&](const char* step) {
            if (std::string(step) == "before_rename") candidate_mid_drop = find_entry(pe->plan(1000 * MiB, false), mid) != nullptr;
        };
        w.now_ += 0;
        auto pe2 = make_pe(w, probe, base_policy());
        DropOutcome o = w.E->drop(mid, w.L->create_consent("/testdata/", 3600, "t"), w.devs);
        CHECK(o.ok && !candidate_mid_drop);
        w.E->on_step = nullptr;
        // and one that is already offloaded is not a candidate
        CHECK(!find_entry(pe->plan(1000 * MiB, false), mid));
    }

    {
        printf("== a class-C device counts half: two of them cannot make weight 2.0 with one B... but B + C cannot either\n");
        World w("C");
        FakeProbe probe;
        std::string f = put(w, "x", 2 * MiB, 1);
        w.now_ += 40 * 86400;
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(100 * MiB, false);
        CHECK(p.entries.empty() && p.skipped["not enough trusted devices to ever hold enough copies"] == 1);
        (void)f;
    }

    {
        printf("== a file replicated to only one device is still a copy-first candidate\n");
        World w;
        FakeProbe probe;
        Bytes d = pattern(2 * MiB, 3);
        w.originals["one"] = d;
        spit(w.path("one"), d);
        std::string f = w.track("one");
        CHECK(w.R->replicate(*w.da, w.ida, f, w.path("one")).ok);
        w.now_ += 40 * 86400;
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(100 * MiB, false);
        CHECK(find_entry(p, f) && find_entry(p, f)->needs_replication && w.L->committed_weight(f, 1) < 2.0);
    }

    {
        printf("== plan warnings and structural limits\n");
        World w;
        FakeProbe probe;
        put(w, "a", 2 * MiB, 1);
        w.now_ += 40 * 86400;
        TierPolicy pol = base_policy();
        pol.max_files_per_plan = 1;
        std::string b = put(w, "b", 2 * MiB, 2);
        w.now_ += 0;
        auto pe = make_pe(w, probe, pol);
        CHECK(pe->plan(100 * MiB, false).entries.size() == 1);   // the cap holds
        w.L->set_meta("backup_acked", "0");
        probe.snaps = 2;
        TierPlan p = pe->plan(100 * MiB, false);
        bool snap = false, backup = false;
        for (auto& x : p.warnings) { if (has(x.c_str(), "snapshot")) snap = true; if (has(x.c_str(), "no backup")) backup = true; }
        CHECK(snap && backup);
        probe.avail = 3ull << 30;
        bool qwarn = false;
        for (auto& x : pe->plan(100 * MiB, false).warnings) if (has(x.c_str(), "keeps the quarantine period")) qwarn = true;
        CHECK(qwarn);
        bool qwarn2 = false;
        for (auto& x : pe->plan(100 * MiB, true).warnings) if (has(x.c_str(), "keeps the quarantine period")) qwarn2 = true;
        CHECK(!qwarn2);
    }
    {
        printf("== with one device the files can never reach weight 2.0: not even candidates\n");
        World w1;
        FakeProbe probe1;
        std::string fid = put(w1, "x", 2 * MiB, 3);
        w1.now_ += 40 * 86400;
        (void)fid;
        w1.L->retire_device(w1.idb);
        auto pe1 = make_pe(w1, probe1, base_policy());
        TierPlan q = pe1->plan(100 * MiB, false);
        CHECK(q.entries.empty() && q.skipped["not enough trusted devices to ever hold enough copies"] == 1);
        bool few = false;
        for (auto& x : q.warnings) if (has(x.c_str(), "fewer trusted devices")) few = true;
        CHECK(few);
    }

    {
        printf("== the approval handshake: exactly this plan, scoped, expiring\n");
        World w;
        FakeProbe probe;
        put(w, "a", 2 * MiB, 1);
        put(w, "b", 2 * MiB, 2);
        put(w, "c", 2 * MiB, 3, "/other/");
        w.now_ += 40 * 86400;
        TierPolicy pol = base_policy();
        pol.roots = {"/testdata/", "/other/"};
        auto pe = make_pe(w, probe, pol);
        TierPlan p = pe->plan(100 * MiB, false);
        std::string err;
        TierPlan forged = p;
        forged.entries[0].size += 1;
        CHECK(pe->approve(forged, &err).consent_by_root.empty() && has(err.c_str(), "altered"));
        for (int field = 0; field < 5; field++) {   // every field the digest covers
            TierPlan f = p;
            if (field == 0) f.entries[0].generation += 1;
            if (field == 1) f.free_now = !f.free_now;
            if (field == 2) f.entries[0].root += "zzz/";
            if (field == 3) f.entries[0].needs_replication = !f.entries[0].needs_replication;
            if (field == 4) f.entries[0].file_id += "x";
            err.clear();
            bool rejected = pe->approve(f, &err).consent_by_root.empty();
            CHECK(rejected && has(err.c_str(), "altered"));
        }
        TierPlan empty = pe->plan(0, false);
        CHECK(pe->approve(empty, &err).consent_by_root.empty() && has(err.c_str(), "nothing"));
        Approval a = pe->approve(p, &err);
        CHECK(a.plan_digest == p.digest && a.consent_by_root.size() == 2 && a.consent_by_root.count("/testdata/") && a.consent_by_root.count("/other/"));
        // each consent is scoped to its root and says what was approved
        {
            auto ack = w.L->consent_ack(a.consent_by_root["/testdata/"]);
            CHECK(ack && has(*ack, p.digest.substr(0, 16).c_str()) && has(*ack, "/testdata/") && has(*ack, "keep the quarantine period") && has(*ack, "2 files"));
            auto ack2 = w.L->consent_ack(a.consent_by_root["/other/"]);
            CHECK(ack2 && has(*ack2, "/other/") && has(*ack2, "1 files"));
        }
        CHECK(!a.consent_by_root["/testdata/"].empty() && a.consent_by_root["/testdata/"] != a.consent_by_root["/other/"]);
        // a consent is only good for its own root: crossing them over moves nothing
        {
            Approval crossed = a;
            std::swap(crossed.consent_by_root["/testdata/"], crossed.consent_by_root["/other/"]);
            ExecReport x = pe->execute(p, crossed, w.devs);
            CHECK(x.dropped == 0 && x.failed == 3 && exists(w.path("a")) && exists(w.path("b")) && exists(w.path("c")) && w.L->list_quarantine().empty());
        }
        // an execution with a different plan's approval is refused, and nothing happens
        put(w, "d", 2 * MiB, 4);
        TierPlan other = pe->plan(100 * MiB, false);
        CHECK(other.digest != p.digest);
        ExecReport rej = pe->execute(other, a, w.devs);
        CHECK(rej.rejected && has(rej.reject_reason.c_str(), "altered") && rej.dropped == 0);
        ExecReport rej2 = pe->execute(forged, a, w.devs);
        CHECK(rej2.rejected && rej2.dropped == 0);
        Approval mode = a;
        mode.free_now = true;
        CHECK(pe->execute(p, mode, w.devs).rejected);
        CHECK(w.L->open_intents().empty() && w.L->list_quarantine().empty() && exists(w.path("a")) && exists(w.path("b")));
    }

    {
        printf("== end to end, LOW: copy, move into quarantine, keep the period, then purge\n");
        World w;
        FakeProbe probe;
        probe.avail = 25ull << 30;
        std::string a = put(w, "a", 3 * MiB, 1), b = put(w, "b", 2 * MiB, 2);
        w.now_ += 40 * 86400;
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(4 * MiB, false);
        CHECK(p.entries.size() == 2 && p.bytes_to_replicate == 5 * MiB);
        std::string err;
        Approval ap = pe->approve(p, &err);
        CountGate gate;
        ExecReport r = pe->execute(p, ap, w.devs, &gate);
        CHECK(!r.rejected && r.replicated == 2 && r.dropped == 2 && r.purged == 0 && r.failed == 0 && r.bytes_dropped == 5 * MiB);
        CHECK(r.target_met && gate.freezes == 2 && gate.unfreezes == 2);
        CHECK(r.avail_before == (25ull << 30) && r.avail_after == (25ull << 30));
        CHECK(!exists(w.path("a")) && !exists(w.path("b")));
        CHECK(held_matches(w, "a") && held_matches(w, "b"));                  // held in quarantine, byte for byte
        CHECK(w.L->list_quarantine(QuarantineState::HELD).size() == 2);
        CHECK(w.remote_intact(a, *w.da, "a") && w.remote_intact(a, *w.db, "a") && w.remote_intact(b, *w.da, "b"));
        CHECK(w.L->get_file(a)->state == FileState::OFFLOADED);
        // before the period is over nothing is purged...
        w.now_ += 3 * 86400;
        CHECK(pe->purge_due(w.devs) == 0 && held_matches(w, "a"));
        // ... after it, with fresh audits, it is
        w.now_ += 5 * 86400;
        CHECK(pe->purge_due(w.devs) == 2);
        CHECK(w.L->list_quarantine(QuarantineState::PURGED).size() == 2 && !w.bytes_somewhere("a") && !w.bytes_somewhere("b"));
        CHECK(w.remote_intact(a, *w.da, "a") && w.remote_intact(b, *w.db, "b"));   // the devices still hold everything
        CHECK(w.L->fsck().empty());
    }

    {
        printf("== end to end, CRITICAL: free now, but only after the same checks\n");
        World w;
        FakeProbe probe;
        probe.avail = 3ull << 30;
        std::string a = put(w, "a", 3 * MiB, 1);
        w.now_ += 40 * 86400;
        auto pe = make_pe(w, probe, base_policy());
        SpaceStatus st = pe->space();
        CHECK(st.level == SpaceLevel::CRITICAL);
        TierPlan p = pe->plan(2 * MiB, true);
        Approval ap = pe->approve(p, nullptr);
        ExecReport r = pe->execute(p, ap, w.devs);
        CHECK(r.dropped == 1 && r.purged == 1 && r.bytes_purged == 3 * MiB && !w.bytes_somewhere("a"));
        CHECK(w.L->list_quarantine(QuarantineState::PURGED).size() == 1 && w.remote_intact(a, *w.da, "a") && w.remote_intact(a, *w.db, "a"));
        // a rotten replica blocks even the emergency path: the bytes stay in quarantine
        std::string b = put(w, "b", 3 * MiB, 2);
        w.now_ += 0;
        w.L->touch_access(b, 1);
        TierPlan p2 = pe->plan(2 * MiB, true);
        Approval ap2 = pe->approve(p2, nullptr);
        // replicate first (the executor does), then rot one device between the copy and the audits
        ExecReport pre = pe->replicate_step(w.devs, 100 * MiB).files == 1 ? ExecReport{} : ExecReport{};
        (void)pre;
        w.rot(b, 1);
        ExecReport r2 = pe->execute(p2, ap2, w.devs);
        CHECK(r2.purged == 0 && w.data_safe("b"));
        CHECK(w.L->list_quarantine(QuarantineState::PURGED).size() == 1);
    }

    {
        printf("== free-now: a copy that goes bad right after the move stops the delete, and the report says so\n");
        World w;
        FakeProbe probe;
        probe.avail = 3ull << 30;
        std::string a = w.ready("a", 3 * MiB, 1);
        w.now_ += 40 * 86400;
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(2 * MiB, true);
        Approval ap = pe->approve(p, nullptr);
        struct RotGate : FileGate {
            std::function<void()> on_unfreeze;
            bool freeze(const FileRec&, std::string*) override { return true; }
            void unfreeze(const FileRec&) override { if (on_unfreeze) on_unfreeze(); }
        } gate;
        gate.on_unfreeze = [&] { w.rot(a, 1); };   // the drop is done; now one replica rots before the purge audits
        ExecReport r = pe->execute(p, ap, w.devs, &gate);
        CHECK(r.dropped == 1 && r.purged == 0 && r.bytes_purged == 0 && !r.target_met && w.data_safe("a"));
        CHECK(w.L->list_quarantine(QuarantineState::HELD).size() == 1 && !r.notes.empty());
    }

    {
        printf("== files that changed since the plan, and consents that ran out\n");
        World w;
        FakeProbe probe;
        std::string a = put(w, "a", 3 * MiB, 1), b = put(w, "b", 2 * MiB, 2), c = put(w, "c", 2 * MiB, 3);
        w.now_ += 40 * 86400;
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(100 * MiB, false);
        Approval ap = pe->approve(p, nullptr);
        // a was modified; b was used; c is fine
        Bytes changed = pattern(3 * MiB, 99);
        spit(w.path("a"), changed);
        struct stat st;
        stat(w.path("a").c_str(), &st);
        w.L->note_local_modified(a, static_cast<uint64_t>(st.st_size), st.st_mtimespec.tv_sec);
        w.L->touch_access(b, w.now_);
        ExecReport r = pe->execute(p, ap, w.devs);
        CHECK(r.dropped == 1 && r.skipped == 2 && !exists(w.path("c")) && exists(w.path("a")) && exists(w.path("b")));
        CHECK(slurp(w.path("a")) == changed && w.L->get_file(a)->state != FileState::OFFLOADED);
    }
    {
        printf("== an approval left lying around dies after its time\n");
        World w2;
        FakeProbe probe2;
        std::string d = put(w2, "d", 2 * MiB, 4);
        w2.now_ += 40 * 86400;
        auto pe2 = make_pe(w2, probe2, base_policy());
        TierPlan p2 = pe2->plan(100 * MiB, false);
        Approval ap2 = pe2->approve(p2, nullptr);
        w2.now_ += 7200;
        w2.L->touch_access(d, 1);   // (not used: still cold)
        ExecReport r2 = pe2->execute(p2, ap2, w2.devs);
        CHECK(r2.dropped == 0 && r2.failed == 1 && exists(w2.path("d")) && w2.L->list_quarantine().empty());
        // nothing was lost either way: the copies made on the way are fine
        CHECK(w2.L->open_intents().empty() && w2.L->fsck().empty());
    }
    {
        printf("== a root the approval does not cover is skipped, not borrowed from another\n");
        World w3;
        FakeProbe probe3;
        put(w3, "e", 2 * MiB, 5);
        w3.now_ += 40 * 86400;
        auto pe3 = make_pe(w3, probe3, base_policy());
        TierPlan p3 = pe3->plan(100 * MiB, false);
        Approval ap3 = pe3->approve(p3, nullptr);
        ap3.consent_by_root.clear();
        ExecReport r3 = pe3->execute(p3, ap3, w3.devs);
        CHECK(r3.dropped == 0 && r3.skipped == 1 && exists(w3.path("e")));
    }

    {
        printf("== a gate that refuses (a writer is active) leaves the file alone\n");
        World w;
        FakeProbe probe;
        put(w, "a", 2 * MiB, 1);
        w.now_ += 40 * 86400;
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(100 * MiB, false);
        Approval ap = pe->approve(p, nullptr);
        CountGate gate;
        gate.allow = false;
        ExecReport r = pe->execute(p, ap, w.devs, &gate);
        CHECK(r.dropped == 0 && r.failed == 1 && exists(w.path("a")) && w.L->list_quarantine().empty() && gate.freezes == 0);
    }

    {
        printf("== background replication: coldest first, within a byte budget, never touching hot files\n");
        World w;
        FakeProbe probe;
        std::string a = put(w, "a", 2 * MiB, 1), b = put(w, "b", 2 * MiB, 2), c = put(w, "c", 2 * MiB, 3), x = put(w, "x", 2 * MiB, 5);
        w.now_ += 10 * 86400;
        w.L->touch_access(b, w.now_ - 9 * 86400);
        w.L->touch_access(x, w.now_ - 8 * 86400);
        w.L->touch_access(c, w.now_ - 2 * 86400);   // too recent to copy yet
        auto pe = make_pe(w, probe, base_policy());
        ReplicationReport r0 = pe->replicate_step(w.devs, 1);   // room for one file: it must be the coldest
        CHECK(r0.files == 1 && w.L->get_file(a)->state == FileState::REPLICATED && w.L->get_file(b)->state == FileState::LOCAL);
        ReplicationReport r = pe->replicate_step(w.devs, 3 * MiB);
        CHECK(r.files == 2 && r.bytes == 4 * MiB);   // the budget is checked before each file, so it can be overshot by one file, not more
        CHECK(w.L->get_file(b)->state == FileState::REPLICATED && w.L->committed_weight(b, 1) >= 2.0 && w.L->get_file(x)->state == FileState::REPLICATED);
        CHECK(w.L->get_file(c)->state == FileState::LOCAL);
        ReplicationReport r2 = pe->replicate_step(w.devs, 100 * MiB);
        CHECK(r2.files == 0);                         // nothing left that is old enough and not already copied
        w.now_ += 10 * 86400;
        ReplicationReport r3 = pe->replicate_step(w.devs, 100 * MiB);
        CHECK(r3.files == 1 && w.L->get_file(c)->state == FileState::REPLICATED);
        CHECK(exists(w.path("a")) && exists(w.path("b")) && exists(w.path("c")));   // copying never removes anything
        // a device that is down: the file is left as it was, and the failure is counted
        w.sb.stop();
        std::string d = put(w, "d", 2 * MiB, 4);
        w.now_ += 40 * 86400;
        ReplicationReport r4 = pe->replicate_step(w.devs, 100 * MiB);
        CHECK(r4.files == 0 && r4.failed >= 1 && exists(w.path("d")) && w.L->get_file(d)->state != FileState::OFFLOADED);
    }

    {
        printf("== tick: reconcile, replicate, purge, and prompt at a sane rate\n");
        World w;
        FakeProbe probe;
        CountNotifier n;
        put(w, "a", 2 * MiB, 1);
        w.now_ += 40 * 86400;
        TierPolicy pol = base_policy();
        auto pe = make_pe(w, probe, pol, &n);
        probe.avail = 100ull << 30;
        TickReport t0 = pe->tick(w.devs);
        CHECK(t0.space.level == SpaceLevel::OK && !t0.prompted && n.calls == 0 && t0.reconciled);
        CHECK(t0.replication.files == 1);                                    // quiet background copying even when space is fine
        TickReport t0b = pe->tick(w.devs);
        CHECK(!t0b.reconciled);                                              // not again within the interval
        probe.avail = 25ull << 30;
        TickReport t1 = pe->tick(w.devs);
        CHECK(t1.space.level == SpaceLevel::LOW && t1.prompted && n.calls == 1 && t1.plan.entries.size() == 1);
        CHECK(!t1.plan.free_now);                                            // LOW keeps the quarantine period
        int64_t t_prompt = w.now_;
        w.now_ += 600;
        CHECK(!pe->tick(w.devs).prompted && n.calls == 1);                   // the same shortage is not announced again
        w.now_ = t_prompt + 6 * 3600 - 1;
        CHECK(!pe->tick(w.devs).prompted && n.calls == 1);
        w.now_ = t_prompt + 6 * 3600;
        CHECK(pe->tick(w.devs).prompted && n.calls == 2);                    // ... until exactly the interval has passed
        probe.avail = 3ull << 30;
        w.now_ += 60;
        TickReport tc = pe->tick(w.devs);
        CHECK(tc.prompted && n.calls == 3 && n.last == SpaceLevel::CRITICAL && tc.plan.free_now);   // worse: immediately, and in free-now mode
        // better again (but still short): the interval applies
        probe.avail = 25ull << 30;
        w.now_ += 7 * 3600;
        CHECK(pe->tick(w.devs).prompted && n.calls == 4 && n.last == SpaceLevel::LOW);
        probe.avail = 3ull << 30;
        w.now_ += 60;
        CHECK(pe->tick(w.devs).prompted && n.calls == 5);
        // restart: the rate limit lives in the ledger, not in memory
        w.close_ledger();
        w.open_ledger();
        auto pe2 = make_pe(w, probe, pol, &n);
        w.now_ += 60;
        CHECK(!pe2->tick(w.devs).prompted && n.calls == 5);
        // back to normal and short again: prompts at once
        probe.avail = 100ull << 30;
        pe2->tick(w.devs);
        probe.avail = 25ull << 30;
        w.now_ += 60;
        CHECK(pe2->tick(w.devs).prompted && n.calls == 6);
        // without a notifier the tick still works and says nothing
        auto quiet = make_pe(w, probe, pol, nullptr);
        probe.avail = 3ull << 30;
        w.now_ += 7 * 3600;
        TickReport tq = quiet->tick(w.devs);
        CHECK(!tq.prompted && tq.space.level == SpaceLevel::CRITICAL && n.calls == 6);
        // tick never moves anything by itself
        CHECK(exists(w.path("a")) && w.L->list_quarantine().empty() && w.L->open_intents().empty());
    }

    {
        printf("== tick purges what is due (when allowed) and never before\n");
        World w;
        FakeProbe probe;
        std::string a = put(w, "a", 2 * MiB, 1);
        w.now_ += 40 * 86400;
        TierPolicy pol = base_policy();
        auto pe = make_pe(w, probe, pol);
        TierPlan p = pe->plan(100 * MiB, false);
        pe->execute(p, pe->approve(p, nullptr), w.devs);
        CHECK(w.L->list_quarantine(QuarantineState::HELD).size() == 1);
        w.now_ += 8 * 86400;
        TierPolicy off = base_policy();
        off.auto_purge = false;
        auto pe_off = make_pe(w, probe, off);
        TickReport t = pe_off->tick(w.devs);
        CHECK(t.purged == 0 && w.L->list_quarantine(QuarantineState::HELD).size() == 1);
        TickReport t2 = pe->tick(w.devs);
        CHECK(t2.purged == 1 && w.L->list_quarantine(QuarantineState::PURGED).size() == 1);
    }

    {
        printf("== execute re-checks the world at the moment it acts\n");
        {   // already-replicated files are not copied again; a file that is already gone from its path is skipped, not failed
            World w;
            FakeProbe probe;
            std::string a = w.ready("a", 2 * MiB, 1), b = w.ready("b", 2 * MiB, 2);
            w.now_ += 40 * 86400;
            auto pe = make_pe(w, probe, base_policy());
            TierPlan p = pe->plan(100 * MiB, false);
            Approval ap = pe->approve(p, nullptr);
            CHECK(w.E->drop(b, w.L->create_consent("/testdata/", 3600, "x"), w.devs).ok);   // someone else moved b meanwhile
            ExecReport r = pe->execute(p, ap, w.devs);
            CHECK(r.dropped == 1 && r.replicated == 0 && r.skipped == 1 && r.failed == 0);
            CHECK(!exists(w.path("a")) && w.L->get_file(a)->state == FileState::OFFLOADED);
        }
        {   // the file is in the middle of being dropped (by someone else) when our execute runs: leave it alone
            World w;
            FakeProbe probe;
            std::string a = w.ready("a", 2 * MiB, 1);
            w.now_ += 40 * 86400;
            auto pe = make_pe(w, probe, base_policy());
            TierPlan p = pe->plan(100 * MiB, false);
            Approval ap = pe->approve(p, nullptr);
            ExecReport inner;
            w.E->on_step = [&](const char* step) { if (std::string(step) == "before_rename") inner = pe->execute(p, ap, w.devs); };
            CHECK(w.E->drop(a, w.L->create_consent("/testdata/", 3600, "t"), w.devs).ok);
            w.E->on_step = nullptr;
            CHECK(inner.dropped == 0 && inner.skipped == 1 && inner.failed == 0 && has(inner.notes.empty() ? "" : inner.notes[0].c_str(), "DROPPING"));
        }
        {   // the user removed the folder from the managed list after the plan was made
            World w;
            FakeProbe probe;
            put(w, "a", 2 * MiB, 1);
            w.now_ += 40 * 86400;
            auto pe = make_pe(w, probe, base_policy());
            TierPlan p = pe->plan(100 * MiB, false);
            Approval ap = pe->approve(p, nullptr);
            TierPolicy narrowed = base_policy();
            narrowed.roots = {"/somewhere-else/"};
            auto pe2 = make_pe(w, probe, narrowed);
            ExecReport r = pe2->execute(p, ap, w.devs);
            CHECK(r.dropped == 0 && r.skipped == 1 && exists(w.path("a")) && w.L->list_quarantine().empty());
            TierPolicy excluded = base_policy();
            excluded.exclude = {"/a"};
            ExecReport r2 = make_pe(w, probe, excluded)->execute(p, ap, w.devs);
            CHECK(r2.dropped == 0 && r2.skipped == 1 && exists(w.path("a")));
        }
        {   // a device retired after the plan is not used, and the file stays where it is
            World w;
            FakeProbe probe;
            std::string a = put(w, "a", 2 * MiB, 1);
            w.now_ += 40 * 86400;
            auto pe = make_pe(w, probe, base_policy());
            TierPlan p = pe->plan(100 * MiB, false);
            Approval ap = pe->approve(p, nullptr);
            w.L->retire_device(w.idb);
            ExecReport r = pe->execute(p, ap, w.devs);
            bool touched_b = false;
            for (auto& rep : w.L->get_replicas(a, 1)) if (rep.device_id == w.idb) touched_b = true;
            bool tried_b = false;
            for (auto& n : r.notes) if (has(n, "replicating to")) tried_b = true;   // a retired device is passed over silently
            CHECK(r.dropped == 0 && r.failed == 1 && !touched_b && !tried_b && exists(w.path("a")));
        }
        {   // edited behind the ledger's back (same size or not): the approved file is not what is on disk
            World w;
            FakeProbe probe;
            std::string a = put(w, "a", 2 * MiB, 1);
            w.now_ += 40 * 86400;
            auto pe = make_pe(w, probe, base_policy());
            TierPlan p = pe->plan(100 * MiB, false);
            Approval ap = pe->approve(p, nullptr);
            spit(w.path("a"), pattern(2 * MiB + 17, 77));
            ExecReport r = pe->execute(p, ap, w.devs);
            CHECK(r.dropped == 0 && r.skipped == 1 && exists(w.path("a")) && w.L->list_quarantine().empty() && w.L->get_file(a)->state == FileState::LOCAL);
        }
    }

    {
        printf("== purge_due: exactly at the end of the period, and never when the copies are no longer good\n");
        World w;
        FakeProbe probe;
        std::string a = put(w, "a", 2 * MiB, 1), b = put(w, "b", 2 * MiB, 2);
        w.now_ += 40 * 86400;
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(100 * MiB, false);
        CHECK(pe->execute(p, pe->approve(p, nullptr), w.devs).dropped == 2);
        int64_t held = w.now_;
        w.now_ = held + 7 * 86400 - 1;
        CHECK(pe->purge_due(w.devs) == 0);
        w.now_ = held + 7 * 86400;
        w.rot(b, 1);                                        // one device's copy of b has rotted: b must not be purged
        CHECK(pe->purge_due(w.devs) == 1);                  // only a
        CHECK(w.L->list_quarantine(QuarantineState::PURGED).size() == 1 && w.L->list_quarantine(QuarantineState::HELD).size() == 1);
        CHECK(held_matches(w, "b"));
    }

    {
        printf("== text for people\n");
        World w;
        FakeProbe probe;
        put(w, "a", 2 * MiB, 1);
        w.now_ += 40 * 86400;
        auto pe = make_pe(w, probe, base_policy());
        TierPlan p = pe->plan(MiB, false);
        std::string text = format_plan(p);
        CHECK(has(text, "/testdata/a") && has(text, "[copy first]") && has(text, p.digest.substr(0, 16).c_str()) && has(text, "quarantine"));
        std::string note = format_notification(pe->space(), p);
        CHECK(has(note, "1 cold file") && has(note, "approve"));
        TierPlan none = pe->plan(0, false);
        CHECK(has(format_notification(pe->space(), none), "No cold files"));
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
