// Tests of the scanner: reconciling the ledger with an origin folder that changed behind the overlay's back, and the rule that
// it must never forget files because the folder was merely unavailable. Real files, real devices, the real drop engine.
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <utime.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <atomic>
#include <thread>

#include "../core/dropengine.hpp"
#include "../core/overlay.hpp"
#include "../core/scanner.hpp"

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
#define CHECK_QUIET(cond) do { if (!(cond)) { printf("FAIL  line %d: %s\n", __LINE__, #cond); failures++; } } while (0)
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
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-scantest-XXXXXX";
    std::vector<char> buf(t.begin(), t.end());
    buf.push_back(0);
    return mkdtemp(buf.data());
}
static uint16_t port_base() { return getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9561; }
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
    std::string faults;   // TIERFS_DEVICE_FAULTS for the next start
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
        if (!faults.empty()) setenv("TIERFS_DEVICE_FAULTS", faults.c_str(), 1);
        int rc = posix_spawn(&pid, path, &fa, nullptr, av.data(), environ);
        unsetenv("TIERFS_DEVICE_FAULTS");
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
static int g_lab = 0;

static std::vector<std::string> walk(const std::string& root) {   // every regular file or symlink under root, relative, sorted
    std::vector<std::string> out;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (it->is_symlink(ec) || it->is_regular_file(ec)) out.push_back(fs::relative(it->path(), root).string());
    }
    std::sort(out.begin(), out.end());
    return out;
}
static bool any_partial(const std::string& root) {
    for (auto& f : walk(root)) if (f.find(".tierfs-partial-") != std::string::npos) return true;
    return false;
}

struct Item {
    std::string name, logical, fid;
    Bytes bytes, bytes_v1;
    uint32_t mode = 0644;
    int64_t mtime = 0;
    std::vector<std::string> chunks, chunks_v1;   // chunk ids of the newest / first version
    bool updated = false;
};

struct Lab {
    std::string root = tmpdir();
    crypto::SecretKey master = crypto::SecretKey::random();
    std::unique_ptr<crypto::Keys> keys = std::make_unique<crypto::Keys>(master);
    std::unique_ptr<Ledger> L;
    std::unique_ptr<Replicator> R;
    std::unique_ptr<DropEngine> E;
    Server sa{PA}, sb{PB};
    std::unique_ptr<DeviceClient> da, db;
    std::string ida, idb, consent, volume;
    int64_t now_ = static_cast<int64_t>(time(nullptr));
    DeviceMap devs;
    std::map<std::string, Item> items;
    int n_;

    Lab() {
        n_ = ++g_lab;
        fs::create_directories(root + "/files");
        sa.start(root + "/devA" + std::to_string(n_));
        sb.start(root + "/devB" + std::to_string(n_));
        da = std::make_unique<DeviceClient>("127.0.0.1", PA, 5000);
        db = std::make_unique<DeviceClient>("127.0.0.1", PB, 5000);
        open_ledger();
        L->set_meta("recovery_acked", "1");
        L->set_meta("test_prefix", "/Users/me/");
        L->ensure_reserve(1 << 20);
        consent = L->create_consent("/Users/me/", 30 * 86400, "test");
        R->attach(*da, "device-a", "B", &ida);
        R->attach(*db, "device-b", "B", &idb);
        devs = {{ida, da.get()}, {idb, db.get()}};
        volume = L->volume_id();
    }
    ~Lab() { E.reset(); R.reset(); L.reset(); da.reset(); db.reset(); sa.stop(); sb.stop(); fs::remove_all(root); }

    void open_ledger() {
        std::string err;
        L = Ledger::open(root + "/ledger", &err);
        if (!L) return;
        L->set_clock([this] { return now_; });
        R = std::make_unique<Replicator>(*L, *keys, L->volume_id());
        std::string files = root + "/files";
        E = std::make_unique<DropEngine>(*L, *R, *keys, L->volume_id(), DropPolicy{}, files + "/.tierfs/quarantine",
                                         [files](const FileRec& f) { return files + "/" + f.path.substr(std::string("/Users/me/proj/").size()); });
    }
    void close_ledger() { E.reset(); R.reset(); L.reset(); }
    std::string path(const std::string& name) const { return root + "/files/" + name; }
    std::string phrase() const { return crypto::encode_recovery(master); }
    std::string devdir(int dev) const { return root + (dev == 0 ? "/devA" : "/devB") + std::to_string(n_); }

    // `name` may contain subdirectories ("sub/deep/x.bin"); they are created in the origin.
    Item& make(const std::string& name, size_t size, uint8_t seed, uint32_t mode = 0644, int64_t mtime = 1600000000, const std::string& dir = "/Users/me/proj/") {
        Item it;
        it.name = name;
        it.logical = dir + name;
        fs::create_directories(fs::path(path(name)).parent_path());
        it.bytes = pattern(size, seed);
        it.mode = mode;
        it.mtime = mtime;
        spit(path(name), it.bytes);
        chmod(path(name).c_str(), mode);
        if (name == "a.bin") setxattr(path(name).c_str(), "com.example.note", "kept", 4, 0, 0);   // extended attributes travel in the manifest
        struct timeval tv[2] = {{mtime, 0}, {mtime, 0}};
        utimes(path(name).c_str(), tv);
        struct stat st;
        stat(path(name).c_str(), &st);
        it.fid = L->track_file(it.logical, size, st.st_mtimespec.tv_sec, st.st_mode & 0777);
        bool a = R->replicate(*da, ida, it.fid, path(name)).ok, b = R->replicate(*db, idb, it.fid, path(name)).ok;
        if (!a || !b) printf("      (setup: replication of %s failed)\n", name.c_str());
        for (auto& c : L->get_chunks(it.fid, 1)) it.chunks.push_back(c.chunk_id);
        it.chunks_v1 = it.chunks;
        it.bytes_v1 = it.bytes;
        return items[name] = it;
    }
    // A second version with entirely different bytes.
    void update(const std::string& name, size_t size, uint8_t seed) {
        Item& it = items[name];
        it.bytes = pattern(size, seed);
        spit(path(name), it.bytes);
        struct stat st;
        stat(path(name).c_str(), &st);
        L->note_local_modified(it.fid, size, st.st_mtimespec.tv_sec);
        bool a = R->replicate(*da, ida, it.fid, path(name)).ok, b = R->replicate(*db, idb, it.fid, path(name)).ok;
        if (!a || !b) printf("      (setup: second replication of %s failed)\n", name.c_str());
        int64_t v = L->get_file(it.fid)->current_version;
        it.chunks.clear();
        for (auto& c : L->get_chunks(it.fid, v)) it.chunks.push_back(c.chunk_id);
        it.mtime = st.st_mtimespec.tv_sec;
        it.updated = true;
    }
    bool drop(const std::string& name, FileGate* gate = nullptr) { return E->drop(items[name].fid, consent, devs, gate).ok; }
    bool replicate(const std::string& name) {
        bool a = R->replicate(*da, ida, items[name].fid, path(name)).ok, b = R->replicate(*db, idb, items[name].fid, path(name)).ok;
        return a && b;
    }
    // The Mac is gone: no ledger, no files, no quarantine. The devices and the phrase are all that is left.
    void destroy_mac() {
        close_ledger();
        fs::remove_all(root + "/ledger");
        fs::remove_all(root + "/files");
    }
    std::string blob(int dev, const std::string& cid) const { return devdir(dev) + "/chunks/" + cid.substr(0, 2) + "/" + cid + ".blob"; }
    void damage(int dev, const std::string& cid) {
        int fd = ::open(blob(dev, cid).c_str(), O_RDWR);
        uint8_t b = 0;
        if (fd >= 0) { pread(fd, &b, 1, 100); b ^= 0x40; pwrite(fd, &b, 1, 100); close(fd); }
    }
    void remove_blob(int dev, const std::string& cid) { unlink(blob(dev, cid).c_str()); }
};


static DeviceMap devmap(Lab& w, int = 0) { return {{w.ida, w.da.get()}, {w.idb, w.db.get()}}; }
static OverlayConfig cfg_for(Lab& w, int64_t wait_ms = 30000) {
    OverlayConfig c;
    c.origin_dir = w.root + "/files";
    c.logical_prefix = "/Users/me/proj/";
    c.write_wait_ms = wait_ms;
    return c;
}
static bool spawn_hydrate_crash(const Lab& w, const std::string& path, const char* point) {
    std::vector<std::string> e;
    for (char** x = environ; *x; x++) e.push_back(*x);
    e.push_back(std::string("TIERFS_CRASH_AT=") + point);
    e.push_back("TIERFS_TEST_MASTER=" + crypto::to_hex(w.master.data(), 32));
    std::vector<char*> envp;
    for (auto& x : e) envp.push_back(const_cast<char*>(x.c_str()));
    envp.push_back(nullptr);
    std::vector<std::string> a = {"overlay_helper", "hydrate", w.root + "/ledger", w.root + "/files", std::to_string(PA), w.ida, std::to_string(PB), w.idb, path};
    std::vector<char*> av;
    for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
    av.push_back(nullptr);
    const char* h = getenv("TIERFS_OVERLAY_HELPER") ? getenv("TIERFS_OVERLAY_HELPER") : "./build/overlay_helper";
    pid_t pid;
    if (posix_spawn(&pid, h, nullptr, nullptr, av.data(), envp.data()) != 0) return false;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 137;
}
static bool spawn_drop_crash(const Lab& w, const std::string& fid, const char* point) {
    std::vector<std::string> e;
    for (char** x = environ; *x; x++) e.push_back(*x);
    e.push_back(std::string("TIERFS_CRASH_AT=") + point);
    e.push_back("TIERFS_TEST_MASTER=" + crypto::to_hex(w.master.data(), 32));
    e.push_back("TIERFS_FAKE_NOW=" + std::to_string(w.now_));
    std::vector<char*> envp;
    for (auto& x : e) envp.push_back(const_cast<char*>(x.c_str()));
    envp.push_back(nullptr);
    std::vector<std::string> a = {"drop_helper", "drop", w.root + "/ledger", w.root + "/files", w.root + "/files/.tierfs/quarantine", std::to_string(PA), w.ida,
                                  std::to_string(PB), w.idb, w.consent, fid};
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
static size_t open_fds() {
    size_t n = 0;
    std::error_code ec;
    for (auto& e : fs::directory_iterator("/dev/fd", ec)) { (void)e; n++; }
    return n;
}
// Reads a whole file through a handle.
static Bytes read_handle_all(Overlay& ov, uint64_t fh, size_t size) {
    Bytes out(size);
    int64_t n = ov.read_fh(fh, 0, size, out.data());
    if (n < 0) return Bytes{};
    out.resize(static_cast<size_t>(n));
    return out;
}
static Bytes read_path_all(Overlay& ov, const std::string& path, size_t size) {
    Bytes out(size + 1);
    int64_t n = ov.read(path, 0, size + 1, out.data());
    if (n < 0) return Bytes{};
    out.resize(static_cast<size_t>(n));
    return out;
}
static bool write_all_fh(Overlay& ov, uint64_t fh, uint64_t off, const Bytes& b) { return ov.write_fh(fh, off, b.data(), b.size()) == static_cast<int64_t>(b.size()); }



static bool listed(Overlay& ov, const std::string& dir, const std::string& name) {
    std::vector<OvEntry> es;
    if (ov.readdir(dir, &es) != 0) return false;
    for (auto& e : es) if (e.name == name) return true;
    return false;
}
static size_t count_state(Ledger& L, FileState s) { return L.list_files(s).size(); }

int main() {
    signal(SIGPIPE, SIG_IGN);

    {
        printf("== a folder nobody has tracked yet: regular files are tracked once, links and the bookkeeping directory never\n");
        Lab w;
        fs::create_directories(w.root + "/files/sub/deep");
        fs::create_directories(w.root + "/files/.tierfs/quarantine/x");
        spit(w.path("a.txt"), pattern(100, 1));
        spit(w.path("sub/b.bin"), pattern(2 * MiB, 2));
        spit(w.path("sub/deep/c.bin"), pattern(1, 3));
        spit(w.path("empty"), Bytes{});
        spit(w.root + "/files/.tierfs/quarantine/x/object", pattern(10, 4));
        chmod(w.path("sub/b.bin").c_str(), 0640);
        struct timeval tv[2] = {{1400000000, 0}, {1400000000, 0}};
        utimes(w.path("a.txt").c_str(), tv);
        symlink("a.txt", (w.root + "/files/lnk").c_str());
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        ScanReport r = sc.scan();
        CHECK(!r.aborted && r.files_seen == 4 && r.tracked_new == 4 && r.problems.empty() && r.retired_vanished == 0);
        auto a = w.L->get_file_by_path("/Users/me/proj/a.txt");
        auto b = w.L->get_file_by_path("/Users/me/proj/sub/b.bin");
        CHECK(a && a->size == 100 && a->mtime == 1400000000 && a->state == FileState::LOCAL && a->local_present);
        CHECK(b && b->size == 2 * MiB && b->mode == 0640 && w.L->get_file_by_path("/Users/me/proj/empty")->size == 0 && w.L->get_file_by_path("/Users/me/proj/sub/deep/c.bin"));
        CHECK(!w.L->get_file_by_path("/Users/me/proj/lnk") && w.L->list_files().size() == 4 && w.L->fsck().empty());
        ScanReport again = sc.scan();
        CHECK(again.tracked_new == 0 && again.marked_modified == 0 && again.unchanged == 4 && again.actions.empty());
        ScanOptions off;
        off.track_new = false;
        spit(w.path("later.txt"), pattern(5, 5));
        CHECK(sc.scan(off).tracked_new == 0 && !w.L->get_file_by_path("/Users/me/proj/later.txt") && sc.scan().tracked_new == 1);
    }

    {
        printf("== changes made behind our back: edited, touched, chmod-ed\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 10, 1, 0644, 1500000000);
        Item& b = w.make("b.bin", MiB + 20, 2, 0644, 1500000000);
        Item& c = w.make("c.bin", MiB + 30, 3, 0644, 1500000000);
        Item& d = w.make("d.bin", MiB + 40, 4, 0644, 1500000000);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        ScanReport quiet = sc.scan();
        CHECK(quiet.unchanged == 4 && quiet.marked_modified == 0 && quiet.attrs_updated == 0 && w.L->get_file(a.fid)->state == FileState::REPLICATED);
        spit(w.path("a.bin"), pattern(MiB + 99, 9));                                  // edited: size and time change
        struct timeval later[2] = {{1500000500, 0}, {1500000500, 0}};
        utimes(w.path("b.bin").c_str(), later);                                       // only touched
        chmod(w.path("c.bin").c_str(), 0600);                                         // only chmod-ed
        spit(w.path("d.bin"), pattern(MiB + 40, 8));                                  // same size, new content...
        utimes(w.path("d.bin").c_str(), later);                                       // ...and a new mtime (the only way anyone can tell)
        chmod(w.path("d.bin").c_str(), 0640);
        auto gen = [&](const std::string& id) { return w.L->get_file(id)->generation; };
        int64_t ga = gen(a.fid), gb = gen(b.fid), gc = gen(c.fid), gd = gen(d.fid);
        ScanReport r = sc.scan();
        CHECK(r.marked_modified == 3 && r.attrs_updated == 1 && r.unchanged == 0 && r.problems.empty());
        for (auto* id : {&a.fid, &b.fid, &c.fid, &d.fid}) CHECK(w.L->get_file(*id)->state == FileState::LOCAL);   // none of them is "replicated" any more
        CHECK(gen(a.fid) > ga && gen(b.fid) > gb && gen(c.fid) > gc && gen(d.fid) > gd);
        CHECK(w.L->get_file(a.fid)->size == MiB + 99 && w.L->get_file(b.fid)->mtime == 1500000500 && w.L->get_file(c.fid)->mode == 0600 && w.L->get_file(d.fid)->mode == 0640 && w.L->get_file(d.fid)->mtime == 1500000500);
        CHECK(!w.E->drop(a.fid, w.consent, w.devs).ok && exists(w.path("a.bin")));      // the old replication can never justify a drop now
        ScanReport settled = sc.scan();
        CHECK(settled.marked_modified == 0 && settled.attrs_updated == 0 && settled.unchanged == 4);
    }

    {
        printf("== files that vanished: forgotten (not erased from the devices), unless it looks like the folder itself is gone\n");
        Lab w;
        for (int i = 0; i < 20; i++) w.make("f" + std::to_string(i) + ".bin", 2000 + i, static_cast<uint8_t>(i + 1));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        // a few missing: forgotten
        for (int i = 0; i < 3; i++) unlink(w.path("f" + std::to_string(i) + ".bin").c_str());
        ScanReport r = sc.scan();
        CHECK(r.retired_vanished == 3 && r.problems.empty() && w.L->list_retired().size() == 3 && !w.L->get_file_by_path("/Users/me/proj/f0.bin") && w.L->fsck().empty());
        CHECK(w.L->get_file(w.items["f0.bin"].fid)->state == FileState::REPLICATED);          // the devices still have it; the row is only parked
        // the file comes back (restored by hand): a NEW file, tracked afresh
        spit(w.path("f0.bin"), w.items["f0.bin"].bytes);
        ScanReport back = sc.scan();
        CHECK(back.tracked_new == 1 && w.L->get_file_by_path("/Users/me/proj/f0.bin")->file_id != w.items["f0.bin"].fid);
        // many missing (more than half, more than the floor): a person is told, nothing is forgotten
        for (int i = 3; i < 17; i++) unlink(w.path("f" + std::to_string(i) + ".bin").c_str());
        ScanReport mass = sc.scan();
        CHECK(mass.retired_vanished == 0 && mass.problems.size() == 1 && has(mass.problems[0], "14 of 18") && has(mass.problems[0], "unmounted") && w.L->list_retired().size() == 3);
        // ... unless told otherwise
        ScanOptions all;
        all.max_vanished_fraction = 1.0;
        CHECK(sc.scan(all).retired_vanished == 14 && w.L->list_retired().size() == 17);
    }

    {
        printf("== the folder itself is not there (unmounted drive): nothing is changed, whatever the ledger holds\n");
        Lab w;
        for (int i = 0; i < 15; i++) w.make("f" + std::to_string(i) + ".bin", 2000 + i, static_cast<uint8_t>(i + 1));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        std::string away = w.root + "/files-away";
        fs::rename(w.root + "/files", away);
        ScanReport r = sc.scan();
        CHECK(r.aborted && has(r.abort_reason, "not available") && r.retired_vanished == 0 && w.L->list_retired().empty() && w.L->list_files().size() == 15);
        fs::create_directories(w.root + "/files");                                            // an EMPTY folder where the files should be
        ScanReport empty = sc.scan();
        CHECK(!empty.aborted && empty.retired_vanished == 0 && empty.problems.size() == 1 && w.L->list_retired().empty());
        fs::remove_all(w.root + "/files");
        fs::rename(away, w.root + "/files");
        ScanReport ok = sc.scan();
        CHECK(!ok.aborted && ok.unchanged == 15 && ok.retired_vanished == 0);
        // an unreadable subdirectory makes the whole scan refuse rather than conclude files are missing
        fs::create_directories(w.root + "/files/locked");
        spit(w.path("locked/x"), pattern(3, 1));
        chmod((w.root + "/files/locked").c_str(), 0);
        ScanReport locked = sc.scan();
        CHECK(locked.aborted && has(locked.abort_reason, "could not be read") && locked.retired_vanished == 0 && locked.tracked_new == 0);
        chmod((w.root + "/files/locked").c_str(), 0755);
    }

    {
        printf("== offloaded files are not the scanner's business; a file that shadows one is reported, not touched\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        Item& b = w.make("b.bin", MiB + 6, 2);
        CHECK(w.drop("a.bin") && w.drop("b.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        ScanReport r = sc.scan();
        CHECK(r.retired_vanished == 0 && r.tracked_new == 0 && r.problems.empty() && count_state(*w.L, FileState::OFFLOADED) == 2);
        spit(w.path("a.bin"), pattern(33, 5));                                                 // somebody put a file where an offloaded one is
        ScanReport s = sc.scan();
        CHECK(s.problems.size() == 1 && has(s.problems[0], "a.bin") && has(s.problems[0], "only on the devices") && slurp(w.path("a.bin")) == pattern(33, 5));
        CHECK(w.L->get_file(a.fid)->state == FileState::OFFLOADED && w.L->get_file(b.fid)->state == FileState::OFFLOADED && s.marked_modified == 0);
    }

    {
        printf("== a drop that was cut off (DROPPING, bytes in quarantine) is left to the engine, not forgotten\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        w.close_ledger();
        CHECK(spawn_drop_crash(w, a.fid, "drop.after_sync"));
        w.open_ledger();
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        CHECK(w.L->get_file(a.fid)->state == FileState::DROPPING);
        ScanReport r = sc.scan();
        CHECK(r.retired_vanished == 0 && w.L->list_retired().empty() && w.L->get_file(a.fid)->state == FileState::DROPPING);
        CHECK(w.E->recover(devmap(w)).problems.empty());
        ScanReport after = sc.scan();
        CHECK(after.problems.empty() && after.retired_vanished == 0 && w.L->list_retired().empty());
    }

    {
        printf("== files being written are looked at later\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        Item& b = w.make("b.bin", MiB + 6, 2);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        uint64_t fa = 0, fb = 0;
        CHECK(ov.open("/a.bin", O_RDWR, &fa) == 0 && ov.open("/b.bin", O_RDWR, &fb) == 0);
        spit(w.path("a.bin"), pattern(MiB + 77, 7));          // changed behind the writer's back
        unlink(w.path("b.bin").c_str());                      // and deleted
        ScanReport r = sc.scan();
        CHECK(r.skipped_busy == 2 && r.marked_modified == 0 && r.retired_vanished == 0 && w.L->list_retired().empty());
        CHECK(ov.release(fa) == 0 && ov.release(fb) == 0);
        ScanReport after = sc.scan();
        CHECK(after.retired_vanished == 1 && w.L->get_file(a.fid)->size == MiB + 77 && Ledger::is_retired_path(w.L->get_file(b.fid)->path));
    }

    {
        printf("== a big folder is tracked in batches and rescanned quickly\n");
        Lab w;
        const int n = 2400;
        for (int d = 0; d < 12; d++) fs::create_directories(w.root + "/files/d" + std::to_string(d));
        for (int i = 0; i < n; i++) spit(w.path("d" + std::to_string(i % 12) + "/f" + std::to_string(i)), pattern(16, static_cast<uint8_t>(i)));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        auto t0 = std::chrono::steady_clock::now();
        ScanReport r = sc.scan();
        auto t1 = std::chrono::steady_clock::now();
        ScanReport again = sc.scan();
        auto t2 = std::chrono::steady_clock::now();
        auto ms = [](auto a, auto b) { return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count(); };
        printf("      (%d files tracked in %lld ms, rescanned in %lld ms)\n", n, (long long)ms(t0, t1), (long long)ms(t1, t2));
        CHECK(r.tracked_new == static_cast<size_t>(n) && again.unchanged == static_cast<size_t>(n) && again.tracked_new == 0 && w.L->list_files().size() == static_cast<size_t>(n));
        CHECK(ms(t0, t1) < 60000 && ms(t1, t2) < 15000 && w.L->fsck().empty());
    }

    {
        printf("== creating, deleting and renaming through the mount while scans run: the scanner never disagrees with the overlay\n");
        Lab w;
        const int nthreads = 4, rounds = 25;
        fs::create_directories(w.root + "/files/a");
        fs::create_directories(w.root + "/files/b");
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        std::atomic<bool> stop{false};
        std::atomic<int> errors{0}, scans{0};
        std::mutex log_mu;
        std::vector<std::string> oplog;
        auto logop = [&](const std::string& s) {
            auto now = std::chrono::steady_clock::now().time_since_epoch();
            std::lock_guard<std::mutex> g(log_mu);
            oplog.push_back(std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(now).count() % 100000000) + " " + s);
        };
        std::thread scanner([&] {
            while (!stop || scans < 5) {   // (at least five scans, even if the workers finish quickly on a busy machine)
                logop("SCAN begin");
                ScanReport r = sc.scan();
                logop("SCAN end retired=" + std::to_string(r.retired_vanished) + (r.actions.empty() ? "" : " first=" + r.actions[0]));
                if (r.aborted || r.retired_vanished != 0 || !r.problems.empty()) { errors++; printf("      scan: aborted=%d retired=%zu problems=%zu %s\n", (int)r.aborted, r.retired_vanished, r.problems.size(), r.problems.empty() ? "" : r.problems[0].c_str()); for (auto& a : r.actions) printf("        action: %s\n", a.c_str()); logop("SCAN reported a problem"); }   // nothing the overlay did may look like a vanished file or a conflict
                scans++;
            }
        });
        std::map<std::string, Bytes> model[nthreads];     // what each thread believes exists, by mount path
        std::vector<std::thread> ts;
        for (int t = 0; t < nthreads; t++)
            ts.emplace_back([&, t] {
                unsigned seed = 77u + t;
                auto name = [&](int k) { return std::string(k % 2 ? "/a/" : "/b/") + "t" + std::to_string(t) + "_" + std::to_string(k / 2); };
                for (int r = 0; r < rounds; r++) {
                    int k = rand_r(&seed) % 6;
                    std::string p = name(k);
                    int action = rand_r(&seed) % 4;
                    if (action == 0 && !model[t].count(p)) {            // create + write
                        uint64_t fh = 0;
                        Bytes data = pattern(50 + rand_r(&seed) % 300, static_cast<uint8_t>(r + t));
                        { logop("create " + p + " begin"); int crc = ov.create(p, 0644, O_WRONLY, &fh); logop("create " + p + " -> " + std::to_string(crc)); if (crc != 0) { errors++; printf("      create %s: %d\n", p.c_str(), crc); continue; } }
                        if (!write_all_fh(ov, fh, 0, data) || ov.release(fh) != 0) errors++;
                        model[t][p] = data;
                    } else if (action == 1 && model[t].count(p)) {      // delete
                        { logop("unlink " + p + " begin"); int urc = ov.unlink(p); logop("unlink " + p + " -> " + std::to_string(urc)); if (urc != 0) { errors++; printf("      unlink %s: %d\n", p.c_str(), urc); } }
                        model[t].erase(p);
                    } else if (action == 2 && model[t].count(p)) {      // rename to another free name of this thread
                        std::string q = name(rand_r(&seed) % 6);
                        if (model[t].count(q)) continue;
                        { logop("rename " + p + " -> " + q + " begin"); int rrc = ov.rename(p, q); logop("rename " + p + " -> " + q + " : " + std::to_string(rrc)); if (rrc != 0) { errors++; printf("      rename %s -> %s: %d\n", p.c_str(), q.c_str(), rrc); } } if (false) {} else { model[t][q] = model[t][p]; model[t].erase(p); }
                    } else if (action == 3 && model[t].count(p)) {      // rewrite in place
                        uint64_t fh = 0;
                        Bytes data = pattern(40 + rand_r(&seed) % 200, static_cast<uint8_t>(r * 3 + t));
                        { logop("open-trunc " + p); int orc = ov.open(p, O_WRONLY | O_TRUNC, &fh); if (orc != 0) { errors++; printf("      open %s: %d\n", p.c_str(), orc); continue; } }
                        if (!write_all_fh(ov, fh, 0, data) || ov.release(fh) != 0) errors++;
                        model[t][p] = data;
                    }
                    usleep(1000);
                }
            });
        for (auto& t : ts) t.join();
        stop = true;
        scanner.join();
        printf("      (%d scans ran alongside)\n", scans.load());
        if (errors != 0) { printf("      --- operation log (last 60) ---\n"); size_t at = oplog.size(); for (size_t i = 0; i < oplog.size(); i++) if (oplog[i].find("retired=1") != std::string::npos || oplog[i].find("retired=2") != std::string::npos) { at = i; break; } size_t from = at > 45 ? at - 45 : 0; for (size_t i = from; i < oplog.size() && i < at + 4; i++) printf("      %s\n", oplog[i].c_str()); }
        CHECK(errors == 0 && scans > 3);
        size_t expected = 0;
        for (int t = 0; t < nthreads; t++)
            for (auto& kv : model[t]) { expected++; CHECK_QUIET(read_path_all(ov, kv.first, kv.second.size()) == kv.second); }
        ScanReport last = sc.scan();
        CHECK(last.tracked_new == 0 && last.marked_modified == 0 && last.retired_vanished == 0 && last.attrs_updated == 0 && last.problems.empty() && last.unchanged == expected);
        CHECK(w.L->list_files_under("/Users/me/proj/").size() == expected && w.L->fsck().empty());   // (deleted files are parked outside that prefix)
    }

    {
        printf("== details: nested bookkeeping names are ordinary, a file is not a folder, a size change without a time change, a hydration in flight, and what the log says\n");
        Lab w;
        fs::create_directories(w.root + "/files/sub/.tierfs");
        spit(w.path("sub/.tierfs/mine.txt"), pattern(9, 1));                       // only the TOP-LEVEL .tierfs is ours
        Item& a = w.make("a.bin", MiB + 5, 1, 0644, 1500000000);
        Item& h = w.make("h.bin", MiB + 6, 2);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        ScanReport r = sc.scan();
        CHECK(r.tracked_new == 1 && w.L->get_file_by_path("/Users/me/proj/sub/.tierfs/mine.txt"));
        // same time, different size
        spit(w.path("a.bin"), pattern(MiB + 99, 4));
        struct timeval tv[2] = {{1500000000, 0}, {1500000000, 0}};
        utimes(w.path("a.bin").c_str(), tv);
        ScanReport s = sc.scan();
        CHECK(s.marked_modified == 1 && w.L->get_file(a.fid)->size == MiB + 99 && w.L->get_file(a.fid)->state == FileState::LOCAL);
        // a hydration in flight (ledger HYDRATING, the file already at its place): looked at later, not a conflict
        CHECK(w.drop("h.bin") && w.L->begin_hydrate(h.fid).ok);
        spit(w.path("h.bin"), h.bytes);
        ScanReport hy = sc.scan();
        CHECK(hy.problems.empty() && hy.skipped_busy >= 1 && w.L->get_file(h.fid)->state == FileState::HYDRATING);
        CHECK(w.L->abort_hydrate(h.fid).ok);
        // the log names what was done
        unlink(w.path("sub/.tierfs/mine.txt").c_str());
        ScanReport v = sc.scan();
        bool logged = false;
        for (auto& x : v.actions) if (x == "vanished: /Users/me/proj/sub/.tierfs/mine.txt") logged = true;
        CHECK(v.retired_vanished == 1 && logged);
        // a folder that is really a file
        Overlay not_a_dir(*w.L, *w.keys, devmap(w), [&] { OverlayConfig c = cfg_for(w); c.origin_dir = w.path("a.bin"); return c; }(), w.E.get());
        Scanner sc2(*w.L, not_a_dir);
        ScanReport nd = sc2.scan();
        CHECK(nd.aborted && has(nd.abort_reason.c_str(), "not available"));
    }

    {
        printf("== the share of missing files is measured against the files that SHOULD be there, not against the offloaded ones\n");
        Lab w;
        for (int i = 0; i < 12; i++) { w.make("off" + std::to_string(i) + ".bin", 1000 + i, static_cast<uint8_t>(i + 1)); CHECK_QUIET(w.drop("off" + std::to_string(i) + ".bin")); }
        for (int i = 0; i < 14; i++) spit(w.path("loc" + std::to_string(i) + ".txt"), pattern(10, static_cast<uint8_t>(i)));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        Scanner sc(*w.L, ov);
        CHECK(sc.scan().tracked_new == 14);
        for (int i = 0; i < 12; i++) unlink(w.path("loc" + std::to_string(i) + ".txt").c_str());   // 12 of the 14 files that should be here are gone
        ScanReport r = sc.scan();
        CHECK(r.retired_vanished == 0 && r.problems.size() == 1 && has(r.problems[0].c_str(), "12 of 14"));
    }

    {
        printf("== the world moves on between the scan's two snapshots: a rename, a creation, a deletion must not fool it\n");
        for (int variant = 0; variant < 4; variant++) {
            Lab w;
            Item& a = w.make("a.bin", MiB + 5, 1);
            Item& b = w.make("b.bin", MiB + 6, 2);
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
            Scanner sc(*w.L, ov);
            size_t rows_before = w.L->list_files_under("/Users/me/proj/").size();
            bool fired = false;
            sc.on_step = [&](const char* step) {
                if (fired) return;
                // variant 0/1: a rename after the walk / after the rows; 2: a deletion after the rows; 3: a creation after the walk
                if (variant == 0 && std::string(step) == "walked") { fired = true; CHECK(ov.rename("/a.bin", "/a2.bin") == 0); }
                if (variant == 1 && std::string(step) == "rows") { fired = true; CHECK(ov.rename("/a.bin", "/a2.bin") == 0); }
                if (variant == 2 && std::string(step) == "rows") { fired = true; CHECK(ov.unlink("/a.bin") == 0); }
                if (variant == 3 && std::string(step) == "walked") {
                    fired = true;
                    uint64_t fh = 0;
                    CHECK(ov.create("/new.bin", 0644, O_WRONLY, &fh) == 0 && write_all_fh(ov, fh, 0, pattern(20, 3)) && ov.release(fh) == 0);
                }
            };
            ScanReport r = sc.scan();
            sc.on_step = nullptr;
            CHECK(fired && !r.aborted && r.problems.empty() && r.retired_vanished == 0 && r.tracked_new == 0);
            if (variant <= 1) {
                CHECK(w.L->get_file(a.fid)->path == "/Users/me/proj/a2.bin" && !w.L->get_file_by_path("/Users/me/proj/a.bin") && w.L->list_files_under("/Users/me/proj/").size() == rows_before);
            } else if (variant == 2) {
                CHECK(Ledger::is_retired_path(w.L->get_file(a.fid)->path) && w.L->get_file_by_path("/Users/me/proj/b.bin")->file_id == b.fid);
            } else {
                CHECK(w.L->get_file_by_path("/Users/me/proj/new.bin") && w.L->list_files_under("/Users/me/proj/").size() == rows_before + 1);
            }
            ScanReport settled = sc.scan();
            CHECK(settled.tracked_new == 0 && settled.marked_modified == 0 && settled.retired_vanished == 0 && settled.problems.empty() && w.L->fsck().empty());
        }
    }

    {
        printf("== what the scan decides is checked against the world as it is when it acts\n");
        // (1) a changed file that disappears (behind our back) after the rows were read is not marked modified from a stale look
        {
            Lab w;
            Item& a = w.make("a.bin", MiB + 5, 1);
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
            Scanner sc(*w.L, ov);
            spit(w.path("a.bin"), pattern(MiB + 77, 3));
            sc.on_step = [&](const char* step) { if (std::string(step) == "rows") unlink(w.path("a.bin").c_str()); };
            ScanReport r = sc.scan();
            sc.on_step = nullptr;
            CHECK(r.marked_modified == 0 && r.retired_vanished == 0 && w.L->get_file(a.fid)->state == FileState::REPLICATED && w.L->get_file(a.fid)->size == MiB + 5);
            CHECK(sc.scan().retired_vanished == 1);                           // the next scan sees it is simply gone
        }
        // (2) a new file that grows between the walk and the tracking is tracked with the size it has when tracked
        {
            Lab w;
            spit(w.path("n.bin"), pattern(10, 1));
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
            Scanner sc(*w.L, ov);
            sc.on_step = [&](const char* step) { if (std::string(step) == "rows") { spit(w.path("n.bin"), pattern(5000, 2)); chmod(w.path("n.bin").c_str(), 0600); } };
            ScanReport r = sc.scan();
            sc.on_step = nullptr;
            auto n = w.L->get_file_by_path("/Users/me/proj/n.bin");
            CHECK(r.tracked_new == 1 && n && n->size == 5000 && n->mode == 0600);
            CHECK(sc.scan().marked_modified == 0);
        }
        // (3) the option to keep the ledger as it is
        {
            Lab w;
            Item& a = w.make("a.bin", MiB + 5, 1);
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
            Scanner sc(*w.L, ov);
            unlink(w.path("a.bin").c_str());
            ScanOptions keep;
            keep.retire_vanished = false;
            CHECK(sc.scan(keep).retired_vanished == 0 && w.L->get_file_by_path("/Users/me/proj/a.bin") && sc.scan().retired_vanished == 1);
            (void)a;
        }
    }

    {
        printf("== the thresholds of the 'folder is probably unavailable' guard are exact\n");
        // 12 tracked files, 10 missing: more than half, but not MORE THAN the floor of 10: forgotten (a small folder is just small)
        {
            Lab w;
            for (int i = 0; i < 12; i++) spit(w.path("f" + std::to_string(i)), pattern(10, static_cast<uint8_t>(i)));
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
            Scanner sc(*w.L, ov);
            CHECK(sc.scan().tracked_new == 12);
            for (int i = 0; i < 10; i++) unlink(w.path("f" + std::to_string(i)).c_str());
            ScanReport r = sc.scan();
            CHECK(r.retired_vanished == 10 && r.problems.empty());
        }
        // 11 of 12 missing: more than the floor and more than half: refused
        {
            Lab w;
            for (int i = 0; i < 12; i++) spit(w.path("f" + std::to_string(i)), pattern(10, static_cast<uint8_t>(i)));
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
            Scanner sc(*w.L, ov);
            sc.scan();
            for (int i = 0; i < 11; i++) unlink(w.path("f" + std::to_string(i)).c_str());
            ScanReport r = sc.scan();
            CHECK(r.retired_vanished == 0 && r.problems.size() == 1);
        }
        // a handful missing from a tiny folder (3 of 4): under the floor, so forgotten, however large the share
        {
            Lab w;
            for (int i = 0; i < 4; i++) spit(w.path("f" + std::to_string(i)), pattern(10, static_cast<uint8_t>(i)));
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
            Scanner sc(*w.L, ov);
            sc.scan();
            for (int i = 0; i < 3; i++) unlink(w.path("f" + std::to_string(i)).c_str());
            CHECK(sc.scan().retired_vanished == 3);
        }
        // exactly at the fraction: 7 of 14 missing with the floor out of the way: not MORE than half, so forgotten
        {
            Lab w;
            for (int i = 0; i < 14; i++) spit(w.path("f" + std::to_string(i)), pattern(10, static_cast<uint8_t>(i)));
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
            Scanner sc(*w.L, ov);
            sc.scan();
            for (int i = 0; i < 7; i++) unlink(w.path("f" + std::to_string(i)).c_str());
            ScanOptions o;
            o.vanished_floor = 0;
            o.max_vanished_fraction = 0.5;
            ScanReport r = sc.scan(o);
            CHECK(r.retired_vanished == 7 && r.problems.empty());
        }
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
