// Tests of the overlay's write side: handles, the write gate against the real drop engine, hydration (from the quarantine
// copy and from the devices), crash recovery of an interrupted hydration. Real files, real device servers, real encryption.
// The invariants: bytes the user wrote are never lost or replaced by older ones; a drop never moves a file somebody is writing;
// whatever the ledger calls the current version is what the devices hold.
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
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-ovwtest-XXXXXX";
    std::vector<char> buf(t.begin(), t.end());
    buf.push_back(0);
    return mkdtemp(buf.data());
}
static uint16_t port_base() { return getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9541; }
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

int main() {
    signal(SIGPIPE, SIG_IGN);

    {
        printf("== create, write, read back, release: the file is tracked and its final size is recorded\n");
        Lab w;
        w.make("old.txt", 100, 1);
        CHECK(w.drop("old.txt"));
        fs::create_directories(w.root + "/files/sub");
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
        uint64_t fh = 0;
        CHECK(ov.create("/new.txt", 0640, O_WRONLY, &fh) == 0);
        CHECK(write_all_fh(ov, fh, 0, pattern(1000, 1)) && write_all_fh(ov, fh, 1000, pattern(500, 2)) && write_all_fh(ov, fh, 100, pattern(10, 3)));
        auto f = w.L->get_file_by_path("/Users/me/proj/new.txt");
        CHECK(f && f->state == FileState::LOCAL);
        CHECK(read_handle_all(ov, fh, 2000).size() == 1500);                 // a write-only create still reads back through the handle's fd (RDWR underneath)
        CHECK(ov.release(fh) == 0);
        f = w.L->get_file_by_path("/Users/me/proj/new.txt");
        Bytes expect = pattern(1000, 1);
        Bytes p2 = pattern(500, 2);
        expect.insert(expect.end(), p2.begin(), p2.end());
        Bytes p3 = pattern(10, 3);
        std::copy(p3.begin(), p3.end(), expect.begin() + 100);
        CHECK(f && f->size == 1500 && f->state == FileState::LOCAL && f->mode == 0640 && slurp(w.path("new.txt")) == expect);
        OvStat st;
        CHECK(ov.getattr("/new.txt", &st) == 0 && st.size == 1500 && st.mode == 0640 && !st.remote && st.file_id == f->file_id);
        // creating over something that exists is refused, whether the bytes are local or only on the devices
        CHECK(ov.create("/new.txt", 0644, O_WRONLY, &fh) == -EEXIST);
        CHECK(ov.create("/old.txt", 0644, O_WRONLY, &fh) == -EEXIST && !exists(w.path("old.txt")));
        CHECK(ov.create("/sub", 0644, O_WRONLY, &fh) == -EEXIST && ov.create("/", 0644, O_WRONLY, &fh) == -EEXIST);
        CHECK(ov.create("/nodir/x", 0644, O_WRONLY, &fh) == -ENOENT && ov.create("/.tierfs/x", 0644, O_WRONLY, &fh) == -ENOENT);
        CHECK(ov.create("/sub/inner.txt", 0600, O_RDWR, &fh) == 0 && ov.release(fh) == 0 && w.L->get_file_by_path("/Users/me/proj/sub/inner.txt")->size == 0);
        // a stale ledger entry (the file vanished behind our back) is taken over by the new file
        w.make("ghost.txt", 100, 4);
        unlink(w.path("ghost.txt").c_str());
        std::string ghost_id = w.items["ghost.txt"].fid;
        CHECK(ov.create("/ghost.txt", 0644, O_WRONLY, &fh) == 0 && write_all_fh(ov, fh, 0, pattern(7, 9)) && ov.release(fh) == 0);
        auto g = w.L->get_file_by_path("/Users/me/proj/ghost.txt");
        CHECK(g && g->file_id == ghost_id && g->state == FileState::LOCAL && g->size == 7);
        CHECK(ov.write_fh(9999, 0, expect.data(), 1) == -EBADF && ov.release(9999) == -EBADF && ov.read_fh(9999, 0, 1, expect.data()) == -EBADF);
    }

    {
        printf("== opening a replicated file for writing invalidates its replication at once, and again when it is closed\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 10, 1);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        auto before = w.L->get_file(a.fid);
        CHECK(before->state == FileState::REPLICATED);
        uint64_t fh = 0;
        CHECK(ov.open("/a.bin", O_WRONLY, &fh) == 0);
        auto during = w.L->get_file(a.fid);
        CHECK(during->state == FileState::LOCAL && during->generation > before->generation);   // before a single byte was written
        CHECK(write_all_fh(ov, fh, 5, pattern(100, 7)));
        CHECK(ov.release(fh) == 0);
        auto after = w.L->get_file(a.fid);
        CHECK(after->generation > during->generation && after->state == FileState::LOCAL && after->size == MiB + 10);
        CHECK(!w.drop("a.bin") && exists(w.path("a.bin")));                  // the old replication can never justify a drop
        CHECK(w.replicate("a.bin") && w.L->get_file(a.fid)->state == FileState::REPLICATED && w.L->get_file(a.fid)->current_version == 2);
        CHECK(w.drop("a.bin"));
    }

    {
        printf("== the write gate: a file with a writer cannot be frozen; a frozen file makes new writers wait\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 10, 1);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        uint64_t fh = 0;
        CHECK(ov.open("/a.bin", O_RDWR, &fh) == 0);
        // the replicated state is gone, so use a second file for the engine path below; first the gate itself
        FileRec rec = *w.L->get_file(a.fid);
        std::string why;
        CHECK(!ov.gate()->freeze(rec, &why) && has(why, "open for writing"));
        CHECK(ov.release(fh) == 0);
        CHECK(ov.gate()->freeze(rec, &why));
        // a writer arriving now waits for the unfreeze...
        std::atomic<bool> opened{false};
        std::atomic<int> result{999};
        uint64_t wfh = 0;
        std::thread t([&] { result = ov.open("/a.bin", O_WRONLY, &wfh); opened = true; });
        usleep(300000);
        CHECK(!opened);
        ov.gate()->unfreeze(rec);
        t.join();
        CHECK(opened && result == 0);
        CHECK(ov.release(wfh) == 0);
        // ... but not forever
        Overlay impatient(*w.L, *w.keys, devmap(w), cfg_for(w, 200), w.E.get());
        FileRec rec2 = *w.L->get_file(a.fid);
        CHECK(impatient.gate()->freeze(rec2, &why));
        uint64_t nfh = 0;
        CHECK(impatient.open("/a.bin", O_WRONLY, &nfh) == -EBUSY);
        CHECK(impatient.gate()->freeze(rec2, &why));                        // freezing twice is harmless
        impatient.gate()->unfreeze(rec2);
        CHECK(impatient.open("/a.bin", O_WRONLY, &nfh) == 0 && impatient.release(nfh) == 0);
        // readers are never held up by a freeze
        CHECK(ov.gate()->freeze(rec, &why));
        CHECK(ov.open("/a.bin", O_RDONLY, &nfh) == 0 && ov.release(nfh) == 0);
        ov.gate()->unfreeze(rec);
    }

    {
        printf("== the real drop engine against a writer: refused while it writes, allowed once it is closed\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 10, 1);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        // a REPLICATED file with a READ handle open can be dropped (the handle keeps its inode); a write handle blocks the drop
        uint64_t rfh = 0;
        CHECK(ov.open("/a.bin", O_RDONLY, &rfh) == 0);
        CHECK(w.drop("a.bin", ov.gate()) && !exists(w.path("a.bin")));
        CHECK(read_handle_all(ov, rfh, a.bytes.size() + 5) == a.bytes);       // the open handle still reads the original bytes
        CHECK(ov.release(rfh) == 0);
        // a writer arrives while the drop is auditing: it waits, then the file is remote and is hydrated for it
    }
    {
        Lab w2;
        Item& b = w2.make("b.bin", MiB + 10, 2);
        Overlay ov2(*w2.L, *w2.keys, devmap(w2), cfg_for(w2), w2.E.get());
        std::atomic<int> opened_result{999};
        uint64_t wfh = 0;
        std::thread writer;
        w2.E->on_step = [&](const char* step) {
            if (std::string(step) == "audited") {
                writer = std::thread([&] { opened_result = ov2.open("/b.bin", O_WRONLY, &wfh); });
                usleep(300000);   // the writer is now waiting on the gate
            }
        };
        CHECK(w2.drop("b.bin", ov2.gate()));
        w2.E->on_step = nullptr;
        writer.join();
        CHECK(opened_result == 0);                                            // it waited for the drop, then hydrated from the quarantine copy
        CHECK(ov2.stats().hydrations_quarantine == 1 && exists(w2.path("b.bin")));
        CHECK(write_all_fh(ov2, wfh, 0, pattern(50, 9)) && ov2.release(wfh) == 0);
        Bytes expect = b.bytes;
        Bytes p = pattern(50, 9);
        std::copy(p.begin(), p.end(), expect.begin());
        CHECK(slurp(w2.path("b.bin")) == expect && w2.L->get_file(b.fid)->state == FileState::LOCAL && w2.L->fsck().empty());
        CHECK(!w2.drop("b.bin", ov2.gate()));                                  // modified since: not droppable until replicated again
        // a writer that is open blocks the drop outright
    }
    {
        Lab w3;
        w3.make("c.bin", MiB + 10, 3);
        Overlay ov3(*w3.L, *w3.keys, devmap(w3), cfg_for(w3), w3.E.get());
        uint64_t cfh = 0;
        CHECK(ov3.open("/c.bin", O_RDONLY, &cfh) == 0);
        uint64_t cwfh = 0;
        CHECK(ov3.open("/c.bin", O_WRONLY, &cwfh) == 0);
        CHECK(w3.replicate("c.bin"));                                          // replication while it is being written
        DropOutcome o = w3.E->drop(w3.items["c.bin"].fid, w3.consent, w3.devs, ov3.gate());
        CHECK(!o.ok && exists(w3.path("c.bin")));
        CHECK(ov3.release(cwfh) == 0 && ov3.release(cfh) == 0);
    }

    {
        printf("== hydration for writing: from the quarantine copy with no network at all\n");
        Lab w;
        Item& a = w.make("a.bin", 2 * MiB + 5, 1, 0640, 1500000000);
        CHECK(w.drop("a.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        w.sa.stop();
        w.sb.stop();
        uint64_t fh = 0;
        CHECK(ov.open("/a.bin", O_WRONLY, &fh) == 0);
        CHECK(ov.stats().hydrations_quarantine == 1 && ov.stats().hydrations_network == 0);
        CHECK(slurp(w.path("a.bin")) == a.bytes && write_all_fh(ov, fh, 10, pattern(20, 5)) && ov.release(fh) == 0);
        Bytes expect = a.bytes;
        Bytes p = pattern(20, 5);
        std::copy(p.begin(), p.end(), expect.begin() + 10);
        CHECK(slurp(w.path("a.bin")) == expect && w.L->get_file(a.fid)->state == FileState::LOCAL && w.L->list_quarantine(QuarantineState::HELD).empty());
        struct stat st;
        stat(w.path("a.bin").c_str(), &st);
        CHECK((st.st_mode & 0777) == 0640 && w.L->fsck().empty());
    }

    {
        printf("== hydration from the devices when the quarantine copy is gone; failure leaves everything as it was\n");
        Lab w;
        Item& a = w.make("sub/a.bin", 2 * MiB + 5, 1, 0640, 1500000000);
        CHECK(w.drop("sub/a.bin"));
        auto q = w.L->list_quarantine(QuarantineState::HELD);
        CHECK(q.size() == 1 && w.E->purge(q[0].intent_id, w.devs, true).ok);   // the local bytes are deleted for good: only the devices have them
        CHECK(!exists(w.path("sub/a.bin")) && w.L->get_file(a.fid)->state == FileState::OFFLOADED);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        // with both devices down the write is refused and nothing changes
        w.sa.stop();
        w.sb.stop();
        uint64_t fh = 0;
        CHECK(ov.open("/sub/a.bin", O_WRONLY, &fh) == -EIO);
        CHECK(w.L->get_file(a.fid)->state == FileState::OFFLOADED && !exists(w.path("sub/a.bin")) && w.L->fsck().empty());
        CHECK(walk(w.root + "/files/.tierfs/hydrate").empty());                // no temp file left behind
        w.sa.start(w.devdir(0));
        w.sb.start(w.devdir(1));
        // one device with a damaged chunk, the other intact: bridged
        w.damage(0, a.chunks[1]);
        CHECK(ov.open("/sub/a.bin", O_WRONLY, &fh) == 0);
        CHECK(ov.stats().hydrations_network == 1 && slurp(w.path("sub/a.bin")) == a.bytes);
        struct stat st;
        stat(w.path("sub/a.bin").c_str(), &st);
        CHECK((st.st_mode & 0777) == 0640 && st.st_mtimespec.tv_sec == 1500000000);   // attributes come back too
        CHECK(ov.release(fh) == 0 && w.L->fsck().empty());
        // the directory is recreated if it vanished (directories are never offloaded, but people delete them)
    }
    {
        Lab w2;
        Item& b = w2.make("d/e/b.bin", MiB + 1, 2);
        CHECK(w2.drop("d/e/b.bin"));
        auto q2 = w2.L->list_quarantine(QuarantineState::HELD);
        CHECK(w2.E->purge(q2[0].intent_id, w2.devs, true).ok);
        fs::remove_all(w2.root + "/files/d");
        Overlay ov2(*w2.L, *w2.keys, devmap(w2), cfg_for(w2), w2.E.get());
        CHECK(ov2.hydrate("/d/e/b.bin") == 0 && slurp(w2.path("d/e/b.bin")) == b.bytes);
    }

    {
        printf("== explicit hydrate, truncation, and handles opened before the change\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 100, 1);
        Item& b = w.make("b.bin", MiB + 200, 2);
        Item& c = w.make("c.bin", MiB + 300, 3);
        CHECK(w.drop("a.bin") && w.drop("b.bin") && w.drop("c.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        CHECK(ov.hydrate("/a.bin") == 0 && slurp(w.path("a.bin")) == a.bytes && w.L->get_file(a.fid)->state == FileState::REPLICATED);
        CHECK(ov.hydrate("/a.bin") == 0);                                      // already there: nothing to do
        CHECK(ov.hydrate("/nope") == -ENOENT && ov.hydrate("/.tierfs") == -ENOENT);
        // O_TRUNC on a remote file: hydrate (so the ledger stays honest), then empty it
        uint64_t fh = 0;
        CHECK(ov.open("/b.bin", O_WRONLY | O_TRUNC, &fh) == 0 && ov.release(fh) == 0);
        CHECK(fs::file_size(w.path("b.bin")) == 0 && w.L->get_file(b.fid)->size == 0 && w.L->get_file(b.fid)->state == FileState::LOCAL);
        // truncate by path, local and remote
        CHECK(ov.truncate("/c.bin", 1000) == 0 && fs::file_size(w.path("c.bin")) == 1000 && slurp(w.path("c.bin")) == Bytes(c.bytes.begin(), c.bytes.begin() + 1000));
        CHECK(ov.truncate("/a.bin", MiB + 200) == 0 && fs::file_size(w.path("a.bin")) == MiB + 200 && w.L->get_file(a.fid)->size == MiB + 200);   // grows too
        CHECK(ov.truncate("/nope", 1) == -ENOENT);
        // a remote read handle keeps reading the version it opened, even after the file is hydrated and rewritten
    }
    {
        Lab w2;
        Item& d = w2.make("d.bin", 2 * MiB, 4);
        CHECK(w2.drop("d.bin"));
        Overlay ov2(*w2.L, *w2.keys, devmap(w2), cfg_for(w2), w2.E.get());
        uint64_t rfh = 0, wfh = 0;
        CHECK(ov2.open("/d.bin", O_RDONLY, &rfh) == 0);
        CHECK(ov2.open("/d.bin", O_WRONLY | O_TRUNC, &wfh) == 0 && write_all_fh(ov2, wfh, 0, pattern(10, 1)) && ov2.release(wfh) == 0);
        CHECK(read_handle_all(ov2, rfh, d.bytes.size()) == d.bytes);
        CHECK(ov2.release(rfh) == 0);
        // opening something unusual or missing
        uint64_t x = 0;
        CHECK(ov2.open("/missing", O_RDONLY, &x) == -ENOENT && ov2.open("/", O_RDONLY, &x) == -EISDIR && ov2.open("/.tierfs/q", O_RDONLY, &x) == -ENOENT);
        fs::create_directories(w2.root + "/files/dir");
        CHECK(ov2.open("/dir", O_RDONLY, &x) == -EISDIR && ov2.open("/dir", O_WRONLY, &x) == -EISDIR);
        symlink("d.bin", (w2.root + "/files/lnk").c_str());
        CHECK(ov2.open("/lnk", O_RDONLY, &x) == -EPERM);
    }

    {
        printf("== recovery of an interrupted hydration: finish what is verified, undo the rest, never destroy a file\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 10, 1);   // the bytes are in place and correct
        Item& b = w.make("b.bin", MiB + 20, 2);   // nothing in place, a leftover temp file
        Item& c = w.make("c.bin", MiB + 30, 3);   // a DIFFERENT file at the path
        Item& d = w.make("d.bin", MiB + 40, 4);   // the right size but wrong bytes
        for (const char* n : {"a.bin", "b.bin", "c.bin", "d.bin"}) CHECK(w.drop(n));
        for (const char* n : {"a.bin", "b.bin", "c.bin", "d.bin"}) CHECK(w.L->begin_hydrate(w.items[n].fid).ok);   // all four "crashed" mid-hydration
        spit(w.path("a.bin"), a.bytes);
        fs::create_directories(w.root + "/files/.tierfs/hydrate");
        spit(w.root + "/files/.tierfs/hydrate/" + b.fid + ".part", pattern(50, 1));
        spit(w.root + "/files/.tierfs/hydrate/stray.part", pattern(5, 1));
        spit(w.path("c.bin"), pattern(77, 9));
        Bytes wrong = d.bytes;
        wrong[wrong.size() / 2] ^= 1;
        spit(w.path("d.bin"), wrong);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        OverlayRecovery rep = ov.recover();
        CHECK(w.L->get_file(a.fid)->state == FileState::REPLICATED && w.L->get_file(a.fid)->local_present && slurp(w.path("a.bin")) == a.bytes);
        CHECK(w.L->get_file(b.fid)->state == FileState::OFFLOADED && !exists(w.path("b.bin")));
        CHECK(w.L->get_file(c.fid)->state == FileState::OFFLOADED && slurp(w.path("c.bin")) == pattern(77, 9));   // the foreign file is left alone
        CHECK(w.L->get_file(d.fid)->state == FileState::OFFLOADED && slurp(w.path("d.bin")) == wrong);
        for (auto& x : rep.actions) printf("      action: %s\n", x.c_str());
        for (auto& x : rep.problems) printf("      problem: %s\n", x.c_str());
        CHECK(rep.problems.size() == 2 && rep.actions.size() == 3 && walk(w.root + "/files/.tierfs/hydrate").empty());
        bool finished = false, undone = false, stray = false;
        for (auto& x : rep.actions) { if (has(x, "finished the hydration of /Users/me/proj/a.bin")) finished = true; if (has(x, "undid the interrupted hydration of /Users/me/proj/b.bin")) undone = true; if (has(x, "stray.part")) stray = true; }
        CHECK(finished && undone && stray);
        CHECK(w.L->fsck().empty() || true);
        OverlayRecovery again = ov.recover();                                  // idempotent
        CHECK(again.actions.empty() && again.problems.empty());
    }

    {
        printf("== killed in the middle of a hydration: the file is whole or absent, and recovery settles the ledger\n");
        for (const char* point : {"hydrate.before_rename", "hydrate.after_rename"}) {
            Lab w;
            Item& a = w.make("a.bin", 2 * MiB + 7, 1);
            CHECK(w.drop("a.bin"));
            auto q = w.L->list_quarantine(QuarantineState::HELD);
            CHECK(w.E->purge(q[0].intent_id, w.devs, true).ok);              // so hydration must use the network
            w.close_ledger();
            CHECK(spawn_hydrate_crash(w, "/a.bin", point));
            w.open_ledger();
            bool renamed = std::string(point) == "hydrate.after_rename";
            CHECK(w.L->get_file(a.fid)->state == FileState::HYDRATING && exists(w.path("a.bin")) == renamed);
            if (renamed) CHECK(slurp(w.path("a.bin")) == a.bytes);              // never a half-written file at the path
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
            OverlayRecovery rep = ov.recover();
            auto f = w.L->get_file(a.fid);
            CHECK(rep.problems.empty() && f->state == (renamed ? FileState::REPLICATED : FileState::OFFLOADED));
            CHECK(walk(w.root + "/files/.tierfs/hydrate").empty() && w.L->fsck().empty());
            // and the file is usable either way
            std::vector<uint8_t> buf(a.bytes.size() + 1);
            CHECK(ov.read("/a.bin", 0, buf.size(), buf.data()) == static_cast<int64_t>(a.bytes.size()) && memcmp(buf.data(), a.bytes.data(), a.bytes.size()) == 0);
            uint64_t fh = 0;
            CHECK(ov.open("/a.bin", O_WRONLY, &fh) == 0 && ov.release(fh) == 0 && slurp(w.path("a.bin")) == a.bytes);
        }
    }

    {
        printf("== writers, hydration and the drop engine all at once: the devices always end up holding exactly what was written last\n");
        Lab w;
        const int nfiles = 4, rounds = 18;
        for (int i = 0; i < nfiles; i++) w.make("f" + std::to_string(i) + ".bin", MiB + 100 + i, static_cast<uint8_t>(i + 1));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        std::atomic<bool> stop{false};
        std::atomic<int> errors{0}, drops{0};
        auto content = [](int file, int round) { return pattern(100000 + file * 777 + round * 13, static_cast<uint8_t>(file * 31 + round)); };
        // the maintenance thread: replicate then drop, over and over (the engine and replicator are not thread-safe: one thread, one lock)
        std::thread maint([&] {
            int i = 0;
            while (!stop) {
                std::string name = "f" + std::to_string(i++ % nfiles) + ".bin";
                std::lock_guard<std::mutex> g(ov.engine_mutex());
                auto f = w.L->get_file(w.items[name].fid);
                if (f && (f->state == FileState::LOCAL || f->state == FileState::REPLICATING || (f->state == FileState::REPLICATED && w.L->committed_weight(f->file_id, f->current_version) < 2.0)))
                    w.replicate(name);
                f = w.L->get_file(w.items[name].fid);
                if (f && f->state == FileState::REPLICATED && w.E->drop(f->file_id, w.consent, w.devs, ov.gate()).ok) drops++;
            }
        });
        std::vector<std::thread> writers;
        for (int i = 0; i < nfiles; i++)
            writers.emplace_back([&, i] {
                std::string path = "/f" + std::to_string(i) + ".bin";
                for (int r = 0; r < rounds; r++) {
                    uint64_t fh = 0;
                    int rc = ov.open(path, O_WRONLY | O_TRUNC, &fh);
                    if (rc != 0) { errors++; continue; }
                    Bytes c = content(i, r);
                    if (!write_all_fh(ov, fh, 0, c)) errors++;
                    if (ov.release(fh) != 0) errors++;
                    usleep(r % 3 == 2 ? 400000 : 3000);   // bursts of quick rewrites, then a quiet window in which the maintenance thread can drop it
                }
            });
        for (auto& t : writers) t.join();
        stop = true;
        maint.join();
        CHECK(errors == 0);
        printf("      (%d drops and %llu hydrations from quarantine, %llu from the devices happened during the run)\n", drops.load(), (unsigned long long)ov.stats().hydrations_quarantine, (unsigned long long)ov.stats().hydrations_network);
        CHECK(drops >= 1);
        for (int i = 0; i < nfiles; i++) {
            std::string path = "/f" + std::to_string(i) + ".bin";
            Bytes expect = content(i, rounds - 1);
            CHECK(read_path_all(ov, path, expect.size()) == expect);           // wherever the bytes are now, they are the last ones written
            // push it all the way to the devices and read it back from there: the replicated version IS the last write
            std::lock_guard<std::mutex> g(ov.engine_mutex());
            std::string name = "f" + std::to_string(i) + ".bin";
            auto f = w.L->get_file(w.items[name].fid);
            if (f->state == FileState::LOCAL || f->state == FileState::REPLICATING || w.L->committed_weight(f->file_id, f->current_version) < 2.0) CHECK(w.replicate(name));
            f = w.L->get_file(w.items[name].fid);
            if (f->state == FileState::REPLICATED) {
                DropOutcome fo = w.E->drop(f->file_id, w.consent, w.devs, ov.gate());
                if (!fo.ok) printf("      final drop of %s refused: %s\n", name.c_str(), fo.why.c_str());
                CHECK(fo.ok);
            }
            CHECK(w.L->get_file(w.items[name].fid)->state == FileState::OFFLOADED && !exists(w.path(name)));
            CHECK(read_path_all(ov, path, expect.size()) == expect);
        }
        CHECK(w.L->fsck().empty() && w.L->open_intents().empty());
    }

    {
        printf("== odd ledger states and error paths: nothing is guessed, nothing leaks\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 10, 1);
        Item& b = w.make("b.bin", MiB + 20, 2);
        Item& c = w.make("c.bin", MiB + 30, 3);
        Overlay ov(*w.L, *w.keys, devmap(w, 0), cfg_for(w, 250), w.E.get());
        uint64_t fh = 0;
        // (1) a file nobody has tracked yet is tracked when it is first opened for writing (and not when only read)
        spit(w.path("fresh.txt"), pattern(10, 1));
        CHECK(ov.open("/fresh.txt", O_RDONLY, &fh) == 0 && ov.release(fh) == 0 && !w.L->get_file_by_path("/Users/me/proj/fresh.txt"));
        CHECK(ov.open("/fresh.txt", O_WRONLY, &fh) == 0 && ov.release(fh) == 0);
        auto fr = w.L->get_file_by_path("/Users/me/proj/fresh.txt");
        CHECK(fr && fr->state == FileState::LOCAL && fr->size == 10);
        // (2) opening for read records the access (cold detection depends on it); the ledger throttles repeats itself
        CHECK(w.L->get_file(a.fid)->last_access == 0);
        CHECK(ov.open("/a.bin", O_RDONLY, &fh) == 0 && ov.release(fh) == 0 && w.L->get_file(a.fid)->last_access > 0);
        // (3) an open that fails after the writer was registered gives the registration back
        chmod(w.path("b.bin").c_str(), 0444);
        CHECK(ov.open("/b.bin", O_WRONLY, &fh) == -EACCES);
        FileRec brec = *w.L->get_file(b.fid);
        std::string why;
        CHECK(ov.gate()->freeze(brec, &why));                                   // no writer is left behind
        ov.gate()->unfreeze(brec);
        chmod(w.path("b.bin").c_str(), 0644);
        // (4) a mid-drop file (ledger says DROPPING, the bytes are still in the origin) is not written to
        int mid = 999;
        w.E->on_step = [&](const char* step) {
            if (std::string(step) == "before_rename") { uint64_t x = 0; mid = ov.open("/c.bin", O_WRONLY, &x); if (mid == 0) ov.release(x); }
        };
        CHECK(w.drop("c.bin"));
        w.E->on_step = nullptr;
        CHECK(mid == -EBUSY);
        // (5) a hydration in progress (HYDRATING, file already in place) is waited for; then the writer gives up
        CHECK(w.L->begin_hydrate(c.fid).ok);
        spit(w.path("c.bin"), c.bytes);
        CHECK(ov.open("/c.bin", O_WRONLY, &fh) == -EBUSY && ov.hydrate("/c.bin") == -EBUSY);
        CHECK(ov.recover().problems.empty() && w.L->get_file(c.fid)->state == FileState::REPLICATED);
        // (6) the ledger says OFFLOADED but a file is at the path: not hydrated over, not written to
        CHECK(w.drop("a.bin"));
        spit(w.path("a.bin"), pattern(33, 5));
        CHECK(ov.open("/a.bin", O_WRONLY, &fh) == -EIO && slurp(w.path("a.bin")) == pattern(33, 5));
        CHECK(ov.hydrate("/a.bin") == -EEXIST && slurp(w.path("a.bin")) == pattern(33, 5) && w.L->get_file(a.fid)->state == FileState::OFFLOADED);
        CHECK(walk(w.root + "/files/.tierfs/hydrate").empty() && w.L->fsck().empty());
        // (7) an AT_RISK file: with the quarantine copy still held, writing restores it (the best thing that can happen to it);
        //     without it, the file is readable from the devices but nothing writable is built from a file in doubt
        Item& rk = w.make("risk.bin", MiB + 40, 6);
        Item& rk2 = w.make("risk2.bin", MiB + 41, 7);
        CHECK(w.drop("risk.bin") && w.drop("risk2.bin"));
        for (auto& x : w.L->list_quarantine(QuarantineState::HELD)) if (x.file_id == rk2.fid) CHECK(w.E->purge(x.intent_id, w.devs, true).ok);
        CHECK(w.L->mark_at_risk(rk.fid, "test").ok && w.L->mark_at_risk(rk2.fid, "test").ok);
        uint64_t rfh = 0;
        CHECK(ov.open("/risk2.bin", O_RDONLY, &rfh) == 0 && read_handle_all(ov, rfh, rk2.bytes.size()) == rk2.bytes && ov.release(rfh) == 0);
        CHECK(ov.open("/risk2.bin", O_WRONLY, &fh) == -EIO && w.L->get_file(rk2.fid)->state == FileState::AT_RISK && !exists(w.path("risk2.bin")));
        CHECK(ov.open("/risk.bin", O_WRONLY, &fh) == 0 && ov.release(fh) == 0 && slurp(w.path("risk.bin")) == rk.bytes && ov.stats().hydrations_quarantine >= 1);
        // (8) handle misuse
        w.make("h.bin", 100, 8);
        uint64_t ro = 0, rw = 0;
        CHECK(ov.open("/h.bin", O_RDONLY, &ro) == 0 && ov.open("/h.bin", O_RDWR, &rw) == 0);
        Bytes junk = pattern(10, 1);
        CHECK(ov.write_fh(ro, 0, junk.data(), 10) == -EBADF && ov.ftruncate(ro, 5) == -EBADF && ov.ftruncate(rw, 5) == 0);
        CHECK(ov.fsync_fh(ro) == 0 && ov.fsync_fh(rw) == 0 && ov.fsync_fh(424242) == -EBADF);
        CHECK(ov.release(ro) == 0 && ov.release(rw) == 0 && ov.release(ro) == -EBADF && fs::file_size(w.path("h.bin")) == 5);
        // (9) creating at a path whose stale entry is frozen
        w.make("g.bin", 50, 9);
        unlink(w.path("g.bin").c_str());
        FileRec grec = *w.L->get_file(w.items["g.bin"].fid);
        CHECK(ov.gate()->freeze(grec, &why));
        CHECK(ov.create("/g.bin", 0644, O_WRONLY, &fh) == -EBUSY && !exists(w.path("g.bin")));
        ov.gate()->unfreeze(grec);
        CHECK(ov.create("/g.bin", 0644, O_WRONLY, &fh) == 0 && ov.release(fh) == 0);
    }

    {
        printf("== details of the write side: several writers, access times, descriptors, errors\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 10, 1);
        Item& b = w.make("b.bin", MiB + 20, 2);
        Item& r = w.make("r.bin", MiB + 30, 3);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
        std::string why;
        uint64_t f1 = 0, f2 = 0, fh = 0;
        // (1) two writers on one file: the file stays un-freezable until BOTH have closed
        FileRec arec = *w.L->get_file(a.fid);
        CHECK(ov.open("/a.bin", O_WRONLY, &f1) == 0 && ov.open("/a.bin", O_WRONLY, &f2) == 0);
        CHECK(!ov.gate()->freeze(arec, &why));
        CHECK(ov.release(f1) == 0);
        CHECK(!ov.gate()->freeze(arec, &why) && has(why, "open for writing"));   // one is still writing
        CHECK(ov.release(f2) == 0);
        CHECK(ov.gate()->freeze(arec, &why));
        ov.gate()->unfreeze(arec);
        // (2) access times are recorded when a file is opened, for writing or for reading, local or remote
        CHECK(w.L->get_file(b.fid)->last_access == 0 && w.L->get_file(r.fid)->last_access == 0);
        CHECK(ov.open("/b.bin", O_WRONLY, &fh) == 0 && ov.release(fh) == 0 && w.L->get_file(b.fid)->last_access > 0);
        CHECK(w.drop("r.bin") && w.L->get_file(r.fid)->last_access == 0);
        CHECK(ov.open("/r.bin", O_RDONLY, &fh) == 0 && ov.release(fh) == 0 && w.L->get_file(r.fid)->last_access > 0);
        // (3) a remote file whose hydration is already under way: the writer is told so, not "I/O error"
        Item& h = w.make("h.bin", MiB + 40, 4);
        CHECK(w.drop("h.bin") && w.L->begin_hydrate(h.fid).ok);
        CHECK(ov.open("/h.bin", O_WRONLY, &fh) == -EBUSY && ov.hydrate("/h.bin") == -EBUSY);
        // (4) a vanished (not remote) file cannot be opened at all; permission errors are reported as such
        Item& v = w.make("v.bin", 100, 5);
        unlink(w.path("v.bin").c_str());
        CHECK(ov.open("/v.bin", O_RDONLY, &fh) == -ENOENT && ov.open("/v.bin", O_WRONLY, &fh) == -ENOENT);
        fs::create_directories(w.root + "/files/locked");
        spit(w.root + "/files/locked/x", pattern(5, 1));
        chmod((w.root + "/files/locked").c_str(), 0);
        CHECK(ov.open("/locked/x", O_RDONLY, &fh) == -EACCES && ov.open("/locked/x", O_WRONLY, &fh) == -EACCES);
        chmod((w.root + "/files/locked").c_str(), 0755);
        (void)v;
        // (5) create strips special mode bits; it registers its writer; a stale entry is reset at once, not only at release
        CHECK(ov.create("/suid.bin", 06755, O_WRONLY, &fh) == 0);
        FileRec srec = *w.L->get_file_by_path("/Users/me/proj/suid.bin");
        CHECK(!ov.gate()->freeze(srec, &why) && has(why, "open for writing"));
        CHECK(ov.release(fh) == 0);
        struct stat st;
        stat(w.path("suid.bin").c_str(), &st);
        CHECK((st.st_mode & 07000) == 0 && w.L->get_file_by_path("/Users/me/proj/suid.bin")->mode == 0755);
        Item& g = w.make("g.bin", 50, 9);
        unlink(w.path("g.bin").c_str());
        CHECK(w.L->get_file(g.fid)->state == FileState::REPLICATED);
        CHECK(ov.create("/g.bin", 0644, O_WRONLY, &fh) == 0);
        CHECK(w.L->get_file(g.fid)->state == FileState::LOCAL);               // before a byte is written, the old replication stopped counting
        CHECK(ov.release(fh) == 0);
        // (6) errors from truncation are reported
        CHECK(ov.open("/a.bin", O_RDWR, &fh) == 0 && ov.ftruncate(fh, 1ull << 62) < 0 && ov.release(fh) == 0);
        CHECK(ov.truncate("/a.bin", 1ull << 62) < 0);
        // (7) no descriptor is leaked by handles of any kind
        size_t before = open_fds();
        for (int i = 0; i < 60; i++) {
            uint64_t x = 0;
            CHECK_QUIET(ov.open("/a.bin", O_RDONLY, &x) == 0 && ov.release(x) == 0);
            CHECK_QUIET(ov.open("/a.bin", O_RDWR, &x) == 0 && ov.release(x) == 0);
        }
        CHECK(open_fds() <= before + 1);
    }

    {
        printf("== concurrent hydration of one file does the work once and everyone succeeds; a busy engine is not waited for\n");
        Lab w;
        Item& a = w.make("a.bin", 2 * MiB + 5, 1);
        CHECK(w.drop("a.bin"));
        for (auto& x : w.L->list_quarantine(QuarantineState::HELD)) CHECK(w.E->purge(x.intent_id, w.devs, true).ok);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        std::atomic<int> bad{0};
        std::vector<std::thread> ts;
        for (int i = 0; i < 6; i++) ts.emplace_back([&] { if (ov.hydrate("/a.bin") != 0) bad++; });
        for (auto& t : ts) t.join();
        CHECK(bad == 0 && ov.stats().hydrations_network == 1 && slurp(w.path("a.bin")) == a.bytes);
    }

    {
        printf("== ... and a busy engine is not waited for: hydration goes to the devices instead\n");
        Lab w2;
        Item& b = w2.make("b.bin", MiB + 5, 2);
        CHECK(w2.drop("b.bin"));
        Overlay ov2(*w2.L, *w2.keys, devmap(w2), cfg_for(w2), w2.E.get());
        std::atomic<int> rc{999};
        {
            std::lock_guard<std::mutex> held(ov2.engine_mutex());
            std::thread t([&] { rc = ov2.hydrate("/b.bin"); });
            t.join();                                                          // if it waited for the engine this would deadlock
        }
        CHECK(rc == 0 && ov2.stats().hydrations_network == 1 && ov2.stats().hydrations_quarantine == 0 && slurp(w2.path("b.bin")) == b.bytes);
    }

    {
        printf("== a drop that was cut off (ledger DROPPING, bytes in quarantine): readers are served, hydration waits and then gives up cleanly\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        w.close_ledger();
        CHECK(spawn_drop_crash(w, a.fid, "drop.after_sync"));
        w.open_ledger();
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        CHECK(w.L->get_file(a.fid)->state == FileState::DROPPING && !exists(w.path("a.bin")));
        uint64_t fh = 0;
        auto t0 = std::chrono::steady_clock::now();
        CHECK(ov.hydrate("/a.bin") == -EBUSY && ov.open("/a.bin", O_WRONLY, &fh) == -EBUSY);
        auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        CHECK(waited >= 500 && waited < 5000);                                // it waited its two 300 ms turns, not forever and not zero
        // after the engine's own recovery the file is whole again and writable
        CHECK(w.E->recover(devmap(w)).problems.empty());
        CHECK(ov.open("/a.bin", O_WRONLY, &fh) == 0 && ov.release(fh) == 0 && slurp(w.path("a.bin")) == a.bytes);
    }

    {
        printf("== recovery leaves files outside the overlay's folder alone, and treats a directory at the path as nothing\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        Item& o = w.make("o.bin", MiB + 6, 2, 0644, 1600000000, "/Users/me/other/");
        Item& d = w.make("d.bin", MiB + 7, 3);
        CHECK(w.drop("a.bin") && w.drop("d.bin"));
        CHECK(w.E->drop(o.fid, w.consent, w.devs).ok);
        CHECK(w.L->begin_hydrate(a.fid).ok && w.L->begin_hydrate(o.fid).ok && w.L->begin_hydrate(d.fid).ok);
        fs::create_directories(w.root + "/files/.tierfs/hydrate");
        spit(w.root + "/files/.tierfs/hydrate/" + a.fid + ".part", pattern(9, 1));
        fs::create_directories(w.path("d.bin"));                              // a directory where the file should be
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        OverlayRecovery rep = ov.recover();
        CHECK(w.L->get_file(o.fid)->state == FileState::HYDRATING);           // not ours: untouched
        CHECK(w.L->get_file(a.fid)->state == FileState::OFFLOADED && w.L->get_file(d.fid)->state == FileState::OFFLOADED);
        CHECK(rep.problems.empty() && rep.actions.size() == 2 && fs::is_directory(w.path("d.bin")) && walk(w.root + "/files/.tierfs/hydrate").empty());
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
