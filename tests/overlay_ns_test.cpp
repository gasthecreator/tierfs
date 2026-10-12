// Tests of the overlay's namespace: mkdir, rmdir, unlink, rename (files and directories, local and remote), symlinks,
// attributes, extended attributes, undelete. Real files, real device servers, real encryption, the real drop engine.
// The invariants: a name always leads to the bytes the user put there (locally or from the devices); a directory is never
// half-renamed; nothing is destroyed that the devices could not give back.
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
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
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-ovntest-XXXXXX";
    std::vector<char> buf(t.begin(), t.end());
    buf.push_back(0);
    return mkdtemp(buf.data());
}
static uint16_t port_base() { return getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9551; }
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


static bool listed(Overlay& ov, const std::string& dir, const std::string& name, bool* remote = nullptr) {
    std::vector<OvEntry> es;
    if (ov.readdir(dir, &es) != 0) return false;
    for (auto& e : es) if (e.name == name) { if (remote) *remote = e.remote; return true; }
    return false;
}
static int64_t xget(Overlay& ov, const std::string& path, const std::string& name, std::string* value = nullptr) {
    uint8_t buf[256];
    int64_t n = ov.getxattr(path, name, buf, sizeof buf);
    if (n >= 0 && value) value->assign(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
    return n;
}

int main() {
    signal(SIGPIPE, SIG_IGN);

    {
        printf("== directories: mkdir, rmdir, and the rule that a directory holding files that live on the devices is not empty\n");
        Lab w;
        Item& a = w.make("d/a.bin", MiB + 5, 1);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        CHECK(ov.mkdir("/new", 0750) == 0 && fs::is_directory(w.path("new")));
        struct stat st;
        stat(w.path("new").c_str(), &st);
        CHECK((st.st_mode & 0777) == 0750);
        CHECK(ov.mkdir("/new", 0755) == -EEXIST && ov.mkdir("/", 0755) == -EEXIST && ov.mkdir("/nope/inner", 0755) == -ENOENT && ov.mkdir("/.tierfs/x", 0755) == -ENOENT);
        CHECK(w.drop("d/a.bin"));
        CHECK(ov.mkdir("/d/a.bin", 0755) == -EEXIST);                      // the name belongs to a file whose bytes are on the devices
        CHECK(ov.rmdir("/d") == -ENOTEMPTY && fs::is_directory(w.path("d")));
        CHECK(ov.rmdir("/") == -EBUSY && ov.rmdir("/nope") == -ENOENT && ov.rmdir("/.tierfs") == -ENOENT);
        spit(w.path("new/x"), pattern(3, 1));
        CHECK(ov.rmdir("/new") == -ENOTEMPTY);
        unlink(w.path("new/x").c_str());
        CHECK(ov.rmdir("/new") == 0 && !exists(w.path("new")));
        CHECK(ov.rmdir("/d/a.bin") != 0);                                  // not a directory
        CHECK(ov.unlink("/d/a.bin") == 0 && ov.rmdir("/d") == 0 && !exists(w.path("d")));   // once the file is deleted the directory is empty
        // a directory with a file in the middle of a drop is not removed either
        Item& b = w.make("e/b.bin", MiB + 6, 2);
        FileRec brec = *w.L->get_file(b.fid);
        std::string why;
        CHECK(ov.gate()->freeze(brec, &why) && ov.rmdir("/e") == -EBUSY);
        ov.gate()->unfreeze(brec);
    }

    {
        printf("== unlink: a local file, a remote file, a file being written; deleted files leave the namespace but not the devices\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        Item& r = w.make("r.bin", MiB + 6, 2);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        spit(w.path("plain.txt"), pattern(10, 3));
        symlink("a.bin", (w.root + "/files/lnk").c_str());
        fs::create_directories(w.root + "/files/dir");
        CHECK(ov.unlink("/plain.txt") == 0 && !exists(w.path("plain.txt")) && !w.L->get_file_by_path("/Users/me/proj/plain.txt"));   // untracked: nothing to record
        CHECK(ov.unlink("/lnk") == 0 && !fs::is_symlink(w.root + "/files/lnk") && exists(w.path("a.bin")));
        CHECK(ov.unlink("/dir") == -EISDIR && ov.unlink("/") == -EISDIR && ov.unlink("/nope") == -ENOENT && ov.unlink("/.tierfs/q") == -ENOENT);
        // a tracked, replicated file: gone from the origin and from every lookup; its row is parked, not erased
        CHECK(ov.unlink("/a.bin") == 0 && !exists(w.path("a.bin")));
        OvStat st;
        CHECK(ov.getattr("/a.bin", &st) == -ENOENT && !listed(ov, "/", "a.bin") && !w.L->get_file_by_path("/Users/me/proj/a.bin"));
        auto parked = w.L->get_file(a.fid);
        CHECK(Ledger::is_retired_path(parked->path) && Ledger::former_path(*parked) == "/Users/me/proj/a.bin" && w.L->fsck().empty());
        // the name is free again, for a brand new file
        uint64_t fh = 0;
        CHECK(ov.create("/a.bin", 0644, O_WRONLY, &fh) == 0 && ov.release(fh) == 0 && w.L->get_file_by_path("/Users/me/proj/a.bin")->file_id != a.fid);
        // a remote file: deleted too; its bytes are still on the devices and in quarantine
        CHECK(w.drop("r.bin") && listed(ov, "/", "r.bin"));
        CHECK(ov.unlink("/r.bin") == 0 && ov.getattr("/r.bin", &st) == -ENOENT && !listed(ov, "/", "r.bin"));
        CHECK(w.L->list_quarantine(QuarantineState::HELD).size() == 1 && w.L->get_file(r.fid)->state == FileState::OFFLOADED && w.L->fsck().empty());
        CHECK(ov.unlink("/r.bin") == -ENOENT);
        // ... and can be undeleted
        struct timeval old_tv[2] = {{1000, 0}, {1000, 0}};
        utimes(w.root.c_str(), old_tv);
        utimes((w.root + "/files").c_str(), old_tv);
        CHECK(ov.undelete("/r.bin") == 0 && ov.getattr("/r.bin", &st) == 0 && st.remote && read_path_all(ov, "/r.bin", r.bytes.size()) == r.bytes);
        struct stat dst;
        CHECK(stat((w.root + "/files").c_str(), &dst) == 0 && dst.st_mtimespec.tv_sec > 1000);     // the directory looks changed, so the kernel looks again
        CHECK(ov.undelete("/r.bin") == -EEXIST && ov.undelete("/nope") == -ENOENT && ov.undelete("/") == -ENOENT);
        // undelete never covers a file that exists now
        CHECK(ov.unlink("/r.bin") == 0);
        CHECK(ov.create("/r.bin", 0644, O_WRONLY, &fh) == 0 && ov.release(fh) == 0);
        CHECK(ov.undelete("/r.bin") == -EEXIST);
        // a writer that has the file open keeps writing to it after the unlink (as on any filesystem), and closing it is harmless
        Item& o = w.make("open.bin", MiB + 7, 4);
        CHECK(ov.open("/open.bin", O_RDWR, &fh) == 0 && ov.unlink("/open.bin") == 0);
        CHECK(write_all_fh(ov, fh, 0, pattern(10, 9)) && ov.release(fh) == 0 && !exists(w.path("open.bin")) && ov.getattr("/open.bin", &st) == -ENOENT);
        (void)o;
        // a file frozen by a drop is waited for, then refused
        std::string why;
        Item& f = w.make("frozen.bin", MiB + 8, 5);
        FileRec frec = *w.L->get_file(f.fid);
        CHECK(ov.gate()->freeze(frec, &why) == true);
        CHECK(ov.unlink("/frozen.bin") == -EBUSY && exists(w.path("frozen.bin")));
        ov.gate()->unfreeze(frec);
        CHECK(ov.unlink("/frozen.bin") == 0);
    }

    {
        printf("== rename of files: local, replacing, remote; the ledger follows and the bytes are where the name says\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        Item& b = w.make("b.bin", MiB + 6, 2);
        Item& r = w.make("r.bin", MiB + 7, 3);
        Item& s = w.make("s.bin", MiB + 8, 4);
        fs::create_directories(w.root + "/files/sub");
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        OvStat st;
        // a replicated local file moves; its replication is stale (the manifest names the old path) until it is replicated again
        auto before = w.L->get_file(a.fid);
        CHECK(ov.rename("/a.bin", "/sub/a2.bin") == 0 && !exists(w.path("a.bin")) && slurp(w.path("sub/a2.bin")) == a.bytes);
        auto after = w.L->get_file(a.fid);
        CHECK(after->path == "/Users/me/proj/sub/a2.bin" && after->state == FileState::LOCAL && after->generation > before->generation && !w.L->get_file_by_path("/Users/me/proj/a.bin"));
        CHECK(ov.getattr("/a.bin", &st) == -ENOENT && ov.getattr("/sub/a2.bin", &st) == 0 && st.file_id == a.fid && listed(ov, "/sub", "a2.bin") && !listed(ov, "/", "a.bin"));
        CHECK(!w.E->drop(a.fid, w.consent, w.devs).ok);                           // renamed since it was replicated: not droppable
        CHECK(w.R->replicate(*w.da, w.ida, a.fid, w.path("sub/a2.bin")).ok && w.R->replicate(*w.db, w.idb, a.fid, w.path("sub/a2.bin")).ok);
        CHECK(w.E->drop(a.fid, w.consent, w.devs, ov.gate()).ok && !exists(w.path("sub/a2.bin")));
        CHECK(read_path_all(ov, "/sub/a2.bin", a.bytes.size()) == a.bytes);       // now served from the devices, at its new name
        // replacing a local file: the replaced one is deleted (not lost: the devices have it), the mover takes the name
        CHECK(ov.rename("/b.bin", "/s.bin") == 0 && slurp(w.path("s.bin")) == b.bytes && !exists(w.path("b.bin")));
        CHECK(w.L->get_file_by_path("/Users/me/proj/s.bin")->file_id == b.fid && Ledger::is_retired_path(w.L->get_file(s.fid)->path));
        // moving a REMOTE file: no bytes move, only the name
        CHECK(!w.E->drop(b.fid, w.consent, w.devs).ok);                          // b was renamed: modified since replication
        CHECK(w.drop("r.bin") && !exists(w.path("r.bin")));
        CHECK(ov.rename("/r.bin", "/sub/r2.bin") == 0 && !exists(w.path("sub/r2.bin")));
        CHECK(ov.getattr("/r.bin", &st) == -ENOENT && ov.getattr("/sub/r2.bin", &st) == 0 && st.remote && listed(ov, "/sub", "r2.bin") && !listed(ov, "/", "r.bin"));
        CHECK(read_path_all(ov, "/sub/r2.bin", r.bytes.size()) == r.bytes && w.L->get_file(r.fid)->state == FileState::OFFLOADED && w.L->fsck().empty());
        // a remote file replacing a local file, and a local file replacing a remote one
        spit(w.path("victim.txt"), pattern(20, 7));
        CHECK(ov.rename("/sub/r2.bin", "/victim.txt") == 0 && ov.getattr("/victim.txt", &st) == 0 && st.remote && !exists(w.path("victim.txt")));
        CHECK(read_path_all(ov, "/victim.txt", r.bytes.size()) == r.bytes);
        spit(w.path("mover.txt"), pattern(30, 8));
        CHECK(ov.rename("/mover.txt", "/victim.txt") == 0 && slurp(w.path("victim.txt")) == pattern(30, 8) && ov.getattr("/victim.txt", &st) == 0 && !st.remote);
        CHECK(Ledger::is_retired_path(w.L->get_file(r.fid)->path) && w.L->get_file(r.fid)->state == FileState::OFFLOADED);
        // an untracked file just moves
        spit(w.path("u1"), pattern(5, 1));
        CHECK(ov.rename("/u1", "/u2") == 0 && slurp(w.path("u2")) == pattern(5, 1) && !w.L->get_file_by_path("/Users/me/proj/u2"));
        // errors
        CHECK(ov.rename("/nope", "/x") == -ENOENT && ov.rename("/u2", "/nodir/x") == -ENOENT && ov.rename("/u2", "/sub") == -EISDIR);
        CHECK(ov.rename("/u2", "/u2") == 0 && ov.rename("/nope", "/nope") == -ENOENT && ov.rename("/", "/x") == -EBUSY && ov.rename("/u2", "/") == -EBUSY);
        CHECK(ov.rename("/u2", "/.tierfs/x") == -ENOENT && ov.rename("/.tierfs/q", "/x") == -ENOENT);
        // a remote file cannot move into a missing directory or onto a directory
        CHECK(w.R->replicate(*w.da, w.ida, b.fid, w.path("s.bin")).ok && w.R->replicate(*w.db, w.idb, b.fid, w.path("s.bin")).ok && w.E->drop(b.fid, w.consent, w.devs).ok);
        CHECK(ov.rename("/s.bin", "/nodir/x") == -ENOENT && ov.rename("/s.bin", "/sub") == -EISDIR && ov.getattr("/s.bin", &st) == 0 && st.remote);
        CHECK(w.L->fsck().empty());
    }

    {
        printf("== rename of a frozen file waits and then refuses\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        Item& b = w.make("b.bin", MiB + 5, 2);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
        std::string why;
        FileRec arec = *w.L->get_file(a.fid), brec = *w.L->get_file(b.fid);
        CHECK(ov.gate()->freeze(arec, &why));
        CHECK(ov.rename("/a.bin", "/a2.bin") == -EBUSY && exists(w.path("a.bin")));
        CHECK(ov.rename("/b.bin", "/a.bin") == -EBUSY && exists(w.path("b.bin")));       // replacing a frozen file is also refused
        ov.gate()->unfreeze(arec);
        // a writer arriving while the rename waits does not deadlock it
        CHECK(ov.gate()->freeze(brec, &why));
        std::atomic<int> rc{999};
        std::thread t([&] { rc = ov.rename("/b.bin", "/b2.bin"); });
        usleep(100000);
        ov.gate()->unfreeze(brec);
        t.join();
        CHECK(rc == 0 && exists(w.path("b2.bin")) && !exists(w.path("b.bin")));
        CHECK(ov.rename("/b2.bin", "/a.bin") == 0 && slurp(w.path("a.bin")) == b.bytes);
    }

    {
        printf("== rename of directories: every tracked file moves with it, local and remote, or nothing does\n");
        Lab w;
        Item& x = w.make("old/x.bin", MiB + 5, 1);
        Item& y = w.make("old/sub/y.bin", MiB + 6, 2);
        Item& z = w.make("old/z.bin", MiB + 7, 3);
        Item& other = w.make("older/q.bin", MiB + 8, 4);
        spit(w.path("old/plain.txt"), pattern(9, 5));
        CHECK(w.drop("old/sub/y.bin") && w.drop("old/z.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        OvStat st;
        CHECK(ov.rename("/old", "/new") == 0 && !exists(w.path("old")) && fs::is_directory(w.path("new")));
        CHECK(ov.getattr("/old", &st) == -ENOENT && ov.getattr("/old/z.bin", &st) == -ENOENT && ov.getattr("/new/z.bin", &st) == 0 && st.remote);
        CHECK(listed(ov, "/new", "z.bin") && listed(ov, "/new", "x.bin") && listed(ov, "/new", "plain.txt") && listed(ov, "/new/sub", "y.bin"));
        CHECK(read_path_all(ov, "/new/z.bin", z.bytes.size()) == z.bytes && read_path_all(ov, "/new/sub/y.bin", y.bytes.size()) == y.bytes && read_path_all(ov, "/new/x.bin", x.bytes.size()) == x.bytes);
        CHECK(w.L->get_file(z.fid)->path == "/Users/me/proj/new/z.bin" && w.L->get_file(z.fid)->state == FileState::OFFLOADED && w.L->get_file(x.fid)->state == FileState::LOCAL);
        CHECK(w.L->get_file(other.fid)->path == "/Users/me/proj/older/q.bin" && exists(w.path("older/q.bin")));   // "old" is not a prefix of "older"
        CHECK(w.L->fsck().empty());
        // into an existing EMPTY directory; over a non-empty one; over a file; into itself
        fs::create_directories(w.root + "/files/empty");
        CHECK(ov.rename("/new", "/empty") == 0 && listed(ov, "/empty", "z.bin") && !exists(w.path("new")));
        fs::create_directories(w.root + "/files/full");
        spit(w.path("full/f"), pattern(1, 1));
        CHECK(ov.rename("/empty", "/full") == -ENOTEMPTY && exists(w.path("empty")) && listed(ov, "/empty", "z.bin"));
        spit(w.path("afile"), pattern(1, 1));
        CHECK(ov.rename("/empty", "/afile") == -ENOTDIR && ov.rename("/empty", "/empty/inside") == -EINVAL && exists(w.path("empty")));
    }

    {
        printf("== a directory with a remote file in the destination, and a drop racing the rename\n");
        Lab w;
        Item& a = w.make("src/a.bin", MiB + 5, 1);
        Item& b = w.make("dst/b.bin", MiB + 6, 2);
        CHECK(w.drop("dst/b.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        // dst exists as a directory whose only content is a remote file: it is NOT empty
        CHECK(ov.rename("/src", "/dst") == -ENOTEMPTY && exists(w.path("src/a.bin")) && w.L->get_file(a.fid)->path == "/Users/me/proj/src/a.bin");
        // a name taken by a remote file blocks a directory rename
        spit(w.path("afile"), pattern(1, 1));
        CHECK(w.drop("src/a.bin") && ov.rename("/src", "/dst/b.bin") == -ENOTDIR);
        // a file in the directory is frozen by a drop: wait, then refuse
        Item& c = w.make("busy/c.bin", MiB + 7, 3);
        FileRec crec = *w.L->get_file(c.fid);
        std::string why;
        CHECK(ov.gate()->freeze(crec, &why) && ov.rename("/busy", "/busy2") == -EBUSY && exists(w.path("busy/c.bin")) && w.L->get_file(c.fid)->path == "/Users/me/proj/busy/c.bin");
        ov.gate()->unfreeze(crec);
        CHECK(ov.rename("/busy", "/busy2") == 0 && w.L->get_file(c.fid)->path == "/Users/me/proj/busy2/c.bin");
        (void)b;
    }

    {
        printf("== symlinks, permissions, times, ownership, free space\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1, 0644, 1500000000);
        Item& r = w.make("r.bin", MiB + 6, 2, 0644, 1500000000);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        OvStat st;
        std::string target;
        CHECK(ov.symlink("a.bin", "/lnk") == 0 && ov.readlink("/lnk", &target) == 0 && target == "a.bin" && ov.getattr("/lnk", &st) == 0 && st.kind == OvKind::Symlink);
        CHECK(ov.symlink("x", "/lnk") == -EEXIST && ov.symlink("x", "/") == -EEXIST && ov.symlink("x", "/nodir/l") == -ENOENT && ov.symlink("x", "/.tierfs/l") == -ENOENT);
        CHECK(w.drop("r.bin") && ov.symlink("x", "/r.bin") == -EEXIST);
        // chmod: a replicated local file (its replication goes stale), a remote one (ledger only), a directory, a link
        auto before = w.L->get_file(a.fid);
        CHECK(ov.chmod("/a.bin", 0600) == 0);
        struct stat fst;
        stat(w.path("a.bin").c_str(), &fst);
        auto after = w.L->get_file(a.fid);
        CHECK((fst.st_mode & 0777) == 0600 && after->mode == 0600 && after->state == FileState::LOCAL && after->generation > before->generation);
        CHECK(ov.chmod("/r.bin", 0640) == 0 && !exists(w.path("r.bin")) && ov.getattr("/r.bin", &st) == 0 && st.mode == 0640 && st.remote);
        CHECK(w.L->get_file(r.fid)->state == FileState::OFFLOADED && w.L->get_file(r.fid)->mode == 0640);
        fs::create_directories(w.root + "/files/dir");
        CHECK(ov.chmod("/dir", 0700) == 0 && ov.getattr("/dir", &st) == 0 && st.mode == 0700);
        CHECK(ov.chmod("/nope", 0600) == -ENOENT && ov.chmod("/.tierfs", 0600) == -ENOENT);
        // utimens
        CHECK(ov.utimens("/a.bin", 1234567890) == 0);
        stat(w.path("a.bin").c_str(), &fst);
        CHECK(fst.st_mtimespec.tv_sec == 1234567890 && w.L->get_file(a.fid)->mtime == 1234567890);
        CHECK(ov.utimens("/r.bin", 1111111111) == 0 && ov.getattr("/r.bin", &st) == 0 && st.mtime == 1111111111 && !exists(w.path("r.bin")));
        CHECK(ov.utimens("/a.bin", std::nullopt) == 0 && ov.utimens("/nope", std::nullopt) == -ENOENT && ov.utimens("/nope", 5) == -ENOENT);
        // hydrating restores the attributes the user set while the file was remote
        CHECK(ov.hydrate("/r.bin") == 0);
        stat(w.path("r.bin").c_str(), &fst);
        CHECK((fst.st_mode & 0777) == 0640 && fst.st_mtimespec.tv_sec == 1111111111 && slurp(w.path("r.bin")) == r.bytes);
        // ownership: only yourself
        CHECK(ov.chown("/a.bin", getuid(), getgid()) == 0 && ov.chown("/a.bin", -1, -1) == 0 && ov.chown("/a.bin", getuid() + 1, -1) == -EPERM && ov.chown("/a.bin", -1, getgid() + 12345) == -EPERM);
        CHECK(ov.chown("/nope", -1, -1) == -ENOENT);
        // free space is the origin volume's
        Overlay::FsStats fs1;
        CHECK(ov.statfs(&fs1) == 0 && fs1.blocks > 0 && fs1.block_size > 0 && fs1.blocks_free <= fs1.blocks && fs1.blocks_avail <= fs1.blocks_free && fs1.files > 0);
    }

    {
        printf("== extended attributes: local, remote (from the manifest), and the ones that need the file\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);        // the test lab gives a.bin the attribute com.example.note=kept
        Item& b = w.make("b.bin", MiB + 6, 2);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        std::string v;
        CHECK(xget(ov, "/a.bin", "com.example.note", &v) == 4 && v == "kept" && xget(ov, "/a.bin", "com.example.none") == -ENOATTR && xget(ov, "/nope", "x") == -ENOENT);
        char names[512];
        int64_t ln = ov.listxattr("/a.bin", names, sizeof names);
        CHECK(ln > 0 && std::string(names, static_cast<size_t>(ln)).find("com.example.note") != std::string::npos);
        // setting one on a replicated local file invalidates its replication (the manifest has the attributes)
        auto before = w.L->get_file(b.fid);
        CHECK(ov.setxattr("/b.bin", "com.example.tag", reinterpret_cast<const uint8_t*>("blue"), 4, 0) == 0 && xget(ov, "/b.bin", "com.example.tag", &v) == 4 && v == "blue");
        CHECK(w.L->get_file(b.fid)->state == FileState::LOCAL && w.L->get_file(b.fid)->generation > before->generation);
        CHECK(ov.removexattr("/b.bin", "com.example.tag") == 0 && xget(ov, "/b.bin", "com.example.tag") == -ENOATTR && ov.removexattr("/b.bin", "com.example.tag") == -ENOATTR);
        // a remote file answers from its manifest
        CHECK(w.drop("a.bin") && !exists(w.path("a.bin")));
        CHECK(xget(ov, "/a.bin", "com.example.note", &v) == 4 && v == "kept" && ov.getxattr("/a.bin", "com.example.note", nullptr, 0) == 4);
        uint8_t tiny[2];
        CHECK(ov.getxattr("/a.bin", "com.example.note", tiny, sizeof tiny) == -ERANGE && xget(ov, "/a.bin", "com.example.zzz") == -ENOATTR);
        ln = ov.listxattr("/a.bin", nullptr, 0);   // (macOS adds attributes of its own, so look for ours rather than expecting only ours)
        CHECK(ln >= static_cast<int64_t>(strlen("com.example.note") + 1) && ov.listxattr("/a.bin", names, 3) == -ERANGE);
        CHECK(ov.listxattr("/a.bin", names, sizeof names) == ln && std::string(names, static_cast<size_t>(ln)).find(std::string("com.example.note") + '\0') != std::string::npos);
        // the manifest is cached: with every device down the answer is still there
        w.sa.stop();
        w.sb.stop();
        CHECK(xget(ov, "/a.bin", "com.example.note", &v) == 4 && v == "kept");
        // ... but a remote file never seen before cannot answer without a device
        Overlay cold(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        CHECK(xget(cold, "/a.bin", "com.example.note") == -EIO && cold.listxattr("/a.bin", names, sizeof names) == -EIO);
        w.sa.start(w.devdir(0));
        w.sb.start(w.devdir(1));
        // changing an attribute of a remote file hydrates it first (from the quarantine copy)
        CHECK(ov.setxattr("/a.bin", "com.example.new", reinterpret_cast<const uint8_t*>("x"), 1, 0) == 0);
        CHECK(exists(w.path("a.bin")) && ov.stats().hydrations_quarantine == 1 && xget(ov, "/a.bin", "com.example.new", &v) == 1 && v == "x" && w.L->get_file(a.fid)->state == FileState::LOCAL);
        CHECK(slurp(w.path("a.bin")) == a.bytes);
    }

    {
        printf("== setting and removing an attribute of a remote file; xattr on missing things\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        CHECK(w.drop("a.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 300), w.E.get());
        CHECK(ov.removexattr("/a.bin", "com.example.note") == 0 && exists(w.path("a.bin")) && xget(ov, "/a.bin", "com.example.note") == -ENOATTR);
        CHECK(ov.setxattr("/nope", "x", reinterpret_cast<const uint8_t*>("1"), 1, 0) == -ENOENT && ov.removexattr("/nope", "x") == -ENOENT && ov.listxattr("/nope", nullptr, 0) == -ENOENT);
        CHECK(ov.setxattr("/.tierfs", "x", reinterpret_cast<const uint8_t*>("1"), 1, 0) == -ENOENT);
        CHECK(slurp(w.path("a.bin")) == a.bytes && w.L->fsck().empty());
    }

    {
        printf("== renames and deletions racing replication and drops: every name still leads to exactly the bytes it should\n");
        Lab w;
        const int nfiles = 4, rounds = 18;
        for (int i = 0; i < nfiles; i++) w.make("d1/f" + std::to_string(i) + ".bin", MiB + 100 + i, static_cast<uint8_t>(i + 1));
        fs::create_directories(w.root + "/files/d2");
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        std::atomic<bool> stop{false};
        std::atomic<int> bad{0}, drops{0};
        std::thread maint([&] {
            int i = 0;
            while (!stop) {
                std::string id = w.items["d1/f" + std::to_string(i++ % nfiles) + ".bin"].fid;
                std::lock_guard<std::mutex> g(ov.engine_mutex());
                auto f = w.L->get_file(id);
                if (!f || Ledger::is_retired_path(f->path)) continue;
                std::string local = w.root + "/files" + f->path.substr(std::string("/Users/me/proj").size());
                if (f->state == FileState::LOCAL || f->state == FileState::REPLICATING || (f->state == FileState::REPLICATED && w.L->committed_weight(id, f->current_version) < 2.0)) {
                    if (exists(local)) { w.R->replicate(*w.da, w.ida, id, local); w.R->replicate(*w.db, w.idb, id, local); }
                }
                f = w.L->get_file(id);
                if (f && f->state == FileState::REPLICATED && w.E->drop(id, w.consent, w.devs, ov.gate()).ok) drops++;
            }
        });
        std::vector<std::thread> movers;
        for (int i = 0; i < nfiles; i++)
            movers.emplace_back([&, i] {
                std::string name = "f" + std::to_string(i) + ".bin";
                std::string here = "/d1/" + name, there = "/d2/" + name;
                bool at_d1 = true;
                for (int r = 0; r < rounds; r++) {
                    int rc = ov.rename(at_d1 ? here : there, at_d1 ? there : here);
                    if (rc == 0) at_d1 = !at_d1; else { bad++; printf("      rename %s failed: %d\n", name.c_str(), rc); }
                    if (r % 4 == 3) {   // touch the file for writing without changing it: a remote file is brought back, so it can be replicated and dropped again
                        uint64_t fh = 0;
                        int orc = ov.open(at_d1 ? here : there, O_WRONLY, &fh);
                        if (orc != 0) { bad++; printf("      open %s failed: %d\n", name.c_str(), orc); }
                        else ov.release(fh);
                    }
                    usleep(r % 3 == 2 ? 700000 : 5000);
                }
                if (!at_d1 && ov.rename(there, here) != 0) bad++;
            });
        for (auto& t : movers) t.join();
        stop = true;
        maint.join();
        printf("      (%d drops happened during the run)\n", drops.load());
        CHECK(bad == 0);
        std::vector<OvEntry> d1, d2;
        CHECK(ov.readdir("/d1", &d1) == 0 && ov.readdir("/d2", &d2) == 0 && d1.size() == static_cast<size_t>(nfiles) && d2.empty());
        for (int i = 0; i < nfiles; i++) {
            std::string name = "f" + std::to_string(i) + ".bin";
            Item& it = w.items["d1/" + name];
            CHECK(read_path_all(ov, "/d1/" + name, it.bytes.size()) == it.bytes);
            OvStat st;
            CHECK(ov.getattr("/d2/" + name, &st) == -ENOENT && w.L->get_file(it.fid)->path == "/Users/me/proj/d1/" + name);
        }
        CHECK(w.L->fsck().empty() && w.L->open_intents().empty());
    }

    {
        printf("== a directory renamed back and forth while its files are replicated and dropped: all of them always reachable at the current name\n");
        Lab w;
        const int nfiles = 4, flips = 12;
        for (int i = 0; i < nfiles; i++) w.make("da/f" + std::to_string(i) + ".bin", MiB + 200 + i, static_cast<uint8_t>(i + 10));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w), w.E.get());
        std::atomic<bool> stop{false};
        std::atomic<int> drops{0};
        std::thread maint([&] {
            int i = 0;
            while (!stop) {
                std::string id = w.items["da/f" + std::to_string(i++ % nfiles) + ".bin"].fid;
                std::lock_guard<std::mutex> g(ov.engine_mutex());
                auto f = w.L->get_file(id);
                if (!f) continue;
                std::string local = w.root + "/files" + f->path.substr(std::string("/Users/me/proj").size());
                if (f->state == FileState::LOCAL || f->state == FileState::REPLICATING || (f->state == FileState::REPLICATED && w.L->committed_weight(id, f->current_version) < 2.0)) {
                    if (exists(local)) { w.R->replicate(*w.da, w.ida, id, local); w.R->replicate(*w.db, w.idb, id, local); }
                }
                f = w.L->get_file(id);
                if (f && f->state == FileState::REPLICATED && w.E->drop(id, w.consent, w.devs, ov.gate()).ok) drops++;
            }
        });
        bool at_da = true;
        int failures_seen = 0;
        for (int i = 0; i < flips; i++) {
            int rc = ov.rename(at_da ? "/da" : "/db", at_da ? "/db" : "/da");
            if (rc == 0) at_da = !at_da; else { failures_seen++; printf("      directory rename failed: %d\n", rc); }
            usleep(i % 3 == 2 ? 800000 : 10000);
            // while the maintenance thread works, every file is readable at the current name, wherever its bytes are
            for (int k = 0; k < nfiles; k++) {
                Item& it = w.items["da/f" + std::to_string(k) + ".bin"];
                std::string path = std::string(at_da ? "/da/f" : "/db/f") + std::to_string(k) + ".bin";
                if (read_path_all(ov, path, it.bytes.size()) != it.bytes) failures_seen++;
            }
        }
        stop = true;
        maint.join();
        printf("      (%d drops happened during the run)\n", drops.load());
        CHECK(failures_seen == 0);
        if (!at_da) CHECK(ov.rename("/db", "/da") == 0);
        for (int k = 0; k < nfiles; k++) {
            Item& it = w.items["da/f" + std::to_string(k) + ".bin"];
            CHECK(read_path_all(ov, "/da/f" + std::to_string(k) + ".bin", it.bytes.size()) == it.bytes && w.L->get_file(it.fid)->path == "/Users/me/proj/da/f" + std::to_string(k) + ".bin");
        }
        CHECK(!exists(w.path("db")) && w.L->fsck().empty() && w.L->open_intents().empty());
    }

    {
        printf("== files in the middle of a drop or a hydration: namespace operations wait, then refuse\n");
        Lab w;
        Item& h = w.make("h.bin", MiB + 5, 1);
        w.make("dd/m.bin", MiB + 6, 2);
        w.make("c.bin", MiB + 7, 3);
        CHECK(w.drop("h.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
        // (1) a remote file whose hydration is under way
        CHECK(w.L->begin_hydrate(h.fid).ok);
        CHECK(ov.unlink("/h.bin") == -EBUSY && ov.rename("/h.bin", "/h2.bin") == -EBUSY && ov.chmod("/h.bin", 0600) == -EBUSY && ov.utimens("/h.bin", 5) == -EBUSY);
        CHECK(w.L->abort_hydrate(h.fid).ok);
        // (2) a local file in the middle of a drop (the ledger says DROPPING, the bytes are still in the origin)
        int u = 999, r = 999, c = 999, d = 999;
        w.E->on_step = [&](const char* step) {
            if (std::string(step) != "before_rename") return;
            u = ov.unlink("/dd/m.bin");
            r = ov.rename("/dd/m.bin", "/dd/m2.bin");
            c = ov.chmod("/dd/m.bin", 0600);
            d = ov.rmdir("/dd");
        };
        CHECK(w.drop("dd/m.bin"));
        w.E->on_step = nullptr;
        CHECK(u == -EBUSY && r == -EBUSY && c == -EBUSY && d == -EBUSY);
        // (3) a drop that was cut off after the move: DROPPING, no bytes in the origin
        w.close_ledger();
        CHECK(spawn_drop_crash(w, w.items["c.bin"].fid, "drop.after_sync"));
        w.open_ledger();
        Overlay ov2(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
        CHECK(w.L->get_file(w.items["c.bin"].fid)->state == FileState::DROPPING);
        CHECK(ov2.unlink("/c.bin") == -EBUSY && ov2.rename("/c.bin", "/c2.bin") == -EBUSY && ov2.chmod("/c.bin", 0600) == -EBUSY);
    }

    {
        printf("== errors are reported as what they are, and nothing is tracked or forgotten by mistake\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1, 0644, 1500000000);
        w.make("ro/f.bin", MiB + 6, 2);
        Item& v = w.make("v.bin", MiB + 7, 3);
        Item& r1 = w.make("r1.bin", MiB + 8, 4);
        Item& r2 = w.make("r2.bin", MiB + 9, 5);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
        OvStat st;
        std::string why;
        fs::create_directories(w.root + "/files/locked");
        spit(w.path("locked/x"), pattern(5, 1));
        chmod((w.root + "/files/locked").c_str(), 0);
        uint8_t buf[16];
        CHECK(ov.unlink("/locked/x") == -EACCES && ov.rename("/locked/x", "/y") == -EACCES && ov.chmod("/locked/x", 0600) == -EACCES);
        CHECK(ov.getxattr("/locked/x", "a", buf, sizeof buf) == -EACCES && ov.listxattr("/locked/x", nullptr, 0) == -EACCES);
        CHECK(ov.setxattr("/locked/x", "a", buf, 1, 0) == -EACCES && ov.removexattr("/locked/x", "a") == -EACCES);
        chmod((w.root + "/files/locked").c_str(), 0755);
        // a directory we cannot write to: the delete fails, and the file is neither forgotten nor left registered as a writer
        FileRec rorec = *w.L->get_file(w.items["ro/f.bin"].fid);
        chmod((w.root + "/files/ro").c_str(), 0555);
        CHECK(ov.unlink("/ro/f.bin") == -EACCES && exists(w.path("ro/f.bin")) && w.L->get_file_by_path("/Users/me/proj/ro/f.bin"));
        CHECK(ov.gate()->freeze(rorec, &why));
        ov.gate()->unfreeze(rorec);
        chmod((w.root + "/files/ro").c_str(), 0755);
        // a tracked file that vanished behind our back is not a file: no delete, rename, chmod or attribute call may act on its row
        unlink(w.path("v.bin").c_str());
        size_t rows = w.L->list_files().size();
        CHECK(ov.unlink("/v.bin") == -ENOENT && ov.rename("/v.bin", "/v2.bin") == -ENOENT && ov.chmod("/v.bin", 0600) == -ENOENT && ov.utimens("/v.bin", 5) == -ENOENT);
        CHECK(ov.getxattr("/v.bin", "a", buf, sizeof buf) == -ENOENT && ov.listxattr("/v.bin", nullptr, 0) == -ENOENT && ov.setxattr("/v.bin", "a", buf, 1, 0) == -ENOENT);
        CHECK(w.L->get_file_by_path("/Users/me/proj/v.bin") && w.L->get_file(v.fid)->state == FileState::REPLICATED && w.L->list_files().size() == rows);
        // an untracked file is changed without ever being tracked
        spit(w.path("plain.txt"), pattern(10, 4));
        rows = w.L->list_files().size();
        uint8_t one = 1;
        CHECK(ov.chmod("/plain.txt", 0600) == 0 && ov.utimens("/plain.txt", 123456789) == 0 && ov.setxattr("/plain.txt", "com.example.t", &one, 1, 0) == 0 && ov.unlink("/plain.txt") == 0);
        spit(w.path("plain2.txt"), pattern(10, 4));
        CHECK(ov.rename("/plain2.txt", "/plain3.txt") == 0 && ov.unlink("/plain3.txt") == 0 && w.L->list_files().size() == rows);
        // renaming a directory to itself does nothing; a sibling's files do not count as its content
        fs::create_directories(w.root + "/files/dir");
        CHECK(ov.rename("/dir", "/dir") == 0 && fs::is_directory(w.path("dir")));
        // a failing attribute call does not touch the ledger and does not leave a writer behind
        FileRec arec = *w.L->get_file(a.fid);
        uint8_t kept[4] = {'k', 'e', 'p', 't'};
        uint64_t ev = w.L->event_count();
        CHECK(ov.setxattr("/a.bin", "com.example.note", kept, 4, XATTR_CREATE) == -EEXIST);          // already there: XATTR_CREATE refuses
        CHECK(w.L->event_count() == ev + 1);                                                           // only the "about to modify" event, not an attribute change
        CHECK(ov.gate()->freeze(arec, &why));
        ov.gate()->unfreeze(arec);
        CHECK(ov.setxattr("/a.bin", "com.example.note", kept, 4, XATTR_REPLACE) == 0 && ov.setxattr("/a.bin", "com.example.zzz", kept, 4, XATTR_REPLACE) == -ENOATTR);
        // special mode bits and the time are applied exactly; "no time" changes nothing
        CHECK(ov.chmod("/a.bin", 04755) == 0);
        struct stat fst;
        stat(w.path("a.bin").c_str(), &fst);
        CHECK((fst.st_mode & 07777) == 04755 && w.L->get_file(a.fid)->mode == 04755);
        CHECK(ov.chmod("/a.bin", 0644) == 0 && w.replicate("a.bin"));
        auto before = w.L->get_file(a.fid);
        CHECK(ov.utimens("/a.bin", std::nullopt) == 0 && w.L->get_file(a.fid)->generation == before->generation && w.L->get_file(a.fid)->state == FileState::REPLICATED);
        // free space matches the volume
        Overlay::FsStats f1;
        struct statvfs sv;
        CHECK(ov.statfs(&f1) == 0 && statvfs(w.root.c_str(), &sv) == 0 && f1.block_size == (sv.f_frsize ? sv.f_frsize : sv.f_bsize) && f1.blocks == sv.f_blocks);
        CHECK(f1.blocks_free + 20000 > sv.f_bfree && f1.blocks_free < sv.f_bfree + 20000 && f1.blocks_free < f1.blocks && f1.blocks_avail + 20000 > sv.f_bavail && f1.files == sv.f_files);
        // undelete: not over a file that is there, not for a file that cannot come back
        CHECK(w.drop("r1.bin") && ov.unlink("/r1.bin") == 0);
        spit(w.path("r1.bin"), pattern(7, 7));                                                        // a file appears there behind our back
        CHECK(ov.undelete("/r1.bin") == -EEXIST && slurp(w.path("r1.bin")) == pattern(7, 7));
        CHECK(ov.unlink("/a.bin") == 0 && ov.undelete("/a.bin") == -EINVAL);                           // a deleted local file has no bytes to come back to
        // a remote file replacing another remote file retires the replaced one
        CHECK(w.drop("r2.bin") && w.drop("v.bin") == false);
        Item& r3 = w.make("r3.bin", MiB + 10, 6);
        CHECK(w.drop("r3.bin") && ov.rename("/r3.bin", "/r2.bin") == 0);
        CHECK(Ledger::is_retired_path(w.L->get_file(r2.fid)->path) && w.L->get_file(r3.fid)->path == "/Users/me/proj/r2.bin" && w.L->get_file(r3.fid)->state == FileState::OFFLOADED);
        CHECK(read_path_all(ov, "/r2.bin", r3.bytes.size()) == r3.bytes);
        // a remote file cannot be moved under a file
        spit(w.path("afile"), pattern(1, 1));
        Item& r4 = w.make("r4.bin", MiB + 11, 7);
        CHECK(w.drop("r4.bin") && ov.rename("/r4.bin", "/afile/x") == -ENOTDIR && ov.getattr("/r4.bin", &st) == 0);
        (void)r1; (void)r4;
    }

    {
        printf("== a directory's neighbours are not its contents: names that merely start the same way\n");
        Lab w;
        Item& s = w.make("src/f.bin", MiB + 5, 1);
        Item& sib = w.make("srcsib/g.bin", MiB + 6, 2);
        Item& d2 = w.make("dstx2/z.bin", MiB + 7, 3);
        fs::create_directories(w.root + "/files/dstx");
        CHECK(w.drop("dstx2/z.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
        std::string why;
        FileRec sibrec = *w.L->get_file(sib.fid);
        CHECK(ov.gate()->freeze(sibrec, &why));                              // a neighbour is frozen by a drop: not our business
        CHECK(ov.rename("/src", "/dstx") == 0 && w.L->get_file(s.fid)->path == "/Users/me/proj/dstx/f.bin");   // ... and neither are remote files in "dstx2"
        ov.gate()->unfreeze(sibrec);
        CHECK(ov.rmdir("/srcsib") == -ENOTEMPTY);
        fs::create_directories(w.root + "/files/old");
        CHECK(ov.rmdir("/old") == 0);                                        // "old" is not "older": nothing remote is inside it
        (void)d2;
    }

    {
        printf("== a rename the ledger cannot follow is undone: the directory is never half-renamed\n");
        Lab w;
        Item& f = w.make("s/f.bin", MiB + 5, 1);
        w.make("t/f.bin", MiB + 6, 2);
        unlink(w.path("t/f.bin").c_str());                                   // t is an empty directory, but the ledger still has a file named t/f.bin
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
        CHECK(ov.rename("/s", "/t") == -EIO);
        CHECK(fs::is_directory(w.path("s")) && exists(w.path("s/f.bin")) && w.L->get_file(f.fid)->path == "/Users/me/proj/s/f.bin" && w.L->fsck().empty());
        CHECK(fs::is_directory(w.path("t")) && !exists(w.path("t/f.bin")));
    }

    {
        printf("== remote attributes: the manifest of the CURRENT version is used, a dead device is skipped, a failed hydration is reported\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);      // carries com.example.note=kept
        CHECK(w.drop("a.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
        std::string v;
        CHECK(xget(ov, "/a.bin", "com.example.note", &v) == 4 && v == "kept");
        // change it (hydrates), replicate the new version, drop again: the cache must not serve version 1's attributes
        uint8_t nv[2] = {'v', '2'};
        CHECK(ov.setxattr("/a.bin", "com.example.note", nv, 2, 0) == 0);
        CHECK(w.replicate("a.bin") && w.L->get_file(a.fid)->current_version == 2 && w.drop("a.bin"));
        CHECK(xget(ov, "/a.bin", "com.example.note", &v) == 2 && v == "v2");
        // exact buffers are enough
        uint8_t exact[2];
        CHECK(ov.getxattr("/a.bin", "com.example.note", exact, 2) == 2);
        char list[512];
        int64_t need = ov.listxattr("/a.bin", nullptr, 0);
        CHECK(need > 0 && ov.listxattr("/a.bin", list, static_cast<size_t>(need)) == need);
    }

    {
        printf("== attributes of a remote file when one device is dead: whichever one it is\n");
        for (int dead = 0; dead < 2; dead++) {
            Lab w;
            w.make("a.bin", MiB + 5, 1);
            CHECK(w.drop("a.bin"));
            (dead == 0 ? w.sa : w.sb).stop();
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
            std::string v;
            CHECK(xget(ov, "/a.bin", "com.example.note", &v) == 4 && v == "kept");
        }
    }

    {
        printf("== local attribute lists and buffers; changing a remote file's attributes when it cannot be brought back\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        Item& b = w.make("b.bin", MiB + 6, 2);
        CHECK(w.drop("b.bin"));
        for (auto& q : w.L->list_quarantine(QuarantineState::HELD)) CHECK(w.E->purge(q.intent_id, w.devs, true).ok);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 250), w.E.get());
        char names[512];
        int64_t n = ov.listxattr("/a.bin", names, sizeof names);
        CHECK(n > 0 && ov.listxattr("/a.bin", names, 1) == -ERANGE && ov.listxattr("/a.bin", names, static_cast<size_t>(n)) == n);
        uint8_t four[4];
        CHECK(ov.getxattr("/a.bin", "com.example.note", four, 4) == 4 && ov.getxattr("/a.bin", "com.example.note", four, 2) == -ERANGE);
        w.sa.stop();
        w.sb.stop();
        uint8_t x = 1;
        CHECK(ov.setxattr("/b.bin", "com.example.t", &x, 1, 0) == -EIO && ov.removexattr("/b.bin", "com.example.note") == -EIO);
        CHECK(!exists(w.path("b.bin")) && w.L->get_file(b.fid)->state == FileState::OFFLOADED && w.L->fsck().empty());
        (void)a;
    }

    {
        printf("== deleting a remote file while it is being hydrated waits for the hydration, then deletes the file\n");
        Lab w;
        Item& f = w.make("f.bin", 3 * MiB + 5, 1);
        CHECK(w.drop("f.bin"));
        for (auto& q : w.L->list_quarantine(QuarantineState::HELD)) CHECK(w.E->purge(q.intent_id, w.devs, true).ok);
        w.sa.stop(); w.sa.faults = "slow=250"; w.sa.start(w.devdir(0));
        w.sb.stop(); w.sb.faults = "slow=250"; w.sb.start(w.devdir(1));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 20000), w.E.get());
        std::atomic<int> hrc{999}, urc{999};
        auto t0 = std::chrono::steady_clock::now();
        std::thread h([&] { hrc = ov.hydrate("/f.bin"); });
        usleep(150000);
        CHECK(w.L->get_file(f.fid)->state == FileState::HYDRATING);
        std::thread u([&] { urc = ov.unlink("/f.bin"); });
        h.join();
        u.join();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        CHECK(hrc == 0 && urc == 0 && ms < 8000);                           // it was woken when the hydration ended, not at the deadline
        OvStat st;
        CHECK(!exists(w.path("f.bin")) && ov.getattr("/f.bin", &st) == -ENOENT && Ledger::is_retired_path(w.L->get_file(f.fid)->path) && w.L->fsck().empty());
    }

    for (int op = 0; op < 2; op++) {
        printf("== %s of a remote file while it is being hydrated: waits, then acts on the file that has just come back\n", op == 0 ? "renaming" : "chmod-ing");
        Lab w;
        Item& f = w.make("f.bin", 3 * MiB + 5, 1);
        CHECK(w.drop("f.bin"));
        for (auto& q : w.L->list_quarantine(QuarantineState::HELD)) CHECK(w.E->purge(q.intent_id, w.devs, true).ok);
        w.sa.stop(); w.sa.faults = "slow=250"; w.sa.start(w.devdir(0));
        w.sb.stop(); w.sb.faults = "slow=250"; w.sb.start(w.devdir(1));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 20000), w.E.get());
        std::atomic<int> hrc{999}, orc{999};
        std::thread h([&] { hrc = ov.hydrate("/f.bin"); });
        usleep(150000);
        CHECK(w.L->get_file(f.fid)->state == FileState::HYDRATING);
        std::thread u([&] { orc = op == 0 ? ov.rename("/f.bin", "/g.bin") : ov.chmod("/f.bin", 0600); });
        h.join();
        u.join();
        CHECK(hrc == 0 && orc == 0);
        if (op == 0) CHECK(!exists(w.path("f.bin")) && slurp(w.path("g.bin")) == f.bytes && w.L->get_file(f.fid)->path == "/Users/me/proj/g.bin");
        else {
            struct stat st;
            CHECK(stat(w.path("f.bin").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600 && w.L->get_file(f.fid)->mode == 0600 && slurp(w.path("f.bin")) == f.bytes);
        }
        CHECK(w.L->fsck().empty());
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
