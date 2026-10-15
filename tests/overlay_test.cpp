// Tests of the overlay's read side: what a path is, and where its bytes come from. Real files in a real origin
// folder, two real device servers, real encryption, the real drop engine moving files out of the origin.
// The invariant: a read returns exactly the original bytes, or fails with EIO; never anything else.
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
#include <functional>
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
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-ovtest-XXXXXX";
    std::vector<char> buf(t.begin(), t.end());
    buf.push_back(0);
    return mkdtemp(buf.data());
}
static uint16_t port_base() { return getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9531; }
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
    bool drop(const std::string& name) { return E->drop(items[name].fid, consent, devs).ok; }
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


static DeviceMap devmap(Lab& w) { return {{w.ida, w.da.get()}, {w.idb, w.db.get()}}; }
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
static OverlayConfig cfg_for(Lab& w, size_t cache = 64u << 20) {
    OverlayConfig c;
    c.origin_dir = w.root + "/files";
    c.logical_prefix = "/Users/me/proj";   // given without the trailing slash on purpose
    c.cache_bytes = cache;
    return c;
}
// Reads the whole thing through the overlay in `step`-byte pieces.
static Bytes read_all(Overlay& ov, const std::string& path, uint64_t size, size_t step) {
    Bytes out;
    std::vector<uint8_t> buf(step);
    for (uint64_t off = 0; off < size + step; off += step) {
        int64_t n = ov.read(path, off, step, buf.data());
        if (n < 0) return Bytes{};
        out.insert(out.end(), buf.begin(), buf.begin() + n);
        if (n == 0) break;
    }
    return out;
}
static bool has_name(const std::vector<OvEntry>& v, const std::string& n) { for (auto& e : v) if (e.name == n) return true; return false; }
static const OvEntry* find_name(const std::vector<OvEntry>& v, const std::string& n) { for (auto& e : v) if (e.name == n) return &e; return nullptr; }

int main() {
    signal(SIGPIPE, SIG_IGN);

    {
        printf("== path resolution: only paths inside the origin, never the bookkeeping directory\n");
        Lab w;
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
        std::string op, lp, rel;
        CHECK(ov.resolve("/a/b.txt", &op, &lp, &rel) && op == w.root + "/files/a/b.txt" && lp == "/Users/me/proj/a/b.txt" && rel == "a/b.txt");
        CHECK(ov.resolve("/", &op, &lp, &rel) && op == w.root + "/files" && lp == "/Users/me/proj/" && rel.empty());
        CHECK(ov.resolve("//a/./b//", &op, &lp, &rel) && rel == "a/b");
        CHECK(!ov.resolve("/a/../b", &op, &lp) && !ov.resolve("/..", &op, &lp) && !ov.resolve("a/b", &op, &lp) && !ov.resolve("", &op, &lp));
        CHECK(!ov.resolve("/.tierfs", &op, &lp) && !ov.resolve("/.tierfs/quarantine/x", &op, &lp) && ov.resolve("/sub/.tierfs", &op, &lp));
        CHECK(!ov.resolve(std::string("/a\0b", 4), &op, &lp));
        OvStat st;
        CHECK(ov.getattr("/.tierfs", &st) == -ENOENT && ov.getattr("/../x", &st) == -ENOENT);
        std::vector<uint8_t> buf(10);
        CHECK(ov.read("/.tierfs/quarantine/x", 0, 10, buf.data()) == -ENOENT);
        std::vector<OvEntry> es;
        CHECK(ov.readdir("/.tierfs", &es) == -ENOENT);
    }

    {
        printf("== local files and directories come straight from the origin\n");
        Lab w;
        Item& a = w.make("a.bin", 2 * MiB + 100, 1, 0640, 1500000000);
        w.make("sub/deep/x.bin", MiB + 7, 2, 0600, 1400000000);
        symlink("a.bin", (w.root + "/files/link").c_str());
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
        OvStat st;
        CHECK(ov.getattr("/a.bin", &st) == 0 && st.kind == OvKind::File && st.size == a.bytes.size() && st.mtime == 1500000000 && st.mode == 0640 && !st.remote && st.file_id == a.fid);
        CHECK(ov.getattr("/", &st) == 0 && st.kind == OvKind::Dir && ov.getattr("/sub", &st) == 0 && st.kind == OvKind::Dir && ov.getattr("/sub/deep", &st) == 0);
        CHECK(ov.getattr("/link", &st) == 0 && st.kind == OvKind::Symlink);
        std::string target;
        CHECK(ov.readlink("/link", &target) == 0 && target == "a.bin" && ov.readlink("/a.bin", &target) == -EINVAL && ov.readlink("/nope", &target) == -ENOENT);
        CHECK(ov.getattr("/nope", &st) == -ENOENT && ov.getattr("/sub/nope/x", &st) == -ENOENT && ov.getattr("/a.bin/x", &st) == -ENOENT);
        std::vector<OvEntry> es;
        CHECK(ov.readdir("/", &es) == 0 && es.size() == 3 && has_name(es, "a.bin") && has_name(es, "sub") && has_name(es, "link"));
        CHECK(es.size() == 3 && es[0].name == "a.bin" && es[1].name == "link" && es[2].name == "sub");   // sorted: a stable order for callers
        CHECK(!has_name(es, ".tierfs") && find_name(es, "sub")->kind == OvKind::Dir && find_name(es, "a.bin")->kind == OvKind::File && !find_name(es, "a.bin")->remote);
        CHECK(ov.readdir("/sub/deep", &es) == 0 && es.size() == 1 && es[0].name == "x.bin");
        CHECK(ov.readdir("/a.bin", &es) < 0 && ov.readdir("/nope", &es) == -ENOENT);
        std::vector<uint8_t> buf(4096);
        CHECK(ov.read("/a.bin", 0, 100, buf.data()) == 100 && memcmp(buf.data(), a.bytes.data(), 100) == 0);
        CHECK(ov.read("/a.bin", 2 * MiB, 4096, buf.data()) == 100 && memcmp(buf.data(), a.bytes.data() + 2 * MiB, 100) == 0);   // short at EOF
        CHECK(ov.read("/a.bin", 2 * MiB + 100, 10, buf.data()) == 0 && ov.read("/a.bin", 10 * MiB, 10, buf.data()) == 0);
        CHECK(ov.read("/a.bin", 5, 0, buf.data()) == 0 && ov.read("/sub", 0, 10, buf.data()) == -EISDIR && ov.read("/nope", 0, 10, buf.data()) == -ENOENT);
        CHECK(ov.stats().chunk_fetches == 0);   // nothing remote was touched
    }

    {
        printf("== a dropped file is still there: same listing, same attributes, same bytes, fetched in pieces\n");
        Lab w;
        Item& a = w.make("a.bin", 3 * MiB + 1000, 1, 0640, 1500000000);
        Item& n = w.make("sub/deep/n.bin", 2 * MiB + 5, 2, 0600, 1400000000);
        Item& keep = w.make("keep.txt", 100, 3);
        CHECK(a.chunks.size() == 4 && w.drop("a.bin") && w.drop("sub/deep/n.bin"));
        CHECK(!exists(w.path("a.bin")) && !exists(w.path("sub/deep/n.bin")) && exists(w.path("keep.txt")));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
        OvStat st;
        CHECK(ov.getattr("/a.bin", &st) == 0 && st.remote && st.kind == OvKind::File && st.size == a.bytes.size() && st.mtime == 1500000000 && st.mode == 0640 && st.file_id == a.fid);
        CHECK(ov.getattr("/sub/deep/n.bin", &st) == 0 && st.remote && st.mode == 0600);
        CHECK(ov.getattr("/keep.txt", &st) == 0 && !st.remote);
        std::vector<OvEntry> es;
        CHECK(ov.readdir("/", &es) == 0 && es.size() == 3 && has_name(es, "a.bin") && has_name(es, "keep.txt") && has_name(es, "sub"));
        CHECK(find_name(es, "a.bin")->remote && !find_name(es, "keep.txt")->remote && !has_name(es, "n.bin"));   // deeper files do not leak upwards
        CHECK(ov.readdir("/sub/deep", &es) == 0 && es.size() == 1 && es[0].name == "n.bin" && es[0].remote);
        std::vector<uint8_t> buf(3 * MiB);
        // a read inside one chunk fetches exactly that chunk
        CHECK(ov.read("/a.bin", 2 * MiB + 10, 100, buf.data()) == 100 && memcmp(buf.data(), a.bytes.data() + 2 * MiB + 10, 100) == 0);
        CHECK(ov.stats().chunk_fetches == 1 && ov.stats().cache_hits == 0);
        CHECK(ov.read("/a.bin", 2 * MiB + 50, 100, buf.data()) == 100 && memcmp(buf.data(), a.bytes.data() + 2 * MiB + 50, 100) == 0);
        CHECK(ov.stats().chunk_fetches == 1 && ov.stats().cache_hits == 1);   // the second read is served from memory
        // a read that ends exactly at a chunk boundary does not touch the next chunk
        {
            Overlay edge(*w.L, *w.keys, devmap(w), cfg_for(w));
            CHECK(edge.read("/a.bin", MiB - 10, 10, buf.data()) == 10 && edge.stats().chunk_fetches == 1);
            CHECK(edge.read("/a.bin", MiB, 10, buf.data()) == 10 && edge.stats().chunk_fetches == 2);   // starting at it: exactly that one
        }
        // across a chunk boundary
        CHECK(ov.read("/a.bin", MiB - 5, 10, buf.data()) == 10 && memcmp(buf.data(), a.bytes.data() + MiB - 5, 10) == 0);
        CHECK(ov.read("/a.bin", MiB, 1, buf.data()) == 1 && buf[0] == a.bytes[MiB] && ov.read("/a.bin", MiB - 1, 1, buf.data()) == 1 && buf[0] == a.bytes[MiB - 1]);
        // the tail, EOF handling, and a read bigger than what is left
        CHECK(ov.read("/a.bin", 3 * MiB, 5000, buf.data()) == 1000 && memcmp(buf.data(), a.bytes.data() + 3 * MiB, 1000) == 0);
        CHECK(ov.read("/a.bin", a.bytes.size(), 10, buf.data()) == 0 && ov.read("/a.bin", a.bytes.size() + 99999, 10, buf.data()) == 0 && ov.read("/a.bin", 0, 0, buf.data()) == 0);
        // the whole file, in awkward pieces, equals the original
        CHECK(read_all(ov, "/a.bin", a.bytes.size(), 65536) == a.bytes);
        CHECK(read_all(ov, "/sub/deep/n.bin", n.bytes.size(), 100000) == n.bytes);
        CHECK(read_all(ov, "/keep.txt", keep.bytes.size(), 64) == keep.bytes);
        CHECK(ov.read("/a.bin", 0, 10, buf.data()) == 10);
    }

    {
        printf("== the local copy wins while it exists; the remote one takes over the moment it does not\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 10, 1);
        std::string fid = a.fid;
        CHECK(a.chunks.size() == 2);
        {
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
            std::vector<uint8_t> buf(100);
            CHECK(ov.read("/a.bin", 0, 100, buf.data()) == 100 && ov.stats().chunk_fetches == 0);   // replicated, still local: no network
        }
        // a power cut during a drop, after the bytes moved to quarantine but before the ledger's second step: the ledger says DROPPING
        w.close_ledger();
        CHECK(spawn_drop_crash(w, fid, "drop.after_sync"));
        w.open_ledger();
        Overlay ov2(*w.L, *w.keys, devmap(w), cfg_for(w));
        CHECK(w.L->get_file(fid)->state == FileState::DROPPING && !exists(w.path("a.bin")));
        OvStat st;
        CHECK(ov2.getattr("/a.bin", &st) == 0 && st.remote && st.size == MiB + 10);
        CHECK(read_all(ov2, "/a.bin", MiB + 10, 4096) == a.bytes);                                     // served from the devices while the bytes sit in quarantine
        // recover: the file comes back; the overlay now serves it from the origin again
        RecoveryReport rr = w.E->recover(devmap(w));
        CHECK(rr.problems.empty() && exists(w.path("a.bin")) == (w.L->get_file(fid)->state == FileState::REPLICATED));
    }

    {
        printf("== devices fail: remote reads fail with EIO or succeed with exact bytes, and the metadata path never waits for them\n");
        Lab w;
        Item& a = w.make("a.bin", 3 * MiB + 1, 1);
        Item& b = w.make("b.bin", 2 * MiB, 2);
        CHECK(w.drop("a.bin") && w.drop("b.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
        std::vector<uint8_t> buf(MiB);
        // one device down: the other serves everything
        w.sb.stop();
        CHECK(read_all(ov, "/a.bin", a.bytes.size(), 1 << 20) == a.bytes);
        // damage on the remaining device: only the damaged chunk is unreadable; the rest is fine; nothing wrong is ever returned
        w.damage(0, a.chunks[1]);
        w.remove_blob(0, b.chunks[1]);
        Overlay fresh(*w.L, *w.keys, devmap(w), cfg_for(w));
        CHECK(fresh.read("/a.bin", 0, 100, buf.data()) == 100 && memcmp(buf.data(), a.bytes.data(), 100) == 0);
        CHECK(fresh.read("/a.bin", MiB, 100, buf.data()) == -EIO);
        CHECK(fresh.read("/a.bin", MiB - 50, 100, buf.data()) == -EIO);          // a read touching the bad chunk fails whole, not short
        CHECK(fresh.read("/a.bin", 2 * MiB, 100, buf.data()) == 100 && memcmp(buf.data(), a.bytes.data() + 2 * MiB, 100) == 0);
        CHECK(fresh.read("/b.bin", MiB + 1, 10, buf.data()) == -EIO && fresh.read("/b.bin", 0, 10, buf.data()) == 10);
        CHECK(fresh.stats().bad_chunks_skipped >= 3);
        // both devices gone: still listed and stat-able, reads fail with EIO
        w.sa.stop();
        OvStat st;
        std::vector<OvEntry> es;
        CHECK(fresh.getattr("/a.bin", &st) == 0 && st.size == a.bytes.size() && fresh.readdir("/", &es) == 0 && has_name(es, "a.bin") && has_name(es, "b.bin"));
        Overlay cold(*w.L, *w.keys, devmap(w), cfg_for(w));
        CHECK(cold.read("/a.bin", 0, 10, buf.data()) == -EIO);
        CHECK(fresh.read("/a.bin", 2 * MiB, 100, buf.data()) == 100);              // ... except what is already verified in memory
    }

    {
        printf("== a device that lies (answers with the wrong chunk) cannot get wrong bytes returned\n");
        Lab w;
        Item& a = w.make("a.bin", 2 * MiB + 3, 1);
        CHECK(w.drop("a.bin"));
        w.sa.stop();
        w.sa.faults = "swap_get";
        w.sa.start(w.devdir(0));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
        CHECK(read_all(ov, "/a.bin", a.bytes.size(), 70000) == a.bytes);          // B's honest copies are used
        w.sb.stop();
        Overlay liar_only(*w.L, *w.keys, devmap(w), cfg_for(w));
        std::vector<uint8_t> buf(100);
        CHECK(liar_only.read("/a.bin", 0, 100, buf.data()) == -EIO && liar_only.stats().bad_chunks_skipped >= 1);
    }

    {
        printf("== a small cache evicts but never returns stale or wrong data\n");
        Lab w;
        Item& a = w.make("a.bin", 4 * MiB, 1);
        CHECK(w.drop("a.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, MiB + MiB / 2));   // room for one chunk
        CHECK(read_all(ov, "/a.bin", a.bytes.size(), MiB) == a.bytes);
        uint64_t f1 = ov.stats().chunk_fetches;
        CHECK(read_all(ov, "/a.bin", a.bytes.size(), MiB) == a.bytes);
        CHECK(ov.stats().chunk_fetches > f1);                                     // the first chunk had been evicted: fetched again, verified again
        std::vector<uint8_t> buf(10);
        uint64_t f2 = ov.stats().chunk_fetches;
        CHECK(ov.read("/a.bin", 3 * MiB, 10, buf.data()) == 10 && ov.read("/a.bin", 3 * MiB + 5, 5, buf.data()) == 5 && ov.stats().chunk_fetches == f2 + 0);   // the last one is still cached
    }

    {
        printf("== many threads reading a remote file at once all get exact bytes\n");
        Lab w;
        Item& a = w.make("a.bin", 5 * MiB + 77, 9);
        CHECK(w.drop("a.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
        std::atomic<int> bad{0};
        std::vector<std::thread> ts;
        for (int t = 0; t < 8; t++)
            ts.emplace_back([&, t] {
                unsigned seed = 1234u + t;
                std::vector<uint8_t> buf(300000);
                for (int i = 0; i < 40; i++) {
                    uint64_t off = rand_r(&seed) % a.bytes.size();
                    size_t len = 1 + rand_r(&seed) % 250000;
                    int64_t n = ov.read("/a.bin", off, len, buf.data());
                    size_t want = static_cast<size_t>(std::min<uint64_t>(len, a.bytes.size() - off));
                    if (n != static_cast<int64_t>(want) || memcmp(buf.data(), a.bytes.data() + off, want) != 0) bad++;
                    OvStat st;
                    if (ov.getattr("/a.bin", &st) != 0 || !st.remote) bad++;
                }
            });
        for (auto& t : ts) t.join();
        CHECK(bad == 0);
    }

    {
        printf("== read-ahead: a sequential reader finds the next chunks already fetched; random readers, and a device that fails, are not hurt\n");
        auto wait_until = [](const std::function<bool()>& f, int ms = 8000) {
            for (int i = 0; i < ms / 10 && !f(); i++) usleep(10000);
            return f();
        };
        Lab w;
        Item& big = w.make("big.bin", 10 * MiB + 500, 1);
        CHECK(big.chunks.size() == 11 && w.drop("big.bin"));
        std::vector<uint8_t> buf(256 * 1024);
        const size_t SM = 64 * 1024;   // eight of these still fit inside the first chunk
        // off by default: the reader pays for every chunk, nothing is fetched ahead
        {
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
            CHECK(read_all(ov, "/big.bin", big.bytes.size(), 256 * 1024) == big.bytes);
            usleep(200000);
            CHECK(ov.stats().prefetched == 0 && ov.stats().chunk_fetches == 11);
        }
        // on: the whole file is still exact, and each chunk is fetched exactly once however the work is split between reader and read-ahead
        {
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            CHECK(read_all(ov, "/big.bin", big.bytes.size(), 256 * 1024) == big.bytes);
            usleep(200000);
            Overlay::Stats st = ov.stats();
            CHECK(st.chunk_fetches == 11 && st.prefetched > 0 && st.cache_hits > 0 && st.bad_chunks_skipped == 0);
        }
        // the window grows with the streak and never passes the limit; two reads are not yet a streak
        {
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            CHECK(ov.read("/big.bin", 0, SM, buf.data()) == static_cast<int64_t>(SM));
            CHECK(ov.read("/big.bin", SM, SM, buf.data()) > 0);
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 1 && ov.stats().prefetched == 0);   // two sequential reads: nothing yet
            CHECK(ov.read("/big.bin", 2 * SM, SM, buf.data()) > 0);
            CHECK(wait_until([&] { return ov.stats().prefetched >= 1; }));
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 2 && ov.stats().prefetched == 1);   // the third: one chunk ahead
            CHECK(ov.read("/big.bin", 3 * SM, SM, buf.data()) > 0);
            CHECK(wait_until([&] { return ov.stats().prefetched >= 2; }));
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 3 && ov.stats().prefetched == 2);   // the fourth: the window has doubled to two
            for (int i = 4; i < 8; i++) CHECK(ov.read("/big.bin", i * SM, SM, buf.data()) > 0);
            CHECK(wait_until([&] { return ov.stats().prefetched >= 4; }));
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 5 && ov.stats().prefetched == 4);   // four ahead, no more, while still inside the first chunk
        }
        // a streak that is broken starts over with a window of one; a read that ends exactly at a chunk boundary is still in the chunk it ends in
        {
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            for (int i = 0; i < 6; i++) ov.read("/big.bin", i * SM, SM, buf.data());   // window 1, 2, 4: chunks 1-4
            CHECK(wait_until([&] { return ov.stats().prefetched >= 4; }));
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 5);
            for (int i = 0; i < 3; i++) ov.read("/big.bin", 5 * MiB + 1000 + i * SM, SM, buf.data());   // a jump: a new streak, window 1 again
            CHECK(wait_until([&] { return ov.stats().prefetched >= 5; }));
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 5 + 1 + 1);   // chunk 5 (read), chunk 6 (the window of one)
            ov.read("/big.bin", 5 * MiB + 1000 + 3 * SM, SM, buf.data());
            CHECK(wait_until([&] { return ov.stats().prefetched >= 6; }));
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 5 + 1 + 1 + 1);   // chunk 7 (the window of two)
        }
        {
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            for (int i = 0; i < 4; i++) ov.read("/big.bin", i * 256 * 1024, 256 * 1024, buf.data());   // the fourth read ends exactly at the end of chunk 0
            CHECK(wait_until([&] { return ov.stats().prefetched >= 2; }));
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 3 && ov.stats().prefetched == 2);   // chunks 1 and 2, not 2 and 3
        }
        // a read that crosses into the next chunk puts the reader in that chunk
        {
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            const size_t S4 = 400 * 1024;
            std::vector<uint8_t> big4(S4);
            for (int i = 0; i < 3; i++) CHECK(ov.read("/big.bin", i * S4, S4, big4.data()) == static_cast<int64_t>(S4));
            CHECK(wait_until([&] { return ov.stats().prefetched >= 1; }));
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 3 && ov.stats().prefetched == 1);   // the third read ended in chunk 1, so chunk 2 is next
        }
        // a read-ahead that fails is not counted as one that worked
        {
            Item& dmg = w.make("dmg.bin", 6 * MiB + 7, 5);
            CHECK(w.drop("dmg.bin"));
            w.damage(0, dmg.chunks[2]);
            w.damage(1, dmg.chunks[2]);
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            for (int i = 0; i < 8; i++) ov.read("/dmg.bin", i * SM, SM, buf.data());
            CHECK(wait_until([&] { return ov.stats().prefetched >= 3; }));
            usleep(400000);
            Overlay::Stats st = ov.stats();
            CHECK(st.prefetched == 3 && st.bad_chunks_skipped == 2 && st.chunk_fetches == 1 + 3 + 2);   // chunks 1, 3 and 4 arrived; chunk 2 failed on both devices
        }
        // the window cannot be bigger than a quarter of the cache
        {
            OverlayConfig c = cfg_for(w, 4 * MiB);
            c.readahead_chunks = 8;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            for (int i = 0; i < 8; i++) CHECK(ov.read("/big.bin", i * SM, SM, buf.data()) > 0);
            usleep(500000);
            CHECK(ov.stats().chunk_fetches == 2 && ov.stats().prefetched == 1);   // a 4 MiB cache holds one chunk of read-ahead
        }
        // chunks that were fetched ahead and evicted are fetched ahead again on a second pass
        {
            OverlayConfig c = cfg_for(w, 4 * MiB);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            CHECK(read_all(ov, "/big.bin", big.bytes.size(), 256 * 1024) == big.bytes);
            usleep(300000);
            uint64_t first = ov.stats().prefetched;
            CHECK(first > 0);
            CHECK(read_all(ov, "/big.bin", big.bytes.size(), 256 * 1024) == big.bytes);
            usleep(300000);
            CHECK(ov.stats().prefetched > first);
        }
        // a slow device: the reader and the read-ahead want the same chunk; it is fetched once, not twice
        {
            w.sa.faults = "slow=120";
            w.sb.faults = "slow=120";
            CHECK(w.sa.start(w.devdir(0)) && w.sb.start(w.devdir(1)));
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            CHECK(read_all(ov, "/big.bin", big.bytes.size(), 128 * 1024) == big.bytes);
            usleep(500000);
            Overlay::Stats st = ov.stats();
            CHECK(st.chunk_fetches == 11 && st.prefetched > 0);   // each of the 11 chunks was fetched exactly once, though the reader and the read-ahead often wanted the same one
            w.sa.faults.clear();
            w.sb.faults.clear();
            CHECK(w.sa.start(w.devdir(0)) && w.sb.start(w.devdir(1)));
        }
        // even a tiny cache gets a window of one
        {
            OverlayConfig c = cfg_for(w, 2 * MiB);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            for (int i = 0; i < 8; i++) ov.read("/big.bin", 6 * MiB + i * SM, SM, buf.data());
            CHECK(wait_until([&] { return ov.stats().prefetched >= 1; }));
            usleep(300000);
            CHECK(ov.stats().prefetched == 1 && ov.stats().chunk_fetches == 2);
        }
        // random readers cause nothing
        {
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            for (uint64_t off : {7 * MiB + 10, 2 * MiB + 99, 9 * MiB + 5, 4 * MiB + 1, 0 * MiB + 1000, 6 * MiB + 77}) CHECK(ov.read("/big.bin", off, 100, buf.data()) == 100);
            usleep(300000);
            CHECK(ov.stats().chunk_fetches == 6 && ov.stats().prefetched == 0);
            // the same place again and again is not a streak either
            for (int i = 0; i < 6; i++) ov.read("/big.bin", 3 * MiB, 100, buf.data());
            usleep(200000);
            CHECK(ov.stats().prefetched == 0);
        }
        // the last chunk is the end: nothing is fetched beyond it
        {
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            uint64_t from = 8 * MiB;
            for (int i = 0; i < 6; i++) CHECK(ov.read("/big.bin", from + i * 256 * 1024, 256 * 1024, buf.data()) > 0);
            for (int i = 0; i < 12; i++) ov.read("/big.bin", from + (6 + i) * 256 * 1024, 256 * 1024, buf.data());
            usleep(500000);
            CHECK(ov.stats().chunk_fetches <= 3 && ov.stats().bad_chunks_skipped == 0);   // chunks 8, 9, 10 and no others
        }
        // a chunk that fails verification is skipped by the read-ahead; the reader still gets exact bytes from the other device, or an error
        {
            std::string victim = big.chunks[3];
            w.damage(0, victim);
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            CHECK(read_all(ov, "/big.bin", big.bytes.size(), 256 * 1024) == big.bytes);   // device A's copy of chunk 3 is bad, B's is good
            w.damage(1, victim);
            Overlay ov2(*w.L, *w.keys, devmap(w), c);
            std::vector<uint8_t> b2(MiB);
            bool failed = false;
            for (uint64_t off = 0; off < big.bytes.size(); off += 256 * 1024) {
                int64_t n = ov2.read("/big.bin", off, 256 * 1024, b2.data());
                if (n < 0) { failed = n == -EIO; break; }
                if (memcmp(b2.data(), big.bytes.data() + off, static_cast<size_t>(n)) != 0) { failed = false; break; }
            }
            CHECK(failed);   // both copies of chunk 3 are bad: EIO at that chunk, never wrong bytes
            CHECK(ov2.stats().bad_chunks_skipped > 0);
        }
        // many readers at once, and an overlay torn down while read-ahead is working
        {
            Item& other = w.make("other.bin", 6 * MiB + 3, 9);
            Item& third = w.make("third.bin", 7 * MiB + 11, 4);
            CHECK(w.drop("other.bin") && w.drop("third.bin"));
            OverlayConfig c = cfg_for(w);
            c.readahead_chunks = 4;
            Overlay ov(*w.L, *w.keys, devmap(w), c);
            std::atomic<int> bad{0};
            std::vector<std::thread> ts;
            for (int t = 0; t < 4; t++)
                ts.emplace_back([&, t] {
                    const std::string p = t % 2 ? "/other.bin" : "/third.bin";
                    const Bytes& want = t % 2 ? other.bytes : third.bytes;
                    std::vector<uint8_t> b(100000);
                    for (uint64_t off = 0; off < want.size(); off += b.size()) {
                        int64_t n = ov.read(p, off, b.size(), b.data());
                        if (n < 0 || memcmp(b.data(), want.data() + off, static_cast<size_t>(n)) != 0) { bad++; break; }
                    }
                });
            for (auto& t : ts) t.join();
            CHECK(bad == 0);
            for (int i = 0; i < 20; i++) {
                OverlayConfig c2 = cfg_for(w);
                c2.readahead_chunks = 8;
                Overlay quick(*w.L, *w.keys, devmap(w), c2);
                for (int k = 0; k < 5; k++) quick.read("/other.bin", k * 100000, 100000, buf.data());
            }   // (destroyed straight away, with fetches queued or running: no crash, no hang)
            CHECK(true);
        }
    }

    {
        printf("== the ledger-only view: a tracked file that is not remote and not local does not exist\n");
        Lab w;
        Item& a = w.make("a.bin", MiB, 1);
        w.make("b.bin", MiB, 2);
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
        unlink(w.path("a.bin").c_str());                      // vanished behind our back; the ledger still says REPLICATED with local bytes
        OvStat st;
        std::vector<OvEntry> es;
        CHECK(ov.getattr("/a.bin", &st) == -ENOENT && ov.readdir("/", &es) == 0 && !has_name(es, "a.bin") && has_name(es, "b.bin"));
        std::vector<uint8_t> vbuf(10);
        CHECK(ov.read("/a.bin", 0, 10, vbuf.data()) == -ENOENT && ov.stats().chunk_fetches == 0);   // not remote (the ledger says its bytes are local): no guessing
        (void)a;
        // a name containing wildcard characters is an ordinary name
        Item& odd = w.make("100%_real [x].bin", MiB, 3);
        CHECK(w.drop("100%_real [x].bin"));
        CHECK(ov.getattr("/100%_real [x].bin", &st) == 0 && st.remote && ov.readdir("/", &es) == 0 && has_name(es, "100%_real [x].bin"));
        CHECK(read_all(ov, "/100%_real [x].bin", odd.bytes.size(), 100000) == odd.bytes);
    }

    {
        printf("== states: HYDRATING and AT_RISK files are remote too; a new local file at the same path shadows the remote one\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 10, 1);
        Item& b = w.make("b.bin", MiB + 20, 2);
        Item& c = w.make("c.bin", MiB + 30, 3);
        CHECK(w.drop("a.bin") && w.drop("b.bin") && w.drop("c.bin"));
        CHECK(w.L->begin_hydrate(a.fid).ok);                                   // a recall is in progress: bytes still come from the devices
        CHECK(w.L->mark_at_risk(b.fid, "test").ok);                            // flagged: still readable as long as any device has it
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
        OvStat st;
        std::vector<OvEntry> es;
        CHECK(w.L->get_file(a.fid)->state == FileState::HYDRATING && w.L->get_file(b.fid)->state == FileState::AT_RISK);
        CHECK(ov.getattr("/a.bin", &st) == 0 && st.remote && ov.getattr("/b.bin", &st) == 0 && st.remote);
        CHECK(ov.readdir("/", &es) == 0 && has_name(es, "a.bin") && has_name(es, "b.bin") && has_name(es, "c.bin"));
        CHECK(read_all(ov, "/a.bin", a.bytes.size(), 100000) == a.bytes && read_all(ov, "/b.bin", b.bytes.size(), 100000) == b.bytes);
        // somebody creates a new file at c's path: the new local file is what the path is, listed once, and read from the origin
        spit(w.path("c.bin"), pattern(77, 9));
        CHECK(ov.getattr("/c.bin", &st) == 0 && !st.remote && st.size == 77);
        CHECK(ov.readdir("/", &es) == 0 && find_name(es, "c.bin") && !find_name(es, "c.bin")->remote && es.size() == 3);
        std::vector<uint8_t> buf(100);
        CHECK(ov.read("/c.bin", 0, 100, buf.data()) == 77 && memcmp(buf.data(), pattern(77, 9).data(), 77) == 0);
        (void)c;
    }

    {
        printf("== a retired device is never asked; unknown or missing clients are ignored\n");
        Lab w;
        Item& a = w.make("a.bin", 2 * MiB + 1, 1);
        CHECK(w.drop("a.bin"));
        w.sa.stop();
        w.sa.faults = "swap_get";
        w.sa.start(w.devdir(0));                                              // A lies...
        CHECK(w.L->retire_device(w.ida));                                     // ...and has been retired
        DeviceMap dm = devmap(w);
        dm["no-such-device"] = w.da.get();                                    // not in the ledger
        dm["null-client"] = nullptr;
        Overlay ov(*w.L, *w.keys, dm, cfg_for(w));
        CHECK(read_all(ov, "/a.bin", a.bytes.size(), 70000) == a.bytes);
        CHECK(ov.stats().bad_chunks_skipped == 0);                            // the liar was never consulted
    }

    {
        printf("== configuration and error details\n");
        Lab w;
        Item& a = w.make("a.bin", 100, 1);
        w.make("sub/b.bin", 100, 2);
        fs::create_directories(w.root + "/files/sub/.tierfs");                // only the TOP-LEVEL .tierfs is ours
        OverlayConfig c = cfg_for(w);
        c.origin_dir += "//";                                                 // trailing slashes are tolerated
        c.logical_prefix = "/Users/me/proj///";
        Overlay ov(*w.L, *w.keys, devmap(w), c);
        std::string op, lp;
        CHECK(ov.resolve("/a.bin", &op, &lp) && op == w.root + "/files/a.bin");
        OvStat st;
        std::vector<OvEntry> es;
        CHECK(ov.readdir("/sub", &es) == 0 && has_name(es, ".tierfs") && has_name(es, "b.bin"));
        CHECK(ov.getattr("/sub/.tierfs", &st) == 0 && st.kind == OvKind::Dir);
        // permissions: an unreadable directory is EACCES, not "no such file"
        fs::create_directories(w.root + "/files/locked");
        spit(w.root + "/files/locked/x", pattern(5, 1));
        chmod((w.root + "/files/locked").c_str(), 0);
        CHECK(ov.getattr("/locked/x", &st) == -EACCES);
        std::vector<uint8_t> buf(10);
        CHECK(ov.read("/locked/x", 0, 10, buf.data()) == -EACCES);
        CHECK(ov.readdir("/locked", &es) == -EACCES);
        chmod((w.root + "/files/locked").c_str(), 0755);
        // a symlink is not followed when read by path (the kernel resolves links before the filesystem is asked)
        symlink("a.bin", (w.root + "/files/lnk").c_str());
        CHECK(ov.read("/lnk", 0, 10, buf.data()) == -ELOOP);
        // a missing origin: nothing exists
        OverlayConfig gone = cfg_for(w);
        gone.origin_dir = w.root + "/does-not-exist";
        Overlay empty(*w.L, *w.keys, devmap(w), gone);
        CHECK(empty.getattr("/", &st) == -ENOENT && empty.readdir("/", &es) == -ENOENT && empty.getattr("/a.bin", &st) == -ENOENT);
        (void)a;
    }

    {
        printf("== which device is asked, and in which order\n");
        // (1) the only device is retired: it is never asked, the read fails
        {
            Lab w;
            Item& a = w.make("a.bin", MiB + 1, 1);
            CHECK(w.drop("a.bin"));
            CHECK(w.L->retire_device(w.ida));
            DeviceMap only_a{{w.ida, w.da.get()}};
            Overlay ov(*w.L, *w.keys, only_a, cfg_for(w));
            std::vector<uint8_t> buf(10);
            CHECK(ov.read("/a.bin", 0, 10, buf.data()) == -EIO && ov.stats().chunk_fetches == 0);
            (void)a;
        }
        // (2) a client that is missing for a device the ledger knows: skipped, the other one serves
        {
            Lab w;
            Item& a = w.make("a.bin", MiB + 1, 1);
            CHECK(w.drop("a.bin"));
            DeviceMap dm = devmap(w);
            dm[w.ida] = nullptr;
            Overlay ov(*w.L, *w.keys, dm, cfg_for(w));
            CHECK(read_all(ov, "/a.bin", a.bytes.size(), 100000) == a.bytes);
        }
        // (3) a device whose replica record is not COMMITTED still serves when it is all there is (the bytes are verified anyway)
        {
            Lab w;
            Item& a = w.make("a.bin", MiB + 1, 1);
            CHECK(w.drop("a.bin"));
            w.sa.stop();
            CHECK(w.L->record_audit(a.fid, 1, w.idb, false, "test").ok);
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
            CHECK(read_all(ov, "/a.bin", a.bytes.size(), 100000) == a.bytes);
        }
        // (4) devices with a COMMITTED replica are asked before those without: a lying device with a failed replica must not be asked first,
        //     whichever of the two ids sorts first
        for (int liar = 0; liar < 2; liar++) {
            Lab w;
            Item& a = w.make("a.bin", MiB + 1, 1);
            CHECK(w.drop("a.bin"));
            Server& s = liar == 0 ? w.sa : w.sb;
            s.stop();
            s.faults = "swap_get";
            s.start(w.devdir(liar));
            CHECK(w.L->record_audit(a.fid, 1, liar == 0 ? w.ida : w.idb, false, "test").ok);
            Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w));
            CHECK(read_all(ov, "/a.bin", a.bytes.size(), 100000) == a.bytes && ov.stats().bad_chunks_skipped == 0);
        }
    }

    {
        printf("== the cache evicts the least recently USED chunk, not the oldest\n");
        Lab w;
        Item& a = w.make("a.bin", 3 * MiB, 1);
        CHECK(w.drop("a.bin"));
        Overlay ov(*w.L, *w.keys, devmap(w), cfg_for(w, 2 * MiB + MiB / 2));   // room for two chunks
        std::vector<uint8_t> buf(10);
        CHECK(ov.read("/a.bin", 0, 10, buf.data()) == 10);                 // chunk 0
        CHECK(ov.read("/a.bin", MiB, 10, buf.data()) == 10);               // chunk 1
        CHECK(ov.read("/a.bin", 5, 10, buf.data()) == 10);                 // chunk 0 again: now the most recent
        CHECK(ov.read("/a.bin", 2 * MiB, 10, buf.data()) == 10);           // chunk 2: something must go, and it must be chunk 1
        uint64_t before = ov.stats().chunk_fetches;
        CHECK(ov.read("/a.bin", 5, 10, buf.data()) == 10 && ov.stats().chunk_fetches == before);        // chunk 0 survived
        CHECK(ov.read("/a.bin", MiB, 10, buf.data()) == 10 && ov.stats().chunk_fetches == before + 1);  // chunk 1 was evicted
        (void)a;
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
