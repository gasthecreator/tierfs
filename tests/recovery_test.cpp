// Disaster drills for the recovery path: the Mac is gone (no ledger, no keys, no files) and all that is left is the
// recovery phrase and the devices. Real files, real device servers, real encryption, the real tierctl binary.
// The question each drill asks: do the files come back byte for byte, and when they cannot, is the report honest?
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
#include <thread>

#include "../core/dropengine.hpp"
#include "../core/recovery.hpp"

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
static bool has(const std::string& s, const std::string& n) { return s.find(n) != std::string::npos; }
// TIERFS_TEST_TMP / TIERFS_TEST_PORT let several copies of this test run side by side (the parallel mutation runner).
static std::string tmpdir() {
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-recotest-XXXXXX";
    std::vector<char> buf(t.begin(), t.end());
    buf.push_back(0);
    return mkdtemp(buf.data());
}
static uint16_t port_base() { return getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9521; }
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
            DevRes r = c.info(info);
            if (r.ok() || r.err == EPERM) return true;   // (a paired device refuses a plaintext client: it is up)
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

    std::string code_a, code_b;   // the pairing codes, when the devices are paired
    // Pairs a device store (creating its secret) and returns the secret and the code the device prints.
    static Bytes pair_store(const std::string& store, std::string* code) {
        std::string cmd = std::string("./build/tierfs-device '") + store + "' --show-pairing-code 2>&1";
        FILE* f = popen(cmd.c_str(), "r");
        std::string out;
        char buf[512];
        while (size_t n = fread(buf, 1, sizeof buf, f)) out.append(buf, n);
        pclose(f);
        size_t s0 = out.find("\n\n    ") + 6;
        *code = out.substr(s0, out.find('\n', s0) - s0);
        std::string err;
        auto k = crypto::decode_recovery(*code, &err);
        return k ? Bytes(k->data(), k->data() + 32) : Bytes{};
    }
    explicit Lab(bool paired = false) {
        n_ = ++g_lab;
        fs::create_directories(root + "/files");
        Bytes psk_a, psk_b;
        if (paired) {
            psk_a = pair_store(root + "/devA" + std::to_string(n_), &code_a);
            psk_b = pair_store(root + "/devB" + std::to_string(n_), &code_b);
        }
        sa.start(root + "/devA" + std::to_string(n_));
        sb.start(root + "/devB" + std::to_string(n_));
        da = std::make_unique<DeviceClient>("127.0.0.1", PA, 5000, psk_a);
        db = std::make_unique<DeviceClient>("127.0.0.1", PB, 5000, psk_b);
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
        E = std::make_unique<DropEngine>(*L, *R, *keys, L->volume_id(), DropPolicy{}, root + "/quarantine",
                                         [files](const FileRec& f) { return files + "/" + f.path.substr(f.path.rfind('/') + 1); });
    }
    void close_ledger() { E.reset(); R.reset(); L.reset(); }
    std::string path(const std::string& name) const { return root + "/files/" + name; }
    std::string phrase() const { return crypto::encode_recovery(master); }
    std::string devdir(int dev) const { return root + (dev == 0 ? "/devA" : "/devB") + std::to_string(n_); }

    Item& make(const std::string& name, size_t size, uint8_t seed, uint32_t mode = 0644, int64_t mtime = 1600000000, const std::string& dir = "/Users/me/proj/", bool to_a = true, bool to_b = true) {
        Item it;
        it.name = name;
        it.logical = dir + name;
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
        bool a = !to_a || R->replicate(*da, ida, it.fid, path(name)).ok, b = !to_b || R->replicate(*db, idb, it.fid, path(name)).ok;
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
        fs::remove_all(root + "/quarantine");
    }
    std::string blob(int dev, const std::string& cid) const { return devdir(dev) + "/chunks/" + cid.substr(0, 2) + "/" + cid + ".blob"; }
    void damage(int dev, const std::string& cid) {
        int fd = ::open(blob(dev, cid).c_str(), O_RDWR);
        uint8_t b = 0;
        if (fd >= 0) { pread(fd, &b, 1, 100); b ^= 0x40; pwrite(fd, &b, 1, 100); close(fd); }
    }
    void remove_blob(int dev, const std::string& cid) { unlink(blob(dev, cid).c_str()); }
    std::vector<RecoveryDevice> both() { return {{"A", da.get()}, {"B", db.get()}}; }
    // Put a hand-made manifest on device A over a chunk that is really there (an attacker with the keys, or a bug).
    // `file_id` empty: a fresh one. `dev`: 0 = A, 1 = B. `foreign_keys`: sealed under a different master (opens for nobody here).
    bool plant(const Item& real, const std::string& path, bool honest_hmac, bool lie_about_size = false, std::string file_id = "", int dev = 0, bool foreign_keys = false) {
        crypto::Manifest m;
        Bytes id(16);
        for (auto& b : id) b = static_cast<uint8_t>(rand());
        m.file_id = file_id.empty() ? crypto::to_hex(id.data(), id.size()) : file_id;
        m.version = 1;
        m.path = path;
        m.mode = 06777;                                                // setuid/setgid must never be restored
        m.mtime = 1000000000;
        m.size = real.bytes.size() + (lie_about_size ? 1 : 0);
        crypto::FileHmac fh(*keys);
        fh.update(real.bytes.data(), real.bytes.size());
        m.file_hmac = honest_hmac ? fh.finish_hex() : std::string(64, '0');
        m.chunks.push_back({real.chunks[0], static_cast<uint32_t>(real.bytes.size())});
        crypto::SecretKey other = crypto::SecretKey::random();
        crypto::Keys other_keys(other);
        Bytes blob = crypto::seal_manifest(foreign_keys ? other_keys : *keys, volume, m);
        PutManifestReply pr;
        return (dev == 0 ? da : db)->put_manifest(m.file_id, 1, blob, {real.chunks[0]}, pr).ok();
    }
    // A manifest over hand-made chunks: `plain` is what the single chunk really contains, `claim_id` / `claim_len` what the
    // manifest says, `whole_hmac_of` the bytes the whole-file check is computed over.
    bool plant_chunk(const std::string& path, const Bytes& plain, const std::string& claim_id, uint32_t claim_len, const Bytes& whole_hmac_of, int dev = 0) {
        Bytes blob = crypto::seal_chunk(*keys, volume, claim_id, plain.data(), plain.size());
        PutChunkReply cr;
        if (!(dev == 0 ? da : db)->put_chunk(claim_id, blob, cr).ok()) return false;
        crypto::Manifest m;
        Bytes id(16);
        for (auto& b : id) b = static_cast<uint8_t>(rand());
        m.file_id = crypto::to_hex(id.data(), id.size());
        m.version = 1;
        m.path = path;
        m.mode = 0644;
        m.mtime = 1000000000;
        m.size = claim_len;
        crypto::FileHmac fh(*keys);
        fh.update(whole_hmac_of.data(), whole_hmac_of.size());
        m.file_hmac = fh.finish_hex();
        m.chunks.push_back({claim_id, claim_len});
        Bytes mb = crypto::seal_manifest(*keys, volume, m);
        PutManifestReply pr;
        return (dev == 0 ? da : db)->put_manifest(m.file_id, 1, mb, {claim_id}, pr).ok();
    }
};

static bool matches(const std::string& out, const Item& it, bool v1 = false) {
    std::string p = out + it.logical;
    struct stat st;
    if (lstat(p.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    if (slurp(p) != (v1 ? it.bytes_v1 : it.bytes)) return false;
    if (v1) return (st.st_mode & 0777) == it.mode;
    return (st.st_mode & 0777) == it.mode && st.st_mtimespec.tv_sec == it.mtime;
}

// Runs a shell command line (for the tierctl drills) and returns its exit status; output goes to *out.
static int sh(const std::string& cmd, std::string* out = nullptr) {
    FILE* f = popen((cmd + " 2>&1").c_str(), "r");
    if (!f) return -1;
    char buf[4096];
    std::string o;
    while (size_t n = fread(buf, 1, sizeof buf, f)) o.append(buf, n);
    int st = pclose(f);
    if (out) *out = o;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
static const char* tierctl_path() { return getenv("TIERFS_TIERCTL") ? getenv("TIERFS_TIERCTL") : "./build/tierctl"; }
static std::string cli_restore(const Lab& w, const std::string& out, const std::string& phrase_file, const std::string& extra = "", const std::string& env = "") {
    return env + " " + tierctl_path() + " restore --out " + out + " --device 127.0.0.1:" + std::to_string(PA) + " --device 127.0.0.1:" + std::to_string(PB) +
           " --phrase-file " + phrase_file + " " + extra;
    (void)w;
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
    std::vector<std::string> a = {"drop_helper", "drop", w.root + "/ledger", w.root + "/files", w.root + "/quarantine", std::to_string(PA), w.ida,
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

int main() {
    signal(SIGPIPE, SIG_IGN);

    {
        printf("== paths from manifests are hostile until proven safe\n");
        std::string rel, why;
        CHECK(safe_relative_path("/Users/me/a.txt", &rel, &why) && rel == "Users/me/a.txt");
        CHECK(safe_relative_path("Users//me/./a.txt", &rel, &why) && rel == "Users/me/a.txt");
        CHECK(safe_relative_path("/a b/ü.txt", &rel, &why) && rel == "a b/ü.txt");
        CHECK(!safe_relative_path("", &rel, &why) && has(why, "empty"));
        CHECK(!safe_relative_path("/", &rel, &why) && has(why, "root"));
        CHECK(!safe_relative_path("/..", &rel, &why) && has(why, ".."));
        CHECK(!safe_relative_path("/a/../../b", &rel, &why) && has(why, ".."));
        CHECK(!safe_relative_path("../x", &rel, &why));
        CHECK(!safe_relative_path("/a/b/..", &rel, &why));
        CHECK(!safe_relative_path(std::string("/a/b\0c", 6), &rel, &why) && has(why, "NUL"));
        CHECK(!safe_relative_path("/a/b\nc", &rel, &why) && has(why, "control"));
        CHECK(!safe_relative_path("/a/b\x7f" "c", &rel, &why) && has(why, "control"));
        CHECK(!safe_relative_path("/a/.tierfs-partial-abc", &rel, &why) && has(why, "reserved"));
        CHECK(!safe_relative_path("/" + std::string(256, 'x'), &rel, &why) && has(why, "255"));
        CHECK(safe_relative_path("/" + std::string(255, 'x'), &rel, &why));
        CHECK(safe_relative_path("/a/...", &rel, &why) && rel == "a/...");   // three dots is an ordinary name
    }

    {
        printf("== drill 1: the Mac is gone; the phrase and the devices bring everything back\n");
        Lab w;
        w.make("a.bin", 2 * MiB + MiB / 2, 1, 0640, 1500000000);
        w.make("b.txt", 1, 2, 0644, 1400000000);
        w.make("c.bin", MiB, 3, 0600, 1300000000);
        w.make("d.bin", MiB + 1, 4, 0755, 1200000000, "/Users/me/other/deep/");
        CHECK(w.drop("a.bin") && w.drop("c.bin"));                       // two of them were already offloaded: only quarantine held their bytes
        CHECK(!exists(w.path("a.bin")) && exists(w.path("b.txt")));
        w.destroy_mac();
        DevInfo ia, ib;
        w.da->info(ia);
        w.db->info(ib);
        size_t files_a = walk(w.devdir(0)).size(), files_b = walk(w.devdir(1)).size();
        std::string out = w.root + "/restored";
        RestoreReport r = recover_from_devices(w.master, w.both(), out);
        CHECK(r.fatal.empty() && r.complete() && r.restored.size() == 4 && r.identical.empty() && r.failed.empty());
        CHECK(r.volume_id == w.volume && r.devices_reachable == 2 && r.manifests_listed == 4 && r.manifests_opened == 4);
        for (auto& kv : w.items) CHECK(matches(out, kv.second));          // bytes, mode and modification time
        CHECK(walk(out).size() == 4 && !any_partial(out));
        char xv[16] = {0};
        CHECK(getxattr((out + w.items["a.bin"].logical).c_str(), "com.example.note", xv, sizeof xv, 0, 0) == 4 && std::string(xv, 4) == "kept");
        DevInfo ja, jb;
        w.da->info(ja);
        w.db->info(jb);
        CHECK(ja.seq == ia.seq && jb.seq == ib.seq && walk(w.devdir(0)).size() == files_a && walk(w.devdir(1)).size() == files_b);   // read-only: the devices did not change
        CHECK(has(format_recovery_report(r), "Everything was recovered"));

        printf("== a second run finds everything already there; a changed file is a conflict, a missing one is restored again\n");
        RestoreReport again = recover_from_devices(w.master, w.both(), out);
        CHECK(again.complete() && again.identical.size() == 4 && again.restored.empty() && again.bytes_needed == 0);
        spit(out + "/Users/me/proj/b.txt", pattern(1, 99));               // the user changed one since (same size, different content)
        unlink((out + "/Users/me/proj/c.bin").c_str());                   // and lost another
        RestoreReport third = recover_from_devices(w.master, w.both(), out);
        CHECK(!third.complete() && third.conflicts.size() == 1 && has(third.conflicts[0], "b.txt") && third.restored.size() == 1 && third.identical.size() == 2);
        CHECK(slurp(out + "/Users/me/proj/b.txt") == pattern(1, 99));      // never overwritten
        // a symlink at the destination is not "the file", even when it points at identical bytes
        std::string target = w.root + "/identical-copy";
        spit(target, w.items["d.bin"].bytes);
        unlink((out + "/Users/me/other/deep/d.bin").c_str());
        symlink(target.c_str(), (out + "/Users/me/other/deep/d.bin").c_str());
        RestoreReport sym = recover_from_devices(w.master, w.both(), out);
        struct stat lst;
        CHECK(sym.conflicts.size() == 2 && lstat((out + "/Users/me/other/deep/d.bin").c_str(), &lst) == 0 && S_ISLNK(lst.st_mode) && slurp(target) == w.items["d.bin"].bytes);
        CHECK(matches(out, w.items["c.bin"]));

        printf("== a dry run writes nothing\n");
        std::string out2 = w.root + "/dry";
        RecoveryOptions dry;
        dry.dry_run = true;
        RestoreReport d = recover_from_devices(w.master, w.both(), out2, dry);
        CHECK(d.fatal.empty() && d.planned.size() == 4 && d.restored.empty() && !exists(out2) && d.bytes_needed == 2 * MiB + MiB / 2 + 1 + MiB + MiB + 1);
        CHECK(has(format_recovery_report(d), "would restore /Users/me/proj/a.bin"));

        printf("== restoring only part of the tree\n");
        RecoveryOptions part;
        part.path_prefix = "/Users/me/other/";
        std::string out3 = w.root + "/part";
        RestoreReport p = recover_from_devices(w.master, w.both(), out3, part);
        CHECK(p.complete() && p.restored.size() == 1 && walk(out3).size() == 1 && matches(out3, w.items["d.bin"]));
    }

    {
        printf("== drill 2: a device is lost (replaced by an empty one)\n");
        Lab w;
        w.make("a.bin", 2 * MiB + 5, 1);
        w.make("b.bin", MiB, 2);
        w.destroy_mac();
        w.sb.stop();
        fs::remove_all(w.devdir(1));
        w.sb.start(w.devdir(1));
        std::string out = w.root + "/out";
        RestoreReport r = recover_from_devices(w.master, w.both(), out);
        CHECK(r.complete() && r.restored.size() == 2 && r.devices_reachable == 1 && matches(out, w.items["a.bin"]) && matches(out, w.items["b.bin"]));
        bool said = false;
        for (auto& x : r.warnings) if (has(x, "not bound")) said = true;
        CHECK(said);
        RestoreReport only_new = recover_from_devices(w.master, {{"B", w.db.get()}}, w.root + "/out2");
        CHECK(!only_new.fatal.empty() && has(only_new.fatal, "no usable device") && !exists(w.root + "/out2"));
        w.sa.stop();   // and with every device gone nothing can be done, and it says so
        RestoreReport none = recover_from_devices(w.master, w.both(), w.root + "/out3");
        CHECK(has(none.fatal, "no usable device") && !exists(w.root + "/out3") && none.devices_reachable == 0);
        bool unreachable_said = false;
        for (auto& x : none.warnings) if (has(x, "A is not reachable")) unreachable_said = true;
        CHECK(unreachable_said);
        CHECK(has(recover_from_devices(w.master, w.both(), "").fatal, "no output directory"));
        CHECK(has(recover_from_devices(w.master, {}, w.root + "/out4").fatal, "no device"));
    }

    {
        printf("== drill 3: damage on different devices is bridged chunk by chunk\n");
        Lab w;
        Item& f = w.make("big.bin", 3 * MiB + 100, 7);
        CHECK(f.chunks.size() == 4);
        w.destroy_mac();
        w.damage(0, f.chunks[0]);          // bit rot on A
        w.damage(1, f.chunks[1]);          // bit rot on B
        w.remove_blob(0, f.chunks[2]);     // a lost file on A
        w.remove_blob(1, f.chunks[3]);     // a lost file on B
        std::string out = w.root + "/out";
        RestoreReport r = recover_from_devices(w.master, w.both(), out);
        CHECK(r.complete() && r.restored.size() == 1 && matches(out, f));
    }

    {
        printf("== drill 3b: a chunk can come from a device that never held this file's manifest (identical content elsewhere)\n");
        Lab w;
        Item& x = w.make("x.bin", 2 * MiB, 5, 0644, 1600000000, "/Users/me/proj/", true, false);    // X lives on A only
        w.make("y.bin", 2 * MiB, 5, 0644, 1600000000, "/Users/me/proj/", false, true);                 // Y (same bytes) lives on B only
        CHECK(x.chunks == w.items["y.bin"].chunks);                                                    // content addressed: the same chunk ids
        w.destroy_mac();
        w.damage(0, x.chunks[1]);                                                                      // X's second chunk rotted on A, its only holder
        std::string out = w.root + "/out";
        RestoreReport r = recover_from_devices(w.master, w.both(), out);
        CHECK(r.complete() && r.restored.size() == 2 && matches(out, x) && matches(out, w.items["y.bin"]));
    }

    {
        printf("== drill 4: a chunk lost everywhere: that file fails honestly, the rest comes back, nothing half-written is left\n");
        Lab w;
        Item& bad = w.make("bad.bin", 2 * MiB + 7, 1);
        w.make("good.bin", MiB + 7, 2);
        w.destroy_mac();
        w.damage(0, bad.chunks[1]);
        w.remove_blob(1, bad.chunks[1]);
        std::string out = w.root + "/out";
        RestoreReport r = recover_from_devices(w.master, w.both(), out);
        CHECK(!r.complete() && r.fatal.empty() && r.failed.size() == 1 && has(r.failed[0], "bad.bin") && has(r.failed[0], "chunk 2 of 3"));
        CHECK(r.restored.size() == 1 && matches(out, w.items["good.bin"]) && !exists(out + bad.logical) && !any_partial(out));
        CHECK(has(format_recovery_report(r), "INCOMPLETE") && has(format_recovery_report(r), "FAILED"));
    }

    {
        printf("== drill 5: the newest version is gone everywhere; the newest one that can be rebuilt is restored, and the report says so\n");
        Lab w;
        w.make("doc.bin", 2 * MiB, 1);
        w.update("doc.bin", 2 * MiB, 77);
        Item& d = w.items["doc.bin"];
        CHECK(d.chunks.size() == 2 && d.chunks[0] != d.chunks_v1[0]);
        w.destroy_mac();
        w.remove_blob(0, d.chunks[0]);
        w.damage(1, d.chunks[0]);
        std::string out = w.root + "/out";
        RestoreReport r = recover_from_devices(w.master, w.both(), out);
        CHECK(!r.complete() && r.restored.size() == 1 && r.older.size() == 1 && r.older[0].version == 1 && r.older[0].latest == 2 && r.failed.empty());
        CHECK(matches(out, d, true));                                       // the first version's bytes, exactly
        bool said = false;
        for (auto& x : r.warnings) if (has(x, "version 2 could not be rebuilt") && has(x, "restored version 1")) said = true;
        CHECK(said && has(format_recovery_report(r), "OLDER VERSION"));
    }

    {
        printf("== when no version can be rebuilt, the report explains why the NEWEST one failed\n");
        Lab w;
        w.make("doc.bin", 2 * MiB, 1);
        w.update("doc.bin", 2 * MiB, 77);
        Item& d = w.items["doc.bin"];
        w.destroy_mac();
        w.remove_blob(0, d.chunks_v1[0]);
        w.remove_blob(1, d.chunks_v1[0]);      // v1 fails at chunk 1 ...
        w.remove_blob(0, d.chunks[1]);
        w.remove_blob(1, d.chunks[1]);         // ... v2 fails at chunk 2
        RestoreReport r = recover_from_devices(w.master, w.both(), w.root + "/out");
        CHECK(r.restored.empty() && r.failed.size() == 1 && has(r.failed[0], "chunk 2 of 2") && !exists(w.root + "/out" + d.logical));
    }

    {
        printf("== ... and with everything intact the NEWEST version comes back\n");
        Lab w2;
        w2.make("doc.bin", 2 * MiB, 1);
        w2.update("doc.bin", 2 * MiB, 77);
        w2.destroy_mac();
        std::string out2 = w2.root + "/out";
        RestoreReport r2 = recover_from_devices(w2.master, w2.both(), out2);
        CHECK(r2.complete() && r2.restored.size() == 1 && r2.restored[0].version == 2 && matches(out2, w2.items["doc.bin"]));
    }

    {
        printf("== drill 6: the wrong phrase, in every way it can be wrong\n");
        Lab w;
        w.make("a.bin", MiB, 1);
        w.destroy_mac();
        std::string good = w.phrase();
        std::string other = crypto::encode_recovery(crypto::SecretKey::random());
        std::string out = w.root + "/out";
        RestoreReport r = recover_from_devices(crypto::SecretKey::random(), w.both(), out);
        CHECK(has(r.fatal, "none of the 1 manifests") && has(r.fatal, "not the phrase for this volume") && !exists(out) && r.restored.empty());
        // via the command line: typos are pinpointed, a valid-but-wrong phrase is refused, lowercase and spacing are fine
        std::string pf = w.root + "/phrase.txt";
        std::string bad = good;
        bad[7] = bad[7] == 'A' ? 'B' : 'A';
        spit(pf, Bytes(bad.begin(), bad.end()));
        std::string text;
        int rc = sh(cli_restore(w, w.root + "/cli1", pf), &text);
        CHECK(rc == 1 && has(text, "group") && has(text, "typo") && !exists(w.root + "/cli1"));
        spit(pf, Bytes(other.begin(), other.end()));
        rc = sh(cli_restore(w, w.root + "/cli2", pf), &text);
        CHECK(rc == 1 && has(text, "NOTHING WAS RECOVERED") && has(text, "not the phrase") && !exists(w.root + "/cli2"));
        std::string sloppy;
        for (char ch : good) sloppy += (ch == '-' ? ' ' : static_cast<char>(tolower(ch)));
        sloppy = "  " + sloppy + "  \n";
        spit(pf, Bytes(sloppy.begin(), sloppy.end()));
        rc = sh(cli_restore(w, w.root + "/cli3", pf), &text);
        CHECK(rc == 0 && has(text, "Everything was recovered") && matches(w.root + "/cli3", w.items["a.bin"]));
        // the phrase can also be piped in (and is never an argument)
        rc = sh("cat " + pf + " | " + tierctl_path() + " restore --out " + w.root + "/cli4 --device 127.0.0.1:" + std::to_string(PA), &text);
        CHECK(rc == 0 && matches(w.root + "/cli4", w.items["a.bin"]));
        rc = sh(std::string(tierctl_path()) + " restore --out " + w.root + "/cli5 --device 127.0.0.1:" + std::to_string(PA) + " --phrase " + good, &text);
        CHECK(rc == 2 && has(text, "unknown option") && !exists(w.root + "/cli5"));
        rc = sh(std::string(tierctl_path()) + " restore --device 127.0.0.1:" + std::to_string(PA), &text);
        CHECK(rc == 2 && has(text, "usage"));
    }

    {
        printf("== drill 7: manifests with hostile paths cannot write outside the output directory\n");
        Lab w;
        Item& real = w.make("real.bin", MiB, 1);
        w.destroy_mac();
        std::string sandbox = w.root + "/sandbox";
        std::string out = sandbox + "/out";
        std::string elsewhere = w.root + "/elsewhere";
        fs::create_directories(out);
        fs::create_directories(elsewhere);
        symlink(elsewhere.c_str(), (out + "/Users").c_str());              // a symlink planted where a directory would go
        CHECK(w.plant(real, "/../../escape1.txt", true) && w.plant(real, "/a/../../escape2.txt", true) && w.plant(real, "/Users/me/.tierfs-partial-zz", true) &&
              w.plant(real, "/", true) && w.plant(real, "/Users/me/proj/via-symlink.txt", true));
        CHECK(w.plant(real, "/fine/./dir//ok.txt", true) && w.plant(real, "/liar/hmac.txt", false) && w.plant(real, "/liar/size.txt", true, true));
        RestoreReport r = recover_from_devices(w.master, w.both(), out);
        CHECK(r.rejected.size() == 6 && r.restored.size() == 1 && r.failed.size() == 2 && !exists(out + "/liar/hmac.txt") && !exists(out + "/liar/size.txt") && !any_partial(out)   // the five planted ones, plus the real file whose directory is the symlink
               && r.restored[0].logical == "/fine/./dir//ok.txt");
        CHECK(!exists(sandbox + "/escape1.txt") && !exists(w.root + "/escape1.txt") && !exists(w.root + "/escape2.txt") && !exists(sandbox + "/escape2.txt"));
        CHECK(walk(elsewhere).empty());                                    // nothing went through the symlink
        struct stat st;
        CHECK(stat((out + "/fine/dir/ok.txt").c_str(), &st) == 0 && (st.st_mode & 07777) == 0777 && slurp(out + "/fine/dir/ok.txt") == real.bytes);
        CHECK(!r.complete());                                              // refused paths make the result incomplete, visibly
    }

    {
        printf("== drill 7b: one refused path alone makes the result incomplete, and the good file still comes back\n");
        Lab w;
        Item& real = w.make("real.bin", MiB, 1);
        w.destroy_mac();
        CHECK(w.plant(real, "/x/../../out-of-tree.txt", true));
        RestoreReport r = recover_from_devices(w.master, w.both(), w.root + "/out");
        CHECK(r.rejected.size() == 1 && r.restored.size() == 1 && r.failed.empty() && r.conflicts.empty() && r.older.empty() && !r.complete() && matches(w.root + "/out", real));
    }

    {
        printf("== drill 7c: chunks that authenticate but are wrong: wrong content under the right id, wrong length\n");
        Lab w;
        Item& real = w.make("real.bin", MiB, 1);
        w.destroy_mac();
        Bytes other = pattern(1000, 33), truth = pattern(1000, 44);
        std::string fake_id(64, 'a');                                      // a chunk id that is NOT the HMAC of what is stored under it
        CHECK(w.plant_chunk("/c/wrong-content.bin", other, fake_id, 1000, truth));
        std::string good_id = crypto::chunk_id(*w.keys, other.data(), other.size());
        CHECK(w.plant_chunk("/c/wrong-length.bin", other, good_id, 999, other));   // the manifest claims 999 bytes, the chunk holds 1000
        RestoreReport r = recover_from_devices(w.master, w.both(), w.root + "/out");
        CHECK(r.restored.size() == 1 && r.failed.size() == 2 && matches(w.root + "/out", real));
        bool content = false, length = false;
        for (auto& f : r.failed) {
            if (has(f, "wrong-content") && has(f, "chunk 1 of 1") && has(f, "does not verify")) content = true;
            if (has(f, "wrong-length") && has(f, "chunk 1 of 1") && has(f, "wrong length")) length = true;
        }
        CHECK(content && length && walk(w.root + "/out/c").empty());   // (an empty directory may remain; no file does)
    }

    {
        printf("== drill 7d: two different files that claim the same path are both kept\n");
        Lab w;
        Item& real = w.make("real.bin", MiB, 1);
        w.destroy_mac();
        CHECK(w.plant(real, "/dup/x.txt", true) && w.plant(real, "/dup/x.txt", true));
        RestoreReport r = recover_from_devices(w.master, w.both(), w.root + "/out");
        size_t at_path = 0, renamed = 0;
        for (auto& f : walk(w.root + "/out/dup")) { if (f == "x.txt") at_path++; if (f.compare(0, 16, "x.txt.recovered-") == 0) renamed++; }
        bool said = false;
        for (auto& x : r.warnings) if (has(x, "belongs to more than one file")) said = true;
        CHECK(r.restored.size() == 3 && at_path == 1 && renamed == 1 && said);
    }

    {
        printf("== drill 7e: manifests that cannot be opened: another device's copy is used; the unreadable ones are counted and reported\n");
        Lab w;
        Item& real = w.make("real.bin", MiB, 1);
        w.destroy_mac();
        // the same (file, version) on both devices: A's copy is sealed under somebody else's key, B's is good
        CHECK(w.plant(real, "/pair/x.txt", true, false, std::string(32, '1'), 0, true) && w.plant(real, "/pair/x.txt", true, false, std::string(32, '1'), 1, false));
        // and one that nobody can open
        CHECK(w.plant(real, "/lost/y.txt", true, false, std::string(32, '2'), 0, true));
        RestoreReport r = recover_from_devices(w.master, w.both(), w.root + "/out");
        CHECK(r.manifests_listed == 3 && r.manifests_opened == 2 && r.manifests_unreadable == 1);
        CHECK(exists(w.root + "/out/pair/x.txt") && !exists(w.root + "/out/lost") && matches(w.root + "/out", real));
        bool each = false, summary = false;
        for (auto& x : r.warnings) {
            if (has(x, "manifest 22222222 v1 cannot be opened")) each = true;
            if (has(x, "1 of 3 manifests could not be opened")) summary = true;
        }
        CHECK(each && summary);
    }

    {
        printf("== drill 7f: devices bound to the volume but holding no manifests\n");
        Lab w2;
        w2.destroy_mac();
        RestoreReport none = recover_from_devices(w2.master, w2.both(), w2.root + "/out");
        CHECK(has(none.fatal, "no manifests") && !exists(w2.root + "/out"));
    }

    {
        printf("== drill 15: the devices are paired; the Mac is gone; only the phrase and the devices' codes are left\n");
        Lab w(/*paired=*/true);
        CHECK(w.code_a.size() > 50 && w.code_b.size() > 50 && w.code_a != w.code_b);
        w.make("a.bin", 2 * MiB + 5, 1, 0640, 1500000000);
        w.make("b.txt", 100, 2);
        CHECK(w.drop("a.bin"));
        std::string phrase = w.phrase();
        w.destroy_mac();
        // the library, with clients that hold the secrets
        std::string out = w.root + "/out";
        RestoreReport r = recover_from_devices(w.master, w.both(), out);
        CHECK(r.complete() && r.restored.size() == 2 && matches(out, w.items["a.bin"]) && matches(out, w.items["b.txt"]));
        // clients without secrets cannot read anything
        DeviceClient naked_a("127.0.0.1", PA, 3000), naked_b("127.0.0.1", PB, 3000);
        RestoreReport denied = recover_from_devices(w.master, {{"A", &naked_a}, {"B", &naked_b}}, w.root + "/out2");
        CHECK(!denied.fatal.empty() && has(denied.fatal, "no usable device") && !exists(w.root + "/out2"));
        // the real tool, on a new Mac: it knows the phrase and the two codes, nothing else
        std::string pf = w.root + "/phrase.txt", codes = w.root + "/codes.txt";
        spit(pf, Bytes(phrase.begin(), phrase.end()));
        std::string cl = "127.0.0.1:" + std::to_string(PA) + " " + w.code_a + "\n127.0.0.1:" + std::to_string(PB) + " " + w.code_b + "\n";
        spit(codes, Bytes(cl.begin(), cl.end()));
        std::string text;
        int rc = sh(cli_restore(w, w.root + "/cli1", pf, "--pairing-file " + codes), &text);
        CHECK(rc == 0 && has(text, "Everything was recovered") && matches(w.root + "/cli1", w.items["a.bin"]) && matches(w.root + "/cli1", w.items["b.txt"]));
        // without the codes it stops, and says what to do; nothing is written
        rc = sh(cli_restore(w, w.root + "/cli2", pf), &text);
        CHECK(rc == 2 && has(text, "device is paired") && !exists(w.root + "/cli2"));
        // one wrong code: that device cannot be read, the restore continues with the other and says so
        std::string bad = "127.0.0.1:" + std::to_string(PA) + " " + w.code_b + "\n127.0.0.1:" + std::to_string(PB) + " " + w.code_b + "\n";
        spit(w.root + "/bad.txt", Bytes(bad.begin(), bad.end()));
        rc = sh(cli_restore(w, w.root + "/cli3", pf, "--pairing-file " + w.root + "/bad.txt"), &text);
        CHECK(rc == 0 && has(text, "note: 127.0.0.1:" + std::to_string(PA) + " is not reachable") && has(text, "authentication with the device failed") && has(text, "1 device(s) reachable") && matches(w.root + "/cli3", w.items["a.bin"]));
        // every code wrong: nothing is recovered, nothing is written
        std::string worse = "127.0.0.1:" + std::to_string(PA) + " " + w.code_b + "\n127.0.0.1:" + std::to_string(PB) + " " + w.code_a + "\n";
        spit(w.root + "/worse.txt", Bytes(worse.begin(), worse.end()));
        rc = sh(cli_restore(w, w.root + "/cli3b", pf, "--pairing-file " + w.root + "/worse.txt"), &text);
        CHECK(rc == 1 && has(text, "NOTHING WAS RECOVERED") && has(text, "no usable device") && !exists(w.root + "/cli3b"));
        // one device down, the other paired and good: the files still come back
        w.sb.stop();
        rc = sh(cli_restore(w, w.root + "/cli4", pf, "--pairing-file " + codes), &text);
        CHECK(rc == 0 && matches(w.root + "/cli4", w.items["a.bin"]));
    }

    {
        printf("== drill 8: killed in the middle of a restore: no half-written file is ever visible, and a rerun finishes\n");
        Lab w;
        w.make("a.bin", 2 * MiB + 3, 1);
        w.make("b.bin", MiB + 3, 2);
        w.destroy_mac();
        std::string pf = w.root + "/phrase.txt";
        std::string ph = w.phrase();
        spit(pf, Bytes(ph.begin(), ph.end()));
        std::string out = w.root + "/out";
        std::string text;
        int rc = sh(cli_restore(w, out, pf, "", "TIERFS_CRASH_AT=restore_before_rename"), &text);
        CHECK(rc == 137);
        bool final_visible = false;
        for (auto& f : walk(out)) if (f.find(".tierfs-partial-") == std::string::npos) final_visible = true;
        CHECK(!final_visible);                                             // only the temp file exists
        CHECK(any_partial(out));
        rc = sh(cli_restore(w, out, pf), &text);
        CHECK(rc == 0 && has(text, "Everything was recovered") && !any_partial(out) && matches(out, w.items["a.bin"]) && matches(out, w.items["b.bin"]));
        std::string out2 = w.root + "/out2";
        rc = sh(cli_restore(w, out2, pf, "", "TIERFS_CRASH_AT=restore_after_rename"), &text);
        CHECK(rc == 137 && walk(out2).size() == 1);                        // exactly one file made it, and it is whole
        rc = sh(cli_restore(w, out2, pf), &text);
        CHECK(rc == 0 && has(text, "already present 1") && matches(out2, w.items["a.bin"]) && matches(out2, w.items["b.bin"]) && !any_partial(out2));
        // exit codes: 0 complete, 3 incomplete, 1 nothing done
        Item& c = w.items["a.bin"];
        w.damage(0, c.chunks[0]);
        w.damage(1, c.chunks[0]);
        rc = sh(cli_restore(w, w.root + "/out3", pf), &text);
        CHECK(rc == 3 && has(text, "FAILED") && has(text, "INCOMPLETE") && matches(w.root + "/out3", w.items["b.bin"]));
    }

    {
        printf("== drill 9: not enough room on the target: refused before anything is written\n");
        RamDisk ram;
        if (!ram.ok) printf("      (no RAM disk available: skipped)\n");
        else {
            Lab w;
            w.make("a.bin", 3 * MiB, 1);
            w.make("b.bin", 3 * MiB, 2);
            w.make("c.bin", 3 * MiB, 3);
            w.destroy_mac();
            std::string out = ram.mount + "/out";
            std::vector<std::string> before = walk(ram.mount);
            RecoveryOptions opt;
            opt.reserve_bytes = 0;
            RestoreReport r = recover_from_devices(w.master, w.both(), out, opt);
            CHECK(has(r.fatal, "not enough room") && has(r.fatal, "nothing was written") && !exists(out) && walk(ram.mount) == before && r.bytes_needed == 9 * MiB);
            RecoveryOptions dry = opt;
            dry.dry_run = true;
            RestoreReport d = recover_from_devices(w.master, w.both(), out, dry);
            CHECK(d.fatal.empty() && d.planned.size() == 3 && !d.warnings.empty() && !exists(out));
            RecoveryOptions one = opt;
            one.path_prefix = "/Users/me/proj/a";
            RestoreReport fit = recover_from_devices(w.master, w.both(), out, one);
            CHECK(fit.complete() && fit.restored.size() == 1 && matches(out, w.items["a.bin"]));
            // an exact fit is allowed: the check is "needs + reserve > free", not ">="
            RecoveryOptions exact = one;
            exact.dry_run = true;
            RestoreReport probe = recover_from_devices(w.master, w.both(), ram.mount + "/out-exact", exact);
            exact.dry_run = false;
            exact.reserve_bytes = probe.bytes_free - probe.bytes_needed;
            RestoreReport fits = recover_from_devices(w.master, w.both(), ram.mount + "/out-exact", exact);
            CHECK(fits.fatal.empty() && fits.restored.size() == 1);
            // the reserve counts: the same file no longer fits when most of the free space is held back
            RecoveryOptions strict = one;
            strict.reserve_bytes = r.bytes_free;
            RestoreReport no = recover_from_devices(w.master, w.both(), ram.mount + "/out2", strict);
            CHECK(has(no.fatal, "not enough room") && !exists(ram.mount + "/out2"));
        }
    }

    {
        printf("== drill 10: a device that lies (answers with the wrong chunk) cannot get wrong bytes written\n");
        Lab w;
        w.make("a.bin", 2 * MiB + 9, 1);
        w.make("b.bin", MiB + 9, 2);
        w.destroy_mac();
        w.sa.stop();
        w.sa.faults = "swap_get";
        w.sa.start(w.devdir(0));
        RestoreReport both = recover_from_devices(w.master, w.both(), w.root + "/out");
        CHECK(both.complete() && matches(w.root + "/out", w.items["a.bin"]) && matches(w.root + "/out", w.items["b.bin"]));   // B's honest copies bridge it
        RestoreReport liar_only = recover_from_devices(w.master, {{"A", w.da.get()}}, w.root + "/out2");
        CHECK(!liar_only.complete() && liar_only.restored.empty() && liar_only.failed.size() == 2 && walk(w.root + "/out2").empty());   // refused, not wrong
    }

    {
        printf("== drill 11: devices that belong to different volumes are never mixed\n");
        Lab w;
        w.make("a.bin", MiB, 1);
        w.destroy_mac();
        w.sb.stop();
        fs::remove_all(w.devdir(1));
        w.sb.start(w.devdir(1));
        CHECK(w.db->bind("some-other-volume-0123456789abcdef").ok());
        RestoreReport r = recover_from_devices(w.master, w.both(), w.root + "/out");
        CHECK(has(r.fatal, "different volumes") && !exists(w.root + "/out"));
    }

    {
        printf("== drill 13: a catalogue bigger than one listing page (1,001 manifests) is read completely\n");
        Lab w;
        Item& one = w.make("b.txt", 1, 2);
        w.destroy_mac();
        bool all = true;
        for (int i = 0; i < 1000; i++) all = w.plant(one, "/bulk/" + std::to_string(i), true) && all;
        CHECK(all);
        RecoveryOptions dry;
        dry.dry_run = true;
        RestoreReport r = recover_from_devices(w.master, w.both(), w.root + "/out", dry);
        CHECK(r.fatal.empty() && r.manifests_listed == 1001 && r.manifests_opened == 1001 && r.planned.size() == 1001);
    }

    {
        printf("== drill 14: damaged manifests: another device's copy is used; if every copy is damaged that file is reported missing\n");
        Lab w;
        Item& a = w.make("a.bin", MiB + 5, 1);
        Item& b = w.make("b.bin", MiB + 6, 2);
        w.destroy_mac();
        auto mf = [&](int dev, const Item& it) { return w.devdir(dev) + "/manifests/" + it.fid + "/1.mf"; };
        auto flip = [&](const std::string& path) {
            int fd = ::open(path.c_str(), O_RDWR);
            uint8_t x = 0;
            if (fd >= 0) { pread(fd, &x, 1, 50); x ^= 0x01; pwrite(fd, &x, 1, 50); close(fd); }
        };
        flip(mf(0, a));                                                    // a's manifest rotted on A only
        RestoreReport r = recover_from_devices(w.master, w.both(), w.root + "/out");
        CHECK(r.complete() && r.restored.size() == 2 && r.manifests_opened == 2 && r.manifests_unreadable == 0 && matches(w.root + "/out", a) && matches(w.root + "/out", b));
        flip(mf(1, a));                                                    // now on B as well: nothing can say what a.bin is
        RestoreReport r2 = recover_from_devices(w.master, w.both(), w.root + "/out2");
        CHECK(r2.manifests_unreadable == 1 && r2.manifests_opened == 1 && r2.restored.size() == 1 && matches(w.root + "/out2", b) && !exists(w.root + "/out2" + a.logical));
        bool said = false;
        for (auto& x : r2.warnings) if (has(x, "cannot be opened") || has(x, "could not be opened")) said = true;
        CHECK(said);
        // an output "directory" that is really a file
        spit(w.root + "/afile", pattern(3, 1));
        RestoreReport r3 = recover_from_devices(w.master, w.both(), w.root + "/afile");
        CHECK(has(r3.fatal, "not a directory") && slurp(w.root + "/afile") == pattern(3, 1));
    }

    {
        printf("== drill 12: ledger-status tells the truth about a ledger, including an interrupted drop\n");
        Lab w;
        w.make("a.bin", MiB + 1, 1);
        w.make("b.bin", MiB + 2, 2);
        std::string text;
        int rc = sh(std::string(tierctl_path()) + " ledger-status " + w.root + "/ledger", &text);
        CHECK(rc == 1 && has(text, "in use"));                             // the running process owns it: refused, nothing touched
        CHECK(sh(std::string(tierctl_path()) + " ledger-status " + w.root + "/no-such-ledger", &text) == 1 && has(text, "no ledger.db") && !exists(w.root + "/no-such-ledger"));
        w.close_ledger();
        rc = sh(std::string(tierctl_path()) + " ledger-status " + w.root + "/ledger", &text);
        CHECK(rc == 0 && has(text, w.volume.c_str()) && has(text, "REPLICATED") && has(text, "open steps:  0") && has(text, "consistency: ok") && has(text, "device-a"));
        CHECK(has(text, "recovery phrase acknowledged: yes") && has(text, "backup acknowledged: NO"));
        CHECK(spawn_drop_crash(w, w.items["a.bin"].fid, "drop.after_sync"));   // power cut in the middle of a drop
        rc = sh(std::string(tierctl_path()) + " ledger-status " + w.root + "/ledger", &text);
        CHECK(rc == 3 && has(text, "open steps:  1") && has(text, "interrupted"));
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
