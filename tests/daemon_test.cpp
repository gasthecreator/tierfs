// Tests of the daemon (everything a mount needs, minus the mount): start-up recovery, the control socket, offloading and
// hydrating on command, devices that are down at start, the maintenance thread. Real device servers, real encryption.
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
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
#include "../core/daemon.hpp"
#include "../core/keysource.hpp"

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
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-daemontest-XXXXXX";
    std::vector<char> buf(t.begin(), t.end());
    buf.push_back(0);
    return mkdtemp(buf.data());
}
static uint16_t port_base() { return getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9571; }
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
static size_t count_files_under(const std::string& dir) {
    size_t n = 0;
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(dir, ec)) n += e.is_regular_file();
    return n;
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
    std::vector<std::string> args;  // extra command-line arguments for the next start
    explicit Server(uint16_t p) : port(p) {}
    bool start(const std::string& store) {
        stop();
        std::vector<std::string> a = {"tierfs-device", store, std::to_string(port), "127.0.0.1"};
        a.insert(a.end(), args.begin(), args.end());
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
            if (r.ok() || r.err == EPERM) return true;  // (a paired device answers a plaintext client with a refusal: it is up)
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


static int g_env = 0;

// A throwaway world: two device servers, an origin folder, a ledger directory, a key file.
struct Env {
    std::string root = tmpdir();
    std::string origin, ledger, keyfile, master_hex;
    Server sa{PA}, sb{PB};
    int n;
    explicit Env(bool start_a = true, bool start_b = true) {
        n = ++g_env;
        origin = root + "/origin";
        ledger = root + "/ledger";
        keyfile = root + "/key";
        fs::create_directories(origin);
        crypto::SecretKey k = crypto::SecretKey::random();
        master_hex = crypto::to_hex(k.data(), 32);
        std::ofstream(keyfile) << master_hex << "\n";
        if (start_a) sa.start(root + "/devA");
        if (start_b) sb.start(root + "/devB");
    }
    ~Env() { sa.stop(); sb.stop(); fs::remove_all(root); }
    std::string path(const std::string& rel) const { return origin + "/" + rel; }
    DaemonConfig config() const {
        DaemonConfig c;
        c.ledger_dir = ledger;
        c.origin_dir = origin;
        c.logical_prefix = "/Users/me/proj/";
        c.key_file = keyfile;
        c.devices = {"127.0.0.1:" + std::to_string(PA), "127.0.0.1:" + std::to_string(PB)};
        c.maint_seconds = 0;
        c.notify = false;
        c.device_timeout_ms = 3000;
        return c;
    }
    // The acknowledgements the user would have made (a throwaway ledger: the test prefix stands in for the backup)
    void open_gates(bool recovery = true) {
        std::string err;
        auto L = Ledger::open(ledger, &err);
        if (!L) { printf("      (cannot open the ledger: %s)\n", err.c_str()); return; }
        L->set_meta("recovery_acked", recovery ? "1" : "0");
        L->set_meta("test_prefix", "/Users/me/");
        L->ensure_reserve(1 << 20);
    }
};

static std::unique_ptr<Daemon> make(Env& e, std::string* err = nullptr, DaemonConfig* override = nullptr) {
    std::string local;
    auto d = Daemon::create(override ? *override : e.config(), err ? err : &local);
    return d;
}
static std::string talk(const std::string& sock, const std::string& line) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, sock.c_str(), sizeof sa.sun_path - 1);
    if (connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) { close(fd); return "CONNECT FAILED"; }
    std::string msg = line + "\n";
    (void)!write(fd, msg.data(), msg.size());
    std::string out;
    char buf[1024];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) out.append(buf, static_cast<size_t>(n));
    close(fd);
    return out;
}
static bool ends_ok(const std::string& r) { return r.size() >= 3 && r.compare(r.size() - 3, 3, "OK\n") == 0; }
static bool spawn_drop_crash(Env& e, const std::string& fid, const char* point, const std::string& ida, const std::string& idb, const std::string& consent) {
    std::vector<std::string> env;
    for (char** x = environ; *x; x++) env.push_back(*x);
    env.push_back(std::string("TIERFS_CRASH_AT=") + point);
    env.push_back("TIERFS_TEST_MASTER=" + e.master_hex);
    std::vector<char*> envp;
    for (auto& x : env) envp.push_back(const_cast<char*>(x.c_str()));
    envp.push_back(nullptr);
    std::vector<std::string> a = {"drop_helper", "drop", e.ledger, e.origin, e.origin + "/.tierfs/quarantine", std::to_string(PA), ida, std::to_string(PB), idb, consent, fid};
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
static Bytes read_through(Overlay& ov, const std::string& path, size_t size) {
    Bytes out(size + 1);
    int64_t n = ov.read(path, 0, size + 1, out.data());
    if (n < 0) return Bytes{};
    out.resize(static_cast<size_t>(n));
    return out;
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    setenv("TIERFS_DEVICE_MIN_SWEEP_AGE", "0", 1);  // (devices started with --allow-delete have no age floor in these tests)

    {
        printf("== configuration problems are reported, not papered over\n");
        Env e(false, false);
        std::string err;
        DaemonConfig c = e.config();
        c.key_file = e.root + "/missing";
        CHECK(!make(e, &err, &c) && has(err, "key file"));
        std::ofstream(e.root + "/short") << "abcd\n";
        c.key_file = e.root + "/short";
        CHECK(!make(e, &err, &c) && has(err, "64 hex"));
        c = e.config();
        c.devices = {"nonsense"};
        CHECK(!make(e, &err, &c) && has(err, "host:port"));
        c.devices = {"127.0.0.1:99999"};
        CHECK(!make(e, &err, &c) && has(err, "port"));
        c = e.config();
        c.origin_dir = "";
        CHECK(!make(e, &err, &c) && has(err, "required"));
        // a second daemon on the same ledger is refused (the ledger belongs to one process)
        auto first = make(e, &err);
        CHECK(first);
        auto second = make(e, &err);
        CHECK(!second && has(err, "in use"));
    }

    {
        printf("== start: devices attached, the folder scanned, the status says so\n");
        Env e;
        spit(e.path("a.bin"), pattern(MiB + 5, 1));
        fs::create_directories(e.path("sub"));
        spit(e.path("sub/b.txt"), pattern(100, 2));
        auto d = make(e);
        std::string err;
        CHECK(d && d->start(&err));
        CHECK(d->ledger().list_files_under("/Users/me/proj/").size() == 2 && d->ledger().list_devices().size() == 2);
        std::string st = d->control("status");
        CHECK(ends_ok(st) && has(st, "files LOCAL 2") && has(st, "attached") && !has(st, "not attached") && has(st, "volume "));
        CHECK(ends_ok(d->control("scan")) && has(d->control("scan"), "unchanged 2"));
        CHECK(has(d->control("frobnicate"), "ERR unknown command") && has(d->control("offload"), "ERR unknown") && has(d->control("offload /../x"), "ERR not a valid path"));
        std::string s1 = d->control("status");
        d->stop();
        d->stop();                                                          // stopping twice is harmless
        CHECK(true);
        (void)s1;
    }

    {
        printf("== offload on command: copied, audited, moved; readable from the devices; hydrated back; a refusal says why\n");
        Env e;
        Bytes a = pattern(2 * MiB + 5, 1), b = pattern(MiB + 7, 2), c = pattern(500, 3);
        spit(e.path("a.bin"), a);
        fs::create_directories(e.path("dir"));
        spit(e.path("dir/b.bin"), b);
        spit(e.path("dir/c.bin"), c);
        e.open_gates(false);                                                // the recovery phrase was NOT acknowledged
        {
            auto d = make(e);
            CHECK(d && d->start(nullptr));
            std::string r = d->control("offload /a.bin");
            CHECK(has(r, "refused /Users/me/proj/a.bin") && has(r, "recovery phrase") && has(r, "ERR") && exists(e.path("a.bin")));   // the ledger's gate held
        }
        e.open_gates(true);
        auto d = make(e);
        CHECK(d && d->start(nullptr));
        std::string r = d->control("offload /a.bin");
        CHECK(has(r, "offloaded /Users/me/proj/a.bin") && ends_ok(r) && !exists(e.path("a.bin")));
        CHECK(read_through(d->overlay(), "/a.bin", a.size()) == a);
        std::string rd = d->control("offload /dir");
        CHECK(has(rd, "offloaded 2, refused 0") && ends_ok(rd) && !exists(e.path("dir/b.bin")) && !exists(e.path("dir/c.bin")));
        CHECK(read_through(d->overlay(), "/dir/b.bin", b.size()) == b && read_through(d->overlay(), "/dir/c.bin", c.size()) == c);
        CHECK(has(d->control("status"), "files OFFLOADED 3") && has(d->control("status"), "quarantine held 3"));
        CHECK(ends_ok(d->control("hydrate /a.bin")) && slurp(e.path("a.bin")) == a);
        CHECK(has(d->control("hydrate /nope"), "ERR") && has(d->control("replicate /nope"), "replicated 0"));
        // delete an offloaded file, then undelete it
        CHECK(d->overlay().unlink("/dir/b.bin") == 0 && has(d->control("undelete /dir/b.bin"), "OK") && read_through(d->overlay(), "/dir/b.bin", b.size()) == b);
        CHECK(has(d->control("undelete /dir/b.bin"), "ERR") && has(d->control("undelete /nope"), "ERR"));
        // replicate without moving anything
        spit(e.path("keep.bin"), pattern(MiB, 9));
        d->control("scan");
        std::string rr = d->control("replicate /keep.bin");
        CHECK(has(rr, "replicated /Users/me/proj/keep.bin") && exists(e.path("keep.bin")) && d->ledger().get_file_by_path("/Users/me/proj/keep.bin")->state == FileState::REPLICATED);
    }

    {
        printf("== the control socket: private, answers, replaced when stale, removed at the end\n");
        Env e;
        spit(e.path("a.bin"), pattern(100, 1));
        std::string sock = e.ledger + "/control.sock";
        {
            auto d = make(e);
            CHECK(d && d->start(nullptr));
            struct stat st;
            CHECK(stat(sock.c_str(), &st) == 0 && S_ISSOCK(st.st_mode) && (st.st_mode & 0777) == 0600);
            std::string r = talk(sock, "status");
            CHECK(ends_ok(r) && has(r, "files LOCAL 1"));
            CHECK(has(talk(sock, "scan"), "unchanged 1") && has(talk(sock, "nonsense"), "ERR unknown command"));
            CHECK(ends_ok(talk(sock, "status\r")));                         // a CRLF line works too
            std::string big(5000, 'x');
            CHECK(has(talk(sock, "offload " + big), "ERR"));                // an oversized line is not a crash
            CHECK(ends_ok(talk(sock, "status")));
        }
        CHECK(!exists(sock));                                               // removed when the daemon stops
        // a stale socket file from a crashed run does not stop a new daemon
        std::ofstream(sock) << "stale";
        auto d2 = make(e);
        CHECK(d2 && d2->start(nullptr) && ends_ok(talk(sock, "status")));
        // a path too long for a unix socket is a clear error
        DaemonConfig c = e.config();
        c.ledger_dir = e.root + "/" + std::string(120, 'l');
        auto d3 = Daemon::create(c, nullptr);
        std::string err;
        CHECK(d3 && !d3->start(&err) && has(err, "too long"));
    }

    {
        printf("== a device that is down at start: the folder still works, and the device is attached when it comes back\n");
        Env e(true, false);
        Bytes a = pattern(MiB + 5, 1);
        spit(e.path("a.bin"), a);
        e.open_gates(true);
        DaemonConfig c = e.config();
        c.maint_seconds = 1;
        c.background_replication = false;
        auto d = make(e, nullptr, &c);
        CHECK(d && d->start(nullptr));
        CHECK(has(d->control("status"), "not attached") && d->ledger().list_devices().size() == 1);
        std::string r = d->control("offload /a.bin");
        CHECK(has(r, "refused") && exists(e.path("a.bin")));                // one device is not enough copies
        e.sb.start(e.root + "/devB");
        bool attached = false;
        for (int i = 0; i < 60 && !attached; i++) { usleep(200000); attached = d->ledger().list_devices().size() == 2; }
        CHECK(attached);
        CHECK(has(d->control("offload /a.bin"), "offloaded /Users/me/proj/a.bin") && read_through(d->overlay(), "/a.bin", a.size()) == a);
    }

    {
        printf("== the maintenance thread: finds new files, copies cold ones (never moves them), and says nothing it should not\n");
        Env e;
        Bytes a = pattern(MiB + 5, 1);
        spit(e.path("a.bin"), a);
        e.open_gates(true);
        DaemonConfig c = e.config();
        c.maint_seconds = 1;
        c.policy.replicate_idle_seconds = 0;      // everything counts as cold enough to copy
        c.policy.min_size = 1;
        auto d = make(e, nullptr, &c);
        CHECK(d && d->start(nullptr));
        spit(e.path("late.bin"), pattern(MiB + 9, 4));                      // appears after the start
        bool copied = false;
        for (int i = 0; i < 100 && !copied; i++) {
            usleep(200000);
            auto la = d->ledger().get_file_by_path("/Users/me/proj/late.bin");
            auto aa = d->ledger().get_file_by_path("/Users/me/proj/a.bin");
            copied = la && aa && la->state == FileState::REPLICATED && aa->state == FileState::REPLICATED;
        }
        CHECK(copied && exists(e.path("a.bin")) && exists(e.path("late.bin")));   // copied to the devices, nothing moved
        CHECK(d->ledger().list_quarantine().empty() && d->ledger().open_intents().empty());
        CHECK(has(d->control("tick"), "OK"));
    }

    {
        printf("== start-up recovery: a cut-off drop is finished or undone before anything is served\n");
        Env e;
        Bytes a = pattern(MiB + 5, 1);
        spit(e.path("a.bin"), a);
        e.open_gates(true);
        std::string fid, ida, idb, consent;
        {
            auto d = make(e);
            CHECK(d && d->start(nullptr));
            CHECK(has(d->control("replicate /a.bin"), "replicated 1"));
            fid = d->ledger().get_file_by_path("/Users/me/proj/a.bin")->file_id;
            auto devs = d->ledger().list_devices();
            ida = devs[0].device_id;
            idb = devs[1].device_id;
            consent = d->ledger().create_consent("/Users/me/", 600, "test");
        }
        CHECK(spawn_drop_crash(e, fid, "drop.after_sync", ida, idb, consent));    // the bytes are in quarantine, the ledger says DROPPING
        CHECK(!exists(e.path("a.bin")));
        auto d = make(e);
        CHECK(d && d->start(nullptr));
        bool recovered = false;
        for (auto& n : d->startup_notes()) if (has(n, "recovered")) recovered = true;
        CHECK(recovered);
        auto f = d->ledger().get_file(fid);
        CHECK(f->state == FileState::OFFLOADED || f->state == FileState::REPLICATED);
        CHECK(d->ledger().open_intents().empty() && d->ledger().fsck().empty());
        CHECK(read_through(d->overlay(), "/a.bin", a.size()) == a);
    }

    {
        printf("== a folder that is not there at start: the daemon starts, forgets nothing, and says so\n");
        Env e;
        for (int i = 0; i < 12; i++) spit(e.path("f" + std::to_string(i)), pattern(10, static_cast<uint8_t>(i)));
        {
            auto d = make(e);
            CHECK(d && d->start(nullptr) && d->ledger().list_files_under("/Users/me/proj/").size() == 12);
        }
        fs::rename(e.origin, e.root + "/origin-away");
        auto d = make(e);
        CHECK(d && d->start(nullptr));
        bool said = false;
        for (auto& n : d->startup_notes()) if (has(n, "ABORTED")) said = true;
        CHECK(said && d->ledger().list_retired().empty() && d->ledger().list_files_under("/Users/me/proj/").size() == 12);
        std::string sc = d->control("scan");
        CHECK(has(sc, "ERR scan aborted") && d->ledger().list_retired().empty());
    }

    {
        printf("== the daemon matches the ledger's name rule to the volume\n");
        Env e;
        spit(e.path("a.bin"), pattern(100, 1));
        {   // a ledger that was told "case-sensitive" but already tracks a file, on a volume that is not
            std::string err;
            auto L = Ledger::open(e.ledger, &err);
            CHECK(L && L->set_case_sensitive(true).ok);
            L->track_file("/Users/me/proj/a.bin", 100, 1, 0644);
        }
        auto d = make(e);
        CHECK(d && d->start(nullptr));
        bool volume_is_sensitive = pathconf(e.origin.c_str(), _PC_CASE_SENSITIVE) == 1;
        bool noted = false;
        for (auto& n : d->startup_notes()) if (has(n, "NEEDS ATTENTION") && has(n, "case")) noted = true;
        CHECK(volume_is_sensitive ? !noted : noted);
        // a fresh ledger simply follows the volume
        Env e2;
        auto d2 = make(e2);
        CHECK(d2 && d2->start(nullptr) && d2->ledger().case_sensitive() == (pathconf(e2.origin.c_str(), _PC_CASE_SENSITIVE) == 1));
    }

    {
        printf("== offload on command honours the dated backup: a file made after the backup stays, an unchanged one moves\n");
        Env e;
        Bytes a = pattern(MiB + 5, 1), b = pattern(MiB + 6, 2);
        spit(e.path("a.bin"), a);
        auto d = make(e);
        CHECK(d && d->start(nullptr));  // a.bin is tracked now
        // real gates (no test area): the phrase acknowledged, a reserve, and a backup recorded AFTER a.bin was tracked
        d->ledger().set_meta("recovery_acked", "1");
        d->ledger().ensure_reserve(1 << 20);
        d->ledger().set_meta("test_prefix", "/nowhere/");
        sleep(2);
        CHECK(d->ledger().ack_backup().ok);
        sleep(2);
        spit(e.path("b.bin"), b);  // created after the backup
        CHECK(has(d->control("scan"), "new 1"));
        std::string r = d->control("offload /a.bin");
        CHECK(has(r, "offloaded /Users/me/proj/a.bin") && !exists(e.path("a.bin")) && read_through(d->overlay(), "/a.bin", a.size()) == a);
        std::string rb = d->control("offload /b.bin");
        CHECK(has(rb, "refused /Users/me/proj/b.bin") && has(rb, "created or changed after the backup") && has(rb, "ERR") && exists(e.path("b.bin")));
        sleep(2);
        CHECK(d->ledger().ack_backup().ok);  // the owner backs up again and says so
        CHECK(has(d->control("offload /b.bin"), "offloaded /Users/me/proj/b.bin") && !exists(e.path("b.bin")));
    }

    {
        printf("== the daemon takes its key from a key store, by volume id\n");
        Env e;
        spit(e.path("a.bin"), pattern(MiB + 5, 1));
        std::string volume;
        {  // the volume exists first (as after `tierctl init`); the key is stored under its id
            std::string err;
            auto L = Ledger::open(e.ledger, &err);
            CHECK(L);
            volume = L->volume_id();
        }
        std::string ks_dir = e.root + "/keystore";
        DaemonConfig c = e.config();
        c.key_file = "dir:" + ks_dir;
        std::string err;
        auto none = Daemon::create(c, &err);
        CHECK(!none && has(err, "no key for volume") && has(err, volume.c_str()));
        auto ks = crypto::make_file_keystore(ks_dir);
        crypto::SecretKey key = crypto::SecretKey::random();
        CHECK(ks->store(volume, key));
        {
            auto d = Daemon::create(c, &err);
            CHECK(d && d->start(nullptr) && has(d->control("status"), "files LOCAL 1"));
        }
        // the same key through the legacy key-file form gives the same volume the same keys: data written under one is readable under the other
        std::ofstream(e.root + "/same-key") << crypto::to_hex(key.data(), 32) << "\n";
        c.key_file = e.root + "/same-key";
        auto d2 = Daemon::create(c, &err);
        CHECK(d2 && d2->start(nullptr));
        d2.reset();  // (the ledger belongs to one daemon at a time)
        // nonsense sources are errors, not guesses
        c.key_file = "dir:";
        CHECK(!Daemon::create(c, &err) && has(err, "needs a path"));
        c.key_file = e.root + "/does-not-exist";
        CHECK(!Daemon::create(c, &err) && has(err, "cannot read the key file"));
    }

    {
        printf("== garbage collection on command: a plan changes nothing, a run forgets old versions and deleted files, the newest stays readable\n");
        Env e(false, false);
        e.sa.args = {"--allow-delete"};
        e.sb.args = {"--allow-delete"};
        e.sa.start(e.root + "/devA");
        e.sb.start(e.root + "/devB");
        e.open_gates(true);
        DaemonConfig cfg = e.config();
        cfg.gc_config.keep_versions = 1;
        cfg.gc_config.rules.grace_seconds = 0;
        cfg.gc_config.rules.deleted_retention_seconds = 0;
        cfg.gc_config.sweep_min_age = 0;
        Bytes v1 = pattern(MiB + 5, 1), v2 = pattern(MiB + 7, 2), w = pattern(300, 5);
        spit(e.path("v.bin"), v1);
        spit(e.path("w.bin"), w);
        auto d = make(e, nullptr, &cfg);
        CHECK(d && d->start(nullptr));
        CHECK(has(d->control("replicate /v.bin"), "replicated /Users/me/proj/v.bin") &&
              has(d->control("replicate /w.bin"), "replicated /Users/me/proj/w.bin"));
        spit(e.path("v.bin"), v2);
        struct utimbuf tb = {time(nullptr) + 5, time(nullptr) + 5};
        utime(e.path("v.bin").c_str(), &tb);
        CHECK(ends_ok(d->control("scan")) && has(d->control("replicate /v.bin"), "replicated /Users/me/proj/v.bin"));
        auto fid = d->ledger().get_file_by_path("/Users/me/proj/v.bin")->file_id;
        CHECK(d->ledger().get_file(fid)->current_version == 2 &&
              count_files_under(e.root + "/devA/manifests") == 3);  // v1 and v2 of v.bin, v1 of w.bin
        uint64_t events = d->ledger().event_count();
        std::string plan = d->control("gc-plan");
        CHECK(ends_ok(plan) && has(plan, "plan only") && has(plan, "versions the rules would let go of: 1") && d->ledger().event_count() == events &&
              d->ledger().pruned_count() == 0);
        std::string run = d->control("gc-run");
        CHECK(ends_ok(run) && has(run, "decided now: 1") && has(run, "manifests deleted 1") && has(run, "deletions still owed by devices: 0"));
        CHECK(d->ledger().pruned_count() == 1 && d->ledger().is_version_pruned(fid, 1) && d->ledger().get_meta("gc_last_run").has_value());
        CHECK(count_files_under(e.root + "/devA/manifests") == 2 && count_files_under(e.root + "/devB/manifests") == 2);
        // the newest version is still there, whole: move it off the Mac and read it back from the devices
        CHECK(has(d->control("offload /v.bin"), "offloaded /Users/me/proj/v.bin") && !exists(e.path("v.bin")));
        CHECK(read_through(d->overlay(), "/v.bin", v2.size()) == v2);
        // delete a file: it goes after its retention period (here: at once)
        CHECK(d->overlay().unlink("/w.bin") == 0);
        std::string run2 = d->control("gc-run");
        CHECK(ends_ok(run2) && has(run2, "decided now: 1") && count_files_under(e.root + "/devA/manifests") == 1 &&
              count_files_under(e.root + "/devB/manifests") == 1);
        CHECK(d->ledger().fsck().empty() && has(d->control("gc-run"), "decided now: 0"));
    }

    {
        printf("== the daemon reads ahead for a sequential reader of an offloaded file, unless told not to\n");
        for (int ra = 0; ra < 2; ra++) {
            Env e;
            e.open_gates(true);
            DaemonConfig cfg = e.config();
            if (ra == 1) cfg.readahead_chunks = 0;
            Bytes big = pattern(5 * MiB + 9, 3);
            spit(e.path("big.bin"), big);
            auto d = make(e, nullptr, &cfg);
            CHECK(d && d->start(nullptr));
            CHECK(has(d->control("offload /big.bin"), "offloaded /Users/me/proj/big.bin") && !exists(e.path("big.bin")));
            Bytes got;
            std::vector<uint8_t> b(128 * 1024);
            for (uint64_t off = 0; off < big.size(); off += b.size()) {
                int64_t n = d->overlay().read("/big.bin", off, b.size(), b.data());
                if (n < 0) break;
                got.insert(got.end(), b.begin(), b.begin() + n);
            }
            CHECK(got == big);
            usleep(300000);
            if (ra == 0) CHECK(d->overlay().stats().prefetched > 0);
            else CHECK(d->overlay().stats().prefetched == 0);
        }
    }

    {
        printf("== the maintenance thread collects garbage only when switched on\n");
        for (int on = 0; on < 2; on++) {
            Env e(false, false);
            e.sa.args = {"--allow-delete"};
            e.sb.args = {"--allow-delete"};
            e.sa.start(e.root + "/devA");
            e.sb.start(e.root + "/devB");
            e.open_gates(true);
            DaemonConfig cfg = e.config();
            cfg.maint_seconds = 1;
            cfg.gc = on == 1;
            cfg.gc_interval_seconds = 1;
            cfg.gc_config.keep_versions = 1;
            cfg.gc_config.rules.grace_seconds = 0;
            cfg.gc_config.sweep_min_age = 0;
            cfg.background_replication = false;
            spit(e.path("m.bin"), pattern(MiB, 1));
            auto d = make(e, nullptr, &cfg);
            CHECK(d && d->start(nullptr));
            d->control("replicate /m.bin");
            spit(e.path("m.bin"), pattern(MiB + 3, 2));
            struct utimbuf tb = {time(nullptr) + 5, time(nullptr) + 5};
            utime(e.path("m.bin").c_str(), &tb);
            d->control("scan");
            d->control("replicate /m.bin");
            CHECK(count_files_under(e.root + "/devA/manifests") == 2);
            for (int i = 0; i < 60 && count_files_under(e.root + "/devA/manifests") == 2; i++) usleep(200000);
            if (on)
                CHECK(count_files_under(e.root + "/devA/manifests") == 1 && count_files_under(e.root + "/devB/manifests") == 1 &&
                      d->ledger().pruned_count() == 1);
            else
                CHECK(count_files_under(e.root + "/devA/manifests") == 2 && d->ledger().pruned_count() == 0);
            d->stop();
        }
    }

    {
        printf("== paired devices: the daemon authenticates with secrets from the key store, and offloading works through the channel\n");
        Env e(false, false);
        Bytes a = pattern(MiB + 5, 1);
        spit(e.path("a.bin"), a);
        auto run = [&](const std::string& store) {  // `tierfs-device <store> --show-pairing-code`: the secret and its key id
            std::string cmd = std::string("./build/tierfs-device '") + store + "' --show-pairing-code 2>&1";
            FILE* f = popen(cmd.c_str(), "r");
            std::string out;
            char buf[512];
            while (size_t n = fread(buf, 1, sizeof buf, f)) out.append(buf, n);
            pclose(f);
            size_t s0 = out.find("\n\n    ") + 6;
            std::string err;
            auto k = crypto::decode_recovery(out.substr(s0, out.find('\n', s0) - s0), &err);
            size_t k0 = out.find("key id: ") + 8;
            return std::make_pair(k ? Bytes(k->data(), k->data() + 32) : Bytes{}, out.substr(k0, 16));
        };
        auto pa = run(e.root + "/devA"), pb = run(e.root + "/devB");
        CHECK(pa.first.size() == 32 && pb.first.size() == 32 && pa.second != pb.second);
        CHECK(e.sa.start(e.root + "/devA") && e.sb.start(e.root + "/devB"));  // paired devices: they now require the channel
        std::string ks_dir = e.root + "/keystore", volume, err;
        {
            auto L = Ledger::open(e.ledger, &err);
            CHECK(L);
            volume = L->volume_id();
        }
        crypto::SecretKey master = crypto::SecretKey::random();
        CHECK(crypto::make_file_keystore(ks_dir)->store(volume, master));
        CHECK(store_pairing_secret("dir:" + ks_dir, pa.first, &err) && store_pairing_secret("dir:" + ks_dir, pb.first, &err));
        e.open_gates(true);
        DaemonConfig c = e.config();
        c.key_file = "dir:" + ks_dir;
        c.devices = {"127.0.0.1:" + std::to_string(PA) + "@" + pa.second, "127.0.0.1:" + std::to_string(PB) + "@" + pb.second};
        {
            auto d = Daemon::create(c, &err);
            CHECK(d && d->start(nullptr));
            std::string st = d->control("status");
            CHECK(has(st, "attached") && !has(st, "not attached") && d->ledger().list_devices().size() == 2);
            std::string r = d->control("offload /a.bin");
            CHECK(has(r, "offloaded /Users/me/proj/a.bin") && !exists(e.path("a.bin")) && read_through(d->overlay(), "/a.bin", a.size()) == a);
            CHECK(ends_ok(d->control("hydrate /a.bin")) && slurp(e.path("a.bin")) == a);
        }
        // the same devices without their secrets stay unattached, and the daemon says so instead of failing
        c.devices = {"127.0.0.1:" + std::to_string(PA), "127.0.0.1:" + std::to_string(PB)};
        {
            auto d = Daemon::create(c, &err);
            CHECK(d && d->start(nullptr) && has(d->control("status"), "not attached") && has(d->control("offload /a.bin"), "refused"));
        }
        // a configuration with a key id that is not in the store, or a malformed one, is refused up front
        c.devices = {"127.0.0.1:" + std::to_string(PA) + "@0123456789abcdef"};
        CHECK(!Daemon::create(c, &err) && has(err, "no pairing secret"));
        c.devices = {"127.0.0.1:" + std::to_string(PA) + "@nothex"};
        CHECK(!Daemon::create(c, &err) && has(err, "16 hex"));
        c.devices = {"127.0.0.1:" + std::to_string(PA) + "@" + pa.second};
        c.key_file = e.root + "/plain-key-file";
        std::ofstream(c.key_file) << crypto::to_hex(master.data(), 32) << "\n";
        CHECK(!Daemon::create(c, &err) && has(err, "key store"));  // a plain key file cannot hold pairing secrets
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
