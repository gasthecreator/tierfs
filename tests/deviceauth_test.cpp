// Tests of device authentication end to end: real tierfs-device processes, real clients, real sockets.
// A paired device accepts only the authenticated channel; an open device keeps the old plaintext behaviour (loopback only).
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <thread>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "../core/deviceclient.hpp"
#include "../core/securechannel.hpp"

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
#define CHECK_QUIET(cond)                                   \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("FAIL  line %d: %s\n", __LINE__, #cond); \
            failures++;                                     \
            if (failfast()) {                               \
                fflush(stdout);                             \
                _exit(1);                                   \
            }                                               \
        }                                                   \
    } while (0)

static bool has(const std::string& s, const std::string& n) { return s.find(n) != std::string::npos; }
static std::string tmpdir() {
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-authtest-XXXXXX";
    std::vector<char> b(t.begin(), t.end());
    b.push_back(0);
    return mkdtemp(b.data());
}
static uint16_t port_base() { return getenv("TIERFS_TEST_PORT") ? static_cast<uint16_t>(atoi(getenv("TIERFS_TEST_PORT"))) : 9581; }
static const char* server_path() { return getenv("TIERFS_DEVICE_SERVER") ? getenv("TIERFS_DEVICE_SERVER") : "./build/tierfs-device"; }

// Runs tierfs-device with the given arguments to completion; returns its exit status and combined output.
static int run_device(const std::vector<std::string>& args, std::string* out) {
    std::string cmd = server_path();
    for (auto& a : args) cmd += " '" + a + "'";
    FILE* f = popen((cmd + " 2>&1").c_str(), "r");
    if (!f) return -1;
    char buf[2048];
    std::string o;
    while (size_t n = fread(buf, 1, sizeof buf, f)) o.append(buf, n);
    int st = pclose(f);
    if (out) *out = o;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

// Like run_device, but under `ulimit -f 0` with SIGXFSZ ignored: every write to a file fails with EFBIG.
static int run_device_no_writes(const std::vector<std::string>& args, std::string* out) {
    std::string cmd = std::string("trap '' XFSZ; ulimit -f 0; exec ") + server_path();
    for (auto& a : args) cmd += " '" + a + "'";
    FILE* f = popen(("/bin/sh -c \"" + cmd + "\" 2>&1").c_str(), "r");
    if (!f) return -1;
    char buf[2048];
    std::string o;
    while (size_t n = fread(buf, 1, sizeof buf, f)) o.append(buf, n);
    int st = pclose(f);
    if (out) *out = o;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

struct Server {
    pid_t pid = 0;
    uint16_t port;
    std::string log;  // when set, the server's stderr goes here
    explicit Server(uint16_t p) : port(p) {}
    bool start(const std::string& store, const std::vector<std::string>& extra = {}, const std::string& handshake_ms = "") {
        stop();
        std::vector<std::string> a = {"tierfs-device", store, std::to_string(port), "127.0.0.1"};
        a.insert(a.end(), extra.begin(), extra.end());
        std::vector<char*> av;
        for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
        av.push_back(nullptr);
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
        if (log.empty())
            posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
        else
            posix_spawn_file_actions_addopen(&fa, 2, log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (!handshake_ms.empty()) setenv("TIERFS_DEVICE_HANDSHAKE_MS", handshake_ms.c_str(), 1);
        int rc = posix_spawn(&pid, server_path(), &fa, nullptr, av.data(), environ);
        unsetenv("TIERFS_DEVICE_HANDSHAKE_MS");
        posix_spawn_file_actions_destroy(&fa);
        if (rc != 0) return false;
        for (int i = 0; i < 100; i++) {  // up when something accepts a connection
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
            bool up = connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
            close(fd);
            if (up) return true;
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

static int raw_connect(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int open_fds() {
    int n = 0;
    if (DIR* d = opendir("/dev/fd")) {
        while (readdir(d)) n++;
        closedir(d);
    }
    return n;
}

// A listening socket on an ephemeral loopback port.
static int listen_ephemeral(uint16_t* port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    socklen_t l = sizeof sa;
    getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &l);
    *port = ntohs(sa.sin_port);
    return fd;
}

// The pairing secret a device printed (or stored): 32 bytes.
static Bytes secret_from_code(const std::string& out) {
    size_t start = out.find("\n\n    ");
    if (start == std::string::npos) return {};
    start += 6;
    std::string code = out.substr(start, out.find('\n', start) - start);
    std::string err;
    auto k = crypto::decode_recovery(code, &err);
    return k ? Bytes(k->data(), k->data() + 32) : Bytes{};
}
static std::string read_text(const std::string& p) {
    std::ifstream f(p);
    std::string s;
    std::getline(f, s);
    return s;
}

static std::string read_all(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static Bytes blob_of(size_t n, uint8_t seed) {
    Bytes b(n);
    for (size_t i = 0; i < n; i++) b[i] = static_cast<uint8_t>(seed + i * 7);
    return b;
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    std::string root = tmpdir();
    const uint16_t P = port_base();

    printf("== pairing codes: created once, shown again on request, replaced only on purpose\n");
    std::string store = root + "/paired";
    std::string out1, out2, out3;
    CHECK(run_device({store, "--show-pairing-code"}, &out1) == 0 && has(out1, "PAIRING CODE") && has(out1, "key id:"));
    Bytes psk = secret_from_code(out1);
    CHECK(psk.size() == 32 && crypto::to_hex(psk.data(), 32) == read_text(store + "/pairing.key") && has(out1, chan::key_id_hex(psk)));
    struct stat st;
    CHECK(stat((store + "/pairing.key").c_str(), &st) == 0 && (st.st_mode & 07777) == 0600);
    CHECK(run_device({store, "--show-pairing-code"}, &out2) == 0 && secret_from_code(out2) == psk &&
          !has(out2, "must pair again"));                                  // the same secret again
    CHECK(stat(store.c_str(), &st) == 0 && (st.st_mode & 07777) == 0700);  // the directory the device made is private too
    {
        std::ifstream f(store + "/pairing.key", std::ios::binary);
        std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        CHECK(raw == crypto::to_hex(psk.data(), 32) + "\n");
    }
    CHECK(run_device({store, "--new-pairing-code"}, &out3) == 0 && has(out3, "every Mac must pair again") && secret_from_code(out3).size() == 32 &&
          secret_from_code(out3) != psk);
    Bytes psk2 = secret_from_code(out3);
    CHECK(crypto::to_hex(psk2.data(), 32) == read_text(store + "/pairing.key") && stat((store + "/pairing.key").c_str(), &st) == 0 &&
          (st.st_mode & 07777) == 0600);
    CHECK(!fs::exists(store + "/pairing.key.new"));
    std::string ow;
    CHECK(run_device({root + "/other", "--new-pairing-code"}, &ow) == 0 && !has(ow, "every Mac must pair again"));  // nothing to replace
    CHECK(has(ow, "PAIRING CODE") && secret_from_code(ow).size() == 32);

    printf("== creating the secret copes with leftovers and refuses to pretend when it cannot write\n");
    {
        std::string o;
        std::string left = root + "/leftover";
        fs::create_directories(left);
        {
            std::ofstream f(left + "/pairing.key.new");
            f << "junk from an interrupted run\n";
        }
        chmod((left + "/pairing.key.new").c_str(), 0644);
        CHECK(run_device({left, "--show-pairing-code"}, &o) == 0 && secret_from_code(o).size() == 32);
        struct stat lst;
        CHECK(stat((left + "/pairing.key").c_str(), &lst) == 0 && (lst.st_mode & 07777) == 0600 && lst.st_size == 65 &&
              !fs::exists(left + "/pairing.key.new"));
        // a store directory that cannot be written
        std::string ro = root + "/readonly";
        fs::create_directories(ro);
        chmod(ro.c_str(), 0500);
        CHECK(run_device({ro, "--show-pairing-code"}, &o) == 1 && has(o, "cannot create") && has(o, "pairing.key.new") &&
              !fs::exists(ro + "/pairing.key"));
        chmod(ro.c_str(), 0700);
        // a write that fails half way leaves nothing behind and does not print a code
        std::string nw = root + "/nowrite";
        fs::create_directories(nw);
        CHECK(run_device_no_writes({nw, "--show-pairing-code"}, &o) == 1 && has(o, "cannot write") && !has(o, "PAIRING CODE") &&
              !fs::exists(nw + "/pairing.key") && !fs::exists(nw + "/pairing.key.new"));
        std::string nw2 = root + "/nowrite-replace";
        run_device({nw2, "--show-pairing-code"}, &o);
        std::string before = read_text(nw2 + "/pairing.key");
        CHECK(run_device_no_writes({nw2, "--new-pairing-code"}, &o) == 1 && !has(o, "PAIRING CODE") && read_text(nw2 + "/pairing.key") == before &&
              !fs::exists(nw2 + "/pairing.key.new"));
        // asking to show the code of a damaged secret is refused, and does not replace it
        std::string dmg = root + "/damaged";
        fs::create_directories(dmg);
        {
            std::ofstream f(dmg + "/pairing.key");
            f << "not hex\n";
        }
        chmod((dmg + "/pairing.key").c_str(), 0600);
        CHECK(run_device({dmg, "--show-pairing-code"}, &o) == 1 && has(o, "64 hex characters") && !has(o, "PAIRING CODE") &&
              read_text(dmg + "/pairing.key") == "not hex");
        CHECK(run_device({dmg, "--new-pairing-code"}, &o) == 1 && read_text(dmg + "/pairing.key") == "not hex");
        std::string loose = root + "/looseshow";
        run_device({loose, "--show-pairing-code"}, nullptr);
        chmod((loose + "/pairing.key").c_str(), 0640);
        CHECK(run_device({loose, "--show-pairing-code"}, &o) == 1 && has(o, "readable only by its owner") && !has(o, "PAIRING CODE"));
    }

    printf("== a damaged or careless pairing file stops the device instead of weakening it\n");
    {
        // an address that is not ours: a device that accepted the file would fail to bind with a different message
        const std::string nowhere = "192.0.2.1";
        std::string o;
        int n = 0;
        for (mode_t m : {0644, 0640, 0604, 0620, 0602, 0660, 0606, 0666, 0610, 0601}) {
            std::string sm = root + "/loose" + std::to_string(n++);
            run_device({sm, "--show-pairing-code"}, nullptr);
            chmod((sm + "/pairing.key").c_str(), m);
            CHECK(run_device({sm, std::to_string(P + 9), nowhere}, &o) == 1 && has(o, "readable only by its owner"));
        }
        {  // the owner's own bits are free to vary
            std::string sm = root + "/ownerbits";
            run_device({sm, "--show-pairing-code"}, nullptr);
            chmod((sm + "/pairing.key").c_str(), 0400);
            CHECK(run_device({sm, std::to_string(P + 9), nowhere}, &o) == 1 && !has(o, "readable only by its owner"));
        }
        std::string s2 = root + "/garbled";
        fs::create_directories(s2);
        {
            std::ofstream f(s2 + "/pairing.key");
            f << "not hex\n";
        }
        chmod((s2 + "/pairing.key").c_str(), 0600);
        CHECK(run_device({s2, std::to_string(P + 9)}, &o) == 1 && has(o, "64 hex characters"));
        std::string s3 = root + "/short";
        fs::create_directories(s3);
        {
            std::ofstream f(s3 + "/pairing.key");
            f << std::string(62, 'a') << "\n";
        }
        chmod((s3 + "/pairing.key").c_str(), 0600);
        CHECK(run_device({s3, std::to_string(P + 9)}, &o) == 1 && has(o, "64 hex characters"));
        std::string s3b = root + "/long";
        fs::create_directories(s3b);
        {
            std::ofstream f(s3b + "/pairing.key");
            f << std::string(66, 'a') << "\n";
        }
        chmod((s3b + "/pairing.key").c_str(), 0600);
        CHECK(run_device({s3b, std::to_string(P + 9), nowhere}, &o) == 1 && has(o, "64 hex characters"));
        std::string s4 = root + "/linked";
        fs::create_directories(s4);
        std::string target = root + "/elsewhere.key";
        {
            std::ofstream f(target);
            f << std::string(64, 'a') << "\n";
        }
        chmod(target.c_str(), 0600);
        symlink(target.c_str(), (s4 + "/pairing.key").c_str());
#ifdef __APPLE__
        lchmod((s4 + "/pairing.key").c_str(),
               0600);  // a link that looks private still is not a regular file (elsewhere a link has no mode of its own)
#endif
        CHECK(run_device({s4, std::to_string(P + 9), nowhere}, &o) == 1 && has(o, "regular file"));
        std::string s5 = root + "/dirkey";
        fs::create_directories(s5 + "/pairing.key");
        chmod((s5 + "/pairing.key").c_str(), 0700);
        CHECK(run_device({s5, std::to_string(P + 9), nowhere}, &o) == 1 && has(o, "regular file"));
    }

    printf("== where a device may listen\n");
    {
        std::string o;
        std::string open_store = root + "/open";
        CHECK(run_device({open_store, std::to_string(P + 9), "192.0.2.1"}, &o) == 2 && has(o, "not paired") && has(o, "--show-pairing-code") &&
              has(o, "--insecure-allow-network"));  // unpaired: loopback only
        CHECK(run_device({open_store, std::to_string(P + 9), "192.0.2.1", "--insecure-allow-network"}, &o) == 1 &&
              !has(o, "not paired"));  // the flag lifts it (the bind then fails: not our address)
        CHECK(run_device({store, std::to_string(P + 9), "192.0.2.1"}, &o) == 1 &&
              !has(o, "not paired"));  // paired: allowed to try (this address is not ours, so bind fails)
    }

    // ---- a paired device, with real clients ----
    Server srv(P);
    srv.log = root + "/paired-banner.log";
    CHECK(srv.start(store));
    CHECK(has(read_all(srv.log), "PAIRED, authenticated channel required") && !has(read_all(srv.log), "NOT PAIRED") &&
          has(read_all(srv.log), "deletions accepted"));
    {
        printf("== the right secret: every operation works through the channel\n");
        DeviceClient dc("127.0.0.1", P, 3000, psk2);
        DevInfo info;
        CHECK(dc.info(info).ok() && !info.device_id.empty() && info.volume_id.empty());
        CHECK(dc.bind("volume-auth-test-0123456789abcdef").ok());
        Bytes blob = blob_of(1u << 20, 3);
        std::string cid = std::string(64, 'a');
        PutChunkReply pr;
        CHECK(dc.put_chunk(cid, blob, pr).ok() && !pr.existed);
        Bytes got;
        CHECK(dc.get_chunk(cid, got).ok() && got == blob);  // a megabyte, byte for byte
        std::vector<bool> have;
        CHECK(dc.has_chunks({cid, std::string(64, 'b')}, have).ok() && have == std::vector<bool>({true, false}));
        PutChunkReply again;
        CHECK(dc.put_chunk(cid, blob, again).ok() && again.existed);
        DevRes missing = dc.get_chunk(std::string(64, 'c'), got);
        CHECK(!missing.ok() && missing.err == ENOENT);  // a device ERROR still arrives as an error, inside the channel
        PutManifestReply mr;
        CHECK(dc.put_manifest(std::string(32, 'f'), 1, blob_of(300, 9), {cid}, mr).ok() && mr.seq == 1);
        Bytes mgot;
        CHECK(dc.get_manifest(std::string(32, 'f'), 1, mgot).ok() && mgot == blob_of(300, 9));
        ListReply lr;
        CHECK(dc.list_manifests(0, 100, lr).ok() && lr.entries.size() == 1);
        std::vector<AuditOut> ao;
        CHECK(dc.audit({{0, cid, 0, Bytes(32, 1)}}, ao).ok() && ao.size() == 1 && ao[0].status == 0);
        // a paired device accepts deletions without being told to (an open one does not): only the authenticated Mac can ask
        GcStatus gs;
        CHECK(dc.gc_status(gs).ok() && gs.deletions_allowed && gs.manifests == 1 && gs.chunks == 1 && gs.manifests_without_refs == 0);
        PutManifestReply mr2;
        CHECK(dc.put_manifest(std::string(32, 'f'), 2, blob_of(310, 10), {cid}, mr2).ok() && mr2.seq == 2);
        std::vector<uint8_t> deleted;
        uint64_t dseq = 0;
        CHECK(dc.delete_manifests({{std::string(32, 'f'), 2}}, deleted, &dseq).ok() && deleted == std::vector<uint8_t>({1}) && dseq == 3);
        SweepOut sw;
        CHECK(dc.sweep(0, 100, false, sw).ok() && sw.chunks_deleted == 0);  // the default floor (1 hour) protects a chunk uploaded a moment ago
        CHECK(dc.get_manifest(std::string(32, 'f'), 2, mgot).err == ENOENT && dc.get_chunk(cid, got).ok());
        // a dropped connection is re-established, with a fresh handshake and fresh keys
        dc.disconnect();
        CHECK(dc.info(info).ok());
        // the device is restarted: the client notices and reconnects on its own
        srv.stop();
        CHECK(srv.start(store));
        CHECK(dc.info(info).ok() && info.volume_id == "volume-auth-test-0123456789abcdef");
        // eight threads share one client
        std::atomic<int> bad{0};
        std::vector<std::thread> ts;
        for (int t = 0; t < 8; t++)
            ts.emplace_back([&, t] {
                for (int i = 0; i < 40; i++) {
                    Bytes b = blob_of(2000 + t * 100 + i, static_cast<uint8_t>(t * 10 + i));
                    std::string id = crypto::to_hex(crypto::sha256(b.data(), b.size()).data(), 32);
                    PutChunkReply p;
                    Bytes back;
                    if (!dc.put_chunk(id, b, p).ok() || !dc.get_chunk(id, back).ok() || back != b) bad++;
                }
            });
        for (auto& t : ts) t.join();
        CHECK(bad == 0);
    }

    printf("== the wrong or missing secret\n");
    {
        Bytes wrong = crypto::random_bytes(32);
        DeviceClient dc("127.0.0.1", P, 2000, wrong);
        DevInfo info;
        DevRes r = dc.info(info);
        CHECK(!r.ok() && r.err == EACCES && has(r.msg, "authentication with the device failed"));
        DeviceClient old("127.0.0.1", P, 2000, psk);  // the secret from before --new-pairing-code
        CHECK(!old.info(info).ok());
        DeviceClient plain("127.0.0.1", P, 2000);
        r = plain.info(info);
        CHECK(!r.ok() && r.err == EPERM && has(r.msg, "device is paired") && has(r.msg, "authentication is required") && has(r.msg, "pair this Mac"));
        DeviceClient shortkey("127.0.0.1", P, 2000, Bytes(31, 1));
        CHECK(!shortkey.info(info).ok());
        // the failures did not hurt a legitimate client
        DeviceClient good("127.0.0.1", P, 2000, psk2);
        CHECK(good.info(info).ok());
    }

    printf("== failures leave no sockets behind, and a silent device cannot hold the client past its deadline\n");
    {
        DevInfo info;
        {  // wrong secret against the real device, many times; then a good client that disconnects
            DeviceClient warm("127.0.0.1", P, 2000, psk2);
            CHECK(warm.info(info).ok());
            warm.disconnect();
            int before = open_fds();
            for (int i = 0; i < 12; i++) {
                DeviceClient bad("127.0.0.1", P, 2000, crypto::random_bytes(32));
                CHECK(!bad.info(info).ok());
            }
            DeviceClient good("127.0.0.1", P, 2000, psk2);
            CHECK(good.info(info).ok());
            good.disconnect();
            CHECK(open_fds() == before);
        }
        {  // a paired-looking device that completes the handshake and then hangs up before answering HELLO
            uint16_t fp = 0;
            int before = open_fds();
            int lfd = listen_ephemeral(&fp);
            CHECK(lfd >= 0);
            std::thread srv([&] {
                for (int i = 0; i < 10; i++) {
                    int c = accept(lfd, nullptr, nullptr);
                    if (c < 0) break;
                    std::string why;
                    auto ch = chan::accept_secure(
                        c,
                        [&](const Bytes& id) -> std::optional<Bytes> { return id == chan::key_id(psk2) ? std::optional<Bytes>(psk2) : std::nullopt; },
                        now_ms() + 3000, &why);
                    Frame f;
                    if (ch) ch->recv(f);  // the HELLO, never answered
                    close(c);
                }
            });
            for (int i = 0; i < 10; i++) {
                DeviceClient dc("127.0.0.1", fp, 2000, psk2);
                DevRes r = dc.info(info);
                CHECK(!r.ok());
            }
            srv.join();
            close(lfd);
            CHECK(open_fds() == before);
        }
        {  // a device that accepts and never speaks: the client gives up at its own timeout
            uint16_t sp = 0;
            int lfd = listen_ephemeral(&sp);
            CHECK(lfd >= 0);
            auto t0 = std::chrono::steady_clock::now();
            DeviceClient dc("127.0.0.1", sp, 700, psk2);
            DevRes r = dc.info(info);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
            CHECK(!r.ok() && r.err == EACCES);
            CHECK(ms >= 500 && ms < 3000);
            close(lfd);
        }
    }

    printf("== a raw attacker on the socket\n");
    {
        // plaintext HELLO: told plainly why, then dropped
        int fd = raw_connect(P);
        Writer w;
        w.u16(3);
        send_frame(fd, 0x01, 1, w.b, now_ms() + 2000);
        Frame f;
        CHECK(recv_frame(fd, f, now_ms() + 2000) == 1 && f.type == 0xFF);
        CHECK(recv_frame(fd, f, now_ms() + 2000) == 0);
        close(fd);
        // requests without a handshake (no HELLO either)
        fd = raw_connect(P);
        send_frame(fd, 0x10, 1, Bytes{}, now_ms() + 2000);
        CHECK(recv_frame(fd, f, now_ms() + 2000) <= 0);
        close(fd);
        // garbage bytes, an absurd length
        fd = raw_connect(P);
        const uint8_t junk[32] = {0xff, 0xff, 0xff, 0xff, 1, 2, 3};
        write_full(fd, junk, sizeof junk, now_ms() + 1000);
        CHECK(recv_frame(fd, f, now_ms() + 2000) <= 0);
        close(fd);
        // an AUTH_INIT with an unknown key id, a truncated one
        fd = raw_connect(P);
        chan::ClientHandshake stranger(crypto::random_bytes(32));
        send_frame(fd, chan::T_AUTH_INIT, 1, stranger.init(), now_ms() + 2000);
        CHECK(recv_frame(fd, f, now_ms() + 2000) <= 0);
        close(fd);
        fd = raw_connect(P);
        chan::ClientHandshake real(psk2);
        Bytes init = real.init();
        init.pop_back();
        send_frame(fd, chan::T_AUTH_INIT, 1, init, now_ms() + 2000);
        CHECK(recv_frame(fd, f, now_ms() + 2000) <= 0);
        close(fd);
        // a correct handshake that then sends a forged frame: the device hangs up, and a legitimate client is unaffected
        fd = raw_connect(P);
        std::string why;
        auto ch = chan::connect_secure(fd, psk2, now_ms() + 3000, &why);
        CHECK(ch != nullptr);
        if (ch) {
            uint8_t forged[40];
            memset(forged, 0x41, sizeof forged);
            forged[0] = 0;
            forged[1] = 0;
            forged[2] = 0;
            forged[3] = 36;
            write_full(fd, forged, sizeof forged, now_ms() + 1000);
            Frame g;
            CHECK(ch->recv(g, now_ms() + 2000) <= 0);
        }
        close(fd);
        DeviceClient good("127.0.0.1", P, 2000, psk2);
        DevInfo info;
        CHECK(good.info(info).ok());
        // many failing handshakes at once do not stop a legitimate client
        std::vector<std::thread> ts;
        std::atomic<int> refused{0};
        for (int i = 0; i < 24; i++)
            ts.emplace_back([&] {
                DeviceClient bad("127.0.0.1", P, 2000, crypto::random_bytes(32));
                DevInfo x;
                if (!bad.info(x).ok()) refused++;
            });
        DeviceClient meanwhile("127.0.0.1", P, 3000, psk2);
        CHECK(meanwhile.info(info).ok());
        for (auto& t : ts) t.join();
        CHECK(refused == 24);
        // failed handshakes are not counted against the connection cap forever
        for (int i = 0; i < 80; i++) {
            DeviceClient bad("127.0.0.1", P, 2000, crypto::random_bytes(32));
            DevInfo x;
            bad.info(x);
        }
        DeviceClient after("127.0.0.1", P, 3000, psk2);
        CHECK(after.info(info).ok());
    }

    printf("== a client that connects and says nothing is dropped at the handshake deadline\n");
    {
        std::string quick_store = root + "/quick";
        run_device({quick_store, "--show-pairing-code"}, nullptr);
        Server quick(P + 1);
        CHECK(quick.start(quick_store, {}, "300"));
        int fd = raw_connect(P + 1);
        auto t0 = std::chrono::steady_clock::now();
        Frame f;
        int r = recv_frame(fd, f, now_ms() + 5000);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        CHECK(r <= 0 && ms >= 250 && ms < 3000);
        close(fd);
        // and a client that sends only half an AUTH_INIT and stalls
        fd = raw_connect(P + 1);
        const uint8_t partial[6] = {0, 0, 0, 80, chan::T_AUTH_INIT, 0};
        write_full(fd, partial, sizeof partial, now_ms() + 1000);
        t0 = std::chrono::steady_clock::now();
        r = recv_frame(fd, f, now_ms() + 5000);
        ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        CHECK(r <= 0 && ms < 3000);
        close(fd);
    }

    printf("== a handshake deadline setting of zero cannot lock everybody out\n");
    {
        std::string fstore = root + "/floor";
        std::string fo;
        CHECK(run_device({fstore, "--show-pairing-code"}, &fo) == 0);
        Bytes fsecret = secret_from_code(fo);
        Server fl(P + 3);
        CHECK(fl.start(fstore, {}, "0"));
        DeviceClient dc("127.0.0.1", P + 3, 3000, fsecret);
        DevInfo info;
        CHECK(dc.info(info).ok());
    }

    printf("== an open (unpaired) device keeps its old behaviour, and a client with a secret says what is wrong\n");
    {
        Server open(P + 2);
        open.log = root + "/open-banner.log";
        CHECK(open.start(root + "/open-store"));
        CHECK(has(read_all(open.log), "NOT PAIRED: plaintext, loopback only") && !has(read_all(open.log), "authenticated channel required"));
        DeviceClient plain("127.0.0.1", P + 2, 2000);
        DevInfo info;
        CHECK(plain.info(info).ok());
        GcStatus gs;
        std::vector<uint8_t> del;
        CHECK(plain.gc_status(gs).ok() && !gs.deletions_allowed);
        DevRes dr = plain.delete_manifests({{std::string(32, 'a'), 1}}, del);
        CHECK(dr.err == EPERM && has(dr.msg, "does not accept deletions") && !has(read_all(open.log), "deletions accepted"));
        {  // an open device started with --allow-delete says so (and accepts the deletion)
            Server del(P + 5);
            del.log = root + "/open-delete-banner.log";
            CHECK(del.start(root + "/open-delete-store", {"--allow-delete"}));
            DeviceClient dcl("127.0.0.1", P + 5, 2000);
            std::vector<uint8_t> gone;
            CHECK(has(read_all(del.log), "NOT PAIRED") && has(read_all(del.log), "deletions accepted") &&
                  dcl.delete_manifests({{std::string(32, 'a'), 1}}, gone).ok() && gone.size() == 1);
        }
        DeviceClient with_secret("127.0.0.1", P + 2, 2000, psk2);
        DevRes r = with_secret.info(info);
        CHECK(!r.ok() && r.err == EACCES && has(r.msg, "authentication with the device failed") && has(r.msg, "refused"));
    }

    printf("== several Macs, one device: a pairing each, revocable, with its own right to delete (ADR-0016)\n");
    {
        std::string st3 = root + "/multi";
        std::string oa, ob, oc, ol;
        // the original pairing and two more
        CHECK(run_device({st3, "--show-pairing-code"}, &oa) == 0);
        Bytes sec_primary = secret_from_code(oa);
        CHECK(has(oa, "label: primary") && has(oa, "may delete"));
        CHECK(run_device({st3, "--add-pairing=Alpha Mac", "--pairing-allow-delete"}, &ob) == 0 && has(ob, "label: Alpha Mac") &&
              has(ob, "may delete"));
        CHECK(run_device({st3, "--add-pairing=Beta Mac"}, &oc) == 0 && has(oc, "label: Beta Mac") && has(oc, "may not delete"));
        Bytes sec_a = secret_from_code(ob), sec_b = secret_from_code(oc);
        CHECK(sec_a.size() == 32 && sec_b.size() == 32 && sec_a != sec_b && sec_a != sec_primary && sec_b != sec_primary);
        std::string kid_a = chan::key_id_hex(sec_a), kid_b = chan::key_id_hex(sec_b), kid_p = chan::key_id_hex(sec_primary);
        CHECK(has(ob, "key id: " + kid_a) && has(oc, "key id: " + kid_b));
        struct stat sf;
        CHECK(stat((st3 + "/pairings/" + kid_a + ".key").c_str(), &sf) == 0 && (sf.st_mode & 07777) == 0600 &&
              stat((st3 + "/pairings").c_str(), &sf) == 0 && (sf.st_mode & 07777) == 0700);
        CHECK(run_device({st3, "--list-pairings"}, &ol) == 0 && has(ol, kid_p) && has(ol, kid_a + "  Alpha Mac") && has(ol, kid_b + "  Beta Mac") &&
              has(ol, "(the original pairing.key)") && !has(ol, "PROBLEM"));
        // labels and counts are checked
        std::string oe;
        CHECK(run_device({st3, "--add-pairing="}, &oe) == 2 && has(oe, "give the Mac a name"));
        CHECK(run_device({st3, "--add-pairing=" + std::string(41, 'x')}, &oe) == 1 && has(oe, "label"));
        CHECK(run_device({st3, "--add-pairing=bad\nname"}, &oe) == 1 && has(oe, "label"));
        CHECK(run_device({st3, "--revoke-pairing=nothex"}, &oe) == 1 && has(oe, "16 lower-case hex"));
        CHECK(run_device({st3, "--revoke-pairing=0123456789abcdef"}, &oe) == 1 && has(oe, "no pairing with key id"));

        Server multi(P + 10);
        multi.log = root + "/multi.log";
        CHECK(multi.start(st3));
        CHECK(has(read_all(multi.log), "3 PAIRING(S)"));
        DeviceClient cp("127.0.0.1", P + 10, 3000, sec_primary), ca("127.0.0.1", P + 10, 3000, sec_a), cb("127.0.0.1", P + 10, 3000, sec_b);
        DevInfo di;
        CHECK(cp.info(di).ok() && ca.info(di).ok() && cb.info(di).ok());  // each Mac gets in with its own secret
        // who may delete
        std::vector<uint8_t> gone;
        GcStatus g1;
        CHECK(cp.delete_manifests({{std::string(32, 'a'), 1}}, gone).ok() && ca.delete_manifests({{std::string(32, 'a'), 1}}, gone).ok());
        DevRes dr2 = cb.delete_manifests({{std::string(32, 'a'), 1}}, gone);
        CHECK(dr2.err == EPERM && has(dr2.msg, "may not delete"));
        SweepOut so;
        CHECK(ca.sweep(3600, 10, true, so).ok());
        DevRes sw = cb.sweep(3600, 10, true, so);
        CHECK(sw.err == EPERM && has(sw.msg, "may not delete"));
        CHECK(ca.gc_status(g1).ok() && g1.deletions_allowed);
        CHECK(cb.gc_status(g1).ok() && !g1.deletions_allowed);  // the status tells each Mac the truth about itself
        CHECK(cb.info(di).ok());                                // and being refused does not close its connection

        // revoking one Mac: its open connection ends at the next request, a new one is refused, the others carry on
        std::string orv;
        CHECK(cb.info(di).ok());
        CHECK(run_device({st3, "--revoke-pairing=" + kid_b}, &orv) == 0 && has(orv, "revoked " + kid_b));
        CHECK(!fs::exists(st3 + "/pairings/" + kid_b + ".key"));
        DevRes after = cb.info(di);
        CHECK(!after.ok());
        DeviceClient cb2("127.0.0.1", P + 10, 3000, sec_b);
        DevRes again = cb2.info(di);
        CHECK(!again.ok() && again.err == EACCES);
        CHECK(ca.info(di).ok() && cp.info(di).ok());
        // revoking the original pairing works the same way
        CHECK(run_device({st3, "--revoke-pairing=" + kid_p}, &orv) == 0 && !fs::exists(st3 + "/pairing.key"));
        CHECK(!cp.info(di).ok());
        CHECK(ca.info(di).ok());
        // changing the right to delete takes effect for a connection that is already open
        {
            std::string path = st3 + "/pairings/" + kid_a + ".key";
            std::string txt = read_all(path);
            size_t at = txt.find("delete=1");
            CHECK(at != std::string::npos);
            txt.replace(at, 8, "delete=0");
            std::ofstream(path, std::ios::trunc) << txt;
            chmod(path.c_str(), 0600);
            DevRes dd = ca.delete_manifests({{std::string(32, 'a'), 1}}, gone);
            CHECK(dd.err == EPERM && has(dd.msg, "may not delete"));
        }
        // a revoked Mac can be given a new pairing, which is a different secret
        std::string on;
        CHECK(run_device({st3, "--add-pairing=Beta Mac again"}, &on) == 0 && secret_from_code(on) != sec_b);
        multi.stop();

        // a pairing file that is not acceptable stops the device (it must never fall back to being open) and --list-pairings says why
        std::string st4 = root + "/multi-bad";
        std::string o4;
        CHECK(run_device({st4, "--add-pairing=Good"}, &o4) == 0);
        std::string kid_g = chan::key_id_hex(secret_from_code(o4));
        std::string gfile = st4 + "/pairings/" + kid_g + ".key";
        std::string good_text = read_all(gfile), o5;
        auto rewrite = [&](const std::string& txt, mode_t mode) {
            std::ofstream(gfile, std::ios::trunc) << txt;
            chmod(gfile.c_str(), mode);
        };
        const std::string nowhere = "192.0.2.1";
        rewrite(good_text, 0644);
        CHECK(run_device({st4, std::to_string(P + 11), nowhere}, &o5) == 1 && has(o5, "readable only by its owner"));
        CHECK(run_device({st4, "--list-pairings"}, &o5) == 1 && has(o5, "PROBLEM"));
        std::string noline = good_text.substr(0, good_text.find("delete="));
        rewrite(noline, 0600);
        CHECK(run_device({st4, std::to_string(P + 11), nowhere}, &o5) == 1 && has(o5, "needs both a label= and a delete= line"));
        std::string typo = good_text;
        typo.replace(typo.find("delete="), 6, "delet=");
        rewrite(typo, 0600);
        CHECK(run_device({st4, std::to_string(P + 11), nowhere}, &o5) == 1 && has(o5, "unrecognised line"));
        std::string twice = good_text + "delete=1\n";
        rewrite(twice, 0600);
        CHECK(run_device({st4, std::to_string(P + 11), nowhere}, &o5) == 1 && has(o5, "unrecognised line"));
        std::string badval = good_text;
        badval.replace(badval.find("delete=0"), 8, "delete=yes");
        rewrite(badval, 0600);
        CHECK(run_device({st4, std::to_string(P + 11), nowhere}, &o5) == 1 && has(o5, "unrecognised line"));
        rewrite(good_text, 0600);
        fs::copy_file(gfile, st4 + "/pairings/0000000000000000.key");
        chmod((st4 + "/pairings/0000000000000000.key").c_str(), 0600);
        CHECK(run_device({st4, std::to_string(P + 11), nowhere}, &o5) == 1 && has(o5, "the file name is not the key id"));
        fs::remove(st4 + "/pairings/0000000000000000.key");
        // the same secret listed twice (once as the original, once as a pairing) is reported, not doubled
        std::string hexline = good_text.substr(0, 64);
        std::ofstream(st4 + "/pairing.key") << hexline << "\n";
        chmod((st4 + "/pairing.key").c_str(), 0600);
        CHECK(run_device({st4, std::to_string(P + 11), nowhere}, &o5) == 1 && has(o5, "the same secret is already listed"));
        // and a good store still starts
        fs::remove(st4 + "/pairing.key");
        Server good(P + 11);
        CHECK(good.start(st4));
        good.stop();
    }

    srv.stop();
    fs::remove_all(root);
    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
