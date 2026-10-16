// A real phone (or the emulator) as one of the two devices, end to end: the Mac's daemon offloads a file to the Android agent and a local device, then
// reads it back from the Android agent ALONE. This is a manual test (it needs the agent running and reachable, e.g. `adb forward tcp:19100 tcp:9100`);
// it is not part of `make test`. See android/README.md.
//
//   TIERFS_ANDROID_DEVICE=127.0.0.1:19100@<keyid>  TIERFS_ANDROID_KEYSTORE=<dir holding the pairing secret, from `tierctl pair --store dir:<dir>`>  \
//   ./build/android_smoke
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "../core/daemon.hpp"
#include "../core/keysource.hpp"

extern char** environ;
using namespace tierfs;
namespace fs = std::filesystem;
using crypto::Bytes;

static int failures = 0;
#define CHECK(cond)                                         \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("FAIL  line %d: %s\n", __LINE__, #cond); \
            failures++;                                     \
        } else                                              \
            printf("PASS  %s\n", #cond);                    \
    } while (0)

static Bytes pattern(size_t n, uint8_t seed) {
    Bytes v(n);
    for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(seed + i * 43 + (i >> 8) + (i >> 20) * 11);
    return v;
}
static Bytes slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
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
    const char* spec = getenv("TIERFS_ANDROID_DEVICE");
    const char* ks = getenv("TIERFS_ANDROID_KEYSTORE");
    if (!spec || !ks) {
        fprintf(stderr, "set TIERFS_ANDROID_DEVICE=host:port@keyid and TIERFS_ANDROID_KEYSTORE=<dir>\n");
        return 2;
    }
    char tmpl[] = "/tmp/tierfs-android-XXXXXX";
    std::string root = mkdtemp(tmpl);
    std::string origin = root + "/origin", ledger = root + "/ledger", ksdir = root + "/keystore";
    fs::create_directories(origin);
    fs::copy(ks, ksdir, fs::copy_options::recursive);   // (the pairing secret; the master key is added below)

    // the second device: a plain local one, so two copies exist and the file may leave the Mac
    pid_t pid = 0;
    {
        std::string store = root + "/local-device";
        std::vector<std::string> a = {"tierfs-device", store, "19101", "127.0.0.1", "--allow-delete"};
        std::vector<char*> av;
        for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
        av.push_back(nullptr);
        posix_spawn(&pid, "./build/tierfs-device", nullptr, nullptr, av.data(), environ);
        usleep(600000);
    }

    DaemonConfig c;
    c.ledger_dir = ledger;
    c.origin_dir = origin;
    c.logical_prefix = "/Users/me/proj/";
    c.key_file = "dir:" + ksdir;
    c.devices = {spec, "127.0.0.1:19101"};
    c.maint_seconds = 0;
    c.notify = false;
    c.device_timeout_ms = 15000;   // (an emulator is slow)
    std::string err, volume;
    {
        auto L = Ledger::open(ledger, &err);
        CHECK(L);
        volume = L->volume_id();
        crypto::SecretKey master = crypto::SecretKey::random();
        CHECK(crypto::make_file_keystore(ksdir)->store(volume, master));
        L->set_meta("recovery_acked", "1");
        L->set_meta("test_prefix", "/Users/me/");   // a throwaway ledger: the test prefix stands in for the backup
        L->ensure_reserve(1 << 20);
    }
    const size_t size = 3 * (1u << 20) + 12345;   // four chunks
    Bytes data = pattern(size, 7);
    {
        std::ofstream(origin + "/a.bin", std::ios::binary).write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    {
        auto d = Daemon::create(c, &err);
        CHECK(d && d->start(&err));
        std::string st = d->control("status");
        CHECK(st.find("not attached") == std::string::npos);   // both devices, including the phone, are attached
        std::string r = d->control("offload /a.bin");
        printf("%s", r.c_str());
        CHECK(r.find("offloaded /Users/me/proj/a.bin") != std::string::npos && !fs::exists(origin + "/a.bin"));
        CHECK(read_through(d->overlay(), "/a.bin", size) == data);
        d->stop();
    }
    // now without the local device: the phone alone must serve every byte (a new daemon has an empty cache)
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
    {
        c.devices = {spec};
        auto d = Daemon::create(c, &err);
        CHECK(d && d->start(&err));
        CHECK(d->control("status").find("not attached") == std::string::npos);
        CHECK(read_through(d->overlay(), "/a.bin", size) == data);   // read back from the Android agent alone
        CHECK(d->control("hydrate /a.bin").find("OK") != std::string::npos && slurp(origin + "/a.bin") == data);
        d->stop();
    }
    fs::remove_all(root);
    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
