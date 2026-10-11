// End-to-end tests of the client library (chunk cache, offline behaviour,
// readahead) against a real backend process. No FUSE and no kernel cache in
// the way, so every assertion is about our own code. `make test-client`.
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <thread>
#include <vector>

#include "../core/tierclient.h"
#include "../core/wire.hpp"

extern char** environ;
namespace fs = std::filesystem;

static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) { printf("FAIL  line %d: %s\n", __LINE__, #cond); failures++; } \
        else printf("PASS  %s\n", #cond);                                          \
    } while (0)

static const uint16_t PORT = 9201;
static const uint64_t MiB = 1u << 20;
static std::string g_root, g_tmp;

struct Backend {
    pid_t pid = 0;
    void start(int delay_ms = 0) {
        stop();  // never leave an orphan holding the port (it would make "backend dead" a lie)
        std::vector<std::string> env;
        for (char** e = environ; *e; e++) env.push_back(*e);
        env.push_back("TIERFS_DELAY_MS=" + std::to_string(delay_ms));
        std::vector<char*> envp;
        for (auto& s : env) envp.push_back(const_cast<char*>(s.c_str()));
        envp.push_back(nullptr);
        std::string port = std::to_string(PORT);
        char* argv[] = {const_cast<char*>("tierfs-backend"), const_cast<char*>(g_root.c_str()),
                        const_cast<char*>(port.c_str()), nullptr};
        // Backend output goes to /dev/null so an orphaned backend (after a test crash)
        // can never keep the caller's pipes open and make a run look like a hang.
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
        posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
        posix_spawn(&pid, "./build/tierfs-backend", &fa, nullptr, argv, envp.data());
        posix_spawn_file_actions_destroy(&fa);
        for (int i = 0; i < 60; i++) {  // wait until it accepts connections
            tc_config cfg = {};
            cfg.host = "127.0.0.1"; cfg.port = PORT; cfg.timeout_ms = 200;
            std::string d = g_tmp + "/probe"; cfg.cache_dir = d.c_str(); cfg.readahead = 0;
            tc_client* c = tc_create(&cfg);
            // tc_getattr("/") succeeds offline by design, so probe with a listing,
            // which only the backend can answer.
            int rc = tc_readdir(c, "/", [](void*, const char*, const tc_attr*) { return 0; }, nullptr);
            tc_destroy(c);
            if (rc == 0) { fs::remove_all(d); return; }
            usleep(50000);
        }
    }
    void stop() {
        if (!pid) return;
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        pid = 0;
    }
    ~Backend() { stop(); }
};

static std::vector<uint8_t> pattern(size_t n, uint32_t seed) {
    std::vector<uint8_t> v(n);
    std::mt19937 g(seed);
    for (auto& b : v) b = static_cast<uint8_t>(g());
    return v;
}
static void write_file(const std::string& name, const std::vector<uint8_t>& d, time_t mtime = 0) {
    std::string p = g_root + "/" + name;
    { std::ofstream f(p, std::ios::binary | std::ios::trunc); f.write((const char*)d.data(), d.size()); }
    if (mtime) { utimbuf t{mtime, mtime}; utime(p.c_str(), &t); }
}
static tc_client* make_client(const std::string& cache, int readahead, uint64_t cache_bytes = 256 * MiB,
                              int timeout_ms = 1000) {
    tc_config cfg = {};
    cfg.host = "127.0.0.1"; cfg.port = PORT; cfg.timeout_ms = timeout_ms;
    cfg.cache_dir = cache.c_str(); cfg.cache_bytes = cache_bytes; cfg.readahead = readahead;
    return tc_create(&cfg);
}
// Read [off, off+len) in <=1 MiB calls; returns false on any error / short read.
static bool read_range(tc_client* c, const char* path, uint64_t off, uint64_t len, std::vector<uint8_t>& out,
                       uint64_t step = MiB) {
    out.clear();
    while (len) {
        uint32_t want = static_cast<uint32_t>(std::min<uint64_t>(len, step));
        std::vector<uint8_t> b(want);
        int64_t n = tc_read(c, path, off, want, b.data());
        if (n < 0) return false;
        if (n == 0) break;
        out.insert(out.end(), b.begin(), b.begin() + n);
        off += n; len -= n;
    }
    return true;
}
static std::vector<uint8_t> slice(const std::vector<uint8_t>& v, uint64_t off, uint64_t len) {
    return std::vector<uint8_t>(v.begin() + off, v.begin() + std::min<uint64_t>(off + len, v.size()));
}
static std::vector<fs::path> chunk_files(const std::string& cache) {
    std::vector<fs::path> out;
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(cache + "/chunks", ec))
        if (e.is_regular_file() && e.path().extension() == ".chk") out.push_back(e.path());
    return out;
}
static std::string run(const std::string& cmd, int* exit_code = nullptr) {
    std::string out;
    FILE* f = popen((cmd + " 2>&1").c_str(), "r");
    char buf[512];
    while (f && fgets(buf, sizeof buf, f)) out += buf;
    int rc = f ? pclose(f) : -1;
    if (exit_code) *exit_code = WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
    return out;
}
static bool contains(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }

// A server that completes the handshake and then answers every request ONE BYTE
// at a time: each byte arrives well inside any per-read timeout, but the whole
// reply takes seconds.
static void trickle_server(int lfd, std::atomic<bool>* stop) {
    while (!*stop) {
        pollfd p{lfd, POLLIN, 0};
        if (poll(&p, 1, 100) <= 0) continue;
        int fd = accept(lfd, nullptr, nullptr);
        if (fd < 0) continue;
        tierfs::Frame f;
        if (tierfs::recv_frame(fd, f) == 1) {  // HELLO
            tierfs::Writer w;
            w.u16(tierfs::PROTO_VERSION);
            w.str("trickle");
            tierfs::send_frame(fd, f.type | tierfs::MSG_REPLY_FLAG, f.id, w.b);
        }
        if (tierfs::recv_frame(fd, f) == 1) {  // STAT: reply slowly
            tierfs::Writer a;
            a.u8(0); a.u64(5); a.i64(1); a.u32(0644);
            tierfs::Writer fr;
            fr.u32(5 + static_cast<uint32_t>(a.b.size()));
            fr.u8(f.type | tierfs::MSG_REPLY_FLAG);
            fr.u32(f.id);
            fr.bytes(a.b.data(), a.b.size());
            for (uint8_t byte : fr.b) {
                if (write(fd, &byte, 1) != 1) break;
                usleep(120000);
            }
        }
        close(fd);
    }
}

static double secs_since(std::chrono::steady_clock::time_point t) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t).count();
}

int main() {
    signal(SIGPIPE, SIG_IGN);  // the fake trickle server writes to sockets the client closes
    char t[] = "/tmp/tierfs-clienttest-XXXXXX";
    g_tmp = mkdtemp(t);
    g_root = g_tmp + "/root";
    fs::create_directories(g_root);
    Backend be;

    {
        printf("== basic reads populate the cache; repeats are free\n");
        auto F = pattern(5 * MiB + MiB / 2, 1);
        write_file("F", F);
        be.start();
        std::string cache = g_tmp + "/c1";
        tc_client* c = make_client(cache, 0);
        tc_attr a;
        CHECK(tc_getattr(c, "/F", &a) == 0 && a.size == F.size() && !a.is_dir);
        std::vector<uint8_t> got;
        CHECK(read_range(c, "/F", 0, F.size(), got, 256 * 1024) && got == F);
        tc_stats s;
        tc_get_stats(c, &s);
        CHECK(s.fetches == 6);  // 5 full chunks + the 0.5 MiB tail, each fetched exactly once
        CHECK(s.bytes_fetched == F.size());
        CHECK(read_range(c, "/F", 0, F.size(), got, 300000) && got == F);  // odd step size
        tc_get_stats(c, &s);
        CHECK(s.fetches == 6);  // second pass served entirely from the cache

        // unaligned read across a chunk boundary, at EOF, past EOF
        std::vector<uint8_t> b(100);
        CHECK(tc_read(c, "/F", MiB - 40, 100, b.data()) == 100 &&
              std::vector<uint8_t>(b) == slice(F, MiB - 40, 100));
        CHECK(tc_read(c, "/F", F.size() - 10, 100, b.data()) == 10 &&
              std::vector<uint8_t>(b.begin(), b.begin() + 10) == slice(F, F.size() - 10, 10));
        CHECK(tc_read(c, "/F", F.size(), 100, b.data()) == 0);
        CHECK(tc_read(c, "/F", F.size() + 5 * MiB, 100, b.data()) == 0);
        CHECK(tc_read(c, "/", 0, 10, b.data()) == -EISDIR);
        CHECK(tc_read(c, "/nope", 0, 10, b.data()) == -ENOENT);
        tc_destroy(c);

        printf("== a new client (remount) serves cached data with the backend DEAD\n");
        be.stop();
        c = make_client(cache, 0);
        CHECK(tc_getattr(c, "/F", &a) == 0 && a.size == F.size());  // metadata persisted too
        CHECK(read_range(c, "/F", 0, F.size(), got) && got == F);
        tc_get_stats(c, &s);
        CHECK(s.fetches == 0);
        tc_destroy(c);
    }

    {
        printf("== on-disk corruption is never returned\n");
        auto F = pattern(4 * MiB, 2);
        write_file("K", F);
        be.start();
        std::string cache = g_tmp + "/c2";
        tc_client* c = make_client(cache, 0);
        tc_attr a;
        tc_getattr(c, "/K", &a);
        std::vector<uint8_t> got;
        CHECK(read_range(c, "/K", 0, F.size(), got) && got == F);
        auto files = chunk_files(cache);
        CHECK(files.size() == 4);
        // Damage one chunk file in the middle of its data.
        {
            int fd = open(files[0].c_str(), O_RDWR);
            uint8_t byte;
            pread(fd, &byte, 1, 12345);
            byte ^= 0x40;
            pwrite(fd, &byte, 1, 12345);
            close(fd);
        }
        be.stop();
        std::vector<uint8_t> b(MiB);
        int bad = 0, ok = 0;
        for (uint64_t i = 0; i < 4; i++) {
            int64_t n = tc_read(c, "/K", i * MiB, MiB, b.data());
            if (n < 0) bad++;
            else if (n == (int64_t)MiB && std::vector<uint8_t>(b) == slice(F, i * MiB, MiB)) ok++;
        }
        CHECK(bad == 1 && ok == 3);  // exactly the damaged chunk fails (EIO); it is never served corrupt
        tc_stats s;
        tc_get_stats(c, &s);
        CHECK(s.chunk_corrupt == 1);
        be.start();  // device comes back: the damaged chunk is refetched transparently
        CHECK(read_range(c, "/K", 0, F.size(), got) && got == F);
        tc_destroy(c);
    }

    {
        printf("== a failure mid-read fails the whole request (no silent truncation)\n");
        auto F = pattern(4 * MiB, 3);
        write_file("T", F);
        be.start();
        std::string cache = g_tmp + "/c3";
        tc_client* c = make_client(cache, 0);
        tc_attr a;
        tc_getattr(c, "/T", &a);
        std::vector<uint8_t> got;
        CHECK(read_range(c, "/T", 0, 2 * MiB, got) && got.size() == 2 * MiB);  // chunks 0,1 cached
        be.stop();
        std::vector<uint8_t> b(MiB);
        // First half of this range is cached, second half is not.
        int64_t n = tc_read(c, "/T", MiB + MiB / 2, MiB, b.data());
        CHECK(n < 0);  // an error, not a 0.5 MiB "short read" the kernel would take for EOF
        CHECK(tc_read(c, "/T", 0, MiB, b.data()) == (int64_t)MiB);  // fully cached ranges still work
        tc_destroy(c);
    }

    {
        printf("== a file changing under a read never yields a blend of versions\n");
        auto A = pattern(3 * MiB, 10), B = pattern(3 * MiB, 11);
        write_file("H", A, 1000000);
        be.start();
        std::string cache = g_tmp + "/c4";
        tc_client* c = make_client(cache, 0);
        tc_attr a;
        tc_getattr(c, "/H", &a);
        std::vector<uint8_t> b(MiB);
        CHECK(tc_read(c, "/H", 0, MiB, b.data()) == (int64_t)MiB && b == slice(A, 0, MiB));  // chunk 0 cached as version A
        write_file("H", B, 2000000);  // same size, new content, new mtime
        // Spans chunk 0 (cached, OLD version) and chunk 1 (not cached -> fetch reveals the change).
        std::vector<uint8_t> r(MiB);
        int64_t n = tc_read(c, "/H", MiB / 2, MiB, r.data());
        CHECK(n == (int64_t)MiB);
        CHECK(r == slice(B, MiB / 2, MiB));  // entirely version B: no half-A half-B result
        CHECK(tc_read(c, "/H", 0, MiB, b.data()) == (int64_t)MiB && b == slice(B, 0, MiB));
        tc_attr a2;
        tc_getattr(c, "/H", &a2);
        CHECK(a2.mtime == 2000000);

        // getattr noticing a new version frees the old chunks immediately
        tc_stats s0, s1;
        tc_get_stats(c, &s0);
        write_file("H", A, 3000000);
        tc_getattr(c, "/H", &a2);
        tc_get_stats(c, &s1);
        CHECK(s1.cache_bytes_used < s0.cache_bytes_used);
        // File deleted on the server: stat says ENOENT and cached data goes away.
        fs::remove(g_root + "/H");
        CHECK(tc_getattr(c, "/H", &a2) == -ENOENT);
        tc_get_stats(c, &s1);
        CHECK(s1.cache_bytes_used == 0);
        tc_destroy(c);
    }

    {
        printf("== eviction keeps the cache within budget; open files are pinned\n");
        auto P = pattern(2 * MiB, 20), Q = pattern(8 * MiB, 21);
        write_file("P", P);
        write_file("Q", Q);
        be.start();
        std::string cache = g_tmp + "/c5";
        tc_client* c = make_client(cache, 0, 3 * MiB);
        tc_attr a;
        tc_getattr(c, "/P", &a);
        tc_getattr(c, "/Q", &a);
        std::vector<uint8_t> got;
        CHECK(read_range(c, "/Q", 0, Q.size(), got) && got == Q);
        tc_stats s;
        tc_get_stats(c, &s);
        CHECK(s.cache_bytes_used <= 3 * MiB);
        CHECK(s.chunk_evicted >= 5);
        CHECK(chunk_files(cache).size() * MiB == s.cache_bytes_used);  // files on disk match the accounting

        tc_pin(c, "/P");
        CHECK(read_range(c, "/P", 0, P.size(), got) && got == P);
        CHECK(read_range(c, "/Q", 0, Q.size(), got) && got == Q);  // heavy traffic while P is open
        tc_get_stats(c, &s);
        uint64_t before = s.fetches;
        CHECK(read_range(c, "/P", 0, P.size(), got) && got == P);
        tc_get_stats(c, &s);
        CHECK(s.fetches == before);  // pinned: still cached, no refetch
        tc_unpin(c, "/P");
        CHECK(read_range(c, "/Q", 0, Q.size(), got) && got == Q);
        CHECK(read_range(c, "/Q", 0, Q.size(), got) && got == Q);
        tc_get_stats(c, &s);
        before = s.fetches;
        CHECK(read_range(c, "/P", 0, P.size(), got) && got == P);
        tc_get_stats(c, &s);
        CHECK(s.fetches > before);  // unpinned: evicted like anything else
        tc_destroy(c);
    }

    {
        printf("== readahead hides latency on sequential reads\n");
        be.stop();
        auto L = pattern(12 * MiB, 30);
        write_file("L", L);
        be.start(40);  // every READ takes 40 ms
        double t_no, t_ra;
        tc_stats s;
        for (int ra : {0, 4}) {
            std::string cache = g_tmp + "/c6_" + std::to_string(ra);
            tc_client* c = make_client(cache, ra, 256 * MiB, 3000);
            tc_attr a;
            tc_getattr(c, "/L", &a);
            auto t0 = std::chrono::steady_clock::now();
            std::vector<uint8_t> got;
            bool ok = read_range(c, "/L", 0, L.size(), got);
            double t = secs_since(t0);
            CHECK(ok && got == L);
            tc_get_stats(c, &s);
            printf("      readahead=%d: %.2fs, fetches=%llu prefetch_fetches=%llu prefetch_used=%llu\n", ra, t,
                   (unsigned long long)s.fetches, (unsigned long long)s.prefetch_fetches,
                   (unsigned long long)s.prefetch_used);
            if (ra == 0) t_no = t; else t_ra = t;
            if (ra == 4) {
                CHECK(s.prefetch_used >= 6);
                CHECK(s.fetches + s.prefetch_fetches >= 12 && s.fetches + s.prefetch_fetches <= 14);  // no duplicate fetching
            }
            tc_destroy(c);
        }
        CHECK(t_ra < t_no * 0.8);

        printf("== random access does not trigger readahead\n");
        std::string cache = g_tmp + "/c7";
        tc_client* c = make_client(cache, 4, 256 * MiB, 3000);
        tc_attr a;
        tc_getattr(c, "/L", &a);
        std::vector<uint8_t> b(1000);
        for (uint64_t off : {7 * MiB, 2 * MiB, 10 * MiB, 5 * MiB}) tc_read(c, "/L", off, 1000, b.data());
        usleep(300000);
        tc_get_stats(c, &s);
        CHECK(s.prefetch_fetches == 0);
        tc_destroy(c);
        be.stop();
    }

    {
        printf("== concurrent readers get correct data (run under sanitizers)\n");
        auto X = pattern(10 * MiB, 40);
        write_file("X", X);
        be.start(2);
        std::string cache = g_tmp + "/c8";
        tc_client* c = make_client(cache, 4, 6 * MiB, 3000);  // small cache: eviction while reading
        tc_attr a;
        tc_getattr(c, "/X", &a);
        std::atomic<int> bad{0};
        std::vector<std::thread> th;
        for (int t = 0; t < 6; t++)
            th.emplace_back([&, t] {
                std::mt19937 g(100 + t);
                for (int i = 0; i < 40; i++) {
                    uint64_t off = g() % X.size();
                    uint32_t len = 1 + g() % (900 * 1024);
                    std::vector<uint8_t> b(len);
                    int64_t n = tc_read(c, "/X", off, len, b.data());
                    uint64_t want = std::min<uint64_t>(len, X.size() - off);
                    if (n != (int64_t)want || memcmp(b.data(), X.data() + off, want) != 0) bad++;
                    if (t % 2) { tc_pin(c, "/X"); tc_unpin(c, "/X"); }
                }
            });
        for (auto& x : th) x.join();
        CHECK(bad == 0);
        tc_destroy(c);
    }

    {
        printf("== a trickling server cannot hold a request open past its deadline\n");
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT + 1);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        bind(lfd, (sockaddr*)&addr, sizeof addr);
        listen(lfd, 4);
        std::atomic<bool> stop{false};
        std::thread srv(trickle_server, lfd, &stop);
        tc_config cfg = {};
        cfg.host = "127.0.0.1"; cfg.port = PORT + 1; cfg.timeout_ms = 500; cfg.readahead = 0;
        std::string d = g_tmp + "/c9"; cfg.cache_dir = d.c_str();
        tc_client* c = tc_create(&cfg);
        tc_attr a;
        auto t0 = std::chrono::steady_clock::now();
        int rc = tc_getattr(c, "/x", &a);   // reply would take ~4 s to trickle in
        double took = secs_since(t0);
        printf("      rc=%d after %.2fs (reply needed ~4 s; timeout is 0.5 s)\n", rc, took);
        CHECK(rc != 0);
        CHECK(took < 1.5);
        tc_destroy(c);
        stop = true;
        srv.join();
        close(lfd);
    }

    {
        printf("== one process per cache directory; tierctl inspects and clears safely\n");
        be.start();
        std::string cache = g_tmp + "/c10";
        write_file("Z", pattern(2 * MiB + 5, 50));
        tc_client* c = make_client(cache, 0);
        CHECK(c != nullptr);
        tc_attr a;
        tc_getattr(c, "/Z", &a);
        std::vector<uint8_t> got;
        CHECK(read_range(c, "/Z", 0, 2 * MiB + 5, got));
        CHECK(make_client(cache, 0) == nullptr);   // second user of the same cache is refused

        int rc;
        std::string out = run("./build/tierctl cache-info " + cache, &rc);
        CHECK(rc == 0 && contains(out, "IN USE") && contains(out, "3 chunks"));
        out = run("./build/tierctl cache-clear " + cache + " --yes", &rc);
        CHECK(rc != 0 && contains(out, "unmount"));            // refuses while mounted
        CHECK(chunk_files(cache).size() == 3);                  // ...and removed nothing
        out = run("./build/tierctl cache-verify " + cache, &rc);
        CHECK(rc != 0 && contains(out, "in use"));
        tc_destroy(c);

        out = run("./build/tierctl cache-info " + cache, &rc);
        CHECK(rc == 0 && contains(out, "idle") && contains(out, "1 files"));
        out = run("./build/tierctl cache-verify " + cache, &rc);
        CHECK(rc == 0 && contains(out, "checked 3 chunks: 0 damaged"));
        auto files = chunk_files(cache);
        { int fd = open(files[0].c_str(), O_RDWR); uint8_t b; pread(fd, &b, 1, 9); b ^= 1; pwrite(fd, &b, 1, 9); close(fd); }
        out = run("./build/tierctl cache-verify " + cache, &rc);
        CHECK(rc == 3 && contains(out, "1 damaged"));
        std::string precious = cache + "/precious.txt";   // not ours: must survive a clear
        { std::ofstream f(precious); f << "do not delete"; }
        out = run("./build/tierctl cache-clear " + cache, &rc);   // dry run
        CHECK(rc == 0 && contains(out, "would remove") && chunk_files(cache).size() == 2);
        out = run("./build/tierctl cache-clear " + cache + " --yes", &rc);
        CHECK(rc == 0 && chunk_files(cache).empty() && !fs::exists(cache + "/chunks.db"));
        CHECK(fs::exists(precious));                            // only tierfs's own files are removed
        out = run("./build/tierctl cache-clear /tmp --yes", &rc);
        CHECK(rc != 0 && contains(out, "does not look like"));  // refuses a folder that is not a cache
        out = run("./build/tierctl cache-info " + cache, &rc);  // still a valid (empty) cache dir
        c = make_client(cache, 0);
        CHECK(c != nullptr);
        tc_getattr(c, "/Z", &a);
        CHECK(read_range(c, "/Z", 0, 2 * MiB + 5, got) && got.size() == 2 * MiB + 5);  // cache rebuilds on demand
        tc_destroy(c);
    }

    be.stop();
    fs::remove_all(g_tmp);
    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
