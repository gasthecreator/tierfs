// tierfs reference backend (Phase 1): serves a directory tree, read-only,
// over the protocol in proto/PROTOCOL.md. One thread per connection.
//
// Usage: tierfs-backend <root-dir> [port=9099] [bind-addr=127.0.0.1]
//
// SECURITY: no TLS / auth yet, so it binds to loopback by default. Do not bind
// to a LAN address until pairing + TLS exist.
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <climits>
#include <thread>
#include <unistd.h>

#include "../core/wire.hpp"

using namespace tierfs;

static std::string g_root;  // realpath of the exported directory, no trailing '/'

// Map a client path to a real filesystem path, guaranteeing the result is
// inside g_root. realpath() resolves "..", "." and symlinks first; only then do
// we check the prefix. Checking the string before resolving would be a classic
// path-traversal bug (a symlink inside the root pointing at /etc passes it).
static int resolve(const std::string& path, std::string& out) {
    if (path.empty() || path[0] != '/' || path.find('\0') != std::string::npos)
        return EINVAL;
    char buf[PATH_MAX];
    if (!realpath((g_root + path).c_str(), buf)) return errno;
    std::string rp = buf;
    if (rp != g_root && rp.compare(0, g_root.size() + 1, g_root + "/") != 0)
        return EACCES;
    out = rp;
    return 0;
}

static void put_attr(Writer& w, const struct stat& st) {
    w.u8(S_ISDIR(st.st_mode) ? 1 : 0);
    w.u64(static_cast<uint64_t>(st.st_size));
    w.i64(static_cast<int64_t>(st.st_mtime));
    w.u32(static_cast<uint32_t>(st.st_mode & 0777));
}

static bool reply(int fd, uint8_t req_type, uint32_t id, const Writer& w) {
    return send_frame(fd, req_type | MSG_REPLY_FLAG, id, w.b);
}

static bool reply_err(int fd, uint32_t id, int err, const char* msg) {
    Writer w;
    w.i32(err);
    w.str(msg);
    return send_frame(fd, MSG_ERROR, id, w.b);
}

static bool do_stat(int fd, const Frame& f, Reader& r) {
    std::string real;
    int e = resolve(r.str(), real);
    struct stat st;
    if (e == 0 && stat(real.c_str(), &st) != 0) e = errno;
    if (e) return reply_err(fd, f.id, e, strerror(e));
    Writer w;
    put_attr(w, st);
    return reply(fd, f.type, f.id, w);
}

static bool do_readdir(int fd, const Frame& f, Reader& r) {
    std::string real;
    int e = resolve(r.str(), real);
    if (e) return reply_err(fd, f.id, e, strerror(e));
    DIR* d = opendir(real.c_str());
    if (!d) return reply_err(fd, f.id, errno, strerror(errno));
    Writer entries;
    uint32_t count = 0;
    while (struct dirent* de = readdir(d)) {
        std::string name = de->d_name;
        if (name == "." || name == "..") continue;
        struct stat st;
        if (fstatat(dirfd(d), de->d_name, &st, 0) != 0) continue;  // dangling link etc.
        try { entries.str(name); } catch (...) { continue; }
        put_attr(entries, st);
        count++;
        if (entries.b.size() > MAX_FRAME - 64) {
            closedir(d);
            return reply_err(fd, f.id, EFBIG, "directory too large for one frame");
        }
    }
    closedir(d);
    Writer w;
    w.u32(count);
    w.bytes(entries.b.data(), entries.b.size());
    return reply(fd, f.type, f.id, w);
}

static int g_delay_ms = 0;  // TIERFS_DELAY_MS: simulate a slow link in tests

// Reply = u64 size, i64 mtime, then the bytes. The size/mtime describe the file
// version the bytes came from, so the client can tell if the file changed since
// it last looked. We fstat before AND after pread and retry if they differ, so
// the label always matches the data (unless the file changes 3 times in a row).
static bool do_read(int fd, const Frame& f, Reader& r) {
    std::string real;
    std::string path = r.str();
    uint64_t off = r.u64();
    uint32_t len = r.u32();
    if (len > MAX_READ) len = MAX_READ;
    if (g_delay_ms > 0) usleep(static_cast<useconds_t>(g_delay_ms) * 1000);
    int e = resolve(path, real);
    if (e) return reply_err(fd, f.id, e, strerror(e));
    int file = open(real.c_str(), O_RDONLY);
    if (file < 0) return reply_err(fd, f.id, errno, strerror(errno));
    struct stat before{}, after{};
    if (fstat(file, &before) != 0 || !S_ISREG(before.st_mode)) {
        int err = S_ISDIR(before.st_mode) ? EISDIR : EINVAL;
        close(file);
        return reply_err(fd, f.id, err, strerror(err));
    }
    std::vector<uint8_t> buf(len);
    ssize_t n = 0;
    int err = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        n = pread(file, buf.data(), len, static_cast<off_t>(off));
        err = errno;
        if (n < 0 || fstat(file, &after) != 0) break;
        if (after.st_size == before.st_size && after.st_mtime == before.st_mtime) break;
        before = after;  // changed under us: retry against the new version
    }
    close(file);
    if (n < 0) return reply_err(fd, f.id, err, strerror(err));
    Writer w;
    w.u64(static_cast<uint64_t>(before.st_size));
    w.i64(static_cast<int64_t>(before.st_mtime));
    w.bytes(buf.data(), static_cast<size_t>(n));
    return reply(fd, f.type, f.id, w);
}

static void serve(int fd) {
    bool greeted = false;
    Frame f;
    for (;;) {
        int rc = recv_frame(fd, f);
        if (rc <= 0) break;
        bool ok;
        try {
            Reader r(f.payload);
            if (f.type == MSG_HELLO) {
                uint16_t v = r.u16();
                if (v != PROTO_VERSION) {
                    reply_err(fd, f.id, EPROTO, "unsupported protocol version");
                    break;
                }
                Writer w;
                w.u16(PROTO_VERSION);
                w.str("tierfs-reference-backend");
                greeted = true;
                ok = reply(fd, f.type, f.id, w);
            } else if (!greeted) {
                reply_err(fd, f.id, EPROTO, "HELLO required first");
                break;
            } else if (f.type == MSG_STAT) {
                ok = do_stat(fd, f, r);
            } else if (f.type == MSG_READDIR) {
                ok = do_readdir(fd, f, r);
            } else if (f.type == MSG_READ) {
                ok = do_read(fd, f, r);
            } else {
                ok = reply_err(fd, f.id, ENOSYS, "unknown message type");
            }
        } catch (const std::exception& ex) {  // malformed payload
            reply_err(fd, f.id, EPROTO, ex.what());
            break;
        }
        if (!ok) break;
    }
    close(fd);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <root-dir> [port] [bind-addr]\n", argv[0]);
        return 2;
    }
    char rootbuf[PATH_MAX];
    if (!realpath(argv[1], rootbuf)) { perror("root"); return 1; }
    g_root = rootbuf;
    int port = argc > 2 ? atoi(argv[2]) : 9099;
    const char* bind_addr = argc > 3 ? argv[3] : "127.0.0.1";

    if (const char* d = getenv("TIERFS_DELAY_MS")) g_delay_ms = atoi(d);
    signal(SIGPIPE, SIG_IGN);  // a client vanishing mid-write must not kill us

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        fprintf(stderr, "bad bind address\n");
        return 2;
    }
    if (bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 ||
        listen(ls, 16) != 0) {
        perror("bind/listen");
        return 1;
    }
    fprintf(stderr, "serving %s on %s:%d (read-only, NO TLS)\n", g_root.c_str(),
            bind_addr, port);
    for (;;) {
        int c = accept(ls, nullptr, nullptr);
        if (c < 0) continue;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        std::thread(serve, c).detach();
    }
}
