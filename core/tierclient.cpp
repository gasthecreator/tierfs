#include "tierclient.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "wire.hpp"

using namespace tierfs;

struct tc_client {
    std::string host;
    std::string port;
    int timeout_ms;
    int fd = -1;
    uint32_t next_id = 1;
    std::mutex mu;  // one connection, one request in flight (FUSE is multithreaded)

    // Metadata cache (in memory for now; Phase 2 persists it in SQLite).
    // Updated on every successful reply. Served ONLY when the network fails, so
    // an online client always sees fresh data and an offline one never hangs
    // Finder. Entries are removed when the server says a path no longer exists.
    using DirList = std::vector<std::pair<std::string, tc_attr>>;
    std::unordered_map<std::string, tc_attr> attrs;
    std::unordered_map<std::string, DirList> dirs;
};

// Errors meaning "can't reach the backend", as opposed to an answer from it.
static bool is_net_err(int rc) {
    return rc == -EHOSTUNREACH || rc == -ETIMEDOUT || rc == -EIO;
}

static std::string join(const std::string& dir, const std::string& name) {
    return dir == "/" ? "/" + name : dir + "/" + name;
}

static void drop(tc_client* c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
}

// Connect with a deadline. A plain connect() to an unreachable host can block
// for over a minute, which would freeze every app touching the mount.
static int connect_timeout(const char* host, const char* port, int timeout_ms) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
        int rc = connect(s, ai->ai_addr, ai->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS) {
            pollfd p{s, POLLOUT, 0};
            if (poll(&p, 1, timeout_ms) == 1) {
                int err = 0;
                socklen_t el = sizeof err;
                getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el);
                rc = err == 0 ? 0 : -1;
            } else {
                rc = -1;
            }
        }
        if (rc == 0) {
            fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK);
            fd = s;
            break;
        }
        close(s);
    }
    freeaddrinfo(res);
    return fd;
}

static bool ensure_connected(tc_client* c) {
    if (c->fd >= 0) return true;
    int fd = connect_timeout(c->host.c_str(), c->port.c_str(), c->timeout_ms);
    if (fd < 0) return false;
    timeval tv{c->timeout_ms / 1000, (c->timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

    Writer w;
    w.u16(PROTO_VERSION);
    Frame resp;
    uint32_t id = c->next_id++;
    if (!send_frame(fd, MSG_HELLO, id, w.b) || recv_frame(fd, resp) != 1 ||
        resp.type != (MSG_HELLO | MSG_REPLY_FLAG) || resp.id != id) {
        close(fd);
        return false;
    }
    c->fd = fd;
    return true;
}

// One request/response. Returns 0 and fills resp, or -errno. A server ERROR
// reply is an application error (connection stays up); an I/O failure drops
// the connection so the next call reconnects.
static int rpc(tc_client* c, uint8_t type, const Writer& req, Frame& resp) {
    for (int attempt = 0; attempt < 2; attempt++) {
        bool had_conn = c->fd >= 0;
        if (!ensure_connected(c)) return -EHOSTUNREACH;
        uint32_t id = c->next_id++;
        bool ok = send_frame(c->fd, type, id, req.b) && recv_frame(c->fd, resp) == 1 &&
                  resp.id == id;
        if (ok) {
            if (resp.type == MSG_ERROR) {
                try {
                    Reader r(resp.payload);
                    int e = r.i32();
                    return e > 0 ? -e : -EIO;
                } catch (...) {
                    return -EPROTO;
                }
            }
            if (resp.type != (type | MSG_REPLY_FLAG)) { drop(c); return -EPROTO; }
            return 0;
        }
        int e = errno;
        drop(c);
        // A connection that sat idle may have been closed by the server; retry
        // once on a fresh connection. A timeout on a fresh connection is final.
        if (!had_conn) return (e == EAGAIN || e == EWOULDBLOCK) ? -ETIMEDOUT : -EIO;
    }
    return -EIO;
}

static tc_attr read_attr(Reader& r) {
    tc_attr a;
    a.is_dir = r.u8();
    a.size = r.u64();
    a.mtime = r.i64();
    a.mode = r.u32();
    return a;
}

extern "C" {

tc_client* tc_create(const char* host, uint16_t port, int timeout_ms) {
    auto* c = new tc_client;
    c->host = host;
    c->port = std::to_string(port);
    c->timeout_ms = timeout_ms > 0 ? timeout_ms : 3000;
    return c;
}

void tc_destroy(tc_client* c) {
    if (!c) return;
    drop(c);
    delete c;
}

int tc_getattr(tc_client* c, const char* path, tc_attr* out) {
    std::lock_guard<std::mutex> lk(c->mu);
    Writer w;
    w.str(path);
    Frame resp;
    int rc = rpc(c, MSG_STAT, w, resp);
    if (rc) {
        if (rc == -ENOENT) { c->attrs.erase(path); c->dirs.erase(path); }
        if (is_net_err(rc)) {
            auto it = c->attrs.find(path);
            if (it != c->attrs.end()) { *out = it->second; return 0; }  // stale but usable
        }
        return rc;
    }
    try {
        Reader r(resp.payload);
        *out = read_attr(r);
    } catch (...) { drop(c); return -EPROTO; }
    c->attrs[path] = *out;
    return 0;
}

int tc_readdir(tc_client* c, const char* path, tc_dir_cb cb, void* ctx) {
    std::lock_guard<std::mutex> lk(c->mu);
    Writer w;
    w.str(path);
    Frame resp;
    int rc = rpc(c, MSG_READDIR, w, resp);
    if (rc) {
        if (rc == -ENOENT) { c->attrs.erase(path); c->dirs.erase(path); }
        if (is_net_err(rc)) {
            auto it = c->dirs.find(path);
            if (it != c->dirs.end()) {  // stale listing
                for (auto& e : it->second)
                    if (cb(ctx, e.first.c_str(), &e.second)) break;
                return 0;
            }
        }
        return rc;
    }
    Reader r(resp.payload);
    tc_client::DirList list;
    try {
        uint32_t count = r.u32();
        for (uint32_t i = 0; i < count; i++) {
            std::string name = r.str();
            tc_attr a = read_attr(r);
            list.emplace_back(std::move(name), a);
        }
    } catch (...) { drop(c); return -EPROTO; }
    for (auto& e : list) c->attrs[join(path, e.first)] = e.second;
    for (auto& e : list)
        if (cb(ctx, e.first.c_str(), &e.second)) break;
    c->dirs[path] = std::move(list);
    return 0;
}

int64_t tc_read(tc_client* c, const char* path, uint64_t off, uint32_t len, void* buf) {
    std::lock_guard<std::mutex> lk(c->mu);
    if (len > MAX_READ) len = MAX_READ;
    Writer w;
    w.str(path);
    w.u64(off);
    w.u32(len);
    Frame resp;
    int rc = rpc(c, MSG_READ, w, resp);
    if (rc) return rc;
    if (resp.payload.size() > len) { drop(c); return -EPROTO; }
    memcpy(buf, resp.payload.data(), resp.payload.size());
    return static_cast<int64_t>(resp.payload.size());
}

}  // extern "C"
