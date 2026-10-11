#include "tierclient.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <filesystem>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "chunkcache.hpp"
#include "metastore.hpp"
#include "wire.hpp"

using namespace tierfs;

static constexpr uint32_t C = CHUNK_SIZE;
static constexpr size_t MAX_QUEUED_PREFETCH = 16;

// One TCP connection to the backend and the lock that serialises its use (the
// protocol has one request in flight per connection).
struct Conn {
    int fd = -1;
    uint32_t next_id = 1;
    std::mutex mu;
};

struct PfReq {
    std::string path;
    uint64_t size;
    int64_t mtime;
    uint32_t idx;
};

struct tc_client {
    std::string host, port;
    int timeout_ms = 3000;
    int readahead = 4;

    // fg serves foreground requests. fg.mu ALSO guards `meta`, which is not
    // thread-safe on its own.
    Conn fg;
    std::unique_ptr<MetaStore> meta;
    std::unique_ptr<ChunkCache> chunks;

    // Open files: their chunks are exempt from eviction.
    std::mutex pin_mu;
    std::unordered_map<std::string, int> pins;

    // Readahead: a few worker threads, each with its own connection. Separate
    // connections mean prefetching never makes a foreground read wait on the same
    // socket, and several chunks can be in flight at once, which is what hides
    // network latency (one prefetch stream would only match the foreground speed).
    std::vector<std::unique_ptr<Conn>> bg;
    std::vector<std::thread> workers;
    std::mutex pf_mu;
    std::condition_variable pf_cv;
    std::deque<PfReq> queue;
    std::set<std::string> queued;    // waiting in `queue`
    std::set<std::string> inflight;  // being fetched right now; readers wait for these
    std::unordered_set<std::string> prefetched;  // fetched ahead, not yet consumed
    bool stop = false;

    std::mutex seq_mu;
    std::unordered_map<std::string, uint64_t> last_end;  // sequential-read detection

    std::atomic<uint64_t> fetches{0}, prefetch_fetches{0}, prefetch_used{0}, bytes_fetched{0};
};

// Errors meaning "can't reach the backend", as opposed to an answer from it.
static bool is_net_err(int rc) {
    return rc == -EHOSTUNREACH || rc == -ETIMEDOUT || rc == -EIO;
}

static void drop(Conn& cn) {
    if (cn.fd >= 0) close(cn.fd);
    cn.fd = -1;
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

static bool ensure_connected(tc_client* c, Conn& cn) {
    if (cn.fd >= 0) return true;
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
    uint32_t id = cn.next_id++;
    if (!send_frame(fd, MSG_HELLO, id, w.b) || recv_frame(fd, resp) != 1 ||
        resp.type != (MSG_HELLO | MSG_REPLY_FLAG) || resp.id != id) {
        close(fd);
        return false;
    }
    cn.fd = fd;
    return true;
}

// One request/response; caller holds cn.mu. Returns 0 and fills resp, or
// -errno. A server ERROR reply is an application error (connection stays up);
// an I/O failure drops the connection so the next call reconnects.
static int rpc(tc_client* c, Conn& cn, uint8_t type, const Writer& req, Frame& resp) {
    for (int attempt = 0; attempt < 2; attempt++) {
        bool had_conn = cn.fd >= 0;
        if (!ensure_connected(c, cn)) return -EHOSTUNREACH;
        uint32_t id = cn.next_id++;
        bool ok = send_frame(cn.fd, type, id, req.b) && recv_frame(cn.fd, resp) == 1 &&
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
            if (resp.type != (type | MSG_REPLY_FLAG)) { drop(cn); return -EPROTO; }
            return 0;
        }
        int e = errno;
        drop(cn);
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

static std::string key_str(const std::string& path, int64_t mtime, uint64_t size, uint32_t idx) {
    return path + '|' + std::to_string(mtime) + '|' + std::to_string(size) + '|' + std::to_string(idx);
}

// If the file's version changed since we last saw it, its old chunks can never
// be used again; free them now instead of waiting for LRU. Caller holds fg.mu.
static void note_version(tc_client* c, const std::string& path, const tc_attr& fresh) {
    tc_attr old;
    if (fresh.is_dir || !c->meta->get_attr(path, old) || old.is_dir) return;
    if (old.size != fresh.size || old.mtime != fresh.mtime) c->chunks->invalidate_path(path);
}

// STAT over the network, updating the cache. Caller holds fg.mu.
static int stat_rpc(tc_client* c, const char* path, tc_attr* out) {
    Writer w;
    w.str(path);
    Frame resp;
    int rc = rpc(c, c->fg, MSG_STAT, w, resp);
    if (rc) return rc;
    try {
        Reader r(resp.payload);
        *out = read_attr(r);
    } catch (...) { drop(c->fg); return -EPROTO; }
    note_version(c, path, *out);
    c->meta->put_attr(path, *out);
    return 0;
}

// ---- reading through the chunk cache --------------------------------------

static void note_used(tc_client* c, const std::string& ks) {
    std::lock_guard<std::mutex> lk(c->pf_mu);
    if (c->prefetched.erase(ks)) c->prefetch_used++;
}

// Fetch chunk `idx` from the backend over `cn` (caller holds cn.mu).
static int fetch_chunk(tc_client* c, Conn& cn, const std::string& path, uint32_t idx,
                       std::vector<uint8_t>& data, uint64_t& size, int64_t& mtime) {
    Writer w;
    w.str(path);
    w.u64(static_cast<uint64_t>(idx) * C);
    w.u32(C);
    Frame resp;
    int rc = rpc(c, cn, MSG_READ, w, resp);
    if (rc) return rc;
    try {
        Reader r(resp.payload);
        size = r.u64();
        mtime = r.i64();
        data.assign(resp.payload.begin() + static_cast<long>(r.pos), resp.payload.end());
    } catch (...) { drop(cn); return -EPROTO; }
    c->bytes_fetched += data.size();
    return 0;
}

// 0 = chunk in `out`; 1 = the file changed on the server (cache refreshed, caller
// must restart the read); <0 = error.
static int get_chunk(tc_client* c, const std::string& path, const tc_attr& a, uint32_t idx,
                     std::vector<uint8_t>& out) {
    ChunkKey k{path, a.size, a.mtime, idx};
    std::string ks = key_str(path, a.mtime, a.size, idx);
    size_t expected = static_cast<size_t>(std::min<uint64_t>(C, a.size - static_cast<uint64_t>(idx) * C));

    if (c->chunks->get(k, out) && out.size() == expected) { note_used(c, ks); return 0; }

    {   // The readahead thread may be fetching exactly this chunk: wait for it
        // rather than asking the backend twice.
        std::unique_lock<std::mutex> lk(c->pf_mu);
        if (c->inflight.count(ks))
            c->pf_cv.wait_for(lk, std::chrono::milliseconds(c->timeout_ms),
                              [&] { return !c->inflight.count(ks); });
    }
    if (c->chunks->get(k, out) && out.size() == expected) { note_used(c, ks); return 0; }

    std::lock_guard<std::mutex> lk(c->fg.mu);
    if (c->chunks->get(k, out) && out.size() == expected) return 0;  // fetched while we queued for the lock

    uint64_t size;
    int64_t mtime;
    int rc = fetch_chunk(c, c->fg, path, idx, out, size, mtime);
    if (rc) return rc;
    c->fetches++;
    if (size != a.size || mtime != a.mtime) {
        // The file is no longer the version we planned this read around. Record
        // the new version and drop every chunk of the old one.
        tc_attr na = a;
        na.size = size;
        na.mtime = mtime;
        c->meta->put_attr(path, na);
        c->chunks->invalidate_path(path);
        return 1;
    }
    if (out.size() != expected) return -EIO;  // inconsistent reply; never cache it
    c->chunks->put(k, out.data(), out.size());
    return 0;
}

static void maybe_prefetch(tc_client* c, const std::string& path, const tc_attr& a,
                           uint64_t off, uint64_t end) {
    if (c->readahead <= 0 || end == 0) return;
    bool sequential;
    {
        std::lock_guard<std::mutex> lk(c->seq_mu);
        auto it = c->last_end.find(path);
        sequential = off == 0 || (it != c->last_end.end() && it->second == off);
        if (c->last_end.size() > 256) c->last_end.clear();
        c->last_end[path] = end;
    }
    if (!sequential) return;
    uint32_t last = static_cast<uint32_t>((end - 1) / C);
    bool added = false;
    for (int i = 1; i <= c->readahead; i++) {
        uint32_t idx = last + static_cast<uint32_t>(i);
        if (static_cast<uint64_t>(idx) * C >= a.size) break;
        if (c->chunks->has(ChunkKey{path, a.size, a.mtime, idx})) continue;
        std::string ks = key_str(path, a.mtime, a.size, idx);
        std::lock_guard<std::mutex> lk(c->pf_mu);
        if (c->queue.size() >= MAX_QUEUED_PREFETCH) break;
        if (c->queued.count(ks) || c->inflight.count(ks)) continue;
        c->queue.push_back({path, a.size, a.mtime, idx});
        c->queued.insert(ks);
        added = true;
    }
    if (added) c->pf_cv.notify_all();
}

static void prefetch_worker(tc_client* c, Conn* bg) {
    for (;;) {
        PfReq req;
        std::string ks;
        {
            std::unique_lock<std::mutex> lk(c->pf_mu);
            c->pf_cv.wait(lk, [&] { return c->stop || !c->queue.empty(); });
            if (c->stop) return;
            req = std::move(c->queue.front());
            c->queue.pop_front();
            ks = key_str(req.path, req.mtime, req.size, req.idx);
            c->queued.erase(ks);
            c->inflight.insert(ks);
        }
        bool failed = false;
        ChunkKey k{req.path, req.size, req.mtime, req.idx};
        if (!c->chunks->has(k)) {
            std::vector<uint8_t> data;
            uint64_t size;
            int64_t mtime;
            std::lock_guard<std::mutex> bg_lock(bg->mu);
            int rc = fetch_chunk(c, *bg, req.path, req.idx, data, size, mtime);
            size_t expected = static_cast<size_t>(std::min<uint64_t>(C, req.size - static_cast<uint64_t>(req.idx) * C));
            if (rc == 0 && size == req.size && mtime == req.mtime && data.size() == expected) {
                c->chunks->put(k, data.data(), data.size());
                c->prefetch_fetches++;
                std::lock_guard<std::mutex> lk(c->pf_mu);
                if (c->prefetched.size() > 4096) c->prefetched.clear();
                c->prefetched.insert(ks);
            } else if (rc != 0) {
                failed = true;  // unreachable: do not keep hammering the network
            }  // a changed file is simply not cached; the next foreground read notices
        }
        std::lock_guard<std::mutex> lk(c->pf_mu);
        c->inflight.erase(ks);
        if (failed) { c->queue.clear(); c->queued.clear(); }
        c->pf_cv.notify_all();
    }
}

extern "C" {

tc_client* tc_create(const tc_config* cfg) {
    auto* c = new tc_client;
    c->host = cfg->host ? cfg->host : "127.0.0.1";
    c->port = std::to_string(cfg->port ? cfg->port : 9099);
    c->timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : 3000;
    c->readahead = cfg->readahead < 0 ? 4 : cfg->readahead;

    std::string dir = cfg->cache_dir ? cfg->cache_dir : "";
    if (dir.empty()) {
        const char* home = getenv("HOME");
        dir = std::string(home ? home : "/tmp") + "/Library/Caches/tierfs/" + c->host + "_" + c->port;
    }
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    c->meta = std::make_unique<MetaStore>(ec ? ":memory:" : dir + "/meta.db");
    if (c->meta->recovered()) fprintf(stderr, "tierfs: metadata cache was unreadable; rebuilt\n");
    c->chunks = std::make_unique<ChunkCache>(
        dir, cfg->cache_bytes ? cfg->cache_bytes : (512ull << 20));
    if (!c->chunks->ok()) fprintf(stderr, "tierfs: chunk cache unavailable; reads will not be cached\n");
    c->chunks->set_pin_check([c](const std::string& p) {
        std::lock_guard<std::mutex> lk(c->pin_mu);
        return c->pins.count(p) > 0;
    });
    int nworkers = std::min(c->readahead, 4);
    for (int i = 0; i < nworkers; i++) {
        c->bg.push_back(std::make_unique<Conn>());
        c->workers.emplace_back(prefetch_worker, c, c->bg.back().get());
    }
    return c;
}

void tc_destroy(tc_client* c) {
    if (!c) return;
    {
        std::lock_guard<std::mutex> lk(c->pf_mu);
        c->stop = true;
    }
    c->pf_cv.notify_all();
    for (auto& t : c->workers) t.join();
    drop(c->fg);
    for (auto& b : c->bg) drop(*b);
    delete c;
}

int tc_getattr(tc_client* c, const char* path, tc_attr* out) {
    std::lock_guard<std::mutex> lk(c->fg.mu);
    int rc = stat_rpc(c, path, out);
    if (rc == 0) return 0;
    if (rc == -ENOENT) { c->meta->forget(path); c->chunks->invalidate_tree(path); }
    if (is_net_err(rc) && c->meta->get_attr(path, *out)) return 0;  // stale but usable
    if (is_net_err(rc) && strcmp(path, "/") == 0) {
        // The root exists by definition. Answering here lets a cold, offline
        // mount complete: if getattr("/") fails, mount_nfs blocks forever in
        // an uninterruptible state (found by scripts/phase2-test.sh).
        *out = tc_attr{1, 0, time(nullptr), 0555};
        return 0;
    }
    return rc;
}

int tc_readdir(tc_client* c, const char* path, tc_dir_cb cb, void* ctx) {
    std::lock_guard<std::mutex> lk(c->fg.mu);
    Writer w;
    w.str(path);
    Frame resp;
    int rc = rpc(c, c->fg, MSG_READDIR, w, resp);
    MetaStore::DirList list;
    if (rc) {
        if (rc == -ENOENT) { c->meta->forget(path); c->chunks->invalidate_tree(path); }
        if (is_net_err(rc) && c->meta->get_dir(path, list)) {  // stale listing
            for (auto& e : list)
                if (cb(ctx, e.first.c_str(), &e.second)) break;
            return 0;
        }
        return rc;
    }
    Reader r(resp.payload);
    try {
        uint32_t count = r.u32();
        for (uint32_t i = 0; i < count; i++) {
            std::string name = r.str();
            tc_attr a = read_attr(r);
            list.emplace_back(std::move(name), a);
        }
    } catch (...) { drop(c->fg); return -EPROTO; }
    for (auto& e : list)
        note_version(c, path == std::string("/") ? "/" + e.first : std::string(path) + "/" + e.first, e.second);
    c->meta->put_dir(path, list);
    for (auto& e : list)
        if (cb(ctx, e.first.c_str(), &e.second)) break;
    return 0;
}

int64_t tc_read(tc_client* c, const char* cpath, uint64_t off, uint32_t len, void* buf) {
    if (len > MAX_READ) len = MAX_READ;
    std::string path = cpath;
    // A file that changes under a read (the server tells us via the size/mtime in
    // every READ reply) forces a restart so the result is never a blend of two
    // versions. Give up after 3 tries: something is rewriting it continuously.
    for (int attempt = 0; attempt < 3; attempt++) {
        tc_attr a;
        {
            std::lock_guard<std::mutex> lk(c->fg.mu);
            if (!c->meta->get_attr(path, a)) {
                int rc = stat_rpc(c, cpath, &a);
                if (rc) return rc;
            }
        }
        if (a.is_dir) return -EISDIR;
        if (off >= a.size) return 0;
        uint64_t end = std::min<uint64_t>(off + len, a.size);

        auto* dst = static_cast<uint8_t*>(buf);
        uint64_t pos = off;
        bool changed = false;
        std::vector<uint8_t> chunk;
        while (pos < end) {
            uint32_t idx = static_cast<uint32_t>(pos / C);
            int rc = get_chunk(c, path, a, idx, chunk);
            if (rc == 1) { changed = true; break; }
            // An error part-way through fails the WHOLE request. Returning the
            // bytes copied so far would look like end-of-file to the kernel and
            // silently truncate the file for cp/cat/git.
            if (rc < 0) return rc;
            size_t from = static_cast<size_t>(pos - static_cast<uint64_t>(idx) * C);
            size_t n = static_cast<size_t>(std::min<uint64_t>(chunk.size() - from, end - pos));
            memcpy(dst, chunk.data() + from, n);
            dst += n;
            pos += n;
        }
        if (changed) continue;
        {
            std::lock_guard<std::mutex> lk(c->fg.mu);
            c->meta->touch(path, time(nullptr));  // feeds the Phase 3 tiering policy
        }
        maybe_prefetch(c, path, a, off, end);
        return static_cast<int64_t>(end - off);
    }
    return -EIO;
}

void tc_pin(tc_client* c, const char* path) {
    std::lock_guard<std::mutex> lk(c->pin_mu);
    c->pins[path]++;
}

void tc_unpin(tc_client* c, const char* path) {
    std::lock_guard<std::mutex> lk(c->pin_mu);
    auto it = c->pins.find(path);
    if (it != c->pins.end() && --it->second <= 0) c->pins.erase(it);
}

void tc_get_stats(tc_client* c, tc_stats* out) {
    ChunkStats s = c->chunks->stats();
    out->chunk_hits = s.hits;
    out->chunk_misses = s.misses;
    out->chunk_corrupt = s.corrupt;
    out->chunk_evicted = s.evicted;
    out->fetches = c->fetches;
    out->prefetch_fetches = c->prefetch_fetches;
    out->prefetch_used = c->prefetch_used;
    out->bytes_fetched = c->bytes_fetched;
    out->cache_bytes_used = c->chunks->bytes_used();
}

}  // extern "C"
