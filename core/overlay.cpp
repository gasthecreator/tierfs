#include "overlay.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <set>

#include "crashpoint.hpp"
#include "fsutil.hpp"

namespace tierfs {
namespace {

OvKind kind_of(mode_t m) {
    if (S_ISDIR(m)) return OvKind::Dir;
    if (S_ISREG(m)) return OvKind::File;
    if (S_ISLNK(m)) return OvKind::Symlink;
    return OvKind::Other;
}

constexpr const char* BOOKKEEPING = ".tierfs";

}  // namespace

Overlay::Overlay(Ledger& ledger, const crypto::Keys& keys, DeviceMap devices, OverlayConfig cfg, DropEngine* engine)
    : ledger_(ledger), keys_(keys), devices_(std::move(devices)), cfg_(std::move(cfg)), engine_(engine) {
    while (cfg_.origin_dir.size() > 1 && cfg_.origin_dir.back() == '/') cfg_.origin_dir.pop_back();
    if (!cfg_.logical_prefix.empty() && cfg_.logical_prefix.back() != '/') cfg_.logical_prefix += '/';
    volume_ = ledger_.volume_id();
}

Overlay::~Overlay() {
    {
        std::lock_guard<std::mutex> g(ra_mu_);
        ra_stop_ = true;
    }
    ra_cv_.notify_all();
    for (auto& t : ra_threads_) t.join();
}

bool Overlay::resolve(const std::string& path, std::string* origin_path, std::string* logical_path, std::string* rel_out) const {
    if (path.empty() || path[0] != '/') return false;
    if (path.find('\0') != std::string::npos) return false;
    std::string rel;
    size_t pos = 1;
    bool first = true;
    while (pos <= path.size()) {
        size_t slash = path.find('/', pos);
        std::string comp = path.substr(pos, slash == std::string::npos ? std::string::npos : slash - pos);
        pos = slash == std::string::npos ? path.size() + 1 : slash + 1;
        if (comp.empty() || comp == ".") continue;
        if (comp == "..") return false;
        if (first && comp == BOOKKEEPING) return false;   // our own directory does not exist as far as users are concerned
        first = false;
        if (!rel.empty()) rel += '/';
        rel += comp;
    }
    if (origin_path) *origin_path = rel.empty() ? cfg_.origin_dir : cfg_.origin_dir + "/" + rel;
    if (logical_path) *logical_path = cfg_.logical_prefix + rel;
    if (rel_out) *rel_out = rel;
    return true;
}

bool Overlay::is_remote_state(const FileRec& f) {
    return f.state == FileState::DROPPING || f.state == FileState::OFFLOADED || f.state == FileState::HYDRATING || f.state == FileState::AT_RISK;
}

// ---------------------------------------------------------------- metadata

int Overlay::getattr(const std::string& path, OvStat* out) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    struct stat st;
    if (lstat(op.c_str(), &st) == 0) {
        OvStat s;
        s.kind = kind_of(st.st_mode);
        s.size = static_cast<uint64_t>(st.st_size);
        s.mtime = st.st_mtimespec.tv_sec;
        s.mtime_nsec = st.st_mtimespec.tv_nsec;
        s.mode = st.st_mode & 0777;
        s.nlink = static_cast<uint32_t>(st.st_nlink);
        if (s.kind == OvKind::File) {
            if (auto f = ledger_.get_file_by_path(lp)) s.file_id = f->file_id;
        }
        if (out) *out = s;
        return 0;
    }
    if (errno != ENOENT && errno != ENOTDIR) return -errno;
    if (rel.empty()) return -ENOENT;
    auto f = ledger_.get_file_by_path(lp);
    if (!f || !is_remote_state(*f)) return -ENOENT;
    if (out) {
        OvStat s;
        s.kind = OvKind::File;
        s.size = f->size;
        s.mtime = f->mtime;
        s.mode = f->mode & 0777;
        s.remote = true;
        s.file_id = f->file_id;
        *out = s;
    }
    return 0;
}

int Overlay::readdir(const std::string& path, std::vector<OvEntry>* out) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    DIR* d = opendir(op.c_str());
    if (!d) return -errno;
    std::set<std::string> seen;
    std::vector<OvEntry> entries;
    while (struct dirent* e = ::readdir(d)) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        if (rel.empty() && name == BOOKKEEPING) continue;
        OvEntry oe;
        oe.name = name;
        struct stat st;
        oe.kind = (fstatat(dirfd(d), name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) ? kind_of(st.st_mode) : OvKind::Other;
        seen.insert(ledger_.fold_path(name));
        entries.push_back(std::move(oe));
    }
    closedir(d);

    std::string dirprefix = lp.empty() || lp.back() == '/' ? lp : lp + "/";
    std::vector<FileRec> under;
    {
        under = ledger_.list_files_under(dirprefix);
    }
    for (const auto& f : under) {
        std::string name = f.path.substr(dirprefix.size());
        if (name.empty() || name.find('/') != std::string::npos) continue;   // deeper: belongs to a subdirectory's listing
        if (!is_remote_state(f) || seen.count(ledger_.fold_path(name))) continue;
        OvEntry oe;
        oe.name = name;
        oe.kind = OvKind::File;
        oe.remote = true;
        seen.insert(ledger_.fold_path(name));
        entries.push_back(std::move(oe));
    }
    std::sort(entries.begin(), entries.end(), [](const OvEntry& a, const OvEntry& b) { return a.name < b.name; });
    if (out) *out = std::move(entries);
    return 0;
}

int Overlay::readlink(const std::string& path, std::string* target) {
    std::string op;
    if (!resolve(path, &op, nullptr)) return -ENOENT;
    char buf[4096];
    ssize_t n = ::readlink(op.c_str(), buf, sizeof buf - 1);
    if (n < 0) return -errno;
    if (target) target->assign(buf, static_cast<size_t>(n));
    return 0;
}

Overlay::Stats Overlay::stats() {
    std::lock_guard<std::mutex> g(cache_mu_);
    return stats_;
}

// ---------------------------------------------------------------- reading

int64_t Overlay::read(const std::string& path, uint64_t offset, size_t size, uint8_t* buf) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    int fd = ::open(op.c_str(), O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) { close(fd); return -EISDIR; }
        size_t got = 0;
        while (got < size) {
            ssize_t n = pread(fd, buf + got, size - got, static_cast<off_t>(offset + got));
            if (n < 0) {
                if (errno == EINTR) continue;
                int e = errno;
                close(fd);
                return -e;
            }
            if (n == 0) break;
            got += static_cast<size_t>(n);
        }
        close(fd);
        return static_cast<int64_t>(got);
    }
    int e = errno;
    if ((e != ENOENT && e != ENOTDIR) || rel.empty()) return -e;
    // Not in the origin: a remote file, if the ledger says so.
    std::optional<FileRec> f;
    {
        f = ledger_.get_file_by_path(lp);
    }
    if (!f || !is_remote_state(*f)) return -ENOENT;
    return read_remote(*f, offset, size, buf);
}

std::vector<std::string> Overlay::device_order(const FileRec& f) {
    std::vector<std::string> order;
    std::set<std::string> have;
    const DeviceMap known = devices_snapshot();
    auto usable = [&](const std::string& id) {
        auto kit = known.find(id);
        if (kit == known.end() || !kit->second) return false;
        auto d = ledger_.get_device(id);
        return d && d->state != "retired";
    };
    for (const auto& r : ledger_.get_replicas(f.file_id, f.current_version))
        if (r.state == ReplicaState::COMMITTED && usable(r.device_id) && have.insert(r.device_id).second) order.push_back(r.device_id);
    for (const auto& kv : known)
        if (usable(kv.first) && have.insert(kv.first).second) order.push_back(kv.first);
    return order;
}

std::shared_ptr<const crypto::Bytes> Overlay::fetch_chunk(const ChunkRec& c, const std::vector<std::string>& order) {
    {
        std::unique_lock<std::mutex> g(cache_mu_);
        for (;;) {
            auto it = cache_.find(c.chunk_id);
            if (it != cache_.end()) {
                lru_.splice(lru_.begin(), lru_, it->second.it);
                stats_.cache_hits++;
                return it->second.data;
            }
            if (!inflight_.count(c.chunk_id)) break;
            cache_cv_.wait(g);  // somebody (a reader, or the read-ahead) is fetching it: wait for that instead of fetching twice
        }
        inflight_.insert(c.chunk_id);
    }
    struct Done {  // whoever fetches releases the claim, success or not, and wakes the waiters
        Overlay& o;
        const std::string& id;
        ~Done() {
            {
                std::lock_guard<std::mutex> g(o.cache_mu_);
                o.inflight_.erase(id);
            }
            o.cache_cv_.notify_all();
        }
    } done{*this, c.chunk_id};
    for (const auto& id : order) {
        crypto::Bytes blob, plain;
        {
            std::lock_guard<std::mutex> g(cache_mu_);
            stats_.chunk_fetches++;
        }
        DeviceClient* client = client_for(id);
        DevRes r = client ? client->get_chunk(c.chunk_id, blob) : DevRes{ENODEV, "no such device"};
        bool good = r.ok() && crypto::open_chunk(keys_, volume_, c.chunk_id, blob.data(), blob.size(), plain) == crypto::OpenError::Ok &&
                    plain.size() == c.len && crypto::chunk_id(keys_, plain.data(), plain.size()) == c.chunk_id;
        if (!good) {
            std::lock_guard<std::mutex> g(cache_mu_);
            stats_.bad_chunks_skipped++;
            continue;
        }
        auto data = std::make_shared<const crypto::Bytes>(std::move(plain));
        std::lock_guard<std::mutex> g(cache_mu_);
        if (!cache_.count(c.chunk_id)) {
            lru_.push_front(c.chunk_id);
            cache_[c.chunk_id] = Entry{data, lru_.begin()};
            cache_used_ += data->size();
            while (cache_used_ > cfg_.cache_bytes && lru_.size() > 1) {
                const std::string& victim = lru_.back();
                auto vit = cache_.find(victim);
                cache_used_ -= vit->second.data->size();
                cache_.erase(vit);
                lru_.pop_back();
            }
        }
        return data;
    }
    return nullptr;
}

int64_t Overlay::read_remote(const FileRec& f, uint64_t offset, size_t size, uint8_t* buf) {
    if (f.current_version <= 0) return -EIO;
    if (offset >= f.size || size == 0) return 0;
    size = static_cast<size_t>(std::min<uint64_t>(size, f.size - offset));
    std::vector<ChunkRec> chunks;
    {
        chunks = ledger_.get_chunks(f.file_id, f.current_version);
    }
    uint64_t total = 0;
    for (const auto& c : chunks) total += c.len;
    if (total != f.size) return -EIO;   // the ledger contradicts itself: refuse rather than guess
    std::vector<std::string> order = device_order(f);
    uint64_t start = 0;
    size_t done = 0;
    for (const auto& c : chunks) {
        uint64_t end = start + c.len;
        if (end > offset && start < offset + size) {
            auto plain = fetch_chunk(c, order);
            if (!plain) return -EIO;
            uint64_t from = std::max<uint64_t>(offset, start) - start;
            uint64_t to = std::min<uint64_t>(offset + size, end) - start;
            memcpy(buf + done, plain->data() + from, static_cast<size_t>(to - from));
            done += static_cast<size_t>(to - from);
        }
        start = end;
        if (start >= offset + size) break;
    }
    note_read(f, chunks, offset, done);
    return static_cast<int64_t>(done);
}

// A sequential reader gets the chunks after the one it is in fetched ahead of time. Never blocks the reader, never reports an error: a failed
// read-ahead is simply a chunk the reader will fetch (and verify) itself.
void Overlay::note_read(const FileRec& f, const std::vector<ChunkRec>& chunks, uint64_t offset, size_t done) {
    if (cfg_.readahead_chunks <= 0 || done == 0) return;
    size_t max_ahead = static_cast<size_t>(cfg_.readahead_chunks);
    max_ahead = std::min<size_t>(max_ahead, std::max<size_t>(1, cfg_.cache_bytes / (4u << 20)));
    uint64_t end = offset + done;
    std::vector<ChunkRec> want;
    std::vector<std::string> order;
    {
        std::lock_guard<std::mutex> g(ra_mu_);
        if (ra_stop_) return;
        if (streaks_.size() > 256) streaks_.clear();
        Streak& s = streaks_[f.file_id];
        if (offset == s.next && s.count > 0) {
            s.count++;
        } else {
            s.count = 1;
            s.window = 1;
        }
        s.next = end;
        if (s.count < 3) return;  // the third read in a row: the first two only establish that this is a sequential reader
        size_t window = std::min(s.window, max_ahead);
        s.window = std::min(max_ahead, s.window * 2);
        uint64_t pos = 0;
        size_t cur = 0;
        for (size_t i = 0; i < chunks.size(); i++) {  // the chunk holding the last byte just read
            if (end - 1 < pos + chunks[i].len) {
                cur = i;
                break;
            }
            pos += chunks[i].len;
            cur = i;
        }
        for (size_t i = cur + 1; i < chunks.size() && i <= cur + window; i++)
            if (!ra_queued_.count(chunks[i].chunk_id)) want.push_back(chunks[i]);
    }
    if (want.empty()) return;
    order = device_order(f);
    {
        std::lock_guard<std::mutex> g(cache_mu_);
        std::vector<ChunkRec> keep;
        for (auto& c : want)
            if (!cache_.count(c.chunk_id) && !inflight_.count(c.chunk_id)) keep.push_back(c);
        want.swap(keep);
    }
    if (want.empty() || order.empty()) return;
    std::lock_guard<std::mutex> g(ra_mu_);
    if (ra_stop_) return;
    if (ra_threads_.empty())
        for (int i = 0; i < std::max(1, cfg_.readahead_threads); i++) ra_threads_.emplace_back([this] { readahead_loop(); });
    for (auto& c : want) {
        if (ra_queue_.size() >= 64) break;  // a full queue means the devices are slower than the reader: do not pile up
        if (ra_queued_.insert(c.chunk_id).second) ra_queue_.push_back(Ahead{c, order});
    }
    ra_cv_.notify_all();
}

void Overlay::readahead_loop() {
    for (;;) {
        Ahead job;
        {
            std::unique_lock<std::mutex> g(ra_mu_);
            ra_cv_.wait(g, [&] { return ra_stop_ || !ra_queue_.empty(); });
            if (ra_stop_) return;
            job = std::move(ra_queue_.front());
            ra_queue_.pop_front();
        }
        bool had;
        {
            std::lock_guard<std::mutex> g(cache_mu_);
            had = cache_.count(job.chunk.chunk_id) > 0;
        }
        auto data = had ? nullptr : fetch_chunk(job.chunk, job.order);
        {
            std::lock_guard<std::mutex> g(cache_mu_);
            if (data) stats_.prefetched++;
        }
        std::lock_guard<std::mutex> g(ra_mu_);
        ra_queued_.erase(job.chunk.chunk_id);
    }
}

// ---------------------------------------------------------------- the write gate

bool Overlay::Gate::freeze(const FileRec& file, std::string* why) {
    std::lock_guard<std::mutex> g(o_.gate_mu_);
    auto w = o_.writers_.find(file.file_id);
    if (w != o_.writers_.end() && w->second > 0) {
        if (why) *why = "file is open for writing";
        return false;
    }
    o_.frozen_.insert(file.file_id);
    return true;
}

void Overlay::Gate::unfreeze(const FileRec& file) {
    {
        std::lock_guard<std::mutex> g(o_.gate_mu_);
        o_.frozen_.erase(file.file_id);
    }
    o_.gate_cv_.notify_all();
}

void Overlay::end_write(const std::string& file_id) {
    {
        std::lock_guard<std::mutex> g(gate_mu_);
        auto it = writers_.find(file_id);
        if (it != writers_.end() && --it->second <= 0) writers_.erase(it);
    }   // (nobody waits for writers to leave: freeze() refuses instead of waiting, so there is nothing to wake)
}

// Registers a writer for the file at `logical`, then records the modification in the ledger. The order matters: once the
// writer is registered no drop can freeze the file, and the generation bump (done before any byte changes) invalidates every
// replication or drop that was prepared against the old bytes.
int Overlay::begin_write(const std::string& logical, const std::string& origin_path, std::string* file_id, bool* need_hydrate, bool modify) {
    *need_hydrate = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(cfg_.write_wait_ms);
    std::unique_lock<std::mutex> g(gate_mu_);
    for (;;) {
        struct stat st;
        bool local = lstat(origin_path.c_str(), &st) == 0;
        auto f = ledger_.get_file_by_path(logical);
        if (!local) {
            if (f && is_remote_state(*f)) { *need_hydrate = true; return 0; }
            return -ENOENT;
        }
        if (S_ISDIR(st.st_mode)) return -EISDIR;
        if (!S_ISREG(st.st_mode)) return -EPERM;
        if (!f) {
            std::string id = ledger_.track_file(logical, static_cast<uint64_t>(st.st_size), st.st_mtimespec.tv_sec, st.st_mode & 0777);
            if (id.empty()) return -EIO;
            f = ledger_.get_file(id);
            if (!f) return -EIO;
        }
        const std::string id = f->file_id;
        if (frozen_.count(id) || f->state == FileState::DROPPING || f->state == FileState::HYDRATING) {
            if (gate_cv_.wait_until(g, deadline) == std::cv_status::timeout) return -EBUSY;
            continue;   // the state may have changed completely (a drop finished: the file is remote now)
        }
        if (f->state == FileState::OFFLOADED) return -EIO;   // bytes in the origin but the ledger says they are gone: inconsistent, do not guess
        writers_[id]++;
        Res r = modify ? ledger_.note_local_modified(id, static_cast<uint64_t>(st.st_size), st.st_mtimespec.tv_sec) : Res{true, "", ""};
        if (!r.ok) {
            auto it = writers_.find(id);
            if (it != writers_.end() && --it->second <= 0) writers_.erase(it);
            return -EIO;
        }
        *file_id = id;
        return 0;
    }
}

// ---------------------------------------------------------------- handles

uint64_t Overlay::add_handle(std::shared_ptr<Handle> h) {
    std::lock_guard<std::mutex> g(handles_mu_);
    uint64_t id = next_fh_++;
    handles_[id] = std::move(h);
    return id;
}

std::shared_ptr<Overlay::Handle> Overlay::get_handle(uint64_t fh) {
    std::lock_guard<std::mutex> g(handles_mu_);
    auto it = handles_.find(fh);
    return it == handles_.end() ? nullptr : it->second;
}

int Overlay::open(const std::string& path, int flags, uint64_t* fh) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    if (rel.empty()) return -EISDIR;
    const bool want_write = (flags & O_ACCMODE) != O_RDONLY || (flags & (O_TRUNC | O_APPEND));
    for (int attempt = 0; attempt < 4; attempt++) {
        struct stat st;
        if (lstat(op.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode)) return -EISDIR;
            if (!S_ISREG(st.st_mode)) return -EPERM;
            auto h = std::make_shared<Handle>();
            if (!want_write) {
                h->fd = ::open(op.c_str(), O_RDONLY | O_NOFOLLOW);
                if (h->fd < 0) {
                    if (errno == ENOENT) continue;   // it was dropped between the stat and the open
                    return -errno;
                }
                if (auto f = ledger_.get_file_by_path(lp)) { h->file_id = f->file_id; ledger_.touch_access(f->file_id, ledger_.now()); }
                if (fh) *fh = add_handle(h);
                return 0;
            }
            std::string id;
            bool need = false;
            int r = begin_write(lp, op, &id, &need);
            if (r < 0) return r;
            if (need) {
                int hr = hydrate_logical(lp, op);
                if (hr < 0) return hr;
                continue;
            }
            h->fd = ::open(op.c_str(), (flags & ~(O_CREAT | O_EXCL)) | O_NOFOLLOW);
            if (h->fd < 0) {
                int e = errno;
                end_write(id);
                if (e == ENOENT) continue;
                return -e;
            }
            h->writable = true;
            h->file_id = id;
            ledger_.touch_access(id, ledger_.now());
            if (fh) *fh = add_handle(h);
            return 0;
        }
        if (errno != ENOENT && errno != ENOTDIR) return -errno;
        auto f = ledger_.get_file_by_path(lp);
        if (!f || !is_remote_state(*f)) return -ENOENT;
        if (!want_write) {
            auto h = std::make_shared<Handle>();
            h->remote = true;
            h->snap = *f;
            h->file_id = f->file_id;
            ledger_.touch_access(f->file_id, ledger_.now());
            if (fh) *fh = add_handle(h);
            return 0;
        }
        int hr = hydrate_logical(lp, op);
        if (hr < 0) return hr;
    }
    return -EIO;
}

int Overlay::create(const std::string& path, uint32_t mode, int flags, uint64_t* fh) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    if (rel.empty()) return -EEXIST;
    std::string id;
    {
        std::lock_guard<std::mutex> g(gate_mu_);
        auto f = ledger_.get_file_by_path(lp);
        if (f && is_remote_state(*f)) return -EEXIST;     // the name is taken by a file whose bytes are on the devices
        if (f && (frozen_.count(f->file_id))) return -EBUSY;
        int fd = ::open(op.c_str(), (flags & ~O_ACCMODE) | O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, mode & 0777);
        if (fd < 0) return -errno;
        struct stat st;
        if (fstat(fd, &st) != 0) { int e = errno; close(fd); return -e; }
        if (f) {   // a stale entry (the file vanished behind our back): the new file takes over its identity
            id = f->file_id;
            if (!ledger_.note_local_modified(id, 0, st.st_mtimespec.tv_sec).ok) { close(fd); ::unlink(op.c_str()); return -EIO; }
        } else {
            id = ledger_.track_file(lp, 0, st.st_mtimespec.tv_sec, mode & 0777);
            if (id.empty()) { close(fd); ::unlink(op.c_str()); return -EIO; }
        }
        writers_[id]++;
        auto h = std::make_shared<Handle>();
        h->fd = fd;
        h->writable = true;
        h->file_id = id;
        if (fh) *fh = add_handle(h);
    }
    return 0;
}

int64_t Overlay::read_fh(uint64_t fh, uint64_t offset, size_t size, uint8_t* buf) {
    auto h = get_handle(fh);
    if (!h) return -EBADF;
    if (h->remote) return read_remote(h->snap, offset, size, buf);
    size_t got = 0;
    while (got < size) {
        ssize_t n = pread(h->fd, buf + got, size - got, static_cast<off_t>(offset + got));
        if (n < 0) { if (errno == EINTR) continue; return -errno; }
        if (n == 0) break;
        got += static_cast<size_t>(n);
    }
    return static_cast<int64_t>(got);
}

int64_t Overlay::write_fh(uint64_t fh, uint64_t offset, const uint8_t* buf, size_t size) {
    auto h = get_handle(fh);
    if (!h || !h->writable) return -EBADF;
    size_t done = 0;
    while (done < size) {
        ssize_t n = pwrite(h->fd, buf + done, size - done, static_cast<off_t>(offset + done));
        if (n < 0) { if (errno == EINTR) continue; return done ? static_cast<int64_t>(done) : -errno; }
        done += static_cast<size_t>(n);
    }
    return static_cast<int64_t>(done);
}

int Overlay::ftruncate(uint64_t fh, uint64_t size) {
    auto h = get_handle(fh);
    if (!h || !h->writable) return -EBADF;
    return ::ftruncate(h->fd, static_cast<off_t>(size)) == 0 ? 0 : -errno;
}

int Overlay::fsync_fh(uint64_t fh) {
    auto h = get_handle(fh);
    if (!h) return -EBADF;
    if (!h->writable) return 0;
    fsutil::full_sync(h->fd);
    return 0;
}

int Overlay::release(uint64_t fh) {
    std::shared_ptr<Handle> h;
    {
        std::lock_guard<std::mutex> g(handles_mu_);
        auto it = handles_.find(fh);
        if (it == handles_.end()) return -EBADF;
        h = it->second;
        handles_.erase(it);
    }
    {  // the locks taken through this descriptor go with it
        std::lock_guard<std::mutex> g(h->lmu);
        if (!h->range_owners.empty() || !h->flock_owners.empty()) {
            std::string key = lock_key(*h);
            for (uint64_t o : h->range_owners) locks_.release_owner(key, o);
            for (uint64_t o : h->flock_owners) locks_.flock_release(key, o);
        }
    }
    if (h->fd < 0) return 0;
    int rc = 0;
    if (h->writable) {
        struct stat st;
        bool have = fstat(h->fd, &st) == 0;
        close(h->fd);
        // The final size and mtime go into the ledger BEFORE the writer is released: until then no drop can freeze the file,
        // and afterwards the generation says "changed since any replication that raced the last writes".
        if (have && !ledger_.note_local_modified(h->file_id, static_cast<uint64_t>(st.st_size), st.st_mtimespec.tv_sec).ok) rc = -EIO;
        end_write(h->file_id);
    } else {
        close(h->fd);
    }
    return rc;
}

int Overlay::truncate(const std::string& path, uint64_t size) {
    uint64_t fh = 0;
    int r = open(path, O_WRONLY, &fh);
    if (r < 0) return r;
    int tr = ftruncate(fh, size);
    int rr = release(fh);
    return tr < 0 ? tr : rr;
}

// ---------------------------------------------------------------- hydration

int Overlay::hydrate(const std::string& path) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    return hydrate_logical(lp, op);
}

int Overlay::hydrate_logical(const std::string& lp, const std::string& op) {
    struct WakeWaiters { std::condition_variable& cv; ~WakeWaiters() { cv.notify_all(); } } wake{gate_cv_};   // writers may be waiting for HYDRATING to end
    auto f0 = ledger_.get_file_by_path(lp);
    if (!f0) { struct stat st; return lstat(op.c_str(), &st) == 0 ? 0 : -ENOENT; }
    std::shared_ptr<std::mutex> lock;
    {
        std::lock_guard<std::mutex> g(hyd_mu_);
        auto& slot = hyd_locks_[f0->file_id];
        if (!slot) slot = std::make_shared<std::mutex>();
        lock = slot;
    }
    std::lock_guard<std::mutex> one_at_a_time(*lock);

    // A drop in progress finishes in moments (the rename is done, the ledger's second step is pending): wait for it.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(cfg_.write_wait_ms);
    std::optional<FileRec> f;
    for (;;) {
        f = ledger_.get_file_by_path(lp);
        if (!f) return -ENOENT;
        if (f->state != FileState::DROPPING) break;
        if (std::chrono::steady_clock::now() > deadline) return -EBUSY;
        usleep(20000);
    }
    if (!is_remote_state(*f)) { struct stat st; return lstat(op.c_str(), &st) == 0 ? 0 : -ENOENT; }   // somebody else hydrated it
    if (f->state == FileState::HYDRATING) return -EBUSY;

    // 1. the quarantine copy, if it is still held: a local rename, verified against the replicated version, no network
    if (engine_ && (f->state == FileState::OFFLOADED || f->state == FileState::AT_RISK)) {
        std::string intent;
        for (const auto& q : ledger_.list_quarantine(QuarantineState::HELD))
            if (q.file_id == f->file_id && q.version == f->current_version) { intent = q.intent_id; break; }
        if (!intent.empty() && engine_mu_.try_lock()) {
            RestoreOutcome ro = engine_->restore(intent, "hydrate");
            engine_mu_.unlock();
            struct stat st;
            if (ro.ok && lstat(op.c_str(), &st) == 0) {
                // The quarantined bytes carry the attributes the file had when it was dropped; the user may have changed them
                // since (chmod/touch on a remote file only changes the ledger): the ledger's are the current ones.
                fchmodat(AT_FDCWD, op.c_str(), static_cast<mode_t>(f->mode & 07777), AT_SYMLINK_NOFOLLOW);
                struct timespec ts[2] = {{0, UTIME_OMIT}, {static_cast<time_t>(f->mtime), 0}};
                utimensat(AT_FDCWD, op.c_str(), ts, AT_SYMLINK_NOFOLLOW);
                std::lock_guard<std::mutex> g(cache_mu_);
                stats_.hydrations_quarantine++;
                return 0;
            }
        }
    }
    // 2. the devices
    return hydrate_from_network(*f, op);
}

int Overlay::hydrate_from_network(const FileRec& f, const std::string& op) {
    if (f.state != FileState::OFFLOADED) return -EIO;   // AT_RISK and the like: readable, but not something to build a writable file from
    if (!ledger_.begin_hydrate(f.file_id).ok) return -EBUSY;
    auto fail = [&](int err, const std::string& tmp) {
        if (!tmp.empty()) ::unlink(tmp.c_str());
        ledger_.abort_hydrate(f.file_id);
        return err;
    };
    std::vector<ChunkRec> chunks = ledger_.get_chunks(f.file_id, f.current_version);
    uint64_t total = 0;
    for (const auto& c : chunks) total += c.len;
    if (total != f.size) return fail(-EIO, "");
    std::vector<std::string> order = device_order(f);

    std::string tmpdir = cfg_.origin_dir + "/" + BOOKKEEPING + "/hydrate";
    std::string tmp = tmpdir + "/" + f.file_id + ".part";
    {   // mkdir -p
        std::string cur = cfg_.origin_dir;
        for (const char* part : {BOOKKEEPING, "hydrate"}) {
            cur += std::string("/") + part;
            if (::mkdir(cur.c_str(), 0700) != 0 && errno != EEXIST) return fail(-errno, "");
        }
    }
    ::unlink(tmp.c_str());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return fail(-errno, "");
    for (const auto& c : chunks) {
        auto plain = fetch_chunk(c, order);
        if (!plain) { close(fd); return fail(-EIO, tmp); }
        size_t off = 0;
        while (off < plain->size()) {
            ssize_t n = ::write(fd, plain->data() + off, plain->size() - off);
            if (n < 0) { if (errno == EINTR) continue; int e = errno; close(fd); return fail(-e, tmp); }
            off += static_cast<size_t>(n);
        }
    }
    fchmod(fd, static_cast<mode_t>(f.mode & 0777));
    struct timespec times[2] = {{0, UTIME_OMIT}, {static_cast<time_t>(f.mtime), 0}};
    futimens(fd, times);
    fsutil::full_sync(fd);
    close(fd);

    {   // the directory (never offloaded) should exist; recreate it if somebody removed it
        std::string rel = op.substr(cfg_.origin_dir.size());
        std::string cur = cfg_.origin_dir;
        size_t pos = 1;
        for (;;) {
            size_t slash = rel.find('/', pos);
            if (slash == std::string::npos) break;
            cur += "/" + rel.substr(pos, slash - pos);
            if (::mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) return fail(-errno, tmp);
            pos = slash + 1;
        }
    }
    crash_point("hydrate.before_rename");
    if (renamex_np(tmp.c_str(), op.c_str(), RENAME_EXCL) != 0) return fail(errno == EEXIST ? -EEXIST : -errno, tmp);
    fsutil::sync_dir(op.substr(0, op.rfind('/')));
    crash_point("hydrate.after_rename");
    if (!ledger_.complete_hydrate(f.file_id).ok) return -EIO;   // the bytes are in place; recover() reconciles the ledger
    std::lock_guard<std::mutex> g(cache_mu_);
    stats_.hydrations_network++;
    return 0;
}

OverlayRecovery Overlay::recover() {
    OverlayRecovery rep;
    for (const auto& f : ledger_.list_files(FileState::HYDRATING)) {
        if (f.path.compare(0, cfg_.logical_prefix.size(), cfg_.logical_prefix) != 0) continue;
        std::string op = cfg_.origin_dir + "/" + f.path.substr(cfg_.logical_prefix.size());
        std::string tmp = cfg_.origin_dir + "/" + BOOKKEEPING + "/hydrate/" + f.file_id + ".part";
        ::unlink(tmp.c_str());
        struct stat st;
        bool present = lstat(op.c_str(), &st) == 0 && S_ISREG(st.st_mode);
        bool same = false;
        if (present && static_cast<uint64_t>(st.st_size) == f.size) {
            // Is it the offloaded version, byte for byte? Every chunk's id must match the ledger's.
            int fd = ::open(op.c_str(), O_RDONLY | O_NOFOLLOW);
            if (fd >= 0) {
                same = true;
                uint64_t off = 0;
                for (const auto& c : ledger_.get_chunks(f.file_id, f.current_version)) {
                    crypto::Bytes buf(c.len);
                    size_t got = 0;
                    while (got < buf.size()) {
                        ssize_t n = pread(fd, buf.data() + got, buf.size() - got, static_cast<off_t>(off + got));
                        if (n < 0 && errno == EINTR) continue;
                        if (n <= 0) break;
                        got += static_cast<size_t>(n);
                    }
                    if (got != buf.size() || crypto::chunk_id(keys_, buf.data(), buf.size()) != c.chunk_id) { same = false; break; }
                    off += c.len;
                }
                close(fd);
            }
        }
        if (same) {
            if (ledger_.complete_hydrate(f.file_id).ok) rep.actions.push_back("finished the hydration of " + f.path + " (the verified file was already in place)");
            else rep.problems.push_back(f.path + ": the file is in place and verified, but the ledger would not complete the hydration");
        } else {
            ledger_.abort_hydrate(f.file_id);
            if (present) rep.problems.push_back(f.path + ": a different file is at this path; the file is OFFLOADED again (the local file shadows it); the version on the devices is untouched");
            else rep.actions.push_back("undid the interrupted hydration of " + f.path + " (it is OFFLOADED again)");
        }
    }
    // temp files of hydrations that never finished (nothing can be in progress before the first request)
    std::string dir = cfg_.origin_dir + "/" + BOOKKEEPING + "/hydrate";
    if (DIR* d = opendir(dir.c_str())) {
        std::vector<std::string> stray;
        while (struct dirent* e = ::readdir(d)) {
            std::string n = e->d_name;
            if (n.size() > 5 && n.compare(n.size() - 5, 5, ".part") == 0) stray.push_back(n);
        }
        closedir(d);
        for (const auto& n : stray) { ::unlink((dir + "/" + n).c_str()); rep.actions.push_back("removed the leftover temp file " + n); }
    }
    return rep;
}


// ---------------------------------------------------------------- the namespace

// Waits (bounded) until the file at `logical` is not frozen by a drop and not mid-drop/mid-hydration; returns its record (or none).
int Overlay::wait_idle(std::unique_lock<std::mutex>& g, const std::string& logical, std::optional<FileRec>* out) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(cfg_.write_wait_ms);
    for (;;) {
        auto f = ledger_.get_file_by_path(logical);
        if (!f) { *out = std::nullopt; return 0; }
        if (!(frozen_.count(f->file_id) || f->state == FileState::DROPPING || f->state == FileState::HYDRATING)) { *out = f; return 0; }
        if (gate_cv_.wait_until(g, deadline) == std::cv_status::timeout) return -EBUSY;
    }
}

int Overlay::mkdir(const std::string& path, uint32_t mode) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    if (rel.empty()) return -EEXIST;
    auto f = ledger_.get_file_by_path(lp);
    if (f && is_remote_state(*f)) return -EEXIST;   // the name is taken by a file whose bytes are on the devices
    return ::mkdir(op.c_str(), mode & 0777) == 0 ? 0 : -errno;
}

int Overlay::rmdir(const std::string& path) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    if (rel.empty()) return -EBUSY;
    std::lock_guard<std::mutex> g(gate_mu_);   // no drop can start freezing a file in the directory while we look
    for (const auto& f : ledger_.list_files_under(lp + "/")) {
        if (frozen_.count(f.file_id) || f.state == FileState::DROPPING) return -EBUSY;
        if (is_remote_state(f)) return -ENOTEMPTY;   // the directory is not empty: files are in it, their bytes are just elsewhere
    }
    return ::rmdir(op.c_str()) == 0 ? 0 : -errno;
}

int Overlay::unlink(const std::string& path) { return unlink_impl(path, 0); }

int Overlay::unlink_impl(const std::string& path, int depth) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    if (rel.empty()) return -EISDIR;
    struct stat st;
    if (lstat(op.c_str(), &st) == 0) {
        if (S_ISDIR(st.st_mode)) return -EISDIR;
        auto f = ledger_.get_file_by_path(lp);
        if (!S_ISREG(st.st_mode) || !f) return ::unlink(op.c_str()) == 0 ? 0 : -errno;
        std::string id;
        bool need = false;
        int r = begin_write(lp, op, &id, &need);   // waits for a drop in progress and keeps new ones away while we work
        if (r < 0) return r;
        if (need) return depth < 4 ? unlink_impl(path, depth + 1) : -EBUSY;   // it was dropped meanwhile: it is a remote file now
        int rc = ::unlink(op.c_str()) == 0 ? 0 : -errno;
        if (rc == 0) ledger_.retire_file(id, "unlinked");   // (if this fails the scanner finds the vanished file)
        end_write(id);
        return rc;
    }
    if (errno != ENOENT && errno != ENOTDIR) return -errno;
    std::unique_lock<std::mutex> g(gate_mu_);
    std::optional<FileRec> f;
    int wr = wait_idle(g, lp, &f);
    if (wr < 0) return wr;
    if (f && !is_remote_state(*f)) {   // it may have been hydrated while we waited: is it a local file now?
        struct stat again;
        g.unlock();
        if (lstat(op.c_str(), &again) == 0) return depth < 4 ? unlink_impl(path, depth + 1) : -EBUSY;
        return -ENOENT;                 // (a tracked file that is simply not there: nothing to delete)
    }
    if (!f) return -ENOENT;
    // a remote file: its bytes stay on the devices (append-only) and in quarantine until the policy purges them
    return ledger_.retire_file(f->file_id, "unlinked").ok ? 0 : -EBUSY;
}

int Overlay::rename(const std::string& from, const std::string& to) { return rename_impl(from, to, 0); }

int Overlay::rename_impl(const std::string& from, const std::string& to, int depth) {
    std::string fop, flp, frel, top, tlp, trel;
    if (!resolve(from, &fop, &flp, &frel) || !resolve(to, &top, &tlp, &trel)) return -ENOENT;
    if (frel.empty() || trel.empty()) return -EBUSY;
    OvStat probe;
    if (frel == trel) return getattr(from, &probe);
    if (trel.compare(0, frel.size() + 1, frel + "/") == 0) return -EINVAL;   // a directory into itself
    struct stat sst, dst;
    bool src_local = lstat(fop.c_str(), &sst) == 0;
    if (!src_local && errno != ENOENT && errno != ENOTDIR) return -errno;
    bool dst_local = lstat(top.c_str(), &dst) == 0;
    const bool dst_dir = dst_local && S_ISDIR(dst.st_mode);

    // ---- a directory: every tracked file under it moves with it, or none does
    if (src_local && S_ISDIR(sst.st_mode)) {
        std::unique_lock<std::mutex> g(gate_mu_);
        const std::string sprefix = flp + "/", dprefix = tlp + "/";
        // On a case-insensitive volume "Dir" -> "DIR" finds the directory itself at the destination: that is a rename, not a collision.
        const bool same_dir = dst_local && sst.st_dev == dst.st_dev && sst.st_ino == dst.st_ino;
        if (dst_local && !dst_dir) return -ENOTDIR;
        if (!same_dir) {
            auto d = ledger_.get_file_by_path(tlp);
            if (d && is_remote_state(*d)) return -ENOTDIR;
            for (const auto& f : ledger_.list_files_under(dprefix))
                if (is_remote_state(f)) return -ENOTEMPTY;
        }
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(cfg_.write_wait_ms);
        for (;;) {
            bool busy = false;
            for (const auto& f : ledger_.list_files_under(sprefix))
                if (frozen_.count(f.file_id) || f.state == FileState::DROPPING || f.state == FileState::HYDRATING) busy = true;
            if (!busy) break;
            if (gate_cv_.wait_until(g, deadline) == std::cv_status::timeout) return -EBUSY;
        }
        if (::rename(fop.c_str(), top.c_str()) != 0) return -errno;
        if (!ledger_.rename_prefix(sprefix, dprefix).ok) {
            ::rename(top.c_str(), fop.c_str());   // never leave the namespace half-renamed
            if (dst_dir && !same_dir) ::mkdir(top.c_str(), dst.st_mode & 07777);   // (the empty directory it replaced comes back too)
            return -EIO;
        }
        return 0;
    }

    // ---- a file (or a link), local or remote
    std::string src_id;
    bool registered = false;
    if (src_local) {
        if (dst_dir) return -EISDIR;
        if (S_ISREG(sst.st_mode) && ledger_.get_file_by_path(flp)) {
            bool need = false;
            int r = begin_write(flp, fop, &src_id, &need);   // waits for a drop in progress and keeps new ones away
            if (r < 0) return r;
            if (need) return depth < 4 ? rename_impl(from, to, depth + 1) : -EBUSY;   // it was dropped meanwhile: it is a remote file now
            registered = true;
        }
    }
    auto finish = [&](int rc) { if (registered) end_write(src_id); return rc; };
    std::unique_lock<std::mutex> g(gate_mu_);
    std::optional<FileRec> df;
    int wr = wait_idle(g, tlp, &df);
    if (wr < 0) { g.unlock(); return finish(wr); }

    if (!src_local) {   // a remote file: only the ledger changes (and a destination it replaces)
        std::optional<FileRec> rf;
        wr = wait_idle(g, flp, &rf);
        if (wr < 0) return wr;
        if (rf && !is_remote_state(*rf)) {   // it may have been hydrated while we waited: is it a local file now?
            struct stat again;
            if (lstat(fop.c_str(), &again) == 0 && depth < 4) { g.unlock(); return rename_impl(from, to, depth + 1); }
            return -ENOENT;
        }
        if (!rf || !is_remote_state(*rf)) return -ENOENT;
        if (dst_dir) return -EISDIR;
        struct stat ps;
        std::string parent = top.substr(0, top.rfind('/'));
        if (stat(parent.c_str(), &ps) != 0) return -errno;
        if (!S_ISDIR(ps.st_mode)) return -ENOTDIR;
        if (df && df->file_id != rf->file_id && !ledger_.retire_file(df->file_id, "replaced by a rename").ok) return -EBUSY;   // (a case-only rename finds itself)
        if (dst_local && ::unlink(top.c_str()) != 0) return -errno;
        return ledger_.rename_file(rf->file_id, tlp).ok ? 0 : -EIO;
    }
    if (::rename(fop.c_str(), top.c_str()) != 0) { int e = errno; g.unlock(); return finish(-e); }
    if (df && df->file_id != src_id) ledger_.retire_file(df->file_id, "replaced by a rename");
    if (!src_id.empty()) ledger_.rename_file(src_id, tlp);   // (a failure leaves it to the scanner: the bytes are where the user put them)
    g.unlock();
    return finish(0);
}

// ---------------------------------------------------------------- hard links and advisory locks (ADR-0011)

int Overlay::link(const std::string& from, const std::string& to) {
    for (int attempt = 0; attempt < 4; attempt++) {
        std::string sop, slp, srel, dop, dlp, drel;
        if (!resolve(from, &sop, &slp, &srel) || !resolve(to, &dop, &dlp, &drel)) return -ENOENT;
        if (srel.empty() || drel.empty()) return -EPERM;
        struct stat st;
        bool local = lstat(sop.c_str(), &st) == 0;
        if (!local && errno != ENOENT && errno != ENOTDIR) return -errno;
        if (local && !S_ISREG(st.st_mode)) return -EPERM;  // directories and symlinks do not get hard links
        if (!local) {
            auto f = ledger_.get_file_by_path(slp);
            if (!f || !is_remote_state(*f)) return -ENOENT;
            int hr = hydrate_logical(slp, sop);  // the bytes come back first: a name without bytes behind it cannot be a second name for them
            if (hr < 0) return hr;
            continue;
        }
        struct stat dst;
        if (lstat(dop.c_str(), &dst) == 0) return -EEXIST;
        auto df = ledger_.get_file_by_path(dlp);
        if (df && is_remote_state(*df)) return -EEXIST;
        // While the second name is being made nobody may drop the first (a drop would move the shared bytes into quarantine).
        std::string id;
        bool need = false;
        if (ledger_.get_file_by_path(slp)) {  // (a file the ledger does not know yet cannot be dropped)
            int r = begin_write(slp, sop, &id, &need, false);
            if (r < 0) return r;
            if (need) continue;  // it was dropped meanwhile: it is remote now, bring it back and look again
        }
        int rc = ::link(sop.c_str(), dop.c_str()) == 0 ? 0 : -errno;
        if (rc == 0) {
            struct stat now;
            if (lstat(dop.c_str(), &now) == 0) {
                if (df)
                    ledger_.note_local_modified(df->file_id, static_cast<uint64_t>(now.st_size),
                                                now.st_mtimespec.tv_sec);  // (a stale entry for the name)
                else
                    ledger_.track_file(dlp, static_cast<uint64_t>(now.st_size), now.st_mtimespec.tv_sec,
                                       now.st_mode & 0777);  // (else the scanner finds it)
            }
        }
        if (!id.empty()) end_write(id);
        return rc;
    }
    return -EIO;
}

std::string Overlay::lock_key(Handle& h) {
    if (!h.file_id.empty()) return "f:" + h.file_id;
    struct stat st;
    if (h.fd >= 0 && fstat(h.fd, &st) == 0)
        return "i:" + std::to_string(static_cast<long long>(st.st_dev)) + ":" + std::to_string(static_cast<unsigned long long>(st.st_ino));
    return "h:" + std::to_string(reinterpret_cast<uintptr_t>(&h));  // (no identity at all: a private key, so nothing conflicts)
}

int Overlay::getlk(uint64_t fh, uint64_t owner, LockInfo* lk) {
    auto h = get_handle(fh);
    if (!h || !lk) return -EBADF;
    LockInfo blocking;
    if (locks_.test(lock_key(*h), owner, LockRange{lk->type, lk->start, lk->len}, &blocking))
        *lk = blocking;
    else
        lk->type = LockType::Unlock;
    return 0;
}

int Overlay::setlk(uint64_t fh, uint64_t owner, const LockRange& lk) {
    auto h = get_handle(fh);
    if (!h) return -EBADF;
    std::string key = lock_key(*h);
    if (!locks_.set(key, owner, lk)) return -EAGAIN;
    if (lk.type != LockType::Unlock) {
        std::lock_guard<std::mutex> g(h->lmu);
        h->range_owners.insert(owner);
    }
    return 0;
}

int Overlay::flock_op(uint64_t fh, uint64_t owner, LockType type) {
    auto h = get_handle(fh);
    if (!h) return -EBADF;
    std::string key = lock_key(*h);
    if (!locks_.flock_try(key, owner, type)) return -EAGAIN;
    if (type != LockType::Unlock) {
        std::lock_guard<std::mutex> g(h->lmu);
        h->flock_owners.insert(owner);
    }
    return 0;
}

int Overlay::unlock_owner(uint64_t fh, uint64_t owner) {
    auto h = get_handle(fh);
    if (!h) return -EBADF;
    locks_.release_owner(lock_key(*h), owner);
    std::lock_guard<std::mutex> g(h->lmu);
    h->range_owners.erase(owner);
    return 0;
}

int Overlay::symlink(const std::string& target, const std::string& linkpath) {
    std::string op, lp, rel;
    if (!resolve(linkpath, &op, &lp, &rel)) return -ENOENT;
    if (rel.empty()) return -EEXIST;
    auto f = ledger_.get_file_by_path(lp);
    if (f && is_remote_state(*f)) return -EEXIST;
    return ::symlink(target.c_str(), op.c_str()) == 0 ? 0 : -errno;
}

// An attribute change on the file at `path`: applied to the origin (when there is a file there) and recorded in the ledger,
// with the writer registered so no drop can move the file meanwhile; a remote file changes only in the ledger.
int Overlay::attr_change(const std::string& path, const std::function<int(const std::string&, bool)>& apply,
                         std::optional<uint32_t> mode, std::optional<int64_t> mtime, int depth) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    struct stat st;
    if (lstat(op.c_str(), &st) == 0) {
        if (!S_ISREG(st.st_mode)) return apply(op, S_ISDIR(st.st_mode));
        auto f = ledger_.get_file_by_path(lp);
        if (!f) return apply(op, false);
        std::string id;
        bool need = false;
        int r = begin_write(lp, op, &id, &need);
        if (r < 0) return r;
        if (need) return depth < 4 ? attr_change(path, apply, mode, mtime, depth + 1) : -EBUSY;
        int rc = apply(op, false);
        if (rc == 0) ledger_.note_attrs_changed(id, mode, mtime);
        end_write(id);
        return rc;
    }
    if (errno != ENOENT && errno != ENOTDIR) return -errno;
    if (rel.empty()) return -ENOENT;
    std::unique_lock<std::mutex> g(gate_mu_);
    std::optional<FileRec> f;
    int wr = wait_idle(g, lp, &f);
    if (wr < 0) return wr;
    if (f && !is_remote_state(*f)) {   // it may have been hydrated while we waited: is it a local file now?
        struct stat again;
        if (lstat(op.c_str(), &again) == 0 && depth < 4) { g.unlock(); return attr_change(path, apply, mode, mtime, depth + 1); }
        return -ENOENT;
    }
    if (!f || !is_remote_state(*f)) return -ENOENT;
    return ledger_.note_attrs_changed(f->file_id, mode, mtime).ok ? 0 : -EBUSY;
}

int Overlay::chmod(const std::string& path, uint32_t mode) {
    return attr_change(path, [&](const std::string& op, bool) { return fchmodat(AT_FDCWD, op.c_str(), static_cast<mode_t>(mode & 07777), AT_SYMLINK_NOFOLLOW) == 0 ? 0 : -errno; },
                       mode, std::nullopt);
}

int Overlay::utimens(const std::string& path, std::optional<int64_t> mtime) {
    if (!mtime) { OvStat st; return getattr(path, &st); }
    return attr_change(path, [&](const std::string& op, bool) {
        struct timespec ts[2] = {{0, UTIME_OMIT}, {static_cast<time_t>(*mtime), 0}};
        return utimensat(AT_FDCWD, op.c_str(), ts, AT_SYMLINK_NOFOLLOW) == 0 ? 0 : -errno;
    }, std::nullopt, mtime);
}

int Overlay::chown(const std::string& path, int64_t uid, int64_t gid) {
    OvStat st;
    int r = getattr(path, &st);
    if (r < 0) return r;
    if ((uid != -1 && uid != static_cast<int64_t>(getuid())) || (gid != -1 && gid != static_cast<int64_t>(getgid()))) return -EPERM;
    return 0;   // everything here belongs to you already
}

int Overlay::statfs(FsStats* out) {
    struct statvfs sv;
    if (::statvfs(cfg_.origin_dir.c_str(), &sv) != 0) return -errno;
    if (out) {
        out->block_size = sv.f_frsize ? sv.f_frsize : sv.f_bsize;
        out->blocks = sv.f_blocks;
        out->blocks_free = sv.f_bfree;
        out->blocks_avail = sv.f_bavail;
        out->files = sv.f_files;
        out->files_free = sv.f_ffree;
    }
    return 0;
}

// ---- extended attributes

int Overlay::remote_xattrs(const FileRec& f, std::vector<std::pair<std::string, crypto::Bytes>>* out) {
    std::string key = f.file_id + ":" + std::to_string(f.current_version);
    {
        std::lock_guard<std::mutex> g(xattr_mu_);
        auto it = xattr_cache_.find(key);
        if (it != xattr_cache_.end()) { *out = it->second; return 0; }
    }
    for (const auto& id : device_order(f)) {
        crypto::Bytes blob;
        DeviceClient* client = client_for(id);
        if (!client || !client->get_manifest(f.file_id, f.current_version, blob).ok()) continue;
        crypto::Manifest m;
        if (crypto::open_manifest(keys_, volume_, f.file_id, f.current_version, blob.data(), blob.size(), m) != crypto::OpenError::Ok) continue;
        std::lock_guard<std::mutex> g(xattr_mu_);
        xattr_cache_[key] = m.xattrs;
        *out = m.xattrs;
        return 0;
    }
    return -EIO;
}

int64_t Overlay::getxattr(const std::string& path, const std::string& name, uint8_t* buf, size_t size) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    struct stat st;
    if (lstat(op.c_str(), &st) == 0) {
        ssize_t n = ::getxattr(op.c_str(), name.c_str(), buf, size, 0, XATTR_NOFOLLOW);
        return n < 0 ? -errno : n;
    }
    if (errno != ENOENT && errno != ENOTDIR) return -errno;
    auto f = ledger_.get_file_by_path(lp);
    if (rel.empty() || !f || !is_remote_state(*f)) return -ENOENT;
    std::vector<std::pair<std::string, crypto::Bytes>> xs;
    int r = remote_xattrs(*f, &xs);
    if (r < 0) return r;
    for (const auto& x : xs) {
        if (x.first != name) continue;
        if (size == 0) return static_cast<int64_t>(x.second.size());
        if (size < x.second.size()) return -ERANGE;
        memcpy(buf, x.second.data(), x.second.size());
        return static_cast<int64_t>(x.second.size());
    }
    return -ENOATTR;
}

int64_t Overlay::listxattr(const std::string& path, char* buf, size_t size) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    struct stat st;
    if (lstat(op.c_str(), &st) == 0) {
        ssize_t n = ::listxattr(op.c_str(), buf, size, XATTR_NOFOLLOW);
        return n < 0 ? -errno : n;
    }
    if (errno != ENOENT && errno != ENOTDIR) return -errno;
    auto f = ledger_.get_file_by_path(lp);
    if (rel.empty() || !f || !is_remote_state(*f)) return -ENOENT;
    std::vector<std::pair<std::string, crypto::Bytes>> xs;
    int r = remote_xattrs(*f, &xs);
    if (r < 0) return r;
    size_t need = 0;
    for (const auto& x : xs) need += x.first.size() + 1;
    if (size == 0) return static_cast<int64_t>(need);
    if (size < need) return -ERANGE;
    size_t off = 0;
    for (const auto& x : xs) { memcpy(buf + off, x.first.c_str(), x.first.size() + 1); off += x.first.size() + 1; }
    return static_cast<int64_t>(need);
}

namespace {
// Changing an attribute of a remote file needs the file: hydrate it, then it is an ordinary local change.
}

int Overlay::setxattr(const std::string& path, const std::string& name, const uint8_t* value, size_t size, int flags) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    struct stat st;
    if (lstat(op.c_str(), &st) != 0) {
        if (errno != ENOENT && errno != ENOTDIR) return -errno;
        int hr = hydrate_logical(lp, op);
        if (hr < 0) return hr;
    }
    return attr_change(path, [&](const std::string& p, bool) { return ::setxattr(p.c_str(), name.c_str(), value, size, 0, flags | XATTR_NOFOLLOW) == 0 ? 0 : -errno; },
                       std::nullopt, std::nullopt);
}

int Overlay::removexattr(const std::string& path, const std::string& name) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel)) return -ENOENT;
    struct stat st;
    if (lstat(op.c_str(), &st) != 0) {
        if (errno != ENOENT && errno != ENOTDIR) return -errno;
        int hr = hydrate_logical(lp, op);
        if (hr < 0) return hr;
    }
    return attr_change(path, [&](const std::string& p, bool) { return ::removexattr(p.c_str(), name.c_str(), XATTR_NOFOLLOW) == 0 ? 0 : -errno; },
                       std::nullopt, std::nullopt);
}

int Overlay::undelete(const std::string& path) {
    std::string op, lp, rel;
    if (!resolve(path, &op, &lp, &rel) || rel.empty()) return -ENOENT;
    struct stat st;
    if (lstat(op.c_str(), &st) == 0) return -EEXIST;
    if (ledger_.get_file_by_path(lp)) return -EEXIST;
    for (const auto& f : ledger_.list_retired()) {
        if (ledger_.fold_path(Ledger::former_path(f)) != ledger_.fold_path(lp)) continue;
        if (!ledger_.undelete_file(f.file_id).ok) return -EINVAL;
        // The name is back without anything in the origin changing, so the directory's modification time did not move, and the
        // kernel (which caches names the way an NFS client does) would keep answering "no such file". Moving it makes it look again.
        utimensat(AT_FDCWD, op.substr(0, op.rfind('/')).c_str(), nullptr, 0);
        return 0;
    }
    return -ENOENT;
}

}  // namespace tierfs
