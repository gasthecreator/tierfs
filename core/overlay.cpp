#include "overlay.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <set>

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

Overlay::Overlay(Ledger& ledger, const crypto::Keys& keys, DeviceMap devices, OverlayConfig cfg)
    : ledger_(ledger), keys_(keys), devices_(std::move(devices)), cfg_(std::move(cfg)) {
    while (cfg_.origin_dir.size() > 1 && cfg_.origin_dir.back() == '/') cfg_.origin_dir.pop_back();
    if (!cfg_.logical_prefix.empty() && cfg_.logical_prefix.back() != '/') cfg_.logical_prefix += '/';
    volume_ = ledger_.volume_id();
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
        s.mode = st.st_mode & 0777;
        if (s.kind == OvKind::File) {
            std::lock_guard<std::mutex> g(ledger_mu_);
            if (auto f = ledger_.get_file_by_path(lp)) s.file_id = f->file_id;
        }
        if (out) *out = s;
        return 0;
    }
    if (errno != ENOENT && errno != ENOTDIR) return -errno;
    if (rel.empty()) return -ENOENT;
    std::lock_guard<std::mutex> g(ledger_mu_);
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
        seen.insert(name);
        entries.push_back(std::move(oe));
    }
    closedir(d);

    std::string dirprefix = lp.empty() || lp.back() == '/' ? lp : lp + "/";
    std::vector<FileRec> under;
    {
        std::lock_guard<std::mutex> g(ledger_mu_);
        under = ledger_.list_files_under(dirprefix);
    }
    for (const auto& f : under) {
        std::string name = f.path.substr(dirprefix.size());
        if (name.empty() || name.find('/') != std::string::npos) continue;   // deeper: belongs to a subdirectory's listing
        if (!is_remote_state(f) || seen.count(name)) continue;
        OvEntry oe;
        oe.name = name;
        oe.kind = OvKind::File;
        oe.remote = true;
        seen.insert(name);
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
        std::lock_guard<std::mutex> g(ledger_mu_);
        f = ledger_.get_file_by_path(lp);
    }
    if (!f || !is_remote_state(*f)) return -ENOENT;
    return read_remote(*f, offset, size, buf);
}

std::vector<std::string> Overlay::device_order(const FileRec& f) {
    std::vector<std::string> order;
    std::set<std::string> have;
    std::lock_guard<std::mutex> g(ledger_mu_);
    auto usable = [&](const std::string& id) {
        if (!devices_.count(id) || !devices_[id]) return false;
        auto d = ledger_.get_device(id);
        return d && d->state != "retired";
    };
    for (const auto& r : ledger_.get_replicas(f.file_id, f.current_version))
        if (r.state == ReplicaState::COMMITTED && usable(r.device_id) && have.insert(r.device_id).second) order.push_back(r.device_id);
    for (const auto& kv : devices_)
        if (usable(kv.first) && have.insert(kv.first).second) order.push_back(kv.first);
    return order;
}

std::shared_ptr<const crypto::Bytes> Overlay::fetch_chunk(const ChunkRec& c, const std::vector<std::string>& order) {
    {
        std::lock_guard<std::mutex> g(cache_mu_);
        auto it = cache_.find(c.chunk_id);
        if (it != cache_.end()) {
            lru_.splice(lru_.begin(), lru_, it->second.it);
            stats_.cache_hits++;
            return it->second.data;
        }
    }
    for (const auto& id : order) {
        crypto::Bytes blob, plain;
        {
            std::lock_guard<std::mutex> g(cache_mu_);
            stats_.chunk_fetches++;
        }
        DevRes r = devices_[id]->get_chunk(c.chunk_id, blob);
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
        std::lock_guard<std::mutex> g(ledger_mu_);
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
    return static_cast<int64_t>(done);
}

}  // namespace tierfs
