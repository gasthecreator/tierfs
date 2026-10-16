// Durable filesystem operations, in one place so their ordering is easy to audit.
//
// On macOS fsync() does NOT force the drive to flush its cache; F_FULLFSYNC does. A rename is atomic
// within a volume, but it only survives a power cut once the DIRECTORIES involved are synced too.
#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace tierfs {
namespace fsutil {

// Flushes a file to the drive, strictly: 0 on success, nonzero if it could not be done. (macOS: F_FULLFSYNC; elsewhere fsync() is the full flush.)
inline int strict_full_sync(int fd) {
#ifdef F_FULLFSYNC
    return fcntl(fd, F_FULLFSYNC) == -1 ? -1 : 0;
#else
    return fsync(fd);
#endif
}

inline void full_sync(int fd) {
    if (strict_full_sync(fd) != 0) fsync(fd);
}

inline void sync_dir(const std::string& path) {
    int fd = ::open(path.empty() ? "." : path.c_str(), O_RDONLY);
    if (fd >= 0) {
        full_sync(fd);
        close(fd);
    }
}

inline std::string parent_of(const std::string& p) {
    std::string par = std::filesystem::path(p).parent_path().string();
    return par.empty() ? "." : par;
}

// mkdir -p, where every directory created is itself made durable. 0 or errno.
inline int make_dir_durable(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) return S_ISDIR(st.st_mode) ? 0 : ENOTDIR;
    std::string parent = parent_of(path);
    if (parent != path && parent != ".") {
        int rc = make_dir_durable(parent);
        if (rc) return rc;
    }
    if (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) return errno;
    sync_dir(parent);
    return 0;
}

// Writes `data` so that afterwards `path` holds exactly it, or is untouched: temp file in the same
// directory, full fsync, rename, directory sync. 0 or errno.
inline int durable_write(const std::string& path, const std::string& data) {
    std::string tmp = path + ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return errno;
    size_t off = 0;
    int err = 0;
    while (off < data.size()) {
        ssize_t w = ::write(fd, data.data() + off, data.size() - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { err = errno ? errno : EIO; break; }
        off += static_cast<size_t>(w);
    }
    if (!err) full_sync(fd);
    close(fd);
    if (!err && rename(tmp.c_str(), path.c_str()) != 0) err = errno;
    if (!err) sync_dir(parent_of(path));
    if (err) unlink(tmp.c_str());
    return err;
}

inline bool is_regular_nofollow(const std::string& path, struct stat* st = nullptr) {
    struct stat s;
    if (lstat(path.c_str(), &s) != 0 || !S_ISREG(s.st_mode)) return false;
    if (st) *st = s;
    return true;
}

inline bool exists_nofollow(const std::string& path) {
    struct stat s;
    return lstat(path.c_str(), &s) == 0;
}

}  // namespace fsutil
}  // namespace tierfs
