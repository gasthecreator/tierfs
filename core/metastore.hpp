// Persistent metadata cache backed by SQLite.
//
// Holds what the client has learned about the remote tree (attributes and
// directory listings) so that `ls`, `stat` and Finder keep working when the
// backend is unreachable, even right after a fresh mount.
//
// IMPORTANT: this is a CACHE. Losing it costs a re-fetch, nothing more, so a
// corrupt or incompatible database is simply discarded and rebuilt. When
// Phase 3 starts offloading files, "this file's only copy is on the device" is
// NOT cache data and must live in a separate durable store.
//
// Not thread-safe by itself; the client calls it under its own mutex.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "tierclient.h"

struct sqlite3;

namespace tierfs {

class MetaStore {
public:
    using DirList = std::vector<std::pair<std::string, tc_attr>>;

    // db_path may be ":memory:". If the file is corrupt or has an unknown
    // schema version it is deleted and recreated (see recovered()).
    explicit MetaStore(const std::string& db_path);
    ~MetaStore();
    MetaStore(const MetaStore&) = delete;
    MetaStore& operator=(const MetaStore&) = delete;

    // False if the database could not be opened at all; every method then
    // does nothing and reports a miss, so callers just run without a cache.
    bool ok() const { return db_ != nullptr; }
    bool recovered() const { return recovered_; }

    void put_attr(const std::string& path, const tc_attr& a);
    bool get_attr(const std::string& path, tc_attr& out);

    // Replace the complete listing of `dir`. Children that disappeared are
    // forgotten together with everything beneath them.
    void put_dir(const std::string& dir, const DirList& entries);
    // False if `dir` has never been listed completely.
    bool get_dir(const std::string& dir, DirList& out);

    // Remove `path` and everything below it, and its entry in the parent listing.
    void forget(const std::string& path);

    // Record an access (for the Phase 3 tiering policy). Writes at most once
    // per minute per path so read-heavy workloads do not hammer the disk.
    void touch(const std::string& path, int64_t now);
    int64_t last_access(const std::string& path);  // 0 = never / unknown

private:
    bool open_and_init(const std::string& path);
    bool exec(const char* sql);
    void forget_inner(const std::string& path);
    void upsert_attr(const std::string& path, const tc_attr& a);

    sqlite3* db_ = nullptr;
    bool recovered_ = false;
};

}  // namespace tierfs
