// On-disk cache of file data in fixed-size chunks.
//
//   <dir>/chunks.db            SQLite index: which chunks exist, sizes, hashes, LRU order
//   <dir>/chunks/ab/<hex>.chk  one file per chunk (raw bytes)
//
// A chunk is identified by (path, file size, file mtime, chunk index). The size
// and mtime are part of the key, so once the remote file changes, chunks of the
// old version can never be returned for the new one.
//
// Every chunk's SHA-256 is stored in the index and checked on each read. A
// chunk that fails the check (bit rot, a torn write after a crash) is deleted
// and reported as a miss, so the caller refetches from the device, or, when the
// device is offline, reports an I/O error instead of returning corrupt bytes.
//
// Like MetaStore this is a CACHE: it may be deleted at any time. It must never
// hold the only copy of anything (Phase 3's offloaded data is a separate store).
//
// Thread-safe.
#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3;

namespace tierfs {

constexpr uint32_t CHUNK_SIZE = 1u << 20;  // equals MAX_READ: one chunk per request

struct ChunkKey {
    std::string path;
    uint64_t size;   // file size this chunk belongs to
    int64_t mtime;   // file mtime this chunk belongs to
    uint32_t idx;    // chunk number: bytes [idx*CHUNK_SIZE, (idx+1)*CHUNK_SIZE)
};

struct ChunkStats {
    uint64_t hits = 0, misses = 0, puts = 0, evicted = 0, corrupt = 0;
};

class ChunkCache {
public:
    // budget_bytes: soft limit; eviction runs after each put. Chunks whose path
    // is pinned are never evicted, so the cache can exceed the budget while
    // many files are open.
    ChunkCache(const std::string& dir, uint64_t budget_bytes);
    ~ChunkCache();
    ChunkCache(const ChunkCache&) = delete;
    ChunkCache& operator=(const ChunkCache&) = delete;

    bool ok() const { return db_ != nullptr; }  // false: disabled (all misses, puts ignored)

    // Verified read. False = miss (including "was corrupt, now deleted").
    bool get(const ChunkKey& k, std::vector<uint8_t>& out);
    // Index-only check (no disk read, no verification): used to skip prefetches.
    bool has(const ChunkKey& k);
    void put(const ChunkKey& k, const uint8_t* data, size_t len);

    void invalidate_path(const std::string& path);  // all versions of one file
    void invalidate_tree(const std::string& path);  // path and everything below

    // Called with the cache lock held; must not call back into the cache.
    void set_pin_check(std::function<bool(const std::string&)> f);

    uint64_t bytes_used();
    ChunkStats stats();

private:
    std::string chunk_path(const std::string& hexkey) const;
    void remove_row_and_file(const std::string& hexkey, uint64_t len);  // lock held
    void evict_locked();
    bool open_and_init();
    void sweep();

    std::string dir_;
    uint64_t budget_;
    sqlite3* db_ = nullptr;
    std::mutex mu_;
    uint64_t bytes_ = 0;
    int64_t tick_ = 0;  // logical clock for LRU order
    ChunkStats st_;
    std::function<bool(const std::string&)> pinned_;
};

}  // namespace tierfs
