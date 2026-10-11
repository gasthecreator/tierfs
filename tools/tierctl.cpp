// tierctl: inspect, verify and clear a tierfs cache directory.
//
//   tierctl cache-info   <dir>          read-only; safe while mounted
//   tierctl cache-verify <dir>          re-hash every chunk, drop damaged ones (needs unmounted)
//   tierctl cache-clear  <dir> [--yes]  delete the caches (needs unmounted); dry run without --yes
//
// cache-clear only ever removes the files tierfs itself creates (chunks/,
// chunks.db*, meta.db*), never "everything in the directory", so pointing it at
// the wrong folder cannot delete anything else.
#include <fcntl.h>
#include <sqlite3.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

#include "../core/chunkcache.hpp"

namespace fs = std::filesystem;

static uint64_t dir_bytes(const fs::path& p) {
    uint64_t n = 0;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(p, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec))
        if (it->is_regular_file(ec)) n += it->file_size(ec);
    return n;
}

// Opens read-only so it never runs crash-recovery against a live mount.
static bool query_one(const std::string& db, const char* sql, long long& a, long long& b, long long& c) {
    sqlite3* h = nullptr;
    if (sqlite3_open_v2(db.c_str(), &h, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) { if (h) sqlite3_close(h); return false; }
    sqlite3_stmt* s = nullptr;
    bool ok = false;
    if (sqlite3_prepare_v2(h, sql, -1, &s, nullptr) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW) {
        a = sqlite3_column_int64(s, 0);
        b = sqlite3_column_int64(s, 1);
        c = sqlite3_column_int64(s, 2);
        ok = true;
    }
    if (s) sqlite3_finalize(s);
    sqlite3_close(h);
    return ok;
}

// Takes the exclusive lock tierfs holds while mounted. 0 = got it (fd returned).
static int lock_exclusive(const std::string& dir, int& fd) {
    fd = open((dir + "/lock").c_str(), O_CREAT | O_RDWR, 0600);
    if (fd < 0) { perror("lock"); return -1; }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        fprintf(stderr, "tierctl: %s is in use by a running tierfs mount; unmount it first\n", dir.c_str());
        close(fd);
        return -1;
    }
    return 0;
}

static std::string human(uint64_t b) {
    char buf[32];
    if (b >= (1u << 30)) snprintf(buf, sizeof buf, "%.2f GiB", b / double(1u << 30));
    else if (b >= (1u << 20)) snprintf(buf, sizeof buf, "%.1f MiB", b / double(1u << 20));
    else snprintf(buf, sizeof buf, "%llu B", (unsigned long long)b);
    return buf;
}

static bool looks_like_cache(const std::string& dir) {
    return fs::exists(dir + "/chunks.db") || fs::exists(dir + "/meta.db") || fs::exists(dir + "/chunks");
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s cache-info|cache-verify|cache-clear <cache-dir> [--yes]\n", argv[0]);
        return 2;
    }
    std::string cmd = argv[1], dir = argv[2];
    if (!fs::is_directory(dir)) { fprintf(stderr, "tierctl: %s is not a directory\n", dir.c_str()); return 1; }
    if (!looks_like_cache(dir)) { fprintf(stderr, "tierctl: %s does not look like a tierfs cache\n", dir.c_str()); return 1; }

    if (cmd == "cache-info") {
        int fd;
        bool in_use = lock_exclusive(dir, fd) != 0;
        if (!in_use) close(fd);
        // lock_exclusive printed an error when busy; for info that is just a status.
        long long chunks = 0, bytes = 0, files = 0, attrs = 0, dirs = 0, unused = 0;
        query_one(dir + "/chunks.db", "SELECT COUNT(*), COALESCE(SUM(len),0), COUNT(DISTINCT path) FROM chunks", chunks, bytes, files);
        query_one(dir + "/meta.db", "SELECT (SELECT COUNT(*) FROM attrs), (SELECT COUNT(*) FROM dirs), 0", attrs, dirs, unused);
        printf("cache:     %s\nstatus:    %s\n", dir.c_str(), in_use ? "IN USE by a running mount" : "idle");
        printf("data:      %lld chunks, %s, %lld files\n", chunks, human((uint64_t)bytes).c_str(), files);
        printf("metadata:  %lld entries, %lld listings\n", attrs, dirs);
        printf("on disk:   %s total\n", human(dir_bytes(dir)).c_str());
        return 0;
    }
    if (cmd == "cache-verify") {
        int fd;
        if (lock_exclusive(dir, fd) != 0) return 1;
        tierfs::ChunkCache c(dir, ~0ull);
        if (!c.ok()) { fprintf(stderr, "tierctl: chunk cache unreadable (it will be rebuilt on next mount)\n"); close(fd); return 1; }
        uint64_t bad = 0, checked = c.verify_all(&bad);
        printf("checked %llu chunks: %llu damaged%s\n", (unsigned long long)checked, (unsigned long long)bad,
               bad ? " (removed; they will be refetched)" : "");
        close(fd);
        return bad ? 3 : 0;
    }
    if (cmd == "cache-clear") {
        bool yes = argc > 3 && strcmp(argv[3], "--yes") == 0;
        int fd;
        if (lock_exclusive(dir, fd) != 0) return 1;
        const char* names[] = {"chunks", "chunks.db", "chunks.db-wal", "chunks.db-shm", "meta.db", "meta.db-wal", "meta.db-shm"};
        uint64_t total = 0;
        for (const char* n : names) {
            fs::path p = fs::path(dir) / n;
            std::error_code ec;
            if (!fs::exists(p, ec)) continue;
            uint64_t sz = fs::is_directory(p, ec) ? dir_bytes(p) : fs::file_size(p, ec);
            total += sz;
            printf("%s %s (%s)\n", yes ? "removing" : "would remove", p.c_str(), human(sz).c_str());
            if (yes) fs::remove_all(p, ec);
        }
        printf("%s %s%s\n", yes ? "freed" : "would free", human(total).c_str(), yes ? "" : "  (re-run with --yes)");
        close(fd);
        return 0;
    }
    fprintf(stderr, "tierctl: unknown command %s\n", cmd.c_str());
    return 2;
}
