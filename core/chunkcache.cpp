#include "chunkcache.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <set>

#include "hash.hpp"
#include "sqlutil.hpp"

namespace tierfs {
namespace {

using sql::Stmt;
using sql::Txn;

constexpr int SCHEMA_VERSION = 1;
constexpr size_t MAX_CHUNK_LEN = 8u << 20;  // sanity bound for anything we read back

std::atomic<uint64_t> g_tmp_counter{0};

// The key is derived from every field that defines the chunk's contents, with
// NUL separators so ("a", 1, ...) and ("a1", ...) cannot collide.
std::string key_hex(const ChunkKey& k) {
    std::string s = k.path;
    s += '\0';
    s += std::to_string(k.mtime);
    s += '\0';
    s += std::to_string(k.size);
    s += '\0';
    s += std::to_string(k.idx);
    return sha256_hex(s.data(), s.size());
}

bool write_all(int fd, const uint8_t* p, size_t n) {
    while (n) {
        ssize_t w = ::write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

// 1 = read `want` bytes, 0 = file missing, -1 = unreadable / wrong size.
int read_exact(const std::string& path, size_t want, std::vector<uint8_t>& out) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || static_cast<uint64_t>(st.st_size) != want || want > MAX_CHUNK_LEN) {
        close(fd);
        return -1;
    }
    out.resize(want);
    size_t got = 0;
    while (got < want) {
        ssize_t r = ::read(fd, out.data() + got, want - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { close(fd); return -1; }
        got += static_cast<size_t>(r);
    }
    close(fd);
    return 1;
}

}  // namespace

ChunkCache::ChunkCache(const std::string& dir, uint64_t budget_bytes)
    : dir_(dir), budget_(budget_bytes) {
    std::error_code ec;
    std::filesystem::create_directories(dir_ + "/chunks", ec);
    if (ec) return;  // stays disabled
    if (!open_and_init()) {
        // Unusable index: it is only a cache, so wipe everything and retry once.
        std::filesystem::remove_all(dir_ + "/chunks", ec);
        for (const char* suffix : {"", "-wal", "-shm"})
            unlink((dir_ + "/chunks.db" + suffix).c_str());
        std::filesystem::create_directories(dir_ + "/chunks", ec);
        open_and_init();
    }
    if (db_) sweep();
}

ChunkCache::~ChunkCache() {
    if (db_) sqlite3_close(db_);
}

bool ChunkCache::open_and_init() {
    std::string path = dir_ + "/chunks.db";
    if (sqlite3_open_v2(path.c_str(), &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK) {
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
        return false;
    }
    sqlite3_busy_timeout(db_, 2000);
    bool good = true;
    int version = -1;
    {
        Stmt v(db_, "PRAGMA user_version");
        if (v.row()) version = static_cast<int>(v.col_num(0));
    }
    if (version != 0 && version != SCHEMA_VERSION) good = false;
    auto exec = [&](const char* q) { return sqlite3_exec(db_, q, nullptr, nullptr, nullptr) == SQLITE_OK; };
    if (good) {
        good = exec("PRAGMA journal_mode=WAL") && exec("PRAGMA synchronous=NORMAL") &&
               exec("CREATE TABLE IF NOT EXISTS chunks("
                    " key TEXT PRIMARY KEY, path TEXT NOT NULL, idx INTEGER NOT NULL,"
                    " fsize INTEGER NOT NULL, mtime INTEGER NOT NULL, len INTEGER NOT NULL,"
                    " sha TEXT NOT NULL, last_used INTEGER NOT NULL) WITHOUT ROWID") &&
               exec("CREATE INDEX IF NOT EXISTS chunks_path ON chunks(path)") &&
               exec("CREATE INDEX IF NOT EXISTS chunks_lru ON chunks(last_used)") &&
               exec(("PRAGMA user_version=" + std::to_string(SCHEMA_VERSION)).c_str());
    }
    if (!good) { sqlite3_close(db_); db_ = nullptr; }
    return good;
}

// Reconcile index and files after a crash: delete half-written temp files,
// files nobody indexes (renamed but the row never committed), and rows whose
// file is gone. Then load the byte total and the LRU clock.
void ChunkCache::sweep() {
    std::set<std::string> indexed;
    {
        Stmt q(db_, "SELECT key FROM chunks");
        while (q.row()) indexed.insert(q.col_text(0));
    }
    std::set<std::string> on_disk;
    std::error_code ec;
    for (auto it = std::filesystem::recursive_directory_iterator(dir_ + "/chunks", ec);
         !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
        if (!it->is_regular_file(ec)) continue;
        std::string name = it->path().filename().string();
        bool is_chunk = name.size() > 4 && name.compare(name.size() - 4, 4, ".chk") == 0;
        std::string key = is_chunk ? name.substr(0, name.size() - 4) : "";
        if (!is_chunk || !indexed.count(key)) {
            std::filesystem::remove(it->path(), ec);
        } else {
            on_disk.insert(key);
        }
    }
    for (const auto& key : indexed) {
        if (on_disk.count(key)) continue;
        Stmt d(db_, "DELETE FROM chunks WHERE key=?1");
        d.text(1, key).run();
    }
    Stmt s(db_, "SELECT COALESCE(SUM(len),0), COALESCE(MAX(last_used),0) FROM chunks");
    if (s.row()) {
        bytes_ = static_cast<uint64_t>(s.col_num(0));
        tick_ = s.col_num(1);
    }
}

std::string ChunkCache::chunk_path(const std::string& hexkey) const {
    return dir_ + "/chunks/" + hexkey.substr(0, 2) + "/" + hexkey + ".chk";
}

void ChunkCache::set_pin_check(std::function<bool(const std::string&)> f) {
    std::lock_guard<std::mutex> lk(mu_);
    pinned_ = std::move(f);
}

void ChunkCache::remove_row_and_file(const std::string& hexkey, uint64_t len) {
    unlink(chunk_path(hexkey).c_str());
    Stmt d(db_, "DELETE FROM chunks WHERE key=?1");
    d.text(1, hexkey).run();
    bytes_ = bytes_ >= len ? bytes_ - len : 0;
}

bool ChunkCache::has(const ChunkKey& k) {
    if (!db_) return false;
    std::string hk = key_hex(k);
    std::lock_guard<std::mutex> lk(mu_);
    Stmt s(db_, "SELECT 1 FROM chunks WHERE key=?1");
    s.text(1, hk);
    return s.row();
}

bool ChunkCache::get(const ChunkKey& k, std::vector<uint8_t>& out) {
    if (!db_) return false;
    std::string hk = key_hex(k);
    uint64_t len = 0;
    std::string want_sha;
    {
        std::lock_guard<std::mutex> lk(mu_);
        Stmt s(db_, "SELECT len, sha FROM chunks WHERE key=?1");
        s.text(1, hk);
        if (!s.row()) { st_.misses++; return false; }
        len = static_cast<uint64_t>(s.col_num(0));
        want_sha = s.col_text(1);
    }
    // Disk read and hashing happen outside the lock so other threads can proceed.
    int rc = read_exact(chunk_path(hk), static_cast<size_t>(len), out);
    bool good = rc == 1 && sha256_hex(out.data(), out.size()) == want_sha;

    std::lock_guard<std::mutex> lk(mu_);
    if (good) {
        Stmt u(db_, "UPDATE chunks SET last_used=?1 WHERE key=?2");
        u.num(1, ++tick_).text(2, hk).run();
        st_.hits++;
        return true;
    }
    // Missing file, wrong size or wrong hash: drop the entry (if a concurrent
    // evict has not already done so) and report a miss.
    bool still_indexed;
    {
        Stmt chk(db_, "SELECT len FROM chunks WHERE key=?1");
        chk.text(1, hk);
        still_indexed = chk.row();
    }
    if (still_indexed) {
        remove_row_and_file(hk, len);
        if (rc != 0) st_.corrupt++;  // rc==0 is a plain race with eviction
    }
    st_.misses++;
    out.clear();
    return false;
}

void ChunkCache::put(const ChunkKey& k, const uint8_t* data, size_t len) {
    if (!db_ || len == 0 || len > MAX_CHUNK_LEN) return;
    std::string hk = key_hex(k);
    std::string sha = sha256_hex(data, len);

    // Write to a temp name then rename: a reader never sees a partial chunk, and
    // a crash leaves at worst a temp file that sweep() removes at next start.
    std::string tmp = dir_ + "/chunks/.tmp." + std::to_string(getpid()) + "." +
                      std::to_string(g_tmp_counter++);
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return;
    bool ok = write_all(fd, data, len);
    close(fd);
    std::string final_path = chunk_path(hk);
    if (ok) {
        std::error_code ec;
        std::filesystem::create_directories(dir_ + "/chunks/" + hk.substr(0, 2), ec);
        ok = ::rename(tmp.c_str(), final_path.c_str()) == 0;
    }
    if (!ok) { unlink(tmp.c_str()); return; }

    std::lock_guard<std::mutex> lk(mu_);
    uint64_t old_len = 0;
    {
        Stmt q(db_, "SELECT len FROM chunks WHERE key=?1");
        q.text(1, hk);
        if (q.row()) old_len = static_cast<uint64_t>(q.col_num(0));
    }
    Stmt ins(db_,
             "INSERT OR REPLACE INTO chunks(key,path,idx,fsize,mtime,len,sha,last_used)"
             " VALUES(?1,?2,?3,?4,?5,?6,?7,?8)");
    if (!ins.text(1, hk).text(2, k.path).num(3, k.idx).num(4, static_cast<int64_t>(k.size))
             .num(5, k.mtime).num(6, static_cast<int64_t>(len)).text(7, sha).num(8, ++tick_).run()) {
        unlink(final_path.c_str());
        return;
    }
    bytes_ = bytes_ - old_len + len;
    st_.puts++;
    evict_locked();
}

// Least-recently-used first, skipping pinned paths. Stops at 90% of the budget
// so we do not evict on every single put once full.
void ChunkCache::evict_locked() {
    if (bytes_ <= budget_) return;
    uint64_t target = budget_ - budget_ / 10;
    uint64_t need = bytes_ - target;

    struct Victim { std::string key; uint64_t len; };
    std::vector<Victim> victims;
    uint64_t sum = 0;
    {
        Stmt q(db_, "SELECT key, path, len FROM chunks ORDER BY last_used ASC");
        while (sum < need && q.row()) {
            if (pinned_ && pinned_(q.col_text(1))) continue;
            uint64_t len = static_cast<uint64_t>(q.col_num(2));
            victims.push_back({q.col_text(0), len});
            sum += len;
        }
    }
    Txn t(db_);
    for (const auto& v : victims) {
        remove_row_and_file(v.key, v.len);
        st_.evicted++;
    }
    t.commit();
}

void ChunkCache::invalidate_path(const std::string& path) {
    if (!db_) return;
    std::lock_guard<std::mutex> lk(mu_);
    struct Row { std::string key; uint64_t len; };
    std::vector<Row> rows;
    {
        Stmt q(db_, "SELECT key, len FROM chunks WHERE path=?1");
        q.text(1, path);
        while (q.row()) rows.push_back({q.col_text(0), static_cast<uint64_t>(q.col_num(1))});
    }
    Txn t(db_);
    for (const auto& r : rows) remove_row_and_file(r.key, r.len);
    t.commit();
}

void ChunkCache::invalidate_tree(const std::string& path) {
    if (!db_) return;
    std::lock_guard<std::mutex> lk(mu_);
    std::string lo = path == "/" ? "/" : path + "/";
    std::string hi = lo;
    hi.back() = static_cast<char>(hi.back() + 1);  // key range, see MetaStore::forget_inner
    struct Row { std::string key; uint64_t len; };
    std::vector<Row> rows;
    {
        Stmt q(db_, "SELECT key, len FROM chunks WHERE path=?1 OR (path>=?2 AND path<?3)");
        q.text(1, path).text(2, lo).text(3, hi);
        while (q.row()) rows.push_back({q.col_text(0), static_cast<uint64_t>(q.col_num(1))});
    }
    Txn t(db_);
    for (const auto& r : rows) remove_row_and_file(r.key, r.len);
    t.commit();
}

uint64_t ChunkCache::bytes_used() {
    std::lock_guard<std::mutex> lk(mu_);
    return bytes_;
}

ChunkInfo ChunkCache::info() {
    ChunkInfo r;
    if (!db_) return r;
    std::lock_guard<std::mutex> lk(mu_);
    Stmt s(db_, "SELECT COUNT(*), COALESCE(SUM(len),0), COUNT(DISTINCT path) FROM chunks");
    if (s.row()) {
        r.chunks = static_cast<uint64_t>(s.col_num(0));
        r.bytes = static_cast<uint64_t>(s.col_num(1));
        r.files = static_cast<uint64_t>(s.col_num(2));
    }
    return r;
}

uint64_t ChunkCache::verify_all(uint64_t* bad_out) {
    if (bad_out) *bad_out = 0;
    if (!db_) return 0;
    struct Row { std::string key, sha; uint64_t len; };
    std::vector<Row> rows;
    {
        std::lock_guard<std::mutex> lk(mu_);
        Stmt q(db_, "SELECT key, sha, len FROM chunks");
        while (q.row()) rows.push_back({q.col_text(0), q.col_text(1), static_cast<uint64_t>(q.col_num(2))});
    }
    uint64_t bad = 0;
    for (const auto& r : rows) {
        std::vector<uint8_t> data;
        int rc = read_exact(chunk_path(r.key), static_cast<size_t>(r.len), data);
        if (rc == 1 && sha256_hex(data.data(), data.size()) == r.sha) continue;
        std::lock_guard<std::mutex> lk(mu_);
        remove_row_and_file(r.key, r.len);
        st_.corrupt++;
        bad++;
    }
    if (bad_out) *bad_out = bad;
    return rows.size();
}

ChunkStats ChunkCache::stats() {
    std::lock_guard<std::mutex> lk(mu_);
    return st_;
}

}  // namespace tierfs
