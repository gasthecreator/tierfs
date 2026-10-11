#include "metastore.hpp"

#include "sqlutil.hpp"

#include <cstdio>
#include <ctime>
#include <set>
#include <unistd.h>

namespace tierfs {
namespace {

using sql::Stmt;
using sql::Txn;

constexpr int SCHEMA_VERSION = 1;

std::string join(const std::string& dir, const std::string& name) {
    return dir == "/" ? "/" + name : dir + "/" + name;
}
std::string parent_of(const std::string& p) {
    size_t i = p.rfind('/');
    return i == 0 ? "/" : p.substr(0, i);
}
std::string base_of(const std::string& p) { return p.substr(p.rfind('/') + 1); }

tc_attr attr_from_row(Stmt& s, int first) {
    tc_attr a;
    a.is_dir = static_cast<uint8_t>(s.col_num(first));
    a.size = static_cast<uint64_t>(s.col_num(first + 1));
    a.mtime = s.col_num(first + 2);
    a.mode = static_cast<uint32_t>(s.col_num(first + 3));
    return a;
}

}  // namespace

MetaStore::MetaStore(const std::string& db_path) {
    if (open_and_init(db_path)) return;
    // Unreadable, corrupt, or from a different schema version: it is only a
    // cache, so throw it away and start over.
    if (db_path != ":memory:") {
        for (const char* suffix : {"", "-wal", "-shm"})
            unlink((db_path + suffix).c_str());
        recovered_ = true;
        open_and_init(db_path);
    }
}

MetaStore::~MetaStore() {
    if (db_) sqlite3_close(db_);
}

bool MetaStore::exec(const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) == SQLITE_OK) return true;
    fprintf(stderr, "tierfs meta: %s\n", err ? err : "error");
    sqlite3_free(err);
    return false;
}

bool MetaStore::open_and_init(const std::string& path) {
    if (sqlite3_open_v2(path.c_str(), &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK) {
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
        return false;
    }
    sqlite3_busy_timeout(db_, 2000);

    bool good = true;
    // Reading user_version is the first real access, so a garbage file fails here.
    int version = -1;
    {
        Stmt v(db_, "PRAGMA user_version");
        if (v.row()) version = static_cast<int>(v.col_num(0));
    }
    if (version != 0 && version != SCHEMA_VERSION) good = false;

    if (good) {
        // WAL + NORMAL: fast commits, and a crash can lose the last few updates
        // but cannot corrupt the file. Fine for a cache.
        if (path != ":memory:") exec("PRAGMA journal_mode=WAL");
        good = exec("PRAGMA synchronous=NORMAL") &&
               exec("CREATE TABLE IF NOT EXISTS attrs("
                    " path TEXT PRIMARY KEY, is_dir INTEGER NOT NULL, size INTEGER NOT NULL,"
                    " mtime INTEGER NOT NULL, mode INTEGER NOT NULL, fetched INTEGER NOT NULL,"
                    " last_access INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID") &&
               exec("CREATE TABLE IF NOT EXISTS dirs("
                    " path TEXT PRIMARY KEY, fetched INTEGER NOT NULL) WITHOUT ROWID") &&
               exec("CREATE TABLE IF NOT EXISTS entries("
                    " dir TEXT NOT NULL, name TEXT NOT NULL, PRIMARY KEY(dir, name)) WITHOUT ROWID") &&
               exec(("PRAGMA user_version=" + std::to_string(SCHEMA_VERSION)).c_str());
    }
    if (!good) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    return good;
}

void MetaStore::upsert_attr(const std::string& path, const tc_attr& a) {
    Stmt s(db_,
           "INSERT INTO attrs(path,is_dir,size,mtime,mode,fetched) VALUES(?1,?2,?3,?4,?5,?6)"
           " ON CONFLICT(path) DO UPDATE SET is_dir=excluded.is_dir, size=excluded.size,"
           " mtime=excluded.mtime, mode=excluded.mode, fetched=excluded.fetched");
    s.text(1, path).num(2, a.is_dir).num(3, static_cast<int64_t>(a.size))
     .num(4, a.mtime).num(5, a.mode).num(6, time(nullptr)).run();
}

void MetaStore::put_attr(const std::string& path, const tc_attr& a) {
    if (!db_) return;
    upsert_attr(path, a);
}

bool MetaStore::get_attr(const std::string& path, tc_attr& out) {
    if (!db_) return false;
    Stmt s(db_, "SELECT is_dir,size,mtime,mode FROM attrs WHERE path=?1");
    s.text(1, path);
    if (!s.row()) return false;
    out = attr_from_row(s, 0);
    return true;
}

// Everything under `path` is the key range [path + "/", path + "0") because '0'
// is the character right after '/'. A range scan uses the primary-key index and
// avoids LIKE, whose % and _ wildcards would need escaping in file names.
void MetaStore::forget_inner(const std::string& path) {
    std::string lo = path == "/" ? "/" : path + "/";
    std::string hi = lo;
    hi.back() = static_cast<char>(hi.back() + 1);
    for (const char* sql : {
             "DELETE FROM attrs WHERE path=?1 OR (path>=?2 AND path<?3)",
             "DELETE FROM dirs WHERE path=?1 OR (path>=?2 AND path<?3)",
             "DELETE FROM entries WHERE dir=?1 OR (dir>=?2 AND dir<?3)"}) {
        Stmt s(db_, sql);
        s.text(1, path).text(2, lo).text(3, hi).run();
    }
    if (path != "/") {
        Stmt s(db_, "DELETE FROM entries WHERE dir=?1 AND name=?2");
        s.text(1, parent_of(path)).text(2, base_of(path)).run();
    }
}

void MetaStore::forget(const std::string& path) {
    if (!db_) return;
    Txn t(db_);
    forget_inner(path);
    t.commit();
}

void MetaStore::put_dir(const std::string& dir, const DirList& entries) {
    if (!db_) return;
    Txn t(db_);

    std::set<std::string> fresh;
    for (const auto& e : entries) fresh.insert(e.first);

    // Collect first, then forget: do not modify a table while stepping over it.
    std::vector<std::string> gone;
    {
        Stmt old(db_, "SELECT name FROM entries WHERE dir=?1");
        old.text(1, dir);
        while (old.row()) {
            std::string name = old.col_text(0);
            if (!fresh.count(name)) gone.push_back(std::move(name));
        }
    }
    for (const auto& name : gone) forget_inner(join(dir, name));

    {
        Stmt del(db_, "DELETE FROM entries WHERE dir=?1");
        del.text(1, dir).run();
    }
    for (const auto& e : entries) {
        upsert_attr(join(dir, e.first), e.second);
        Stmt ins(db_, "INSERT INTO entries(dir,name) VALUES(?1,?2)");
        ins.text(1, dir).text(2, e.first).run();
    }
    Stmt mark(db_, "INSERT OR REPLACE INTO dirs(path,fetched) VALUES(?1,?2)");
    mark.text(1, dir).num(2, time(nullptr)).run();
    t.commit();
}

bool MetaStore::get_dir(const std::string& dir, DirList& out) {
    if (!db_) return false;
    {
        Stmt has(db_, "SELECT 1 FROM dirs WHERE path=?1");
        has.text(1, dir);
        if (!has.row()) return false;
    }
    out.clear();
    Stmt s(db_,
           "SELECT e.name, a.is_dir, a.size, a.mtime, a.mode FROM entries e"
           " JOIN attrs a ON a.path = CASE WHEN e.dir='/' THEN '/' || e.name"
           " ELSE e.dir || '/' || e.name END WHERE e.dir=?1 ORDER BY e.name");
    s.text(1, dir);
    while (s.row()) out.emplace_back(s.col_text(0), attr_from_row(s, 1));
    return true;
}

void MetaStore::touch(const std::string& path, int64_t now) {
    if (!db_) return;
    Stmt s(db_, "UPDATE attrs SET last_access=?1 WHERE path=?2 AND last_access<?3");
    s.num(1, now).text(2, path).num(3, now - 60).run();
}

int64_t MetaStore::last_access(const std::string& path) {
    if (!db_) return 0;
    Stmt s(db_, "SELECT last_access FROM attrs WHERE path=?1");
    s.text(1, path);
    return s.row() ? s.col_num(0) : 0;
}

}  // namespace tierfs
