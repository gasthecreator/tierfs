#include "ledger.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <map>
#include <set>

#include "crashpoint.hpp"
#include "hash.hpp"
#include "sqlutil.hpp"

namespace tierfs {
namespace {

using sql::Stmt;
using sql::Txn;

constexpr int SCHEMA_VERSION = 1;
const std::string GENESIS(64, '0');

const char* const FILE_STATES[] = {"LOCAL", "REPLICATING", "REPLICATED", "DROPPING", "OFFLOADED", "HYDRATING", "AT_RISK"};
const char* const REPLICA_STATES[] = {"PENDING", "UPLOADED", "COMMITTED", "AUDIT_FAILED", "MISSING"};

FileState parse_file_state(const std::string& s) {
    for (int i = 0; i < 7; i++) if (s == FILE_STATES[i]) return static_cast<FileState>(i);
    return FileState::AT_RISK;  // unknown text must never read as a safe state
}
ReplicaState parse_replica_state(const std::string& s) {
    for (int i = 0; i < 5; i++) if (s == REPLICA_STATES[i]) return static_cast<ReplicaState>(i);
    return ReplicaState::MISSING;
}

Res fail(const std::string& why) { return Res{false, why, ""}; }
Res ok(const std::string& id = "") { return Res{true, "", id}; }

// Length-prefixed fields: a '|' inside a path or detail string cannot make two
// different events hash the same.
std::string event_hash(int64_t seq, int64_t ts, const std::string& kind, const std::string& file_id,
                       int64_t version, const std::string& device_id, const std::string& detail,
                       const std::string& prev) {
    std::string m;
    auto add = [&](const std::string& f) { m += std::to_string(f.size()); m += ':'; m += f; m += ';'; };
    add(std::to_string(seq)); add(std::to_string(ts)); add(kind); add(file_id);
    add(std::to_string(version)); add(device_id); add(detail); add(prev);
    return sha256_hex(m.data(), m.size());
}

bool has_committed(sqlite3* db, const std::string& file_id, int64_t version);

const char* const FILE_COLS = "file_id,path,current_version,generation,state,size,mtime,mode,local_present,last_access";

FileRec file_from(Stmt& s) {
    FileRec f;
    f.file_id = s.col_text(0);
    f.path = s.col_text(1);
    f.current_version = s.col_num(2);
    f.generation = s.col_num(3);
    f.state = parse_file_state(s.col_text(4));
    f.size = static_cast<uint64_t>(s.col_num(5));
    f.mtime = s.col_num(6);
    f.mode = static_cast<uint32_t>(s.col_num(7));
    f.local_present = s.col_num(8) != 0;
    f.last_access = s.col_num(9);
    return f;
}

std::optional<FileRec> load_file(sqlite3* db, const std::string& file_id) {
    Stmt s(db, (std::string("SELECT ") + FILE_COLS + " FROM files WHERE file_id=?1").c_str());
    s.text(1, file_id);
    if (!s.row()) return std::nullopt;
    return file_from(s);
}

bool replica_transition_allowed(const std::optional<ReplicaState>& from, ReplicaState to) {
    if (!from) return to == ReplicaState::PENDING;
    switch (*from) {
        case ReplicaState::PENDING:      return to == ReplicaState::PENDING || to == ReplicaState::UPLOADED || to == ReplicaState::MISSING;
        case ReplicaState::UPLOADED:     return to == ReplicaState::UPLOADED || to == ReplicaState::COMMITTED || to == ReplicaState::PENDING || to == ReplicaState::MISSING;
        case ReplicaState::COMMITTED:    return to == ReplicaState::COMMITTED || to == ReplicaState::AUDIT_FAILED || to == ReplicaState::MISSING;
        case ReplicaState::AUDIT_FAILED:
        case ReplicaState::MISSING:      return to == ReplicaState::PENDING;
    }
    return false;
}

}  // namespace

const char* to_string(FileState s) { return FILE_STATES[static_cast<int>(s)]; }
const char* to_string(ReplicaState s) { return REPLICA_STATES[static_cast<int>(s)]; }
const char* to_string(QuarantineState s) {
    static const char* const names[] = {"held", "purging", "purged", "restoring", "restored"};
    return names[static_cast<int>(s)];
}

int64_t Ledger::now() const { return clock_ ? clock_() : static_cast<int64_t>(time(nullptr)); }

std::string Ledger::new_id() {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    unsigned char b[16];
    arc4random_buf(b, sizeof b);
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += hex[c >> 4]; s += hex[c & 15]; }
    return s;
}

bool Ledger::exec(const char* sql) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    char* e = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &e) == SQLITE_OK) return true;
    fprintf(stderr, "tierfs ledger: %s\n", e ? e : "error");
    sqlite3_free(e);
    return false;
}

// ---------------------------------------------------------------- open / schema

std::unique_ptr<Ledger> Ledger::open(const std::string& dir, std::string* err) {
    auto fail_open = [&](const std::string& m) -> std::unique_ptr<Ledger> {
        if (err) *err = m;
        return nullptr;
    };
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return fail_open("cannot create " + dir + ": " + ec.message());

    std::unique_ptr<Ledger> L(new Ledger);
    L->dir_ = dir;
    L->lock_fd_ = ::open((dir + "/ledger.lock").c_str(), O_CREAT | O_RDWR, 0600);
    if (L->lock_fd_ < 0) return fail_open("cannot create lock file");
    if (flock(L->lock_fd_, LOCK_EX | LOCK_NB) != 0) return fail_open("ledger is in use by another process");

    std::string path = dir + "/ledger.db";
    bool existed = std::filesystem::exists(path, ec) && std::filesystem::file_size(path, ec) > 0;
    if (sqlite3_open_v2(path.c_str(), &L->db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK)
        return fail_open("cannot open " + path);
    sqlite3_busy_timeout(L->db_, 5000);

    if (existed) {
        Stmt ic(L->db_, "PRAGMA integrity_check");
        if (!ic.valid() || !ic.row() || ic.col_text(0) != "ok")
            return fail_open(path + " failed its integrity check; refusing to touch it (restore a snapshot from a device)");
    }
    int version = 0;
    long tables = 0;
    {
        Stmt v(L->db_, "PRAGMA user_version");
        if (v.valid() && v.row()) version = static_cast<int>(v.col_num(0));
        Stmt t(L->db_, "SELECT COUNT(*) FROM sqlite_master");
        if (t.valid() && t.row()) tables = static_cast<long>(t.col_num(0));
        else return fail_open(path + " is not a readable database; refusing to touch it");
    }
    if (version != 0 && version != SCHEMA_VERSION)
        return fail_open("ledger schema version " + std::to_string(version) + " is not understood by this build (expects " +
                         std::to_string(SCHEMA_VERSION) + "); refusing to touch it");
    if (version == 0 && tables != 0)
        return fail_open(path + " has tables but no version; refusing to touch it");

    // Durability settings. If the platform will not take them, do not run at all:
    // a ledger that silently loses commits is worse than no ledger.
    L->exec("PRAGMA journal_mode=WAL");
    L->exec("PRAGMA synchronous=FULL");
    L->exec("PRAGMA fullfsync=ON");
    L->exec("PRAGMA checkpoint_fullfsync=ON");
    L->exec("PRAGMA foreign_keys=ON");
    auto pragma_is = [&](const char* q, const std::string& want) {
        Stmt s(L->db_, q);
        return s.valid() && s.row() && s.col_text(0) == want;
    };
    if (!pragma_is("PRAGMA journal_mode", "wal") || !pragma_is("PRAGMA synchronous", "2") ||
        !pragma_is("PRAGMA fullfsync", "1") || !pragma_is("PRAGMA checkpoint_fullfsync", "1") ||
        !pragma_is("PRAGMA foreign_keys", "1"))
        return fail_open("cannot enable full-fsync durability settings on " + dir);

    if (version == 0) {
        std::string e;
        if (!L->init_schema(&e)) return fail_open("cannot create ledger: " + e);
    }
    return L;
}

Ledger::~Ledger() {
    if (db_) sqlite3_close(db_);
    if (lock_fd_ >= 0) close(lock_fd_);
}

bool Ledger::init_schema(std::string* err) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) { *err = "cannot begin"; return false; }
    const char* ddl[] = {
        "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
        "CREATE TABLE devices(device_id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " class TEXT NOT NULL CHECK(class IN('A','B','C')),"
        " state TEXT NOT NULL DEFAULT 'active' CHECK(state IN('active','retired','suspect')),"
        " registered_at INTEGER NOT NULL, epoch INTEGER NOT NULL DEFAULT 0, last_seq INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID",
        "CREATE TABLE files(file_id TEXT PRIMARY KEY, path TEXT NOT NULL UNIQUE,"
        " current_version INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 1,"
        " state TEXT NOT NULL CHECK(state IN('LOCAL','REPLICATING','REPLICATED','DROPPING','OFFLOADED','HYDRATING','AT_RISK')),"
        " prior_state TEXT, size INTEGER NOT NULL, mtime INTEGER NOT NULL, mode INTEGER NOT NULL,"
        " local_present INTEGER NOT NULL DEFAULT 1, last_access INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL) WITHOUT ROWID",
        "CREATE TABLE versions(file_id TEXT NOT NULL REFERENCES files(file_id), version INTEGER NOT NULL,"
        " generation INTEGER NOT NULL, size INTEGER NOT NULL, mtime INTEGER NOT NULL,"
        " chunk_count INTEGER NOT NULL, created_at INTEGER NOT NULL, manifest_sha256 TEXT,"
        " PRIMARY KEY(file_id,version)) WITHOUT ROWID",
        "CREATE TABLE chunk_challenges(file_id TEXT NOT NULL, version INTEGER NOT NULL, idx INTEGER NOT NULL, n INTEGER NOT NULL,"
        " response TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(file_id,version,idx,n),"
        " FOREIGN KEY(file_id,version) REFERENCES versions(file_id,version)) WITHOUT ROWID",
        "CREATE TABLE version_chunks(file_id TEXT NOT NULL, version INTEGER NOT NULL, idx INTEGER NOT NULL,"
        " chunk_id TEXT NOT NULL, len INTEGER NOT NULL, blob_sha256 TEXT NOT NULL,"
        " PRIMARY KEY(file_id,version,idx), FOREIGN KEY(file_id,version) REFERENCES versions(file_id,version)) WITHOUT ROWID",
        "CREATE TABLE replicas(file_id TEXT NOT NULL, version INTEGER NOT NULL,"
        " device_id TEXT NOT NULL REFERENCES devices(device_id),"
        " state TEXT NOT NULL CHECK(state IN('PENDING','UPLOADED','COMMITTED','AUDIT_FAILED','MISSING')),"
        " committed_at INTEGER NOT NULL DEFAULT 0, last_audit_at INTEGER NOT NULL DEFAULT 0,"
        " device_seq INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(file_id,version,device_id),"
        " FOREIGN KEY(file_id,version) REFERENCES versions(file_id,version)) WITHOUT ROWID",
        "CREATE TABLE intents(intent_id TEXT PRIMARY KEY, kind TEXT NOT NULL, file_id TEXT NOT NULL REFERENCES files(file_id),"
        " version INTEGER NOT NULL, generation INTEGER NOT NULL, payload TEXT NOT NULL DEFAULT '',"
        " state TEXT NOT NULL CHECK(state IN('open','done','aborted')), created_at INTEGER NOT NULL,"
        " done_at INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID",
        "CREATE UNIQUE INDEX one_open_drop ON intents(file_id) WHERE state='open' AND kind='DROP_LOCAL'",
        "CREATE TABLE quarantine(intent_id TEXT PRIMARY KEY REFERENCES intents(intent_id), file_id TEXT NOT NULL REFERENCES files(file_id),"
        " version INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN('held','purging','purged','restoring','restored')),"
        " held_at INTEGER NOT NULL, resolved_at INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '') WITHOUT ROWID",
        "CREATE TABLE consents(consent_id TEXT PRIMARY KEY, scope_prefix TEXT NOT NULL CHECK(length(scope_prefix)>0),"
        " created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ack_text TEXT NOT NULL) WITHOUT ROWID",
        "CREATE TABLE events(seq INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, file_id TEXT NOT NULL,"
        " version INTEGER NOT NULL, device_id TEXT NOT NULL, detail TEXT NOT NULL,"
        " prev_hash TEXT NOT NULL, hash TEXT NOT NULL)",
        // Nothing in the ledger is ever deleted or rewritten as history: the engine
        // can have bugs, but a bug cannot erase the record of what happened.
        "CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END",
        "CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END",
        "CREATE TRIGGER files_no_delete BEFORE DELETE ON files BEGIN SELECT RAISE(ABORT,'ledger rows are never deleted'); END",
        "CREATE TRIGGER versions_no_delete BEFORE DELETE ON versions BEGIN SELECT RAISE(ABORT,'ledger rows are never deleted'); END",
        "CREATE TRIGGER chunks_no_delete BEFORE DELETE ON version_chunks BEGIN SELECT RAISE(ABORT,'ledger rows are never deleted'); END",
        "CREATE TRIGGER replicas_no_delete BEFORE DELETE ON replicas BEGIN SELECT RAISE(ABORT,'ledger rows are never deleted'); END",
        "CREATE TRIGGER intents_no_delete BEFORE DELETE ON intents BEGIN SELECT RAISE(ABORT,'ledger rows are never deleted'); END",
        "CREATE TRIGGER consents_no_delete BEFORE DELETE ON consents BEGIN SELECT RAISE(ABORT,'ledger rows are never deleted'); END",
        "CREATE TRIGGER devices_no_delete BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT,'ledger rows are never deleted'); END",
        "CREATE TRIGGER quarantine_no_delete BEFORE DELETE ON quarantine BEGIN SELECT RAISE(ABORT,'ledger rows are never deleted'); END",
        "CREATE TRIGGER quarantine_final BEFORE UPDATE ON quarantine WHEN OLD.state IN ('purged','restored')"
        " BEGIN SELECT RAISE(ABORT,'a resolved quarantine is final'); END",
        "CREATE TRIGGER challenges_no_delete BEFORE DELETE ON chunk_challenges BEGIN SELECT RAISE(ABORT,'ledger rows are never deleted'); END",
        // A challenge is used once: after its nonce has been shown to a device it is worthless (the device
        // could have kept the answer), so a used row can never be reset or altered.
        "CREATE TRIGGER challenges_use_once BEFORE UPDATE ON chunk_challenges"
        " WHEN OLD.used=1 OR NEW.response!=OLD.response OR NEW.n!=OLD.n OR NEW.idx!=OLD.idx"
        " BEGIN SELECT RAISE(ABORT,'a used challenge is never reused or altered'); END",
        "CREATE TRIGGER manifest_hash_once BEFORE UPDATE ON versions"
        " WHEN OLD.manifest_sha256 IS NOT NULL AND NEW.manifest_sha256 IS NOT OLD.manifest_sha256"
        " BEGIN SELECT RAISE(ABORT,'a recorded manifest hash never changes'); END",
    };
    for (const char* q : ddl)
        if (!exec(q)) { *err = q; return false; }
    {
        Stmt a(db_, "INSERT INTO meta(key,value) VALUES('volume_id',?1)");
        a.text(1, new_id()).run();
        Stmt b(db_, "INSERT INTO meta(key,value) VALUES('created_at',?1)");
        b.text(1, std::to_string(now())).run();
    }
    append_event("ledger.created", "", 0, "", "schema " + std::to_string(SCHEMA_VERSION));
    if (!exec(("PRAGMA user_version=" + std::to_string(SCHEMA_VERSION)).c_str())) { *err = "user_version"; return false; }
    if (!t.commit()) { *err = "commit"; return false; }
    return true;
}

// Must run inside the caller's transaction, so the event and the state change it
// describes commit or vanish together.
void Ledger::append_event(const std::string& kind, const std::string& file_id, int64_t version,
                          const std::string& device_id, const std::string& detail) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    int64_t seq = 1;
    std::string prev = GENESIS;
    {
        Stmt q(db_, "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1");
        if (q.row()) { seq = q.col_num(0) + 1; prev = q.col_text(1); }
    }
    int64_t ts = now();
    std::string h = event_hash(seq, ts, kind, file_id, version, device_id, detail, prev);
    Stmt ins(db_, "INSERT INTO events(seq,ts,kind,file_id,version,device_id,detail,prev_hash,hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)");
    ins.num(1, seq).num(2, ts).text(3, kind).text(4, file_id).num(5, version).text(6, device_id).text(7, detail).text(8, prev).text(9, h).run();
}

// ---------------------------------------------------------------- meta / reserve / devices

std::optional<std::string> Ledger::get_meta(const std::string& key) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt s(db_, "SELECT value FROM meta WHERE key=?1");
    s.text(1, key);
    if (!s.row()) return std::nullopt;
    return s.col_text(0);
}

bool Ledger::set_meta(const std::string& key, const std::string& value) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return false;
    Stmt s(db_, "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
    if (!s.text(1, key).text(2, value).run()) return false;
    append_event("meta.set", "", 0, "", key + "=" + value);
    return t.commit();
}

std::string Ledger::volume_id() { return get_meta("volume_id").value_or(""); }

bool Ledger::ensure_reserve(uint64_t bytes) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::string p = dir_ + "/ledger.reserve";
    struct stat st;
    if (stat(p.c_str(), &st) == 0 && static_cast<uint64_t>(st.st_size) >= bytes) return true;
    int fd = ::open(p.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return false;
    std::vector<char> zeros(1 << 20, 0);  // real blocks, not a sparse file
    uint64_t left = bytes;
    bool good = true;
    while (left && good) {
        size_t n = static_cast<size_t>(std::min<uint64_t>(left, zeros.size()));
        good = write(fd, zeros.data(), n) == static_cast<ssize_t>(n);
        left -= n;
    }
    good = good && fcntl(fd, F_FULLFSYNC) == 0;
    close(fd);
    if (!good) unlink(p.c_str());
    return good;
}

bool Ledger::has_reserve() {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    struct stat st;
    return stat((dir_ + "/ledger.reserve").c_str(), &st) == 0 && st.st_size > 0;
}

bool Ledger::release_reserve() { return unlink((dir_ + "/ledger.reserve").c_str()) == 0; }

bool Ledger::register_device(const std::string& device_id, const std::string& name, const std::string& cls) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    if (cls != "A" && cls != "B" && cls != "C") return false;
    Txn t(db_);
    if (!t.began()) return false;
    Stmt s(db_, "INSERT INTO devices(device_id,name,class,registered_at) VALUES(?1,?2,?3,?4)");
    if (!s.text(1, device_id).text(2, name).text(3, cls).num(4, now()).run()) return false;
    append_event("device.registered", "", 0, device_id, name + " class " + cls);
    return t.commit();
}

bool Ledger::retire_device(const std::string& device_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return false;
    Stmt s(db_, "UPDATE devices SET state='retired' WHERE device_id=?1 AND state='active'");
    if (!s.text(1, device_id).run() || sqlite3_changes(db_) != 1) return false;
    append_event("device.retired", "", 0, device_id, "");
    reevaluate_for_device(device_id, "device retired");
    return t.commit();
}

// ---------------------------------------------------------------- files

std::string Ledger::track_file(const std::string& path, uint64_t size, int64_t mtime, uint32_t mode) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    if (auto f = get_file_by_path(path)) return f->file_id;
    Txn t(db_);
    if (!t.began()) return "";
    std::string id = new_id();
    Stmt s(db_, "INSERT INTO files(file_id,path,state,size,mtime,mode,created_at) VALUES(?1,?2,'LOCAL',?3,?4,?5,?6)");
    if (!s.text(1, id).text(2, path).num(3, static_cast<int64_t>(size)).num(4, mtime).num(5, mode).num(6, now()).run()) return "";
    append_event("file.tracked", id, 0, "", path);
    return t.commit() ? id : "";
}

std::optional<FileRec> Ledger::get_file(const std::string& file_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    return load_file(db_, file_id);
}

size_t Ledger::track_files(const std::vector<NewFile>& files) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    size_t added = 0;
    for (size_t start = 0; start < files.size(); start += 500) {   // bounded transactions: a huge scan never holds the database for long
        Txn t(db_);
        if (!t.began()) return added;
        size_t batch = 0;
        for (size_t i = start; i < files.size() && i < start + 500; i++) {
            const NewFile& f = files[i];
            Stmt q(db_, "SELECT 1 FROM files WHERE path=?1");
            q.text(1, f.path);
            if (q.row()) continue;
            std::string id = new_id();
            Stmt s(db_, "INSERT INTO files(file_id,path,state,size,mtime,mode,created_at) VALUES(?1,?2,'LOCAL',?3,?4,?5,?6)");
            if (!s.text(1, id).text(2, f.path).num(3, static_cast<int64_t>(f.size)).num(4, f.mtime).num(5, f.mode).num(6, now()).run()) continue;
            append_event("file.tracked", id, 0, "", f.path);
            batch++;
        }
        if (!t.commit()) return added;
        added += batch;
    }
    return added;
}

std::optional<FileRec> Ledger::get_file_by_path(const std::string& path) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt s(db_, (std::string("SELECT ") + FILE_COLS + " FROM files WHERE path=?1").c_str());
    s.text(1, path);
    if (!s.row()) return std::nullopt;
    return file_from(s);
}

std::vector<FileRec> Ledger::list_files(std::optional<FileState> state) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<FileRec> out;
    std::string q = std::string("SELECT ") + FILE_COLS + " FROM files";
    if (state) q += std::string(" WHERE state='") + to_string(*state) + "'";
    q += " ORDER BY path";
    Stmt s(db_, q.c_str());
    while (s.row()) out.push_back(file_from(s));
    return out;
}

std::vector<FileRec> Ledger::list_files_under(const std::string& prefix) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<FileRec> out;
    // Byte range [prefix, prefix + 0xFF): 0xFF never occurs in UTF-8, so this is exactly "starts with prefix"
    // without LIKE's wildcard characters (paths may contain % and _).
    Stmt s(db_, (std::string("SELECT ") + FILE_COLS + " FROM files WHERE path>=?1 AND path<?2 ORDER BY path").c_str());
    s.text(1, prefix).text(2, prefix + "\xff");
    while (s.row()) out.push_back(file_from(s));
    return out;
}

Res Ledger::note_local_modified(const std::string& file_id, uint64_t new_size, int64_t new_mtime) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (f->state == FileState::DROPPING || f->state == FileState::HYDRATING)
        return fail(std::string("file is ") + to_string(f->state) + "; writers must wait");
    if (f->state == FileState::OFFLOADED) return fail("file is OFFLOADED; hydrate it before modifying");
    Stmt u(db_, "UPDATE files SET generation=generation+1, state='LOCAL', size=?2, mtime=?3, local_present=1 WHERE file_id=?1 AND state=?4");
    if (!u.text(1, file_id).num(2, static_cast<int64_t>(new_size)).num(3, new_mtime).text(4, to_string(f->state)).run() ||
        sqlite3_changes(db_) != 1)
        return fail("file changed concurrently");
    append_event("file.modified", file_id, f->current_version, "", std::string("was ") + to_string(f->state));
    return t.commit() ? ok() : fail("commit failed");
}

namespace {
const char RETIRED_PREFIX[] = "/\x01" "deleted/";
const size_t RETIRED_PREFIX_LEN = sizeof(RETIRED_PREFIX) - 1;
bool has_local_bytes(FileState s) { return s == FileState::LOCAL || s == FileState::REPLICATING || s == FileState::REPLICATED; }
}  // namespace

bool Ledger::is_retired_path(const std::string& path) { return path.compare(0, RETIRED_PREFIX_LEN, RETIRED_PREFIX) == 0; }

std::string Ledger::former_path(const FileRec& f) {
    if (!is_retired_path(f.path)) return f.path;
    size_t skip = RETIRED_PREFIX_LEN + f.file_id.size();
    return skip <= f.path.size() ? f.path.substr(skip) : std::string();
}

std::vector<FileRec> Ledger::list_retired() { return list_files_under(RETIRED_PREFIX); }

Res Ledger::retire_file(const std::string& file_id, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (is_retired_path(f->path)) return fail("file is already deleted");
    if (f->state == FileState::DROPPING || f->state == FileState::HYDRATING)
        return fail(std::string("file is ") + to_string(f->state) + "; it cannot be deleted in the middle of that");
    Stmt u(db_, "UPDATE files SET path=?2 WHERE file_id=?1 AND path=?3 AND state=?4");
    if (!u.text(1, file_id).text(2, std::string(RETIRED_PREFIX) + file_id + f->path).text(3, f->path).text(4, to_string(f->state)).run() ||
        sqlite3_changes(db_) != 1)
        return fail("file changed concurrently");
    append_event("file.deleted", file_id, f->current_version, "", reason + " (was " + f->path + ", " + to_string(f->state) + ")");
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::undelete_file(const std::string& file_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (!is_retired_path(f->path)) return fail("file is not deleted");
    if (f->state != FileState::OFFLOADED) return fail(std::string("only an offloaded file can be undeleted (this one is ") + to_string(f->state) + ")");
    std::string back = former_path(*f);
    if (back.empty() || back[0] != '/') return fail("the former path is unknown");
    Stmt u(db_, "UPDATE files SET path=?2 WHERE file_id=?1 AND path=?3");
    if (!u.text(1, file_id).text(2, back).text(3, f->path).run() || sqlite3_changes(db_) != 1) return fail("the former path is taken");
    append_event("file.undeleted", file_id, f->current_version, "", "back at " + back);
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::rename_file(const std::string& file_id, const std::string& new_path) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    if (new_path.empty() || new_path[0] != '/' || is_retired_path(new_path)) return fail("not a valid path");
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (is_retired_path(f->path)) return fail("file is deleted");
    if (f->state == FileState::DROPPING || f->state == FileState::HYDRATING)
        return fail(std::string("file is ") + to_string(f->state) + "; it cannot be renamed in the middle of that");
    if (new_path == f->path) return fail("the new path is the old path");
    std::string sql = has_local_bytes(f->state) ? "UPDATE files SET path=?2, generation=generation+1, state='LOCAL' WHERE file_id=?1 AND state=?3"
                                                : "UPDATE files SET path=?2 WHERE file_id=?1 AND state=?3";
    Stmt u(db_, sql.c_str());
    if (!u.text(1, file_id).text(2, new_path).text(3, to_string(f->state)).run() || sqlite3_changes(db_) != 1) return fail("the new path is taken");
    append_event("file.renamed", file_id, f->current_version, "", f->path + " -> " + new_path);
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::rename_prefix(const std::string& old_prefix, const std::string& new_prefix) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    auto dir_ok = [](const std::string& p) { return p.size() >= 2 && p[0] == '/' && p.back() == '/' && !Ledger::is_retired_path(p); };
    if (!dir_ok(old_prefix) || !dir_ok(new_prefix)) return fail("not valid directory prefixes");
    if (new_prefix.compare(0, old_prefix.size(), old_prefix) == 0) return fail("a directory cannot be moved into itself");
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    std::vector<FileRec> rows = list_files_under(old_prefix);
    for (const auto& f : rows)
        if (f.state == FileState::DROPPING || f.state == FileState::HYDRATING)
            return fail(f.path + " is " + to_string(f.state) + "; the directory cannot be renamed in the middle of that");
    for (const auto& f : rows) {
        std::string np = new_prefix + f.path.substr(old_prefix.size());
        std::string sql = has_local_bytes(f.state) ? "UPDATE files SET path=?2, generation=generation+1, state='LOCAL' WHERE file_id=?1 AND state=?3"
                                                   : "UPDATE files SET path=?2 WHERE file_id=?1 AND state=?3";
        Stmt u(db_, sql.c_str());
        if (!u.text(1, f.file_id).text(2, np).text(3, to_string(f.state)).run() || sqlite3_changes(db_) != 1) return fail(np + " is taken");
    }
    append_event("files.renamed_prefix", "", 0, "", old_prefix + " -> " + new_prefix + " (" + std::to_string(rows.size()) + " files)");
    if (!t.commit()) return fail("commit failed");
    return ok(std::to_string(rows.size()));
}

Res Ledger::note_attrs_changed(const std::string& file_id, std::optional<uint32_t> mode, std::optional<int64_t> mtime) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (is_retired_path(f->path)) return fail("file is deleted");
    if (f->state == FileState::DROPPING || f->state == FileState::HYDRATING)
        return fail(std::string("file is ") + to_string(f->state) + "; its attributes cannot change in the middle of that");
    std::string sql = std::string("UPDATE files SET mode=COALESCE(?2,mode), mtime=COALESCE(?3,mtime)") +
                      (has_local_bytes(f->state) ? ", generation=generation+1, state='LOCAL'" : "") + " WHERE file_id=?1 AND state=?4";
    Stmt u(db_, sql.c_str());
    u.text(1, file_id);
    if (mode) u.num(2, static_cast<int64_t>(*mode & 07777)); else u.null(2);
    if (mtime) u.num(3, *mtime); else u.null(3);
    u.text(4, to_string(f->state));
    if (!u.run() || sqlite3_changes(db_) != 1) return fail("file changed concurrently");
    append_event("file.attrs", file_id, f->current_version, "", std::string(mode ? "mode " : "") + (mtime ? "mtime" : ""));
    return t.commit() ? ok() : fail("commit failed");
}

void Ledger::touch_access(const std::string& file_id, int64_t tm) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt u(db_, "UPDATE files SET last_access=?2 WHERE file_id=?1 AND last_access<?3");
    u.text(1, file_id).num(2, tm).num(3, tm - 60).run();
}

// ---------------------------------------------------------------- replication

Res Ledger::begin_replication(const std::string& file_id, const std::vector<ChunkRec>& chunks,
                              uint64_t size, int64_t mtime) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    uint64_t total = 0;
    for (size_t i = 0; i < chunks.size(); i++) {
        if (chunks[i].idx != i || chunks[i].len == 0 || chunks[i].chunk_id.empty() || chunks[i].blob_sha256.empty())
            return fail("chunk list must be contiguous from 0 with non-empty ids and lengths");
        total += chunks[i].len;
    }
    if (total != size) return fail("chunk lengths do not add up to the file size");

    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (f->state != FileState::LOCAL) return fail(std::string("file is ") + to_string(f->state) + ", not LOCAL");
    if (!f->local_present) return fail("local bytes are not present");
    int64_t version = f->current_version + 1;
    {
        Stmt v(db_, "INSERT INTO versions(file_id,version,generation,size,mtime,chunk_count,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)");
        if (!v.text(1, file_id).num(2, version).num(3, f->generation).num(4, static_cast<int64_t>(size)).num(5, mtime)
                 .num(6, static_cast<int64_t>(chunks.size())).num(7, now()).run())
            return fail("cannot record version");
    }
    for (const auto& c : chunks) {
        Stmt s(db_, "INSERT INTO version_chunks(file_id,version,idx,chunk_id,len,blob_sha256) VALUES(?1,?2,?3,?4,?5,?6)");
        if (!s.text(1, file_id).num(2, version).num(3, c.idx).text(4, c.chunk_id).num(5, c.len).text(6, c.blob_sha256).run())
            return fail("cannot record chunk");
    }
    Stmt u(db_, "UPDATE files SET state='REPLICATING', current_version=?2, size=?3, mtime=?4 WHERE file_id=?1 AND state='LOCAL' AND generation=?5");
    if (!u.text(1, file_id).num(2, version).num(3, static_cast<int64_t>(size)).num(4, mtime).num(5, f->generation).run() ||
        sqlite3_changes(db_) != 1)
        return fail("file changed concurrently");
    append_event("replication.begin", file_id, version, "", std::to_string(chunks.size()) + " chunks");
    return t.commit() ? ok(std::to_string(version)) : fail("commit failed");
}

Res Ledger::set_replica(const std::string& file_id, int64_t version, const std::string& device_id,
                        ReplicaState state, int64_t device_seq) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    if (state == ReplicaState::COMMITTED && device_seq <= 0)
        return fail("a COMMITTED replica needs the device's commit sequence number");
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    {
        Stmt v(db_, "SELECT 1 FROM versions WHERE file_id=?1 AND version=?2");
        v.text(1, file_id).num(2, version);
        if (!v.row()) return fail("unknown file version");
        Stmt d(db_, "SELECT state FROM devices WHERE device_id=?1");
        d.text(1, device_id);
        if (!d.row()) return fail("unknown device");
        if (d.col_text(0) != "active") return fail("device is retired");
    }
    std::optional<ReplicaState> from;
    {
        Stmt r(db_, "SELECT state FROM replicas WHERE file_id=?1 AND version=?2 AND device_id=?3");
        r.text(1, file_id).num(2, version).text(3, device_id);
        if (r.row()) from = parse_replica_state(r.col_text(0));
    }
    if (!replica_transition_allowed(from, state))
        return fail(std::string("replica transition ") + (from ? to_string(*from) : "(none)") + " -> " + to_string(state) + " is not allowed");
    if (!from) {
        Stmt i(db_, "INSERT INTO replicas(file_id,version,device_id,state) VALUES(?1,?2,?3,?4)");
        if (!i.text(1, file_id).num(2, version).text(3, device_id).text(4, to_string(state)).run()) return fail("cannot record replica");
    } else {
        Stmt u(db_, "UPDATE replicas SET state=?4, committed_at=CASE WHEN ?4='COMMITTED' AND state!='COMMITTED' THEN ?5 ELSE committed_at END,"
                    " device_seq=CASE WHEN ?6>0 THEN ?6 ELSE device_seq END WHERE file_id=?1 AND version=?2 AND device_id=?3 AND state=?7");
        if (!u.text(1, file_id).num(2, version).text(3, device_id).text(4, to_string(state)).num(5, now()).num(6, device_seq)
                 .text(7, to_string(*from)).run() || sqlite3_changes(db_) != 1)
            return fail("replica changed concurrently");
    }
    append_event("replica.state", file_id, version, device_id, to_string(state));
    // Losing the last committed replica of a file that depends on it is not something to hide.
    if (state != ReplicaState::COMMITTED) demote_if_orphaned(file_id, version, device_id, std::string("replica ") + to_string(state));
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::adopt_replica(const std::string& file_id, int64_t version, const std::string& device_id, int64_t device_seq) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    if (device_seq <= 0) return fail("adoption needs the device's commit sequence number");
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    {
        Stmt v(db_, "SELECT 1 FROM versions WHERE file_id=?1 AND version=?2");
        v.text(1, file_id).num(2, version);
        if (!v.row()) return fail("unknown file version (import its manifest first)");
        Stmt d(db_, "SELECT state FROM devices WHERE device_id=?1");
        d.text(1, device_id);
        if (!d.row() || d.col_text(0) != "active") return fail("unknown or retired device");
    }
    Stmt u(db_, "INSERT INTO replicas(file_id,version,device_id,state,committed_at,device_seq) VALUES(?1,?2,?3,'COMMITTED',?4,?5)"
                " ON CONFLICT(file_id,version,device_id) DO UPDATE SET state='COMMITTED', committed_at=excluded.committed_at,"
                " device_seq=excluded.device_seq, last_audit_at=0");
    if (!u.text(1, file_id).num(2, version).text(3, device_id).num(4, now()).num(5, device_seq).run()) return fail("cannot adopt");
    append_event("replica.adopted", file_id, version, device_id, "seq " + std::to_string(device_seq));
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::finish_replication(const std::string& file_id, int64_t version) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (f->state != FileState::REPLICATING) return fail(std::string("file is ") + to_string(f->state) + ", not REPLICATING");
    if (f->current_version != version) return fail("version mismatch");
    {
        Stmt g(db_, "SELECT generation FROM versions WHERE file_id=?1 AND version=?2");
        g.text(1, file_id).num(2, version);
        if (!g.row() || g.col_num(0) != f->generation) return fail("file changed since replication began");
        Stmt c(db_, "SELECT COUNT(*) FROM replicas r JOIN devices d USING(device_id) WHERE r.file_id=?1 AND r.version=?2 AND r.state='COMMITTED' AND d.state='active'");
        c.text(1, file_id).num(2, version);
        if (!c.row() || c.col_num(0) < 1) return fail("no replica is COMMITTED");
    }
    Stmt u(db_, "UPDATE files SET state='REPLICATED' WHERE file_id=?1 AND state='REPLICATING' AND generation=?2");
    if (!u.text(1, file_id).num(2, f->generation).run() || sqlite3_changes(db_) != 1) return fail("file changed concurrently");
    append_event("replication.done", file_id, version, "", "");
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::record_audit(const std::string& file_id, int64_t version, const std::string& device_id,
                         bool good, const std::string& detail) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    Stmt r(db_, "SELECT state FROM replicas WHERE file_id=?1 AND version=?2 AND device_id=?3");
    r.text(1, file_id).num(2, version).text(3, device_id);
    if (!r.row()) return fail("no such replica");
    if (r.col_text(0) != "COMMITTED") return fail("replica is " + r.col_text(0) + ", not COMMITTED");
    if (good) {
        Stmt u(db_, "UPDATE replicas SET last_audit_at=?4 WHERE file_id=?1 AND version=?2 AND device_id=?3 AND state='COMMITTED'");
        if (!u.text(1, file_id).num(2, version).text(3, device_id).num(4, now()).run() || sqlite3_changes(db_) != 1) return fail("replica changed concurrently");
        append_event("audit.ok", file_id, version, device_id, detail);
        return t.commit() ? ok() : fail("commit failed");
    }
    // Demotion plus the AT_RISK check live in set_replica's logic; do it inline so
    // it stays in this transaction.
    Stmt u(db_, "UPDATE replicas SET state='AUDIT_FAILED' WHERE file_id=?1 AND version=?2 AND device_id=?3 AND state='COMMITTED'");
    if (!u.text(1, file_id).num(2, version).text(3, device_id).run() || sqlite3_changes(db_) != 1) return fail("replica changed concurrently");
    append_event("audit.failed", file_id, version, device_id, detail);
    demote_if_orphaned(file_id, version, device_id, "replica failed its audit: " + detail);
    return t.commit() ? ok() : fail("commit failed");
}

std::vector<ReplicaRec> Ledger::get_replicas(const std::string& file_id, int64_t version) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<ReplicaRec> out;
    Stmt s(db_, "SELECT device_id,state,committed_at,last_audit_at,device_seq FROM replicas WHERE file_id=?1 AND version=?2 ORDER BY device_id");
    s.text(1, file_id).num(2, version);
    while (s.row()) {
        ReplicaRec r;
        r.device_id = s.col_text(0);
        r.state = parse_replica_state(s.col_text(1));
        r.committed_at = s.col_num(2);
        r.last_audit_at = s.col_num(3);
        r.device_seq = s.col_num(4);
        out.push_back(r);
    }
    return out;
}

bool Ledger::has_version(const std::string& file_id, int64_t version) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt s(db_, "SELECT 1 FROM versions WHERE file_id=?1 AND version=?2");
    s.text(1, file_id).num(2, version);
    return s.row();
}

std::vector<ChunkRec> Ledger::get_chunks(const std::string& file_id, int64_t version) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<ChunkRec> out;
    Stmt s(db_, "SELECT idx,chunk_id,len,blob_sha256 FROM version_chunks WHERE file_id=?1 AND version=?2 ORDER BY idx");
    s.text(1, file_id).num(2, version);
    while (s.row()) {
        ChunkRec c;
        c.idx = static_cast<uint32_t>(s.col_num(0));
        c.chunk_id = s.col_text(1);
        c.len = static_cast<uint32_t>(s.col_num(2));
        c.blob_sha256 = s.col_text(3);
        out.push_back(c);
    }
    return out;
}

double Ledger::replica_weight(const std::string& file_id, int64_t version, int64_t max_audit_age) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt s(db_, "SELECT COALESCE(SUM(CASE d.class WHEN 'C' THEN 0.5 ELSE 1.0 END),0) FROM replicas r JOIN devices d ON d.device_id=r.device_id"
                " WHERE r.file_id=?1 AND r.version=?2 AND r.state='COMMITTED' AND d.state='active' AND r.last_audit_at>0 AND r.last_audit_at>=?3");
    s.text(1, file_id).num(2, version).num(3, now() - max_audit_age);
    return s.row() ? s.col_real(0) : 0.0;
}

// ---------------------------------------------------------------- orphaned files, devices, challenges

void Ledger::demote_if_orphaned(const std::string& file_id, int64_t version, const std::string& device_id, const std::string& why) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    auto f = load_file(db_, file_id);
    if (!f || f->current_version != version) return;
    if (f->state != FileState::OFFLOADED && f->state != FileState::REPLICATED) return;
    if (has_committed(db_, file_id, version)) return;
    if (f->state == FileState::OFFLOADED) {
        Stmt m(db_, "UPDATE files SET prior_state=state, state='AT_RISK' WHERE file_id=?1 AND state='OFFLOADED'");
        if (m.text(1, file_id).run()) append_event("file.at_risk", file_id, version, device_id, "last committed replica lost: " + why);
    } else {   // still has its bytes: just replicate it again (same version, the engine resumes it)
        Stmt m(db_, "UPDATE files SET state='REPLICATING' WHERE file_id=?1 AND state='REPLICATED'");
        if (m.text(1, file_id).run()) append_event("file.rereplicate", file_id, version, device_id, "last committed replica lost: " + why);
    }
}

void Ledger::reevaluate_for_device(const std::string& device_id, const std::string& why) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<std::pair<std::string, int64_t>> affected;
    {
        Stmt q(db_, "SELECT DISTINCT f.file_id, f.current_version FROM replicas r JOIN files f ON f.file_id=r.file_id AND f.current_version=r.version WHERE r.device_id=?1");
        q.text(1, device_id);
        while (q.row()) affected.emplace_back(q.col_text(0), q.col_num(1));
    }
    for (auto& a : affected) demote_if_orphaned(a.first, a.second, device_id, why);
}

namespace {
DeviceRec device_from(Stmt& s) {
    DeviceRec d;
    d.device_id = s.col_text(0);
    d.name = s.col_text(1);
    d.cls = s.col_text(2);
    d.state = s.col_text(3);
    d.epoch = s.col_num(4);
    d.last_seq = s.col_num(5);
    return d;
}
}  // namespace

std::optional<DeviceRec> Ledger::get_device(const std::string& device_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt s(db_, "SELECT device_id,name,class,state,epoch,last_seq FROM devices WHERE device_id=?1");
    s.text(1, device_id);
    if (!s.row()) return std::nullopt;
    return device_from(s);
}

std::vector<DeviceRec> Ledger::list_devices() {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<DeviceRec> out;
    Stmt s(db_, "SELECT device_id,name,class,state,epoch,last_seq FROM devices ORDER BY device_id");
    while (s.row()) out.push_back(device_from(s));
    return out;
}

DeviceObservation Ledger::observe_device(const std::string& device_id, uint64_t epoch, uint64_t seq) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return DeviceObservation::Unknown;
    auto d = get_device(device_id);
    if (!d) return DeviceObservation::Unknown;
    DeviceObservation result = DeviceObservation::Ok;
    const int64_t e = static_cast<int64_t>(epoch), sq = static_cast<int64_t>(seq);
    if (d->epoch == 0) {
        Stmt u(db_, "UPDATE devices SET epoch=?2, last_seq=?3 WHERE device_id=?1 AND epoch=0");
        if (!u.text(1, device_id).num(2, e).num(3, sq).run() || sqlite3_changes(db_) != 1) return DeviceObservation::Unknown;
        append_event("device.first_seen", "", 0, device_id, "epoch " + std::to_string(e) + " seq " + std::to_string(sq));
        result = DeviceObservation::First;
    } else if (d->epoch != e) {
        Stmt u(db_, "UPDATE devices SET epoch=?2, last_seq=?3, state=CASE WHEN state='retired' THEN 'retired' ELSE 'suspect' END WHERE device_id=?1");
        if (!u.text(1, device_id).num(2, e).num(3, sq).run()) return DeviceObservation::Unknown;
        append_event("device.suspect", "", 0, device_id, "epoch changed " + std::to_string(d->epoch) + " -> " + std::to_string(e));
        reevaluate_for_device(device_id, "device epoch changed");
        result = DeviceObservation::EpochChanged;
    } else if (sq < d->last_seq) {
        Stmt u(db_, "UPDATE devices SET state=CASE WHEN state='retired' THEN 'retired' ELSE 'suspect' END WHERE device_id=?1");
        if (!u.text(1, device_id).run()) return DeviceObservation::Unknown;
        append_event("device.suspect", "", 0, device_id, "sequence went back " + std::to_string(d->last_seq) + " -> " + std::to_string(sq));
        reevaluate_for_device(device_id, "device sequence went backwards");
        result = DeviceObservation::Rollback;   // last_seq stays at the high-water mark: it is still behind until cleared
    } else if (sq > d->last_seq) {
        Stmt u(db_, "UPDATE devices SET last_seq=?2 WHERE device_id=?1");
        if (!u.text(1, device_id).num(2, sq).run()) return DeviceObservation::Unknown;
    }
    return t.commit() ? result : DeviceObservation::Unknown;
}

Res Ledger::clear_device_suspect(const std::string& device_id, uint64_t seq) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    Stmt u(db_, "UPDATE devices SET state='active', last_seq=?2 WHERE device_id=?1 AND state='suspect'");
    if (!u.text(1, device_id).num(2, static_cast<int64_t>(seq)).run() || sqlite3_changes(db_) != 1) return fail("device is not suspect");
    append_event("device.cleared", "", 0, device_id, "seq " + std::to_string(seq));
    return t.commit() ? ok() : fail("commit failed");
}

std::vector<DeviceReplica> Ledger::replicas_on_device(const std::string& device_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<DeviceReplica> out;
    Stmt s(db_, "SELECT file_id, version, state FROM replicas WHERE device_id=?1 ORDER BY file_id, version");
    s.text(1, device_id);
    while (s.row()) out.push_back({s.col_text(0), s.col_num(1), parse_replica_state(s.col_text(2))});
    return out;
}

Res Ledger::set_manifest_hash(const std::string& file_id, int64_t version, const std::string& sha) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    if (sha.size() != 64) return fail("a manifest hash is 64 hex characters");
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    Stmt q(db_, "SELECT manifest_sha256 FROM versions WHERE file_id=?1 AND version=?2");
    q.text(1, file_id).num(2, version);
    if (!q.row()) return fail("unknown file version");
    if (!q.col_null(0)) return q.col_text(0) == sha ? ok() : fail("a different manifest hash is already recorded for this version");
    Stmt u(db_, "UPDATE versions SET manifest_sha256=?3 WHERE file_id=?1 AND version=?2 AND manifest_sha256 IS NULL");
    if (!u.text(1, file_id).num(2, version).text(3, sha).run() || sqlite3_changes(db_) != 1) return fail("version changed concurrently");
    append_event("manifest.hash", file_id, version, "", sha);
    return t.commit() ? ok() : fail("commit failed");
}

std::optional<std::string> Ledger::get_manifest_hash(const std::string& file_id, int64_t version) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt q(db_, "SELECT manifest_sha256 FROM versions WHERE file_id=?1 AND version=?2");
    q.text(1, file_id).num(2, version);
    if (!q.row() || q.col_null(0)) return std::nullopt;
    return q.col_text(0);
}

Res Ledger::add_challenges(const std::string& file_id, int64_t version, int64_t idx, const std::vector<Challenge>& cs) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    for (const auto& c : cs) {
        if (c.response.size() != 64) return fail("a challenge response is 64 hex characters");
        Stmt i(db_, "INSERT INTO chunk_challenges(file_id,version,idx,n,response) VALUES(?1,?2,?3,?4,?5)");
        if (!i.text(1, file_id).num(2, version).num(3, idx).num(4, c.n).text(5, c.response).run()) return fail("cannot record challenge (duplicate n?)");
    }
    return t.commit() ? ok() : fail("commit failed");
}

std::optional<Challenge> Ledger::take_challenge(const std::string& file_id, int64_t version, int64_t idx) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return std::nullopt;
    Challenge c;
    {
        Stmt q(db_, "SELECT n, response FROM chunk_challenges WHERE file_id=?1 AND version=?2 AND idx=?3 AND used=0 ORDER BY n LIMIT 1");
        q.text(1, file_id).num(2, version).num(3, idx);
        if (!q.row()) return std::nullopt;
        c.n = static_cast<uint32_t>(q.col_num(0));
        c.response = q.col_text(1);
    }
    Stmt u(db_, "UPDATE chunk_challenges SET used=1 WHERE file_id=?1 AND version=?2 AND idx=?3 AND n=?4 AND used=0");
    if (!u.text(1, file_id).num(2, version).num(3, idx).num(4, c.n).run() || sqlite3_changes(db_) != 1) return std::nullopt;
    return t.commit() ? std::optional<Challenge>(c) : std::nullopt;   // burned even if the caller never gets to use it
}

size_t Ledger::challenges_left(const std::string& file_id, int64_t version, int64_t idx) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt q(db_, "SELECT COUNT(*) FROM chunk_challenges WHERE file_id=?1 AND version=?2 AND idx=?3 AND used=0");
    q.text(1, file_id).num(2, version).num(3, idx);
    return q.row() ? static_cast<size_t>(q.col_num(0)) : 0;
}

uint32_t Ledger::next_challenge_n(const std::string& file_id, int64_t version, int64_t idx) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt q(db_, "SELECT COALESCE(MAX(n)+1, 0) FROM chunk_challenges WHERE file_id=?1 AND version=?2 AND idx=?3");
    q.text(1, file_id).num(2, version).num(3, idx);
    return q.row() ? static_cast<uint32_t>(q.col_num(0)) : 0;
}

double Ledger::committed_weight(const std::string& file_id, int64_t version) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt s(db_, "SELECT COALESCE(SUM(CASE d.class WHEN 'C' THEN 0.5 ELSE 1.0 END),0) FROM replicas r JOIN devices d ON d.device_id=r.device_id"
                " WHERE r.file_id=?1 AND r.version=?2 AND r.state='COMMITTED' AND d.state='active'");
    s.text(1, file_id).num(2, version);
    return s.row() ? s.col_real(0) : 0.0;
}

// ---------------------------------------------------------------- consent

std::string Ledger::create_consent(const std::string& scope_prefix, int64_t ttl_seconds, const std::string& ack_text) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    if (scope_prefix.empty() || ttl_seconds <= 0) return "";
    Txn t(db_);
    if (!t.began()) return "";
    std::string id = new_id();
    Stmt s(db_, "INSERT INTO consents(consent_id,scope_prefix,created_at,expires_at,ack_text) VALUES(?1,?2,?3,?4,?5)");
    if (!s.text(1, id).text(2, scope_prefix).num(3, now()).num(4, now() + ttl_seconds).text(5, ack_text).run()) return "";
    append_event("consent.created", "", 0, "", scope_prefix + " ttl " + std::to_string(ttl_seconds));
    return t.commit() ? id : "";
}

std::optional<std::string> Ledger::consent_ack(const std::string& consent_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt s(db_, "SELECT ack_text FROM consents WHERE consent_id=?1");
    s.text(1, consent_id);
    if (!s.row()) return std::nullopt;
    return s.col_text(0);
}

// ---------------------------------------------------------------- dropping local bytes

Res Ledger::begin_drop(const std::string& file_id, int64_t version, int64_t generation,
                       const std::string& consent_id, double min_weight, int64_t max_audit_age) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    // Everything below is one IMMEDIATE transaction: the checks and the state
    // change cannot be separated by another writer, and any early return rolls
    // back with nothing changed (fail closed, rule I3).
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");

    if (get_meta("recovery_acked").value_or("") != "1") return fail("recovery phrase not acknowledged");
    if (!has_reserve()) return fail("ledger reserve missing (disk-full safety)");
    if (min_weight <= 0 || max_audit_age <= 0) return fail("policy must require a positive replica weight and a finite audit age");

    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");

    if (get_meta("backup_acked").value_or("") != "1") {
        std::string pre = get_meta("test_prefix").value_or("");
        if (pre.empty() || f->path.compare(0, pre.size(), pre) != 0)
            return fail("backup not acknowledged and path is outside the test prefix");
    }
    {
        Stmt c(db_, "SELECT scope_prefix, expires_at FROM consents WHERE consent_id=?1");
        c.text(1, consent_id);
        if (!c.row()) return fail("no valid consent");
        if (c.col_num(1) <= now()) return fail("consent expired");
        std::string scope = c.col_text(0);
        if (f->path.compare(0, scope.size(), scope) != 0) return fail("consent does not cover this path");
    }
    if (f->state != FileState::REPLICATED) return fail(std::string("file is ") + to_string(f->state) + ", not REPLICATED");
    if (f->current_version != version || version <= 0) return fail("version mismatch");
    if (f->generation != generation) return fail("generation mismatch (file changed)");
    if (!f->local_present) return fail("local bytes not present");
    {
        Stmt g(db_, "SELECT generation FROM versions WHERE file_id=?1 AND version=?2");
        g.text(1, file_id).num(2, version);
        if (!g.row() || g.col_num(0) != f->generation) return fail("replicated bytes are not the current bytes");
    }
    double w = replica_weight(file_id, version, max_audit_age);
    if (w < min_weight) {
        char buf[96];
        snprintf(buf, sizeof buf, "insufficient replica weight (have %.1f, need %.1f)", w, min_weight);
        return fail(buf);
    }

    std::string intent = new_id();
    Stmt u(db_, "UPDATE files SET state='DROPPING' WHERE file_id=?1 AND state='REPLICATED' AND generation=?2 AND current_version=?3 AND local_present=1");
    if (!u.text(1, file_id).num(2, generation).num(3, version).run() || sqlite3_changes(db_) != 1) return fail("file changed concurrently");
    char payload[96];
    snprintf(payload, sizeof payload, "%.3f|%lld", min_weight, static_cast<long long>(max_audit_age));
    Stmt i(db_, "INSERT INTO intents(intent_id,kind,file_id,version,generation,payload,state,created_at) VALUES(?1,'DROP_LOCAL',?2,?3,?4,?5,'open',?6)");
    if (!i.text(1, intent).text(2, file_id).num(3, version).num(4, generation).text(5, payload).num(6, now()).run())
        return fail("cannot record intent");
    append_event("drop.begin", file_id, version, "", "intent " + intent + " consent " + consent_id);
    crash_point("ledger.drop.before_commit");
    if (!t.commit()) return fail("commit failed");
    crash_point("ledger.drop.after_commit");
    return ok(intent);
}

Res Ledger::complete_drop(const std::string& intent_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    Stmt q(db_, "SELECT file_id,version,generation,payload FROM intents WHERE intent_id=?1 AND kind='DROP_LOCAL' AND state='open'");
    q.text(1, intent_id);
    if (!q.row()) return fail("no such open drop intent");
    std::string file_id = q.col_text(0);
    int64_t version = q.col_num(1), generation = q.col_num(2);
    double min_weight = 0;
    long long max_age = 0;
    if (sscanf(q.col_text(3).c_str(), "%lf|%lld", &min_weight, &max_age) != 2 || min_weight <= 0 || max_age <= 0)
        return fail("intent payload unreadable");
    auto f = load_file(db_, file_id);
    if (!f || f->state != FileState::DROPPING || f->current_version != version || f->generation != generation)
        return fail("file is no longer in the state this drop was prepared for");
    // Completion repeats the replica check: a failed audit between A and B, or a
    // recovery that took hours, must not slip through on stale evidence.
    double w = replica_weight(file_id, version, max_age);
    if (w < min_weight) {
        char buf[96];
        snprintf(buf, sizeof buf, "replicas no longer satisfy the policy (have %.1f, need %.1f): re-audit or abort", w, min_weight);
        return fail(buf);
    }
    Stmt u(db_, "UPDATE files SET state='OFFLOADED', local_present=0 WHERE file_id=?1 AND state='DROPPING' AND generation=?2");
    if (!u.text(1, file_id).num(2, generation).run() || sqlite3_changes(db_) != 1) return fail("file changed concurrently");
    Stmt d(db_, "UPDATE intents SET state='done', done_at=?2 WHERE intent_id=?1 AND state='open'");
    if (!d.text(1, intent_id).num(2, now()).run() || sqlite3_changes(db_) != 1) return fail("intent changed concurrently");
    Stmt qi(db_, "INSERT INTO quarantine(intent_id,file_id,version,state,held_at) VALUES(?1,?2,?3,'held',?4)");
    if (!qi.text(1, intent_id).text(2, file_id).num(3, version).num(4, now()).run()) return fail("cannot record the quarantine");
    append_event("drop.complete", file_id, version, "", "intent " + intent_id);
    crash_point("ledger.complete.before_commit");
    if (!t.commit()) return fail("commit failed");
    crash_point("ledger.complete.after_commit");
    return ok();
}

Res Ledger::abort_drop(const std::string& intent_id, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    Stmt q(db_, "SELECT file_id,version,generation FROM intents WHERE intent_id=?1 AND kind='DROP_LOCAL' AND state='open'");
    q.text(1, intent_id);
    if (!q.row()) return fail("no such open drop intent");
    std::string file_id = q.col_text(0);
    int64_t version = q.col_num(1), generation = q.col_num(2);
    Stmt u(db_, "UPDATE files SET state='REPLICATED', local_present=1 WHERE file_id=?1 AND state='DROPPING' AND generation=?2");
    if (!u.text(1, file_id).num(2, generation).run() || sqlite3_changes(db_) != 1) return fail("file is not DROPPING for this intent");
    Stmt d(db_, "UPDATE intents SET state='aborted', done_at=?2 WHERE intent_id=?1 AND state='open'");
    if (!d.text(1, intent_id).num(2, now()).run() || sqlite3_changes(db_) != 1) return fail("intent changed concurrently");
    append_event("drop.abort", file_id, version, "", reason);
    return t.commit() ? ok() : fail("commit failed");
}

std::vector<IntentRec> Ledger::open_intents() {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<IntentRec> out;
    Stmt s(db_, "SELECT intent_id,kind,file_id,version,generation,payload FROM intents WHERE state='open' ORDER BY created_at, intent_id");
    while (s.row()) {
        IntentRec r;
        r.intent_id = s.col_text(0);
        r.kind = s.col_text(1);
        r.file_id = s.col_text(2);
        r.version = s.col_num(3);
        r.generation = s.col_num(4);
        r.payload = s.col_text(5);
        out.push_back(r);
    }
    return out;
}

// ---------------------------------------------------------------- quarantine

namespace {
QuarantineState parse_qstate(const std::string& s) {
    if (s == "held") return QuarantineState::HELD;
    if (s == "purging") return QuarantineState::PURGING;
    if (s == "purged") return QuarantineState::PURGED;
    if (s == "restoring") return QuarantineState::RESTORING;
    return QuarantineState::RESTORED;
}
QuarantineRec quarantine_from(Stmt& s) {
    QuarantineRec q;
    q.intent_id = s.col_text(0);
    q.file_id = s.col_text(1);
    q.version = s.col_num(2);
    q.state = parse_qstate(s.col_text(3));
    q.held_at = s.col_num(4);
    q.resolved_at = s.col_num(5);
    q.note = s.col_text(6);
    return q;
}
const char* const QCOLS = "intent_id,file_id,version,state,held_at,resolved_at,note";
}  // namespace

std::optional<QuarantineRec> Ledger::get_quarantine(const std::string& intent_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt s(db_, (std::string("SELECT ") + QCOLS + " FROM quarantine WHERE intent_id=?1").c_str());
    s.text(1, intent_id);
    if (!s.row()) return std::nullopt;
    return quarantine_from(s);
}

std::vector<QuarantineRec> Ledger::list_quarantine(std::optional<QuarantineState> state) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<QuarantineRec> out;
    std::string q = std::string("SELECT ") + QCOLS + " FROM quarantine";
    if (state) q += std::string(" WHERE state='") + to_string(*state) + "'";
    q += " ORDER BY held_at, intent_id";
    Stmt s(db_, q.c_str());
    while (s.row()) out.push_back(quarantine_from(s));
    return out;
}

Res Ledger::begin_purge(const std::string& intent_id, int64_t retention_seconds, bool emergency, double min_weight, int64_t max_audit_age) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    if (get_meta("recovery_acked").value_or("") != "1") return fail("recovery phrase not acknowledged");
    if (!has_reserve()) return fail("ledger reserve missing (disk-full safety)");
    if (min_weight <= 0 || max_audit_age <= 0 || retention_seconds < 0) return fail("policy must require a positive replica weight and a finite audit age");
    auto q = get_quarantine(intent_id);
    if (!q) return fail("no such quarantine");
    if (q->state != QuarantineState::HELD && q->state != QuarantineState::PURGING)
        return fail(std::string("quarantine is ") + to_string(q->state) + ", not HELD");
    auto f = load_file(db_, q->file_id);
    if (!f) return fail("unknown file");
    if (get_meta("backup_acked").value_or("") != "1") {
        std::string pre = get_meta("test_prefix").value_or("");
        if (pre.empty() || f->path.compare(0, pre.size(), pre) != 0)
            return fail("backup not acknowledged and path is outside the test prefix");
    }
    // AT_RISK means a replica was lost while the bytes sat in quarantine: they may be the only good copy.
    if (f->state != FileState::OFFLOADED && f->state != FileState::REPLICATED)
        return fail(std::string("file is ") + to_string(f->state) + "; restore the quarantined bytes instead of deleting them");
    if (!emergency && now() - q->held_at < retention_seconds) return fail("the quarantine period has not elapsed");
    double w = replica_weight(q->file_id, q->version, max_audit_age);
    if (w < min_weight) {
        char buf[110];
        snprintf(buf, sizeof buf, "insufficient replica weight to delete the quarantined bytes (have %.1f, need %.1f)", w, min_weight);
        return fail(buf);
    }
    if (q->state == QuarantineState::HELD) {
        Stmt u(db_, "UPDATE quarantine SET state='purging' WHERE intent_id=?1 AND state='held'");
        if (!u.text(1, intent_id).run() || sqlite3_changes(db_) != 1) return fail("quarantine changed concurrently");
        append_event("purge.begin", q->file_id, q->version, "", "intent " + intent_id + (emergency ? " (emergency)" : ""));
    }
    crash_point("ledger.purge.before_commit");
    if (!t.commit()) return fail("commit failed");
    crash_point("ledger.purge.after_commit");
    return ok();
}

Res Ledger::complete_purge(const std::string& intent_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto q = get_quarantine(intent_id);
    if (!q) return fail("no such quarantine");
    Stmt u(db_, "UPDATE quarantine SET state='purged', resolved_at=?2 WHERE intent_id=?1 AND state='purging'");
    if (!u.text(1, intent_id).num(2, now()).run() || sqlite3_changes(db_) != 1)
        return fail(std::string("quarantine is ") + to_string(q->state) + ", not PURGING");
    append_event("purge.complete", q->file_id, q->version, "", "intent " + intent_id);
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::begin_restore(const std::string& intent_id, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto q = get_quarantine(intent_id);
    if (!q) return fail("no such quarantine");
    if (q->state != QuarantineState::HELD && q->state != QuarantineState::RESTORING)
        return fail(std::string("quarantine is ") + to_string(q->state) + ", not HELD");
    auto f = load_file(db_, q->file_id);
    if (!f) return fail("unknown file");
    if (f->state != FileState::OFFLOADED && f->state != FileState::AT_RISK)
        return fail(std::string("file is ") + to_string(f->state) + "; only OFFLOADED or AT_RISK files can be restored from quarantine");
    if (q->state == QuarantineState::HELD) {
        Stmt u(db_, "UPDATE quarantine SET state='restoring', note=?2 WHERE intent_id=?1 AND state='held'");
        if (!u.text(1, intent_id).text(2, reason).run() || sqlite3_changes(db_) != 1) return fail("quarantine changed concurrently");
        append_event("restore.begin", q->file_id, q->version, "", "intent " + intent_id + ": " + reason);
    }
    crash_point("ledger.restore.before_commit");
    if (!t.commit()) return fail("commit failed");
    return ok();
}

Res Ledger::complete_restore(const std::string& intent_id, bool bytes_verified) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto q = get_quarantine(intent_id);
    if (!q) return fail("no such quarantine");
    if (q->state != QuarantineState::RESTORING) return fail(std::string("quarantine is ") + to_string(q->state) + ", not RESTORING");
    auto f = load_file(db_, q->file_id);
    if (!f) return fail("unknown file");
    if (f->state != FileState::OFFLOADED && f->state != FileState::AT_RISK)
        return fail(std::string("file is ") + to_string(f->state) + "; cannot complete the restore");
    bool as_replicated = bytes_verified && q->version == f->current_version && has_committed(db_, q->file_id, q->version);
    if (as_replicated) {
        Stmt u(db_, "UPDATE files SET state='REPLICATED', prior_state=NULL, local_present=1 WHERE file_id=?1 AND state=?2");
        if (!u.text(1, q->file_id).text(2, to_string(f->state)).run() || sqlite3_changes(db_) != 1) return fail("file changed concurrently");
    } else {   // we cannot vouch for these bytes: they are LOCAL data again, and anything prepared against the old state is void
        Stmt u(db_, "UPDATE files SET state='LOCAL', prior_state=NULL, local_present=1, generation=generation+1 WHERE file_id=?1 AND state=?2");
        if (!u.text(1, q->file_id).text(2, to_string(f->state)).run() || sqlite3_changes(db_) != 1) return fail("file changed concurrently");
    }
    Stmt qu(db_, "UPDATE quarantine SET state='restored', resolved_at=?2 WHERE intent_id=?1 AND state='restoring'");
    if (!qu.text(1, intent_id).num(2, now()).run() || sqlite3_changes(db_) != 1) return fail("quarantine changed concurrently");
    append_event("restore.complete", q->file_id, q->version, "", std::string("intent ") + intent_id + (as_replicated ? " (as REPLICATED)" : " (as LOCAL: bytes not vouched for)"));
    return t.commit() ? ok() : fail("commit failed");
}

// ---------------------------------------------------------------- recall / risk

namespace {
bool has_committed(sqlite3* db, const std::string& file_id, int64_t version) {
    Stmt c(db, "SELECT COUNT(*) FROM replicas r JOIN devices d USING(device_id) WHERE r.file_id=?1 AND r.version=?2 AND r.state='COMMITTED' AND d.state='active'");
    c.text(1, file_id).num(2, version);
    return c.row() && c.col_num(0) >= 1;
}
}  // namespace

Res Ledger::begin_hydrate(const std::string& file_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (f->state != FileState::OFFLOADED) return fail(std::string("file is ") + to_string(f->state) + ", not OFFLOADED");
    if (!has_committed(db_, file_id, f->current_version)) return fail("no committed replica to hydrate from");
    Stmt u(db_, "UPDATE files SET state='HYDRATING' WHERE file_id=?1 AND state='OFFLOADED'");
    if (!u.text(1, file_id).run() || sqlite3_changes(db_) != 1) return fail("file changed concurrently");
    append_event("hydrate.begin", file_id, f->current_version, "", "");
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::complete_hydrate(const std::string& file_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    Stmt u(db_, "UPDATE files SET state='REPLICATED', local_present=1 WHERE file_id=?1 AND state='HYDRATING'");
    if (!u.text(1, file_id).run() || sqlite3_changes(db_) != 1) return fail(std::string("file is ") + to_string(f->state) + ", not HYDRATING");
    append_event("hydrate.complete", file_id, f->current_version, "", "");
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::abort_hydrate(const std::string& file_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    Stmt u(db_, "UPDATE files SET state='OFFLOADED', local_present=0 WHERE file_id=?1 AND state='HYDRATING'");
    if (!u.text(1, file_id).run() || sqlite3_changes(db_) != 1) return fail(std::string("file is ") + to_string(f->state) + ", not HYDRATING");
    append_event("hydrate.abort", file_id, f->current_version, "", "");
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::mark_at_risk(const std::string& file_id, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (f->state == FileState::DROPPING) return fail("resolve the open drop first (complete_drop or abort_drop)");
    if (f->state == FileState::AT_RISK) return ok();
    Stmt u(db_, "UPDATE files SET prior_state=state, state='AT_RISK' WHERE file_id=?1 AND state=?2");
    if (!u.text(1, file_id).text(2, to_string(f->state)).run() || sqlite3_changes(db_) != 1) return fail("file changed concurrently");
    append_event("file.at_risk", file_id, f->current_version, "", reason);
    return t.commit() ? ok() : fail("commit failed");
}

Res Ledger::clear_at_risk(const std::string& file_id) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Txn t(db_);
    if (!t.began()) return fail("cannot begin transaction");
    auto f = load_file(db_, file_id);
    if (!f) return fail("unknown file");
    if (f->state != FileState::AT_RISK) return fail("file is not AT_RISK");
    bool remote = f->current_version > 0 && has_committed(db_, file_id, f->current_version);
    const char* to;
    if (f->local_present) to = remote ? "REPLICATED" : "LOCAL";
    else if (remote) to = "OFFLOADED";
    else return fail("no committed replica and no local bytes: cannot clear (the data may be lost)");
    Stmt u(db_, "UPDATE files SET state=?2, prior_state=NULL WHERE file_id=?1 AND state='AT_RISK'");
    if (!u.text(1, file_id).text(2, to).run() || sqlite3_changes(db_) != 1) return fail("file changed concurrently");
    append_event("file.risk_cleared", file_id, f->current_version, "", to);
    return t.commit() ? ok() : fail("commit failed");
}

// ---------------------------------------------------------------- integrity

uint64_t Ledger::event_count() {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    Stmt s(db_, "SELECT COUNT(*) FROM events");
    return s.row() ? static_cast<uint64_t>(s.col_num(0)) : 0;
}

bool Ledger::snapshot_to(const std::string& path) {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) return false;
    std::string q = "VACUUM INTO '";
    for (char c : path) { if (c == '\'') q += '\''; q += c; }
    q += "'";
    return exec(q.c_str());
}

std::vector<std::string> Ledger::fsck() {
    std::lock_guard<std::recursive_mutex> lock_(mu_);
    std::vector<std::string> bad;
    auto report = [&](const std::string& m) { bad.push_back(m); };
    {
        Stmt ic(db_, "PRAGMA integrity_check");
        if (!ic.row() || ic.col_text(0) != "ok") report("SQLite integrity_check failed");
        Stmt fk(db_, "PRAGMA foreign_key_check");
        if (fk.row()) report("foreign key violation: " + fk.col_text(0));
    }
    {   // hash chain, contiguous sequence numbers
        Stmt e(db_, "SELECT seq,ts,kind,file_id,version,device_id,detail,prev_hash,hash FROM events ORDER BY seq");
        int64_t expect = 1;
        std::string prev = GENESIS;
        while (e.row()) {
            int64_t seq = e.col_num(0);
            if (seq != expect) { report("events: gap or reorder at seq " + std::to_string(seq) + " (expected " + std::to_string(expect) + ")"); expect = seq; }
            if (e.col_text(7) != prev) report("events: broken chain at seq " + std::to_string(seq));
            std::string h = event_hash(seq, e.col_num(1), e.col_text(2), e.col_text(3), e.col_num(4), e.col_text(5), e.col_text(6), e.col_text(7));
            if (h != e.col_text(8)) report("events: hash mismatch at seq " + std::to_string(seq) + " (row altered)");
            prev = e.col_text(8);
            expect = seq + 1;
        }
    }
    auto each = [&](const char* sql, const char* what) {
        Stmt s(db_, sql);
        while (s.row()) report(std::string(what) + ": " + s.col_text(0));
    };
    each("SELECT path FROM files WHERE state='OFFLOADED' AND local_present!=0", "OFFLOADED file claims local bytes");
    each("SELECT path FROM files f WHERE state='OFFLOADED' AND NOT EXISTS (SELECT 1 FROM replicas r JOIN devices d USING(device_id) WHERE r.file_id=f.file_id AND r.version=f.current_version AND r.state='COMMITTED' AND d.state='active')",
         "OFFLOADED file with no committed replica");
    each("SELECT path FROM files f WHERE state='REPLICATED' AND (local_present=0 OR NOT EXISTS (SELECT 1 FROM replicas r JOIN devices d USING(device_id) WHERE r.file_id=f.file_id AND r.version=f.current_version AND r.state='COMMITTED' AND d.state='active'))",
         "REPLICATED file lacks local bytes or a committed replica");
    each("SELECT path FROM files WHERE state IN('LOCAL','REPLICATING') AND local_present=0", "LOCAL/REPLICATING file without local bytes");
    each("SELECT path FROM files f WHERE state='DROPPING' AND NOT EXISTS (SELECT 1 FROM intents i WHERE i.file_id=f.file_id AND i.kind='DROP_LOCAL' AND i.state='open' AND i.version=f.current_version AND i.generation=f.generation)",
         "DROPPING file without a matching open intent");
    each("SELECT f.path FROM intents i JOIN files f USING(file_id) WHERE i.kind='DROP_LOCAL' AND i.state='open' AND f.state!='DROPPING'",
         "open drop intent for a file that is not DROPPING");
    each("SELECT q.intent_id FROM quarantine q LEFT JOIN intents i ON i.intent_id=q.intent_id WHERE i.state IS NOT 'done' OR i.kind IS NOT 'DROP_LOCAL'",
         "quarantine without a completed drop");
    each("SELECT f.path FROM quarantine q JOIN files f USING(file_id) WHERE q.state IN('held','purging','restoring') AND f.state IN('LOCAL','REPLICATING') AND f.local_present=0",
         "file lost its bytes with a quarantine still open");
    each("SELECT path FROM files WHERE current_version>0 AND NOT EXISTS (SELECT 1 FROM versions v WHERE v.file_id=files.file_id AND v.version=files.current_version)",
         "current version has no record");
    each("SELECT f.path FROM versions v JOIN files f USING(file_id) WHERE v.chunk_count != (SELECT COUNT(*) FROM version_chunks c WHERE c.file_id=v.file_id AND c.version=v.version)",
         "version chunk count does not match its chunk rows");
    each("SELECT f.path FROM versions v JOIN files f USING(file_id) WHERE v.size != COALESCE((SELECT SUM(len) FROM version_chunks c WHERE c.file_id=v.file_id AND c.version=v.version),0)",
         "version size does not match its chunk lengths");
    each("SELECT f.path FROM replicas r JOIN files f USING(file_id) WHERE r.state='COMMITTED' AND r.device_seq<=0",
         "COMMITTED replica without a device sequence number");
    return bad;
}

}  // namespace tierfs
