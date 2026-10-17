#include "devicestore.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include <map>
#include <thread>

#include "crashpoint.hpp"
#include "fsutil.hpp"
#include "crypto.hpp"
#include "sqlutil.hpp"

namespace tierfs {
namespace {

using sql::Stmt;
using sql::Txn;
namespace fs = std::filesystem;

constexpr int SCHEMA_VERSION =
    2;  // 2: reference lists, the guarded delete triggers, chunk_touch and gc_log (ADR-0010); version 1 is migrated on open

// A trash file's name carries the time it went in. Two things trashed in the same second must not overwrite each other (nor may a manifest and its chunk
// list end up with different times): take the first second from `t` on for which none of the names is taken. Purging is delayed by that much, no more.
int64_t free_trash_time(const std::string& dir, const std::string& stem, int64_t t, std::initializer_list<const char*> exts) {
    for (;; t++) {
        bool taken = false;
        for (const char* e : exts) {
            struct stat st;
            if (lstat((dir + "/" + stem + "." + std::to_string(t) + "." + e).c_str(), &st) == 0) taken = true;
        }
        if (!taken) return t;
    }
}

bool is_lower_hex(const std::string& s, size_t n) {
    if (s.size() != n) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

// macOS fsync() does not force the drive to flush its cache; F_FULLFSYNC does.
void full_sync(int fd) { fsutil::full_sync(fd); }

void sync_dir(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd >= 0) {
        full_sync(fd);
        close(fd);
    }
}

// mkdir -p where every directory we create is itself made durable (its parent is synced).
int make_dir_durable(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) return S_ISDIR(st.st_mode) ? 0 : ENOTDIR;
    std::string parent = fs::path(path).parent_path().string();
    if (!parent.empty() && parent != path) {
        int rc = make_dir_durable(parent);
        if (rc) return rc;
    }
    if (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) return errno;
    sync_dir(parent.empty() ? "." : parent);
    return 0;
}

std::string first_n(const std::string& s, size_t n) { return s.substr(0, n); }

std::atomic<uint64_t> g_tmp_counter{0};

}  // namespace

bool valid_chunk_id(const std::string& s) { return is_lower_hex(s, 64); }
bool valid_file_id(const std::string& s) { return is_lower_hex(s, 32); }

bool DeviceFaults::parse(const std::string& csv, DeviceFaults* out, std::string* err) {
    DeviceFaults f;
    size_t pos = 0;
    while (pos <= csv.size()) {
        size_t comma = csv.find(',', pos);
        std::string name = csv.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        pos = comma == std::string::npos ? csv.size() + 1 : comma + 1;
        if (name.empty()) continue;
        if (name == "lie_ack_chunk") f.lie_ack_chunk = true;
        else if (name == "lie_ack_manifest") f.lie_ack_manifest = true;
        else if (name == "corrupt_on_store") f.corrupt_on_store = true;
        else if (name == "truncate_on_store") f.truncate_on_store = true;
        else if (name == "swap_get") f.swap_get = true;
        else if (name == "lose_manifest_after_commit") f.lose_manifest_after_commit = true;
        else if (name == "enospc") f.enospc = true;
        else if (name == "drop_connection_after_put") f.drop_connection_after_put = true;
        else if (name.compare(0, 5, "slow=") == 0) f.slow_ms = atoi(name.c_str() + 5);
        else {
            if (err) *err = "unknown fault '" + name + "'";
            return false;
        }
    }
    *out = f;
    return true;
}

// ---------------------------------------------------------------- open / schema

std::unique_ptr<DeviceStore> DeviceStore::open(const std::string& dir, std::string* err) {
    auto bad = [&](const std::string& m) -> std::unique_ptr<DeviceStore> {
        if (err) *err = m;
        return nullptr;
    };
    std::error_code ec;
    fs::create_directories(dir + "/tmp", ec);
    fs::create_directories(dir + "/chunks", ec);
    fs::create_directories(dir + "/manifests", ec);
    if (ec) return bad("cannot create " + dir + ": " + ec.message());

    std::unique_ptr<DeviceStore> d(new DeviceStore);
    d->dir_ = dir;
    d->lock_fd_ = ::open((dir + "/lock").c_str(), O_CREAT | O_RDWR, 0600);
    if (d->lock_fd_ < 0) return bad("cannot create lock file");
    if (flock(d->lock_fd_, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) return bad("device store is in use by another process");
        // Some filesystems cannot lock at all (shared storage on a phone, some network mounts): say so, instead of blaming another process.
        return bad(std::string("this filesystem cannot lock the store directory (") + strerror(errno) + "): put the store on a local disk");
    }

    // Half-written uploads from a previous crash. They were never acknowledged, so they
    // are safe to drop; they live in tmp/ precisely so this is the only place we delete.
    for (auto& e : fs::directory_iterator(dir + "/tmp", ec)) fs::remove(e.path(), ec);

    std::string e;
    if (!d->init(&e)) return bad(e);
    return d;
}

DeviceStore::~DeviceStore() {
    if (db_) sqlite3_close(db_);
    if (lock_fd_ >= 0) close(lock_fd_);
}

bool DeviceStore::exec(const char* sql) {
    char* e = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &e) == SQLITE_OK) return true;
    fprintf(stderr, "tierfs device: %s\n", e ? e : "error");
    sqlite3_free(e);
    return false;
}

bool DeviceStore::init(std::string* err) {
    std::string path = dir_ + "/device.db";
    std::error_code ec;
    bool existed = fs::exists(path, ec) && fs::file_size(path, ec) > 0;
    if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
        *err = "cannot open " + path;
        return false;
    }
    sqlite3_busy_timeout(db_, 5000);
    if (existed) {
        Stmt ic(db_, "PRAGMA integrity_check");
        if (!ic.valid() || !ic.row() || ic.col_text(0) != "ok") {
            *err = path + " failed its integrity check; refusing to touch it";
            return false;
        }
    }
    int version = 0;
    long tables = 0;
    {
        Stmt v(db_, "PRAGMA user_version");
        if (v.valid() && v.row()) version = static_cast<int>(v.col_num(0));
        Stmt t(db_, "SELECT COUNT(*) FROM sqlite_master");
        if (t.valid() && t.row()) tables = static_cast<long>(t.col_num(0));
        else { *err = path + " is not a readable database; refusing to touch it"; return false; }
    }
    if (version != 0 && version != SCHEMA_VERSION && version != 1) {
        *err = "device store schema version " + std::to_string(version) + " is not understood by this build; refusing to touch it";
        return false;
    }
    if (version == 0 && tables != 0) { *err = path + " has tables but no version; refusing to touch it"; return false; }

    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA synchronous=FULL");
    exec("PRAGMA fullfsync=ON");
    exec("PRAGMA checkpoint_fullfsync=ON");
    auto pragma_is = [&](const char* q, const std::string& want) {
        Stmt s(db_, q);
        return s.valid() && s.row() && s.col_text(0) == want;
    };
    if (!pragma_is("PRAGMA journal_mode", "wal") || !pragma_is("PRAGMA synchronous", "2") ||
        !pragma_is("PRAGMA fullfsync", "1") || !pragma_is("PRAGMA checkpoint_fullfsync", "1")) {
        *err = "cannot enable full-fsync durability settings";
        return false;
    }
    if (version == 1) return migrate_1_to_2() ? true : (*err = "cannot upgrade the device store to schema version 2; it was left as it was", false);
    if (version != 0) {
        exec("UPDATE meta SET value='0' WHERE key='gc_open'");  // only ever 1 inside a transaction that rolled back or committed it back to 0
        return true;
    }

    Txn t(db_);
    if (!t.began()) { *err = "cannot begin"; return false; }
    const char* ddl[] = {
        "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
        "CREATE TABLE chunks(chunk_id TEXT PRIMARY KEY, size INTEGER NOT NULL, sha256 TEXT NOT NULL, created_at INTEGER NOT NULL) WITHOUT ROWID",
        "CREATE TABLE manifests(file_id TEXT NOT NULL, version INTEGER NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,"
        " seq INTEGER NOT NULL UNIQUE, created_at INTEGER NOT NULL, PRIMARY KEY(file_id, version)) WITHOUT ROWID",
        // Append-only: the device cannot be told to forget (I4), and a bug cannot either.
        "CREATE TRIGGER chunks_append_only_u BEFORE UPDATE ON chunks BEGIN SELECT RAISE(ABORT,'append-only'); END",
        "CREATE TRIGGER manifests_append_only_u BEFORE UPDATE ON manifests BEGIN SELECT RAISE(ABORT,'append-only'); END",
        "CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta BEGIN SELECT RAISE(ABORT,'meta rows are never deleted'); END",
        // Identity never changes; a volume binding never changes once set; seq only goes up.
        "CREATE TRIGGER meta_fixed_identity BEFORE UPDATE ON meta WHEN OLD.key IN ('device_id','epoch','created_at')"
        " BEGIN SELECT RAISE(ABORT,'device identity is fixed'); END",
        "CREATE TRIGGER meta_volume_once BEFORE UPDATE ON meta WHEN OLD.key='volume_id' AND OLD.value!=''"
        " BEGIN SELECT RAISE(ABORT,'device is bound to a volume for good'); END",
        "CREATE TRIGGER meta_seq_monotonic BEFORE UPDATE ON meta WHEN OLD.key='seq' AND CAST(NEW.value AS INTEGER)<=CAST(OLD.value AS INTEGER)"
        " BEGIN SELECT RAISE(ABORT,'commit sequence only goes up'); END",
    };
    for (const char* q : ddl)
        if (!exec(q)) { *err = std::string("schema: ") + q; return false; }
    if (!create_gc_schema()) {
        *err = "schema: garbage collection tables";
        return false;
    }
    crypto::Bytes id = crypto::random_bytes(16), ep = crypto::random_bytes(8);
    if (id.size() != 16 || ep.size() != 8) { *err = "system RNG failed"; return false; }
    uint64_t epoch = 0;
    for (uint8_t b : ep) epoch = (epoch << 8) | b;
    epoch &= 0x7fffffffffffffffull;  // keep it a positive SQLite integer
    auto put = [&](const char* k, const std::string& v) {
        Stmt s(db_, "INSERT INTO meta(key,value) VALUES(?1,?2)");
        return s.text(1, k).text(2, v).run();
    };
    if (!put("device_id", crypto::to_hex(id.data(), id.size())) || !put("epoch", std::to_string(epoch)) || !put("volume_id", "") ||
        !put("seq", "0") || !put("created_at", std::to_string(time(nullptr)))) {
        *err = "cannot initialise";
        return false;
    }
    if (!exec(("PRAGMA user_version=" + std::to_string(SCHEMA_VERSION)).c_str()) || !t.commit()) { *err = "cannot commit"; return false; }
    return true;
}

std::string DeviceStore::meta_get(const std::string& key) {
    Stmt s(db_, "SELECT value FROM meta WHERE key=?1");
    s.text(1, key);
    return s.row() ? s.col_text(0) : "";
}

// Everything schema version 2 adds, inside the caller's transaction. Deleting a chunk or a manifest is possible only inside a transaction
// that has set meta gc_open to 1, and a chunk that any stored manifest lists can never be deleted at all (the trigger does not look at gc_open).
bool DeviceStore::create_gc_schema() {
    const char* ddl[] = {
        "CREATE TABLE manifest_refs(file_id TEXT NOT NULL, version INTEGER NOT NULL, chunk_id TEXT NOT NULL,"
        " PRIMARY KEY(file_id, version, chunk_id)) WITHOUT ROWID",
        "CREATE INDEX manifest_refs_by_chunk ON manifest_refs(chunk_id)",
        "CREATE TABLE refs_done(file_id TEXT NOT NULL, version INTEGER NOT NULL, PRIMARY KEY(file_id, version)) WITHOUT ROWID",
        "CREATE TABLE chunk_touch(chunk_id TEXT PRIMARY KEY, at INTEGER NOT NULL) WITHOUT ROWID",
        "CREATE TABLE gc_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, item TEXT NOT NULL,"
        " version INTEGER NOT NULL, size INTEGER NOT NULL)",
        "CREATE TRIGGER gc_log_no_update BEFORE UPDATE ON gc_log BEGIN SELECT RAISE(ABORT,'the deletion log is append-only'); END",
        "CREATE TRIGGER gc_log_no_delete BEFORE DELETE ON gc_log BEGIN SELECT RAISE(ABORT,'the deletion log is append-only'); END",
        "CREATE TRIGGER chunks_delete_guard BEFORE DELETE ON chunks WHEN (SELECT value FROM meta WHERE key='gc_open')!='1'"
        " BEGIN SELECT RAISE(ABORT,'append-only outside a sweep'); END",
        "CREATE TRIGGER chunks_delete_listed BEFORE DELETE ON chunks WHEN EXISTS(SELECT 1 FROM manifest_refs WHERE chunk_id=OLD.chunk_id)"
        " BEGIN SELECT RAISE(ABORT,'a stored manifest still lists this chunk'); END",
        "CREATE TRIGGER manifests_delete_guard BEFORE DELETE ON manifests WHEN (SELECT value FROM meta WHERE key='gc_open')!='1'"
        " BEGIN SELECT RAISE(ABORT,'append-only outside a deletion'); END",
        "INSERT INTO meta(key,value) VALUES('gc_open','0')",
    };
    for (const char* q : ddl)
        if (!exec(q)) return false;
    return true;
}

bool DeviceStore::migrate_1_to_2() {
    Txn t(db_);
    if (!t.began()) return false;
    if (!exec("DROP TRIGGER IF EXISTS chunks_append_only_d") || !exec("DROP TRIGGER IF EXISTS manifests_append_only_d") || !create_gc_schema())
        return false;
    // The manifests stored so far have no reference lists: sweeping stays refused until the Mac re-sends them (backfill in put_manifest).
    if (!exec("PRAGMA user_version=2") || !t.commit()) return false;
    return true;
}

int DeviceStore::count_refless_locked() {
    Stmt q(db_, "SELECT COUNT(*) FROM manifests m WHERE NOT EXISTS(SELECT 1 FROM refs_done r WHERE r.file_id=m.file_id AND r.version=m.version)");
    return q.row() ? static_cast<int>(q.col_num(0)) : 1 << 30;  // unreadable: count as unknown, which refuses a sweep
}

// A chunk that no manifest lists is a sweep candidate: remember that the Mac mentioned it, so one it is about to use is not swept.
void DeviceStore::touch_unreferenced_locked(const std::vector<std::string>& ids) {
    std::vector<std::string> todo;
    for (const auto& id : ids) {
        Stmt q(db_, "SELECT 1 FROM manifest_refs WHERE chunk_id=?1 LIMIT 1");
        q.text(1, id);
        if (!q.row()) todo.push_back(id);
    }
    if (todo.empty()) return;
    Txn t(db_);
    if (!t.began()) return;
    for (const auto& id : todo) {
        Stmt ins(db_, "INSERT OR REPLACE INTO chunk_touch(chunk_id,at) VALUES(?1,?2)");
        if (!ins.text(1, id).num(2, time(nullptr)).run()) return;
    }
    t.commit();
}

std::string DeviceStore::chunk_path(const std::string& id) const { return dir_ + "/chunks/" + first_n(id, 2) + "/" + id + ".blob"; }
std::string DeviceStore::manifest_path(const std::string& file_id, int64_t version) const {
    return dir_ + "/manifests/" + file_id + "/" + std::to_string(version) + ".mf";
}

// ---------------------------------------------------------------- durable file write

// temp file -> full fsync -> rename -> full fsync of the directory. When this returns 0
// the bytes are on the drive and visible under final_path, atomically (never half-written).
int DeviceStore::durable_write(const std::string& final_path, const std::vector<uint8_t>& data) {
    std::string tmp = dir_ + "/tmp/" + std::to_string(getpid()) + "." + std::to_string(g_tmp_counter++);
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
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
    if (!err) {
        std::string parent = fs::path(final_path).parent_path().string();
        err = make_dir_durable(parent);
        if (!err && rename(tmp.c_str(), final_path.c_str()) != 0) err = errno;
        if (!err) sync_dir(parent);
    }
    if (err) unlink(tmp.c_str());
    return err;
}

// ---------------------------------------------------------------- operations

DevInfo DeviceStore::info() {
    std::lock_guard<std::mutex> lk(mu_);
    DevInfo i;
    i.device_id = meta_get("device_id");
    i.epoch = strtoull(meta_get("epoch").c_str(), nullptr, 10);
    i.seq = strtoull(meta_get("seq").c_str(), nullptr, 10);
    i.volume_id = meta_get("volume_id");
    struct statvfs sv;
    if (statvfs(dir_.c_str(), &sv) == 0) i.free_bytes = static_cast<uint64_t>(sv.f_bavail) * sv.f_frsize;
    return i;
}

int DeviceStore::bind_volume(const std::string& volume_id, std::string* msg) {
    if (volume_id.empty() || volume_id.size() > 128) { if (msg) *msg = "bad volume id"; return EINVAL; }
    std::lock_guard<std::mutex> lk(mu_);
    std::string cur = meta_get("volume_id");
    if (cur == volume_id) return 0;
    if (!cur.empty()) { if (msg) *msg = "device is bound to a different volume"; return EPERM; }
    Txn t(db_);
    Stmt s(db_, "UPDATE meta SET value=?1 WHERE key='volume_id' AND value=''");
    if (!t.began() || !s.text(1, volume_id).run() || sqlite3_changes(db_) != 1 || !t.commit()) {
        if (msg) *msg = "cannot record the binding";
        return EIO;
    }
    return 0;
}

std::vector<bool> DeviceStore::has_chunks(const std::vector<std::string>& ids) {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<bool> out;
    for (const auto& id : ids) {
        Stmt s(db_, "SELECT 1 FROM chunks WHERE chunk_id=?1");
        s.text(1, id);
        out.push_back(valid_chunk_id(id) && s.row());
    }
    std::vector<std::string> present;
    for (size_t i = 0; i < ids.size(); i++)
        if (out[i]) present.push_back(ids[i]);
    touch_unreferenced_locked(present);
    return out;
}

PutChunkOut DeviceStore::put_chunk(const std::string& id, const std::vector<uint8_t>& blob, const std::string& claimed) {
    PutChunkOut out;
    auto fail = [&](int e, const std::string& m) { out.err = e; out.msg = m; return out; };
    if (!valid_chunk_id(id)) return fail(EINVAL, "bad chunk id");
    if (blob.empty() || blob.size() > MAX_CHUNK_BLOB) return fail(EMSGSIZE, "blob size out of range");
    std::string actual = crypto::sha256_hex(blob.data(), blob.size());
    if (claimed != actual) return fail(EBADMSG, "blob does not match its claimed hash (damaged in transit)");

    std::lock_guard<std::mutex> lk(mu_);
    if (faults_.slow_ms) std::this_thread::sleep_for(std::chrono::milliseconds(faults_.slow_ms));
    {
        Stmt q(db_, "SELECT sha256 FROM chunks WHERE chunk_id=?1");
        q.text(1, id);
        if (q.row()) {   // append-only: keep the original, say so, and tell the sender what we hold
            out.existed = true;
            out.sha256_hex = q.col_text(0);
        }
    }
    if (out.existed) {
        touch_unreferenced_locked({id});
        return out;
    }
    if (faults_.enospc) return fail(ENOSPC, "device is full");
    struct statvfs sv;
    if (statvfs(dir_.c_str(), &sv) == 0 &&
        static_cast<uint64_t>(sv.f_bavail) * sv.f_frsize < blob.size() + min_free_)
        return fail(ENOSPC, "device is full");

    std::string path = chunk_path(id);
    if (!faults_.lie_ack_chunk) {
        int e = durable_write(path, blob);
        if (e) return fail(e, std::string("cannot store chunk: ") + strerror(e));
    }
    crash_point("device.chunk.after_rename");   // file durable, no index row yet: an invisible orphan
    {
        Txn t(db_);
        Stmt ins(db_, "INSERT INTO chunks(chunk_id,size,sha256,created_at) VALUES(?1,?2,?3,?4)");
        if (!t.began() || !ins.text(1, id).num(2, static_cast<int64_t>(blob.size())).text(3, actual).num(4, time(nullptr)).run() || !t.commit())
            return fail(EIO, "cannot record chunk");
    }
    crash_point("device.chunk.after_index");
    if (faults_.corrupt_on_store && !faults_.lie_ack_chunk) {
        int fd = ::open(path.c_str(), O_RDWR);
        if (fd >= 0) {
            uint8_t b = 0;
            off_t pos = static_cast<off_t>(blob.size() / 2);
            if (pread(fd, &b, 1, pos) == 1) { b ^= 0x5a; pwrite(fd, &b, 1, pos); }
            close(fd);
        }
    }
    if (faults_.truncate_on_store && !faults_.lie_ack_chunk) truncate(path.c_str(), static_cast<off_t>(blob.size() / 2));
    out.sha256_hex = actual;
    return out;
}

// Reads exactly `size` bytes of a file; 0 ok, ENOENT if absent, EIO otherwise.
static int read_file(const std::string& path, std::vector<uint8_t>& out, int64_t expect_size = -1) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return errno == ENOENT ? ENOENT : EIO;
    struct stat st;
    if (fstat(fd, &st) != 0 || (expect_size >= 0 && st.st_size != expect_size)) { close(fd); return EIO; }
    // Nothing we store is bigger than this. A multi-gigabyte file at a chunk path is damage or
    // an attack, and must not be pulled into memory before it is judged.
    if (st.st_size < 0 || static_cast<uint64_t>(st.st_size) > MAX_MANIFEST_BLOB) { close(fd); return EIO; }
    out.resize(static_cast<size_t>(st.st_size));
    size_t got = 0;
    while (got < out.size()) {
        ssize_t r = ::read(fd, out.data() + got, out.size() - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { close(fd); return EIO; }
        got += static_cast<size_t>(r);
    }
    close(fd);
    return 0;
}

int DeviceStore::get_chunk(const std::string& id, std::vector<uint8_t>& out, std::string* msg) {
    if (!valid_chunk_id(id)) { if (msg) *msg = "bad chunk id"; return EINVAL; }
    std::string want_sha, serve_id = id;
    int64_t size = 0;
    DeviceFaults f;
    {
        std::lock_guard<std::mutex> lk(mu_);
        f = faults_;
        Stmt q(db_, "SELECT size, sha256 FROM chunks WHERE chunk_id=?1");
        q.text(1, id);
        if (!q.row()) { if (msg) *msg = "no such chunk"; return ENOENT; }
        size = q.col_num(0);
        want_sha = q.col_text(1);
        if (f.swap_get) {   // misbehave: answer with some OTHER chunk
            Stmt o(db_, "SELECT chunk_id, size, sha256 FROM chunks WHERE chunk_id!=?1 LIMIT 1");
            o.text(1, id);
            if (o.row()) { serve_id = o.col_text(0); size = o.col_num(1); want_sha = o.col_text(2); }
        }
    }
    if (f.slow_ms) std::this_thread::sleep_for(std::chrono::milliseconds(f.slow_ms));
    int rc = read_file(chunk_path(serve_id), out, size);
    if (rc == 0 && crypto::sha256_hex(out.data(), out.size()) != want_sha) rc = EIO;
    if (rc) {
        out.clear();
        std::lock_guard<std::mutex> lk(mu_);
        damaged_++;
        if (msg) *msg = rc == ENOENT ? "chunk file is missing on this device" : "stored chunk is damaged; refusing to serve it";
        return rc == ENOENT ? ENOENT : EIO;
    }
    return 0;
}

PutManifestOut DeviceStore::put_manifest(const std::string& file_id, int64_t version, const std::vector<uint8_t>& blob,
                                         const std::string& claimed, const std::vector<std::string>& chunk_ids) {
    PutManifestOut out;
    auto fail = [&](int e, const std::string& m) { out.err = e; out.msg = m; return out; };
    if (!valid_file_id(file_id)) return fail(EINVAL, "bad file id");
    if (version < 1 || version > (1ll << 40)) return fail(EINVAL, "bad version");
    if (blob.empty() || blob.size() > MAX_MANIFEST_BLOB) return fail(EMSGSIZE, "manifest size out of range");
    if (chunk_ids.size() > MAX_MANIFEST_CHUNKS) return fail(EMSGSIZE, "too many chunks");
    for (const auto& c : chunk_ids)
        if (!valid_chunk_id(c)) return fail(EINVAL, "bad chunk id in list");
    std::string actual = crypto::sha256_hex(blob.data(), blob.size());
    if (claimed != actual) return fail(EBADMSG, "manifest does not match its claimed hash (damaged in transit)");

    std::lock_guard<std::mutex> lk(mu_);
    if (faults_.slow_ms) std::this_thread::sleep_for(std::chrono::milliseconds(faults_.slow_ms));
    {
        Stmt q(db_, "SELECT sha256, seq FROM manifests WHERE file_id=?1 AND version=?2");
        q.text(1, file_id).num(2, version);
        if (q.row()) {   // versions are immutable: the first manifest stays, the sender learns its hash and seq
            out.existed = true;
            out.sha256_hex = q.col_text(0);
            out.seq = static_cast<uint64_t>(q.col_num(1));
        }
    }
    if (out.existed) {
        // A manifest stored before reference lists existed gets its list when the very same manifest is sent again (the Mac fetched the
        // blob, read the list inside it and re-sent both): only if every listed chunk is here, and only for an identical blob.
        Stmt done(db_, "SELECT 1 FROM refs_done WHERE file_id=?1 AND version=?2");
        done.text(1, file_id).num(2, version);
        bool have = done.row();
        bool all_here = out.sha256_hex == actual;
        for (size_t i = 0; !have && all_here && i < chunk_ids.size(); i++) {
            Stmt c(db_, "SELECT 1 FROM chunks WHERE chunk_id=?1");
            c.text(1, chunk_ids[i]);
            all_here = c.row();
        }
        if (!have && all_here) {
            Txn t(db_);
            bool ok = t.began();
            for (const auto& c : chunk_ids) {
                Stmt r(db_, "INSERT OR IGNORE INTO manifest_refs(file_id,version,chunk_id) VALUES(?1,?2,?3)");
                ok = ok && r.text(1, file_id).num(2, version).text(3, c).run();
            }
            Stmt d(db_, "INSERT OR IGNORE INTO refs_done(file_id,version) VALUES(?1,?2)");
            ok = ok && d.text(1, file_id).num(2, version).run() && t.commit();
        }
        return out;
    }
    // A manifest may only describe chunks the device really has.
    for (const auto& c : chunk_ids) {
        Stmt q(db_, "SELECT 1 FROM chunks WHERE chunk_id=?1");
        q.text(1, c);
        if (!q.row()) return fail(ENOENT, "chunk " + c + " is not present on this device");
    }
    if (faults_.enospc) return fail(ENOSPC, "device is full");
    struct statvfs sv;
    if (statvfs(dir_.c_str(), &sv) == 0 &&
        static_cast<uint64_t>(sv.f_bavail) * sv.f_frsize < blob.size() + min_free_)
        return fail(ENOSPC, "device is full");

    std::string path = manifest_path(file_id, version);
    if (!faults_.lie_ack_manifest) {
        int e = durable_write(path, blob);
        if (e) return fail(e, std::string("cannot store manifest: ") + strerror(e));
    }
    crash_point("device.manifest.after_rename");
    uint64_t seq = 0;
    {
        Txn t(db_);
        if (!t.began()) return fail(EIO, "cannot begin");
        seq = strtoull(meta_get("seq").c_str(), nullptr, 10) + 1;
        Stmt ins(db_, "INSERT INTO manifests(file_id,version,size,sha256,seq,created_at) VALUES(?1,?2,?3,?4,?5,?6)");
        Stmt up(db_, "UPDATE meta SET value=?1 WHERE key='seq'");
        if (!ins.text(1, file_id).num(2, version).num(3, static_cast<int64_t>(blob.size())).text(4, actual).num(5, static_cast<int64_t>(seq))
                 .num(6, time(nullptr)).run() ||
            !up.text(1, std::to_string(seq)).run())
            return fail(EIO, "cannot record manifest");
        for (const auto& c : chunk_ids) {
            Stmt r(db_, "INSERT OR IGNORE INTO manifest_refs(file_id,version,chunk_id) VALUES(?1,?2,?3)");
            if (!r.text(1, file_id).num(2, version).text(3, c).run()) return fail(EIO, "cannot record the manifest's chunk list");
        }
        Stmt dn(db_, "INSERT INTO refs_done(file_id,version) VALUES(?1,?2)");
        if (!dn.text(1, file_id).num(2, version).run()) return fail(EIO, "cannot record the manifest's chunk list");
        crash_point("device.manifest.before_commit");
        if (!t.commit()) return fail(EIO, "cannot commit manifest");
    }
    crash_point("device.manifest.after_commit");
    if (faults_.lose_manifest_after_commit) unlink(path.c_str());
    out.seq = seq;
    out.sha256_hex = actual;
    return out;
}

int DeviceStore::get_manifest(const std::string& file_id, int64_t version, std::vector<uint8_t>& out, std::string* msg) {
    if (!valid_file_id(file_id) || version < 1) { if (msg) *msg = "bad manifest id"; return EINVAL; }
    std::string want;
    int64_t size = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (faults_.slow_ms) std::this_thread::sleep_for(std::chrono::milliseconds(faults_.slow_ms));
        Stmt q(db_, "SELECT size, sha256 FROM manifests WHERE file_id=?1 AND version=?2");
        q.text(1, file_id).num(2, version);
        if (!q.row()) { if (msg) *msg = "no such manifest"; return ENOENT; }
        size = q.col_num(0);
        want = q.col_text(1);
    }
    int rc = read_file(manifest_path(file_id, version), out, size);
    if (rc == 0 && crypto::sha256_hex(out.data(), out.size()) != want) rc = EIO;
    if (rc) {
        out.clear();
        std::lock_guard<std::mutex> lk(mu_);
        damaged_++;
        if (msg) *msg = rc == ENOENT ? "manifest file is missing on this device" : "stored manifest is damaged; refusing to serve it";
        return rc;
    }
    return 0;
}

int DeviceStore::list_manifests(uint64_t since, size_t max, std::vector<ManifestEntry>& out, DevInfo* info_out) {
    if (max == 0 || max > MAX_LIST_ENTRIES) max = MAX_LIST_ENTRIES;
    out.clear();
    {
        std::lock_guard<std::mutex> lk(mu_);
        Stmt q(db_, "SELECT seq,file_id,version,sha256 FROM manifests WHERE seq>?1 ORDER BY seq LIMIT ?2");
        q.num(1, static_cast<int64_t>(since)).num(2, static_cast<int64_t>(max));
        while (q.row()) {
            ManifestEntry e;
            e.seq = static_cast<uint64_t>(q.col_num(0));
            e.file_id = q.col_text(1);
            e.version = q.col_num(2);
            e.sha256_hex = q.col_text(3);
            out.push_back(std::move(e));
        }
    }
    if (info_out) *info_out = info();
    return 0;
}

std::vector<AuditOut> DeviceStore::audit(const std::vector<AuditItem>& items) {
    std::vector<AuditOut> out;
    DeviceFaults f = faults();
    for (const auto& it : items) {
        AuditOut a;
        std::string path;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (it.kind == 0) {
                Stmt q(db_, "SELECT 1 FROM chunks WHERE chunk_id=?1");
                q.text(1, it.id);
                if (valid_chunk_id(it.id) && q.row()) path = chunk_path(it.id);
            } else {
                Stmt q(db_, "SELECT 1 FROM manifests WHERE file_id=?1 AND version=?2");
                q.text(1, it.id).num(2, it.version);
                if (valid_file_id(it.id) && q.row()) path = manifest_path(it.id, it.version);
            }
        }
        if (f.slow_ms) std::this_thread::sleep_for(std::chrono::milliseconds(f.slow_ms));
        if (path.empty()) { a.status = 1; out.push_back(a); continue; }
        // Whatever is on the disk RIGHT NOW is what gets hashed: no cached answers, and no
        // self-check that could hide a problem. The caller compares with its precomputed value.
        std::vector<uint8_t> data;
        int rc = read_file(path, data);
        if (rc == ENOENT) { a.status = 1; out.push_back(a); continue; }
        if (rc) { a.status = 2; out.push_back(a); continue; }
        a.response_hex = crypto::audit_response_hex(it.nonce, data.data(), data.size());
        out.push_back(a);
    }
    return out;
}

// ---------------------------------------------------------------- garbage collection (ADR-0010)

void DeviceStore::set_deletions_allowed(bool allowed) {
    std::lock_guard<std::mutex> lk(mu_);
    deletions_allowed_ = allowed;
}

void DeviceStore::set_min_sweep_age(uint64_t seconds) {
    std::lock_guard<std::mutex> lk(mu_);
    min_sweep_age_ = seconds;
}

static const char* const NO_DELETIONS = "this device does not accept deletions (pair it, or start it with --allow-delete)";

DeleteManifestsOut DeviceStore::delete_manifests(const std::vector<std::pair<std::string, int64_t>>& items) {
    DeleteManifestsOut out;
    auto fail = [&](int e, const std::string& m) {
        out.err = e;
        out.msg = m;
        out.deleted.clear();
        return out;
    };
    if (items.empty() || items.size() > MAX_DELETE_ITEMS) return fail(EMSGSIZE, "between 1 and 64 manifests per request");
    for (const auto& it : items)
        if (!valid_file_id(it.first) || it.second < 1 || it.second > (1ll << 40)) return fail(EINVAL, "bad manifest id");

    std::lock_guard<std::mutex> lk(mu_);
    if (!deletions_allowed_) return fail(EPERM, NO_DELETIONS);
    if (faults_.slow_ms) std::this_thread::sleep_for(std::chrono::milliseconds(faults_.slow_ms));
    std::vector<std::string> gone_paths;
    std::vector<std::pair<std::string, int64_t>> gone_items;
    std::vector<int64_t> gone_when(items.size(), 0);   // (per item: the second its trash files are named for)
    std::vector<int64_t> moved_when;
    out.deleted.assign(items.size(), 0);
    uint64_t seq = strtoull(meta_get("seq").c_str(), nullptr, 10);
    {
        Txn t(db_);
        if (!t.began() || !exec("UPDATE meta SET value='1' WHERE key='gc_open'")) return fail(EIO, "cannot begin");
        bool any = false;
        for (size_t i = 0; i < items.size(); i++) {
            int64_t size = 0;
            {
                Stmt q(db_, "SELECT size FROM manifests WHERE file_id=?1 AND version=?2");
                q.text(1, items[i].first).num(2, items[i].second);
                if (!q.row()) continue;  // not here (already deleted, or never was): fine, say so
                size = q.col_num(0);
            }
            if (trash_retention_ > 0) {  // keep the chunk list with the manifest: once the index rows are gone it exists nowhere else
                std::string refs;
                Stmt rq(db_, "SELECT chunk_id FROM manifest_refs WHERE file_id=?1 AND version=?2 ORDER BY chunk_id");
                rq.text(1, items[i].first).num(2, items[i].second);
                while (rq.row()) refs += rq.col_text(0) + "\n";
                const std::string tdir = dir_ + "/trash/manifests/" + items[i].first;
                const int64_t tt = free_trash_time(tdir, std::to_string(items[i].second), time(nullptr), {"mf", "refs"});
                gone_when[i] = tt;
                std::string rp = tdir + "/" + std::to_string(items[i].second) + "." + std::to_string(tt) + ".refs";
                int e = durable_write(rp, std::vector<uint8_t>(refs.begin(), refs.end()));
                if (e) return fail(e, std::string("cannot keep the chunk list in the trash: ") + strerror(e));
            }
            Stmt r(db_, "DELETE FROM manifest_refs WHERE file_id=?1 AND version=?2");
            Stmt d(db_, "DELETE FROM refs_done WHERE file_id=?1 AND version=?2");
            Stmt m(db_, "DELETE FROM manifests WHERE file_id=?1 AND version=?2");
            Stmt lg(db_, "INSERT INTO gc_log(ts,kind,item,version,size) VALUES(?1,'manifest',?2,?3,?4)");
            if (!r.text(1, items[i].first).num(2, items[i].second).run() || !d.text(1, items[i].first).num(2, items[i].second).run() ||
                !m.text(1, items[i].first).num(2, items[i].second).run() ||
                !lg.num(1, time(nullptr)).text(2, items[i].first).num(3, items[i].second).num(4, size).run())
                return fail(EIO, "cannot delete the manifest's records");
            out.deleted[i] = 1;
            any = true;
            gone_paths.push_back(manifest_path(items[i].first, items[i].second));
            gone_items.push_back(items[i]);
            moved_when.push_back(gone_when[i]);
        }
        if (any) {
            seq++;
            Stmt up(db_, "UPDATE meta SET value=?1 WHERE key='seq'");
            if (!up.text(1, std::to_string(seq)).run()) return fail(EIO, "cannot advance the commit sequence");
        }
        if (!exec("UPDATE meta SET value='0' WHERE key='gc_open'")) return fail(EIO, "cannot close the deletion");
        crash_point("device.delete.before_commit");
        if (!t.commit()) return fail(EIO, "cannot commit the deletion");
    }
    crash_point("device.delete.after_commit");  // records gone, files still there: strays, removed below or by the next sweep
    for (size_t i = 0; i < gone_paths.size(); i++) {
        const std::string& p = gone_paths[i];
        const auto& it = gone_items[i];
        if (!(trash_retention_ > 0 && moved_when[i] > 0 &&
              trash_file(p, dir_ + "/trash/manifests/" + it.first + "/" + std::to_string(it.second) + "." + std::to_string(moved_when[i]) + ".mf")))
            unlink(p.c_str());
        std::string parent = fs::path(p).parent_path().string();
        rmdir(parent.c_str());  // only succeeds when it is empty
    }
    if (!gone_paths.empty()) sync_dir(dir_ + "/manifests");
    out.seq = seq;
    return out;
}

// ---------------------------------------------------------------- the trash (ADR-0017)
//
//   <store>/trash/chunks/<chunk id>.<unix time>.blob
//   <store>/trash/manifests/<file id>/<version>.<unix time>.mf        the manifest, as it was stored
//   <store>/trash/manifests/<file id>/<version>.<unix time>.refs      its chunk list, one chunk id per line (the index row is gone, so it is kept
//   here)
// The time is when it went into the trash. Only files are kept: restoring goes through put_chunk/put_manifest like any upload.

namespace {

struct TrashName {
    std::string id;  // chunk id (64 hex) or the version number
    int64_t at = 0;
    std::string ext;  // "blob", "mf" or "refs"
};

bool all_digits(const std::string& s) { return !s.empty() && s.size() < 19 && s.find_first_not_of("0123456789") == std::string::npos; }

bool parse_trash_name(const std::string& name, TrashName* out) {
    size_t last = name.rfind('.');
    if (last == std::string::npos) return false;
    std::string ext = name.substr(last + 1), rest = name.substr(0, last);
    size_t mid = rest.rfind('.');
    if (mid == std::string::npos) return false;
    std::string id = rest.substr(0, mid), at = rest.substr(mid + 1);
    if (!all_digits(at) || (ext != "blob" && ext != "mf" && ext != "refs")) return false;
    if (ext == "blob" ? !valid_chunk_id(id) : !all_digits(id)) return false;
    out->id = id;
    out->at = atoll(at.c_str());
    out->ext = ext;
    return true;
}

template <class F>
void each_trash_file(const std::string& trash, F fn) {  // fn(path, kind 'c'|'m', file_id, TrashName, size)
    std::error_code ec;
    for (auto& f : fs::directory_iterator(trash + "/chunks", ec)) {
        TrashName tn;
        std::error_code e2;
        if (!f.is_regular_file(e2) || !parse_trash_name(f.path().filename().string(), &tn) || tn.ext != "blob") continue;
        fn(f.path().string(), 'c', std::string(), tn, static_cast<uint64_t>(f.file_size(e2)));
    }
    for (auto& d : fs::directory_iterator(trash + "/manifests", ec)) {
        std::error_code e2;
        std::string fid = d.path().filename().string();
        if (!d.is_directory(e2) || !valid_file_id(fid)) continue;
        for (auto& f : fs::directory_iterator(d.path(), e2)) {
            TrashName tn;
            std::error_code e3;
            if (!f.is_regular_file(e3) || !parse_trash_name(f.path().filename().string(), &tn) || tn.ext == "blob") continue;
            fn(f.path().string(), 'm', fid, tn, static_cast<uint64_t>(f.file_size(e3)));
        }
    }
}

}  // namespace

bool DeviceStore::trash_file(const std::string& from, const std::string& to) {
    std::string parent = fs::path(to).parent_path().string();
    if (make_dir_durable(parent) != 0) return false;
    if (rename(from.c_str(), to.c_str()) != 0) return false;
    sync_dir(parent);
    sync_dir(fs::path(from).parent_path().string());
    return true;
}

void DeviceStore::set_trash_retention(int64_t seconds) {
    std::lock_guard<std::mutex> lk(mu_);
    trash_retention_ = seconds < 0 ? 0 : seconds;
}
int64_t DeviceStore::trash_retention() {
    std::lock_guard<std::mutex> lk(mu_);
    return trash_retention_;
}

TrashStats DeviceStore::trash_stats() {
    std::lock_guard<std::mutex> lk(mu_);
    TrashStats s;
    each_trash_file(dir_ + "/trash", [&](const std::string&, char kind, const std::string&, const TrashName& tn, uint64_t size) {
        if (kind == 'c') {
            s.chunks++;
            s.chunk_bytes += size;
        } else if (tn.ext == "mf") {
            s.manifests++;
            s.manifest_bytes += size;
        } else {
            s.manifest_bytes += size;
        }
        if (s.oldest == 0 || tn.at < s.oldest) s.oldest = tn.at;
        if (tn.at > s.newest) s.newest = tn.at;
    });
    return s;
}

uint64_t DeviceStore::trash_purge(int64_t now, bool everything) {
    std::lock_guard<std::mutex> lk(mu_);
    if (now == 0) now = time(nullptr);
    uint64_t removed = 0;
    std::vector<std::string> dirs;
    each_trash_file(dir_ + "/trash", [&](const std::string& path, char kind, const std::string& fid, const TrashName& tn, uint64_t) {
        if (!everything && now - tn.at < trash_retention_) return;
        if (unlink(path.c_str()) == 0) removed++;
        if (kind == 'm') dirs.push_back(dir_ + "/trash/manifests/" + fid);
    });
    for (const auto& d : dirs) rmdir(d.c_str());  // (only succeeds when empty)
    if (removed) {
        sync_dir(dir_ + "/trash/chunks");
        sync_dir(dir_ + "/trash/manifests");
    }
    return removed;
}

TrashRestoreOut DeviceStore::trash_restore(int64_t newer_than_s) {
    TrashRestoreOut out;
    struct Item {
        std::string path, fid;
        TrashName tn;
    };
    std::vector<Item> chunks, manifests;
    std::map<std::string, std::string> refs_of;  // "<fid>/<ver>.<at>" -> path of the .refs file
    const int64_t cutoff = newer_than_s > 0 ? static_cast<int64_t>(time(nullptr)) - newer_than_s : 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        each_trash_file(dir_ + "/trash", [&](const std::string& path, char kind, const std::string& fid, const TrashName& tn, uint64_t) {
            if (tn.at < cutoff) return;
            if (kind == 'c')
                chunks.push_back({path, fid, tn});
            else if (tn.ext == "mf")
                manifests.push_back({path, fid, tn});
            else
                refs_of[fid + "/" + tn.id + "." + std::to_string(tn.at)] = path;
        });
    }
    std::sort(chunks.begin(), chunks.end(),
              [](const Item& a, const Item& b) { return a.tn.at > b.tn.at; });  // newest first: if the same one was trashed twice, that one wins
    for (const auto& c : chunks) {
        std::vector<uint8_t> blob;
        if (read_file(c.path, blob) != 0) {
            out.skipped++;
            out.notes.push_back("chunk " + c.tn.id + ": cannot read the trashed file");
            continue;
        }
        if (has_chunks({c.tn.id})[0]) {  // already back (uploaded again): the trashed copy is not needed
            out.skipped++;
            continue;
        }
        PutChunkOut r = put_chunk(c.tn.id, blob, crypto::sha256_hex(blob.data(), blob.size()));
        if (r.err) {
            out.skipped++;
            out.notes.push_back("chunk " + c.tn.id + ": " + r.msg);
            continue;
        }
        unlink(c.path.c_str());
        out.chunks++;
    }
    for (const auto& m : manifests) {
        auto ref = refs_of.find(m.fid + "/" + m.tn.id + "." + std::to_string(m.tn.at));
        if (ref == refs_of.end()) {
            out.skipped++;
            out.notes.push_back("manifest " + m.fid + " version " + m.tn.id + ": its chunk list was not kept, so it cannot be restored");
            continue;
        }
        std::vector<uint8_t> blob, rl;
        if (read_file(m.path, blob) != 0 || read_file(ref->second, rl) != 0) {
            out.skipped++;
            out.notes.push_back("manifest " + m.fid + " version " + m.tn.id + ": cannot read the trashed files");
            continue;
        }
        std::vector<std::string> ids;
        std::string text(rl.begin(), rl.end()), line;
        bool bad = false;
        for (char ch : text + "\n") {
            if (ch != '\n') {
                line += ch;
                continue;
            }
            if (line.empty()) continue;
            if (!valid_chunk_id(line)) bad = true;
            ids.push_back(line);
            line.clear();
        }
        if (bad) {
            out.skipped++;
            out.notes.push_back("manifest " + m.fid + " version " + m.tn.id + ": its saved chunk list is damaged");
            continue;
        }
        int64_t version = atoll(m.tn.id.c_str());
        PutManifestOut r = put_manifest(m.fid, version, blob, crypto::sha256_hex(blob.data(), blob.size()), ids);
        if (r.err) {
            out.skipped++;
            out.notes.push_back("manifest " + m.fid + " version " + m.tn.id + ": " + r.msg);
            continue;
        }
        unlink(m.path.c_str());
        unlink(ref->second.c_str());
        rmdir(fs::path(m.path).parent_path().c_str());
        if (r.existed)
            out.skipped++;
        else
            out.manifests++;
    }
    return out;
}

GcStatus DeviceStore::gc_status() {
    std::lock_guard<std::mutex> lk(mu_);
    GcStatus g;
    g.deletions_allowed = deletions_allowed_;
    auto num = [&](const char* sql) {
        Stmt q(db_, sql);
        return q.row() ? static_cast<uint64_t>(q.col_num(0)) : 0;
    };
    g.manifests = static_cast<uint32_t>(num("SELECT COUNT(*) FROM manifests"));
    int refless = count_refless_locked();
    g.manifests_without_refs = static_cast<uint32_t>(refless);
    g.chunks = num("SELECT COUNT(*) FROM chunks");
    g.chunk_bytes = num("SELECT COALESCE(SUM(size),0) FROM chunks");
    g.unreferenced_chunks = num("SELECT COUNT(*) FROM chunks c WHERE NOT EXISTS(SELECT 1 FROM manifest_refs r WHERE r.chunk_id=c.chunk_id)");
    g.unreferenced_bytes =
        num("SELECT COALESCE(SUM(size),0) FROM chunks c WHERE NOT EXISTS(SELECT 1 FROM manifest_refs r WHERE r.chunk_id=c.chunk_id)");
    g.manifests_deleted = num("SELECT COUNT(*) FROM gc_log WHERE kind='manifest'");
    g.chunks_deleted = num("SELECT COUNT(*) FROM gc_log WHERE kind='chunk'");
    g.trash_retention_s = trash_retention_;
    each_trash_file(dir_ + "/trash", [&](const std::string&, char, const std::string&, const TrashName&, uint64_t size) {
        g.trash_files++;
        g.trash_bytes += size;
    });
    return g;
}

SweepOut DeviceStore::sweep(uint64_t min_age_s, size_t max_chunks, bool dry_run) {
    SweepOut out;
    auto fail = [&](int e, const std::string& m) {
        out.err = e;
        out.msg = m;
        return out;
    };
    if (max_chunks == 0) return fail(EINVAL, "a sweep must be allowed to delete at least one chunk");
    if (max_chunks > MAX_SWEEP_CHUNKS) max_chunks = MAX_SWEEP_CHUNKS;

    std::lock_guard<std::mutex> lk(mu_);
    if (!deletions_allowed_) return fail(EPERM, NO_DELETIONS);
    if (faults_.slow_ms) std::this_thread::sleep_for(std::chrono::milliseconds(faults_.slow_ms));
    int refless = count_refless_locked();
    if (refless > 0)
        return fail(EPERM, std::to_string(refless) +
                               " stored manifest(s) have no chunk list yet (stored by an older version); the Mac must re-send them first (a "
                               "garbage-collection run from the Mac does that)");
    uint64_t age = std::max(min_age_s, min_sweep_age_);
    int64_t now = time(nullptr);
    int64_t cutoff = now - static_cast<int64_t>(std::min<uint64_t>(age, 1ull << 40));

    struct Cand {
        std::string id;
        int64_t size;
    };
    std::vector<Cand> cands;
    {
        Stmt q(db_,
               "SELECT c.chunk_id, c.size FROM chunks c LEFT JOIN chunk_touch t ON t.chunk_id=c.chunk_id"
               " WHERE NOT EXISTS(SELECT 1 FROM manifest_refs r WHERE r.chunk_id=c.chunk_id)"
               " AND MAX(c.created_at, COALESCE(t.at,0)) <= ?1 ORDER BY c.created_at LIMIT ?2");
        q.num(1, cutoff).num(2, static_cast<int64_t>(max_chunks));
        while (q.row()) cands.push_back({q.col_text(0), q.col_num(1)});
    }
    uint64_t unref_total = 0;
    {
        Stmt q(db_, "SELECT COUNT(*) FROM chunks c WHERE NOT EXISTS(SELECT 1 FROM manifest_refs r WHERE r.chunk_id=c.chunk_id)");
        if (q.row()) unref_total = static_cast<uint64_t>(q.col_num(0));
    }
    for (const auto& c : cands) {
        out.chunks_deleted++;
        out.bytes_deleted += static_cast<uint64_t>(c.size);
    }
    if (!dry_run && !cands.empty()) {
        Txn t(db_);
        if (!t.began() || !exec("UPDATE meta SET value='1' WHERE key='gc_open'")) {
            out = SweepOut();
            return fail(EIO, "cannot begin");
        }
        for (const auto& c : cands) {
            Stmt tc(db_, "DELETE FROM chunk_touch WHERE chunk_id=?1");
            Stmt d(db_, "DELETE FROM chunks WHERE chunk_id=?1");
            Stmt lg(db_, "INSERT INTO gc_log(ts,kind,item,version,size) VALUES(?1,'chunk',?2,0,?3)");
            if (!tc.text(1, c.id).run() || !d.text(1, c.id).run() || !lg.num(1, now).text(2, c.id).num(3, c.size).run()) {
                out = SweepOut();
                return fail(EIO, "cannot delete a chunk's records");  // the transaction rolls back: nothing was swept
            }
        }
        if (!exec("UPDATE meta SET value='0' WHERE key='gc_open'")) {
            out = SweepOut();
            return fail(EIO, "cannot close the sweep");
        }
        crash_point("device.sweep.before_commit");
        if (!t.commit()) {
            out = SweepOut();
            return fail(EIO, "cannot commit the sweep");
        }
        crash_point("device.sweep.after_commit");  // records gone, files still there: strays, removed below or by the next sweep
        for (const auto& c : cands) {  // the records are gone: keep the file in the trash for the retention period (ADR-0017), or remove it
            std::string path = chunk_path(c.id);
            if (trash_retention_ > 0 &&
                trash_file(path, dir_ + "/trash/chunks/" + c.id + "." + std::to_string(free_trash_time(dir_ + "/trash/chunks", c.id, now, {"blob"})) + ".blob"))
                continue;
            unlink(path.c_str());
        }
        sync_dir(dir_ + "/chunks");
    }
    out.chunks_left = unref_total >= out.chunks_deleted ? unref_total - out.chunks_deleted : 0;

    // Leftovers of a crash between "records deleted" and "file unlinked" (or the reverse for an upload): files that no row describes.
    std::error_code ec;
    for (auto& sub : fs::directory_iterator(dir_ + "/chunks", ec)) {
        std::error_code e2;
        if (!sub.is_directory(e2)) continue;
        for (auto& f : fs::directory_iterator(sub.path(), e2)) {
            std::string name = f.path().filename().string();
            if (name.size() != 64 + 5 || name.compare(64, 5, ".blob") != 0 || !valid_chunk_id(name.substr(0, 64))) continue;
            Stmt q(db_, "SELECT 1 FROM chunks WHERE chunk_id=?1");
            q.text(1, name.substr(0, 64));
            if (q.row()) continue;
            struct stat st;
            if (stat(f.path().c_str(), &st) != 0 || static_cast<int64_t>(st.st_mtime) > cutoff) continue;
            if (!dry_run && !(trash_retention_ > 0 &&
                              trash_file(f.path().string(), dir_ + "/trash/chunks/" + name.substr(0, 64) + "." +
                                                                std::to_string(free_trash_time(dir_ + "/trash/chunks", name.substr(0, 64), now, {"blob"})) + ".blob")))
                unlink(f.path().c_str());
            out.strays_removed++;
        }
    }
    for (auto& sub : fs::directory_iterator(dir_ + "/manifests", ec)) {
        std::error_code e2;
        std::string fid = sub.path().filename().string();
        if (!sub.is_directory(e2) || !valid_file_id(fid)) continue;
        for (auto& f : fs::directory_iterator(sub.path(), e2)) {
            std::string name = f.path().filename().string();
            size_t dot = name.rfind(".mf");
            if (dot == std::string::npos || dot + 3 != name.size() || dot == 0) continue;
            int64_t ver = atoll(name.substr(0, dot).c_str());
            if (ver < 1 || std::to_string(ver) != name.substr(0, dot)) continue;
            Stmt q(db_, "SELECT 1 FROM manifests WHERE file_id=?1 AND version=?2");
            q.text(1, fid).num(2, ver);
            if (q.row()) continue;
            struct stat st;
            if (stat(f.path().c_str(), &st) != 0 || static_cast<int64_t>(st.st_mtime) > cutoff) continue;
            if (!dry_run &&
                !(trash_retention_ > 0 &&
                  trash_file(f.path().string(), dir_ + "/trash/manifests/" + fid + "/" + std::to_string(ver) + "." +
                                                    std::to_string(free_trash_time(dir_ + "/trash/manifests/" + fid, std::to_string(ver), now, {"mf", "refs"})) + ".mf")))
                unlink(f.path().c_str());
            out.strays_removed++;
        }
        if (!dry_run) rmdir(sub.path().c_str());
    }
    return out;
}

void DeviceStore::set_free_reserve(uint64_t bytes) {
    std::lock_guard<std::mutex> lk(mu_);
    min_free_ = bytes;
}

void DeviceStore::set_faults(const DeviceFaults& f) {
    std::lock_guard<std::mutex> lk(mu_);
    faults_ = f;
}
DeviceFaults DeviceStore::faults() {
    std::lock_guard<std::mutex> lk(mu_);
    return faults_;
}

}  // namespace tierfs
