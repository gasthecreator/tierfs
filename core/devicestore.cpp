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
#include <filesystem>
#include <thread>

#include "crashpoint.hpp"
#include "crypto.hpp"
#include "sqlutil.hpp"

namespace tierfs {
namespace {

using sql::Stmt;
using sql::Txn;
namespace fs = std::filesystem;

constexpr int SCHEMA_VERSION = 1;

bool is_lower_hex(const std::string& s, size_t n) {
    if (s.size() != n) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

// macOS fsync() does not force the drive to flush its cache; F_FULLFSYNC does.
void full_sync(int fd) {
    if (fcntl(fd, F_FULLFSYNC) != 0) fsync(fd);
}

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
    if (flock(d->lock_fd_, LOCK_EX | LOCK_NB) != 0) return bad("device store is in use by another process");

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
    if (version != 0 && version != SCHEMA_VERSION) {
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
    if (version != 0) return true;

    Txn t(db_);
    if (!t.began()) { *err = "cannot begin"; return false; }
    const char* ddl[] = {
        "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
        "CREATE TABLE chunks(chunk_id TEXT PRIMARY KEY, size INTEGER NOT NULL, sha256 TEXT NOT NULL, created_at INTEGER NOT NULL) WITHOUT ROWID",
        "CREATE TABLE manifests(file_id TEXT NOT NULL, version INTEGER NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,"
        " seq INTEGER NOT NULL UNIQUE, created_at INTEGER NOT NULL, PRIMARY KEY(file_id, version)) WITHOUT ROWID",
        // Append-only: the device cannot be told to forget (I4), and a bug cannot either.
        "CREATE TRIGGER chunks_append_only_u BEFORE UPDATE ON chunks BEGIN SELECT RAISE(ABORT,'append-only'); END",
        "CREATE TRIGGER chunks_append_only_d BEFORE DELETE ON chunks BEGIN SELECT RAISE(ABORT,'append-only'); END",
        "CREATE TRIGGER manifests_append_only_u BEFORE UPDATE ON manifests BEGIN SELECT RAISE(ABORT,'append-only'); END",
        "CREATE TRIGGER manifests_append_only_d BEFORE DELETE ON manifests BEGIN SELECT RAISE(ABORT,'append-only'); END",
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
            return out;
        }
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
            return out;
        }
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
