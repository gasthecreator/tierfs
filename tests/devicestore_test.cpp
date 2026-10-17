// Tests for the device store: durability ordering under crashes, append-only rules,
// audits against real crypto, and every misbehaving-device mode.
#include <fcntl.h>
#include <spawn.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <map>
#include <thread>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../core/crypto.hpp"
#include "../core/devicestore.hpp"

extern char** environ;
using namespace tierfs;
using crypto::Bytes;
namespace fs = std::filesystem;

static int failures = 0;
static bool failfast() {  // the mutation runner stops a test at its first failure
    static const bool f = getenv("TIERFS_TEST_FAILFAST") != nullptr;
    return f;
}
#define CHECK(cond)                                         \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("FAIL  line %d: %s\n", __LINE__, #cond); \
            failures++;                                     \
            if (failfast()) {                               \
                fflush(stdout);                             \
                _exit(1);                                   \
            }                                               \
        } else                                              \
            printf("PASS  %s\n", #cond);                    \
    } while (0)

// Safe element access for assertions: a failed earlier check must not become a crash that hides it.
static bool at(const std::vector<bool>& v, size_t i) { return i < v.size() ? v[i] : false; }  // (a vector<bool> has no elements to refer to)
template <class T> static const T& at(const std::vector<T>& v, size_t i) { static const T dummy{}; return i < v.size() ? v[i] : dummy; }
static bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }
static std::string tmpdir() {
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-devtest-XXXXXX";
    std::vector<char> b(t.begin(), t.end());
    b.push_back(0);
    return mkdtemp(b.data());
}
static Bytes pattern(size_t n, uint8_t seed) {
    Bytes v(n);
    for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(seed + i * 37 + (i >> 9));
    return v;
}
static std::string sha(const Bytes& b) { return crypto::sha256_hex(b.data(), b.size()); }

// The Mac's side of the exchange: seal a chunk the way production does.
struct Sealed { std::string id; Bytes blob; };
static const crypto::Keys& keys() {
    static crypto::Keys k(crypto::SecretKey::random());
    return k;
}
static Sealed seal(const Bytes& plain) {
    Sealed s;
    s.id = crypto::chunk_id(keys(), plain.data(), plain.size());
    s.blob = crypto::seal_chunk(keys(), "vol-test", s.id, plain.data(), plain.size());
    return s;
}
// A blob that is NOT the one seal() produces for this plaintext, but is filed under the same chunk id:
// what an old seal, a corrupted copy or a hostile upload under a known id would look like.
static Sealed seal_conflicting(const Bytes& plain, int variant) {
    Sealed s;
    s.id = crypto::chunk_id(keys(), plain.data(), plain.size());
    s.blob = crypto::seal_chunk(keys(), "conflict-" + std::to_string(variant), s.id, plain.data(), plain.size());
    return s;
}
static std::string chunk_file(const std::string& dir, const std::string& id) { return dir + "/chunks/" + id.substr(0, 2) + "/" + id + ".blob"; }
static const std::string FID1 = "0123456789abcdef0123456789abcdef", FID2 = "fedcba9876543210fedcba9876543210";

static std::unique_ptr<DeviceStore> open_store(const std::string& dir, std::string* err = nullptr) {
    std::string e;
    return DeviceStore::open(dir, err ? err : &e);
}
static PutChunkOut put(DeviceStore& d, const Sealed& s) { return d.put_chunk(s.id, s.blob, sha(s.blob)); }
static PutManifestOut put_man(DeviceStore& d, const std::string& fid, int64_t v, const Bytes& blob, std::vector<std::string> ids) {
    return d.put_manifest(fid, v, blob, sha(blob), ids);
}
static AuditItem chunk_audit(const std::string& id, uint32_t n) {
    AuditItem a;
    a.kind = 0; a.id = id; a.nonce = crypto::audit_nonce(keys(), id, n);
    return a;
}
static std::string expected(const std::string& id, uint32_t n, const Bytes& blob) {
    return crypto::audit_response_hex(crypto::audit_nonce(keys(), id, n), blob.data(), blob.size());
}
static size_t count_files(const std::string& dir) {
    size_t n = 0;
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(dir, ec)) n += e.is_regular_file();
    return n;
}
static sqlite3* raw_open(const std::string& dir) {
    sqlite3* db = nullptr;
    sqlite3_open((dir + "/device.db").c_str(), &db);
    return db;
}
static bool raw_exec(sqlite3* db, const char* sql) { return sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK; }
// The deletion window flag, read through a second connection while the store itself is open.
static std::string window_value(const std::string& dir) {
    sqlite3* db = raw_open(dir);
    sqlite3_stmt* st = nullptr;
    std::string v = "?";
    sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='gc_open'", -1, &st, nullptr);
    if (sqlite3_step(st) == SQLITE_ROW) v = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    sqlite3_close(db);
    return v;
}

static const char* helper_path() { const char* h = getenv("TIERFS_DEVICE_HELPER"); return h ? h : "./build/device_helper"; }
static bool crash_run(const char* point, std::vector<std::string> args) {
    std::vector<std::string> env;
    for (char** e = environ; *e; e++) env.push_back(*e);
    env.push_back(std::string("TIERFS_CRASH_AT=") + point);
    std::vector<char*> envp;
    for (auto& e : env) envp.push_back(const_cast<char*>(e.c_str()));
    envp.push_back(nullptr);
    std::vector<std::string> a = {"device_helper"};
    a.insert(a.end(), args.begin(), args.end());
    std::vector<char*> av;
    for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
    av.push_back(nullptr);
    pid_t pid;
    if (posix_spawn(&pid, helper_path(), nullptr, nullptr, av.data(), envp.data()) != 0) return false;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 137;
}
static std::string write_tmp(const std::string& dir, const std::string& name, const Bytes& b) {
    std::string p = dir + "/" + name;
    std::ofstream f(p, std::ios::binary);
    f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
    return p;
}

int main() {
    {
        printf("== identity, exclusivity, binding\n");
        std::string dir = tmpdir();
        std::string id, vol;
        uint64_t epoch;
        {
            auto d = open_store(dir);
            DevInfo i = d->info();
            id = i.device_id; epoch = i.epoch;
            CHECK(id.size() == 32 && epoch > 0 && i.seq == 0 && i.volume_id.empty() && i.free_bytes > 0);
            std::string err;
            CHECK(!DeviceStore::open(dir, &err) && has(err, "in use"));   // one process per store
            std::string msg;
            CHECK(d->bind_volume("", &msg) == EINVAL);
            CHECK(d->bind_volume("volume-A", &msg) == 0);
            CHECK(d->bind_volume("volume-A", &msg) == 0);                 // same volume again is fine
            CHECK(d->bind_volume("volume-B", &msg) == EPERM && has(msg, "different volume"));
        }
        auto d = open_store(dir);
        DevInfo i = d->info();
        CHECK(i.device_id == id && i.epoch == epoch && i.volume_id == "volume-A");   // identity and binding persist
        CHECK(d->bind_volume("volume-B", nullptr) == EPERM);
        d.reset();
        sqlite3* db = raw_open(dir);   // even direct database tampering is refused by triggers
        CHECK(!raw_exec(db, "UPDATE meta SET value='volume-B' WHERE key='volume_id'"));
        CHECK(!raw_exec(db, "UPDATE meta SET value='999' WHERE key='epoch'"));
        CHECK(!raw_exec(db, "UPDATE meta SET value='x' WHERE key='device_id'"));
        CHECK(!raw_exec(db, "DELETE FROM meta"));
        sqlite3_close(db);
        fs::remove_all(dir);
    }

    {
        printf("== chunks: store, fetch, idempotence, hostile input\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        Sealed a = seal(pattern(100000, 1));
        PutChunkOut r = put(*d, a);
        CHECK(r.err == 0 && !r.existed && r.sha256_hex == sha(a.blob));
        CHECK(d->has_chunks({a.id, std::string(64, 'a'), "../etc/passwd"}) == std::vector<bool>({true, false, false}));
        Bytes got;
        CHECK(d->get_chunk(a.id, got, nullptr) == 0 && got == a.blob);
        CHECK(count_files(dir + "/tmp") == 0);                      // nothing left in the staging area

        // the same plaintext sealed again has different bytes (random nonce): the device keeps the original
        Sealed again = seal(pattern(100000, 1));
        CHECK(again.id == a.id && again.blob == a.blob);    // sealing is deterministic: a retry is byte-identical
        PutChunkOut r2 = put(*d, again);
        CHECK(r2.err == 0 && r2.existed && r2.sha256_hex == sha(a.blob));   // "existed", and the hash proves it is the same bytes
        Sealed other = seal_conflicting(pattern(100000, 1), 1);             // DIFFERENT bytes under the same id
        CHECK(other.id == a.id && other.blob != a.blob);
        PutChunkOut r3 = put(*d, other);
        CHECK(r3.err == 0 && r3.existed && r3.sha256_hex == sha(a.blob) && r3.sha256_hex != sha(other.blob));   // the original is kept and the sender can SEE the difference
        CHECK(d->get_chunk(a.id, got, nullptr) == 0 && got == a.blob);      // never overwritten

        // transit damage: the claimed hash does not match
        Sealed b = seal(pattern(5000, 2));
        PutChunkOut bad = d->put_chunk(b.id, b.blob, std::string(64, '0'));
        CHECK(bad.err == EBADMSG && !d->has_chunks({b.id})[0]);
        Bytes damaged = b.blob;
        damaged[40] ^= 1;
        CHECK(d->put_chunk(b.id, damaged, sha(b.blob)).err == EBADMSG);
        CHECK(count_files(dir + "/chunks") == 1 && count_files(dir + "/tmp") == 0);   // a refusal leaves no trace

        // ids that are not exactly 64 lowercase hex characters never touch the filesystem
        for (const char* id : {"", "../../etc/passwd", "AA", "abc/def", "x"}) {
            CHECK(d->put_chunk(id, b.blob, sha(b.blob)).err == EINVAL);
            CHECK(d->get_chunk(id, got, nullptr) == EINVAL);
        }
        std::string upper = a.id;
        upper[0] = 'A';
        CHECK(d->put_chunk(upper, b.blob, sha(b.blob)).err == EINVAL);
        CHECK(d->put_chunk(b.id, {}, sha({})).err == EMSGSIZE);
        CHECK(d->put_chunk(b.id, Bytes(MAX_CHUNK_BLOB + 1, 1), sha(Bytes(MAX_CHUNK_BLOB + 1, 1))).err == EMSGSIZE);
        CHECK(d->get_chunk(std::string(64, 'e'), got, nullptr) == ENOENT);
        CHECK(count_files(dir + "/chunks") == 1);

        d.reset();
        auto d2 = open_store(dir);        // survives a restart
        CHECK(d2->get_chunk(a.id, got, nullptr) == 0 && got == a.blob);
        d2.reset();
        sqlite3* db = raw_open(dir);
        CHECK(!raw_exec(db, "DELETE FROM chunks"));               // append-only, even for a direct database edit
        CHECK(!raw_exec(db, "UPDATE chunks SET sha256='x'"));
        sqlite3_close(db);
        fs::remove_all(dir);
    }

    {
        printf("== manifests: only over chunks that exist; immutable; ordered log\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        Sealed c1 = seal(pattern(2000, 3)), c2 = seal(pattern(3000, 4));
        put(*d, c1);
        Bytes m1 = pattern(500, 9), m2 = pattern(600, 10), m3 = pattern(700, 11);
        PutManifestOut miss = put_man(*d, FID1, 1, m1, {c1.id, c2.id});   // c2 was never uploaded
        CHECK(miss.err == ENOENT && has(miss.msg, c2.id.substr(0, 8).c_str()));
        CHECK(d->info().seq == 0 && count_files(dir + "/manifests") == 0);   // refused: nothing recorded
        put(*d, c2);
        PutManifestOut ok1 = put_man(*d, FID1, 1, m1, {c1.id, c2.id});
        CHECK(ok1.err == 0 && !ok1.existed && ok1.seq == 1 && ok1.sha256_hex == sha(m1));
        PutManifestOut ok2 = put_man(*d, FID2, 1, m2, {c1.id});
        CHECK(ok2.err == 0 && ok2.seq == 2);
        PutManifestOut v2 = put_man(*d, FID1, 2, m3, {c2.id});
        CHECK(v2.err == 0 && v2.seq == 3);
        PutManifestOut dup = put_man(*d, FID1, 1, m3, {c1.id});           // a different body for an existing version
        CHECK(dup.err == 0 && dup.existed && dup.seq == 1 && dup.sha256_hex == sha(m1));   // original kept, sender told
        Bytes got;
        CHECK(d->get_manifest(FID1, 1, got, nullptr) == 0 && got == m1);
        CHECK(d->get_manifest(FID1, 9, got, nullptr) == ENOENT);
        CHECK(d->info().seq == 3);

        CHECK(put_man(*d, "short", 1, m1, {}).err == EINVAL);
        CHECK(put_man(*d, FID1, 0, m1, {}).err == EINVAL);
        CHECK(put_man(*d, FID1, 5, m1, {"../x"}).err == EINVAL);
        CHECK(d->put_manifest(FID1, 5, m1, std::string(64, '0'), {}).err == EBADMSG);
        CHECK(put_man(*d, FID1, 5, {}, {}).err == EMSGSIZE);
        CHECK(put_man(*d, FID1, 5, m1, std::vector<std::string>(MAX_MANIFEST_CHUNKS + 1)).err == EMSGSIZE);

        std::vector<ManifestEntry> l;
        DevInfo info;
        CHECK(d->list_manifests(0, 100, l, &info) == 0 && l.size() == 3 && info.seq == 3);
        CHECK(at(l, 0).seq == 1 && at(l, 0).file_id == FID1 && at(l, 0).version == 1 && at(l, 0).sha256_hex == sha(m1));
        CHECK(at(l, 1).seq == 2 && at(l, 1).file_id == FID2 && at(l, 2).seq == 3 && at(l, 2).version == 2);
        d->list_manifests(1, 1, l, nullptr);
        CHECK(l.size() == 1 && at(l, 0).seq == 2);                            // paging
        d->list_manifests(3, 10, l, nullptr);
        CHECK(l.empty());
        d.reset();
        d = open_store(dir);
        CHECK(d->info().seq == 3);                                         // sequence survives restart
        CHECK(put_man(*d, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, m1, {c1.id}).seq == 4);   // and keeps counting
        d.reset();
        sqlite3* db = raw_open(dir);
        CHECK(!raw_exec(db, "UPDATE meta SET value='1' WHERE key='seq'"));   // the sequence can never go down
        CHECK(!raw_exec(db, "DELETE FROM manifests"));
        sqlite3_close(db);
        fs::remove_all(dir);
    }

    {
        printf("== audits: the device must read its disk now\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        Sealed c = seal(pattern(4000, 5));
        put(*d, c);
        Bytes man = pattern(300, 6);
        put_man(*d, FID1, 1, man, {c.id});
        for (uint32_t n = 0; n < 4; n++) {   // the Mac's precomputed pool of 4 one-time challenges
            auto out = d->audit({chunk_audit(c.id, n)});
            CHECK(out.size() == 1 && out[0].status == 0 && out[0].response_hex == expected(c.id, n, c.blob));
        }
        CHECK(expected(c.id, 0, c.blob) != expected(c.id, 1, c.blob));      // different challenge, different answer
        AuditItem m;
        m.kind = 1; m.id = FID1; m.version = 1; m.nonce = crypto::audit_nonce(keys(), "m:" + FID1 + ":1", 0);
        auto mo = d->audit({m});
        CHECK(at(mo, 0).status == 0 && at(mo, 0).response_hex == crypto::audit_response_hex(m.nonce, man.data(), man.size()));
        auto unknown = d->audit({chunk_audit(std::string(64, 'b'), 0)});
        CHECK(at(unknown, 0).status == 1);
        std::vector<AuditItem> many{chunk_audit(c.id, 0), chunk_audit(std::string(64, 'c'), 0), chunk_audit(c.id, 1)};
        auto mo2 = d->audit(many);
        CHECK(mo2.size() == 3 && at(mo2, 0).status == 0 && at(mo2, 1).status == 1 && at(mo2, 2).status == 0);   // per-item results

        // real damage on disk: bit rot, truncation, loss. The honest device still answers
        // from what is there, the Mac's comparison catches it, and GET refuses to serve it.
        std::string f = chunk_file(dir, c.id);
        { int fd = ::open(f.c_str(), O_RDWR); uint8_t b; pread(fd, &b, 1, 1000); b ^= 4; pwrite(fd, &b, 1, 1000); close(fd); }
        auto rot = d->audit({chunk_audit(c.id, 2)});
        CHECK(at(rot, 0).status == 0 && at(rot, 0).response_hex != expected(c.id, 2, c.blob));   // answered, wrongly: detectable
        Bytes got;
        std::string msg;
        CHECK(d->get_chunk(c.id, got, &msg) == EIO && got.empty() && has(msg, "damaged"));
        CHECK(d->damaged_reads() == 1);
        truncate(f.c_str(), 100);
        CHECK(d->audit({chunk_audit(c.id, 3)})[0].response_hex != expected(c.id, 3, c.blob));
        // a gigantic file where a chunk should be (sparse, so it costs no disk): refused fast, never read into memory
        truncate(f.c_str(), 2ll << 30);
        auto t0 = std::chrono::steady_clock::now();
        CHECK(d->get_chunk(c.id, got, nullptr) == EIO && got.empty());
        CHECK(d->audit({chunk_audit(c.id, 0)})[0].status == 2);          // unreadable, not answered
        CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(1));
        unlink(f.c_str());
        CHECK(d->audit({chunk_audit(c.id, 0)})[0].status == 1);
        CHECK(d->get_chunk(c.id, got, &msg) == ENOENT && has(msg, "missing"));
        fs::remove_all(dir);
    }

    {
        printf("== misbehaving devices: every fault is detectable by the Mac\n");
        DeviceFaults f;
        std::string err;
        CHECK(DeviceFaults::parse("corrupt_on_store,slow=30,enospc", &f, &err) && f.corrupt_on_store && f.slow_ms == 30 && f.enospc && !f.swap_get);
        CHECK(!DeviceFaults::parse("bogus", &f, &err) && has(err, "bogus"));
        CHECK(DeviceFaults::parse("", &f, &err) && !f.corrupt_on_store);

        Bytes plain = pattern(6000, 7);
        {   // acknowledges without storing
            std::string dir = tmpdir();
            auto d = open_store(dir);
            DeviceFaults ff; ff.lie_ack_chunk = true;
            d->set_faults(ff);
            Sealed c = seal(plain);
            CHECK(put(*d, c).err == 0 && d->has_chunks({c.id})[0]);          // it CLAIMS to have it
            CHECK(!fs::exists(chunk_file(dir, c.id)));
            CHECK(d->audit({chunk_audit(c.id, 0)})[0].status == 1);          // ... and an audit exposes the lie
            Bytes got;
            CHECK(d->get_chunk(c.id, got, nullptr) == ENOENT);
            fs::remove_all(dir);
        }
        {   // bit rot right after the ack
            std::string dir = tmpdir();
            auto d = open_store(dir);
            DeviceFaults ff; ff.corrupt_on_store = true;
            d->set_faults(ff);
            Sealed c = seal(plain);
            CHECK(put(*d, c).err == 0);
            CHECK(d->audit({chunk_audit(c.id, 0)})[0].response_hex != expected(c.id, 0, c.blob));
            Bytes got;
            CHECK(d->get_chunk(c.id, got, nullptr) == EIO);
            fs::remove_all(dir);
        }
        {   // truncated after the ack
            std::string dir = tmpdir();
            auto d = open_store(dir);
            DeviceFaults ff; ff.truncate_on_store = true;
            d->set_faults(ff);
            Sealed c = seal(plain);
            CHECK(put(*d, c).err == 0);
            CHECK(d->audit({chunk_audit(c.id, 0)})[0].response_hex != expected(c.id, 0, c.blob));
            fs::remove_all(dir);
        }
        {   // serves the wrong chunk: the AEAD binding on the Mac side catches it
            std::string dir = tmpdir();
            auto d = open_store(dir);
            Sealed a = seal(pattern(3000, 20)), b = seal(pattern(3000, 21));
            put(*d, a); put(*d, b);
            DeviceFaults ff; ff.swap_get = true;
            d->set_faults(ff);
            Bytes got;
            CHECK(d->get_chunk(a.id, got, nullptr) == 0 && got != a.blob);   // device does not notice it lies
            Bytes plain_out;
            CHECK(crypto::open_chunk(keys(), "vol-test", a.id, got.data(), got.size(), plain_out) == crypto::OpenError::AuthFailed);
            fs::remove_all(dir);
        }
        {   // manifest vanishes after commit / is never written
            for (int mode = 0; mode < 2; mode++) {
                std::string dir = tmpdir();
                auto d = open_store(dir);
                Sealed c = seal(plain);
                put(*d, c);
                DeviceFaults ff;
                (mode == 0 ? ff.lose_manifest_after_commit : ff.lie_ack_manifest) = true;
                d->set_faults(ff);
                CHECK(put_man(*d, FID1, 1, pattern(200, 1), {c.id}).seq == 1);
                std::vector<ManifestEntry> l;
                d->list_manifests(0, 10, l, nullptr);
                CHECK(l.size() == 1);                                         // the log says it exists
                Bytes got;
                CHECK(d->get_manifest(FID1, 1, got, nullptr) == ENOENT);       // the disk says it does not
                AuditItem m;
                m.kind = 1; m.id = FID1; m.version = 1; m.nonce = Bytes(32, 1);
                CHECK(d->audit({m})[0].status == 1);
                fs::remove_all(dir);
            }
        }
        {   // disk full: refused cleanly, nothing half-recorded
            std::string dir = tmpdir();
            auto d = open_store(dir);
            DeviceFaults ff; ff.enospc = true;
            d->set_faults(ff);
            Sealed c = seal(plain);
            CHECK(put(*d, c).err == ENOSPC && !d->has_chunks({c.id})[0]);
            CHECK(count_files(dir + "/chunks") == 0 && count_files(dir + "/tmp") == 0);
            ff.enospc = false;
            d->set_faults(ff);
            put(*d, c);
            ff.enospc = true;
            d->set_faults(ff);
            CHECK(put_man(*d, FID1, 1, pattern(100, 2), {c.id}).err == ENOSPC && d->info().seq == 0);
            fs::remove_all(dir);
        }
        {   // nearly full: the reserve keeps a device from being filled to the last byte
            std::string dir = tmpdir();
            auto d = open_store(dir);
            Sealed c = seal(plain);
            d->set_free_reserve(~0ull / 2);
            CHECK(put(*d, c).err == ENOSPC && !d->has_chunks({c.id})[0] && count_files(dir + "/chunks") == 0);
            d->set_free_reserve(MIN_FREE_RESERVE);
            put(*d, c);
            d->set_free_reserve(~0ull / 2);
            CHECK(put_man(*d, FID1, 1, pattern(100, 2), {c.id}).err == ENOSPC && d->info().seq == 0);
            d->set_free_reserve(MIN_FREE_RESERVE);
            CHECK(put_man(*d, FID1, 1, pattern(100, 2), {c.id}).seq == 1);   // and it recovers once there is room
            fs::remove_all(dir);
        }
        {   // slow
            std::string dir = tmpdir();
            auto d = open_store(dir);
            DeviceFaults ff; ff.slow_ms = 80;
            d->set_faults(ff);
            Sealed c = seal(plain);
            auto t0 = std::chrono::steady_clock::now();
            put(*d, c);
            CHECK(std::chrono::steady_clock::now() - t0 >= std::chrono::milliseconds(80));
            fs::remove_all(dir);
        }
    }

    {
        printf("== a device restored from an old copy is visible through its sequence number\n");
        std::string dir = tmpdir(), snap = tmpdir();
        Sealed c = seal(pattern(1000, 30));
        uint64_t epoch;
        {
            auto d = open_store(dir);
            put(*d, c);
            put_man(*d, FID1, 1, pattern(100, 1), {c.id});
            put_man(*d, FID2, 1, pattern(100, 2), {c.id});
            epoch = d->info().epoch;
        }
        fs::remove_all(snap);
        fs::copy(dir, snap, fs::copy_options::recursive);       // a backup taken at seq 2
        {
            auto d = open_store(dir);
            put_man(*d, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, pattern(100, 3), {c.id});
            CHECK(d->info().seq == 3);
        }
        fs::remove_all(dir);
        fs::copy(snap, dir, fs::copy_options::recursive);       // ... later restored over the live store
        auto d = open_store(dir);
        CHECK(d->info().seq == 2 && d->info().epoch == epoch);  // seq went 3 -> 2 with the same epoch: the Mac's reconciler keys on this
        std::vector<ManifestEntry> l;
        d->list_manifests(2, 10, l, nullptr);
        CHECK(l.empty());
        fs::remove_all(dir);
        fs::remove_all(snap);
    }

    {
        printf("== crash injection: dying at each durability step\n");
        Sealed c = seal(pattern(5000, 40));
        auto stage = [&](const std::string& dir, const std::string& name, const Bytes& b) { return write_tmp(dir, name, b); };

        {   // file renamed into place, index row not yet written: an invisible orphan
            std::string dir = tmpdir(), files = tmpdir();
            std::string bf = stage(files, "blob", c.blob);
            CHECK(crash_run("device.chunk.after_rename", {"put_chunk", dir, c.id, bf}));
            auto d = open_store(dir);
            CHECK(!d->has_chunks({c.id})[0] && fs::exists(chunk_file(dir, c.id)));   // orphan file, but not claimed
            Bytes got;
            CHECK(d->get_chunk(c.id, got, nullptr) == ENOENT);                      // never served without a row
            PutChunkOut r = put(*d, c);                                             // the retry succeeds and replaces the orphan
            CHECK(r.err == 0 && !r.existed && d->get_chunk(c.id, got, nullptr) == 0 && got == c.blob);
            CHECK(count_files(dir + "/tmp") == 0);
            fs::remove_all(dir); fs::remove_all(files);
        }
        {   // dies right after the row commit: fully durable
            std::string dir = tmpdir(), files = tmpdir();
            std::string bf = stage(files, "blob", c.blob);
            CHECK(crash_run("device.chunk.after_index", {"put_chunk", dir, c.id, bf}));
            auto d = open_store(dir);
            Bytes got;
            CHECK(d->has_chunks({c.id})[0] && d->get_chunk(c.id, got, nullptr) == 0 && got == c.blob);
            CHECK(d->audit({chunk_audit(c.id, 0)})[0].response_hex == expected(c.id, 0, c.blob));
            fs::remove_all(dir); fs::remove_all(files);
        }
        Bytes man = pattern(400, 41);
        auto with_chunk = [&](const std::string& dir) { auto d = open_store(dir); put(*d, c); };
        {   // manifest file in place, no row: not committed, seq unchanged
            std::string dir = tmpdir(), files = tmpdir();
            with_chunk(dir);
            std::string mf = stage(files, "man", man);
            CHECK(crash_run("device.manifest.after_rename", {"put_manifest", dir, FID1, "1", mf, c.id}));
            auto d = open_store(dir);
            std::vector<ManifestEntry> l;
            d->list_manifests(0, 10, l, nullptr);
            CHECK(l.empty() && d->info().seq == 0);
            Bytes got;
            CHECK(d->get_manifest(FID1, 1, got, nullptr) == ENOENT);                 // an orphan file is not a manifest
            PutManifestOut r = put_man(*d, FID1, 1, man, {c.id});
            CHECK(r.err == 0 && !r.existed && r.seq == 1);
            fs::remove_all(dir); fs::remove_all(files);
        }
        {   // inside the transaction, just before commit: rolled back as one unit
            std::string dir = tmpdir(), files = tmpdir();
            with_chunk(dir);
            std::string mf = stage(files, "man", man);
            CHECK(crash_run("device.manifest.before_commit", {"put_manifest", dir, FID1, "1", mf, c.id}));
            auto d = open_store(dir);
            std::vector<ManifestEntry> l;
            d->list_manifests(0, 10, l, nullptr);
            CHECK(l.empty() && d->info().seq == 0);                                  // row and seq bump rolled back together
            CHECK(put_man(*d, FID1, 1, man, {c.id}).seq == 1);                        // no gap in the sequence
            fs::remove_all(dir); fs::remove_all(files);
        }
        {   // after commit: committed and retrievable
            std::string dir = tmpdir(), files = tmpdir();
            with_chunk(dir);
            std::string mf = stage(files, "man", man);
            CHECK(crash_run("device.manifest.after_commit", {"put_manifest", dir, FID1, "1", mf, c.id}));
            auto d = open_store(dir);
            std::vector<ManifestEntry> l;
            d->list_manifests(0, 10, l, nullptr);
            Bytes got;
            CHECK(l.size() == 1 && at(l, 0).seq == 1 && d->get_manifest(FID1, 1, got, nullptr) == 0 && got == man);
            PutManifestOut again = put_man(*d, FID1, 1, man, {c.id});
            CHECK(again.existed && again.seq == 1);                                  // the Mac's retry after a lost ack is harmless
            fs::remove_all(dir); fs::remove_all(files);
        }
        {   // staging leftovers from a crash are removed at start; real data never is
            std::string dir = tmpdir();
            { auto d = open_store(dir); put(*d, c); }
            { std::ofstream t(dir + "/tmp/999.0"); t << "half written"; }
            std::string orphan = dir + "/chunks/zz/" + std::string(64, 'a') + ".blob";
            fs::create_directories(dir + "/chunks/zz");
            { std::ofstream t(orphan); t << "orphan"; }
            auto d = open_store(dir);
            CHECK(!fs::exists(dir + "/tmp/999.0"));
            CHECK(fs::exists(orphan) && fs::exists(chunk_file(dir, c.id)));          // never deletes stored data
            fs::remove_all(dir);
        }
    }

    {
        printf("== concurrent uploads race safely\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        Bytes plain = pattern(2000, 50);
        std::string id = crypto::chunk_id(keys(), plain.data(), plain.size());
        std::vector<Sealed> variants;
        for (int i = 0; i < 8; i++) variants.push_back(seal_conflicting(plain, i));   // same chunk id, 8 different ciphertexts
        std::atomic<int> stored{0}, existed{0}, errors{0};
        std::vector<std::string> shas(8);
        std::vector<std::thread> th;
        for (int i = 0; i < 8; i++)
            th.emplace_back([&, i] {
                PutChunkOut r = d->put_chunk(variants[i].id, variants[i].blob, sha(variants[i].blob));
                if (r.err) errors++;
                else (r.existed ? existed : stored)++;
                shas[i] = r.sha256_hex;
            });
        for (auto& t : th) t.join();
        CHECK(stored == 1 && existed == 7 && errors == 0);              // exactly one winner
        CHECK(std::set<std::string>(shas.begin(), shas.end()).size() == 1);   // everyone is told the same truth
        Bytes got;
        CHECK(d->get_chunk(id, got, nullptr) == 0 && sha(got) == shas[0]);
        std::vector<std::thread> th2;
        std::atomic<int> okc{0};
        for (int i = 0; i < 6; i++)
            th2.emplace_back([&, i] {
                Sealed s = seal(pattern(1500, static_cast<uint8_t>(60 + i)));
                okc += d->put_chunk(s.id, s.blob, sha(s.blob)).err == 0;
                put_man(*d, std::string(31, 'a') + std::to_string(i), 1, pattern(80, 1), {s.id});
            });
        for (auto& t : th2) t.join();
        CHECK(okc == 6 && d->info().seq == 6);                           // six distinct manifests, six distinct seq numbers
        std::vector<ManifestEntry> l;
        d->list_manifests(0, 100, l, nullptr);
        std::set<uint64_t> seqs;
        for (auto& e : l) seqs.insert(e.seq);
        CHECK(l.size() == 6 && seqs.size() == 6 && *seqs.begin() == 1 && *seqs.rbegin() == 6);   // no gaps, no duplicates
        fs::remove_all(dir);
    }

    {
        printf("== garbage collection: only an authorized Mac may delete; a listed chunk is never swept\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        Sealed a = seal(pattern(1500, 21)), b = seal(pattern(1600, 22)), c = seal(pattern(1700, 23)), dd = seal(pattern(1800, 24));
        for (auto* x : {&a, &b, &c, &dd}) put(*d, *x);
        Bytes m1 = pattern(300, 31), m2 = pattern(310, 32), m3 = pattern(320, 33);
        CHECK(put_man(*d, FID1, 1, m1, {a.id, b.id}).err == 0 && put_man(*d, FID1, 2, m2, {b.id, c.id}).err == 0 &&
              put_man(*d, FID2, 1, m3, {c.id}).err == 0);
        // off by default
        DeleteManifestsOut denied = d->delete_manifests({{FID1, 1}});
        CHECK(denied.err == EPERM && has(denied.msg, "does not accept deletions"));
        SweepOut sdenied = d->sweep(0, 10, false);
        CHECK(sdenied.err == EPERM && has(sdenied.msg, "does not accept deletions") && fs::exists(chunk_file(dir, dd.id)));
        GcStatus g0 = d->gc_status();
        CHECK(!g0.deletions_allowed && g0.manifests == 3 && g0.manifests_without_refs == 0 && g0.chunks == 4 && g0.unreferenced_chunks == 1 &&
              g0.unreferenced_bytes == dd.blob.size() && g0.manifests_deleted == 0 && g0.chunks_deleted == 0);
        d->set_deletions_allowed(true);
        d->set_min_sweep_age(0);
        CHECK(d->gc_status().deletions_allowed);

        // bad requests
        CHECK(d->delete_manifests({}).err == EMSGSIZE);
        CHECK(d->delete_manifests(std::vector<std::pair<std::string, int64_t>>(MAX_DELETE_ITEMS + 1, {FID1, 1})).err == EMSGSIZE);
        CHECK(d->delete_manifests(std::vector<std::pair<std::string, int64_t>>(MAX_DELETE_ITEMS, {FID1, 99})).err == 0);  // exactly the limit is fine
        CHECK(d->delete_manifests({{"not-an-id", 1}}).err == EINVAL && d->delete_manifests({{FID1, 0}}).err == EINVAL &&
              d->delete_manifests({{FID1, -3}}).err == EINVAL);
        CHECK(d->delete_manifests({{FID1, (1ll << 40) + 1}}).err == EINVAL && d->delete_manifests({{FID1, 1ll << 40}}).err == 0);
        CHECK(d->sweep(0, 0, false).err == EINVAL);
        CHECK(d->info().seq == 3);  // nothing above deleted anything, so the sequence did not move

        // a dry run reports and changes nothing
        SweepOut dry = d->sweep(0, 100, true);
        CHECK(dry.err == 0 && dry.chunks_deleted == 1 && dry.bytes_deleted == dd.blob.size() && dry.chunks_left == 0 &&
              fs::exists(chunk_file(dir, dd.id)) && at(d->has_chunks({dd.id}), 0));
        // the real sweep takes the unreferenced chunk and nothing else
        SweepOut sw = d->sweep(0, 100, false);
        CHECK(sw.err == 0 && sw.chunks_deleted == 1 && sw.bytes_deleted == dd.blob.size() && sw.chunks_left == 0 && sw.strays_removed == 0);
        CHECK(!fs::exists(chunk_file(dir, dd.id)) && !at(d->has_chunks({dd.id}), 0));
        for (auto* x : {&a, &b, &c}) CHECK(fs::exists(chunk_file(dir, x->id)) && at(d->has_chunks({x->id}), 0));
        std::vector<uint8_t> got;
        std::string msg;
        CHECK(d->get_chunk(dd.id, got, &msg) == ENOENT);
        SweepOut again = d->sweep(0, 100, false);
        CHECK(again.err == 0 && again.chunks_deleted == 0 && again.bytes_deleted == 0);  // idempotent

        // deleting a manifest: it goes, its siblings stay, the commit sequence moves once, repeating it changes nothing
        uint64_t seq0 = d->info().seq;
        DeleteManifestsOut del = d->delete_manifests({{FID1, 1}});
        CHECK(del.err == 0 && del.deleted.size() == 1 && del.deleted[0] == 1 && del.seq == seq0 + 1 && d->info().seq == seq0 + 1);
        CHECK(!fs::exists(dir + "/manifests/" + FID1 + "/1.mf") && fs::exists(dir + "/manifests/" + FID1 + "/2.mf"));
        CHECK(d->get_manifest(FID1, 1, got, &msg) == ENOENT && d->get_manifest(FID1, 2, got, &msg) == 0 && got == m2);
        DeleteManifestsOut rep = d->delete_manifests({{FID1, 1}});
        CHECK(rep.err == 0 && rep.deleted.size() == 1 && rep.deleted[0] == 0 && rep.seq == seq0 + 1 && d->info().seq == seq0 + 1);
        DeleteManifestsOut mixed = d->delete_manifests({{FID1, 1}, {FID2, 7}, {FID1, 1}});
        CHECK(mixed.err == 0 && mixed.deleted == std::vector<uint8_t>({0, 0, 0}) && d->info().seq == seq0 + 1);
        // a (deleted) version's number is not reusable by accident: a new manifest still gets the next sequence number
        PutManifestOut next = put_man(*d, FID2, 2, pattern(330, 34), {c.id});
        CHECK(next.err == 0 && next.seq == seq0 + 2);
        // a's only manifest is gone, b and c are still listed by the others
        SweepOut s2 = d->sweep(0, 100, false);
        CHECK(s2.err == 0 && s2.chunks_deleted == 1 && s2.bytes_deleted == a.blob.size() && !at(d->has_chunks({a.id}), 0) &&
              at(d->has_chunks({b.id}), 0) && at(d->has_chunks({c.id}), 0));
        // the device's own log and totals
        GcStatus g1 = d->gc_status();
        CHECK(g1.manifests == 3 && g1.manifests_deleted == 1 && g1.chunks_deleted == 2 && g1.chunks == 2 && g1.unreferenced_chunks == 0 &&
              g1.chunk_bytes == b.blob.size() + c.blob.size());
        // a manifest that was alone in its directory takes the directory with it, at once
        const std::string FID3 = "00112233445566778899aabbccddeeff";
        CHECK(put_man(*d, FID3, 1, pattern(340, 36), {b.id}).err == 0 && fs::exists(dir + "/manifests/" + FID3 + "/1.mf"));
        CHECK(d->delete_manifests({{FID3, 1}}).deleted[0] == 1 && !fs::exists(dir + "/manifests/" + FID3));
        // a deleted version can be stored again (the Mac does that if it has to rebuild it)
        CHECK(put_man(*d, FID1, 1, m1, {b.id}).err == 0 && !put_man(*d, FID1, 1, m1, {b.id}).err && d->get_manifest(FID1, 1, got, &msg) == 0 &&
              got == m1);
        CHECK(d->delete_manifests({{FID1, 1}}).deleted[0] == 1);
        // three manifests at once, then a limited sweep leaves the rest for later
        DeleteManifestsOut three = d->delete_manifests({{FID1, 2}, {FID2, 1}, {FID2, 2}});
        CHECK(three.err == 0 && three.deleted == std::vector<uint8_t>({1, 1, 1}) && three.seq == d->info().seq);
        SweepOut lim = d->sweep(0, 1, false);
        CHECK(lim.err == 0 && lim.chunks_deleted == 1 && lim.chunks_left == 1 && d->gc_status().chunks == 1);
        SweepOut rest = d->sweep(0, 1, false);
        CHECK(rest.chunks_deleted == 1 && rest.chunks_left == 0 && d->gc_status().chunks == 0 && count_files(dir + "/chunks") == 0 &&
              count_files(dir + "/manifests") == 0);
        CHECK(!fs::exists(dir + "/manifests/" + FID1) && !fs::exists(dir + "/manifests/" + FID2));  // empty directories are removed too

        // age: a chunk that was just uploaded, or just reported present to the Mac, is not swept
        Sealed e = seal(pattern(1900, 25));
        put(*d, e);
        d->set_min_sweep_age(3600);
        CHECK(d->sweep(0, 10, false).chunks_deleted == 0 && at(d->has_chunks({e.id}), 0));  // the floor raises a request for 0
        CHECK(d->sweep(7200, 10, false).chunks_deleted == 0);                               // a larger request is honoured
        CHECK(d->sweep(~0ull, 10, false).chunks_deleted == 0 &&
              d->sweep(1ull << 62, 10, false).chunks_deleted == 0);  // so is an absurd one (no wrap-around)
        d->set_min_sweep_age(0);
        std::this_thread::sleep_for(std::chrono::milliseconds(2200));
        d->has_chunks({e.id});  // the Mac mentioned it: the clock restarts
        CHECK(d->sweep(2, 10, false).chunks_deleted == 0 && at(d->has_chunks({e.id}), 0));
        std::this_thread::sleep_for(std::chrono::milliseconds(2200));
        PutChunkOut dupe = put(*d, e);  // uploading it again restarts it too
        CHECK(dupe.existed && d->sweep(2, 10, false).chunks_deleted == 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(2200));
        d->set_min_sweep_age(1);
        CHECK(d->sweep(3600, 10, false).chunks_deleted == 0);  // the request wins over a smaller floor
        SweepOut aged = d->sweep(2, 10, false);
        CHECK(aged.chunks_deleted == 1 && !at(d->has_chunks({e.id}), 0));
        fs::remove_all(dir);
    }

    {
        printf("== garbage collection: the database itself refuses what the code must never do\n");
        std::string dir = tmpdir();
        Sealed x = seal(pattern(1500, 41)), y = seal(pattern(1600, 42)), w = seal(pattern(1650, 44));
        {
            auto d = open_store(dir);
            sqlite3* fresh = raw_open(dir);  // a brand-new store starts with the deletion window closed
            sqlite3_stmt* st0 = nullptr;
            sqlite3_prepare_v2(fresh, "SELECT value FROM meta WHERE key='gc_open'", -1, &st0, nullptr);
            CHECK(sqlite3_step(st0) == SQLITE_ROW && std::string(reinterpret_cast<const char*>(sqlite3_column_text(st0, 0))) == "0");
            sqlite3_finalize(st0);
            sqlite3_close(fresh);
            put(*d, x);
            put(*d, y);
            put(*d, w);
            CHECK(put_man(*d, FID1, 1, pattern(300, 43), {x.id}).err == 0);
            CHECK(put_man(*d, FID2, 1, pattern(301, 45), {y.id}).err == 0);
            d->set_deletions_allowed(true);
            d->set_min_sweep_age(0);
            CHECK(d->delete_manifests({{FID2, 1}}).deleted[0] == 1);  // y is unlisted now, and w always was
            CHECK(window_value(dir) == "0");                          // closed again after a deletion...
            CHECK(d->sweep(0, 1, false).chunks_deleted == 1);         // one of them goes
            CHECK(window_value(dir) == "0");                          // ... and after a sweep
        }
        {  // a window left open by a crashed process is closed when the store is opened again
            sqlite3* db = raw_open(dir);
            CHECK(raw_exec(db, "UPDATE meta SET value='1' WHERE key='gc_open'"));
            sqlite3_close(db);
            auto d = open_store(dir);
        }
        sqlite3* db = raw_open(dir);
        auto count = [&](const char* sql) {
            sqlite3_stmt* st = nullptr;
            sqlite3_prepare_v2(db, sql, -1, &st, nullptr);
            int n = sqlite3_step(st) == SQLITE_ROW ? sqlite3_column_int(st, 0) : -1;
            sqlite3_finalize(st);
            return n;
        };
        CHECK(!raw_exec(db, "DELETE FROM chunks WHERE chunk_id NOT IN (SELECT chunk_id FROM manifest_refs)"));  // outside a sweep: refused
        CHECK(!raw_exec(db, "DELETE FROM manifests"));
        CHECK(!raw_exec(db, "UPDATE chunks SET size=1") && !raw_exec(db, "UPDATE manifests SET size=1"));
        CHECK(raw_exec(db, "BEGIN") && raw_exec(db, "UPDATE meta SET value='1' WHERE key='gc_open'"));
        CHECK(!raw_exec(db, ("DELETE FROM chunks WHERE chunk_id='" + x.id + "'").c_str()));  // listed by a manifest: refused even inside a sweep
        std::string unlisted;
        {
            sqlite3_stmt* st = nullptr;
            sqlite3_prepare_v2(db, "SELECT chunk_id FROM chunks WHERE chunk_id NOT IN (SELECT chunk_id FROM manifest_refs)", -1, &st, nullptr);
            if (sqlite3_step(st) == SQLITE_ROW) unlisted = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
            sqlite3_finalize(st);
        }
        CHECK(unlisted.size() == 64 &&
              raw_exec(db, ("DELETE FROM chunks WHERE chunk_id='" + unlisted + "'").c_str()));  // unlisted: allowed inside one
        CHECK(raw_exec(db, "ROLLBACK"));
        CHECK(count("SELECT COUNT(*) FROM chunks") == 2 &&
              count("SELECT COUNT(*) FROM meta WHERE key='gc_open' AND value='0'") == 1);  // (x, and the one the sweep left)
        CHECK(raw_exec(db, "INSERT INTO gc_log(ts,kind,item,version,size) VALUES(1,'chunk','x',0,1)"));
        CHECK(!raw_exec(db, "UPDATE gc_log SET size=2") && !raw_exec(db, "DELETE FROM gc_log"));
        // the reference lists are real
        CHECK(count("SELECT COUNT(*) FROM manifest_refs") == 1 && count("SELECT COUNT(*) FROM refs_done") == 1 &&
              count("SELECT COUNT(*) FROM manifests") == 1);  // FID2 v1 is gone, with its list
        sqlite3_close(db);
        fs::remove_all(dir);
    }

    {
        printf("== garbage collection: a store from before reference lists is upgraded and refuses to sweep until the Mac re-sends its manifests\n");
        std::string dir = tmpdir();
        Sealed x = seal(pattern(1500, 51)), y = seal(pattern(1600, 52)), z = seal(pattern(1700, 53));
        Bytes m1 = pattern(300, 54), m2 = pattern(310, 55);
        {
            auto d = open_store(dir);
            for (auto* s : {&x, &y, &z}) put(*d, *s);
            CHECK(put_man(*d, FID1, 1, m1, {x.id, y.id}).err == 0 &&
                  put_man(*d, FID2, 1, m2, {}).err == 0);  // the second lists no chunks (an empty file)
        }
        {  // turn it back into a version 1 store
            sqlite3* db = raw_open(dir);
            const char* undo[] = {"DROP TRIGGER chunks_delete_guard",
                                  "DROP TRIGGER chunks_delete_listed",
                                  "DROP TRIGGER manifests_delete_guard",
                                  "DROP TRIGGER gc_log_no_update",
                                  "DROP TRIGGER gc_log_no_delete",
                                  "DROP TABLE manifest_refs",
                                  "DROP TABLE refs_done",
                                  "DROP TABLE chunk_touch",
                                  "DROP TABLE gc_log",
                                  "DROP TRIGGER meta_no_delete",
                                  "DELETE FROM meta WHERE key='gc_open'",
                                  "CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta BEGIN SELECT RAISE(ABORT,'meta rows are never deleted'); END",
                                  "CREATE TRIGGER chunks_append_only_d BEFORE DELETE ON chunks BEGIN SELECT RAISE(ABORT,'append-only'); END",
                                  "CREATE TRIGGER manifests_append_only_d BEFORE DELETE ON manifests BEGIN SELECT RAISE(ABORT,'append-only'); END",
                                  "PRAGMA user_version=1"};
            for (const char* q : undo) CHECK(raw_exec(db, q));
            sqlite3_close(db);
        }
        std::string err;
        auto d = DeviceStore::open(dir, &err);
        CHECK(d != nullptr);
        if (!d) {
            fs::remove_all(dir);
            goto next_block;
        }
        {
            sqlite3* db = raw_open(dir);
            sqlite3_stmt* st = nullptr;
            sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &st, nullptr);
            CHECK(sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 2);
            sqlite3_finalize(st);
            sqlite3_close(db);
        }
        d->set_deletions_allowed(true);
        d->set_min_sweep_age(0);
        CHECK(d->info().seq == 2 && at(d->has_chunks({x.id, y.id, z.id}), 2));  // nothing was lost in the upgrade
        GcStatus g = d->gc_status();
        CHECK(g.manifests == 2 && g.manifests_without_refs == 2 &&
              g.unreferenced_chunks == 3);  // everything looks unreferenced: so a sweep must refuse
        SweepOut refused = d->sweep(0, 100, false);
        CHECK(refused.err == EPERM && has(refused.msg, "2 stored manifest(s) have no chunk list") && has(refused.msg, "garbage-collection run") &&
              count_files(dir + "/chunks") == 3);
        CHECK(d->sweep(0, 100, true).err == EPERM);
        // deleting a manifest needs no reference list
        // a different blob under the same version does not earn a list (the first one stays, the sender is told what is held)
        PutManifestOut other = put_man(*d, FID1, 1, pattern(299, 99), {x.id, y.id});
        CHECK(other.err == 0 && other.existed && other.sha256_hex == sha(m1) && d->gc_status().manifests_without_refs == 2);
        // nor does a list naming a chunk the device lacks
        PutManifestOut ghost = put_man(*d, FID1, 1, m1, {x.id, std::string(64, 'a')});
        CHECK(ghost.err == 0 && ghost.existed && d->gc_status().manifests_without_refs == 2);
        // the very same manifest with its real list is accepted as the list
        PutManifestOut back = put_man(*d, FID1, 1, m1, {x.id, y.id});
        CHECK(back.err == 0 && back.existed && back.seq == 1 && d->info().seq == 2 && d->gc_status().manifests_without_refs == 1);
        CHECK(d->sweep(0, 100, false).err == EPERM);  // one manifest still lacks its list
        PutManifestOut back2 = put_man(*d, FID2, 1, m2, {});
        CHECK(back2.err == 0 && back2.existed && d->gc_status().manifests_without_refs == 0 && d->info().seq == 2);
        SweepOut ok = d->sweep(0, 100, false);
        CHECK(ok.err == 0 && ok.chunks_deleted == 1 && !at(d->has_chunks({z.id}), 0) && at(d->has_chunks({x.id}), 0) && at(d->has_chunks({y.id}), 0));
        // the lists now protect x and y for real
        CHECK(d->delete_manifests({{FID1, 1}}).deleted[0] == 1);
        CHECK(d->sweep(0, 100, false).chunks_deleted == 2 && d->gc_status().chunks == 0);
        d.reset();
        fs::remove_all(dir);
    }
next_block:

    {
        printf("== garbage collection: leftovers of a crash are removed, other files are not touched\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        d->set_deletions_allowed(true);
        d->set_min_sweep_age(3600);
        Sealed live = seal(pattern(1500, 61));
        put(*d, live);
        CHECK(put_man(*d, FID1, 1, pattern(300, 62), {live.id}).err == 0);
        auto age = [&](const std::string& path, int64_t seconds_ago) {
            struct timespec ts[2];
            ts[0].tv_sec = ts[1].tv_sec = time(nullptr) - seconds_ago;
            ts[0].tv_nsec = ts[1].tv_nsec = 0;
            utimensat(AT_FDCWD, path.c_str(), ts, 0);
        };
        std::string id_old(64, 'b'), id_young(64, 'c'), id_odd = "xyz";
        fs::create_directories(dir + "/chunks/bb");
        fs::create_directories(dir + "/chunks/cc");
        std::string stray_old = dir + "/chunks/bb/" + id_old + ".blob", stray_young = dir + "/chunks/cc/" + id_young + ".blob";
        std::string other1 = dir + "/chunks/bb/" + "notachunk.blob", other2 = dir + "/chunks/bb/" + id_old + ".part",
                    other3 = dir + "/chunks/readme.txt";
        std::string other4 = dir + "/chunks/bb/" + std::string(64, 'g') + ".blob";  // the right length, but not hex
        for (auto* p : {&stray_old, &stray_young, &other1, &other2, &other3, &other4}) {
            std::ofstream f(*p);
            f << "x";
        }
        for (auto* p : {&stray_old, &other1, &other2, &other3, &other4}) age(*p, 7200);
        std::string mdir = dir + "/manifests/" + FID2;
        fs::create_directories(mdir);
        std::string mstray_old = mdir + "/5.mf", mstray_young = mdir + "/6.mf", mother = mdir + "/7.txt", mother2 = mdir + "/05.mf";
        for (auto* p : {&mstray_old, &mstray_young, &mother, &mother2}) {
            std::ofstream f(*p);
            f << "x";
        }
        for (auto* p : {&mstray_old, &mother, &mother2}) age(*p, 7200);
        const std::string FID3 = "00112233445566778899aabbccddeeff", FID4 = "ffeeddccbbaa99887766554433221100";
        fs::create_directories(dir + "/manifests/" + FID3);
        std::string alone = dir + "/manifests/" + FID3 + "/9.mf";
        {
            std::ofstream f(alone);
            f << "x";
        }
        age(alone, 7200);
        fs::create_directories(dir + "/manifests/" + FID4);  // an empty directory (nothing to remove but the directory itself)
        std::string zero = mdir + "/0.mf", bak = mdir + "/8.mf.bak", foreign_dir = dir + "/manifests/not-an-id", foreign = foreign_dir + "/5.mf";
        fs::create_directories(foreign_dir);
        for (auto* p : {&zero, &bak, &foreign}) {
            std::ofstream f(*p);
            f << "x";
        }
        for (auto* p : {&zero, &bak, &foreign}) age(*p, 7200);
        std::string live_file = chunk_file(dir, live.id);
        age(live_file, 7200);  // old, but it has a row and a manifest listing it
        std::vector<uint8_t> gm;
        SweepOut dry = d->sweep(0, 10, true);
        CHECK(dry.err == 0 && dry.strays_removed == 3 && fs::exists(stray_old) && fs::exists(mstray_old) && fs::exists(alone) &&
              fs::exists(dir + "/manifests/" + FID3) &&
              fs::exists(dir + "/manifests/" + FID4));  // reported, not removed (not even an empty directory)
        SweepOut s = d->sweep(0, 10, false);
        CHECK(s.err == 0 && s.strays_removed == 3 && s.chunks_deleted == 0);
        CHECK(!fs::exists(stray_old) && !fs::exists(mstray_old) && !fs::exists(alone) && fs::exists(stray_young) && fs::exists(mstray_young));
        CHECK(!fs::exists(dir + "/manifests/" + FID3) &&
              !fs::exists(dir + "/manifests/" + FID4));  // the directory that held only a stray goes with it, and an empty one goes
        CHECK(fs::exists(zero) && fs::exists(bak) &&
              fs::exists(foreign));  // version 0, another extension, a directory that is not a file id: not ours
        CHECK(fs::exists(other1) && fs::exists(other2) && fs::exists(other3) && fs::exists(other4) && fs::exists(mother) && fs::exists(mother2) &&
              fs::exists(live_file));
        CHECK(at(d->has_chunks({live.id}), 0) && d->get_manifest(FID1, 1, gm, nullptr) == 0);
        age(stray_young, 7200);
        age(mstray_young, 7200);
        CHECK(d->sweep(0, 10, false).strays_removed == 2 && !fs::exists(stray_young) && !fs::exists(mstray_young));
        CHECK(fs::exists(mdir));  // not empty (the other files), so kept
        fs::remove_all(dir);
    }

    {
        printf("== garbage collection: dying at each step loses nothing that is listed and repeats cleanly\n");
        std::string dir = tmpdir();
        Sealed x = seal(pattern(1500, 71)), y = seal(pattern(1600, 72));
        Bytes m = pattern(300, 73);
        {
            auto d = open_store(dir);
            put(*d, x);
            put(*d, y);
            CHECK(put_man(*d, FID1, 1, m, {x.id}).err == 0);
        }
        // a delete that dies before its commit changes nothing
        CHECK(crash_run("device.delete.before_commit", {"delete_manifest", dir, FID1, "1"}));
        {
            auto d = open_store(dir);
            std::vector<uint8_t> got;
            std::string msg;
            CHECK(d->get_manifest(FID1, 1, got, &msg) == 0 && got == m && d->info().seq == 1 && d->gc_status().manifests_without_refs == 0);
        }
        // one that dies after it: the manifest is gone, its file is a stray, and the next sweep removes it
        CHECK(crash_run("device.delete.after_commit", {"delete_manifest", dir, FID1, "1"}));
        {
            auto d = open_store(dir);
            d->set_deletions_allowed(true);
            d->set_min_sweep_age(0);
            std::vector<uint8_t> got;
            std::string msg;
            CHECK(d->get_manifest(FID1, 1, got, &msg) == ENOENT && d->info().seq == 2);
            CHECK(fs::exists(dir + "/manifests/" + FID1 + "/1.mf"));
            SweepOut s = d->sweep(0, 10, false);
            CHECK(s.err == 0 && s.strays_removed == 1 && s.chunks_deleted == 2 &&
                  !fs::exists(dir + "/manifests/" + FID1 + "/1.mf"));  // x and y are unlisted now
            CHECK(!at(d->has_chunks({x.id}), 0) && !at(d->has_chunks({y.id}), 0));
        }
        // sweep: dies before the commit
        Sealed z = seal(pattern(1700, 74));
        {
            auto d = open_store(dir);
            put(*d, z);
        }
        CHECK(crash_run("device.sweep.before_commit", {"sweep", dir, "0"}));
        {
            auto d = open_store(dir);
            CHECK(at(d->has_chunks({z.id}), 0) && fs::exists(chunk_file(dir, z.id)));
        }
        // ... and after it: the row is gone, the file is a stray; the chunk is simply not there, and the next sweep cleans up
        CHECK(crash_run("device.sweep.after_commit", {"sweep", dir, "0"}));
        {
            auto d = open_store(dir);
            d->set_deletions_allowed(true);
            d->set_min_sweep_age(0);
            CHECK(!at(d->has_chunks({z.id}), 0) && fs::exists(chunk_file(dir, z.id)));
            std::vector<uint8_t> got;
            std::string msg;
            CHECK(d->get_chunk(z.id, got, &msg) == ENOENT);
            CHECK(d->sweep(0, 10, false).strays_removed == 1 && !fs::exists(chunk_file(dir, z.id)));
            // the chunk can be uploaded again, and is then served
            CHECK(put(*d, z).err == 0 && d->get_chunk(z.id, got, &msg) == 0);
        }
        fs::remove_all(dir);
    }

    {
        printf("== garbage collection: sweeping while uploads race never strands a manifest\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        d->set_deletions_allowed(true);
        d->set_min_sweep_age(0);  // the most aggressive sweep there is: no grace at all
        std::atomic<bool> stop{false};
        std::atomic<int> accepted{0}, refused_missing{0}, bad{0};
        std::thread sweeper([&] {
            while (!stop) {
                d->sweep(0, 1000, false);
                std::this_thread::sleep_for(std::chrono::milliseconds(2));  // (an unfair mutex would otherwise let this loop starve the uploaders)
            }
        });
        std::vector<std::thread> uploaders;
        for (int t = 0; t < 3; t++)
            uploaders.emplace_back([&, t] {
                for (int i = 0; i < 40; i++) {
                    Sealed s1 = seal(pattern(1200, static_cast<uint8_t>(t * 50 + i))),
                           s2 = seal(pattern(1300, static_cast<uint8_t>(t * 50 + i + 100)));
                    put(*d, s1);
                    put(*d, s2);
                    std::string fid = crypto::to_hex(crypto::random_bytes(16).data(), 16);
                    PutManifestOut m = put_man(*d, fid, 1, pattern(200, static_cast<uint8_t>(i)), {s1.id, s2.id});
                    if (m.err == 0)
                        accepted++;
                    else if (m.err == ENOENT)
                        refused_missing++;  // the sweeper got a chunk first: the manifest was refused, which is safe
                    else
                        bad++;
                }
            });
        for (auto& u : uploaders) u.join();
        stop = true;
        sweeper.join();
        CHECK(bad == 0 && accepted + refused_missing == 120);
        // every manifest that was accepted still has all its chunks
        std::vector<ManifestEntry> l;
        d->list_manifests(0, 1000, l, nullptr);
        CHECK(l.size() == static_cast<size_t>(accepted.load()));
        d->set_deletions_allowed(false);
        GcStatus g = d->gc_status();
        CHECK(g.manifests == static_cast<uint32_t>(accepted.load()) && g.chunks >= static_cast<uint64_t>(2 * accepted.load()) &&
              g.manifests_without_refs == 0);
        sqlite3* db = raw_open(dir);
        sqlite3_stmt* st = nullptr;
        sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM manifest_refs r WHERE NOT EXISTS(SELECT 1 FROM chunks c WHERE c.chunk_id=r.chunk_id)", -1, &st,
                           nullptr);
        CHECK(sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 0);
        sqlite3_finalize(st);
        sqlite3_close(db);
        fs::remove_all(dir);
    }

    {
        printf("== the trash: a deletion is kept for a while and can be undone (ADR-0017)\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        d->set_deletions_allowed(true);
        d->set_min_sweep_age(0);
        CHECK(d->trash_retention() == DEFAULT_TRASH_RETENTION);  // seven days unless told otherwise
        d->set_trash_retention(3600);
        Sealed a = seal(pattern(1500, 71)), b = seal(pattern(1600, 72)), c = seal(pattern(1700, 73));
        for (auto* x : {&a, &b, &c}) put(*d, *x);
        Bytes m1 = pattern(300, 74), m2 = pattern(310, 75);
        CHECK(put_man(*d, FID1, 1, m1, {a.id, b.id}).err == 0 && put_man(*d, FID2, 1, m2, {b.id, c.id}).err == 0);
        auto trash_files = [&](const std::string& sub) {
            std::vector<std::string> v;
            std::error_code ec;
            for (auto& e : fs::recursive_directory_iterator(dir + "/trash/" + sub, ec))
                if (e.is_regular_file()) v.push_back(e.path().string());
            std::sort(v.begin(), v.end());
            return v;
        };
        CHECK(d->trash_stats().chunks == 0 && d->trash_stats().manifests == 0 && d->trash_stats().oldest == 0 && !fs::exists(dir + "/trash"));
        int64_t t0 = time(nullptr);
        // deleting a manifest keeps it, with its chunk list
        DeleteManifestsOut del = d->delete_manifests({{FID1, 1}});
        CHECK(del.err == 0 && del.deleted[0] == 1 && !fs::exists(dir + "/manifests/" + FID1 + "/1.mf"));
        auto mf = trash_files("manifests");
        CHECK(mf.size() == 2);
        std::string mf_path, refs_path;
        for (auto& f : mf) (f.size() > 3 && f.compare(f.size() - 3, 3, ".mf") == 0 ? mf_path : refs_path) = f;
        CHECK(!mf_path.empty() && !refs_path.empty() && fs::path(mf_path).parent_path().filename() == FID1);
        {
            std::ifstream f(mf_path, std::ios::binary);
            Bytes got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            std::ifstream r(refs_path);
            std::string refs((std::istreambuf_iterator<char>(r)), std::istreambuf_iterator<char>());
            std::string want = a.id < b.id ? a.id + "\n" + b.id + "\n" : b.id + "\n" + a.id + "\n";
            CHECK(got == m1 && refs == want);  // the manifest as stored, and its chunk list, one id a line, in order
        }
        // a sweep keeps the chunk it removes
        SweepOut sw = d->sweep(0, 10, false);
        CHECK(sw.err == 0 && sw.chunks_deleted == 1 && !fs::exists(chunk_file(dir, a.id)) && !at(d->has_chunks({a.id}), 0));
        auto ch = trash_files("chunks");
        CHECK(ch.size() == 1 && ch[0].find(a.id + ".") != std::string::npos && ch[0].size() > 5 && ch[0].compare(ch[0].size() - 5, 5, ".blob") == 0);
        {
            std::ifstream f(ch[0], std::ios::binary);
            Bytes got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            CHECK(got == a.blob);
        }
        TrashStats ts = d->trash_stats();
        CHECK(ts.chunks == 1 && ts.chunk_bytes == a.blob.size() && ts.manifests == 1 && ts.manifest_bytes >= m1.size() && ts.oldest >= t0 &&
              ts.newest >= ts.oldest && ts.newest <= time(nullptr));
        GcStatus gs = d->gc_status();
        CHECK(gs.trash_files == 3 && gs.trash_bytes == ts.chunk_bytes + ts.manifest_bytes && gs.trash_retention_s == 3600);
        // purging respects the retention exactly
        CHECK(d->trash_purge(ts.newest + 3599) == 0 && d->trash_stats().chunks == 1);
        // (the oldest item went in at ts.oldest: it goes at ts.oldest + 3600, the newest at ts.newest + 3600)
        // restoring: the chunk and the manifest, with its chunk list, come back through the normal paths
        uint64_t seq_before = d->info().seq;
        TrashRestoreOut rs = d->trash_restore(0);
        CHECK(rs.err == 0 && rs.chunks == 1 && rs.manifests == 1 && rs.skipped == 0 && rs.notes.empty());
        std::vector<uint8_t> got;
        std::string msg;
        CHECK(at(d->has_chunks({a.id}), 0) && d->get_chunk(a.id, got, &msg) == 0 && got == a.blob);
        CHECK(d->get_manifest(FID1, 1, got, &msg) == 0 && got == m1 && d->info().seq == seq_before + 1);  // a restored manifest is a new commit
        CHECK(d->trash_stats().chunks == 0 && d->trash_stats().manifests == 0 && trash_files("chunks").empty() && trash_files("manifests").empty());
        CHECK(!fs::exists(dir + "/trash/manifests/" + FID1));
        GcStatus back = d->gc_status();
        CHECK(back.manifests_without_refs == 0 && back.unreferenced_chunks == 0);  // its chunk list is back, so a sweep takes nothing that it needs
        CHECK(d->sweep(0, 10, false).chunks_deleted == 0 && at(d->has_chunks({a.id}), 0) && at(d->has_chunks({b.id}), 0));
        CHECK(d->trash_restore(0).chunks == 0);  // nothing left to restore

        // the window: only what went in recently
        CHECK(d->delete_manifests({{FID1, 1}}).deleted[0] == 1 && d->sweep(0, 10, false).chunks_deleted == 1);
        for (auto& f : trash_files("chunks")) {  // pretend the chunk went in a day ago
            std::string old_name = fs::path(f).parent_path().string() + "/" + a.id + "." + std::to_string(time(nullptr) - 86400) + ".blob";
            fs::rename(f, old_name);
        }
        TrashRestoreOut win = d->trash_restore(600);
        CHECK(win.chunks == 0 && win.manifests == 0 &&
              !at(d->has_chunks({a.id}), 0));  // the manifest is recent but its chunk is too old; it needs the chunk
        CHECK(win.skipped == 1 && !win.notes.empty() && win.notes[0].find("not present") != std::string::npos);
        TrashRestoreOut all = d->trash_restore(2 * 86400);
        CHECK(all.chunks == 1 && all.manifests == 1 && at(d->has_chunks({a.id}), 0) && d->get_manifest(FID1, 1, got, &msg) == 0);

        // a chunk that was uploaded again meanwhile: the trashed copy is not put over it
        CHECK(d->delete_manifests({{FID1, 1}}).deleted[0] == 1 && d->sweep(0, 10, false).chunks_deleted == 1);
        put(*d, a);
        TrashRestoreOut dup = d->trash_restore(0);
        CHECK(dup.chunks == 0 && dup.manifests == 1 && dup.skipped == 1 && at(d->has_chunks({a.id}), 0));

        // the chunk list was lost or damaged: the manifest is not restored, and the reason is given
        CHECK(d->trash_purge(0, true) > 0 && d->trash_stats().chunks == 0);  // (start from an empty trash)
        CHECK(d->delete_manifests({{FID1, 1}}).deleted[0] == 1);
        for (auto& f : trash_files("manifests"))
            if (f.size() > 5 && f.compare(f.size() - 5, 5, ".refs") == 0) fs::remove(f);
        TrashRestoreOut norefs = d->trash_restore(0);
        CHECK(norefs.manifests == 0 && norefs.skipped == 1 && norefs.notes.size() == 1 &&
              norefs.notes[0].find("chunk list was not kept") != std::string::npos);
        for (auto& f : trash_files("manifests")) fs::remove(f);
        CHECK(d->delete_manifests({{FID2, 1}}).deleted[0] == 1);
        for (auto& f : trash_files("manifests"))
            if (f.size() > 5 && f.compare(f.size() - 5, 5, ".refs") == 0) std::ofstream(f, std::ios::trunc) << "not a chunk id\n";
        TrashRestoreOut badrefs = d->trash_restore(0);
        CHECK(badrefs.manifests == 0 && badrefs.skipped == 1 && badrefs.notes[0].find("damaged") != std::string::npos);

        // files in the trash directory that are not ours are neither counted, restored nor purged
        fs::create_directories(dir + "/trash/chunks");
        std::ofstream(dir + "/trash/chunks/notes.txt") << "mine";
        std::ofstream(dir + "/trash/chunks/" + std::string(64, 'g') + ".5.blob") << "x";
        std::ofstream(dir + "/trash/chunks/" + std::string(64, 'a') + ".x.blob") << "x";
        fs::create_directories(dir + "/trash/manifests/not-a-file-id");
        std::ofstream(dir + "/trash/manifests/not-a-file-id/1.5.mf") << "x";
        uint64_t before_purge = d->trash_stats().manifests;
        d->trash_purge(time(nullptr) + 1000000);
        CHECK(fs::exists(dir + "/trash/chunks/notes.txt") && fs::exists(dir + "/trash/manifests/not-a-file-id/1.5.mf") && before_purge <= 1);
        CHECK(d->trash_stats().chunks == 0 && trash_files("manifests").size() == 1 /* only the foreign one */);
        // purging for good, and "everything"
        CHECK(put_man(*d, FID1, 1, m1, {a.id, b.id}).err == 0);
        CHECK(d->delete_manifests({{FID1, 1}}).deleted[0] == 1);
        CHECK(d->trash_stats().manifests == 1);
        CHECK(d->trash_purge(time(nullptr) + 3599) == 0 && d->trash_stats().manifests == 1);
        CHECK(d->trash_purge(time(nullptr) + 3601) == 2 && d->trash_stats().manifests == 0 && !fs::exists(dir + "/trash/manifests/" + FID1));
        CHECK(fs::exists(dir + "/trash/chunks/notes.txt"));  // still not ours, still there
        fs::remove_all(dir);
    }

    {
        printf("== the trash: names, times and files that are not ours; exact boundaries; unreadable files\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        d->set_deletions_allowed(true);
        d->set_min_sweep_age(0);
        d->set_trash_retention(3600);
        const int64_t T = 1000000000;  // a fixed time long ago: names are written by hand below
        fs::create_directories(dir + "/trash/chunks");
        fs::create_directories(dir + "/trash/manifests/" + FID1);
        std::string c64(64, 'a'), c64b(64, 'b');
        auto make = [&](const std::string& path, const std::string& text = "x") { std::ofstream(path, std::ios::binary) << text; };
        // none of these is a trash file of ours: not counted, not restored, not purged
        std::vector<std::string> foreign = {
            dir + "/trash/chunks/" + c64 + ".5.bak",                              // another extension
            dir + "/trash/chunks/" + c64 + ".blob",                               // no time
            dir + "/trash/chunks/" + c64 + "..blob",                              // an empty time
            dir + "/trash/chunks/" + c64 + ".x5.blob",                            // a time that is not a number
            dir + "/trash/chunks/" + c64 + "." + std::string(25, '7') + ".blob",  // a number too long to be a time
            dir + "/trash/chunks/" + std::string(64, 'g') + ".5.blob",            // not hex
            dir + "/trash/chunks/" + std::string(63, 'a') + ".5.blob",            // too short
            dir + "/trash/chunks/5.blob",
            dir + "/trash/chunks/1.5.mf",  // a manifest file among the chunks
            dir + "/trash/chunks/1.5.refs",
            dir + "/trash/manifests/" + FID1 + "/" + c64 + ".5.blob",  // a chunk among the manifests
            dir + "/trash/manifests/" + FID1 + "/x.5.mf",              // a version that is not a number
            dir + "/trash/manifests/" + FID1 + "/1..mf",
            dir + "/trash/manifests/" + FID1 + "/1.mf",
            dir + "/trash/manifests/" + FID1 + "/1.5.txt",
            dir + "/trash/manifests/" + FID1 + "/.5.mf",
        };
        for (auto& f : foreign) make(f);
        fs::create_directories(dir + "/trash/chunks/" + c64b + ".7.blob");  // a directory with a trash file's name
        make(dir + "/trash/chunks/" + c64b + ".7.blob/inside.txt");
        fs::create_directories(dir + "/trash/manifests/" + std::string(31, 'a'));  // not a file id
        make(dir + "/trash/manifests/" + std::string(31, 'a') + "/1.5.mf");
        fs::create_directories(dir + "/trash/manifests/" + std::string(32, 'G'));
        make(dir + "/trash/manifests/" + std::string(32, 'G') + "/1.5.mf");
        TrashStats none = d->trash_stats();
        CHECK(none.chunks == 0 && none.manifests == 0 && none.chunk_bytes == 0 && none.manifest_bytes == 0 && none.oldest == 0 && none.newest == 0);
        CHECK(d->gc_status().trash_files == 0 && d->trash_purge(T + 10000000000ll, false) == 0);
        for (auto& f : foreign) CHECK(fs::exists(f));
        CHECK(fs::exists(dir + "/trash/chunks/" + c64b + ".7.blob/inside.txt") &&
              fs::exists(dir + "/trash/manifests/" + std::string(31, 'a') + "/1.5.mf") &&
              fs::exists(dir + "/trash/manifests/" + std::string(32, 'G') + "/1.5.mf"));
        TrashRestoreOut nothing = d->trash_restore(0);
        CHECK(nothing.chunks == 0 && nothing.manifests == 0 && nothing.skipped == 0);
        CHECK(d->trash_purge(0, true) == 0 && fs::exists(foreign[0]));  // not even "everything" touches what is not ours

        // real ones, with times written by hand: the oldest and the newest, and the exact moment of purging
        Sealed a = seal(pattern(1500, 91)), b = seal(pattern(1600, 92));
        make(dir + "/trash/chunks/" + a.id + "." + std::to_string(T) + ".blob", std::string(a.blob.begin(), a.blob.end()));
        make(dir + "/trash/chunks/" + b.id + "." + std::to_string(T + 500) + ".blob", std::string(b.blob.begin(), b.blob.end()));
        TrashStats two = d->trash_stats();
        CHECK(two.chunks == 2 && two.oldest == T && two.newest == T + 500 && two.chunk_bytes == a.blob.size() + b.blob.size());
        CHECK(d->trash_purge(T + 3599) == 0 && d->trash_stats().chunks == 2);  // not yet
        CHECK(d->trash_purge(T + 3600) == 1 && d->trash_stats().chunks == 1);  // exactly the retention: gone
        CHECK(d->trash_purge(T + 4099) == 0 && d->trash_stats().chunks == 1);
        CHECK(d->trash_purge(T + 4100) == 1 && d->trash_stats().chunks == 0);
        // a file that cannot be removed is not counted as removed
        make(dir + "/trash/chunks/" + a.id + "." + std::to_string(T) + ".blob", std::string(a.blob.begin(), a.blob.end()));
        chmod((dir + "/trash/chunks").c_str(), 0500);
        CHECK(d->trash_purge(T + 100000) == 0 && d->trash_stats().chunks == 1);
        chmod((dir + "/trash/chunks").c_str(), 0700);
        CHECK(d->trash_purge(T + 100000) == 1 && d->trash_stats().chunks == 0);

        // a chunk trashed twice (an old copy and a newer one): the newest wins
        make(dir + "/trash/chunks/" + a.id + "." + std::to_string(T) + ".blob", "an older, different copy");
        make(dir + "/trash/chunks/" + a.id + "." + std::to_string(T + 9) + ".blob", std::string(a.blob.begin(), a.blob.end()));
        TrashRestoreOut twice = d->trash_restore(0);
        std::vector<uint8_t> got;
        std::string msg;
        CHECK(twice.chunks == 1 && twice.skipped == 1 && d->get_chunk(a.id, got, &msg) == 0 && got == a.blob);
        d->trash_purge(0, true);  // (the older copy was skipped and is still there: clear it away)
        // a chunk that cannot be read is skipped, and the reason is given
        make(dir + "/trash/chunks/" + b.id + "." + std::to_string(T) + ".blob", std::string(b.blob.begin(), b.blob.end()));
        chmod((dir + "/trash/chunks/" + b.id + "." + std::to_string(T) + ".blob").c_str(), 0);
        TrashRestoreOut unread = d->trash_restore(0);
        CHECK(unread.chunks == 0 && unread.skipped == 1 && unread.notes.size() == 1 &&
              unread.notes[0].find("cannot read the trashed file") != std::string::npos);
        chmod((dir + "/trash/chunks/" + b.id + "." + std::to_string(T) + ".blob").c_str(), 0600);
        CHECK(d->trash_restore(0).chunks == 1);

        // a manifest whose saved chunk list has no final newline still restores every chunk in it; and one that was uploaded again is not counted
        // twice
        Bytes mblob = pattern(300, 93);
        make(dir + "/trash/manifests/" + FID1 + "/3." + std::to_string(T) + ".mf", std::string(mblob.begin(), mblob.end()));
        make(dir + "/trash/manifests/" + FID1 + "/3." + std::to_string(T) + ".refs", a.id + "\n" + b.id);  // (no newline at the end)
        TrashRestoreOut m = d->trash_restore(0);
        CHECK(m.manifests == 1 && m.skipped == 0 && d->get_manifest(FID1, 3, got, &msg) == 0 && got == mblob);
        CHECK(d->delete_manifests({{FID1, 3}}).deleted[0] == 1);
        CHECK(d->sweep(0, 10, false).chunks_deleted ==
              2);  // only because the restored manifest's list had BOTH chunks, a sweep after deleting it takes both
        CHECK(put_man(*d, FID1, 3, mblob, {a.id, b.id}).err != 0);  // (the chunks are in the trash now, so this cannot be uploaded)
        TrashRestoreOut back = d->trash_restore(0);
        CHECK(back.chunks == 2 && back.manifests == 1);
        CHECK(d->delete_manifests({{FID1, 3}}).deleted[0] == 1);
        CHECK(put_man(*d, FID1, 3, mblob, {a.id, b.id}).err == 0);  // uploaded again by the Mac before anyone restores
        TrashRestoreOut dup = d->trash_restore(0);
        CHECK(dup.manifests == 0 && dup.skipped == 1);
        // restoring one manifest does not take the trash of another of the same file with it
        CHECK(d->delete_manifests({{FID1, 3}}).deleted[0] == 1);
        make(dir + "/trash/manifests/" + FID1 + "/4." + std::to_string(T) + ".mf",
             std::string(mblob.begin(), mblob.end()));  // (no chunk list: cannot be restored)
        TrashRestoreOut partial = d->trash_restore(0);
        CHECK(partial.manifests == 1 && partial.skipped == 1 && fs::exists(dir + "/trash/manifests/" + FID1 + "/4." + std::to_string(T) + ".mf"));
        // a deletion that cannot keep the chunk list in the trash does not happen at all
        CHECK(put_man(*d, FID2, 1, mblob, {a.id, b.id}).err == 0);
        chmod((dir + "/trash/manifests").c_str(), 0500);  // (nothing can be created in it, and FID2 has no directory there yet)
        DeleteManifestsOut nokeep = d->delete_manifests({{FID2, 1}});
        CHECK(nokeep.err != 0 && has(nokeep.msg.c_str(), "cannot keep the chunk list in the trash") && d->get_manifest(FID2, 1, got, &msg) == 0);
        chmod((dir + "/trash/manifests").c_str(), 0700);
        CHECK(d->delete_manifests({{FID2, 1}}).deleted[0] == 1);
        fs::remove_all(dir);
    }

    {
        printf("== the trash: two things trashed in the same second do not overwrite each other, and a manifest keeps its own chunk list\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        d->set_deletions_allowed(true);
        d->set_min_sweep_age(0);
        d->set_trash_retention(3600);
        Sealed a = seal(pattern(1500, 95)), b = seal(pattern(1600, 96));
        put(*d, a);
        put(*d, b);
        Bytes m1 = pattern(300, 97), m2 = pattern(310, 98);
        // the same version number deleted, stored again with a different chunk list and deleted again, all in one second
        CHECK(put_man(*d, FID1, 1, m1, {a.id}).err == 0 && d->delete_manifests({{FID1, 1}}).deleted[0] == 1);
        CHECK(put_man(*d, FID1, 1, m2, {b.id}).err == 0 && d->delete_manifests({{FID1, 1}}).deleted[0] == 1);
        CHECK(put_man(*d, FID1, 1, m1, {a.id, b.id}).err == 0 && d->delete_manifests({{FID1, 1}}).deleted[0] == 1);
        TrashStats ts = d->trash_stats();
        CHECK(ts.manifests == 3);                                             // three trashed manifests, none overwritten
        CHECK(ts.newest - ts.oldest < 10 && ts.newest <= time(nullptr) + 5);  // and the times are still about now, not pushed far away
        // every manifest has exactly the chunk list it had (paired by its time)
        std::map<std::string, std::string> refs_by_stem;
        std::map<std::string, Bytes> mf_by_stem;
        for (auto& e : fs::directory_iterator(dir + "/trash/manifests/" + FID1)) {
            std::string name = e.path().filename().string();
            std::ifstream f(e.path(), std::ios::binary);
            std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            if (name.size() > 5 && name.compare(name.size() - 5, 5, ".refs") == 0)
                refs_by_stem[name.substr(0, name.size() - 5)] = text;
            else if (name.size() > 3 && name.compare(name.size() - 3, 3, ".mf") == 0)
                mf_by_stem[name.substr(0, name.size() - 3)] = Bytes(text.begin(), text.end());
        }
        CHECK(refs_by_stem.size() == 3 && mf_by_stem.size() == 3);
        int matched = 0;
        for (auto& kv : mf_by_stem) {
            auto r = refs_by_stem.find(kv.first);
            if (r == refs_by_stem.end()) continue;
            if (kv.second == m2 && r->second == b.id + "\n")
                matched++;
            else if (kv.second == m1 &&
                     (r->second == a.id + "\n" || r->second == (a.id < b.id ? a.id + "\n" + b.id + "\n" : b.id + "\n" + a.id + "\n")))
                matched++;
        }
        CHECK(matched == 3);
        // a leftover chunk list from a failed deletion (no manifest next to it) is not overwritten either
        {
            const int64_t now0 = time(nullptr);
            fs::create_directories(dir + "/trash/manifests/" + FID2);
            for (int64_t t = now0 - 1; t <= now0 + 1; t++)
                std::ofstream(dir + "/trash/manifests/" + FID2 + "/1." + std::to_string(t) + ".refs") << "stale\n";
            CHECK(put_man(*d, FID2, 1, m1, {a.id}).err == 0 && d->delete_manifests({{FID2, 1}}).deleted[0] == 1);
            for (int64_t t = now0 - 1; t <= now0 + 1; t++) {
                std::ifstream f(dir + "/trash/manifests/" + FID2 + "/1." + std::to_string(t) + ".refs");
                std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                CHECK(text == "stale\n");
            }
        }
        // the same chunk swept twice in one second, with a copy put back in between
        CHECK(d->sweep(0, 10, false).chunks_deleted == 2);  // a and b are unreferenced now
        put(*d, a);
        put(*d, b);
        CHECK(d->sweep(0, 10, false).chunks_deleted == 2);  // swept again
        CHECK(d->trash_stats().chunks == 4);                // four trashed chunk files: nothing was overwritten
        fs::remove_all(dir);
    }

    {
        printf("== the trash: retention zero deletes at once, the setting is honoured, and strays are kept too\n");
        std::string dir = tmpdir();
        auto d = open_store(dir);
        d->set_deletions_allowed(true);
        d->set_min_sweep_age(0);
        d->set_trash_retention(0);
        Sealed a = seal(pattern(1500, 81)), b = seal(pattern(1600, 82));
        put(*d, a);
        put(*d, b);
        CHECK(put_man(*d, FID1, 1, pattern(300, 83), {a.id}).err == 0);
        CHECK(d->delete_manifests({{FID1, 1}}).deleted[0] == 1 && d->sweep(0, 10, false).chunks_deleted == 2);
        CHECK(!fs::exists(dir + "/trash") && d->trash_stats().chunks == 0 && d->gc_status().trash_files == 0 &&
              d->gc_status().trash_retention_s == 0);
        d->set_trash_retention(-5);
        CHECK(d->trash_retention() == 0);  // never negative
        d->set_trash_retention(86400);
        CHECK(d->trash_retention() == 86400 && d->gc_status().trash_retention_s == 86400);
        // a stray (no index row) older than the age goes to the trash too, not away for good
        std::string id(64, 'b');
        fs::create_directories(dir + "/chunks/bb");
        std::string stray = dir + "/chunks/bb/" + id + ".blob";
        std::ofstream(stray) << "leftover";
        struct timespec ts[2];
        ts[0].tv_sec = ts[1].tv_sec = time(nullptr) - 7200;
        ts[0].tv_nsec = ts[1].tv_nsec = 0;
        utimensat(AT_FDCWD, stray.c_str(), ts, 0);
        std::string mdir = dir + "/manifests/" + FID2;
        fs::create_directories(mdir);
        std::ofstream(mdir + "/4.mf") << "leftover manifest";
        utimensat(AT_FDCWD, (mdir + "/4.mf").c_str(), ts, 0);
        SweepOut s = d->sweep(3600, 10, false);
        CHECK(s.err == 0 && s.strays_removed == 2 && !fs::exists(stray) && !fs::exists(mdir + "/4.mf"));
        TrashStats st = d->trash_stats();
        CHECK(st.chunks == 1 && st.manifests == 1);
        // restoring a stray manifest is refused (no chunk list), restoring the stray chunk works
        TrashRestoreOut r = d->trash_restore(0);
        CHECK(r.manifests == 0 && r.skipped >= 1);
        fs::remove_all(dir);
    }

    {
        printf("== never wipes or repairs a store it does not understand\n");
        std::string d1 = tmpdir(), d2 = tmpdir();
        std::string garbage(6000, 'x');
        { std::ofstream f(d1 + "/device.db", std::ios::binary); f << garbage; }
        std::string err;
        CHECK(!DeviceStore::open(d1, &err) && !err.empty());
        std::ifstream in(d1 + "/device.db", std::ios::binary);
        std::string after((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        CHECK(after == garbage);
        { auto d = open_store(d2); }
        { sqlite3* db = raw_open(d2); raw_exec(db, "PRAGMA user_version=77"); sqlite3_close(db); }
        CHECK(!DeviceStore::open(d2, &err) && has(err, "not understood"));
        fs::remove_all(d1); fs::remove_all(d2);
    }

    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
