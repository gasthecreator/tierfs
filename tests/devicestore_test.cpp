// Tests for the device store: durability ordering under crashes, append-only rules,
// audits against real crypto, and every misbehaving-device mode.
#include <fcntl.h>
#include <spawn.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <thread>

#include "../core/crypto.hpp"
#include "../core/devicestore.hpp"

extern char** environ;
using namespace tierfs;
using crypto::Bytes;
namespace fs = std::filesystem;

static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) { printf("FAIL  line %d: %s\n", __LINE__, #cond); failures++; } \
        else printf("PASS  %s\n", #cond);                                          \
    } while (0)


// Safe element access for assertions: a failed earlier check must not become a crash that hides it.
template <class T> static const T& at(const std::vector<T>& v, size_t i) { static const T dummy{}; return i < v.size() ? v[i] : dummy; }
static bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }
static std::string tmpdir() {
    char t[] = "/tmp/tierfs-devtest-XXXXXX";
    return mkdtemp(t);
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
