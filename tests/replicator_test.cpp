// Integration tests of the replicate engine: real files, a real device process, a real ledger, real
// encryption. The point is to make it commit something it should not, or lose track of something.
#include <fcntl.h>
#include <signal.h>
#include <sqlite3.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <utime.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <thread>

#include "../core/replicator.hpp"

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

template <class T> static const T& at(const std::vector<T>& v, size_t i) { static const T dummy{}; return i < v.size() ? v[i] : dummy; }
static bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }
static std::string tmpdir() {
    char t[] = "/tmp/tierfs-repltest-XXXXXX";
    return mkdtemp(t);
}
static Bytes pattern(size_t n, uint8_t seed) {
    Bytes v(n);
    for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(seed + i * 41 + (i >> 8) + (i >> 20) * 7);
    return v;
}
static Bytes slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
static void spit(const std::string& p, const Bytes& b) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}
static size_t count_files(const std::string& dir, const char* ext = nullptr) {
    size_t n = 0;
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(dir, ec))
        if (e.is_regular_file() && (!ext || e.path().extension() == ext)) n++;
    return n;
}

struct Server {
    pid_t pid = 0;
    uint16_t port;
    std::string store;
    explicit Server(uint16_t p) : port(p) {}
    bool start(const std::string& store_dir, std::vector<std::string> extra = {}) {
        stop();
        store = store_dir;
        std::vector<std::string> a = {"tierfs-device", store_dir, std::to_string(port), "127.0.0.1"};
        a.insert(a.end(), extra.begin(), extra.end());
        std::vector<char*> av;
        for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
        av.push_back(nullptr);
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
        posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
        const char* path = getenv("TIERFS_DEVICE_SERVER") ? getenv("TIERFS_DEVICE_SERVER") : "./build/tierfs-device";
        int rc = posix_spawn(&pid, path, &fa, nullptr, av.data(), environ);
        posix_spawn_file_actions_destroy(&fa);
        if (rc != 0) return false;
        for (int i = 0; i < 100; i++) {
            DeviceClient c("127.0.0.1", port, 300);
            DevInfo info;
            if (c.info(info).ok()) return true;
            usleep(50000);
        }
        return false;
    }
    void stop() {
        if (!pid) return;
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        pid = 0;
    }
    ~Server() { stop(); }
};

struct Env {
    std::string root = tmpdir();
    crypto::SecretKey master = crypto::SecretKey::random();
    std::unique_ptr<crypto::Keys> keys = std::make_unique<crypto::Keys>(master);
    std::unique_ptr<Ledger> L;
    std::unique_ptr<Replicator> R;
    Env() {
        fs::create_directories(root + "/files");
        open_ledger();
    }
    ~Env() { R.reset(); L.reset(); fs::remove_all(root); }
    void open_ledger() {
        std::string err;
        L = Ledger::open(root + "/ledger", &err);
        if (L) R = std::make_unique<Replicator>(*L, *keys, L->volume_id());
    }
    void close_ledger() { R.reset(); L.reset(); }
    std::string path(const std::string& name) const { return root + "/files/" + name; }
    std::string write(const std::string& name, const Bytes& b) { spit(path(name), b); return path(name); }
    std::string track(const std::string& name) {
        struct stat st;
        stat(path(name).c_str(), &st);
        return L->track_file("/testdata/" + name, static_cast<uint64_t>(st.st_size), st.st_mtimespec.tv_sec, st.st_mode & 0777);
    }
    std::string attach(DeviceClient& dev, const char* cls = "B", DeviceObservation* obs = nullptr) {
        std::string id;
        Res r = R->attach(dev, "test-device", cls, &id, obs);
        if (!r) printf("      attach failed: %s\n", r.why.c_str());
        return id;
    }
    // Everything we can check about a fully replicated file.
    bool intact(DeviceClient& dev, const std::string& fid, const std::string& file_name) {
        Bytes got;
        Res r = R->fetch_version(dev, fid, L->get_file(fid)->current_version, [&](const uint8_t* p, size_t n) { got.insert(got.end(), p, p + n); return true; });
        return r.ok && got == slurp(path(file_name));
    }
};

static bool spawn_helper(const Env& env, uint16_t port, const std::string& device_id, const std::string& file_id, const std::string& local,
                         const char* crash_point) {
    std::vector<std::string> e;
    for (char** x = environ; *x; x++) e.push_back(*x);
    e.push_back(std::string("TIERFS_CRASH_AT=") + crash_point);
    e.push_back("TIERFS_TEST_MASTER=" + crypto::to_hex(env.master.data(), 32));
    std::vector<char*> envp;
    for (auto& x : e) envp.push_back(const_cast<char*>(x.c_str()));
    envp.push_back(nullptr);
    std::vector<std::string> a = {"repl_helper", env.root + "/ledger", std::to_string(port), device_id, file_id, local};
    std::vector<char*> av;
    for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
    av.push_back(nullptr);
    const char* h = getenv("TIERFS_REPL_HELPER") ? getenv("TIERFS_REPL_HELPER") : "./build/repl_helper";
    pid_t pid;
    if (posix_spawn(&pid, h, nullptr, nullptr, av.data(), envp.data()) != 0) return false;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 137;
}

static const uint16_t PA = 9401, PB = 9402;
static const size_t MiB = 1u << 20;

int main() {
    signal(SIGPIPE, SIG_IGN);
    std::string stores = tmpdir();
    Server sa(PA), sb(PB);

    {
        printf("== a file goes to a device, is proven there, and comes back identical\n");
        CHECK(sa.start(stores + "/a1"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev, "B");
        CHECK(did.size() == 32);
        struct Case { const char* name; size_t size; };
        for (Case c : {Case{"empty", 0}, Case{"one", 1}, Case{"exact", MiB}, Case{"plus1", MiB + 1}, Case{"multi", 2 * MiB + MiB / 2}, Case{"five", 5 * MiB}}) {
            env.write(c.name, pattern(c.size, static_cast<uint8_t>(c.size % 200)));
            std::string fid = env.track(c.name);
            ReplicateOutcome o = env.R->replicate(dev, did, fid, env.path(c.name));
            size_t chunks = (c.size + MiB - 1) / MiB;
            CHECK(o.ok && o.version == 1 && o.chunks_total == chunks && o.chunks_uploaded == chunks);
            auto f = env.L->get_file(fid);
            CHECK(f && f->state == FileState::REPLICATED && f->local_present);
            auto reps = env.L->get_replicas(fid, 1);
            CHECK(reps.size() == 1 && at(reps, 0).state == ReplicaState::COMMITTED && at(reps, 0).device_seq > 0);
            CHECK(env.intact(dev, fid, c.name));                                  // downloaded, decrypted, whole-file HMAC verified, byte-identical
            CHECK(env.L->challenges_left(fid, 1, MANIFEST_CHALLENGE_IDX) == 4);
            for (size_t i = 0; i < chunks; i++) CHECK(env.L->challenges_left(fid, 1, static_cast<int64_t>(i)) == 4);
            CHECK(env.L->get_manifest_hash(fid, 1).has_value());
        }
        CHECK(env.L->fsck().empty());
        // metadata travels with the file
        env.write("meta", pattern(3000, 5));
        setxattr(env.path("meta").c_str(), "user.tierfs.note", "kept", 4, 0, 0);
        chmod(env.path("meta").c_str(), 0640);
        std::string mid = env.track("meta");
        CHECK(env.R->replicate(dev, did, mid, env.path("meta")).ok);
        Bytes mb;
        crypto::Manifest man;
        CHECK(dev.get_manifest(mid, 1, mb).ok() && crypto::open_manifest(*env.keys, env.L->volume_id(), mid, 1, mb.data(), mb.size(), man) == crypto::OpenError::Ok);
        CHECK(man.path == "/testdata/meta" && man.mode == 0640 && man.size == 3000 && man.version == 1);
        bool found = false;
        for (auto& x : man.xattrs) found |= x.first == "user.tierfs.note" && x.second == Bytes({'k', 'e', 'p', 't'});
        CHECK(found);

        // doing it again changes nothing
        uint64_t ev = env.L->event_count();
        ReplicateOutcome again = env.R->replicate(dev, did, mid, env.path("meta"));
        CHECK(again.ok && again.already_done && env.L->event_count() == ev);
        DevInfo i;
        dev.info(i);
        CHECK(i.seq == 7);                                                         // six files plus "meta", one manifest each
    }

    {
        printf("== chunks the device already has are verified, not trusted\n");
        CHECK(sa.start(stores + "/a2"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        Bytes base = pattern(3 * MiB, 40);
        env.write("orig", base);
        std::string f1 = env.track("orig");
        CHECK(env.R->replicate(dev, did, f1, env.path("orig")).ok);
        env.write("copy", base);                                                   // identical content, different file
        std::string f2 = env.track("copy");
        ReplicateOutcome o = env.R->replicate(dev, did, f2, env.path("copy"));
        CHECK(o.ok && o.chunks_uploaded == 0 && o.chunks_already_present == 3 && o.chunks_audited >= 3);   // nothing sent, all three audited
        Bytes partial = base;                                                      // first two chunks shared, last one different
        for (size_t i = 2 * MiB; i < partial.size(); i++) partial[i] ^= 0x5c;
        env.write("part", partial);
        std::string f3 = env.track("part");
        ReplicateOutcome p = env.R->replicate(dev, did, f3, env.path("part"));
        CHECK(p.ok && p.chunks_uploaded == 1 && p.chunks_already_present == 2);
        CHECK(env.intact(dev, f1, "orig") && env.intact(dev, f2, "copy") && env.intact(dev, f3, "part"));
        CHECK(count_files(stores + "/a2/chunks", ".blob") == 4);                   // 3 + 1 new: stored once each
    }

    {
        printf("== a conflicting object on the device is refused, never overwritten or trusted\n");
        CHECK(sa.start(stores + "/a3"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        Bytes data = pattern(MiB + 500, 60);
        env.write("victim", data);
        std::string fid = env.track("victim");
        // someone files DIFFERENT bytes under the chunk id this file will need
        std::string cid = crypto::chunk_id(*env.keys, data.data(), MiB);
        Bytes junk = crypto::seal_chunk(*env.keys, "not-our-volume", cid, data.data(), MiB);
        PutChunkReply pr;
        CHECK(dev.put_chunk(cid, junk, pr).ok());
        ReplicateOutcome o = env.R->replicate(dev, did, fid, env.path("victim"));
        CHECK(!o.ok && has(o.why, "failed its audit") && env.L->get_file(fid)->local_present);   // the device LISTS the chunk, so it is audited, and fails
        auto reps = env.L->get_replicas(fid, 1);
        CHECK(at(reps, 0).state == ReplicaState::MISSING);                          // this device cannot be used for this chunk
        CHECK(env.L->get_file(fid)->state == FileState::REPLICATING && env.L->fsck().empty());
        Bytes still;
        CHECK(dev.get_chunk(cid, still).ok() && still == junk);                     // append-only: untouched

        // the same conflict discovered at upload time: the chunk appears between "what do you have?" and the PUT
        {
            CHECK(sa.start(stores + "/a3r"));
            Env envr;
            DeviceClient devr("127.0.0.1", PA, 3000);
            std::string didr = envr.attach(devr);
            envr.write("race", data);
            std::string fidr = envr.track("race");
            std::string cidr = crypto::chunk_id(*envr.keys, data.data(), MiB);   // THIS environment's id for the chunk (its own keys)
            envr.R->on_step = [&](const char* s) {
                if (!strcmp(s, "pass2_after_has")) {
                    Bytes j = crypto::seal_chunk(*envr.keys, "not-our-volume", cidr, data.data(), MiB);
                    PutChunkReply p2;
                    devr.put_chunk(cidr, j, p2);
                }
            };
            ReplicateOutcome orc = envr.R->replicate(devr, didr, fidr, envr.path("race"));
            if (orc.ok || !has(orc.why, "DIFFERENT bytes")) printf("      engine said: ok=%d why='%s'\n", orc.ok, orc.why.c_str());
            CHECK(!orc.ok && has(orc.why, "DIFFERENT bytes"));
            CHECK(at(envr.L->get_replicas(fidr, 1), 0).state == ReplicaState::MISSING);
        }

        // and a conflicting MANIFEST for a version
        Env env2;
        DeviceClient dev2("127.0.0.1", PA, 3000);
        CHECK(sa.start(stores + "/a3b"));
        std::string did2 = env2.attach(dev2);
        env2.write("m", pattern(2000, 61));
        std::string fid2 = env2.track("m");
        Bytes c1 = pattern(2000, 61);
        std::string c1id = crypto::chunk_id(*env2.keys, c1.data(), c1.size());
        Bytes c1blob = crypto::seal_chunk(*env2.keys, env2.L->volume_id(), c1id, c1.data(), c1.size());
        CHECK(dev2.put_chunk(c1id, c1blob, pr).ok());
        PutManifestReply pm;
        CHECK(dev2.put_manifest(fid2, 1, pattern(300, 1), {c1id}, pm).ok());        // a manifest we did not write
        ReplicateOutcome o2 = env2.R->replicate(dev2, did2, fid2, env2.path("m"));
        CHECK(!o2.ok && has(o2.why, "DIFFERENT manifest"));
        ReconcileReport rr = env2.R->reconcile(dev2, did2, false);
        CHECK(rr.ok && rr.conflicts.size() == 1);                                    // reconcile reports it as well
    }

    {
        printf("== a file that changes while it is being replicated is never committed\n");
        CHECK(sa.start(stores + "/a4"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        Bytes v1 = pattern(2 * MiB + 100, 70), v2 = pattern(2 * MiB + 100, 71);
        env.write("live", v1);
        std::string fid = env.track("live");
        int64_t gen0 = env.L->get_file(fid)->generation;

        env.R->on_step = [&](const char* s) { if (!strcmp(s, "pass1_done")) spit(env.path("live"), v2); };   // rewritten between the two reads
        ReplicateOutcome o = env.R->replicate(dev, did, fid, env.path("live"));
        CHECK(!o.ok && o.file_changed);
        auto f = env.L->get_file(fid);
        CHECK(f->state == FileState::LOCAL && f->generation > gen0 && f->current_version == 0 && env.L->get_replicas(fid, 1).empty());
        env.R->on_step = nullptr;
        ReplicateOutcome o2 = env.R->replicate(dev, did, fid, env.path("live"));
        CHECK(o2.ok && o2.version == 1 && env.intact(dev, fid, "live"));             // the NEW content is what was replicated

        // modified after the plan was recorded but before upload
        Bytes v3 = pattern(2 * MiB + 100, 72), v4 = pattern(2 * MiB + 100, 73);
        env.write("live2", v3);
        std::string fid2 = env.track("live2");
        env.R->on_step = [&](const char* s) { if (!strcmp(s, "pass2_start")) { spit(env.path("live2"), v4); } };
        ReplicateOutcome o3 = env.R->replicate(dev, did, fid2, env.path("live2"));
        CHECK(!o3.ok && o3.file_changed && has(o3.why, "no longer matches"));
        CHECK(env.L->get_file(fid2)->state == FileState::LOCAL && env.L->get_file(fid2)->current_version == 1);   // version 1 stays on record, immutable
        CHECK(env.L->get_replicas(fid2, 1).empty() || at(env.L->get_replicas(fid2, 1), 0).state != ReplicaState::COMMITTED);
        env.R->on_step = nullptr;
        ReplicateOutcome o4 = env.R->replicate(dev, did, fid2, env.path("live2"));
        CHECK(o4.ok && o4.version == 2 && env.intact(dev, fid2, "live2"));          // a NEW version for the new bytes
        CHECK(!env.L->get_chunks(fid2, 1).empty() && env.L->fsck().empty());

        // the FIRST chunk is rewritten (same size, same length) after it has already been read and uploaded:
        // later chunks still match the plan, so only the end-of-upload snapshot can tell
        Bytes early = pattern(4 * MiB, 77);
        env.write("early", early);
        std::string fide = env.track("early");
        env.R->on_step = [&](const char* s) {
            if (!strcmp(s, "pass2_mid")) {
                int fdw = ::open(env.path("early").c_str(), O_WRONLY);
                uint8_t b = 0xEE;
                pwrite(fdw, &b, 1, 10);
                close(fdw);
            }
        };
        ReplicateOutcome oe = env.R->replicate(dev, did, fide, env.path("early"));
        CHECK(!oe.ok && oe.file_changed && has(oe.why, "while it was being uploaded"));
        CHECK(env.L->get_file(fide)->state == FileState::LOCAL);
        env.R->on_step = nullptr;
        ReplicateOutcome oe2 = env.R->replicate(dev, did, fide, env.path("early"));
        CHECK(oe2.ok && env.intact(dev, fide, "early"));                                // the next attempt captures the new bytes

        // appended to after the plan was made: every planned chunk still matches, only the SIZE gives it away
        Bytes before_append = pattern(2 * MiB + 100, 76);
        env.write("grow", before_append);
        std::string fidg = env.track("grow");
        env.R->on_step = [&](const char* s) {
            if (!strcmp(s, "pass2_start")) { std::ofstream f(env.path("grow"), std::ios::binary | std::ios::app); f << "appended later"; }
        };
        ReplicateOutcome og = env.R->replicate(dev, did, fidg, env.path("grow"));
        CHECK(!og.ok && og.file_changed && has(og.why, "size differs"));
        CHECK(env.L->get_file(fidg)->state == FileState::LOCAL && env.L->get_replicas(fidg, 1).empty());
        env.R->on_step = nullptr;

        // touched (same bytes, new modification time) during the read: also refused
        env.write("touch", pattern(MiB + 7, 74));
        std::string fid3 = env.track("touch");
        env.R->on_step = [&](const char* s) { if (!strcmp(s, "pass1_done")) { utimbuf t{1000, 1000}; utime(env.path("touch").c_str(), &t); } };
        CHECK(!env.R->replicate(dev, did, fid3, env.path("touch")).ok);
        env.R->on_step = nullptr;
        // shrunk during the read
        env.write("shrink", pattern(3 * MiB, 75));
        std::string fid4 = env.track("shrink");
        env.R->on_step = [&](const char* s) { if (!strcmp(s, "pass2_start")) truncate(env.path("shrink").c_str(), MiB / 2); };
        env.R->replicate(dev, did, fid4, env.path("shrink"));
        // (pass 2 starts only after the plan, so this exercises the size check)
        CHECK(env.L->get_file(fid4)->state == FileState::LOCAL);
        env.R->on_step = nullptr;
    }

    {
        printf("== misbehaving devices are caught before anything is committed\n");
        for (const char* fault : {"lie_ack_chunk", "corrupt_on_store", "truncate_on_store"}) {
            std::string store = stores + "/f_" + fault;
            CHECK(sa.start(store, {std::string("--faults=") + fault}));
            Env env;
            DeviceClient dev("127.0.0.1", PA, 3000);
            std::string did = env.attach(dev);
            env.write("f", pattern(2 * MiB, 80));
            std::string fid = env.track("f");
            ReplicateOutcome o = env.R->replicate(dev, did, fid, env.path("f"));
            CHECK(!o.ok && has(o.why, "failed its audit"));
            auto reps = env.L->get_replicas(fid, 1);
            CHECK(at(reps, 0).state == ReplicaState::MISSING);
            CHECK(env.L->get_file(fid)->state == FileState::REPLICATING);            // never reached REPLICATED
            CHECK(env.L->replica_weight(fid, 1, 600) == 0.0 && env.L->fsck().empty());
            DevInfo i;
            dev.info(i);
            CHECK(i.seq == 0);                                                      // the manifest was never even sent
        }
        for (const char* fault : {"lie_ack_manifest", "lose_manifest_after_commit"}) {   // chunks are fine; the MANIFEST is the lie
            std::string store = stores + "/fm_" + fault;
            CHECK(sa.start(store, {std::string("--faults=") + fault}));
            Env env;
            DeviceClient dev("127.0.0.1", PA, 3000);
            std::string did = env.attach(dev);
            env.write("f", pattern(MiB + 3, 84));
            std::string fid = env.track("f");
            ReplicateOutcome o = env.R->replicate(dev, did, fid, env.path("f"));
            CHECK(!o.ok && has(o.why, "manifest audit"));
            CHECK(at(env.L->get_replicas(fid, 1), 0).state == ReplicaState::MISSING);
            CHECK(env.L->get_file(fid)->state == FileState::REPLICATING && env.L->replica_weight(fid, 1, 600) == 0.0 && env.L->fsck().empty());
            // the device's index now claims a manifest it does not hold; it can never be trusted with this version
            CHECK(sa.start(store));
            DeviceClient dev2("127.0.0.1", PA, 3000);
            ReplicateOutcome o2 = env.R->replicate(dev2, did, fid, env.path("f"));
            CHECK(!o2.ok && env.L->get_file(fid)->state == FileState::REPLICATING);
        }
        {   // disk full, then a healthy restart resumes
            std::string store = stores + "/f_full";
            CHECK(sa.start(store, {"--faults=enospc"}));
            Env env;
            DeviceClient dev("127.0.0.1", PA, 3000);
            std::string did = env.attach(dev);
            env.write("f", pattern(2 * MiB, 81));
            std::string fid = env.track("f");
            ReplicateOutcome o = env.R->replicate(dev, did, fid, env.path("f"));
            CHECK(!o.ok && has(o.why, "full"));
            CHECK(env.L->get_file(fid)->state == FileState::REPLICATING && env.L->fsck().empty());
            CHECK(sa.start(store));                                                  // same store, fault gone
            DeviceClient dev2("127.0.0.1", PA, 3000);
            ReplicateOutcome o2 = env.R->replicate(dev2, did, fid, env.path("f"));
            CHECK(o2.ok && o2.version == 1 && env.L->get_file(fid)->state == FileState::REPLICATED && env.intact(dev2, fid, "f"));
        }
        {   // slow device: a timeout is not evidence of lying, so the replica is not marked lost
            std::string store = stores + "/f_slow";
            CHECK(sa.start(store, {"--faults=slow=700"}));
            Env env;
            DeviceClient impatient("127.0.0.1", PA, 300);
            DeviceClient patient("127.0.0.1", PA, 5000);
            std::string did = env.attach(patient);
            env.write("f", pattern(MiB, 82));
            std::string fid = env.track("f");
            ReplicateOutcome o = env.R->replicate(impatient, did, fid, env.path("f"));
            CHECK(!o.ok);
            auto reps = env.L->get_replicas(fid, 1);
            CHECK(reps.empty() || at(reps, 0).state == ReplicaState::PENDING || at(reps, 0).state == ReplicaState::UPLOADED);   // retryable, not condemned
            ReplicateOutcome o2 = env.R->replicate(patient, did, fid, env.path("f"));
            CHECK(o2.ok && env.L->get_file(fid)->state == FileState::REPLICATED);
        }
        {   // the acknowledgement is lost after the device has stored the chunk
            std::string store = stores + "/f_lost";
            CHECK(sa.start(store, {"--faults=drop_connection_after_put"}));
            Env env;
            DeviceClient dev("127.0.0.1", PA, 1500);
            std::string did = env.attach(dev);
            env.write("f", pattern(3 * MiB, 83));
            std::string fid = env.track("f");
            ReplicateOutcome o = env.R->replicate(dev, did, fid, env.path("f"));
            CHECK(!o.ok);
            CHECK(sa.start(store));
            DeviceClient dev2("127.0.0.1", PA, 3000);
            ReplicateOutcome o2 = env.R->replicate(dev2, did, fid, env.path("f"));
            CHECK(o2.ok && o2.chunks_already_present >= 1 && env.intact(dev2, fid, "f"));   // the stored chunk was found, verified, reused
            CHECK(count_files(store + "/chunks", ".blob") == 3 && count_files(store + "/manifests", ".mf") == 1);   // no duplicates
            DevInfo i;
            dev2.info(i);
            CHECK(i.seq == 1 && env.L->fsck().empty());
        }
    }

    {
        printf("== crash injection: the process dies at each step, and recovery converges\n");
        struct Scenario { const char* point; bool reconcile_first; };
        for (Scenario sc : {Scenario{"repl.after_begin", false}, Scenario{"repl.mid_upload", false}, Scenario{"repl.before_manifest", false},
                            Scenario{"repl.after_manifest_put", false}, Scenario{"repl.after_manifest_put", true}, Scenario{"repl.before_finish", false}}) {
            printf("   -- %s%s\n", sc.point, sc.reconcile_first ? " (recover via reconcile first)" : "");
            std::string store = stores + "/c_" + sc.point + (sc.reconcile_first ? "_r" : "");
            CHECK(sa.start(store));
            Env env;
            DeviceClient dev("127.0.0.1", PA, 3000);
            std::string did = env.attach(dev);
            Bytes data = pattern(4 * MiB + 321, 90);
            env.write("f", data);
            std::string fid = env.track("f");
            env.close_ledger();                                                      // the helper needs the ledger lock
            CHECK(spawn_helper(env, PA, did, fid, env.path("f"), sc.point));          // it dies at the crash point
            env.open_ledger();
            CHECK(env.L->fsck().empty());                                            // the ledger is consistent at every crash point
            DevInfo before;
            dev.info(before);
            auto st = env.L->get_file(fid)->state;
            CHECK(st == FileState::REPLICATING || st == FileState::LOCAL);           // never wrongly claims REPLICATED

            if (sc.reconcile_first) {
                ReconcileReport rr = env.R->reconcile(dev, did, false);
                CHECK(rr.ok && rr.adopted.size() == 1);                              // the committed manifest is recognised by its hash
                CHECK(at(env.L->get_replicas(fid, 1), 0).state == ReplicaState::COMMITTED);
            }
            ReplicateOutcome o = env.R->replicate(dev, did, fid, env.path("f"));
            CHECK(o.ok && o.version == 1);
            CHECK(env.L->get_file(fid)->state == FileState::REPLICATED && env.L->fsck().empty());
            CHECK(env.intact(dev, fid, "f"));
            CHECK(count_files(store + "/chunks", ".blob") == 5);                     // exactly the 5 chunks: nothing duplicated, nothing lost
            DevInfo after;
            dev.info(after);
            CHECK(after.seq == 1 && count_files(store + "/manifests", ".mf") == 1);  // one manifest, committed once
            if (!strcmp(sc.point, "repl.mid_upload") || !strcmp(sc.point, "repl.before_manifest") || !strcmp(sc.point, "repl.after_manifest_put") || !strcmp(sc.point, "repl.before_finish"))
                CHECK(o.chunks_uploaded < 5 || o.already_done || o.chunks_already_present > 0);   // it reused what the first attempt left
            AuditReport ar = env.R->audit_replica(dev, did, fid, 1);
            CHECK(ar.ok && ar.items == 6);                                           // 5 chunks + manifest, all prove themselves
        }
    }

    {
        printf("== a plan the ledger holds must still match what sealing produces\n");
        CHECK(sa.start(stores + "/pl"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        env.write("f", pattern(MiB + 9, 160));
        std::string fid = env.track("f");
        env.close_ledger();
        CHECK(spawn_helper(env, PA, did, fid, env.path("f"), "repl.after_begin"));     // the plan is recorded, nothing uploaded
        {   // corrupt one recorded blob hash behind the ledger's back
            sqlite3* db = nullptr;
            sqlite3_open((env.root + "/ledger/ledger.db").c_str(), &db);
            std::string q = "UPDATE version_chunks SET blob_sha256='" + std::string(64, '0') + "' WHERE file_id='" + fid + "' AND idx=0";
            CHECK(sqlite3_exec(db, q.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
            sqlite3_close(db);
        }
        env.open_ledger();
        ReplicateOutcome o = env.R->replicate(dev, did, fid, env.path("f"));
        CHECK(!o.ok && o.file_changed && has(o.why, "no longer seals to the planned bytes"));
        DevInfo i;
        dev.info(i);
        CHECK(i.seq == 0 && env.L->get_file(fid)->state == FileState::LOCAL);          // nothing was committed on a plan that does not hold
    }

    {
        printf("== audits: one-time challenges, refresh by full fetch, and damage found\n");
        CHECK(sa.start(stores + "/au"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        env.write("one", pattern(5000, 100));
        std::string fid = env.track("one");
        CHECK(env.R->replicate(dev, did, fid, env.path("one")).ok);
        for (int i = 1; i <= 4; i++) {
            AuditReport r = env.R->audit_replica(dev, did, fid, 1);
            CHECK(r.ok && r.items == 2 && r.refetched == 0);                         // chunk + manifest per audit
        }
        CHECK(env.L->challenges_left(fid, 1, 0) == 0 && env.L->challenges_left(fid, 1, MANIFEST_CHALLENGE_IDX) == 0);
        AuditReport fifth = env.R->audit_replica(dev, did, fid, 1);
        CHECK(fifth.ok && fifth.refetched == 2);                                     // pool used up: downloaded, verified end to end, pool refreshed
        CHECK(env.L->challenges_left(fid, 1, 0) == 4 && env.L->next_challenge_n(fid, 1, 0) == 8);
        CHECK(env.R->audit_replica(dev, did, fid, 1).ok);                            // and the fresh pool works
        CHECK(!env.R->audit_replica(dev, did, fid, 7).ok && !env.R->audit_replica(dev, "no-such-device", fid, 1).ok);

        // when the challenge pool is used up the audit downloads and verifies the real bytes: damage must be caught there too
        for (int guard = 0; guard < 10 && env.L->challenges_left(fid, 1, 0) > 0; guard++) env.R->audit_replica(dev, did, fid, 1);   // use up the refreshed pool
        CHECK(env.L->challenges_left(fid, 1, 0) == 0);
        std::string cid0 = env.L->get_chunks(fid, 1)[0].chunk_id;
        std::string blob0 = stores + "/au/chunks/" + cid0.substr(0, 2) + "/" + cid0 + ".blob";
        { int fd = ::open(blob0.c_str(), O_RDWR); uint8_t b; pread(fd, &b, 1, 60); b ^= 2; pwrite(fd, &b, 1, 60); close(fd); }
        AuditReport viafetch = env.R->audit_replica(dev, did, fid, 1);
        CHECK(!viafetch.ok && !viafetch.failures.empty());                           // the stored bytes do not verify
        { int fd = ::open(blob0.c_str(), O_RDWR); uint8_t b; pread(fd, &b, 1, 60); b ^= 2; pwrite(fd, &b, 1, 60); close(fd); }   // repair it for the next part
        CHECK(env.R->replicate(dev, did, fid, env.path("one")).ok);                   // (the failed audit demoted the file: re-replicate it)

        // bit rot on the device
        std::string cid = env.L->get_chunks(fid, 1)[0].chunk_id;
        std::string blob = stores + "/au/chunks/" + cid.substr(0, 2) + "/" + cid + ".blob";
        { int fd = ::open(blob.c_str(), O_RDWR); uint8_t b; pread(fd, &b, 1, 100); b ^= 1; pwrite(fd, &b, 1, 100); close(fd); }
        AuditReport bad = env.R->audit_replica(dev, did, fid, 1);
        CHECK(!bad.ok && !bad.failures.empty() && has(bad.failures[0], "does not match"));
        CHECK(at(env.L->get_replicas(fid, 1), 0).state == ReplicaState::AUDIT_FAILED);
        CHECK(env.L->get_file(fid)->state == FileState::REPLICATING && env.L->fsck().empty());   // the only replica is gone: replicate again
        CHECK(!env.R->audit_replica(dev, did, fid, 1).ok);                           // a replica that is not committed cannot be audited
    }

    {
        printf("== recall refuses anything that does not add up, even if it decrypts\n");
        CHECK(sa.start(stores + "/fv"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        env.write("g", pattern(MiB + 100, 150));
        std::string fid = env.track("g");
        CHECK(env.R->replicate(dev, did, fid, env.path("g")).ok);
        Bytes mb;
        crypto::Manifest good;
        std::string vol = env.L->volume_id();
        CHECK(dev.get_manifest(fid, 1, mb).ok() && crypto::open_manifest(*env.keys, vol, fid, 1, mb.data(), mb.size(), good) == crypto::OpenError::Ok);
        auto fetch = [&](const std::string& file_id, int64_t v) {
            Bytes got;
            return env.R->fetch_version(dev, file_id, v, [&](const uint8_t* p, size_t n) { got.insert(got.end(), p, p + n); return true; });
        };
        CHECK(fetch(fid, 1).ok);
        // authentic manifests (we hold the key, so we can forge them) that lie about the file, filed as later versions
        std::vector<std::string> ids;
        for (auto& c : good.chunks) ids.push_back(c.chunk_id);
        auto plant = [&](int64_t v, const crypto::Manifest& m) {
            crypto::Manifest mm = m;
            mm.file_id = fid;
            mm.version = v;
            Bytes blob = crypto::seal_manifest(*env.keys, vol, mm);
            PutManifestReply pr;
            return dev.put_manifest(fid, v, blob, ids, pr).ok();
        };
        crypto::Manifest wrong_size = good;
        wrong_size.size += 1;
        crypto::Manifest wrong_len = good;
        wrong_len.chunks[0].len -= 1;
        crypto::Manifest wrong_hmac = good;
        wrong_hmac.file_hmac = std::string(64, '0');
        CHECK(plant(2, wrong_size) && plant(3, wrong_len) && plant(4, wrong_hmac));
        Res r2 = fetch(fid, 2), r3 = fetch(fid, 3), r4 = fetch(fid, 4);
        CHECK(!r2.ok && has(r2.why, "add up"));
        CHECK(!r3.ok && has(r3.why, "wrong length"));
        CHECK(!r4.ok && has(r4.why, "whole-file check"));
        CHECK(!fetch(fid, 9).ok && !fetch("ffffffffffffffffffffffffffffffff", 1).ok);       // nothing there
        // a receiver that stops early stops the transfer
        CHECK(!env.R->fetch_version(dev, fid, 1, [](const uint8_t*, size_t) { return false; }).ok);
        // a manifest sealed for another volume is refused outright
        Bytes foreign = crypto::seal_manifest(*env.keys, "another-volume", good);
        PutManifestReply pr;
        CHECK(dev.put_manifest(fid, 5, foreign, ids, pr).ok());
        CHECK(!fetch(fid, 5).ok);
    }

    {
        printf("== a full re-download is verified on the Mac too, even when the device is happy with its own bytes\n");
        CHECK(sa.start(stores + "/sw", {"--faults=swap_get"}));       // serves a DIFFERENT (perfectly intact) chunk when asked for one
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        env.write("two", pattern(2 * MiB, 170));
        std::string fid = env.track("two");
        CHECK(env.R->replicate(dev, did, fid, env.path("two")).ok);    // uploads and challenge audits are honest
        for (int guard = 0; guard < 12 && (env.L->challenges_left(fid, 1, 0) > 0 || env.L->challenges_left(fid, 1, 1) > 0 ||
                                           env.L->challenges_left(fid, 1, MANIFEST_CHALLENGE_IDX) > 0); guard++)
            env.R->audit_replica(dev, did, fid, 1);                    // spend the pools; the last audits fall back to downloading
        AuditReport r = env.R->audit_replica(dev, did, fid, 1);        // next one must download: and the device sends the wrong chunk
        bool refetched_bad = false;
        for (auto& f : r.failures) refetched_bad |= has(f, "do not verify");
        CHECK(!r.ok && refetched_bad);
    }

    {
        printf("== a suspect device that fails any audit stays suspect\n");
        CHECK(sa.start(stores + "/sp"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        env.write("a", pattern(MiB + 1, 171));
        env.write("b", pattern(MiB + 2, 172));
        std::string fa = env.track("a"), fb = env.track("b");
        CHECK(env.R->replicate(dev, did, fa, env.path("a")).ok && env.R->replicate(dev, did, fb, env.path("b")).ok);
        DevInfo di;
        dev.info(di);
        CHECK(env.L->observe_device(did, di.epoch, di.seq - 1) == DeviceObservation::Rollback);   // pretend it came back older than we remember
        CHECK(env.L->get_device(did)->state == "suspect");
        std::string cid = env.L->get_chunks(fa, 1)[0].chunk_id;                                   // and one of its chunks has rotted
        std::string blob = stores + "/sp/chunks/" + cid.substr(0, 2) + "/" + cid + ".blob";
        { int fd = ::open(blob.c_str(), O_RDWR); uint8_t b; pread(fd, &b, 1, 77); b ^= 8; pwrite(fd, &b, 1, 77); close(fd); }
        ReconcileReport rr = env.R->reconcile(dev, did, false);
        CHECK(rr.ok && rr.audited == 2 && rr.audit_failed == 1 && !rr.suspect_cleared);
        CHECK(env.L->get_device(did)->state == "suspect");                                         // not trusted until EVERYTHING it claims checks out
        CHECK(at(env.L->get_replicas(fa, 1), 0).state == ReplicaState::AUDIT_FAILED && at(env.L->get_replicas(fb, 1), 0).state == ReplicaState::COMMITTED);
        CHECK(env.L->fsck().empty());
    }

    {
        printf("== a second device, and weight\n");
        CHECK(sa.start(stores + "/d1"));
        CHECK(sb.start(stores + "/d2"));
        Env env;
        DeviceClient da("127.0.0.1", PA, 3000), db("127.0.0.1", PB, 3000);
        std::string ida = env.attach(da, "B"), idb = env.attach(db, "C");
        CHECK(ida != idb && env.L->list_devices().size() == 2);
        env.write("f", pattern(2 * MiB + 9, 110));
        std::string fid = env.track("f");
        CHECK(env.R->replicate(da, ida, fid, env.path("f")).ok);
        CHECK(env.R->audit_replica(da, ida, fid, 1).ok && env.L->replica_weight(fid, 1, 600) == 1.0);
        ReplicateOutcome o = env.R->replicate(db, idb, fid, env.path("f"));         // add the second replica to the existing version
        CHECK(o.ok && o.version == 1 && !o.already_done && env.L->get_file(fid)->state == FileState::REPLICATED);
        CHECK(env.R->audit_replica(db, idb, fid, 1).ok && env.L->replica_weight(fid, 1, 600) == 1.5);   // a B plus a C
        CHECK(env.intact(da, fid, "f") && env.intact(db, fid, "f"));
        // a wrong device identity at the same address is refused
        CHECK(!env.R->replicate(db, ida, fid, env.path("f")).ok);
        // attaching again is harmless
        DeviceObservation obs;
        CHECK(env.attach(da, "B", &obs) == ida && obs == DeviceObservation::Ok && env.L->list_devices().size() == 2);
        CHECK(env.L->fsck().empty());
    }

    {
        printf("== attach refuses what does not belong\n");
        CHECK(sa.start(stores + "/at"));
        Env e1, e2;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string id1;
        DeviceObservation obs;
        CHECK(e1.R->attach(dev, "mine", "B", &id1, &obs) && obs == DeviceObservation::First);
        std::string id2;
        Res r = e2.R->attach(dev, "yours", "B", &id2);                               // another volume tries to use the same device
        CHECK(!r && has(r.why, "different volume"));
        CHECK(!e1.R->attach(dev, "bad", "Z", &id2) || e1.L->list_devices().size() == 1);
        DeviceClient nobody("127.0.0.1", 9499, 300);
        CHECK(!e1.R->attach(nobody, "gone", "B", &id2));
    }

    {
        printf("== reconcile: a device restored from an old copy is spotted, and earns trust back by audits\n");
        std::string store = stores + "/rb", snap = stores + "/rb_snap";
        CHECK(sa.start(store));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        std::vector<std::string> ids;
        for (int i = 1; i <= 2; i++) {
            env.write("f" + std::to_string(i), pattern(MiB + i, static_cast<uint8_t>(120 + i)));
            ids.push_back(env.track("f" + std::to_string(i)));
            CHECK(env.R->replicate(dev, did, ids.back(), env.path("f" + std::to_string(i))).ok);
        }
        sa.stop();
        fs::remove_all(snap);
        fs::copy(store, snap, fs::copy_options::recursive);                          // a backup of the device at seq 2
        CHECK(sa.start(store));
        DeviceClient dev2("127.0.0.1", PA, 3000);
        env.write("f3", pattern(MiB + 3, 123));
        std::string f3 = env.track("f3");
        CHECK(env.R->replicate(dev2, did, f3, env.path("f3")).ok);                    // seq 3
        sa.stop();
        fs::remove_all(store);
        fs::copy(snap, store, fs::copy_options::recursive);                          // ... restored over the live device
        CHECK(sa.start(store));
        DeviceClient dev3("127.0.0.1", PA, 3000);
        // The device is replaced by the old copy while the ledger still believes it is healthy (no attach in between):
        // replicate() must notice by itself and refuse to commit anything to it.
        ReplicateOutcome blind = env.R->replicate(dev3, did, f3, env.path("f3"));
        CHECK(!blind.ok && has(blind.why, "restored or reset"));
        CHECK(env.L->get_device(did)->state == "suspect");
        DeviceObservation obs;
        CHECK(env.attach(dev3, "B", &obs) == did && obs == DeviceObservation::Rollback);   // still behind its high-water mark
        // Now let its sequence number catch up by writing to it directly. Catching up does NOT make it trustworthy again:
        {
            auto chunks0 = env.L->get_chunks(ids[0], 1);
            for (int k = 0; k < 3; k++) {
                char fake[33];
                snprintf(fake, sizeof fake, "%032x", 0x1000 + k);
                PutManifestReply pm;
                dev3.put_manifest(fake, 1, pattern(40, static_cast<uint8_t>(k)), {at(chunks0, 0).chunk_id}, pm);
            }
            DevInfo di;
            dev3.info(di);
            CHECK(di.seq >= 3);
            CHECK(env.L->observe_device(did, di.epoch, di.seq) == DeviceObservation::Ok && env.L->get_device(did)->state == "suspect");
            ReplicateOutcome stillsuspect = env.R->replicate(dev3, did, ids[0], env.path("f1"));
            CHECK(!stillsuspect.ok && has(stillsuspect.why, "suspect"));
        }
        CHECK(env.L->get_file(f3)->state == FileState::REPLICATING && env.L->get_file(ids[0])->state == FileState::REPLICATING);   // nothing can lean on it now
        CHECK(!env.R->replicate(dev3, did, f3, env.path("f3")).ok);                  // and the engine will not use it until it is checked
        ReconcileReport rr = env.R->reconcile(dev3, did, false);
        CHECK(rr.ok && !rr.rolled_back && rr.manifests_missing.size() == 1 && has(rr.manifests_missing[0], f3.c_str()));   // (no longer behind: it caught up)
        CHECK(rr.unknown_manifests.size() == 3);                                          // the strangers are reported, never adopted
        CHECK(rr.audited == 2 && rr.audit_failed == 0 && rr.suspect_cleared);         // the two survivors prove themselves
        CHECK(env.L->get_device(did)->state == "active");
        CHECK(env.L->get_file(ids[0])->state == FileState::REPLICATING);              // (REPLICATING with a committed replica: just needs finishing)
        for (int i = 0; i < 2; i++) CHECK(env.R->replicate(dev3, did, ids[static_cast<size_t>(i)], env.path("f" + std::to_string(i + 1))).already_done);
        ReplicateOutcome again = env.R->replicate(dev3, did, f3, env.path("f3"));    // the lost one is simply done again
        CHECK(again.ok && env.L->get_file(f3)->state == FileState::REPLICATED && env.intact(dev3, f3, "f3"));
        CHECK(env.L->fsck().empty());
        for (auto& f : env.L->list_files()) CHECK(f.state == FileState::REPLICATED);
    }

    {
        printf("== reconcile: damage, loss, and strangers\n");
        CHECK(sa.start(stores + "/rc"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        env.write("keep", pattern(MiB + 5, 130));
        env.write("lose", pattern(MiB + 6, 131));
        std::string k = env.track("keep"), l = env.track("lose");
        CHECK(env.R->replicate(dev, did, k, env.path("keep")).ok && env.R->replicate(dev, did, l, env.path("lose")).ok);
        // a manifest nobody here wrote
        PutChunkReply pc;
        PutManifestReply pm;
        Bytes cb = pattern(100, 7);
        std::string cid = crypto::chunk_id(*env.keys, cb.data(), cb.size());
        dev.put_chunk(cid, crypto::seal_chunk(*env.keys, env.L->volume_id(), cid, cb.data(), cb.size()), pc);
        CHECK(dev.put_manifest("abababababababababababababababab", 1, pattern(50, 1), {cid}, pm).ok());
        // the device quietly loses a manifest file (its index still lists it)
        std::string mf = stores + "/rc/manifests/" + l + "/1.mf";
        CHECK(fs::exists(mf));
        unlink(mf.c_str());
        ReconcileReport rr = env.R->reconcile(dev, did, true);                        // deep: audit everything
        CHECK(rr.ok && rr.unknown_manifests.size() == 1 && has(rr.unknown_manifests[0], "abababab"));   // reported, never adopted
        CHECK(rr.audited == 2 && rr.audit_failed == 1);                               // the lost manifest file is found by the audit
        CHECK(at(env.L->get_replicas(l, 1), 0).state == ReplicaState::AUDIT_FAILED && env.L->get_file(l)->state == FileState::REPLICATING);
        CHECK(at(env.L->get_replicas(k, 1), 0).state == ReplicaState::COMMITTED && env.L->get_file(k)->state == FileState::REPLICATED);
        CHECK(env.L->fsck().empty());
        CHECK(env.L->list_files().size() == 2);                                      // the stranger created nothing in the ledger
        // an honest first contact
        Env env2;
        DeviceClient dev2("127.0.0.1", PA, 3000);
        CHECK(!env2.R->reconcile(dev2, "0123456789abcdef0123456789abcdef", false).ok);   // unknown device
    }

    {
        printf("== preconditions: only files in a replicable state, regular files, manageable sizes\n");
        CHECK(sa.start(stores + "/pre"));
        Env env;
        DeviceClient dev("127.0.0.1", PA, 3000);
        std::string did = env.attach(dev);
        env.write("f", pattern(MiB, 140));
        std::string fid = env.track("f");
        CHECK(env.R->replicate(dev, did, fid, env.path("f")).ok);
        // OFFLOADED files have no local bytes to read
        env.L->set_meta("recovery_acked", "1");
        env.L->set_meta("backup_acked", "1");
        env.L->set_meta("backup_acked_at", "4000000000");  // a dated statement (year 2096: newer than everything here); an undated one is refused
        env.L->ensure_reserve(1 << 20);
        std::string consent = env.L->create_consent("/testdata/", 3600, "test");
        auto f = env.L->get_file(fid);
        env.R->audit_replica(dev, did, fid, 1);
        Res d = env.L->begin_drop(fid, 1, f->generation, consent, 1.0, 600);
        CHECK(d.ok);
        ReplicateOutcome during = env.R->replicate(dev, did, fid, env.path("f"));
        CHECK(!during.ok && has(during.why, "DROPPING"));
        CHECK(env.L->complete_drop(d.id).ok);
        ReplicateOutcome off = env.R->replicate(dev, did, fid, env.path("f"));
        CHECK(!off.ok && (has(off.why, "local bytes") || has(off.why, "OFFLOADED")));
        // not a regular file
        fs::create_directories(env.root + "/files/adir");
        std::string dir_id = env.L->track_file("/testdata/adir", 0, 1, 0755);
        CHECK(!env.R->replicate(dev, did, dir_id, env.path("adir")).ok);
        symlink(env.path("f").c_str(), env.path("link").c_str());
        std::string link_id = env.L->track_file("/testdata/link", MiB, 1, 0644);
        CHECK(!env.R->replicate(dev, did, link_id, env.path("link")).ok);              // symlinks are not followed
        CHECK(!env.R->replicate(dev, did, "no-such-file", env.path("f")).ok);
        CHECK(!env.R->replicate(dev, did, link_id, env.root + "/files/missing").ok);
        // too big for one manifest: refused before a byte is read (sparse file, costs no disk)
        std::string big = env.path("huge");
        { int fd = ::open(big.c_str(), O_CREAT | O_WRONLY, 0644); ftruncate(fd, 300ll << 30); close(fd); }
        std::string big_id = env.track("huge");
        ReplicateOutcome bo = env.R->replicate(dev, did, big_id, big);
        CHECK(!bo.ok && has(bo.why, "too large"));
        CHECK(env.L->fsck().empty());
    }

    sa.stop();
    sb.stop();
    fs::remove_all(stores);
    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
