// Tests for the durable ledger. The point of these is to try to make the ledger
// agree to something unsafe, or to lose track of something, and fail if it does.
#include <spawn.h>
#include <sqlite3.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>

#include "../core/hash.hpp"
#include "../core/ledger.hpp"

extern char** environ;
using namespace tierfs;
namespace fs = std::filesystem;

static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) { printf("FAIL  line %d: %s\n", __LINE__, #cond); failures++; } \
        else printf("PASS  %s\n", #cond);                                          \
    } while (0)

static bool has(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }

static std::string tmpdir() {
    char t[] = "/tmp/tierfs-ledgertest-XXXXXX";
    return mkdtemp(t);
}

static int64_t g_time = 1'000'000;

static std::unique_ptr<Ledger> open_ledger(const std::string& dir, std::string* err = nullptr) {
    std::string e;
    auto L = Ledger::open(dir, err ? err : &e);
    if (L) L->set_clock([] { return g_time; });
    return L;
}

// A ledger with the gates open: recovery phrase and backup acknowledged, reserve
// present, a consent covering /testdata/, devices of each class.
struct Fixture {
    std::string dir = tmpdir();
    std::unique_ptr<Ledger> L;
    std::string consent;
    Fixture(bool recovery = true, bool backup = true) {
        g_time = 1'000'000;
        L = open_ledger(dir);
        if (recovery) L->set_meta("recovery_acked", "1");
        if (backup) L->set_meta("backup_acked", "1");
        L->ensure_reserve(1 << 20);
        for (auto [id, cls] : {std::pair<const char*, const char*>{"devA", "A"}, {"devB1", "B"}, {"devB2", "B"}, {"devC", "C"}})
            L->register_device(id, id, cls);
        consent = L->create_consent("/testdata/", 3600, "I understand");
    }
    ~Fixture() { L.reset(); fs::remove_all(dir); }

    static std::vector<ChunkRec> chunks(uint64_t size) {
        std::vector<ChunkRec> v;
        uint32_t idx = 0;
        while (size) {
            uint32_t len = static_cast<uint32_t>(std::min<uint64_t>(size, 1 << 20));
            v.push_back({idx, "chunk" + std::to_string(idx), len, "blob" + std::to_string(idx)});
            size -= len;
            idx++;
        }
        return v;
    }
    // Takes a file all the way to REPLICATED with the given devices committed AND audited.
    std::string replicated(const std::string& path, std::vector<std::string> devices, uint64_t size = 2500000) {
        std::string id = L->track_file(path, size, 123, 0644);
        auto r = L->begin_replication(id, chunks(size), size, 123);
        int64_t v = std::atoll(r.id.c_str());
        for (auto& d : devices) {
            L->set_replica(id, v, d, ReplicaState::PENDING);
            L->set_replica(id, v, d, ReplicaState::UPLOADED);
            L->set_replica(id, v, d, ReplicaState::COMMITTED, 7);
        }
        L->finish_replication(id, v);
        for (auto& d : devices) L->record_audit(id, v, d, true, "ok");
        return id;
    }
    Res drop(const std::string& id, double w = 2.0, int64_t age = 600) {
        auto f = L->get_file(id);
        if (!f) return L->begin_drop(id, 1, 1, consent, w, age);   // unknown file: let the ledger refuse it
        return L->begin_drop(id, f->current_version, f->generation, consent, w, age);
    }
};

// Asserts a refused drop changed nothing: same file state, no new intent, no new events.
#define EXPECT_REFUSED(fx, id, expr, why_text)                                         \
    do {                                                                               \
        auto before = (fx).L->get_file(id);                                            \
        uint64_t ev = (fx).L->event_count();                                           \
        size_t intents_ = (fx).L->open_intents().size();                               \
        Res r_ = (expr);                                                               \
        CHECK(!r_.ok && has(r_.why, why_text));                                        \
        if (r_.ok || !has(r_.why, why_text)) printf("      got: ok=%d why='%s'\n", r_.ok, r_.why.c_str()); \
        auto after = (fx).L->get_file(id);                                             \
        CHECK(after->state == before->state && after->local_present == before->local_present); \
        CHECK((fx).L->open_intents().size() == intents_ && (fx).L->event_count() == ev);  \
    } while (0)

// Runs the helper binary with the named crash point armed. It must die with
// status 137 (the injected crash). Spawned fresh rather than forked: forking a
// process that has already used sqlite/os_log intermittently crashes the child on
// macOS. The parent must not hold the ledger open (flock).
// The mutation script points this at a helper built from the mutated source.
static const char* helper_path() {
    const char* h = getenv("TIERFS_HELPER");
    return h ? h : "./build/ledger_helper";
}

static bool crash_run(const char* point, std::vector<std::string> args) {
    std::vector<std::string> env;
    for (char** e = environ; *e; e++) env.push_back(*e);
    env.push_back(std::string("TIERFS_CRASH_AT=") + point);
    env.push_back("TIERFS_FAKE_NOW=" + std::to_string(g_time));
    std::vector<char*> envp;
    for (auto& e : env) envp.push_back(const_cast<char*>(e.c_str()));
    envp.push_back(nullptr);
    std::vector<std::string> argv_s = {"ledger_helper"};
    argv_s.insert(argv_s.end(), args.begin(), args.end());
    std::vector<char*> argv;
    for (auto& a : argv_s) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    pid_t pid;
    if (posix_spawn(&pid, helper_path(), nullptr, nullptr, argv.data(), envp.data()) != 0) return false;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 137;
}

// Independent copy of the ledger's event hash format, to forge self-consistent rows.
static std::string test_event_hash(int64_t seq, int64_t ts, const std::string& kind, const std::string& file_id,
                                   int64_t version, const std::string& device_id, const std::string& detail,
                                   const std::string& prev) {
    std::string m;
    auto add = [&](const std::string& f) { m += std::to_string(f.size()); m += ':'; m += f; m += ';'; };
    add(std::to_string(seq)); add(std::to_string(ts)); add(kind); add(file_id);
    add(std::to_string(version)); add(device_id); add(detail); add(prev);
    return sha256_hex(m.data(), m.size());
}
static std::string raw_text(sqlite3* db, const char* sql) {
    sqlite3_stmt* st = nullptr;
    std::string out;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char* t = sqlite3_column_text(st, 0);
        if (t) out = reinterpret_cast<const char*>(t);
    }
    if (st) sqlite3_finalize(st);
    return out;
}

static sqlite3* raw_open(const std::string& dir) {
    sqlite3* db = nullptr;
    sqlite3_open((dir + "/ledger.db").c_str(), &db);
    return db;
}
static bool raw_exec(sqlite3* db, const char* sql) { return sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK; }

int main() {
    {
        printf("== open, durability, exclusivity\n");
        Fixture fx;
        CHECK(fx.L->volume_id().size() == 32);
        CHECK(fx.L->fsck().empty());
        std::string err;
        CHECK(!Ledger::open(fx.dir, &err) && has(err, "in use"));  // one process per ledger
        std::string id = fx.L->track_file("/testdata/a", 10, 1, 0644);
        std::string vol = fx.L->volume_id();
        fx.L.reset();
        fx.L = open_ledger(fx.dir);
        CHECK(fx.L && fx.L->volume_id() == vol && fx.L->get_file(id)->path == "/testdata/a");  // survives reopen
        CHECK(fx.L->track_file("/testdata/a", 10, 1, 0644) == id);  // idempotent
        CHECK(fx.L->fsck().empty());
    }

    {
        printf("== never wipes or repairs a ledger it does not understand\n");
        std::string d = tmpdir();
        std::string garbage(8192, 'x');
        { std::ofstream f(d + "/ledger.db", std::ios::binary); f << garbage; }
        std::string err;
        CHECK(!Ledger::open(d, &err) && !err.empty());
        std::ifstream in(d + "/ledger.db", std::ios::binary);
        std::string after((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        CHECK(after == garbage);  // untouched

        std::string d2 = tmpdir();
        { auto L = open_ledger(d2); L->track_file("/testdata/x", 1, 1, 0644); }
        { sqlite3* db = raw_open(d2); raw_exec(db, "PRAGMA user_version=99"); sqlite3_close(db); }
        CHECK(!Ledger::open(d2, &err) && has(err, "not understood"));
        { sqlite3* db = raw_open(d2); raw_exec(db, "PRAGMA user_version=1"); sqlite3_close(db); }
        { auto L = open_ledger(d2); CHECK(L && L->get_file_by_path("/testdata/x")); }  // data still there

        std::string d3 = tmpdir();
        { std::ofstream f(d3 + "/ledger.db"); }  // zero-byte file counts as new
        CHECK(open_ledger(d3) != nullptr);
        fs::remove_all(d); fs::remove_all(d2); fs::remove_all(d3);
    }

    {
        printf("== history cannot be rewritten or deleted\n");
        Fixture fx;
        fx.replicated("/testdata/h", {"devA", "devB1"});
        CHECK(fx.L->fsck().empty());
        fx.L.reset();
        sqlite3* db = raw_open(fx.dir);
        CHECK(!raw_exec(db, "UPDATE events SET detail='forged' WHERE seq=2"));   // trigger blocks it
        CHECK(!raw_exec(db, "DELETE FROM events WHERE seq=3"));
        CHECK(!raw_exec(db, "DELETE FROM files"));
        CHECK(!raw_exec(db, "DELETE FROM replicas"));
        CHECK(!raw_exec(db, "DELETE FROM consents"));
        // An attacker (or bug) who drops the trigger is still caught by the hash chain.
        CHECK(raw_exec(db, "DROP TRIGGER events_no_update"));
        CHECK(raw_exec(db, "UPDATE events SET detail='forged' WHERE seq=2"));
        sqlite3_close(db);
        fx.L = open_ledger(fx.dir);
        auto bad = fx.L->fsck();
        bool found = false;
        for (auto& b : bad) found |= has(b, "hash mismatch at seq 2");
        CHECK(found);

        {   Fixture fz;   // a forged row whose own hash is correct: only the link to its predecessor gives it away
            fz.replicated("/testdata/h3", {"devA", "devB1"});
            fz.L.reset();
            sqlite3* d3 = raw_open(fz.dir);
            raw_exec(d3, "DROP TRIGGER events_no_update");
            sqlite3_stmt* st = nullptr;
            sqlite3_prepare_v2(d3, "SELECT ts,kind,file_id,version,device_id,detail FROM events WHERE seq=3", -1, &st, nullptr);
            CHECK(sqlite3_step(st) == SQLITE_ROW);
            auto col = [&](int i) { return std::string(reinterpret_cast<const char*>(sqlite3_column_text(st, i))); };
            std::string fake_prev(64, 'a');
            std::string h = test_event_hash(3, sqlite3_column_int64(st, 0), col(1), col(2), sqlite3_column_int64(st, 3), col(4), col(5), fake_prev);
            sqlite3_finalize(st);
            std::string q = "UPDATE events SET prev_hash='" + fake_prev + "', hash='" + h + "' WHERE seq=3";
            CHECK(raw_exec(d3, q.c_str()));
            sqlite3_close(d3);
            fz.L = open_ledger(fz.dir);
            bool link = false;
            for (auto& b : fz.L->fsck()) link |= has(b, "broken chain");
            CHECK(link);
        }
        Fixture fy;
        fy.replicated("/testdata/h2", {"devA", "devB1"});
        fy.L.reset();
        db = raw_open(fy.dir);
        raw_exec(db, "DROP TRIGGER events_no_delete");
        CHECK(raw_exec(db, "DELETE FROM events WHERE seq=4"));
        sqlite3_close(db);
        fy.L = open_ledger(fy.dir);
        bad = fy.L->fsck();
        found = false;
        for (auto& b : bad) found |= has(b, "gap or reorder") || has(b, "broken chain");
        CHECK(found);
    }

    {
        printf("== full lifecycle: replicate, drop, hydrate, modify\n");
        Fixture fx;
        std::string id = fx.L->track_file("/testdata/f", 2500000, 55, 0644);
        auto ch = Fixture::chunks(2500000);
        CHECK(!fx.L->begin_replication(id, {{0, "c", 10, "b"}}, 2500000, 55).ok);  // lengths do not add up
        CHECK(!fx.L->begin_replication(id, {{1, "c", 2500000, "b"}}, 2500000, 55).ok);  // not contiguous from 0
        auto r = fx.L->begin_replication(id, ch, 2500000, 55);
        CHECK(r.ok && r.id == "1");
        CHECK(fx.L->get_file(id)->state == FileState::REPLICATING);
        CHECK(!fx.L->begin_replication(id, ch, 2500000, 55).ok);  // already replicating
        CHECK(!fx.L->finish_replication(id, 1).ok);               // nothing committed yet
        CHECK(!fx.L->set_replica(id, 1, "devA", ReplicaState::COMMITTED, 5).ok);  // skipping states
        CHECK(fx.L->set_replica(id, 1, "devA", ReplicaState::PENDING).ok);
        CHECK(!fx.L->set_replica(id, 1, "devA", ReplicaState::COMMITTED, 5).ok);  // PENDING -> COMMITTED not allowed
        CHECK(fx.L->set_replica(id, 1, "devA", ReplicaState::UPLOADED).ok);
        CHECK(!fx.L->set_replica(id, 1, "devA", ReplicaState::COMMITTED, 0).ok);  // needs a device sequence
        CHECK(!fx.L->set_replica(id, 1, "nope", ReplicaState::PENDING).ok);       // unknown device
        CHECK(fx.L->set_replica(id, 1, "devA", ReplicaState::COMMITTED, 5).ok);
        CHECK(fx.L->finish_replication(id, 1).ok);
        CHECK(fx.L->get_file(id)->state == FileState::REPLICATED);
        CHECK(fx.L->get_chunks(id, 1).size() == 3);
        CHECK(fx.L->fsck().empty());

        fx.L->set_replica(id, 1, "devB1", ReplicaState::PENDING);
        fx.L->set_replica(id, 1, "devB1", ReplicaState::UPLOADED);
        fx.L->set_replica(id, 1, "devB1", ReplicaState::COMMITTED, 9);
        CHECK(fx.L->record_audit(id, 1, "devA", true, "ok").ok);
        CHECK(fx.L->record_audit(id, 1, "devB1", true, "ok").ok);
        CHECK(fx.L->replica_weight(id, 1, 600) == 2.0);

        Res d = fx.drop(id);
        CHECK(d.ok && !d.id.empty());
        CHECK(fx.L->get_file(id)->state == FileState::DROPPING);
        CHECK(fx.L->open_intents().size() == 1 && fx.L->open_intents()[0].intent_id == d.id);
        CHECK(fx.L->fsck().empty());
        CHECK(!fx.L->note_local_modified(id, 5, 5).ok);   // writers are refused while dropping
        CHECK(!fx.drop(id).ok);                           // no second drop
        CHECK(fx.L->complete_drop(d.id).ok);
        auto f = fx.L->get_file(id);
        CHECK(f->state == FileState::OFFLOADED && !f->local_present);
        CHECK(fx.L->open_intents().empty());
        CHECK(!fx.L->complete_drop(d.id).ok);             // an intent completes once
        CHECK(!fx.L->note_local_modified(id, 5, 5).ok);   // must hydrate first
        CHECK(fx.L->fsck().empty());

        CHECK(fx.L->begin_hydrate(id).ok);
        CHECK(fx.L->get_file(id)->state == FileState::HYDRATING);
        CHECK(!fx.L->note_local_modified(id, 5, 5).ok);
        CHECK(fx.L->abort_hydrate(id).ok && fx.L->get_file(id)->state == FileState::OFFLOADED);
        CHECK(fx.L->begin_hydrate(id).ok && fx.L->complete_hydrate(id).ok);
        f = fx.L->get_file(id);
        CHECK(f->state == FileState::REPLICATED && f->local_present);
        CHECK(fx.L->fsck().empty());
        {   fx.L.reset();   // the event log tells the whole story, in order
            sqlite3* db = raw_open(fx.dir);
            std::string kinds = raw_text(db, "SELECT group_concat(kind, ' ') FROM (SELECT kind FROM events WHERE kind NOT LIKE 'meta.%' AND kind NOT LIKE 'device.%' AND kind NOT LIKE 'consent.%' ORDER BY seq)");
            sqlite3_close(db);
            CHECK(kinds == "ledger.created file.tracked replication.begin replica.state replica.state replica.state replication.done"
                           " replica.state replica.state replica.state audit.ok audit.ok drop.begin drop.complete hydrate.begin hydrate.abort"
                           " hydrate.begin hydrate.complete");
            fx.L = open_ledger(fx.dir);
        }

        int64_t gen = f->generation;
        CHECK(fx.L->note_local_modified(id, 3000000, 99).ok);   // user edits the file
        f = fx.L->get_file(id);
        CHECK(f->state == FileState::LOCAL && f->generation == gen + 1 && f->size == 3000000);
        auto r2 = fx.L->begin_replication(id, Fixture::chunks(3000000), 3000000, 99);
        CHECK(r2.ok && r2.id == "2");                           // a NEW immutable version
        CHECK(fx.L->get_chunks(id, 1).size() == 3 && fx.L->get_chunks(id, 2).size() == 3);  // old one kept
        CHECK(fx.L->fsck().empty());
    }

    {
        printf("== every safety gate refuses, and a refusal changes nothing\n");
        {   Fixture fx(/*recovery=*/false);
            auto id = fx.replicated("/testdata/g1", {"devA", "devB1"});
            EXPECT_REFUSED(fx, id, fx.drop(id), "recovery phrase");
        }
        {   Fixture fx(true, /*backup=*/false);
            fx.L->set_meta("test_prefix", "/testdata/");
            auto in = fx.replicated("/testdata/in-prefix", {"devA", "devB1"});
            CHECK(fx.drop(in).ok);                        // allowed: under the test prefix
            auto out = fx.replicated("/home/user/real.doc", {"devA", "devB1"});
            fx.consent = fx.L->create_consent("/home/", 3600, "yes");
            EXPECT_REFUSED(fx, out, fx.drop(out), "backup not acknowledged");
            fx.L->set_meta("backup_acked", "1");
            CHECK(fx.drop(out).ok);                       // once the owner acknowledges the backup
        }
        {   Fixture fx;
            auto id = fx.replicated("/testdata/g2", {"devA", "devB1"});
            fx.L->release_reserve();
            EXPECT_REFUSED(fx, id, fx.drop(id), "reserve");
            fx.L->ensure_reserve(1 << 20);
            CHECK(fx.drop(id).ok);
        }
        {   Fixture fx;
            auto id = fx.replicated("/testdata/g3", {"devA", "devB1"});
            auto f = fx.L->get_file(id);
            EXPECT_REFUSED(fx, id, fx.L->begin_drop(id, 1, f->generation, "bogus-consent", 2.0, 600), "no valid consent");
            std::string other = fx.L->create_consent("/elsewhere/", 3600, "x");
            EXPECT_REFUSED(fx, id, fx.L->begin_drop(id, 1, f->generation, other, 2.0, 600), "does not cover");
            g_time += 7200;                                // consent (1 h) expires
            fx.L->record_audit(id, 1, "devA", true, "re"); fx.L->record_audit(id, 1, "devB1", true, "re");
            EXPECT_REFUSED(fx, id, fx.drop(id), "consent expired");
            CHECK(fx.L->create_consent("", 3600, "x").empty() && fx.L->create_consent("/x/", 0, "x").empty());
        }
        {   Fixture fx;  // replica weight: class C counts half, never alone
            auto onlyC = fx.replicated("/testdata/w1", {"devC"});
            EXPECT_REFUSED(fx, onlyC, fx.drop(onlyC), "insufficient replica weight (have 0.5");
            auto ac = fx.replicated("/testdata/w2", {"devA", "devC"});
            EXPECT_REFUSED(fx, ac, fx.drop(ac), "have 1.5");
            auto single = fx.replicated("/testdata/w3", {"devA"});
            EXPECT_REFUSED(fx, single, fx.drop(single), "have 1.0");
            CHECK(fx.drop(single, /*min_weight=*/1.0).ok);   // single-copy mode only if policy says so
            auto bb = fx.replicated("/testdata/w4", {"devB1", "devB2"});
            CHECK(fx.drop(bb).ok);
            EXPECT_REFUSED(fx, onlyC, fx.drop(onlyC, 0.0), "positive");
            EXPECT_REFUSED(fx, onlyC, fx.drop(onlyC, 2.0, 0), "finite audit age");
        }
        {   Fixture fx;  // replicas must be recently AUDITED, not merely committed
            std::string id = fx.L->track_file("/testdata/u", 100, 1, 0644);
            fx.L->begin_replication(id, Fixture::chunks(100), 100, 1);
            for (auto d : {"devA", "devB1"}) {
                fx.L->set_replica(id, 1, d, ReplicaState::PENDING);
                fx.L->set_replica(id, 1, d, ReplicaState::UPLOADED);
                fx.L->set_replica(id, 1, d, ReplicaState::COMMITTED, 3);
            }
            fx.L->finish_replication(id, 1);
            EXPECT_REFUSED(fx, id, fx.drop(id), "have 0.0");   // never audited
            EXPECT_REFUSED(fx, id, fx.drop(id, 2.0, 5'000'000), "have 0.0");  // ...even if "recent" would reach back before time began
            fx.L->record_audit(id, 1, "devA", true, "a"); fx.L->record_audit(id, 1, "devB1", true, "b");
            g_time += 601;                                     // audits go stale
            EXPECT_REFUSED(fx, id, fx.drop(id), "insufficient replica weight");
            fx.L->record_audit(id, 1, "devA", true, "a"); fx.L->record_audit(id, 1, "devB1", true, "b");
            CHECK(fx.drop(id).ok);
        }
        {   Fixture fx;  // a retired device stops counting
            auto id = fx.replicated("/testdata/r", {"devB1", "devB2"});
            fx.L->retire_device("devB2");
            EXPECT_REFUSED(fx, id, fx.drop(id), "have 1.0");
            CHECK(!fx.L->set_replica(id, 1, "devB2", ReplicaState::MISSING).ok);  // retired: no further changes
        }
        {   Fixture fx;  // stale view of the file
            auto id = fx.replicated("/testdata/s", {"devA", "devB1"});
            auto f = fx.L->get_file(id);
            EXPECT_REFUSED(fx, id, fx.L->begin_drop(id, 2, f->generation, fx.consent, 2.0, 600), "version mismatch");
            EXPECT_REFUSED(fx, id, fx.L->begin_drop(id, 1, f->generation + 1, fx.consent, 2.0, 600), "generation mismatch");
            Res unk = fx.drop("no-such-file");   // (EXPECT_REFUSED reads the file row, which does not exist here)
            CHECK(!unk.ok && has(unk.why, "unknown file"));
        }
    }

    {
        printf("== a file modified after it was replicated can never be dropped\n");
        Fixture fx;
        auto id = fx.replicated("/testdata/m", {"devA", "devB1"});
        auto before = fx.L->get_file(id);
        CHECK(fx.L->note_local_modified(id, 2500001, 77).ok);
        CHECK(fx.L->get_file(id)->state == FileState::LOCAL);
        EXPECT_REFUSED(fx, id, fx.L->begin_drop(id, 1, before->generation, fx.consent, 2.0, 600), "not REPLICATED");
        // modified while still replicating: replication cannot be finished against the new bytes
        std::string id2 = fx.L->track_file("/testdata/m2", 100, 1, 0644);
        fx.L->begin_replication(id2, Fixture::chunks(100), 100, 1);
        for (auto d : {"devA"}) {
            fx.L->set_replica(id2, 1, d, ReplicaState::PENDING); fx.L->set_replica(id2, 1, d, ReplicaState::UPLOADED);
            fx.L->set_replica(id2, 1, d, ReplicaState::COMMITTED, 3);
        }
        CHECK(fx.L->note_local_modified(id2, 101, 2).ok);
        CHECK(!fx.L->finish_replication(id2, 1).ok);
        CHECK(fx.L->fsck().empty());
    }

    {
        printf("== completion re-checks the evidence; aborting restores REPLICATED\n");
        Fixture fx;
        auto id = fx.replicated("/testdata/c", {"devA", "devB1"});
        Res d = fx.drop(id);
        CHECK(d.ok);
        CHECK(fx.L->record_audit(id, 1, "devB1", false, "blob hash mismatch").ok);  // device fails a late audit
        Res c = fx.L->complete_drop(d.id);
        CHECK(!c.ok && has(c.why, "no longer satisfy"));
        CHECK(fx.L->get_file(id)->state == FileState::DROPPING);
        CHECK(fx.L->abort_drop(d.id, "restored from quarantine").ok);
        auto f = fx.L->get_file(id);
        CHECK(f->state == FileState::REPLICATED && f->local_present && fx.L->open_intents().empty());
        CHECK(fx.L->fsck().empty());

        auto id2 = fx.replicated("/testdata/c2", {"devA", "devB1"});
        Res d2 = fx.drop(id2);
        g_time += 3600;   // a recovery after a crash that took an hour: evidence is stale
        CHECK(!fx.L->complete_drop(d2.id).ok);
        fx.L->record_audit(id2, 1, "devA", true, "again"); fx.L->record_audit(id2, 1, "devB1", true, "again");
        CHECK(fx.L->complete_drop(d2.id).ok);   // fresh audits: now it may complete
        CHECK(fx.L->fsck().empty());
    }

    {
        printf("== losing the last replica of an offloaded file raises AT_RISK automatically\n");
        Fixture fx;
        auto id = fx.replicated("/testdata/r1", {"devA", "devB1"});
        Res d = fx.drop(id);
        fx.L->complete_drop(d.id);
        CHECK(fx.L->record_audit(id, 1, "devA", false, "missing blob").ok);
        CHECK(fx.L->get_file(id)->state == FileState::OFFLOADED);   // one replica left
        CHECK(fx.L->record_audit(id, 1, "devB1", false, "device was reset").ok);
        CHECK(fx.L->get_file(id)->state == FileState::AT_RISK);     // none left: alert
        CHECK(!fx.L->begin_hydrate(id).ok);
        Res cl = fx.L->clear_at_risk(id);
        CHECK(!cl.ok && has(cl.why, "cannot clear"));               // never pretend it is fine
        CHECK(!fx.L->adopt_replica(id, 1, "devA", 0).ok);
        { Res a9 = fx.L->adopt_replica(id, 9, "devA", 4); CHECK(!a9.ok && has(a9.why, "unknown file version")); }
        CHECK(fx.L->adopt_replica(id, 1, "devA", 12).ok);           // found again on the device
        CHECK(fx.L->clear_at_risk(id).ok);
        CHECK(fx.L->get_file(id)->state == FileState::OFFLOADED);
        CHECK(fx.L->fsck().empty());
        // a file in the middle of a drop must be resolved, not hidden behind AT_RISK
        auto id2 = fx.replicated("/testdata/r2", {"devA", "devB1"});
        fx.drop(id2);
        CHECK(!fx.L->mark_at_risk(id2, "x").ok);
        auto id3 = fx.replicated("/testdata/r3", {"devA", "devB1"});
        CHECK(fx.L->mark_at_risk(id3, "manual").ok && fx.L->get_file(id3)->state == FileState::AT_RISK);
        CHECK(fx.L->clear_at_risk(id3).ok && fx.L->get_file(id3)->state == FileState::REPLICATED);
        CHECK(fx.L->fsck().empty());
    }

    {
        printf("== the ledger re-checks its own invariants even if rows were tampered with\n");
        Fixture fx;
        std::string id = fx.L->track_file("/testdata/t1", 100, 1, 0644);
        fx.L->begin_replication(id, Fixture::chunks(100), 100, 1);
        fx.L->set_replica(id, 1, "devA", ReplicaState::PENDING);
        fx.L->set_replica(id, 1, "devA", ReplicaState::UPLOADED);
        fx.L->set_replica(id, 1, "devA", ReplicaState::COMMITTED, 3);
        auto id2 = fx.replicated("/testdata/t2", {"devA", "devB1"});
        fx.L->complete_drop(fx.drop(id2).id);
        fx.L.reset();
        sqlite3* db = raw_open(fx.dir);
        std::string q1 = "UPDATE files SET generation=generation+1 WHERE file_id='" + id + "'";   // bytes changed behind the ledger's back
        std::string q2 = "UPDATE replicas SET state='MISSING' WHERE file_id='" + id2 + "'";      // OFFLOADED with every replica gone
        CHECK(raw_exec(db, q1.c_str()) && raw_exec(db, q2.c_str()));
        sqlite3_close(db);
        fx.L = open_ledger(fx.dir);
        Res f = fx.L->finish_replication(id, 1);
        CHECK(!f.ok && has(f.why, "changed since replication began"));
        Res h = fx.L->begin_hydrate(id2);
        CHECK(!h.ok && has(h.why, "no committed replica"));
    }

    {
        printf("== fsck catches states the API could never produce\n");
        Fixture fx;
        auto id = fx.replicated("/testdata/z", {"devA", "devB1"});
        auto id2 = fx.replicated("/testdata/z2", {"devA", "devB1"});
        auto id3 = fx.replicated("/testdata/z3", {"devA", "devB1"});
        fx.L.reset();
        sqlite3* db = raw_open(fx.dir);
        std::string q1 = "UPDATE files SET state='OFFLOADED' WHERE file_id='" + id + "'";            // claims offloaded but local_present=1
        std::string q2 = "UPDATE files SET state='DROPPING' WHERE file_id='" + id2 + "'";            // dropping with no intent
        std::string q3 = "UPDATE replicas SET state='MISSING' WHERE file_id='" + id3 + "'";          // replicated with no committed replica
        CHECK(raw_exec(db, q1.c_str()) && raw_exec(db, q2.c_str()) && raw_exec(db, q3.c_str()));
        sqlite3_close(db);
        fx.L = open_ledger(fx.dir);
        std::string all;
        for (auto& b : fx.L->fsck()) all += b + "\n";
        CHECK(has(all, "OFFLOADED file claims local bytes"));
        CHECK(has(all, "DROPPING file without a matching open intent"));
        CHECK(has(all, "REPLICATED file lacks local bytes or a committed replica"));
    }

    {
        printf("== crash injection: the process dies at each point, restart finds a consistent ledger\n");
        struct Setup { std::string dir, id, intent, consent; };
        auto setup = [](bool begin_drop_too) {
            Setup s;
            Fixture* fx = new Fixture;
            s.dir = fx->dir;
            s.consent = fx->consent;
            s.id = fx->replicated("/testdata/crash", {"devA", "devB1"});
            if (begin_drop_too) s.intent = fx->drop(s.id).id;
            fx->dir = tmpdir();   // keep the populated directory; ~Fixture removes this spare one
            fx->L.reset();
            delete fx;
            return s;
        };
        // 1. dies before transaction A commits: nothing happened
        {   Setup s = setup(false);
            CHECK(crash_run("ledger.drop.before_commit", {"drop", s.dir, s.id, s.consent}));
            auto L = open_ledger(s.dir);
            auto f = L ? L->get_file(s.id) : std::nullopt;
            CHECK(f && f->state == FileState::REPLICATED && f->local_present && L->open_intents().empty());
            CHECK(L && L->fsck().empty());
            fs::remove_all(s.dir);
        }
        // 2. dies right after A commits: DROPPING with an open intent, bytes still local
        {   Setup s = setup(false);
            CHECK(crash_run("ledger.drop.after_commit", {"drop", s.dir, s.id, s.consent}));
            auto L = open_ledger(s.dir);
            auto f = L ? L->get_file(s.id) : std::nullopt;
            CHECK(f && f->state == FileState::DROPPING);
            auto intents = L ? L->open_intents() : std::vector<IntentRec>{};
            CHECK(intents.size() == 1 && intents[0].kind == "DROP_LOCAL");
            CHECK(L && L->fsck().empty());
            if (L && intents.size() == 1) {   // recovery: stale evidence is refused, a re-audit lets it complete
                g_time += 5000;
                CHECK(!L->complete_drop(intents[0].intent_id).ok);
                L->record_audit(s.id, 1, "devA", true, "r"); L->record_audit(s.id, 1, "devB1", true, "r");
                CHECK(L->complete_drop(intents[0].intent_id).ok);
                CHECK(L->get_file(s.id)->state == FileState::OFFLOADED && L->fsck().empty());
            }
            fs::remove_all(s.dir);
        }
        // 3. dies before B commits: still DROPPING, completion works afterwards
        {   Setup s = setup(true);
            CHECK(!s.intent.empty());
            CHECK(crash_run("ledger.complete.before_commit", {"complete", s.dir, s.intent}));
            auto L = open_ledger(s.dir);
            auto f = L ? L->get_file(s.id) : std::nullopt;
            CHECK(f && f->state == FileState::DROPPING && L->open_intents().size() == 1);
            CHECK(L && L->fsck().empty());
            CHECK(L && L->complete_drop(s.intent).ok && L->fsck().empty());
            fs::remove_all(s.dir);
        }
        // 4. dies right after B commits: OFFLOADED, intent done
        {   Setup s = setup(true);
            CHECK(crash_run("ledger.complete.after_commit", {"complete", s.dir, s.intent}));
            auto L = open_ledger(s.dir);
            auto f = L ? L->get_file(s.id) : std::nullopt;
            CHECK(f && f->state == FileState::OFFLOADED && !f->local_present && L->open_intents().empty());
            CHECK(L && L->fsck().empty());
            fs::remove_all(s.dir);
        }
        // the crash point is inert when not armed (helper runs to completion, exit 0)
        {   Setup s = setup(true);
            pid_t pid;
            std::vector<std::string> a = {"ledger_helper", "complete", s.dir, s.intent};
            std::vector<char*> av;
            for (auto& x : a) av.push_back(const_cast<char*>(x.c_str()));
            av.push_back(nullptr);
            CHECK(posix_spawn(&pid, helper_path(), nullptr, nullptr, av.data(), environ) == 0);
            int st = 0;
            waitpid(pid, &st, 0);
            CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 5);   // refused (evidence is stale in real time), but did not crash
            fs::remove_all(s.dir);
        }
    }

    {
        printf("== snapshots, reserve, access tracking\n");
        Fixture fx;
        auto id = fx.replicated("/testdata/snap", {"devA", "devB1"});
        std::string snapdir = tmpdir();
        CHECK(fx.L->snapshot_to(snapdir + "/ledger.db"));
        CHECK(!fx.L->snapshot_to(snapdir + "/ledger.db"));    // never overwrites
        auto S = open_ledger(snapdir);
        CHECK(S && S->get_file(id)->state == FileState::REPLICATED && S->fsck().empty());
        CHECK(S->volume_id() == fx.L->volume_id() && S->event_count() == fx.L->event_count());
        S.reset();
        fs::remove_all(snapdir);

        fx.L->release_reserve();
        CHECK(!fx.L->has_reserve() && fx.L->ensure_reserve(2 << 20) && fx.L->has_reserve());
        CHECK(fs::file_size(fx.dir + "/ledger.reserve") >= (2u << 20));

        fx.L->touch_access(id, 5000);
        CHECK(fx.L->get_file(id)->last_access == 5000);
        fx.L->touch_access(id, 5030);    // throttled
        CHECK(fx.L->get_file(id)->last_access == 5000);
        fx.L->touch_access(id, 5100);
        CHECK(fx.L->get_file(id)->last_access == 5100);
        CHECK(fx.L->list_files(FileState::REPLICATED).size() == 1 && fx.L->list_files(FileState::LOCAL).empty());
    }

    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
