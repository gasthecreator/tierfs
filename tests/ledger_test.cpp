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
#include <atomic>
#include <functional>
#include <thread>
#include <vector>

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
        if (backup) ack_all();
        L->ensure_reserve(1 << 20);
        for (auto [id, cls] : {std::pair<const char*, const char*>{"devA", "A"}, {"devB1", "B"}, {"devB2", "B"}, {"devC", "C"}})
            L->register_device(id, id, cls);
        consent = L->create_consent("/testdata/", 3600, "I understand");
    }
    // The owner\'s statement about a backup that is newer than everything in these tests (year 2096): the dated gate is tested explicitly below.
    void ack_all() {
        L->set_meta("backup_acked", "1");
        L->set_meta("backup_acked_at", "4000000000");
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
            fx.ack_all();
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
        printf("== a device that rolls back or resets loses its standing, and dependants fall back\n");
        Fixture fx;
        CHECK(fx.L->observe_device("nobody", 1, 1) == DeviceObservation::Unknown);
        auto d0 = fx.L->get_device("devA");
        CHECK(d0 && d0->epoch == 0 && d0->last_seq == 0 && d0->state == "active" && d0->cls == "A");
        CHECK(fx.L->observe_device("devA", 111, 5) == DeviceObservation::First);
        CHECK(fx.L->observe_device("devA", 111, 7) == DeviceObservation::Ok && fx.L->get_device("devA")->last_seq == 7);
        CHECK(fx.L->observe_device("devA", 111, 7) == DeviceObservation::Ok);
        CHECK(fx.L->observe_device("devA", 111, 6) == DeviceObservation::Rollback);      // same epoch, lower seq: restored from an old copy
        auto d1 = fx.L->get_device("devA");
        CHECK(d1->state == "suspect" && d1->last_seq == 7);                             // the high-water mark is kept
        CHECK(fx.L->observe_device("devA", 111, 9) == DeviceObservation::Ok && fx.L->get_device("devA")->state == "suspect");   // catching up does not clear it
        CHECK(!fx.L->clear_device_suspect("devB1", 1).ok);                              // only suspect devices can be cleared
        CHECK(fx.L->clear_device_suspect("devA", 9).ok);
        CHECK(fx.L->get_device("devA")->state == "active" && fx.L->get_device("devA")->last_seq == 9);
        CHECK(fx.L->observe_device("devA", 111, 9) == DeviceObservation::Ok && fx.L->get_device("devA")->state == "active");   // 9 is the new normal
        CHECK(fx.L->observe_device("devA", 222, 1) == DeviceObservation::EpochChanged);  // re-initialised or replaced
        CHECK(fx.L->get_device("devA")->state == "suspect" && fx.L->get_device("devA")->epoch == 222);
        fx.L->clear_device_suspect("devA", 1);
        fx.L->retire_device("devB2");
        CHECK(fx.L->observe_device("devB2", 5, 5) == DeviceObservation::First);
        CHECK(fx.L->observe_device("devB2", 6, 1) == DeviceObservation::EpochChanged && fx.L->get_device("devB2")->state == "retired");   // retired stays retired
        CHECK(fx.L->observe_device("devB2", 6, 0) == DeviceObservation::Rollback && fx.L->get_device("devB2")->state == "retired");   // ... also when it rolls back
        CHECK(fx.L->list_devices().size() == 4);
        CHECK(fx.L->fsck().empty());

        // a REPLICATED file with two replicas survives losing one device but not both
        auto id = fx.replicated("/testdata/dep", {"devA", "devB1"});
        fx.L->observe_device("devB1", 50, 10);
        CHECK(fx.L->observe_device("devA", 222, 0) == DeviceObservation::Rollback);      // seq 0 < 1
        CHECK(fx.L->get_file(id)->state == FileState::REPLICATED);                       // devB1 still stands
        CHECK(fx.L->observe_device("devB1", 50, 9) == DeviceObservation::Rollback);
        CHECK(fx.L->get_file(id)->state == FileState::REPLICATING);                      // nothing left to rely on: replicate again
        CHECK(fx.L->fsck().empty());
        EXPECT_REFUSED(fx, id, fx.drop(id), "not REPLICATED");
        CHECK(fx.L->replica_weight(id, 1, 600) == 0.0);                                  // suspect devices count for nothing
        CHECK(fx.L->clear_device_suspect("devA", 4).ok);
        CHECK(fx.L->finish_replication(id, 1).ok && fx.L->get_file(id)->state == FileState::REPLICATED && fx.L->fsck().empty());

        // an OFFLOADED file whose devices are both suspect is AT_RISK, and can be recovered when they are cleared
        CHECK(fx.L->clear_device_suspect("devB1", 9).ok);   // (it was left suspect by the step above)
        auto off = fx.replicated("/testdata/off", {"devA", "devB1"});
        fx.L->complete_drop(fx.drop(off).id);
        CHECK(fx.L->get_file(off)->state == FileState::OFFLOADED);
        fx.L->observe_device("devA", 222, 1);        // devA: rollback again (seq 1 < 4)
        fx.L->observe_device("devB1", 50, 1);        // devB1 is already suspect and now even further back
        CHECK(fx.L->get_file(off)->state == FileState::AT_RISK && fx.L->fsck().empty());
        CHECK(fx.L->clear_device_suspect("devA", 1).ok && fx.L->clear_at_risk(off).ok);
        CHECK(fx.L->get_file(off)->state == FileState::OFFLOADED);

        {   // a device that comes back with a NEW epoch (wiped, replaced, reinstalled) is no better than a rolled-back one
            Fixture ep;
            CHECK(ep.L->observe_device("devA", 500, 3) == DeviceObservation::First);
            auto e1 = ep.replicated("/testdata/epoch", {"devA"});
            CHECK(ep.L->get_file(e1)->state == FileState::REPLICATED);
            CHECK(ep.L->observe_device("devA", 501, 9) == DeviceObservation::EpochChanged);
            CHECK(ep.L->get_device("devA")->state == "suspect" && ep.L->get_file(e1)->state == FileState::REPLICATING);
            CHECK(ep.L->fsck().empty());
        }

        // the other ways to lose the last replica of a REPLICATED file behave the same
        auto a = fx.replicated("/testdata/only-a", {"devA"});
        CHECK(fx.L->set_replica(a, 1, "devA", ReplicaState::MISSING).ok);
        CHECK(fx.L->get_file(a)->state == FileState::REPLICATING);
        auto b = fx.replicated("/testdata/only-a2", {"devA"});
        CHECK(fx.L->record_audit(b, 1, "devA", false, "gone").ok && fx.L->get_file(b)->state == FileState::REPLICATING);
        auto c = fx.replicated("/testdata/only-a3", {"devA"});
        fx.L->retire_device("devA");
        CHECK(fx.L->get_file(c)->state == FileState::REPLICATING && fx.L->fsck().empty());
        CHECK(fx.L->replicas_on_device("devA").size() >= 4);
    }

    {
        printf("== manifest hashes are set once; audit challenges are used once\n");
        Fixture fx;
        std::string id = fx.L->track_file("/testdata/ch", 3000000, 1, 0644);
        fx.L->begin_replication(id, Fixture::chunks(3000000), 3000000, 1);
        std::string h1(64, 'a'), h2(64, 'b');
        CHECK(!fx.L->get_manifest_hash(id, 1).has_value());
        CHECK(!fx.L->set_manifest_hash(id, 9, h1).ok);                       // unknown version
        CHECK(!fx.L->set_manifest_hash(id, 1, "short").ok);
        CHECK(fx.L->set_manifest_hash(id, 1, h1).ok && fx.L->get_manifest_hash(id, 1) == h1);
        CHECK(fx.L->set_manifest_hash(id, 1, h1).ok);                        // idempotent
        Res other = fx.L->set_manifest_hash(id, 1, h2);
        CHECK(!other.ok && has(other.why, "already recorded") && fx.L->get_manifest_hash(id, 1) == h1);

        std::vector<Challenge> cs;
        for (uint32_t n = 0; n < 4; n++) cs.push_back({n, std::string(64, char('0' + n))});
        CHECK(fx.L->add_challenges(id, 1, 0, cs).ok);
        CHECK(fx.L->challenges_left(id, 1, 0) == 4 && fx.L->next_challenge_n(id, 1, 0) == 4 && fx.L->challenges_left(id, 1, 1) == 0);
        CHECK(!fx.L->add_challenges(id, 1, 0, {{2, std::string(64, 'e')}}).ok);       // a number is never reissued
        CHECK(!fx.L->add_challenges(id, 1, 0, {{9, "short"}}).ok);
        CHECK(!fx.L->add_challenges(id, 7, 0, {{0, std::string(64, 'e')}}).ok);       // no such version
        for (uint32_t n = 0; n < 4; n++) {
            auto c = fx.L->take_challenge(id, 1, 0);
            CHECK(c && c->n == n && c->response == std::string(64, char('0' + n)));     // in order, each exactly once
        }
        CHECK(!fx.L->take_challenge(id, 1, 0).has_value() && fx.L->challenges_left(id, 1, 0) == 0);
        CHECK(fx.L->next_challenge_n(id, 1, 0) == 4);                                    // refresh continues the numbering
        CHECK(fx.L->add_challenges(id, 1, 0, {{4, std::string(64, 'f')}}).ok && fx.L->take_challenge(id, 1, 0)->n == 4);
        CHECK(fx.L->add_challenges(id, 1, MANIFEST_CHALLENGE_IDX, {{0, std::string(64, '9')}}).ok);   // the manifest has its own pool
        CHECK(fx.L->take_challenge(id, 1, MANIFEST_CHALLENGE_IDX)->response == std::string(64, '9'));
        CHECK(fx.L->fsck().empty());
        fx.L.reset();
        sqlite3* db = raw_open(fx.dir);
        CHECK(!raw_exec(db, "UPDATE chunk_challenges SET used=0"));                       // a burned challenge cannot be revived
        CHECK(!raw_exec(db, "UPDATE chunk_challenges SET response='x'"));
        CHECK(!raw_exec(db, "DELETE FROM chunk_challenges"));
        CHECK(!raw_exec(db, ("UPDATE versions SET manifest_sha256='" + std::string(64, 'c') + "' WHERE file_id='" + id + "'").c_str()));
        sqlite3_close(db);
    }

    {
        printf("== quarantine: dropped bytes are held, and deleting them is gated by fresh evidence\n");
        Fixture fx;
        auto id = fx.replicated("/testdata/q1", {"devA", "devB1"});
        Res d = fx.drop(id);
        CHECK(d.ok && !fx.L->get_quarantine(d.id).has_value());                // nothing is quarantined until the drop completes
        CHECK(fx.L->complete_drop(d.id).ok);
        auto q = fx.L->get_quarantine(d.id);
        CHECK(q && q->state == QuarantineState::HELD && q->held_at == g_time && q->version == 1 && q->file_id == id);
        CHECK(fx.L->list_quarantine().size() == 1 && fx.L->list_quarantine(QuarantineState::PURGED).empty() && fx.L->fsck().empty());
        CHECK(!fx.L->get_quarantine("nope").has_value());

        const int64_t WEEK = 7 * 86400;
        auto refuse = [&](Res r, const char* why) {
            auto after = fx.L->get_quarantine(d.id);
            bool unchanged = after && after->state == QuarantineState::HELD;
            CHECK(!r.ok && has(r.why, why) && unchanged);
            if (r.ok || !has(r.why, why)) printf("      got: ok=%d why='%s'\n", r.ok, r.why.c_str());
        };
        refuse(fx.L->begin_purge(d.id, WEEK, false, 2.0, 600), "has not elapsed");                       // the same day
        refuse(fx.L->begin_purge("nope", 0, true, 2.0, 600), "no such quarantine");
        refuse(fx.L->begin_purge(d.id, 0, true, 0.0, 600), "positive");
        refuse(fx.L->begin_purge(d.id, 0, true, 2.0, 0), "finite audit age");
        g_time += 10 * 86400;                                                                              // ten days later: the period is over, but the audits are stale
        refuse(fx.L->begin_purge(d.id, WEEK, false, 2.0, 600), "insufficient replica weight");
        fx.L->record_audit(id, 1, "devA", true, "again");
        refuse(fx.L->begin_purge(d.id, WEEK, false, 2.0, 600), "have 1.0");                              // one fresh audit is not enough
        fx.L->record_audit(id, 1, "devB1", true, "again");
        // gates, one at a time
        fx.L->set_meta("recovery_acked", "0");
        refuse(fx.L->begin_purge(d.id, WEEK, false, 2.0, 600), "recovery phrase");
        fx.L->set_meta("recovery_acked", "1");
        fx.L->release_reserve();
        refuse(fx.L->begin_purge(d.id, WEEK, false, 2.0, 600), "reserve");
        fx.L->ensure_reserve(1 << 20);
        fx.L->set_meta("backup_acked", "0");
        refuse(fx.L->begin_purge(d.id, WEEK, false, 2.0, 600), "backup not acknowledged");
        fx.L->set_meta("backup_acked", "1");
        // a device that stops being trustworthy takes its weight with it
        fx.L->observe_device("devB1", 9, 9);
        fx.L->observe_device("devB1", 9, 5);                                                              // rolled back: suspect
        refuse(fx.L->begin_purge(d.id, WEEK, false, 2.0, 600), "have 1.0");
        fx.L->clear_device_suspect("devB1", 5);
        fx.L->record_audit(id, 1, "devB1", true, "cleared and re-audited");
        CHECK(fx.L->fsck().empty());

        // now it is allowed
        CHECK(fx.L->begin_purge(d.id, WEEK, false, 2.0, 600).ok);
        CHECK(fx.L->get_quarantine(d.id)->state == QuarantineState::PURGING);
        uint64_t ev = fx.L->event_count();
        CHECK(fx.L->begin_purge(d.id, WEEK, false, 2.0, 600).ok && fx.L->event_count() == ev);           // a retry is harmless
        CHECK(!fx.L->begin_restore(d.id, "too late").ok);                                                 // the bytes may already be going
        CHECK(fx.L->complete_purge(d.id).ok);
        auto done = fx.L->get_quarantine(d.id);
        CHECK(done->state == QuarantineState::PURGED && done->resolved_at == g_time);
        CHECK(!fx.L->complete_purge(d.id).ok && !fx.L->begin_purge(d.id, 0, true, 2.0, 600).ok && !fx.L->begin_restore(d.id, "x").ok);
        CHECK(fx.L->get_file(id)->state == FileState::OFFLOADED && fx.L->fsck().empty());
        fx.L.reset();
        sqlite3* db = raw_open(fx.dir);
        CHECK(!raw_exec(db, "UPDATE quarantine SET state='held'"));                                       // a purge cannot be un-purged
        CHECK(!raw_exec(db, "DELETE FROM quarantine"));
        sqlite3_close(db);
    }

    {
        printf("== quarantine: the completing steps cannot be used to skip the gated beginning\n");
        Fixture fx;
        auto id = fx.replicated("/testdata/skip", {"devA", "devB1"});
        Res d = fx.drop(id);
        fx.L->complete_drop(d.id);
        Res c1 = fx.L->complete_purge(d.id);                       // never begun: the gates were never consulted
        CHECK(!c1.ok && has(c1.why, "not PURGING"));
        Res c2 = fx.L->complete_restore(d.id, true);
        CHECK(!c2.ok && has(c2.why, "not RESTORING"));
        CHECK(fx.L->get_quarantine(d.id)->state == QuarantineState::HELD && fx.L->get_file(id)->state == FileState::OFFLOADED);
        fx.L->begin_restore(d.id, "x");
        Res c3 = fx.L->complete_purge(d.id);                       // wrong direction
        CHECK(!c3.ok && fx.L->get_quarantine(d.id)->state == QuarantineState::RESTORING);
        CHECK(fx.L->fsck().empty());
    }

    {
        printf("== quarantine: emergency purge, hydrated files, AT_RISK files\n");
        Fixture fx;
        auto id = fx.replicated("/testdata/q2", {"devA", "devB1"});
        Res d = fx.drop(id);
        fx.L->complete_drop(d.id);
        // an emergency (low disk) skips the waiting period, NEVER the evidence
        CHECK(fx.L->begin_purge(d.id, 7 * 86400, true, 2.0, 600).ok);
        CHECK(fx.L->get_quarantine(d.id)->state == QuarantineState::PURGING);

        Fixture fy;
        auto id2 = fy.replicated("/testdata/q3", {"devA", "devB1"});
        Res d2 = fy.drop(id2);
        fy.L->complete_drop(d2.id);
        g_time += 5000;                                                                                    // audits are stale
        Res stale = fy.L->begin_purge(d2.id, 0, true, 2.0, 600);
        CHECK(!stale.ok && has(stale.why, "insufficient replica weight"));
        fy.L->record_audit(id2, 1, "devA", true, "a"); fy.L->record_audit(id2, 1, "devB1", true, "b");
        // the file is recalled (hydrated), then the leftover quarantine can go
        CHECK(fy.L->begin_hydrate(id2).ok && fy.L->complete_hydrate(id2).ok && fy.L->get_file(id2)->state == FileState::REPLICATED);
        CHECK(fy.L->begin_purge(d2.id, 0, false, 2.0, 600).ok && fy.L->complete_purge(d2.id).ok);
        CHECK(fy.L->fsck().empty());

        Fixture fz;
        auto id3 = fz.replicated("/testdata/q4", {"devA", "devB1"});
        Res d3 = fz.drop(id3);
        fz.L->complete_drop(d3.id);
        CHECK(fz.L->record_audit(id3, 1, "devB1", false, "gone").ok);                                    // one replica fails: 1.0 left
        fz.L->record_audit(id3, 1, "devA", true, "ok");
        Res weak = fz.L->begin_purge(d3.id, 0, true, 2.0, 600);
        CHECK(!weak.ok && has(weak.why, "have 1.0"));
        CHECK(fz.L->record_audit(id3, 1, "devA", false, "gone too").ok);                                 // now none: the file is AT_RISK
        CHECK(fz.L->get_file(id3)->state == FileState::AT_RISK);
        Res risky = fz.L->begin_purge(d3.id, 0, true, 0.5, 600);
        CHECK(!risky.ok && has(risky.why, "restore the quarantined bytes instead"));                     // the quarantine may be the only copy left
        CHECK(fz.L->get_quarantine(d3.id)->state == QuarantineState::HELD && fz.L->fsck().empty());
    }

    {
        printf("== quarantine: restoring\n");
        Fixture fx;
        auto id = fx.replicated("/testdata/r1", {"devA", "devB1"});
        Res d = fx.drop(id);
        fx.L->complete_drop(d.id);
        CHECK(!fx.L->begin_restore("nope", "x").ok);
        CHECK(fx.L->begin_restore(d.id, "a replica failed").ok);
        auto q = fx.L->get_quarantine(d.id);
        CHECK(q->state == QuarantineState::RESTORING && q->note == "a replica failed");
        uint64_t ev = fx.L->event_count();
        CHECK(fx.L->begin_restore(d.id, "again").ok && fx.L->event_count() == ev);                        // retry is harmless
        CHECK(!fx.L->begin_purge(d.id, 0, true, 2.0, 600).ok);                                            // cannot purge while restoring
        CHECK(fx.L->complete_restore(d.id, true).ok);
        auto f = fx.L->get_file(id);
        CHECK(f->state == FileState::REPLICATED && f->local_present && fx.L->fsck().empty());             // bytes vouched for, committed replicas exist
        CHECK(fx.L->get_quarantine(d.id)->state == QuarantineState::RESTORED && !fx.L->complete_restore(d.id, true).ok);

        // bytes we cannot vouch for come back as LOCAL data with a new generation
        auto id2 = fx.replicated("/testdata/r2", {"devA", "devB1"});
        Res d2 = fx.drop(id2);
        fx.L->complete_drop(d2.id);
        int64_t gen = fx.L->get_file(id2)->generation;
        CHECK(fx.L->begin_restore(d2.id, "damaged?").ok && fx.L->complete_restore(d2.id, false).ok);
        auto f2 = fx.L->get_file(id2);
        CHECK(f2->state == FileState::LOCAL && f2->local_present && f2->generation == gen + 1 && fx.L->fsck().empty());

        // every replica gone while quarantined: the file is AT_RISK and the quarantine is what is left
        auto id3 = fx.replicated("/testdata/r3", {"devA", "devB1"});
        Res d3 = fx.drop(id3);
        fx.L->complete_drop(d3.id);
        fx.L->record_audit(id3, 1, "devA", false, "gone");
        fx.L->record_audit(id3, 1, "devB1", false, "gone");
        CHECK(fx.L->get_file(id3)->state == FileState::AT_RISK);
        CHECK(fx.L->begin_restore(d3.id, "last copy").ok && fx.L->complete_restore(d3.id, true).ok);
        auto f3 = fx.L->get_file(id3);
        CHECK(f3->state == FileState::LOCAL && f3->local_present);                                         // nothing to be REPLICATED against: replicate it again
        CHECK(fx.L->fsck().empty());

        // not offered for files that are not offloaded
        auto id4 = fx.replicated("/testdata/r4", {"devA", "devB1"});
        Res d4 = fx.drop(id4);
        fx.L->complete_drop(d4.id);
        fx.L->begin_hydrate(id4);
        fx.L->complete_hydrate(id4);                                                                       // recalled: REPLICATED again
        Res nope = fx.L->begin_restore(d4.id, "x");
        CHECK(!nope.ok && has(nope.why, "OFFLOADED or AT_RISK"));
    }

    {
        printf("== quarantine: crash injection around purge and restore\n");
        struct Setup { std::string dir, id, intent; };
        auto setup = []() {
            Setup s;
            Fixture* fx = new Fixture;
            s.dir = fx->dir;
            s.id = fx->replicated("/testdata/qc", {"devA", "devB1"});
            s.intent = fx->drop(s.id).id;
            fx->L->complete_drop(s.intent);
            fx->dir = tmpdir();
            fx->L.reset();
            delete fx;
            return s;
        };
        {   Setup s = setup();
            CHECK(crash_run("ledger.purge.before_commit", {"purge", s.dir, s.intent}));
            auto L = open_ledger(s.dir);
            CHECK(L && L->get_quarantine(s.intent)->state == QuarantineState::HELD && L->fsck().empty());   // nothing happened
            fs::remove_all(s.dir);
        }
        {   Setup s = setup();
            CHECK(crash_run("ledger.purge.after_commit", {"purge", s.dir, s.intent}));
            auto L = open_ledger(s.dir);
            CHECK(L && L->get_quarantine(s.intent)->state == QuarantineState::PURGING && L->fsck().empty());
            CHECK(L->begin_purge(s.intent, 0, true, 2.0, 600).ok && L->complete_purge(s.intent).ok);       // the engine can finish it
            fs::remove_all(s.dir);
        }
        {   Setup s = setup();
            CHECK(crash_run("ledger.restore.before_commit", {"restore", s.dir, s.intent}));
            auto L = open_ledger(s.dir);
            CHECK(L && L->get_quarantine(s.intent)->state == QuarantineState::HELD && L->fsck().empty());
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

    {
        printf("== the ledger can be shared by many threads (filesystem, policy and engines use it at once)\n");
        Fixture fx;
        const int threads = 8, per = 40;
        std::atomic<int> errors{0};
        std::vector<std::thread> ts;
        for (int t = 0; t < threads; t++)
            ts.emplace_back([&, t] {
                for (int i = 0; i < per; i++) {
                    std::string path = "/testdata/t" + std::to_string(t) + "/f" + std::to_string(i);
                    std::string id = fx.L->track_file(path, 100 + i, 1000 + i, 0644);
                    if (id.empty()) { errors++; continue; }
                    auto f = fx.L->get_file_by_path(path);
                    if (!f || f->file_id != id || f->size != static_cast<uint64_t>(100 + i)) errors++;
                    if (!fx.L->note_local_modified(id, 200 + i, 2000 + i).ok) errors++;
                    fx.L->touch_access(id, 5000 + i);
                    if (!fx.L->set_meta("k" + std::to_string(t), std::to_string(i))) errors++;
                    if (fx.L->list_files_under("/testdata/t" + std::to_string(t) + "/").empty()) errors++;
                    fx.L->get_meta("k" + std::to_string(t));
                    fx.L->list_devices();
                }
            });
        for (auto& t : ts) t.join();
        CHECK(errors == 0);
        CHECK(fx.L->list_files().size() == static_cast<size_t>(threads * per));
        CHECK(fx.L->list_files_under("/testdata/t3/").size() == static_cast<size_t>(per) && fx.L->list_files_under("/testdata/t3").size() == static_cast<size_t>(per));
        CHECK(fx.L->fsck().empty());                                       // the hash chain is intact: no event was lost or interleaved
        for (int t = 0; t < threads; t++) CHECK(fx.L->get_meta("k" + std::to_string(t)).value_or("") == std::to_string(per - 1));
    }

    {
        printf("== the namespace: deleting, undeleting, renaming files and directories, changing attributes\n");
        Fixture fx;
        auto offload = [&](const std::string& path) {
            std::string id = fx.replicated(path, {"devA", "devB1"});
            Res d = fx.drop(id);
            CHECK(d.ok && fx.L->complete_drop(d.id).ok);
            return id;
        };
        // ---- deleting
        std::string a = fx.L->track_file("/testdata/dir/a", 100, 50, 0644);
        CHECK(fx.L->retire_file(a, "user deleted it").ok);
        CHECK(!fx.L->get_file_by_path("/testdata/dir/a") && fx.L->get_file(a)->state == FileState::LOCAL);
        CHECK(Ledger::is_retired_path(fx.L->get_file(a)->path) && Ledger::former_path(*fx.L->get_file(a)) == "/testdata/dir/a");
        CHECK(!Ledger::is_retired_path("/testdata/dir/a") && Ledger::former_path(*fx.L->get_file(fx.L->track_file("/testdata/live", 1, 1, 0644))) == "/testdata/live");
        CHECK(fx.L->list_retired().size() == 1 && fx.L->list_retired()[0].file_id == a);
        CHECK(!fx.L->retire_file(a, "again").ok && !fx.L->retire_file("nope", "x").ok);      // once; and only known files
        CHECK(fx.L->list_files_under("/testdata/dir/").empty());                              // invisible to every lookup by path
        std::string a2 = fx.L->track_file("/testdata/dir/a", 200, 60, 0600);                  // the name is free again: a NEW file
        CHECK(a2 != a && fx.L->get_file(a2)->size == 200);
        CHECK(!fx.L->undelete_file(a).ok);                                                    // a deleted LOCAL file cannot come back
        CHECK(!fx.L->rename_file(a, "/testdata/x").ok && !fx.L->note_attrs_changed(a, 0600, std::nullopt).ok);   // a deleted file is not renamed or touched
        // an offloaded file: deleted, then undeleted; a name taken meanwhile blocks it
        std::string off = offload("/testdata/off");
        CHECK(fx.L->retire_file(off, "user deleted it").ok && !fx.L->get_file_by_path("/testdata/off"));
        CHECK(fx.L->get_file(off)->state == FileState::OFFLOADED && fx.L->fsck().empty());
        std::string squatter = fx.L->track_file("/testdata/off", 5, 5, 0644);
        CHECK(!fx.L->undelete_file(off).ok && Ledger::is_retired_path(fx.L->get_file(off)->path));
        CHECK(fx.L->retire_file(squatter, "gone").ok && fx.L->undelete_file(off).ok);
        CHECK(fx.L->get_file_by_path("/testdata/off")->file_id == off && !fx.L->undelete_file(off).ok);
        // never in the middle of a drop or a hydration
        std::string mid = fx.replicated("/testdata/mid", {"devA", "devB1"});
        Res d = fx.drop(mid);
        CHECK(d.ok && !fx.L->retire_file(mid, "x").ok && !fx.L->rename_file(mid, "/testdata/mid2").ok && !fx.L->note_attrs_changed(mid, 0600, std::nullopt).ok);
        CHECK(fx.L->complete_drop(d.id).ok && fx.L->begin_hydrate(mid).ok);
        CHECK(!fx.L->retire_file(mid, "x").ok && !fx.L->rename_file(mid, "/testdata/mid2").ok && !fx.L->note_attrs_changed(mid, 0600, std::nullopt).ok);
        CHECK(fx.L->abort_hydrate(mid).ok);
        // a deleted LOCAL file whose old name is still free cannot be undeleted either (nothing of it exists locally any more)
        std::string lonely = fx.L->track_file("/testdata/lonely", 10, 10, 0644);
        CHECK(fx.L->retire_file(lonely, "gone").ok && !fx.L->undelete_file(lonely).ok && !fx.L->get_file_by_path("/testdata/lonely"));
        // every change is written to the history
        uint64_t e0 = fx.L->event_count();
        std::string evf = fx.L->track_file("/testdata/ev", 10, 10, 0644);
        uint64_t e1 = fx.L->event_count();
        CHECK(fx.L->note_attrs_changed(evf, 0600, std::nullopt).ok && fx.L->event_count() == e1 + 1);
        CHECK(fx.L->rename_file(evf, "/testdata/ev2").ok && fx.L->event_count() == e1 + 2);
        CHECK(fx.L->retire_file(evf, "x").ok && fx.L->event_count() == e1 + 3);
        std::string evo = offload("/testdata/evo");
        uint64_t e2 = fx.L->event_count();
        CHECK(fx.L->retire_file(evo, "x").ok && fx.L->undelete_file(evo).ok && fx.L->event_count() == e2 + 2);
        std::string evd = fx.L->track_file("/testdata/evdir/f", 10, 10, 0644);
        uint64_t e3 = fx.L->event_count();
        CHECK(fx.L->rename_prefix("/testdata/evdir/", "/testdata/evdir2/").ok && fx.L->event_count() == e3 + 1 && e0 < e1);
        (void)evd;
        // ---- renaming one file
        std::string r = fx.replicated("/testdata/r", {"devA", "devB1"});
        auto before = fx.L->get_file(r);
        CHECK(fx.L->rename_file(r, "/testdata/r2").ok);
        auto after = fx.L->get_file(r);
        CHECK(after->path == "/testdata/r2" && after->state == FileState::LOCAL && after->generation > before->generation && after->current_version == before->current_version);
        CHECK(!fx.L->get_file_by_path("/testdata/r") && fx.L->get_file_by_path("/testdata/r2")->file_id == r);
        CHECK(!fx.L->rename_file(r, "/testdata/r2").ok && !fx.L->rename_file(r, "/testdata/off").ok);      // same path; a taken path
        CHECK(!fx.L->rename_file(r, "").ok && !fx.L->rename_file(r, "relative").ok && !fx.L->rename_file(r, std::string("/\x01") + "deleted/x").ok);
        CHECK(!fx.drop(r).ok);                                                                               // renamed since it was replicated: not droppable
        std::string o2 = offload("/testdata/o2");
        CHECK(fx.L->rename_file(o2, "/testdata/o3").ok && fx.L->get_file(o2)->state == FileState::OFFLOADED && fx.L->get_file(o2)->path == "/testdata/o3" && !fx.L->get_file(o2)->local_present);
        // ---- renaming a directory
        std::string d1 = fx.replicated("/testdata/old/x", {"devA", "devB1"});
        std::string d2 = offload("/testdata/old/sub/y");
        std::string d3 = fx.L->track_file("/testdata/old/z", 10, 10, 0644);
        std::string other = fx.L->track_file("/testdata/older/q", 10, 10, 0644);                              // a different directory with the same leading text
        CHECK(fx.L->rename_prefix("/testdata/old/", "/testdata/new/").ok);
        CHECK(fx.L->get_file(d1)->path == "/testdata/new/x" && fx.L->get_file(d2)->path == "/testdata/new/sub/y" && fx.L->get_file(d3)->path == "/testdata/new/z");
        CHECK(fx.L->get_file(other)->path == "/testdata/older/q");
        CHECK(fx.L->get_file(d1)->state == FileState::LOCAL && fx.L->get_file(d2)->state == FileState::OFFLOADED);
        CHECK(fx.L->list_files_under("/testdata/old/").empty() && fx.L->list_files_under("/testdata/new/").size() == 3 && fx.L->fsck().empty());
        auto moved = fx.L->rename_prefix("/testdata/new/", "/testdata/newer/");
        CHECK(moved.ok && moved.id == "3");
        std::string t1 = fx.L->track_file("/testdata/src/f", 1, 1, 0644), t2 = fx.L->track_file("/testdata/dst/f", 1, 1, 0644);
        uint64_t ev = fx.L->event_count();
        CHECK(!fx.L->rename_prefix("/testdata/src/", "/testdata/dst/").ok && fx.L->get_file(t1)->path == "/testdata/src/f" && fx.L->get_file(t2)->path == "/testdata/dst/f");   // a taken name refuses ALL of it
        CHECK(fx.L->event_count() == ev);
        CHECK(!fx.L->rename_prefix("/testdata/src/", "/testdata/src/inner/").ok && !fx.L->rename_prefix("/testdata/src", "/testdata/s2/").ok && !fx.L->rename_prefix("/testdata/src/", "/testdata/s2").ok);
        CHECK(fx.L->rename_prefix("/testdata/nothing/", "/testdata/else/").ok && fx.L->rename_prefix("/testdata/nothing/", "/testdata/else/").id == "0");
        CHECK(!fx.L->rename_prefix(std::string("/\x01") + "deleted/", "/testdata/grave/").ok && !fx.L->rename_prefix("/testdata/src/", std::string("/\x01") + "deleted/x/").ok);
        std::string hyd = offload("/testdata/hyd/h");
        CHECK(fx.L->begin_hydrate(hyd).ok && !fx.L->rename_prefix("/testdata/hyd/", "/testdata/hyd2/").ok && fx.L->get_file(hyd)->path == "/testdata/hyd/h");
        CHECK(fx.L->abort_hydrate(hyd).ok);
        std::string mid3 = fx.replicated("/testdata/busy/m", {"devA", "devB1"});
        std::string calm = fx.L->track_file("/testdata/busy/calm", 1, 1, 0644);
        Res dd = fx.drop(mid3);
        CHECK(dd.ok && !fx.L->rename_prefix("/testdata/busy/", "/testdata/free/").ok && fx.L->get_file(calm)->path == "/testdata/busy/calm");   // one busy file stops the whole move
        CHECK(fx.L->complete_drop(dd.id).ok);
        // ---- attributes
        std::string at = fx.replicated("/testdata/at", {"devA", "devB1"});
        auto b4 = fx.L->get_file(at);
        CHECK(fx.L->note_attrs_changed(at, 0600, 777).ok);
        auto af = fx.L->get_file(at);
        CHECK(af->mode == 0600 && af->mtime == 777 && af->state == FileState::LOCAL && af->generation > b4->generation && af->size == b4->size);
        CHECK(fx.L->note_attrs_changed(at, 0640, std::nullopt).ok && fx.L->get_file(at)->mode == 0640 && fx.L->get_file(at)->mtime == 777);
        CHECK(fx.L->note_attrs_changed(at, std::nullopt, 888).ok && fx.L->get_file(at)->mode == 0640 && fx.L->get_file(at)->mtime == 888);
        std::string of = offload("/testdata/of");
        auto ob = fx.L->get_file(of);
        CHECK(fx.L->note_attrs_changed(of, 0600, 999).ok);
        auto oa = fx.L->get_file(of);
        CHECK(oa->mode == 0600 && oa->mtime == 999 && oa->state == FileState::OFFLOADED && oa->generation == ob->generation && !oa->local_present);
        CHECK(fx.L->note_attrs_changed(of, 04755, std::nullopt).ok && fx.L->get_file(of)->mode == 04755);
        CHECK(!fx.L->note_attrs_changed("nope", 0600, std::nullopt).ok);
        CHECK(fx.L->fsck().empty());
    }

    {
        printf("== tracking many files in one transaction\n");
        Fixture fx;
        std::string pre = fx.L->track_file("/testdata/pre", 7, 7, 0644);
        std::vector<Ledger::NewFile> files;
        for (int i = 0; i < 1203; i++) files.push_back({"/testdata/bulk/f" + std::to_string(i), static_cast<uint64_t>(100 + i), 1000 + i, 0640});
        files.push_back({"/testdata/pre", 999, 999, 0600});          // already tracked: left exactly as it is
        files.push_back({"/testdata/bulk/f5", 1, 1, 0600});          // a duplicate inside the batch
        uint64_t ev = fx.L->event_count();
        CHECK(fx.L->track_files(files) == 1203);
        CHECK(fx.L->event_count() == ev + 1203 && fx.L->fsck().empty());
        auto f = fx.L->get_file_by_path("/testdata/bulk/f1202");
        CHECK(f && f->size == 1302 && f->mtime == 2202 && f->mode == 0640 && f->state == FileState::LOCAL && f->generation == 1);
        CHECK(fx.L->get_file_by_path("/testdata/bulk/f5")->size == 105 && fx.L->get_file(pre)->size == 7 && fx.L->get_file(pre)->mtime == 7);
        CHECK(fx.L->list_files_under("/testdata/bulk/").size() == 1203 && fx.L->track_files(files) == 0 && fx.L->track_files({}) == 0);
        CHECK(fx.L->event_count() == ev + 1203);
    }

    {
        printf("== names are unique the way the volume sees them: case and Unicode form do not make a second file\n");
        Fixture fx;
        const std::string nfc = "/testdata/caf\xC3\xA9.txt", nfd = "/testdata/cafe\xCC\x81.txt";
        std::string a = fx.L->track_file("/testdata/Report.TXT", 10, 1, 0644);
        CHECK(fx.L->track_file("/testdata/report.txt", 99, 2, 0600) == a && fx.L->track_file("/TESTDATA/REPORT.TXT", 1, 1, 0644) == a);
        CHECK(fx.L->get_file_by_path("/testdata/rEpOrT.tXt")->file_id == a && fx.L->get_file(a)->path == "/testdata/Report.TXT" && fx.L->get_file(a)->size == 10);   // first spelling is kept
        std::string c = fx.L->track_file(nfc, 5, 1, 0644);
        CHECK(fx.L->track_file(nfd, 6, 1, 0644) == c && fx.L->get_file_by_path(nfd)->file_id == c && fx.L->get_file_by_path("/testdata/CAF\xC3\x89.txt")->file_id == c);
        CHECK(fx.L->fold_path("/A/\xC3\x84") == fx.L->fold_path("/a/A\xCC\x88") && fx.L->fold_path("/a") != fx.L->fold_path("/b") && fx.L->fold_path("/ss") != fx.L->fold_path("/\xC3\x9F"));
        // names that are not valid UTF-8 still fold (ASCII only) instead of colliding or crashing
        std::string bad1 = fx.L->track_file("/testdata/\xFF\xFE-Name", 1, 1, 0644);
        CHECK(fx.L->track_file("/TESTDATA/\xFF\xFE-NAME", 2, 2, 0644) == bad1 && fx.L->fold_path("/A\xFF") == "/a\xFF");
        // listing and prefixes
        fx.L->track_file("/testdata/Dir/One", 1, 1, 0644);
        fx.L->track_file("/testdata/dir/two", 1, 1, 0644);       // same directory, different spelling of its name
        CHECK(fx.L->list_files_under("/TESTDATA/DIR/").size() == 2 && fx.L->list_files_under("/testdata/dir/").size() == 2 && fx.L->list_files_under("/testdata/dirx/").empty());
        // batches: a duplicate inside the batch, and one against an existing row, in different case
        std::vector<Ledger::NewFile> nf = {{"/testdata/B/x", 1, 1, 0644}, {"/testdata/b/X", 2, 2, 0644}, {"/testdata/REPORT.txt", 3, 3, 0644}, {"/testdata/b/y", 4, 4, 0644}};
        CHECK(fx.L->track_files(nf) == 2 && fx.L->get_file_by_path("/testdata/b/x")->size == 1 && fx.L->get_file_by_path("/testdata/Report.TXT")->size == 10);
        // renames
        CHECK(fx.L->rename_file(a, "/testdata/REPORT.txt").ok && fx.L->get_file(a)->path == "/testdata/REPORT.txt");              // a case-only rename is a rename, not a collision
        std::string other = fx.L->track_file("/testdata/other", 1, 1, 0644);
        CHECK(!fx.L->rename_file(other, "/testdata/Report.txt").ok && fx.L->get_file(other)->path == "/testdata/other");          // another file's name, in other case: taken
        CHECK(!fx.L->rename_file(other, "/testdata/CAFE\xCC\x81.txt").ok);                                                            // ... also across Unicode forms
        CHECK(fx.L->rename_prefix("/testdata/DIR/", "/testdata/Folder/").ok && fx.L->get_file_by_path("/testdata/folder/one")->path == "/testdata/Folder/One" && fx.L->get_file_by_path("/testdata/folder/TWO")->path == "/testdata/Folder/two");
        CHECK(fx.L->rename_prefix("/testdata/Folder/", "/testdata/FOLDER/").ok && fx.L->get_file_by_path("/testdata/folder/one")->path == "/testdata/FOLDER/One");   // a case-only rename of a directory
        CHECK(!fx.L->rename_prefix("/testdata/FOLDER/", "/TESTDATA/folder/inner/").ok);                                             // into itself, whatever the spelling
        fx.L->track_file("/testdata/Dst/f", 1, 1, 0644);
        fx.L->track_file("/testdata/Src/F", 1, 1, 0644);
        CHECK(!fx.L->rename_prefix("/testdata/src/", "/testdata/DST/").ok && fx.L->get_file_by_path("/testdata/SRC/f")->path == "/testdata/Src/F");   // a taken name (differently spelled) refuses all of it
        std::string nfd_dir = fx.L->track_file("/testdata/cafe\xCC\x81/f1", 1, 1, 0644);
        CHECK(fx.L->rename_prefix("/testdata/caf\xC3\xA9/", "/testdata/cafes/").ok && fx.L->get_file(nfd_dir)->path == "/testdata/cafes/f1");   // the old directory was stored in another Unicode form (different length)
        // delete and undelete keep the name's identity
        std::string off = fx.replicated("/testdata/Off.bin", {"devA", "devB1"});
        Res d = fx.drop(off);
        CHECK(d.ok && fx.L->complete_drop(d.id).ok && fx.L->retire_file(off, "x").ok);
        CHECK(fx.L->track_file("/testdata/OFF.BIN", 1, 1, 0644) != off);                                                              // the name is free again after a delete
        CHECK(!fx.L->undelete_file(off).ok);                                                                                          // ... and a new file with that name (any case) blocks the undelete
        CHECK(fx.L->fsck().empty());
    }

    {
        printf("== a case-sensitive volume keeps both; the rule is fixed once files exist; it survives a reopen\n");
        std::string dir = tmpdir();
        {
            auto L = open_ledger(dir);
            CHECK(!L->case_sensitive() && L->set_case_sensitive(true).ok && L->case_sensitive());
            std::string x = L->track_file("/a/File", 1, 1, 0644), y = L->track_file("/a/file", 2, 2, 0644);
            CHECK(x != y && L->get_file_by_path("/a/File")->file_id == x && L->get_file_by_path("/a/file")->file_id == y && L->fold_path("/A/B") == "/A/B");
            CHECK(!L->set_case_sensitive(false).ok && L->case_sensitive() && L->set_case_sensitive(true).ok);
            CHECK(L->list_files_under("/a/").size() == 2 && L->list_files_under("/A/").empty() && L->fsck().empty());
        }
        {
            auto L = open_ledger(dir);
            CHECK(L->case_sensitive() && L->get_file_by_path("/a/File") && L->get_file_by_path("/a/file") && !L->get_file_by_path("/A/FILE"));
        }
        std::string d2 = tmpdir();
        { auto L = open_ledger(d2); L->track_file("/a", 1, 1, 0644); CHECK(!L->set_case_sensitive(true).ok && !L->case_sensitive()); }
        fs::remove_all(dir); fs::remove_all(d2);
    }

    {
        printf("== upgrading a version 1 ledger: keys are filled, a collision refuses the upgrade and changes nothing, tampering shows in fsck\n");
        std::string d = tmpdir();
        { auto L = open_ledger(d); L->track_file("/testdata/One", 1, 1, 0644); L->track_file("/testdata/two", 1, 1, 0644); }
        { sqlite3* db = raw_open(d); raw_exec(db, "PRAGMA user_version=1"); raw_exec(db, "UPDATE files SET pkey='old-'||file_id"); sqlite3_close(db); }
        { auto L = open_ledger(d); CHECK(L && L->get_file_by_path("/testdata/ONE") && L->get_file_by_path("/TESTDATA/Two") && L->fsck().empty()); }
        { sqlite3* db = raw_open(d); CHECK(raw_text(db, "PRAGMA user_version") == "2"); sqlite3_close(db); }
        // a v1 ledger whose two paths differ only in case cannot be upgraded; it is left exactly as it was
        std::string d2 = tmpdir();
        { auto L = open_ledger(d2); L->set_case_sensitive(true); L->track_file("/x/File", 1, 1, 0644); L->track_file("/x/file", 1, 1, 0644); }
        { sqlite3* db = raw_open(d2); raw_exec(db, "PRAGMA user_version=1"); raw_exec(db, "UPDATE files SET pkey='old-'||file_id"); raw_exec(db, "DELETE FROM meta WHERE key='case_sensitive'"); sqlite3_close(db); }
        std::string err;
        CHECK(!Ledger::open(d2, &err) && has(err, "upgrade") && has(err, "differ only in case"));
        { sqlite3* db = raw_open(d2); CHECK(raw_text(db, "PRAGMA user_version") == "1" && has(raw_text(db, "SELECT pkey FROM files ORDER BY path LIMIT 1"), "old-")); sqlite3_close(db); }
        // tampering with a key is caught
        { auto L = open_ledger(d); CHECK(L->fsck().empty()); }
        { sqlite3* db = raw_open(d); raw_exec(db, "UPDATE files SET pkey='zzz' WHERE path='/testdata/two'"); sqlite3_close(db); }
        { auto L = open_ledger(d); auto bad = L->fsck(); CHECK(bad.size() == 1 && has(bad[0], "path key does not match") && has(bad[0], "/testdata/two")); }
        fs::remove_all(d); fs::remove_all(d2);
    }

    {
        printf("== the backup statement is dated: only files unchanged since the backup may leave the Mac, and the statement expires\n");
        Fixture fx(true, /*backup=*/false);
        auto offer = [&](const std::string& id) { return fx.drop(id); };
        const int64_t DAY = 86400;
        g_time = 1'000'000;
        fx.consent = fx.L->create_consent("/outside/", 100 * DAY, "test");
        // two files exist before the owner records a backup at t0
        g_time = 1'000'000;
        std::string early = fx.replicated("/outside/early", {"devA", "devB1"});
        std::string edited = fx.replicated("/outside/edited", {"devA", "devB1"});
        std::string ren = fx.replicated("/outside/ren", {"devA", "devB1"});
        auto fr = [&](const std::string& id) { return *fx.L->get_file(id); };
        CHECK(!fx.L->backup_check(fr(early)).ok && fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::NotAcknowledged);
        EXPECT_REFUSED(fx, early, offer(early), "backup not acknowledged");
        g_time = 1'000'100;
        CHECK(fx.L->ack_backup().ok && fx.L->get_meta("backup_acked").value_or("") == "1" &&
              fx.L->get_meta("backup_acked_at").value_or("") == "1000100");
        // a statement without a date (an old ledger, or hand-edited) is refused
        fx.L->set_meta("backup_acked_at", "");
        CHECK(fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::NoDate);
        EXPECT_REFUSED(fx, early, offer(early), "has no date");
        fx.L->set_meta("backup_acked_at", "soon");
        CHECK(fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::NoDate);
        fx.L->set_meta("backup_acked_at", "-5");
        CHECK(fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::NoDate);
        fx.L->set_meta("backup_acked_at", "0");
        CHECK(fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::NoDate);
        fx.L->set_meta("backup_acked_at", "1000100x");  // a number followed by junk is not a date
        CHECK(fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::NoDate);
        fx.L->set_meta("backup_acked_at", "1000100 ");
        CHECK(fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::NoDate);
        fx.L->ack_backup();
        // a file created AFTER the backup is not in it
        g_time = 1'000'200;
        std::string late = fx.replicated("/outside/late", {"devA", "devB1"});
        auto bl = fx.L->backup_check(fr(late));
        CHECK(!bl.ok && bl.kind == Ledger::BackupKind::ChangedAfter && bl.acked_at == 1'000'100 && bl.last_change == 1'000'200);
        EXPECT_REFUSED(fx, late, offer(late), "created or changed after the backup");
        // a file edited after the backup is not either (even though it was replicated again since)
        g_time = 1'000'300;
        CHECK(fx.L->note_local_modified(edited, 7, 7).ok);
        {
            auto r = fx.L->begin_replication(edited, Fixture::chunks(7), 7, 7);
            int64_t v = std::atoll(r.id.c_str());
            for (const char* d : {"devA", "devB1"}) {
                fx.L->set_replica(edited, v, d, ReplicaState::PENDING);
                fx.L->set_replica(edited, v, d, ReplicaState::UPLOADED);
                fx.L->set_replica(edited, v, d, ReplicaState::COMMITTED, 9);
            }
            fx.L->finish_replication(edited, v);
            for (const char* d : {"devA", "devB1"}) fx.L->record_audit(edited, v, d, true, "ok");
        }
        CHECK(fx.L->backup_check(fr(edited)).kind == Ledger::BackupKind::ChangedAfter);
        EXPECT_REFUSED(fx, edited, offer(edited), "created or changed after the backup");
        // the file that did not change is fine; renaming and attribute changes do not count as content changes
        g_time = 1'000'350;
        CHECK(fx.L->rename_file(ren, "/outside/ren-renamed").ok && fx.L->note_attrs_changed(ren, 0600, std::nullopt).ok);
        CHECK(fx.L->backup_check(fr(ren)).ok && fx.L->backup_check(fr(ren)).last_change == 1'000'000);
        g_time = 1'000'300;
        CHECK(fx.L->backup_check(fr(early)).ok && fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::Ok &&
              fx.L->backup_check(fr(early)).last_change == 1'000'000);
        // recording a new backup after the changes covers them all
        g_time = 1'000'400;
        CHECK(fx.L->ack_backup().ok && fx.L->backup_check(fr(late)).ok && fx.L->backup_check(fr(edited)).ok);
        // a change in the very same second as the statement is NOT assumed covered
        std::string same = fx.replicated("/outside/same", {"devA", "devB1"});
        CHECK(fx.L->backup_check(fr(same)).kind == Ledger::BackupKind::ChangedAfter);
        g_time = 1'000'401;
        fx.L->ack_backup();
        CHECK(fx.L->backup_check(fr(same)).ok);
        // expiry: 30 days by default, adjustable, and exactly at the limit still counts
        g_time = 1'000'401 + 30 * DAY;
        CHECK(fx.L->backup_check(fr(early)).ok);
        g_time += 1;
        auto old = fx.L->backup_check(fr(early));
        CHECK(!old.ok && old.kind == Ledger::BackupKind::TooOld && has(old.why.c_str(), "older than 30 days"));
        EXPECT_REFUSED(fx, early, offer(early), "older than 30 days");
        fx.L->set_meta("backup_max_age_days", "60");
        CHECK(fx.L->backup_check(fr(early)).ok);
        fx.L->set_meta("backup_max_age_days", "7");
        CHECK(fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::TooOld &&
              has(fx.L->backup_check(fr(early)).why.c_str(), "older than 7 days"));
        fx.L->set_meta("backup_max_age_days", "0");  // nonsense is clamped to a day, not "never expires"
        CHECK(fx.L->backup_check(fr(early)).kind == Ledger::BackupKind::TooOld &&
              has(fx.L->backup_check(fr(early)).why.c_str(), "older than 1 days"));
        // the test area bypasses the whole gate, and says so
        fx.L->set_meta("test_prefix", "/outside/");
        CHECK(fx.L->backup_check(fr(late)).ok && fx.L->backup_check(fr(late)).kind == Ledger::BackupKind::TestArea);
        fx.L->set_meta("test_prefix", "/nowhere/");
        CHECK(!fx.L->backup_check(fr(early)).ok);
        // the same gate guards the purge of the quarantined bytes
        fx.L->set_meta("backup_max_age_days", "30");
        g_time = 1'000'500;
        fx.L->ack_backup();
        Res dd = fx.drop(early);
        CHECK(dd.ok && fx.L->complete_drop(dd.id).ok);
        g_time += 8 * DAY;
        fx.L->ack_backup();  // (a fresh statement: the old one is 8 days old, still valid, but the audits must be fresh too)
        for (const char* d : {"devA", "devB1"}) fx.L->record_audit(early, 1, d, true, "ok");
        CHECK(fx.L->begin_purge(dd.id, 7 * DAY, false, 2.0, 600).ok);
        // ... and a purge is refused when the statement has expired
        std::string e2 = fx.replicated("/outside/e2", {"devA", "devB1"});
        g_time += 1;
        fx.L->ack_backup();
        Res d2 = fx.drop(e2);
        CHECK(d2.ok && fx.L->complete_drop(d2.id).ok);
        g_time += 40 * DAY;
        Res p2 = fx.L->begin_purge(d2.id, 7 * DAY, false, 2.0, 600);
        CHECK(!p2.ok && has(p2.why.c_str(), "older than 30 days"));
        g_time = 1'000'000;
    }

    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
