// Tests of the advisory lock table (core/locks.*): every range case by hand, then thousands of random operations checked against a byte-by-byte
// model.
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <thread>

#include "../core/locks.hpp"

using namespace tierfs;

static int failures = 0;
static bool failfast() {
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

static LockRange R(uint64_t s, uint64_t l) { return {LockType::Read, s, l}; }
static LockRange W(uint64_t s, uint64_t l) { return {LockType::Write, s, l}; }
static LockRange U(uint64_t s, uint64_t l) { return {LockType::Unlock, s, l}; }
namespace tierfs {
static bool operator==(const LockInfo& a, const LockInfo& b) {
    return a.type == b.type && a.start == b.start && a.len == b.len && a.owner == b.owner;
}
}  // namespace tierfs
static LockInfo L(LockType t, uint64_t s, uint64_t l, uint64_t o) { return {t, s, l, o}; }
static const LockType RD = LockType::Read, WR = LockType::Write;

int main() {
    printf("== who blocks whom\n");
    {
        LockTable t;
        const std::string k = "f";
        CHECK(t.set(k, 1, R(0, 10)) && t.set(k, 2, R(5, 10)) && t.set(k, 3, R(0, 0)));  // readers share
        CHECK(!t.set(k, 4, W(8, 1)) && !t.set(k, 4, W(0, 0)));                          // a writer waits for them all
        CHECK(t.set(k, 4, W(100, 5)) == false);                                         // (owner 3 holds a read lock to the end of the file)
        t.release_owner(k, 3);
        CHECK(t.set(k, 4, W(100, 5)) && !t.set(k, 1, W(102, 1)) && !t.set(k, 1, R(104, 1)));  // a writer excludes readers and writers
        CHECK(t.set(k, 1, R(105, 3)) && t.set(k, 1, W(0, 5)));  // beyond owner 4's [100,105); and [0,5) touches nobody else's range
        CHECK(!t.set(k, 2, W(4, 2)) && !t.set(k, 2, W(5, 2)));  // byte 4 is owner 1's exclusive; bytes 5-9 are still owner 1's shared
        t.release_owner(k, 1);
        t.release_owner(k, 2);
        t.release_owner(k, 4);
        CHECK(!t.held(k) && t.count() == 0);
    }
    {  // touching ranges do not conflict; overlapping by one byte does
        LockTable t;
        CHECK(t.set("f", 1, W(0, 10)) && t.set("f", 2, W(10, 10)) && !t.set("f", 3, W(9, 2)) && !t.set("f", 3, W(19, 1)) && t.set("f", 3, W(20, 1)));
        // the end of file is a range too
        CHECK(t.set("f", 3, W(20, 0)));  // owner 3 already holds [20,21): it may widen its own lock to the end of the file
        CHECK(!t.set("f", 4, R(0, 0)));
        // different files never interact
        CHECK(t.set("g", 4, W(0, 0)) && t.set("h", 4, W(0, 0)));
    }
    printf("== an owner's own locks never conflict; setting replaces\n");
    {
        LockTable t;
        CHECK(t.set("f", 1, R(0, 10)) && t.set("f", 1, W(0, 10)));  // upgrade
        CHECK(t.list("f") == std::vector<LockInfo>({L(WR, 0, 10, 1)}));
        CHECK(t.set("f", 1, R(0, 10)) && t.list("f") == std::vector<LockInfo>({L(RD, 0, 10, 1)}));                                // downgrade
        CHECK(t.set("f", 1, W(4, 2)) && t.list("f") == std::vector<LockInfo>({L(RD, 0, 4, 1), L(WR, 4, 2, 1), L(RD, 6, 4, 1)}));  // split
        CHECK(t.set("f", 1, R(4, 2)) && t.list("f") == std::vector<LockInfo>({L(RD, 0, 10, 1)}));                                 // and merged again
        CHECK(t.set("f", 1, R(10, 5)) && t.list("f") == std::vector<LockInfo>({L(RD, 0, 15, 1)}));  // touching ranges of one kind become one
        CHECK(t.set("f", 1, R(20, 5)) && t.list("f") == std::vector<LockInfo>({L(RD, 0, 15, 1), L(RD, 20, 5, 1)}));  // a gap keeps them apart
        CHECK(t.set("f", 1, R(15, 5)) && t.list("f") == std::vector<LockInfo>({L(RD, 0, 25, 1)}));                   // filling the gap joins them
        CHECK(t.set("f", 1, W(0, 0)) && t.list("f") == std::vector<LockInfo>({L(WR, 0, 0, 1)}));  // to the end of the file swallows everything
        CHECK(t.set("f", 1, U(10, 5)) && t.list("f") == std::vector<LockInfo>({L(WR, 0, 10, 1), L(WR, 15, 0, 1)}));  // a hole in it
        CHECK(t.set("f", 1, U(0, 0)) && t.list("f").empty() && !t.held("f"));
        CHECK(t.set("f", 1, U(0, 0)));  // unlocking nothing is fine
    }
    printf("== unlocking\n");
    {
        LockTable t;
        t.set("f", 1, W(0, 10));
        t.set("f", 2, R(20, 5));
        CHECK(t.set("f", 2, U(0, 100)) && t.list("f") == std::vector<LockInfo>({L(WR, 0, 10, 1)}));  // owner 2's unlock touches only owner 2's locks
        CHECK(t.set("f", 3, U(0, 0)) && t.list("f").size() == 1);                                    // and an owner with nothing unlocks nothing
        CHECK(t.set("f", 1, U(0, 3)) && t.list("f") == std::vector<LockInfo>({L(WR, 3, 7, 1)}));
        CHECK(t.set("f", 1, U(7, 3)) && t.list("f") == std::vector<LockInfo>({L(WR, 3, 4, 1)}));
        CHECK(t.set("f", 1, U(4, 2)) && t.list("f") == std::vector<LockInfo>({L(WR, 3, 1, 1), L(WR, 6, 1, 1)}));
        CHECK(t.set("f", 2, W(4, 2)) && !t.set("f", 2, W(3, 2)));  // the freed middle can be taken; the neighbour's bytes cannot
    }
    printf("== a refused lock changes nothing\n");
    {
        LockTable t;
        t.set("f", 1, R(0, 10));
        t.set("f", 2, W(20, 10));
        auto before = t.list("f");
        CHECK(!t.set("f", 2, W(5, 20)) && t.list("f") == before);  // owner 1 reads [0,10)
        CHECK(!t.set("f", 1, R(25, 1)) && t.list("f") == before);  // owner 2 writes [20,30)
        CHECK(!t.set("f", 1, W(0, 0)) && t.list("f") == before);
    }
    printf("== F_GETLK: the first lock that is in the way\n");
    {
        LockTable t;
        t.set("f", 1, W(100, 10));
        t.set("f", 2, W(50, 10));
        t.set("f", 3, R(0, 5));
        LockInfo b;
        CHECK(t.test("f", 9, W(0, 1000), &b) && b.owner == 3 && b.type == RD && b.start == 0 && b.len == 5);  // the first by position
        CHECK(t.test("f", 9, R(0, 1000), &b) && b.owner == 2 && b.type == WR && b.start == 50 &&
              b.len == 10);  // a reader is not blocked by a read lock
        CHECK(t.test("f", 9, R(105, 1), &b) && b.owner == 1 && b.start == 100);
        CHECK(!t.test("f", 9, R(60, 40), nullptr) && !t.test("f", 9, W(5, 45), nullptr));    // gaps are free
        CHECK(!t.test("f", 1, W(100, 10), nullptr) && !t.test("f", 2, W(50, 10), nullptr));  // your own locks are not in your way
        CHECK(!t.test("f", 9, U(0, 0), nullptr) && !t.test("nothing", 9, W(0, 0), nullptr));
        CHECK(t.test("f", 9, W(0, 0), &b) && b.owner == 3);  // to the end of the file
        t.set("f", 4, W(200, 0));
        CHECK(t.test("f", 9, R(1000000, 1), &b) && b.owner == 4 && b.len == 0 && b.start == 200);  // a lock to the end reports length 0
    }
    {  // the first by position wins even when its owner has the smaller number
        LockTable t;
        t.set("f", 1, W(0, 5));
        t.set("f", 2, W(50, 5));
        t.set("f", 3, W(20, 5));
        LockInfo b;
        CHECK(t.test("f", 9, W(0, 100), &b) && b.owner == 1 && b.start == 0);
        CHECK(t.test("f", 9, W(10, 100), &b) && b.owner == 3 && b.start == 20);
        CHECK(t.test("f", 9, W(30, 100), &b) && b.owner == 2 && b.start == 50);
    }
    printf("== closing the file releases the owner's locks\n");
    {
        LockTable t;
        t.set("f", 1, W(0, 10));
        t.set("f", 1, W(20, 10));
        t.set("f", 2, R(40, 10));
        t.set("g", 1, W(0, 10));
        t.release_owner("f", 1);
        CHECK(t.list("f") == std::vector<LockInfo>({L(RD, 40, 10, 2)}) && t.list("g").size() == 1);  // only on that file
        t.release_owner("nothing", 1);
        t.release_owner("f", 7);
        CHECK(t.list("f").size() == 1 && t.set("f", 3, W(0, 10)));
        t.release_owner("f", 2);
        t.release_owner("f", 3);
        CHECK(!t.held("f") && t.held("g"));
    }
    printf("== extreme offsets\n");
    {
        LockTable t;
        const uint64_t MAX = ~0ull;
        CHECK(t.set("f", 1, W(MAX - 5, 100)));  // would pass the end: it runs to the end
        CHECK(!t.set("f", 2, W(MAX - 1, 1)) && t.set("f", 2, W(MAX - 10, 4)) == true);
        CHECK(t.list("f").size() == 2 && t.list("f")[0].start == MAX - 5 && t.list("f")[0].len == 0 && t.list("f")[1].len == 4);
        CHECK(t.set("f", 3, W(MAX, 0)) && t.list("f").size() == 2);  // an empty range holds nothing
        CHECK(t.set("f", 1, U(0, 0)) && t.set("f", 2, U(0, 0)));
    }
    printf("== flock\n");
    {
        LockTable t;
        CHECK(t.flock_try("f", 1, RD) && t.flock_try("f", 2, RD) && !t.flock_try("f", 3, WR) && t.flock_try("f", 3, RD));
        CHECK(!t.flock_try("f", 1, WR));  // two other readers
        t.flock_release("f", 2);
        t.flock_release("f", 3);
        CHECK(t.flock_try("f", 1, WR));  // owner 1 alone: converts to exclusive
        CHECK(!t.flock_try("f", 2, RD) && !t.flock_try("f", 2, WR));
        CHECK(t.flock_try("f", 1, RD) && t.flock_try("f", 2, RD));                                // downgrade lets a reader in
        CHECK(t.flock_try("f", 2, LockType::Unlock) && t.held("f") && !t.flock_try("f", 3, WR));  // owner 1's shared lock is still there
        CHECK(t.flock_try("f", 1, LockType::Unlock) && !t.held("f"));
        CHECK(t.flock_try("f", 9, LockType::Unlock));  // unlocking what is not locked is fine
        CHECK(t.flock_try("f", 1, WR) && t.flock_try("g", 2, WR) && t.count() == 2);
        t.flock_release("f", 1);
        t.flock_release("g", 2);
        CHECK(t.count() == 0);
        // byte-range locks and flocks do not see each other
        CHECK(t.set("f", 1, W(0, 0)) && t.flock_try("f", 2, WR) && t.count() == 2 && t.held("f"));
        t.release_owner("f", 1);
        CHECK(t.held("f"));  // the flock is still there
        t.flock_release("f", 2);
        CHECK(!t.held("f"));
    }
    printf("== random operations against a byte-by-byte model\n");
    {
        std::mt19937_64 rng(12345);
        for (int round = 0; round < 40; round++) {
            LockTable t;
            constexpr int N = 24;      // a file of 24 bytes, plus "to the end" ranges that reach byte N and beyond
            int model[4][N + 2] = {};  // owner -> byte -> 0 none, 1 read, 2 write (byte N stands for "everything from N on")
            for (int step = 0; step < 300; step++) {
                uint64_t owner = rng() % 3 + 1;
                int kind = static_cast<int>(rng() % 6);  // 0,1: read, 2,3: write, 4: unlock, 5: release the owner
                uint64_t start = rng() % N;
                uint64_t len = 1 + rng() % std::min<uint64_t>(8, N - start);  // bounded ranges end inside the file...
                if (rng() % 7 == 0) len = 0;                                  // ...or run to its end (cell N of the model)
                if (kind == 5) {
                    t.release_owner("k", owner);
                    for (int b = 0; b <= N; b++) model[owner][b] = 0;
                } else {
                    LockType type = kind < 2 ? RD : kind < 4 ? WR : LockType::Unlock;
                    uint64_t end = len == 0 ? N + 1 : start + len;
                    int want = type == RD ? 1 : type == WR ? 2 : 0;
                    bool conflict = false;
                    for (uint64_t b = start; b < end && want; b++)
                        for (int o = 1; o <= 3; o++)
                            if (o != static_cast<int>(owner) && model[o][b] && (model[o][b] == 2 || want == 2)) conflict = true;
                    bool ok = t.set("k", owner, {type, start, len});
                    CHECK(ok == !conflict);
                    if (ok)
                        for (uint64_t b = start; b < end; b++) model[owner][b] = want;
                }
                // the table must equal the model: per owner, maximal runs of one kind
                std::vector<LockInfo> expect;
                for (uint64_t o = 1; o <= 3; o++) {
                    int b = 0;
                    while (b <= N) {
                        if (!model[o][b]) {
                            b++;
                            continue;
                        }
                        int e = b;
                        while (e + 1 <= N && model[o][e + 1] == model[o][b]) e++;
                        bool to_end = e == N;
                        expect.push_back(L(model[o][b] == 1 ? RD : WR, static_cast<uint64_t>(b), to_end ? 0 : static_cast<uint64_t>(e - b + 1), o));
                        b = e + 1;
                    }
                }
                auto got = t.list("k");
                bool same = got.size() == expect.size();
                for (size_t i = 0; same && i < got.size(); i++) same = got[i] == expect[i];
                if (!same) {
                    printf("FAIL  model mismatch (round %d step %d)\n", round, step);
                    failures++;
                    if (failfast()) {
                        fflush(stdout);
                        _exit(1);
                    }
                }
            }
        }
        CHECK(true);
    }
    printf("== threads\n");
    {
        LockTable t;
        std::atomic<int> won{0};
        std::vector<std::thread> ts;
        for (int i = 0; i < 8; i++)
            ts.emplace_back([&, i] {
                for (int k = 0; k < 500; k++) {
                    if (t.set("hot", static_cast<uint64_t>(i + 1), W(0, 0))) {
                        won++;
                        t.release_owner("hot", static_cast<uint64_t>(i + 1));
                    }
                    LockInfo b;
                    t.test("hot", static_cast<uint64_t>(i + 1), R(0, 1), &b);
                }
            });
        for (auto& th : ts) th.join();
        CHECK(won > 0 && !t.held("hot"));  // never two writers at once is checked by the single-key invariant below
        LockTable u;
        std::atomic<int> inside{0}, max_inside{0};
        std::vector<std::thread> vs;
        for (int i = 0; i < 6; i++)
            vs.emplace_back([&, i] {
                for (int k = 0; k < 300; k++) {
                    if (u.flock_try("x", static_cast<uint64_t>(i + 1), WR)) {
                        int n = ++inside;
                        int m = max_inside.load();
                        while (n > m && !max_inside.compare_exchange_weak(m, n)) {
                        }
                        --inside;
                        u.flock_release("x", static_cast<uint64_t>(i + 1));
                    }
                }
            });
        for (auto& th : vs) th.join();
        CHECK(max_inside == 1 && !u.held("x"));
    }
    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
