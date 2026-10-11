// Unit tests for MetaStore. Run with `make test-unit`.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <unistd.h>

#include "../core/metastore.hpp"

using tierfs::MetaStore;

static int failures = 0;
#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) { printf("FAIL  line %d: %s\n", __LINE__, #cond); failures++; } \
        else printf("PASS  %s\n", #cond);                                \
    } while (0)

static tc_attr file(uint64_t size, int64_t mtime = 100) { return {0, size, mtime, 0644}; }
static tc_attr dir() { return {1, 0, 50, 0755}; }

static std::string tmpdb() {
    char t[] = "/tmp/tierfs-metatest-XXXXXX";
    int fd = mkstemp(t);
    close(fd);
    return t;
}

int main() {
    {  // basic attr round trip
        MetaStore m(":memory:");
        CHECK(m.ok());
        tc_attr out;
        CHECK(!m.get_attr("/a", out));
        m.put_attr("/a", file(42, 777));
        CHECK(m.get_attr("/a", out) && out.size == 42 && out.mtime == 777 && !out.is_dir);
        m.put_attr("/a", file(43, 778));  // overwrite
        CHECK(m.get_attr("/a", out) && out.size == 43);
    }
    {  // listings: store, read back, replace, prune
        MetaStore m(":memory:");
        MetaStore::DirList got;
        CHECK(!m.get_dir("/d", got));  // never listed
        m.put_dir("/d", {{"x", file(1)}, {"sub", dir()}, {"y", file(2)}});
        CHECK(m.get_dir("/d", got) && got.size() == 3);
        CHECK(got[0].first == "sub" && got[1].first == "x");  // ordered by name
        tc_attr a;
        CHECK(m.get_attr("/d/x", a) && a.size == 1);  // child attrs usable by stat

        m.put_dir("/d/sub", {{"deep.txt", file(9)}});
        CHECK(m.get_attr("/d/sub/deep.txt", a));

        // 'sub' vanishes from the parent: its whole subtree must go too.
        m.put_dir("/d", {{"x", file(5)}, {"y", file(2)}});
        CHECK(m.get_dir("/d", got) && got.size() == 2);
        CHECK(m.get_attr("/d/x", a) && a.size == 5);  // updated
        CHECK(!m.get_attr("/d/sub", a));
        CHECK(!m.get_attr("/d/sub/deep.txt", a));
        CHECK(!m.get_dir("/d/sub", got));
    }
    {  // forget: subtree + parent listing entry; siblings with similar names survive
        MetaStore m(":memory:");
        m.put_dir("/", {{"a", dir()}, {"a0", dir()}, {"a2", dir()}, {"a b", file(1)}});
        m.put_dir("/a0", {{"h", file(1)}});  // "0" sorts right after "/": the range-boundary case
        m.put_dir("/a", {{"f", file(1)}});
        m.put_dir("/a2", {{"g", file(1)}});
        m.forget("/a");
        tc_attr t;
        MetaStore::DirList l;
        CHECK(!m.get_attr("/a", t) && !m.get_attr("/a/f", t));
        CHECK(m.get_attr("/a2", t) && m.get_attr("/a2/g", t));  // prefix-but-not-child survives
        CHECK(m.get_attr("/a0", t) && m.get_attr("/a0/h", t));
        CHECK(m.get_attr("/a b", t));
        CHECK(m.get_dir("/", l) && l.size() == 3);  // 'a' removed from root listing
    }
    {  // names containing SQL LIKE wildcards and quotes behave literally
        MetaStore m(":memory:");
        m.put_dir("/", {{"100%", dir()}, {"a_b", dir()}, {"it's", file(3)}});
        m.put_dir("/100%", {{"x", file(1)}});
        m.put_dir("/a_b", {{"y", file(1)}});
        m.forget("/100%");
        tc_attr t;
        CHECK(!m.get_attr("/100%/x", t));
        CHECK(m.get_attr("/a_b/y", t));
        CHECK(m.get_attr("/it's", t) && t.size == 3);
    }
    {  // persistence across reopen + last_access throttle
        std::string db = tmpdb();
        {
            MetaStore m(db);
            m.put_dir("/", {{"f", file(7)}});
            m.touch("/f", 1000);
        }
        MetaStore m(db);
        tc_attr a;
        MetaStore::DirList l;
        CHECK(!m.recovered());
        CHECK(m.get_dir("/", l) && l.size() == 1 && l[0].second.size == 7);
        CHECK(m.last_access("/f") == 1000);
        m.touch("/f", 1030);  // within 60 s: ignored
        CHECK(m.last_access("/f") == 1000);
        m.touch("/f", 1100);  // later: recorded
        CHECK(m.last_access("/f") == 1100);
        CHECK(m.last_access("/missing") == 0);
        m.put_attr("/f", file(8));  // refresh must keep access history
        CHECK(m.last_access("/f") == 1100);
        CHECK(m.get_attr("/f", a) && a.size == 8);
        for (const char* s : {"", "-wal", "-shm"}) unlink((db + s).c_str());
    }
    {  // corrupt file is discarded, not fatal
        std::string db = tmpdb();
        { std::ofstream f(db, std::ios::binary); f << std::string(5000, 'x'); }
        MetaStore m(db);
        CHECK(m.ok() && m.recovered());
        tc_attr a;
        CHECK(!m.get_attr("/anything", a));
        m.put_attr("/a", file(1));
        CHECK(m.get_attr("/a", a));
        for (const char* s : {"", "-wal", "-shm"}) unlink((db + s).c_str());
    }
    {  // wrong schema version is discarded
        std::string db = tmpdb();
        { MetaStore m(db); m.put_attr("/a", file(1)); }
        { // bump the on-disk version behind the store's back
            std::string cmd = "sqlite3 '" + db + "' 'PRAGMA user_version=99'";
            CHECK(system(cmd.c_str()) == 0);
        }
        MetaStore m(db);
        tc_attr a;
        CHECK(m.ok() && m.recovered() && !m.get_attr("/a", a));
        for (const char* s : {"", "-wal", "-shm"}) unlink((db + s).c_str());
    }
    {  // unusable location: runs without a cache instead of crashing
        MetaStore m("/nonexistent-dir/x/meta.db");
        tc_attr a;
        CHECK(!m.ok());
        m.put_attr("/a", file(1));
        CHECK(!m.get_attr("/a", a));
    }
    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
