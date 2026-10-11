// Unit tests for ChunkCache. Run with `make test-unit`.
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "../core/chunkcache.hpp"

using namespace tierfs;
namespace fs = std::filesystem;

static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) { printf("FAIL  line %d: %s\n", __LINE__, #cond); failures++; } \
        else printf("PASS  %s\n", #cond);                                          \
    } while (0)

static std::string tmpdir() {
    char t[] = "/tmp/tierfs-chunktest-XXXXXX";
    return mkdtemp(t);
}
static std::vector<uint8_t> blob(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(seed + i * 31);
    return v;
}
static ChunkKey key(const std::string& p, uint32_t idx, int64_t mtime = 100, uint64_t size = 5000000) {
    return {p, size, mtime, idx};
}
static std::vector<fs::path> chunk_files(const std::string& dir) {
    std::vector<fs::path> out;
    for (auto& e : fs::recursive_directory_iterator(dir + "/chunks"))
        if (e.is_regular_file()) out.push_back(e.path());
    return out;
}

int main() {
    {  // round trip, version isolation, accounting
        std::string d = tmpdir();
        ChunkCache c(d, 100u << 20);
        CHECK(c.ok());
        auto a = blob(CHUNK_SIZE, 1), out = std::vector<uint8_t>();
        CHECK(!c.get(key("/f", 0), out));
        c.put(key("/f", 0), a.data(), a.size());
        CHECK(c.get(key("/f", 0), out) && out == a);
        CHECK(!c.get(key("/f", 1), out));              // other chunk index
        CHECK(!c.get(key("/f", 0, 101), out));         // file mtime changed -> different version
        CHECK(!c.get(key("/f", 0, 100, 5000001), out)); // file size changed
        CHECK(!c.get(key("/g", 0), out));              // other path
        CHECK(c.bytes_used() == CHUNK_SIZE);
        c.put(key("/f", 0), a.data(), a.size());       // overwrite same key: no double count
        CHECK(c.bytes_used() == CHUNK_SIZE);
        auto tail = blob(1234, 9);                      // short last chunk
        c.put(key("/f", 4), tail.data(), tail.size());
        CHECK(c.get(key("/f", 4), out) && out == tail);
        CHECK(c.bytes_used() == CHUNK_SIZE + 1234);
        CHECK(c.has(key("/f", 4)) && !c.has(key("/f", 3)));
        fs::remove_all(d);
    }
    {  // corruption: flipped byte, truncated file, deleted file
        std::string d = tmpdir();
        ChunkCache c(d, 100u << 20);
        auto a = blob(100000, 3), out = std::vector<uint8_t>();
        for (uint32_t i = 0; i < 3; i++) c.put(key("/f", i), a.data(), a.size());
        auto files = chunk_files(d);
        CHECK(files.size() == 3);
        {   // flip one bit in file 0
            int fd = ::open(files[0].c_str(), O_RDWR);
            uint8_t b; pread(fd, &b, 1, 5000); b ^= 1; pwrite(fd, &b, 1, 5000); close(fd);
        }
        truncate(files[1].c_str(), 99999);
        unlink(files[2].c_str());
        int hits = 0;
        for (uint32_t i = 0; i < 3; i++) hits += c.get(key("/f", i), out);
        CHECK(hits == 0);                       // never returns damaged bytes
        CHECK(c.stats().corrupt == 2);          // flipped + truncated counted; vanished file is not "corruption"
        CHECK(c.bytes_used() == 0);             // entries dropped, accounting repaired
        CHECK(!c.has(key("/f", 0)) && !c.has(key("/f", 1)) && !c.has(key("/f", 2)));
        c.put(key("/f", 0), a.data(), a.size());  // and it heals on refetch
        CHECK(c.get(key("/f", 0), out) && out == a);
        fs::remove_all(d);
    }
    {  // LRU eviction under a budget; recency refreshed by reads
        std::string d = tmpdir();
        ChunkCache c(d, 5 * 100000);
        auto a = blob(100000, 5), out = std::vector<uint8_t>();
        for (uint32_t i = 0; i < 5; i++) c.put(key("/f", i), a.data(), a.size());
        CHECK(c.bytes_used() == 500000);
        c.get(key("/f", 0), out);               // chunk 0 becomes most recently used
        c.put(key("/f", 5), a.data(), a.size()); // over budget: evict oldest (chunk 1...)
        CHECK(c.bytes_used() <= 500000);
        CHECK(c.get(key("/f", 0), out));        // recently used survived
        CHECK(!c.has(key("/f", 1)));            // least recently used went first
        CHECK(c.has(key("/f", 5)));             // newest survived
        CHECK(c.stats().evicted >= 1);
        CHECK(chunk_files(d).size() * 100000 == c.bytes_used());  // files match accounting
        fs::remove_all(d);
    }
    {  // pinned paths are never evicted, even over budget
        std::string d = tmpdir();
        ChunkCache c(d, 3 * 100000);
        c.set_pin_check([](const std::string& p) { return p == "/open"; });
        auto a = blob(100000, 7), out = std::vector<uint8_t>();
        for (uint32_t i = 0; i < 4; i++) c.put(key("/open", i), a.data(), a.size());
        for (uint32_t i = 0; i < 4; i++) c.put(key("/other", i), a.data(), a.size());
        for (uint32_t i = 0; i < 4; i++) CHECK(c.has(key("/open", i)));
        CHECK(c.bytes_used() >= 400000);        // allowed to exceed budget when pinned
        int other = 0;
        for (uint32_t i = 0; i < 4; i++) other += c.has(key("/other", i));
        CHECK(other < 4);                       // unpinned data was evicted instead
        fs::remove_all(d);
    }
    {  // invalidation, including the "0 sorts after /" boundary
        std::string d = tmpdir();
        ChunkCache c(d, 100u << 20);
        auto a = blob(1000, 2), out = std::vector<uint8_t>();
        for (const char* p : {"/dir/f", "/dir/sub/g", "/dir0/h", "/dir2/i", "/dirx"})
            c.put(key(p, 0), a.data(), a.size());
        c.put(key("/dir/f", 1), a.data(), a.size());
        c.invalidate_path("/dir/f");
        CHECK(!c.has(key("/dir/f", 0)) && !c.has(key("/dir/f", 1)));
        CHECK(c.has(key("/dir/sub/g", 0)));
        c.invalidate_tree("/dir");
        CHECK(!c.has(key("/dir/sub/g", 0)));
        CHECK(c.has(key("/dir0/h", 0)));        // sibling that sorts right after "/dir/"
        CHECK(c.has(key("/dir2/i", 0)) && c.has(key("/dirx", 0)));
        CHECK(c.bytes_used() == 3000);
        fs::remove_all(d);
    }
    {  // persistence + crash leftovers repaired at startup
        std::string d = tmpdir();
        auto a = blob(50000, 4), out = std::vector<uint8_t>();
        {
            ChunkCache c(d, 100u << 20);
            c.put(key("/keep", 0), a.data(), a.size());
            c.put(key("/ghost", 0), a.data(), a.size());
        }
        auto files = chunk_files(d);
        std::string ghost_file;
        for (auto& f : files) { std::string cmp; (void)cmp; ghost_file = f.string(); }
        { std::ofstream t(d + "/chunks/.tmp.123.0"); t << "half written"; }       // crash mid-write
        { fs::create_directories(d + "/chunks/zz"); std::ofstream o(d + "/chunks/zz/" + std::string(64, 'a') + ".chk"); o << "orphan"; }  // renamed, row never committed
        ChunkCache c(d, 100u << 20);
        CHECK(c.ok());
        CHECK(c.get(key("/keep", 0), out) && out == a);   // survived restart
        CHECK(c.bytes_used() == 100000);
        CHECK(!fs::exists(d + "/chunks/.tmp.123.0"));      // temp file removed
        CHECK(!fs::exists(d + "/chunks/zz/" + std::string(64, 'a') + ".chk")); // orphan removed
        // row whose file vanished while we were down
        auto fl = chunk_files(d);
        CHECK(fl.size() == 2);
        unlink(fl[0].c_str());
        { ChunkCache c2(d, 100u << 20); CHECK(c2.bytes_used() == 50000); }
        fs::remove_all(d);
    }
    {  // garbage index is wiped and rebuilt; unusable directory disables the cache
        std::string d = tmpdir();
        { fs::create_directories(d); std::ofstream f(d + "/chunks.db", std::ios::binary); f << std::string(9000, 'x'); }
        ChunkCache c(d, 1u << 20);
        auto a = blob(1000, 1), out = std::vector<uint8_t>();
        CHECK(c.ok());
        c.put(key("/f", 0), a.data(), a.size());
        CHECK(c.get(key("/f", 0), out) && out == a);
        fs::remove_all(d);
        ChunkCache bad("/nonexistent-root-dir/x/y", 1u << 20);
        CHECK(!bad.ok());
        bad.put(key("/f", 0), a.data(), a.size());     // no crash, no effect
        CHECK(!bad.get(key("/f", 0), out));
    }
    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
