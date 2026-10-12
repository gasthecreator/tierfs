// Tests of the key-source resolver: where the master key comes from ("keychain", "dir:PATH", or a key file).
// The real Keychain is exercised only with TIERFS_TEST_KEYCHAIN=1 (one throwaway item, deleted again).
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "../core/keysource.hpp"

using namespace tierfs;
namespace fs = std::filesystem;

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

static bool has(const std::string& s, const std::string& n) { return s.find(n) != std::string::npos; }
static std::string tmpdir() {
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-keysrctest-XXXXXX";
    std::vector<char> b(t.begin(), t.end());
    b.push_back(0);
    return mkdtemp(b.data());
}
static void write_file(const std::string& p, const std::string& s) { std::ofstream(p, std::ios::binary) << s; }

int main() {
    std::string root = tmpdir();
    crypto::SecretKey key = crypto::SecretKey::random();
    std::string hex = crypto::to_hex(key.data(), 32);
    std::string err;

    printf("== which sources have a store\n");
    CHECK(keystore_for("keychain", &err) != nullptr);
    CHECK(keystore_for("dir:" + root + "/s", &err) != nullptr && err.empty());
    err.clear();
    CHECK(keystore_for("dir:", &err) == nullptr && has(err, "needs a path"));
    err.clear();
    CHECK(keystore_for(root + "/keyfile", &err) == nullptr && err.empty());  // a plain path is a key file: no store, and not an error
    CHECK(keystore_for("dir", &err) == nullptr && keystore_for("keychains", &err) == nullptr && keystore_for("DIR:/x", &err) == nullptr);

    printf("== key files\n");
    write_file(root + "/k1", hex + "\n");
    auto k = load_master_key(root + "/k1", "ignored-volume", &err);
    CHECK(k && *k == key);
    write_file(root + "/k2", "  " + hex + "  \r\n");
    k = load_master_key(root + "/k2", "v", &err);
    CHECK(k && *k == key);  // spaces and CRLF are forgiven
    write_file(root + "/k3", hex);
    k = load_master_key(root + "/k3", "v", &err);
    CHECK(k && *k == key);  // no trailing newline is fine
    write_file(root + "/short", hex.substr(0, 62) + "\n");
    err.clear();
    CHECK(!load_master_key(root + "/short", "v", &err) && has(err, "64 hex"));
    write_file(root + "/long", hex + "00\n");
    err.clear();
    CHECK(!load_master_key(root + "/long", "v", &err) && has(err, "64 hex"));
    write_file(root + "/junk", std::string(64, 'z') + "\n");
    err.clear();
    CHECK(!load_master_key(root + "/junk", "v", &err) && has(err, "64 hex"));
    write_file(root + "/empty", "");
    err.clear();
    CHECK(!load_master_key(root + "/empty", "v", &err) && has(err, "cannot read the key file"));
    err.clear();
    CHECK(!load_master_key(root + "/missing", "v", &err) && has(err, "cannot read the key file") && has(err, "/missing"));
    err.clear();
    CHECK(!load_master_key("", "v", &err) && has(err, "no key source"));

    printf("== the development store\n");
    std::string ks_dir = root + "/ks";
    auto ks = keystore_for("dir:" + ks_dir, &err);
    CHECK(ks && ks->store("volume-one", key));
    k = load_master_key("dir:" + ks_dir, "volume-one", &err);
    CHECK(k && *k == key);
    err.clear();
    CHECK(!load_master_key("dir:" + ks_dir, "volume-two", &err) && has(err, "no key for volume volume-two") && has(err, "dir:" + ks_dir));
    err.clear();
    CHECK(!load_master_key("dir:", "volume-one", &err) && has(err, "needs a path"));
    crypto::SecretKey other = crypto::SecretKey::random();
    CHECK(ks->store("volume-two", other));
    k = load_master_key("dir:" + ks_dir, "volume-two", &err);
    CHECK(k && *k == other && !(*k == key));  // each volume gets its own key
    CHECK(!ks->store("volume-one", other));   // a stored key is never silently replaced
    k = load_master_key("dir:" + ks_dir, "volume-one", &err);
    CHECK(k && *k == key);

    printf("== the Keychain\n");
    if (getenv("TIERFS_TEST_KEYCHAIN")) {
        auto kc = keystore_for("keychain", &err);
        std::string vol = "tierfs-keysrc-" + crypto::to_hex(crypto::random_bytes(6).data(), 6);
        CHECK(kc && kc->store(vol, key));
        k = load_master_key("keychain", vol, &err);
        CHECK(k && *k == key);
        err.clear();
        CHECK(!load_master_key("keychain", vol + "-other", &err) && has(err, "no key for volume"));
        CHECK(kc->erase(vol));
    } else {
        printf("(Keychain checks skipped; set TIERFS_TEST_KEYCHAIN=1)\n");
    }

    fs::remove_all(root);
    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
