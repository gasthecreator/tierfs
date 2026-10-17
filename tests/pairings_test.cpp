// Tests of the pairing store (core/pairings.*): several secrets per device, each revocable, with its own right to delete; and files that are not acceptable
// are reported and never trusted.
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "../core/pairings.hpp"
#include "../core/securechannel.hpp"

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

static std::string tmpdir() {
    std::string t = std::string(getenv("TIERFS_TEST_TMP") ? getenv("TIERFS_TEST_TMP") : "/tmp") + "/tierfs-pairtest-XXXXXX";
    std::vector<char> b(t.begin(), t.end());
    b.push_back(0);
    return mkdtemp(b.data());
}
static bool has(const std::string& s, const std::string& n) { return s.find(n) != std::string::npos; }
static std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
static void spit(const std::string& p, const std::string& t, mode_t m = 0600) {
    std::ofstream(p, std::ios::trunc | std::ios::binary) << t;
    chmod(p.c_str(), m);
}
static bool any_problem(const std::vector<std::string>& v, const std::string& needle) {
    for (auto& s : v)
        if (has(s, needle)) return true;
    return false;
}

int main() {
    std::string root = tmpdir();
    std::string err;

    printf("== labels\n");
    CHECK(pairing::valid_label("Gideon's MacBook") && pairing::valid_label("x") && pairing::valid_label(std::string(40, 'x')));
    CHECK(!pairing::valid_label("") && !pairing::valid_label(std::string(41, 'x')) && !pairing::valid_label("a\nb") && !pairing::valid_label("a\x01") &&
          !pairing::valid_label(std::string("a\x7f")) && !pairing::valid_label(std::string("a\0b", 3)));
    CHECK(pairing::valid_label("naïve 日本 😀") && pairing::valid_label("a=b"));

    printf("== adding, finding, listing\n");
    {
        std::string s = root + "/a";
        CHECK(pairing::list(s).empty());
        auto e1 = pairing::add(s, "Alpha", true, &err);
        auto e2 = pairing::add(s, "Beta", false, &err);
        CHECK(e1 && e2 && e1->key_id != e2->key_id && e1->secret != e2->secret && e1->secret.size() == 32);
        CHECK(e1->allow_delete && !e2->allow_delete && e1->label == "Alpha" && e2->label == "Beta" && !e1->primary && e1->created > 1700000000);
        CHECK(e1->key_id == chan::key_id_hex(e1->secret) && e1->key_id.size() == 16);
        struct stat st;
        CHECK(stat((s + "/pairings/" + e1->key_id + ".key").c_str(), &st) == 0 && (st.st_mode & 07777) == 0600);
        CHECK(stat((s + "/pairings").c_str(), &st) == 0 && (st.st_mode & 07777) == 0700);
        CHECK(slurp(e1->file) == crypto::to_hex(e1->secret.data(), 32) + "\nlabel=Alpha\ndelete=1\ncreated=" + std::to_string(e1->created) + "\n");
        std::vector<std::string> problems;
        auto all = pairing::list(s, &problems);
        CHECK(all.size() == 2 && problems.empty());
        auto f1 = pairing::find(s, chan::key_id(e1->secret));
        CHECK(f1 && f1->secret == e1->secret && f1->allow_delete && f1->label == "Alpha");
        auto f2 = pairing::find(s, chan::key_id(e2->secret));
        CHECK(f2 && f2->secret == e2->secret && !f2->allow_delete);
        CHECK(!pairing::find(s, crypto::Bytes(8, 0)) && !pairing::find(s, crypto::Bytes()) && !pairing::find(s, crypto::Bytes(7, 1)) && !pairing::find(s, crypto::Bytes(9, 1)));
        CHECK(!pairing::add(s, "", true, &err) && has(err, "label") && !pairing::add(s, std::string(41, 'x'), true, &err));
        CHECK(!pairing::add(s, "bad\nlabel", true, &err));
        std::vector<std::string> after_bad;
        CHECK(pairing::list(s, &after_bad).size() == 2 && after_bad.empty());   // and a refused label leaves nothing behind that would stop the device
        // the original pairing.key is a pairing too: "primary", and it may delete
        auto p = pairing::set_primary(s, false, &err);
        CHECK(p && p->primary && p->label == "primary" && p->allow_delete && slurp(s + "/pairing.key") == crypto::to_hex(p->secret.data(), 32) + "\n");
        CHECK(pairing::list(s).size() == 3);
        auto fp = pairing::find(s, chan::key_id(p->secret));
        CHECK(fp && fp->primary && fp->secret == p->secret);
        CHECK(!pairing::set_primary(s, false, &err) && has(err, "already exists") && !fs::exists(s + "/pairing.key.new"));   // refusing leaves nothing behind
        auto p2 = pairing::set_primary(s, true, &err);
        CHECK(p2 && p2->secret != p->secret && !pairing::find(s, chan::key_id(p->secret)) && pairing::find(s, chan::key_id(p2->secret)));
        CHECK(!pairing::refresh(*p) && pairing::refresh(*p2));   // a connection made with the replaced secret is no longer valid
        CHECK(!fs::exists(s + "/pairing.key.new"));
    }

    printf("== the count is limited\n");
    {
        std::string s = root + "/many";
        size_t made = 0;
        for (size_t i = 0; i < pairing::MAX_ENTRIES; i++)
            if (pairing::add(s, "m" + std::to_string(i), false, &err)) made++;
        CHECK(made == pairing::MAX_ENTRIES && pairing::list(s).size() == pairing::MAX_ENTRIES);
        CHECK(!pairing::add(s, "one too many", false, &err) && has(err, "already has"));
        CHECK(pairing::list(s).size() == pairing::MAX_ENTRIES);
    }
    printf("== revoking\n");
    {
        std::string s = root + "/r";
        auto e1 = pairing::add(s, "One", true, &err), e2 = pairing::add(s, "Two", true, &err);
        auto p = pairing::set_primary(s, false, &err);
        CHECK(e1 && e2 && p);
        for (const char* bad_id : {"nothex", "0123456789ABCDEF", "", "0123456789abcde", "0123456789abcdef0", "../../victim", "0123456789abcdez"}) {
            err.clear();
            CHECK(!pairing::revoke(s, bad_id, &err) && has(err, "16 lower-case hex"));   // and never a path: nothing outside the store can be removed this way
        }
        spit(root + "/victim.key", "keep me");
        CHECK(!pairing::revoke(root + "/r", "../../victim", &err) && fs::exists(root + "/victim.key"));
        CHECK(!pairing::revoke(s, "0123456789abcdef", &err) && has(err, "no pairing with key id"));
        CHECK(pairing::revoke(s, e1->key_id, &err) && !pairing::find(s, chan::key_id(e1->secret)) && !fs::exists(e1->file));
        CHECK(!pairing::revoke(s, e1->key_id, &err));                       // not twice
        CHECK(pairing::find(s, chan::key_id(e2->secret)) && pairing::find(s, chan::key_id(p->secret)));   // the others are untouched
        CHECK(pairing::revoke(s, p->key_id, &err) && !fs::exists(s + "/pairing.key") && pairing::find(s, chan::key_id(e2->secret)));
        CHECK(pairing::list(s).size() == 1);
        // refresh: unchanged is kept, removed is gone, changed is re-read
        auto cur = pairing::find(s, chan::key_id(e2->secret));
        CHECK(cur && pairing::refresh(*cur));
        spit(e2->file, crypto::to_hex(e2->secret.data(), 32) + "\nlabel=Two\ndelete=0\ncreated=1\n");
        auto changed = pairing::refresh(*cur);
        CHECK(changed && !changed->allow_delete && changed->key_id == cur->key_id);
        {   // the file was replaced by another with the same modification time: still noticed (by its identity)
            struct stat before;
            lstat(e2->file.c_str(), &before);
            std::string tmp = e2->file + ".swap";
            spit(tmp, crypto::to_hex(e2->secret.data(), 32) + "\nlabel=Two\ndelete=1\ncreated=1\n");
            struct timespec ts[2] = {before.st_atimespec, before.st_mtimespec};
            utimensat(AT_FDCWD, tmp.c_str(), ts, 0);
            rename(tmp.c_str(), e2->file.c_str());
            auto swapped = pairing::refresh(*changed);
            CHECK(swapped && swapped->allow_delete);   // it noticed the new file and read it (the right to delete is back)
            changed = swapped;
        }
        spit(e2->file, std::string(64, 'a') + "\nlabel=Two\ndelete=1\ncreated=1\n");   // a different secret under the same name
        CHECK(!pairing::refresh(*changed));
        spit(e2->file, crypto::to_hex(e2->secret.data(), 32) + "\nlabel=Two\ndelete=1\ncreated=1\n", 0644);   // loosened permissions
        CHECK(!pairing::refresh(*changed));
        spit(e2->file, crypto::to_hex(e2->secret.data(), 32) + "\nlabel=Two\ndelete=1\ncreated=1\n");
        CHECK(pairing::refresh(*changed));
        fs::remove(e2->file);
        CHECK(!pairing::refresh(*changed));
    }

    printf("== files that are not acceptable are reported, never trusted\n");
    {
        std::string s = root + "/bad";
        auto good = pairing::add(s, "Good", false, &err);
        CHECK(good);
        std::string text = slurp(good->file);
        std::vector<std::string> pr;
        auto expect_bad = [&](const std::string& content, mode_t mode, const std::string& why) {
            spit(good->file, content, mode);
            pr.clear();
            auto all = pairing::list(s, &pr);
            bool ok = all.empty() && any_problem(pr, why) && !pairing::find(s, chan::key_id(good->secret));
            if (!ok) printf("      (for: %s; problems: %zu)\n", why.c_str(), pr.size());
            return ok;
        };
        CHECK(expect_bad(text, 0644, "readable only by its owner"));
        CHECK(expect_bad(text, 0640, "readable only by its owner"));
        CHECK(expect_bad(text, 0604, "readable only by its owner"));
        CHECK(expect_bad("not hex\nlabel=Good\ndelete=0\n", 0600, "64 hex characters"));
        CHECK(expect_bad(std::string(62, 'a') + "\nlabel=Good\ndelete=0\n", 0600, "64 hex characters"));
        CHECK(expect_bad(std::string(66, 'a') + "\nlabel=Good\ndelete=0\n", 0600, "64 hex characters"));
        CHECK(expect_bad(std::string(64, 'a') + "\nlabel=Good\ndelete=0\n", 0600, "the file name is not the key id"));
        std::string hex = text.substr(0, 64);
        CHECK(expect_bad(hex + "\ndelete=0\n", 0600, "needs both"));
        CHECK(expect_bad(hex + "\nlabel=Good\n", 0600, "needs both"));
        CHECK(expect_bad(hex + "\nlabel=Good\ndelete=0\ndelete=1\n", 0600, "unrecognised line"));
        CHECK(expect_bad(hex + "\nlabel=Good\nlabel=Other\ndelete=0\n", 0600, "unrecognised line"));
        CHECK(expect_bad(hex + "\nlabel=Good\ndelete=2\n", 0600, "unrecognised line"));
        CHECK(expect_bad(hex + "\nlabel=Good\ndelete=\n", 0600, "unrecognised line"));
        CHECK(expect_bad(hex + "\nlabel=Good\ndelet=1\n", 0600, "unrecognised line"));
        CHECK(expect_bad(hex + "\nlabel=Good\ndelete=0\nsurprise\n", 0600, "unrecognised line"));
        CHECK(expect_bad(hex + "\nlabel=Good\ndelete=0\ncreated=12x\n", 0600, "unrecognised line"));
        CHECK(expect_bad(hex + "\nlabel=\ndelete=0\n", 0600, "label is not acceptable"));
        CHECK(expect_bad(hex + "\nlabel=" + std::string(41, 'x') + "\ndelete=0\n", 0600, "label is not acceptable"));
        // fine again, including a blank line and no "created"
        spit(good->file, hex + "\n\nlabel=Good\ndelete=1\n");
        auto ok = pairing::find(s, chan::key_id(good->secret));
        CHECK(ok && ok->allow_delete && ok->created == 0 && pairing::list(s).size() == 1);
        // a link instead of a file; a directory instead of a file
        fs::remove(good->file);
        spit(root + "/target.key", hex + "\nlabel=Good\ndelete=0\n");
        symlink((root + "/target.key").c_str(), good->file.c_str());
        lchmod(good->file.c_str(), 0600);   // a link that looks private still is not a regular file
        pr.clear();
        CHECK(pairing::list(s, &pr).empty() && any_problem(pr, "regular file") && !pairing::find(s, chan::key_id(good->secret)));
        fs::remove(good->file);
        fs::create_directories(good->file);
        pr.clear();
        CHECK(pairing::list(s, &pr).empty() && any_problem(pr, "regular file"));
        fs::remove_all(good->file);
        // other files in the directory are not pairings and are ignored; a leftover temporary is ignored too
        spit(s + "/pairings/notes.txt", "hello");
        spit(s + "/pairings/" + good->key_id + ".key.new", "half written");
        pr.clear();
        CHECK(pairing::list(s, &pr).empty() && pr.empty());
        // the original file with loose permissions is reported too
        std::string s2 = root + "/bad2";
        auto p = pairing::set_primary(s2, false, &err);
        CHECK(p);
        chmod(p->file.c_str(), 0644);
        pr.clear();
        CHECK(pairing::list(s2, &pr).empty() && any_problem(pr, "readable only by its owner") && !pairing::find(s2, chan::key_id(p->secret)));
        // the same secret twice
        std::string s3 = root + "/dup";
        auto d1 = pairing::add(s3, "A", false, &err);
        CHECK(d1);
        spit(s3 + "/pairing.key", crypto::to_hex(d1->secret.data(), 32) + "\n");
        pr.clear();
        auto both = pairing::list(s3, &pr);
        CHECK(both.size() == 1 && any_problem(pr, "the same secret is already listed") && both[0].primary);
    }

    fs::remove_all(root);
    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
