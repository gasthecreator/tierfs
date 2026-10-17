#include "pairings.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "fsutil.hpp"
#include "securechannel.hpp"

namespace tierfs::pairing {
namespace {

int64_t mtime_ns_of(const struct stat& st) {
#ifdef __APPLE__
    return static_cast<int64_t>(st.st_mtimespec.tv_sec) * 1000000000ll + st.st_mtimespec.tv_nsec;
#else
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000ll + st.st_mtim.tv_nsec;
#endif
}

bool valid_key_id_hex(const std::string& s) {
    if (s.size() != 16) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

std::string dir_of(const std::string& store) { return store + "/pairings"; }

// Reads one pairing file. nullopt with *why when it is not acceptable.
std::optional<Entry> parse_file(const std::string& path, bool primary, std::string* why) {
    auto fail = [&](const std::string& m) -> std::optional<Entry> {
        if (why) *why = path + ": " + m;
        return std::nullopt;
    };
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) return fail("cannot be read");
    if (!S_ISREG(st.st_mode) || (st.st_mode & 077) != 0) return fail("must be a regular file readable only by its owner (chmod 600)");
    std::ifstream f(path);
    if (!f) return fail("cannot be read");
    std::string line;
    std::getline(f, line);
    auto raw = crypto::from_hex(line);
    if (!raw || raw->size() != chan::PSK_LEN) return fail("does not start with 64 hex characters");
    Entry e;
    e.secret = *raw;
    e.key_id = chan::key_id_hex(e.secret);
    e.file = path;
    e.primary = primary;
    e.mtime_ns = mtime_ns_of(st);
    e.inode = st.st_ino;
    if (primary) {
        e.label = "primary";
        e.allow_delete = true;  // the original single secret has always been allowed to delete: existing devices behave as before
    } else {
        std::string name = path.substr(path.rfind('/') + 1);
        if (name != e.key_id + ".key") return fail("the file name is not the key id of the secret inside (" + e.key_id + ".key)");
        bool saw_label = false, saw_delete = false;
        while (std::getline(f, line)) {
            if (line.empty()) continue;
            size_t eq = line.find('=');
            std::string k = eq == std::string::npos ? line : line.substr(0, eq), v = eq == std::string::npos ? "" : line.substr(eq + 1);
            if (k == "label" && !saw_label) {
                if (!valid_label(v)) return fail("the label is not acceptable");
                e.label = v;
                saw_label = true;
            } else if (k == "delete" && !saw_delete && (v == "0" || v == "1")) {
                e.allow_delete = v == "1";
                saw_delete = true;
            } else if (k == "created" && !v.empty() && v.find_first_not_of("0123456789") == std::string::npos && v.size() < 18) {
                e.created = atoll(v.c_str());
            } else {
                return fail("unrecognised line '" + line.substr(0, 40) + "'");  // a typo must not silently change what a Mac may do
            }
        }
        if (!saw_label || !saw_delete) return fail("needs both a label= and a delete= line");
    }
    return e;
}

// Writes a new file with a fresh name; never replaces one (revoke first).
bool write_new(const std::string& path, const std::string& content, std::string* err) {
    std::string tmp = path + ".new";
    unlink(tmp.c_str());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (err) *err = "cannot create " + tmp + ": " + strerror(errno);
        return false;
    }
    bool ok = write(fd, content.data(), content.size()) == static_cast<ssize_t>(content.size()) && fsutil::strict_full_sync(fd) == 0;
    close(fd);
    struct stat st;
    if (ok && lstat(path.c_str(), &st) == 0) {
        unlink(tmp.c_str());
        if (err) *err = path + " already exists";
        return false;
    }
    if (!ok || rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        if (err) *err = "cannot write " + path;
        return false;
    }
    fsutil::sync_dir(fsutil::parent_of(path));
    return true;
}

}  // namespace

bool valid_label(const std::string& s) {
    if (s.empty() || s.size() > MAX_LABEL) return false;
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f) return false;
    return true;
}

std::vector<Entry> list(const std::string& store, std::vector<std::string>* problems) {
    std::vector<Entry> out;
    auto note = [&](const std::string& m) {
        if (problems) problems->push_back(m);
    };
    auto add_unique = [&](Entry e) {
        for (const auto& have : out)
            if (have.key_id == e.key_id) {
                note(e.file + ": the same secret is already listed (" + have.file + ")");
                return;
            }
        out.push_back(std::move(e));
    };
    {
        std::string why;
        std::string path = store + "/pairing.key";
        struct stat st;
        if (lstat(path.c_str(), &st) == 0) {
            if (auto e = parse_file(path, true, &why))
                add_unique(*e);
            else
                note(why);
        }
    }
    std::vector<std::string> names;
    if (DIR* d = opendir(dir_of(store).c_str())) {
        while (dirent* de = readdir(d)) {
            std::string n = de->d_name;
            if (n.size() > 4 && n.compare(n.size() - 4, 4, ".key") == 0) names.push_back(n);  // (anything else in the directory is not a pairing)
        }
        closedir(d);
    }
    std::sort(names.begin(), names.end());
    for (const auto& n : names) {
        std::string why;
        if (auto e = parse_file(dir_of(store) + "/" + n, false, &why))
            add_unique(*e);
        else
            note(why);
    }
    return out;
}

std::optional<Entry> find(const std::string& store, const crypto::Bytes& key_id) {
    std::string hex = crypto::to_hex(key_id.data(), key_id.size());
    if (!valid_key_id_hex(hex)) return std::nullopt;
    // Look only at the file that could hold this id (the primary, or <keyid>.key): a handshake must not cost a read of every pairing.
    struct stat st;
    std::string prim = store + "/pairing.key";
    if (lstat(prim.c_str(), &st) == 0) {
        if (auto e = parse_file(prim, true, nullptr); e && e->key_id == hex) return e;
    }
    return parse_file(dir_of(store) + "/" + hex + ".key", false, nullptr);
}

std::optional<Entry> refresh(const Entry& e) {
    struct stat st;
    if (lstat(e.file.c_str(), &st) != 0) return std::nullopt;  // revoked
    if (mtime_ns_of(st) == e.mtime_ns && st.st_ino == e.inode) return e;
    auto again = parse_file(e.file, e.primary, nullptr);
    if (!again || again->key_id != e.key_id) return std::nullopt;
    return again;
}

std::optional<Entry> add(const std::string& store, const std::string& label, bool allow_delete, std::string* err) {
    auto fail = [&](const std::string& m) -> std::optional<Entry> {
        if (err) *err = m;
        return std::nullopt;
    };
    if (!valid_label(label)) return fail("the label must be 1 to " + std::to_string(MAX_LABEL) + " printable characters");
    if (list(store).size() >= MAX_ENTRIES) return fail("this device already has " + std::to_string(MAX_ENTRIES) + " pairings");
    mkdir(store.c_str(), 0700);
    mkdir(dir_of(store).c_str(), 0700);
    crypto::Bytes secret = crypto::random_bytes(chan::PSK_LEN);
    if (secret.size() != chan::PSK_LEN) return fail("the system random generator failed");
    std::string id = chan::key_id_hex(secret);
    std::string content = crypto::to_hex(secret.data(), secret.size()) + "\nlabel=" + label + "\ndelete=" + (allow_delete ? "1" : "0") +
                          "\ncreated=" + std::to_string(static_cast<long long>(time(nullptr))) + "\n";
    std::string path = dir_of(store) + "/" + id + ".key", werr;
    if (!write_new(path, content, &werr)) return fail(werr);
    auto e = parse_file(path, false, &werr);
    if (!e) return fail(werr);
    return e;
}

bool revoke(const std::string& store, const std::string& key_id_hex, std::string* err) {
    if (!valid_key_id_hex(key_id_hex)) {
        if (err) *err = "a key id is 16 lower-case hex characters";
        return false;
    }
    std::string prim = store + "/pairing.key";
    struct stat st;
    if (lstat(prim.c_str(), &st) == 0) {
        auto e = parse_file(prim, true, nullptr);
        if (e && e->key_id == key_id_hex) {
            if (unlink(prim.c_str()) != 0) {
                if (err) *err = "cannot remove " + prim;
                return false;
            }
            fsutil::sync_dir(store);
            return true;
        }
    }
    std::string path = dir_of(store) + "/" + key_id_hex + ".key";
    if (unlink(path.c_str()) != 0) {
        if (err) *err = errno == ENOENT ? "no pairing with key id " + key_id_hex : "cannot remove " + path;
        return false;
    }
    fsutil::sync_dir(dir_of(store));
    return true;
}

std::optional<Entry> set_primary(const std::string& store, bool replace, std::string* err) {
    auto fail = [&](const std::string& m) -> std::optional<Entry> {
        if (err) *err = m;
        return std::nullopt;
    };
    mkdir(store.c_str(), 0700);
    crypto::Bytes secret = crypto::random_bytes(chan::PSK_LEN);
    if (secret.size() != chan::PSK_LEN) return fail("the system random generator failed");
    std::string path = store + "/pairing.key", tmp = path + ".new", werr;
    unlink(tmp.c_str());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return fail("cannot create " + tmp + ": " + strerror(errno));
    std::string hex = crypto::to_hex(secret.data(), secret.size()) + "\n";
    bool ok = write(fd, hex.data(), hex.size()) == static_cast<ssize_t>(hex.size()) && fsutil::strict_full_sync(fd) == 0;
    close(fd);
    struct stat st;
    if (ok && !replace && lstat(path.c_str(), &st) == 0) {
        unlink(tmp.c_str());
        return fail(path + " already exists");
    }
    if (!ok || rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return fail("cannot write " + path);
    }
    fsutil::sync_dir(store);
    auto e = parse_file(path, true, &werr);
    if (!e) return fail(werr);
    return e;
}

}  // namespace tierfs::pairing
