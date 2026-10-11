#include "recovery.hpp"

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <map>
#include <set>

#include "crashpoint.hpp"
#include "fsutil.hpp"

namespace tierfs {
namespace {

using crypto::Bytes;

constexpr const char* PARTIAL_PREFIX = ".tierfs-partial-";

std::string gib(uint64_t bytes) {
    char buf[32];
    if (bytes >= (1ull << 30)) snprintf(buf, sizeof buf, "%.2f GiB", bytes / double(1ull << 30));
    else snprintf(buf, sizeof buf, "%.1f MiB", bytes / double(1ull << 20));
    return buf;
}

std::string short_id(const std::string& s) { return s.substr(0, 8); }

struct Catalogued {
    crypto::Manifest m;
    std::vector<size_t> holders;   // indexes of the devices that listed this (file, version)
};

struct Ctx {
    const crypto::Keys* keys = nullptr;
    std::string volume;
    const std::vector<RecoveryDevice>* devs = nullptr;
    std::vector<bool> alive;
    const RecoveryOptions* opt = nullptr;
    RestoreReport* rep = nullptr;
    void say(const std::string& s) const { if (opt->progress) opt->progress(s); }
};

std::string parent_dir(const std::string& p) {
    size_t i = p.rfind('/');
    return i == std::string::npos ? "." : (i == 0 ? "/" : p.substr(0, i));
}
// Make every directory of `rel`'s parent under `root`, refusing anything that is not a plain directory.
bool make_parents(const std::string& root, const std::string& rel, std::string* why) {
    std::string cur = root;
    size_t pos = 0;
    for (;;) {
        size_t slash = rel.find('/', pos);
        if (slash == std::string::npos) return true;   // the rest is the file name itself
        cur += "/" + rel.substr(pos, slash - pos);
        struct stat st;
        if (lstat(cur.c_str(), &st) == 0) {
            if (!S_ISDIR(st.st_mode)) { *why = cur + " is not a plain directory (symlink or file)"; return false; }
        } else if (errno == ENOENT) {
            if (mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) { *why = "cannot create " + cur + ": " + strerror(errno); return false; }
            if (lstat(cur.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) { *why = cur + " is not a plain directory"; return false; }
        } else {
            *why = "cannot inspect " + cur + ": " + strerror(errno);
            return false;
        }
        pos = slash + 1;
    }
}

// The newest ancestor of `p` that exists (to ask how much room there is before creating anything).
std::string existing_ancestor(std::string p) {
    struct stat st;
    while (p.size() > 1 && stat(p.c_str(), &st) != 0) p = parent_dir(p);
    return p;
}

bool file_matches(const std::string& path, const crypto::Keys& keys, const crypto::Manifest& m) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode) || static_cast<uint64_t>(st.st_size) != m.size) return false;
    int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    crypto::FileHmac fh(keys);
    std::vector<uint8_t> buf(1 << 20);
    for (;;) {
        ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0) { if (errno == EINTR) continue; close(fd); return false; }
        if (n == 0) break;
        fh.update(buf.data(), static_cast<size_t>(n));
    }
    close(fd);
    return fh.finish_hex() == m.file_hmac;
}

bool write_all(int fd, const uint8_t* p, size_t n) {
    while (n) {
        ssize_t w = ::write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return false; }
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

// One chunk from whichever device has a good copy. Order: the devices that listed the manifest first.
bool fetch_chunk(const Ctx& c, const crypto::Manifest::ChunkRef& ref, const std::vector<size_t>& prefer, Bytes& plain, std::string* why) {
    std::vector<size_t> order = prefer;
    for (size_t i = 0; i < c.devs->size(); i++)
        if (std::find(order.begin(), order.end(), i) == order.end()) order.push_back(i);
    std::string last = "no device is reachable";
    bool detailed = false;   // a device that HAD the chunk but gave a bad one explains more than devices that merely lack it
    for (size_t di : order) {
        if (!c.alive[di]) continue;
        const auto& d = (*c.devs)[di];
        Bytes blob;
        DevRes g = d.client->get_chunk(ref.chunk_id, blob);
        if (!g.ok()) { if (!detailed) last = d.name + ": " + g.msg; continue; }
        Bytes p;
        crypto::OpenError oe = crypto::open_chunk(*c.keys, c.volume, ref.chunk_id, blob.data(), blob.size(), p);
        if (oe != crypto::OpenError::Ok) { last = d.name + ": the chunk does not verify (" + crypto::to_string(oe) + ")"; detailed = true; continue; }
        if (p.size() != ref.len) { last = d.name + ": the chunk has the wrong length"; detailed = true; continue; }
        if (crypto::chunk_id(*c.keys, p.data(), p.size()) != ref.chunk_id) { last = d.name + ": the chunk is not the one asked for"; detailed = true; continue; }
        plain = std::move(p);
        return true;
    }
    *why = last;
    return false;
}

// Rebuild one version into a temp file next to `dest`, verify it, and move it into place without overwriting.
// Returns "" on success, or the reason.
std::string restore_version(const Ctx& c, const Catalogued& cat, const std::string& dest, std::vector<std::string>* notes) {
    const crypto::Manifest& m = cat.m;
    std::string tmp = parent_dir(dest) + "/" + PARTIAL_PREFIX + short_id(m.file_id);
    struct stat st;
    if (lstat(tmp.c_str(), &st) == 0 && S_ISREG(st.st_mode)) unlink(tmp.c_str());   // a leftover of our own interrupted run
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return std::string("cannot create the temporary file: ") + strerror(errno);
    auto abort_with = [&](const std::string& why) { close(fd); unlink(tmp.c_str()); return why; };

    crypto::FileHmac fh(*c.keys);
    uint64_t total = 0;
    for (size_t i = 0; i < m.chunks.size(); i++) {
        Bytes plain;
        std::string why;
        if (!fetch_chunk(c, m.chunks[i], cat.holders, plain, &why))
            return abort_with("chunk " + std::to_string(i + 1) + " of " + std::to_string(m.chunks.size()) + " (" + short_id(m.chunks[i].chunk_id) +
                              ") cannot be recovered from any device: " + why);
        fh.update(plain.data(), plain.size());
        total += plain.size();
        if (!write_all(fd, plain.data(), plain.size())) return abort_with(std::string("cannot write: ") + strerror(errno));
    }
    if (total != m.size) return abort_with("the chunks add up to " + std::to_string(total) + " bytes, the manifest says " + std::to_string(m.size));
    if (fh.finish_hex() != m.file_hmac) return abort_with("the whole-file check failed: the rebuilt file is not the original");

    if (c.opt->apply_xattrs)
        for (const auto& x : m.xattrs)
            if (fsetxattr(fd, x.first.c_str(), x.second.data(), x.second.size(), 0, 0) != 0 && notes)
                notes->push_back("extended attribute " + x.first + " could not be restored: " + strerror(errno));
    fchmod(fd, static_cast<mode_t>(m.mode & 0777));   // never setuid/setgid from a manifest
    struct timespec times[2] = {{0, UTIME_OMIT}, {static_cast<time_t>(m.mtime), 0}};
    futimens(fd, times);
    fsutil::full_sync(fd);
    crash_point("restore_before_rename");
    close(fd);
    if (renamex_np(tmp.c_str(), dest.c_str(), RENAME_EXCL) != 0) {
        int e = errno;
        unlink(tmp.c_str());
        return e == EEXIST ? "the destination appeared while restoring: left alone" : std::string("cannot move the file into place: ") + strerror(e);
    }
    fsutil::sync_dir(parent_dir(dest));
    crash_point("restore_after_rename");
    return "";
}

}  // namespace

bool RestoreReport::complete() const {
    return fatal.empty() && failed.empty() && conflicts.empty() && rejected.empty() && older.empty();
}

bool safe_relative_path(const std::string& logical, std::string* rel, std::string* why) {
    auto no = [&](const char* m) { if (why) *why = m; return false; };
    if (logical.empty()) return no("empty path");
    if (logical.find('\0') != std::string::npos) return no("path contains a NUL byte");
    std::string out;
    size_t pos = 0;
    while (pos <= logical.size()) {
        size_t slash = logical.find('/', pos);
        std::string comp = logical.substr(pos, slash == std::string::npos ? std::string::npos : slash - pos);
        pos = slash == std::string::npos ? logical.size() + 1 : slash + 1;
        if (comp.empty() || comp == ".") continue;
        if (comp == "..") return no("path contains '..'");
        if (comp.size() > 255) return no("a path component is longer than 255 bytes");
        for (unsigned char ch : comp) if (ch < 0x20 || ch == 0x7f) return no("a path component contains a control character");
        if (comp.compare(0, strlen(PARTIAL_PREFIX), PARTIAL_PREFIX) == 0) return no("a path component uses a name reserved for recovery temp files");
        if (!out.empty()) out += "/";
        out += comp;
    }
    if (out.empty()) return no("the path names the root");
    if (rel) *rel = out;
    return true;
}

RestoreReport recover_from_devices(const crypto::SecretKey& master, const std::vector<RecoveryDevice>& devices, const std::string& out_dir,
                                    const RecoveryOptions& opt) {
    RestoreReport rep;
    rep.dry_run = opt.dry_run;
    auto fatal = [&](const std::string& why) { rep.fatal = why; return rep; };
    if (devices.empty()) return fatal("no device was given");
    if (out_dir.empty()) return fatal("no output directory was given");
    if (!master.valid()) return fatal("the recovery key is not valid");

    crypto::Keys keys(master);
    Ctx c;
    c.keys = &keys;
    c.devs = &devices;
    c.opt = &opt;
    c.rep = &rep;
    c.alive.assign(devices.size(), false);

    // 1. who is there, and which volume do they belong to
    std::string volume;
    for (size_t i = 0; i < devices.size(); i++) {
        DevInfo info;
        DevRes r = devices[i].client->info(info);
        if (!r.ok()) { rep.warnings.push_back(devices[i].name + " is not reachable: " + r.msg); continue; }
        if (info.volume_id.empty()) { rep.warnings.push_back(devices[i].name + " is not bound to any volume: it holds nothing to recover"); continue; }
        if (volume.empty()) volume = info.volume_id;
        else if (volume != info.volume_id)
            return fatal("the devices belong to different volumes (" + short_id(volume) + " and " + short_id(info.volume_id) + "); restore them separately");
        c.alive[i] = true;
        rep.devices_reachable++;
    }
    if (volume.empty()) return fatal("no usable device: " + (rep.warnings.empty() ? std::string("none given") : rep.warnings[0]));
    rep.volume_id = volume;
    c.volume = volume;

    // 2. the catalogue: every manifest every device lists, opened with the phrase's keys
    std::map<std::pair<std::string, int64_t>, std::vector<size_t>> listed;
    for (size_t i = 0; i < devices.size(); i++) {
        if (!c.alive[i]) continue;
        uint64_t since = 0;
        for (;;) {
            ListReply lr;
            DevRes r = devices[i].client->list_manifests(since, 1000, lr);
            if (!r.ok()) { rep.warnings.push_back(devices[i].name + ": cannot list its manifests: " + r.msg); break; }
            for (auto& e : lr.entries) {
                since = std::max(since, e.seq);
                auto& v = listed[{e.file_id, e.version}];
                if (std::find(v.begin(), v.end(), i) == v.end()) v.push_back(i);
            }
            if (lr.entries.size() < 1000) break;
        }
    }
    rep.manifests_listed = listed.size();
    if (listed.empty()) return fatal("the devices hold no manifests: there is nothing to recover");

    std::map<std::string, std::map<int64_t, Catalogued>> by_file;   // file_id -> version -> manifest
    for (auto& kv : listed) {
        const std::string& fid = kv.first.first;
        int64_t ver = kv.first.second;
        bool opened = false;
        std::string last = "no device returned it";
        for (size_t di : kv.second) {
            Bytes blob;
            DevRes g = devices[di].client->get_manifest(fid, ver, blob);
            if (!g.ok()) { last = devices[di].name + ": " + g.msg; continue; }
            crypto::Manifest m;
            crypto::OpenError oe = crypto::open_manifest(keys, volume, fid, ver, blob.data(), blob.size(), m);
            if (oe != crypto::OpenError::Ok) { last = devices[di].name + ": " + crypto::to_string(oe); continue; }
            Catalogued cat;
            cat.m = std::move(m);
            cat.holders = kv.second;
            by_file[fid][ver] = std::move(cat);
            opened = true;
            break;
        }
        if (opened) rep.manifests_opened++;
        else {
            rep.manifests_unreadable++;
            if (rep.manifests_unreadable <= 5) rep.warnings.push_back("manifest " + short_id(fid) + " v" + std::to_string(ver) + " cannot be opened (" + last + ")");
        }
    }
    if (rep.manifests_opened == 0)
        return fatal("none of the " + std::to_string(rep.manifests_listed) +
                     " manifests on the devices opens with this recovery phrase: it is not the phrase for this volume (or the devices were damaged)");
    if (rep.manifests_unreadable)
        rep.warnings.push_back(std::to_string(rep.manifests_unreadable) + " of " + std::to_string(rep.manifests_listed) + " manifests could not be opened");

    // 3. the plan: the newest readable version of each file, at a safe path
    struct Planned { std::string file_id, rel; RecoveredFile info; };
    std::vector<Planned> plan;
    for (auto& fk : by_file) {
        const Catalogued& latest = fk.second.rbegin()->second;
        if (!opt.path_prefix.empty() && latest.m.path.compare(0, opt.path_prefix.size(), opt.path_prefix) != 0) continue;
        std::string rel, why;
        if (!safe_relative_path(latest.m.path, &rel, &why)) {
            rep.rejected.push_back(short_id(fk.first) + ": unsafe path \"" + latest.m.path + "\" (" + why + ")");
            continue;
        }
        Planned p;
        p.file_id = fk.first;
        p.rel = rel;
        p.info.logical = latest.m.path;
        p.info.version = p.info.latest = latest.m.version;
        p.info.size = latest.m.size;
        plan.push_back(std::move(p));
    }
    rep.files_found = plan.size();
    std::sort(plan.begin(), plan.end(), [](const Planned& a, const Planned& b) { return a.rel != b.rel ? a.rel < b.rel : a.file_id < b.file_id; });
    {   // two different files that claim the same path: keep both, never let one overwrite the other
        std::string prev;
        for (auto& p : plan) {
            std::string orig = p.rel;
            if (orig == prev) {
                p.rel += ".recovered-" + short_id(p.file_id);
                rep.warnings.push_back(p.info.logical + " belongs to more than one file; the extra one is restored as " + p.rel);
            }
            prev = orig;
        }
    }
    std::string root = out_dir;
    while (root.size() > 1 && root.back() == '/') root.pop_back();
    for (auto& p : plan) p.info.dest = root + "/" + p.rel;

    // 4. is there room? (before anything is written)
    for (auto& p : plan) {
        struct stat st;
        if (lstat(p.info.dest.c_str(), &st) != 0) rep.bytes_needed += p.info.size;
        rep.planned.push_back(p.info);
    }
    {
        struct statfs sf;
        std::string probe = existing_ancestor(root);
        if (statfs(probe.c_str(), &sf) == 0) rep.bytes_free = static_cast<uint64_t>(sf.f_bavail) * sf.f_bsize;
    }
    if (rep.bytes_needed + opt.reserve_bytes > rep.bytes_free) {
        std::string msg = "not enough room in " + root + ": the files need " + gib(rep.bytes_needed) + " (plus a " + gib(opt.reserve_bytes) +
                          " reserve) and " + gib(rep.bytes_free) + " is free";
        if (!opt.dry_run) return fatal(msg + "; nothing was written");
        rep.warnings.push_back(msg);
    }
    if (opt.dry_run) return rep;

    // 5. restore
    struct stat rst;
    if (stat(root.c_str(), &rst) != 0) {
        if (mkdir(root.c_str(), 0755) != 0 && errno != EEXIST) return fatal("cannot create " + root + ": " + strerror(errno));
    } else if (!S_ISDIR(rst.st_mode)) {
        return fatal(root + " exists and is not a directory");
    }
    for (auto& p : plan) {
        const auto& versions = by_file[p.file_id];
        const std::string& dest = p.info.dest;
        std::string why;
        if (!make_parents(root, p.rel, &why)) { rep.rejected.push_back(p.info.logical + ": " + why); continue; }

        struct stat dst;
        if (lstat(dest.c_str(), &dst) == 0) {
            if (file_matches(dest, keys, versions.rbegin()->second.m)) { rep.identical.push_back(p.info); c.say("already there: " + p.info.logical); }
            else rep.conflicts.push_back(p.info.logical + ": " + dest + " already exists and is different; left alone");
            continue;
        }
        std::string newest_why;
        bool done = false;
        for (auto it = versions.rbegin(); it != versions.rend() && !done; ++it) {
            std::vector<std::string> notes;
            std::string err = restore_version(c, it->second, dest, &notes);
            for (auto& n : notes) rep.warnings.push_back(p.info.logical + ": " + n);
            if (err.empty()) {
                RecoveredFile rf = p.info;
                rf.version = it->first;
                rf.size = it->second.m.size;
                rep.restored.push_back(rf);
                if (it->first != p.info.latest) {
                    rep.older.push_back(rf);
                    rep.warnings.push_back(p.info.logical + ": version " + std::to_string(p.info.latest) + " could not be rebuilt (" + newest_why +
                                           "); restored version " + std::to_string(it->first) + " instead");
                }
                c.say("restored " + p.info.logical + " (v" + std::to_string(it->first) + ", " + gib(rf.size) + ")");
                done = true;
            } else {
                if (it == versions.rbegin()) newest_why = err;   // report why the NEWEST failed
                if (err.find("destination appeared") != std::string::npos) { rep.conflicts.push_back(p.info.logical + ": " + err); done = true; }
            }
        }
        if (!done) rep.failed.push_back(p.info.logical + ": " + newest_why);
    }
    return rep;
}

std::string format_recovery_report(const RestoreReport& r) {
    std::string s;
    if (!r.fatal.empty()) return "NOTHING WAS RECOVERED: " + r.fatal + "\n";
    s += std::string(r.dry_run ? "Dry run: " : "") + "volume " + short_id(r.volume_id) + ", " + std::to_string(r.devices_reachable) + " device(s) reachable, " +
         std::to_string(r.manifests_opened) + " of " + std::to_string(r.manifests_listed) + " manifests opened, " + std::to_string(r.files_found) + " file(s).\n";
    s += "Space: " + gib(r.bytes_needed) + " needed, " + gib(r.bytes_free) + " free.\n";
    if (r.dry_run) {
        for (auto& f : r.planned) s += "  would restore " + f.logical + "  v" + std::to_string(f.version) + ", " + gib(f.size) + "\n";
    } else {
        s += "Restored " + std::to_string(r.restored.size()) + ", already present " + std::to_string(r.identical.size()) + ", failed " +
             std::to_string(r.failed.size()) + ", conflicts " + std::to_string(r.conflicts.size()) + ", refused unsafe paths " + std::to_string(r.rejected.size()) + ".\n";
    }
    for (auto& f : r.older) s += "  OLDER VERSION: " + f.logical + " restored as v" + std::to_string(f.version) + " (newest was v" + std::to_string(f.latest) + ")\n";
    for (auto& f : r.failed) s += "  FAILED: " + f + "\n";
    for (auto& f : r.conflicts) s += "  CONFLICT: " + f + "\n";
    for (auto& f : r.rejected) s += "  REFUSED: " + f + "\n";
    for (auto& w : r.warnings) s += "  note: " + w + "\n";
    if (!r.dry_run) s += r.complete() ? "Everything was recovered.\n" : "The recovery is INCOMPLETE: see above.\n";
    return s;
}

}  // namespace tierfs
