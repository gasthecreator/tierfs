#include "scanner.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <cerrno>
#include <cstring>
#include <map>

namespace tierfs {
namespace {

struct Found {
    std::string rel;          // relative to the origin, no leading slash
    uint64_t size = 0;
    int64_t mtime = 0;
    uint32_t mode = 0;
};

// Depth-first walk of the origin: regular files only (symlinks, devices and sockets are not tracked), never the bookkeeping
// directory at the top, never through symlinks.
void walk(const std::string& root, const std::string& rel, std::vector<Found>& out, bool& complete) {
    std::string dir = rel.empty() ? root : root + "/" + rel;
    DIR* d = opendir(dir.c_str());
    if (!d) { complete = false; return; }
    std::vector<std::string> subdirs;
    while (struct dirent* e = readdir(d)) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        if (rel.empty() && name == ".tierfs") continue;
        struct stat st;
        if (fstatat(dirfd(d), name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;   // vanished while we looked
        std::string r = rel.empty() ? name : rel + "/" + name;
        if (S_ISDIR(st.st_mode)) subdirs.push_back(r);
        else if (S_ISREG(st.st_mode)) out.push_back({r, static_cast<uint64_t>(st.st_size), st.st_mtimespec.tv_sec, st.st_mode & 0777u});
    }
    closedir(d);
    for (const auto& s : subdirs) walk(root, s, out, complete);
}

bool local_bytes(FileState s) { return s == FileState::LOCAL || s == FileState::REPLICATING || s == FileState::REPLICATED; }

}  // namespace

ScanReport Scanner::scan(const ScanOptions& opt) {
    ScanReport rep;
    const std::string root = overlay_.config().origin_dir;
    const std::string prefix = overlay_.config().logical_prefix;
    struct stat rst;
    if (stat(root.c_str(), &rst) != 0 || !S_ISDIR(rst.st_mode)) {
        rep.aborted = true;
        rep.abort_reason = root + " is not available: nothing was changed";
        return rep;
    }
    std::vector<Found> found;
    bool complete = true;
    walk(root, "", found, complete);
    if (!complete) {
        rep.aborted = true;
        rep.abort_reason = "the folder could not be read completely: nothing was changed";
        return rep;
    }
    rep.files_seen = found.size();
    if (on_step) on_step("walked");

    std::map<std::string, FileRec> rows;   // logical path -> row, live files only
    for (auto& f : ledger_.list_files_under(prefix)) rows[ledger_.fold_path(f.path)] = f;   // keyed by the name as the volume sees it
    std::map<std::string, bool> seen_rel;
    for (const auto& f : found) seen_rel[ledger_.fold_path(f.rel)] = true;
    if (on_step) on_step("rows");

    // ---- files that are in the origin
    std::vector<Ledger::NewFile> to_track;
    for (const auto& f : found) {
        std::string lp = prefix + f.rel;
        auto it = rows.find(ledger_.fold_path(lp));
        if (it == rows.end()) {
            if (opt.track_new) to_track.push_back({lp, f.size, f.mtime, f.mode});
            continue;
        }
        const FileRec& row = it->second;
        if (local_bytes(row.state)) {
            bool size_or_time = row.size != f.size || row.mtime != f.mtime;
            bool mode = row.mode != f.mode;
            bool respelled = row.path != lp;   // renamed behind our back, only in case or Unicode form
            if (!size_or_time && !mode && !respelled) { rep.unchanged++; continue; }
            bool done = false;
            overlay_.locked([&] {   // re-check under the namespace lock: a rename or a write may have got there first
                struct stat st;
                std::string op = root + "/" + f.rel;
                auto cur = ledger_.get_file_by_path(lp);
                if (!cur || !local_bytes(cur->state) || lstat(op.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return;
                if (overlay_.has_writers_locked(cur->file_id)) { rep.skipped_busy++; done = true; return; }
                if (cur->path != lp && ledger_.rename_file(cur->file_id, lp).ok) {   // the name on disk is the truth
                    rep.respelled++;
                    rep.actions.push_back("respelled: " + cur->path + " -> " + lp);
                    cur = ledger_.get_file(cur->file_id);
                    if (!cur) return;
                }
                uint64_t sz = static_cast<uint64_t>(st.st_size);
                int64_t mt = st.st_mtimespec.tv_sec;
                uint32_t md = st.st_mode & 0777u;
                if (cur->size != sz || cur->mtime != mt) {
                    if (ledger_.note_local_modified(cur->file_id, sz, mt).ok) { rep.marked_modified++; rep.actions.push_back("modified: " + lp); }
                    if (cur->mode != md) ledger_.note_attrs_changed(cur->file_id, md, std::nullopt);
                } else if (cur->mode != md) {
                    if (ledger_.note_attrs_changed(cur->file_id, md, std::nullopt).ok) { rep.attrs_updated++; rep.actions.push_back("attributes: " + lp); }
                }
                done = true;
            });
            if (!done) rep.skipped_busy++;
        } else if (row.state == FileState::DROPPING || row.state == FileState::HYDRATING) {
            rep.skipped_busy++;   // a drop or a hydration is in flight (or was cut off: the engine's and the overlay's recovery settle it)
        } else {
            rep.problems.push_back(lp + ": the ledger says its bytes are only on the devices, but a file is at this path; left alone");
        }
    }
    // New files are decided one at a time under the namespace lock, with a fresh look: the walk and the rows are snapshots, and a
    // file a rename has just moved looks new in one of them and missing in the other. (Batches of 100 keep each hold on the lock short.)
    for (size_t start = 0; start < to_track.size(); start += 100) {
        size_t n = 0;
        overlay_.locked([&] {
            std::vector<Ledger::NewFile> batch;
            for (size_t i = start; i < to_track.size() && i < start + 100; i++) {
                const auto& nf = to_track[i];
                struct stat st;
                std::string op = root + "/" + nf.path.substr(prefix.size());
                if (lstat(op.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;           // gone, or moved meanwhile
                if (ledger_.get_file_by_path(nf.path)) continue;                              // tracked meanwhile (created or renamed through the mount)
                batch.push_back({nf.path, static_cast<uint64_t>(st.st_size), st.st_mtimespec.tv_sec, st.st_mode & 0777u});
            }
            n = ledger_.track_files(batch);
        });
        rep.tracked_new += n;
        if (n) rep.actions.push_back("tracked " + std::to_string(n) + " new file(s)");
    }

    // ---- tracked files with local bytes that are not in the origin any more
    std::vector<FileRec> vanished;
    size_t local_rows = 0;
    for (const auto& kv : rows) {
        const FileRec& row = kv.second;
        if (!local_bytes(row.state)) continue;
        local_rows++;
        if (!seen_rel.count(ledger_.fold_path(row.path.substr(prefix.size())))) vanished.push_back(row);
    }
    if (!opt.retire_vanished || vanished.empty()) return rep;
    if (vanished.size() > opt.vanished_floor && static_cast<double>(vanished.size()) > opt.max_vanished_fraction * static_cast<double>(local_rows)) {
        rep.problems.push_back(std::to_string(vanished.size()) + " of " + std::to_string(local_rows) +
                               " tracked files are missing from " + root + ": the folder may be unmounted or on a disconnected drive; nothing was forgotten");
        return rep;
    }
    for (const auto& row : vanished) {
        overlay_.locked([&] {
            struct stat st;
            std::string op = root + "/" + row.path.substr(prefix.size());
            auto cur = ledger_.get_file_by_path(row.path);
            if (!cur || cur->file_id != row.file_id || !local_bytes(cur->state)) return;       // changed meanwhile (renamed, dropped, ...)
            if (lstat(op.c_str(), &st) == 0) return;                                           // it is back
            if (overlay_.has_writers_locked(cur->file_id)) { rep.skipped_busy++; return; }
            if (ledger_.retire_file(cur->file_id, "vanished from the origin").ok) {
                rep.retired_vanished++;
                rep.actions.push_back("vanished: " + row.path);
            }
        });
    }
    return rep;
}

}  // namespace tierfs
