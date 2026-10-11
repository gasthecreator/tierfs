#include "dropengine.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>

#include "crashpoint.hpp"
#include "fsutil.hpp"

namespace tierfs {
namespace {

using crypto::Bytes;

// "The same file, unmodified": a write changes size or mtime (to the nanosecond), a replace changes the inode.
struct Snap {
    int64_t size = 0, mtime_s = 0, mtime_ns = 0;
    uint64_t ino = 0;
    int32_t dev = 0;
};
bool same(const Snap& a, const Snap& b) {
    return a.size == b.size && a.mtime_s == b.mtime_s && a.mtime_ns == b.mtime_ns && a.ino == b.ino && a.dev == b.dev;
}
Snap snap_of(const struct stat& st) {
    Snap s;
    s.size = st.st_size;
    s.mtime_s = st.st_mtimespec.tv_sec;
    s.mtime_ns = st.st_mtimespec.tv_nsec;
    s.ino = st.st_ino;
    s.dev = st.st_dev;
    return s;
}
bool snap_of_path(const std::string& path, Snap* out) {
    struct stat st;
    if (!fsutil::is_regular_nofollow(path, &st)) return false;
    *out = snap_of(st);
    return true;
}

bool read_at(int fd, uint64_t off, size_t len, Bytes& buf) {
    buf.resize(len);
    size_t got = 0;
    while (got < len) {
        ssize_t r = pread(fd, buf.data() + got, len - got, static_cast<off_t>(off + got));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

}  // namespace

struct DropEngine::Check {
    bool ok = false;
    bool mismatch = false;   // the file is there but its CONTENT is not the replicated version
    std::string why;
    Snap snap;
};

DropEngine::DropEngine(Ledger& ledger, Replicator& replicator, const crypto::Keys& keys, std::string volume_id, DropPolicy policy,
                       std::string quarantine_root, OriginResolver resolver)
    : ledger_(ledger), replicator_(replicator), keys_(keys), volume_(std::move(volume_id)), policy_(policy),
      qroot_(std::move(quarantine_root)), resolve_(std::move(resolver)) {}

std::string DropEngine::quarantine_dir(const std::string& intent_id) const { return qroot_ + "/" + intent_id; }
std::string DropEngine::quarantine_object(const std::string& intent_id) const { return qroot_ + "/" + intent_id + "/object"; }

// ---------------------------------------------------------------- helpers

// Reads the file at `path` and compares it, chunk by chunk, with what the ledger recorded for `version`:
// chunk ids (keyed hashes of the content), lengths, sealed-blob hashes, and the total size. This is what
// stops a modification that nobody reported from being destroyed by a drop.
DropEngine::Check DropEngine::check_against_plan(const std::string& path, const std::string& file_id, int64_t version) {
    Check c;
    if (!ledger_.has_version(file_id, version)) { c.why = "the ledger has no such version"; return c; }
    struct stat st;
    if (!fsutil::is_regular_nofollow(path, &st)) { c.why = "the local path is not a regular file (missing, a directory, or a symlink)"; return c; }
    int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW);
    if (fd < 0) { c.why = std::string("cannot open the local file: ") + strerror(errno); return c; }
    struct Closer { int fd; ~Closer() { close(fd); } } closer{fd};
    struct stat fst;
    if (fstat(fd, &fst) != 0) { c.why = "cannot stat the local file"; return c; }
    c.snap = snap_of(fst);

    std::vector<ChunkRec> chunks = ledger_.get_chunks(file_id, version);
    uint64_t expected = 0;
    for (const auto& ch : chunks) expected += ch.len;
    if (static_cast<uint64_t>(c.snap.size) != expected) {
        c.mismatch = true;
        c.why = "the local file's size differs from the replicated version";
        return c;
    }
    Bytes buf;
    for (const auto& ch : chunks) {
        if (!read_at(fd, static_cast<uint64_t>(ch.idx) * REPL_CHUNK, ch.len, buf)) {
            c.mismatch = true;
            c.why = "the local file is shorter than the replicated version";
            return c;
        }
        if (crypto::chunk_id(keys_, buf.data(), buf.size()) != ch.chunk_id) {
            c.mismatch = true;
            c.why = "chunk " + std::to_string(ch.idx) + " of the local file is not what was replicated";
            return c;
        }
        Bytes blob = crypto::seal_chunk(keys_, volume_, ch.chunk_id, buf.data(), buf.size());
        if (blob.empty() || crypto::sha256_hex(blob.data(), blob.size()) != ch.blob_sha256) {
            c.mismatch = true;
            c.why = "chunk " + std::to_string(ch.idx) + " no longer seals to the recorded bytes";
            return c;
        }
    }
    struct stat after;
    if (fstat(fd, &after) != 0 || !same(c.snap, snap_of(after))) {
        c.mismatch = true;
        c.why = "the local file changed while it was being verified";
        return c;
    }
    c.ok = true;
    return c;
}

// A FRESH audit of every replica we can reach. Each result is recorded in the ledger (a failure demotes the
// replica); the ledger, not this function, decides whether what is left is enough.
void DropEngine::audit_all(const DeviceMap& devices, const std::string& file_id, int64_t version, size_t* audited, size_t* failed) {
    for (const auto& kv : devices) {
        auto dr = ledger_.get_device(kv.first);
        if (!dr || dr->state != "active" || !kv.second) continue;
        bool committed = false;
        for (const auto& r : ledger_.get_replicas(file_id, version))
            if (r.device_id == kv.first && r.state == ReplicaState::COMMITTED) committed = true;
        if (!committed) continue;
        AuditReport ar = replicator_.audit_replica(*kv.second, kv.first, file_id, version);
        if (audited) (*audited)++;
        if (!ar.ok && failed) (*failed)++;
    }
}

bool DropEngine::move_back(const std::string& intent_id, const std::string& local_path) {
    if (fsutil::exists_nofollow(local_path)) return false;   // never overwrite whatever is there now
    if (rename(quarantine_object(intent_id).c_str(), local_path.c_str()) != 0) return false;
    fsutil::sync_dir(fsutil::parent_of(local_path));
    fsutil::sync_dir(quarantine_dir(intent_id));
    return true;
}

void DropEngine::remove_quarantine(const std::string& intent_id) {
    std::string dir = quarantine_dir(intent_id);
    unlink(quarantine_object(intent_id).c_str());
    unlink((dir + "/meta").c_str());
    unlink((dir + "/meta.tmp").c_str());
    rmdir(dir.c_str());
    fsutil::sync_dir(qroot_);
}

// ---------------------------------------------------------------- drop

DropOutcome DropEngine::drop(const std::string& file_id, const std::string& consent_id, const DeviceMap& devices, FileGate* gate) {
    DropOutcome out;
    auto fail = [&](const std::string& why) { out.ok = false; out.why = why; return out; };
    auto step = [&](const char* n) { if (on_step) on_step(n); };

    auto file = ledger_.get_file(file_id);
    if (!file) return fail("unknown file");
    if (file->state != FileState::REPLICATED) return fail(std::string("file is ") + to_string(file->state) + ", not REPLICATED");
    if (!file->local_present || file->current_version <= 0) return fail("there are no local bytes to drop");
    const int64_t version = file->current_version;
    const std::string local = resolve_(*file);

    // 1. keep writers away for the whole operation
    struct Unfreezer {
        FileGate* g;
        const FileRec* f;
        bool on = false;
        ~Unfreezer() { if (on && g) g->unfreeze(*f); }
    } unfreezer{gate, &*file};
    if (gate) {
        std::string why;
        if (!gate->freeze(*file, &why)) return fail("cannot freeze the file: " + why);
        unfreezer.on = true;
    }
    step("frozen");

    // 2. the local bytes must STILL be the replicated version: this is what we are about to move out of the way
    Check chk = check_against_plan(local, file_id, version);
    if (!chk.ok) {
        if (chk.mismatch) {
            out.file_changed = true;
            ledger_.note_local_modified(file_id, static_cast<uint64_t>(chk.snap.size), chk.snap.mtime_s);   // nothing prepared for the old bytes may be used
        }
        return fail("local verification failed: " + chk.why);
    }
    step("local_verified");

    // 3. fresh evidence from the devices
    audit_all(devices, file_id, version, &out.replicas_audited, &out.audits_failed);
    step("audited");

    // 4. the ledger decides, in one transaction, whether every rule holds
    auto cur = ledger_.get_file(file_id);
    if (!cur) return fail("unknown file");
    Res bd = ledger_.begin_drop(file_id, version, cur->generation, consent_id, policy_.min_weight, policy_.max_audit_age);
    if (!bd) return fail("the ledger refused the drop: " + bd.why);
    const std::string intent = bd.id;
    out.intent_id = intent;

    // From here the ledger says DROPPING. Any failure before the rename must undo that.
    auto undo = [&](const std::string& why) {
        remove_quarantine(intent);
        ledger_.abort_drop(intent, why);
        return fail(why);
    };

    // 5. prepare the quarantine: same volume (rename must be atomic), durable directory, a note saying what this is
    if (int e = fsutil::make_dir_durable(qroot_)) return undo(std::string("cannot create the quarantine area: ") + strerror(e));
    struct stat qst, lst;
    if (stat(qroot_.c_str(), &qst) != 0 || stat(fsutil::parent_of(local).c_str(), &lst) != 0 || qst.st_dev != lst.st_dev)
        return undo("the quarantine area is on a different volume from the file (a rename could not be atomic)");
    if (int e = fsutil::make_dir_durable(quarantine_dir(intent))) return undo(std::string("cannot create the quarantine directory: ") + strerror(e));
    {
        // A plain text note beside the bytes, so that even without the ledger a human can tell what this is.
        std::string meta = "tierfs quarantine\nintent=" + intent + "\nfile_id=" + file_id + "\nlogical_path=" + file->path +
                           "\nlocal_path=" + local + "\nversion=" + std::to_string(version) + "\ngeneration=" + std::to_string(cur->generation) +
                           "\nsize=" + std::to_string(chk.snap.size) + "\n";
        if (int e = fsutil::durable_write(quarantine_dir(intent) + "/meta", meta)) return undo(std::string("cannot write the quarantine note: ") + strerror(e));
    }
    crash_point("drop.after_meta");

    // 6. the file must be exactly what we verified: not rewritten, not replaced, in the time since
    step("before_rename");
    Snap now;
    if (!snap_of_path(local, &now) || !same(now, chk.snap)) {
        out.file_changed = true;
        DropOutcome r = undo("the file was modified after it was verified; not dropped");   // withdraw the drop FIRST: a file mid-drop cannot be marked modified
        struct stat s2;
        if (fsutil::is_regular_nofollow(local, &s2)) ledger_.note_local_modified(file_id, static_cast<uint64_t>(s2.st_size), s2.st_mtimespec.tv_sec);
        return r;
    }

    // 7. the move. One atomic rename, then make it durable (both directories).
    if (rename(local.c_str(), quarantine_object(intent).c_str()) != 0) return undo(std::string("cannot move the file into quarantine: ") + strerror(errno));
    crash_point("drop.after_rename");
    fsutil::sync_dir(fsutil::parent_of(local));
    fsutil::sync_dir(quarantine_dir(intent));
    crash_point("drop.after_sync");

    // 8. record it. If the ledger now refuses (its evidence went stale, say), the bytes go back.
    Res cd = ledger_.complete_drop(intent);
    if (!cd) {
        std::string why = "the ledger refused to complete the drop (" + cd.why + ")";
        if (!move_back(intent, local)) {
            out.why = why + "; AND the bytes could not be moved back: they are in " + quarantine_object(intent) + " (see recover())";
            return out;
        }
        remove_quarantine(intent);
        ledger_.abort_drop(intent, why);
        return fail(why + "; the bytes were restored");
    }
    out.ok = true;
    return out;
}

// ---------------------------------------------------------------- purge

PurgeOutcome DropEngine::purge(const std::string& intent_id, const DeviceMap& devices, bool emergency) {
    PurgeOutcome out;
    auto fail = [&](const std::string& why) { out.ok = false; out.why = why; return out; };
    auto q = ledger_.get_quarantine(intent_id);
    if (!q) return fail("no such quarantine");
    if (q->state != QuarantineState::HELD && q->state != QuarantineState::PURGING)
        return fail(std::string("quarantine is ") + to_string(q->state));

    // Deleting the quarantine is the LAST chance to undo the drop: prove the replicas are good right now.
    audit_all(devices, q->file_id, q->version, &out.replicas_audited, &out.audits_failed);
    Res bp = ledger_.begin_purge(intent_id, policy_.quarantine_seconds, emergency, policy_.min_weight, policy_.max_audit_age);
    if (!bp) return fail("the ledger refused the purge: " + bp.why);
    crash_point("purge.after_begin");
    remove_quarantine(intent_id);
    crash_point("purge.after_unlink");
    Res cp = ledger_.complete_purge(intent_id);
    if (!cp) return fail("the bytes are deleted but the ledger could not record it: " + cp.why);
    out.ok = true;
    return out;
}

// ---------------------------------------------------------------- restore

RestoreOutcome DropEngine::restore(const std::string& intent_id, const std::string& reason) {
    RestoreOutcome out;
    auto fail = [&](const std::string& why) { out.ok = false; out.why = why; return out; };
    auto q = ledger_.get_quarantine(intent_id);
    if (!q) return fail("no such quarantine");
    auto file = ledger_.get_file(q->file_id);
    if (!file) return fail("unknown file");
    const std::string local = resolve_(*file);

    Res br = ledger_.begin_restore(intent_id, reason);
    if (!br) return fail("the ledger refused the restore: " + br.why);
    crash_point("restore.after_begin");
    if (!fsutil::exists_nofollow(quarantine_object(intent_id))) return fail("the quarantined bytes are missing; the restore is recorded but not done");
    if (fsutil::exists_nofollow(local)) return fail("the original path is occupied; resolve it by hand (the restore stays recorded as in progress)");
    // The bytes we are bringing back may be the only good copy; say honestly whether they still match.
    Check chk = check_against_plan(quarantine_object(intent_id), q->file_id, q->version);
    out.bytes_verified = chk.ok;
    if (!move_back(intent_id, local)) return fail(std::string("cannot move the bytes back: ") + strerror(errno));
    crash_point("restore.after_rename");
    remove_quarantine(intent_id);
    Res cr = ledger_.complete_restore(intent_id, chk.ok);
    if (!cr) return fail("the bytes are back but the ledger could not record it: " + cr.why);
    out.ok = true;
    return out;
}

// ---------------------------------------------------------------- recovery

RecoveryReport DropEngine::recover(const DeviceMap& devices) {
    RecoveryReport rep;
    auto action = [&](const std::string& s) { rep.actions.push_back(s); };
    auto problem = [&](const std::string& s) { rep.problems.push_back(s); };

    // ---- drops that were in flight ----
    for (const auto& in : ledger_.open_intents()) {
        if (in.kind != "DROP_LOCAL") continue;
        auto file = ledger_.get_file(in.file_id);
        if (!file) { problem("intent " + in.intent_id + ": unknown file"); continue; }
        const std::string local = resolve_(*file);
        const bool at_origin = fsutil::exists_nofollow(local);
        const bool in_quarantine = fsutil::exists_nofollow(quarantine_object(in.intent_id));
        const std::string label = file->path + " (intent " + in.intent_id.substr(0, 8) + ")";

        if (at_origin && !in_quarantine) {
            // The move never happened. Undo the ledger's claim, and make sure nobody wrote to the file meanwhile.
            remove_quarantine(in.intent_id);
            ledger_.abort_drop(in.intent_id, "recovered after a crash before the move");
            Check chk = check_against_plan(local, in.file_id, in.version);
            if (chk.mismatch) {
                ledger_.note_local_modified(in.file_id, static_cast<uint64_t>(chk.snap.size), chk.snap.mtime_s);
                action(label + ": drop abandoned; the file had been modified, marked LOCAL");
            } else if (!chk.ok) {
                problem(label + ": drop abandoned, but the local file could not be verified: " + chk.why);
            } else {
                action(label + ": drop abandoned; the bytes never left");
            }
        } else if (!at_origin && in_quarantine) {
            // Moved. Finish the ledger side if the replicas still prove out; otherwise put the bytes back.
            size_t audited = 0, failed = 0;
            audit_all(devices, in.file_id, in.version, &audited, &failed);
            Res cd = ledger_.complete_drop(in.intent_id);
            if (cd) {
                action(label + ": drop completed (bytes are in quarantine, replicas verified)");
            } else if (move_back(in.intent_id, local)) {
                remove_quarantine(in.intent_id);
                ledger_.abort_drop(in.intent_id, "recovered after a crash: " + cd.why);
                action(label + ": replicas no longer sufficient, bytes restored (" + cd.why + ")");
            } else {
                problem(label + ": cannot complete (" + cd.why + ") and cannot move the bytes back; they are in " + quarantine_object(in.intent_id));
            }
        } else if (at_origin && in_quarantine) {
            problem(label + ": the file exists BOTH at its original path and in quarantine; refusing to guess");
        } else {
            // Gone from both places. The only safe conclusion is one the replicas can vouch for.
            size_t audited = 0, failed = 0;
            audit_all(devices, in.file_id, in.version, &audited, &failed);
            Res cd = ledger_.complete_drop(in.intent_id);
            if (cd) problem(label + ": the local bytes are GONE from both places, but the replicas verify; recorded as OFFLOADED");
            else problem(label + ": the local bytes are GONE and the replicas cannot be verified (" + cd.why + "): possible DATA LOSS");
        }
    }

    // ---- quarantines that were mid-purge, mid-restore, or just held ----
    for (const auto& q : ledger_.list_quarantine()) {
        auto file = ledger_.get_file(q.file_id);
        if (!file) continue;
        const std::string local = resolve_(*file);
        const bool at_origin = fsutil::exists_nofollow(local);
        const bool in_quarantine = fsutil::exists_nofollow(quarantine_object(q.intent_id));
        const std::string label = file->path + " (intent " + q.intent_id.substr(0, 8) + ")";
        switch (q.state) {
            case QuarantineState::PURGING:
                remove_quarantine(q.intent_id);
                if (ledger_.complete_purge(q.intent_id)) action(label + ": interrupted purge finished");
                else problem(label + ": the purge could not be recorded");
                break;
            case QuarantineState::RESTORING:
                if (in_quarantine && !at_origin) {
                    Check chk = check_against_plan(quarantine_object(q.intent_id), q.file_id, q.version);
                    if (move_back(q.intent_id, local)) {
                        remove_quarantine(q.intent_id);
                        if (ledger_.complete_restore(q.intent_id, chk.ok)) action(label + ": interrupted restore finished");
                        else problem(label + ": the bytes are back but the restore could not be recorded");
                    } else {
                        problem(label + ": cannot move the bytes back");
                    }
                } else if (at_origin && !in_quarantine) {
                    Check chk = check_against_plan(local, q.file_id, q.version);
                    remove_quarantine(q.intent_id);
                    if (ledger_.complete_restore(q.intent_id, chk.ok)) action(label + ": restore had already moved the bytes; recorded");
                    else problem(label + ": the restore could not be recorded");
                } else {
                    problem(label + (at_origin ? ": bytes exist both in quarantine and at the original path" : ": restore in progress but the bytes are in neither place"));
                }
                break;
            case QuarantineState::HELD:
                if (!in_quarantine) problem(label + ": quarantined bytes are missing");
                break;
            default:
                break;
        }
    }
    return rep;
}

}  // namespace tierfs
