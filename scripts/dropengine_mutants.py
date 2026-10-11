# Mutants for core/dropengine.cpp (loaded by mutate-dropengine.py). Raw strings: what you see is the source.
# Tags: [power-loss] needs a power cut to observe; [needs-second-volume] needs a second filesystem;
#       [redundant] a guard that a second, independent guard also covers (expected to survive alone).
D = 'core/dropengine.cpp'
M = [
 ("local verification skipped", D,
  r'''    Check chk = check_against_plan(local, file_id, version);
    if (!chk.ok) {''',
  r'''    Check chk = check_against_plan(local, file_id, version);
    if (false) {'''),
 ("local modification not reported to the ledger", D,
  r'''            ledger_.note_local_modified(file_id, static_cast<uint64_t>(chk.snap.size), chk.snap.mtime_s);   // nothing prepared for the old bytes may be used''',
  ''),
 ("no fresh audits before dropping", D,
  r'''    audit_all(devices, file_id, version, &out.replicas_audited, &out.audits_failed);
    step("audited");''',
  r'''    step("audited");'''),
 ("freeze result ignored", D,
  r'''if (!gate->freeze(*file, &why)) return fail("cannot freeze the file: " + why);''',
  r'''gate->freeze(*file, &why);'''),
 ("never unfreezes", D,
  r'''~Unfreezer() { if (on && g) g->unfreeze(*f); }''',
  r'''~Unfreezer() {}'''),
 ("no identity check before the move", D,
  r'''if (!snap_of_path(local, &now) || !same(now, chk.snap)) {''',
  r'''if (false) {'''),
 ("identity ignores the modification time", D,
  r'''return a.size == b.size && a.mtime_s == b.mtime_s && a.mtime_ns == b.mtime_ns && a.ino == b.ino && a.dev == b.dev;''',
  r'''return a.size == b.size && a.ino == b.ino && a.dev == b.dev;'''),
 ("identity ignores the inode", D,
  r'''return a.size == b.size && a.mtime_s == b.mtime_s && a.mtime_ns == b.mtime_ns && a.ino == b.ino && a.dev == b.dev;''',
  r'''return a.size == b.size && a.mtime_s == b.mtime_s && a.mtime_ns == b.mtime_ns;'''),
 ("quarantine note not written", D,
  r'''if (int e = fsutil::durable_write(quarantine_dir(intent) + "/meta", meta)) return undo(std::string("cannot write the quarantine note: ") + strerror(e));''',
  ''),
 ("file DELETED instead of moved", D,
  r'''if (rename(local.c_str(), quarantine_object(intent).c_str()) != 0) return undo(std::string("cannot move the file into quarantine: ") + strerror(errno));''',
  r'''if (unlink(local.c_str()) != 0) return undo(std::string("cannot move the file into quarantine: ") + strerror(errno));'''),
 ("bytes not put back when the ledger refuses", D,
  r'''if (!move_back(intent, local)) {
            out.why = why''',
  r'''if (false && !move_back(intent, local)) {
            out.why = why'''),
 ("withdrawn drop not recorded", D,
  r'''        remove_quarantine(intent);
        ledger_.abort_drop(intent, why);
        return fail(why);''',
  r'''        remove_quarantine(intent);
        return fail(why);'''),
 ("file marked modified before the drop is withdrawn", D,
  r'''        DropOutcome r = undo("the file was modified after it was verified; not dropped");   // withdraw the drop FIRST: a file mid-drop cannot be marked modified
        struct stat s2;
        if (fsutil::is_regular_nofollow(local, &s2)) ledger_.note_local_modified(file_id, static_cast<uint64_t>(s2.st_size), s2.st_mtimespec.tv_sec);
        return r;''',
  r'''        struct stat s2;
        if (fsutil::is_regular_nofollow(local, &s2)) ledger_.note_local_modified(file_id, static_cast<uint64_t>(s2.st_size), s2.st_mtimespec.tv_sec);
        DropOutcome r = undo("the file was modified after it was verified; not dropped");
        return r;'''),
 ("verify only the first chunk", D,
  r'''    for (const auto& ch : chunks) {
        if (!read_at(fd, static_cast<uint64_t>(ch.idx) * REPL_CHUNK, ch.len, buf)) {''',
  r'''    for (const auto& ch : std::vector<ChunkRec>(chunks.begin(), chunks.begin() + std::min<size_t>(1, chunks.size()))) {
        if (!read_at(fd, static_cast<uint64_t>(ch.idx) * REPL_CHUNK, ch.len, buf)) {'''),
 ("local size not compared", D,
  r'''if (static_cast<uint64_t>(c.snap.size) != expected) {''',
  r'''if (false) {'''),
 ("[redundant] chunk id not compared (the blob hash covers it)", D,
  r'''if (crypto::chunk_id(keys_, buf.data(), buf.size()) != ch.chunk_id) {''',
  r'''if (false) {'''),
 ("[redundant] blob hash not compared (the chunk id covers it)", D,
  r'''if (blob.empty() || crypto::sha256_hex(blob.data(), blob.size()) != ch.blob_sha256) {''',
  r'''if (blob.empty()) {'''),
 ("[redundant] engine does not check REPLICATED (the ledger does)", D,
  r'''if (file->state != FileState::REPLICATED) return fail(std::string("file is ") + to_string(file->state) + ", not REPLICATED");''',
  ''),
 ("quarantine on another volume allowed", D,
  r'''qst.st_dev != lst.st_dev''',
  r'''false'''),
 ("[power-loss] directories not synced after the move", D,
  r'''    fsutil::sync_dir(fsutil::parent_of(local));
    fsutil::sync_dir(quarantine_dir(intent));
    crash_point("drop.after_sync");''',
  r'''    crash_point("drop.after_sync");'''),
 ("drop crash point after_meta removed", D, r'''crash_point("drop.after_meta");''', ''),
 ("drop crash point after_rename removed", D, r'''crash_point("drop.after_rename");''', ''),
 ("drop crash point after_sync removed", D, r'''crash_point("drop.after_sync");''', ''),
 ("recovery: bytes that never left are not handled", D,
  r'''if (at_origin && !in_quarantine) {
            // The move never happened.''',
  r'''if (false) {
            // The move never happened.'''),
 ("recovery: moved bytes are not handled", D,
  r'''} else if (!at_origin && in_quarantine) {''',
  r'''} else if (false) {'''),
 ("recovery completes a drop on old evidence", D,
  r'''            size_t audited = 0, failed = 0;
            audit_all(devices, in.file_id, in.version, &audited, &failed);
            Res cd = ledger_.complete_drop(in.intent_id);
            if (cd) {
                action(label + ": drop completed''',
  r'''            size_t audited = 0, failed = 0;
            Res cd = ledger_.complete_drop(in.intent_id);
            if (cd) {
                action(label + ": drop completed'''),
 ("recovery: bytes in both places not flagged", D,
  r'''} else if (at_origin && in_quarantine) {''',
  r'''} else if (false) {'''),
 ("purge without fresh audits", D,
  r'''    audit_all(devices, q->file_id, q->version, &out.replicas_audited, &out.audits_failed);
    Res bp''',
  r'''    Res bp'''),
 ("purge deletes before the ledger agrees", D,
  r'''    Res bp = ledger_.begin_purge(intent_id, policy_.quarantine_seconds, emergency, policy_.min_weight, policy_.max_audit_age);
    if (!bp) return fail("the ledger refused the purge: " + bp.why);
    crash_point("purge.after_begin");
    remove_quarantine(intent_id);''',
  r'''    remove_quarantine(intent_id);
    Res bp = ledger_.begin_purge(intent_id, policy_.quarantine_seconds, emergency, policy_.min_weight, policy_.max_audit_age);
    if (!bp) return fail("the ledger refused the purge: " + bp.why);
    crash_point("purge.after_begin");'''),
 ("purge crash point after_begin removed", D, r'''crash_point("purge.after_begin");''', ''),
 ("purge crash point after_unlink removed", D, r'''crash_point("purge.after_unlink");''', ''),
 ("restore skips the ledger's go-ahead", D,
  r'''    Res br = ledger_.begin_restore(intent_id, reason);
    if (!br) return fail("the ledger refused the restore: " + br.why);''',
  ''),
 ("restored bytes always called verified", D,
  r'''Res cr = ledger_.complete_restore(intent_id, chk.ok);''',
  r'''Res cr = ledger_.complete_restore(intent_id, true);'''),
 ("restore crash point after_begin removed", D, r'''crash_point("restore.after_begin");''', ''),
 ("restore crash point after_rename removed", D, r'''crash_point("restore.after_rename");''', ''),
 ("recovery: interrupted restore not finished", D,
  r'''                if (in_quarantine && !at_origin) {
                    Check chk''',
  r'''                if (false) {
                    Check chk'''),
 ("recovery: interrupted purge not finished", D,
  r'''            case QuarantineState::PURGING:
                remove_quarantine(q.intent_id);''',
  r'''            case QuarantineState::PURGING:'''),
 ("[redundant] restore does not check for an occupied path (move_back does)", D,
  r'''if (fsutil::exists_nofollow(local)) return fail("the original path is occupied; resolve it by hand (the restore stays recorded as in progress)");''',
  ''),
 ("[redundant] move_back may overwrite (restore checks first)", D,
  r'''if (fsutil::exists_nofollow(local_path)) return false;   // never overwrite whatever is there now''',
  ''),
]
