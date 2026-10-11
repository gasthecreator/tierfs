# Mutants for the quarantine / purge / restore rules in core/ledger.cpp (loaded by mutate-ledger.py).
# Each entry: (name, text to find, replacement). Raw strings: what you see is what is in the source.
M3E = [
 ("[3e] purge without recovery ack",
  r'''if (get_meta("recovery_acked").value_or("") != "1") return fail("recovery phrase not acknowledged");
    if (!has_reserve()) return fail("ledger reserve missing (disk-full safety)");
    if (min_weight <= 0 || max_audit_age <= 0 || retention_seconds < 0)''',
  r'''if (!has_reserve()) return fail("ledger reserve missing (disk-full safety)");
    if (min_weight <= 0 || max_audit_age <= 0 || retention_seconds < 0)'''),
 ("[3e] purge without reserve",
  r'''if (get_meta("recovery_acked").value_or("") != "1") return fail("recovery phrase not acknowledged");
    if (!has_reserve()) return fail("ledger reserve missing (disk-full safety)");
    if (min_weight <= 0 || max_audit_age <= 0 || retention_seconds < 0)''',
  r'''if (get_meta("recovery_acked").value_or("") != "1") return fail("recovery phrase not acknowledged");
    if (min_weight <= 0 || max_audit_age <= 0 || retention_seconds < 0)'''),
 ("[3e] purge policy unchecked",
  r'''if (min_weight <= 0 || max_audit_age <= 0 || retention_seconds < 0) return fail("policy must require a positive replica weight and a finite audit age");''',
  ''),
 ("[3e] purge without backup gate",
  r'''if (!f) return fail("unknown file");
    if (get_meta("backup_acked").value_or("") != "1") {
        std::string pre = get_meta("test_prefix").value_or("");
        if (pre.empty() || f->path.compare(0, pre.size(), pre) != 0)
            return fail("backup not acknowledged and path is outside the test prefix");
    }
    // AT_RISK''',
  r'''if (!f) return fail("unknown file");
    // AT_RISK'''),
 ("[3e] purge of AT_RISK file allowed",
  r'''if (f->state != FileState::OFFLOADED && f->state != FileState::REPLICATED)
        return fail(std::string("file is ") + to_string(f->state) + "; restore the quarantined bytes instead of deleting them");''',
  ''),
 ("[3e] retention ignored",
  r'''if (!emergency && now() - q->held_at < retention_seconds) return fail("the quarantine period has not elapsed");''',
  ''),
 ("[3e] emergency skips the evidence",
  r'''double w = replica_weight(q->file_id, q->version, max_audit_age);
    if (w < min_weight) {
        char buf[110];''',
  r'''double w = replica_weight(q->file_id, q->version, max_audit_age);
    if (!emergency && w < min_weight) {
        char buf[110];'''),
 ("[3e] purge weight unchecked",
  r'''if (w < min_weight) {
        char buf[110];''',
  r'''if (false) {
        char buf[110];'''),
 ("[3e] purge in any quarantine state",
  r'''if (q->state != QuarantineState::HELD && q->state != QuarantineState::PURGING)''',
  r'''if (false)'''),
 ("[3e] purge never recorded as begun",
  r'''UPDATE quarantine SET state='purging' WHERE intent_id=?1 AND state='held'");''',
  r'''UPDATE quarantine SET state='held' WHERE intent_id=?1 AND state='held'");'''),
 ("[3e] complete_purge from any state",
  r'''UPDATE quarantine SET state='purged', resolved_at=?2 WHERE intent_id=?1 AND state='purging'");''',
  r'''UPDATE quarantine SET state='purged', resolved_at=?2 WHERE intent_id=?1");'''),
 ("[3e] restore in any quarantine state",
  r'''if (q->state != QuarantineState::HELD && q->state != QuarantineState::RESTORING)''',
  r'''if (false)'''),
 ("[3e] restore for any file state",
  r'''if (f->state != FileState::OFFLOADED && f->state != FileState::AT_RISK)
        return fail(std::string("file is ") + to_string(f->state) + "; only OFFLOADED or AT_RISK files can be restored from quarantine");''',
  ''),
 ("[3e] unvouched bytes called REPLICATED",
  r'''bool as_replicated = bytes_verified && q->version == f->current_version && has_committed(db_, q->file_id, q->version);''',
  r'''bool as_replicated = true;'''),
 ("[3e] restore ignores verification",
  r'''bool as_replicated = bytes_verified && q->version''',
  r'''bool as_replicated = q->version'''),
 ("[3e] unvouched restore keeps generation",
  r'''local_present=1, generation=generation+1 WHERE file_id=?1 AND state=?2''',
  r'''local_present=1, generation=generation WHERE file_id=?1 AND state=?2'''),
 ("[3e] restore leaves bytes marked absent",
  r'''UPDATE files SET state='REPLICATED', prior_state=NULL, local_present=1''',
  r'''UPDATE files SET state='REPLICATED', prior_state=NULL, local_present=0'''),
 ("[3e] drop creates no quarantine",
  r'''Stmt qi(db_, "INSERT INTO quarantine(intent_id,file_id,version,state,held_at) VALUES(?1,?2,?3,'held',?4)");''',
  r'''Stmt qi(db_, "SELECT 1 WHERE ?1 IS NULL AND ?2 IS NULL AND ?3 IS NULL AND ?4 IS NULL");'''),
 ("[3e] resolved quarantine can change",
  r'''"CREATE TRIGGER quarantine_final BEFORE UPDATE ON quarantine WHEN OLD.state IN ('purged','restored')"
        " BEGIN SELECT RAISE(ABORT,'a resolved quarantine is final'); END",''',
  ''),
 ("[3e] purge crash point removed", r'''crash_point("ledger.purge.after_commit");''', ''),
 ("[3e] restore crash point removed", r'''crash_point("ledger.restore.before_commit");''', ''),
]
