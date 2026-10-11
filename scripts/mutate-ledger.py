#!/usr/bin/env python3
"""Mutation test for core/ledger.cpp: remove one safety rule at a time and confirm
tests/ledger_test.cpp notices. A mutant that SURVIVES is a hole in the tests."""
import subprocess, sys, os, shutil
MUTANTS = [
 ("skip recovery-phrase gate",     'if (get_meta("recovery_acked").value_or("") != "1") return fail("recovery phrase not acknowledged");', ''),
 ("skip backup gate",              'if (get_meta("backup_acked").value_or("") != "1") {', 'if (false) {'),
 ("skip reserve gate",             'if (!has_reserve()) return fail("ledger reserve missing (disk-full safety)");', ''),
 ("skip consent expiry",           'if (c.col_num(1) <= now()) return fail("consent expired");', ''),
 ("skip consent scope",            'if (f->path.compare(0, scope.size(), scope) != 0) return fail("consent does not cover this path");', ''),
 ("skip consent existence",        'if (!c.row()) return fail("no valid consent");', 'c.row();'),
 ("skip weight check (begin)",     'if (w < min_weight) {\n        char buf[96];\n        snprintf(buf, sizeof buf, "insufficient', 'if (false) {\n        char buf[96];\n        snprintf(buf, sizeof buf, "insufficient'),
 ("ignore audit age",              ' AND r.last_audit_at>0 AND r.last_audit_at>=?3"', '"'),
 ("count unaudited replicas",      ' AND r.last_audit_at>0 AND r.last_audit_at>=?3"', ' AND r.last_audit_at>=?3"'),
 ("skip generation compare",       'if (f->generation != generation) return fail("generation mismatch (file changed)");', ''),
 ("skip version compare",          'if (f->current_version != version || version <= 0) return fail("version mismatch");', ''),
 ("skip state==REPLICATED",        'if (f->state != FileState::REPLICATED) return fail(std::string("file is ") + to_string(f->state) + ", not REPLICATED");', ''),
 ("skip re-check at completion",   'if (w < min_weight) {\n        char buf[96];\n        snprintf(buf, sizeof buf, "replicas no longer', 'if (false) {\n        char buf[96];\n        snprintf(buf, sizeof buf, "replicas no longer'),
 ("count retired devices",         ' AND d.state=\'active\' AND r.last_audit_at>0', ' AND r.last_audit_at>0'),
 ("class C weighs 1.0",            "WHEN 'C' THEN 0.5 ELSE 1.0", "WHEN 'C' THEN 1.0 ELSE 1.0"),
 ("events rewritable",             '"CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,\'events are append-only\'); END",', ''),
 ("rows deletable",                '"CREATE TRIGGER files_no_delete BEFORE DELETE ON files BEGIN SELECT RAISE(ABORT,\'ledger rows are never deleted\'); END",', ''),
 ("fsck ignores hash mismatch",    'if (h != e.col_text(8)) report(', 'if (false) report('),
 ("fsck ignores broken chain",     'if (e.col_text(7) != prev) report(', 'if (false) report('),
 ("modification keeps generation", 'generation=generation+1, state=\'LOCAL\'', 'generation=generation, state=\'LOCAL\''),
 ("finish ignores generation",     'if (!g.row() || g.col_num(0) != f->generation) return fail("file changed since replication began");', ''),
 ("no AT_RISK on last replica lost (audit)", 'if (c.row() && c.col_num(0) == 0) {\n            Stmt m(db_, "UPDATE files SET prior_state=state, state=\'AT_RISK\' WHERE file_id=?1 AND state=\'OFFLOADED\'");\n            m.text(1, file_id).run();\n            append_event("file.at_risk", file_id, version, device_id, "last committed replica failed its audit");', 'if (false) {\n            Stmt m(db_, "UPDATE files SET prior_state=state, state=\'AT_RISK\' WHERE file_id=?1 AND state=\'OFFLOADED\'");\n            m.text(1, file_id).run();\n            append_event("file.at_risk", file_id, version, device_id, "last committed replica failed its audit");'),
 ("clear_at_risk without evidence", 'else return fail("no committed replica and no local bytes: cannot clear (the data may be lost)");', 'else to = "OFFLOADED";'),
 ("adopt skips version check",     'if (!v.row()) return fail("unknown file version (import its manifest first)");', ''),
 ("hydrate without replica",       'if (!has_committed(db_, file_id, f->current_version)) return fail("no committed replica to hydrate from");', ''),
 ("modification allowed while dropping", 'if (f->state == FileState::DROPPING || f->state == FileState::HYDRATING)\n        return fail(std::string("file is ") + to_string(f->state) + "; writers must wait");', ''),
 ("crash point A removed",         '    crash_point("ledger.drop.before_commit");\n', ''),
 ("crash point after-B removed",   '    crash_point("ledger.complete.after_commit");\n', ''),
 ("drop leaves state unchanged (txn A not atomic with intent)", 'append_event("drop.begin"', 'append_event("drop.begin2"'),
 ("COMMITTED without device seq",  'if (state == ReplicaState::COMMITTED && device_seq <= 0)\n        return fail("a COMMITTED replica needs the device\'s commit sequence number");', ''),
 ("chunk list unchecked",          'if (total != size) return fail("chunk lengths do not add up to the file size");', ''),
]
only = sys.argv[1:] 
src = open('core/ledger.cpp').read()
os.makedirs('build/mut', exist_ok=True)
survivors = []
for name, frm, to in MUTANTS:
    if only and not any(o in name for o in only): continue
    if frm not in src:
        print(f"{name:<52} !! pattern not found (mutant list is stale)"); survivors.append(name + " (stale)"); continue
    open('build/mut/ledger.cpp','w').write(src.replace(frm, to, 1))
    for h in ('ledger.hpp','sqlutil.hpp','hash.hpp','crashpoint.hpp','tierclient.h'):
        shutil.copy('core/'+h, 'build/mut/'+h)
    base = ['c++','-std=c++17','-g','-I','core','-Ibuild/mut']
    r = subprocess.run(base+['tests/ledger_test.cpp','build/mut/ledger.cpp','-o','build/mut/t','-lsqlite3'],capture_output=True,text=True)
    r2 = subprocess.run(base+['tests/ledger_helper.cpp','build/mut/ledger.cpp','-o','build/mut/helper','-lsqlite3'],capture_output=True,text=True)
    if r.returncode or r2.returncode:
        print(f"{name:<52} (does not compile: {(r.stderr or r2.stderr).splitlines()[0][:60]})"); continue
    env = dict(os.environ, TIERFS_HELPER='./build/mut/helper')
    try:
        p = subprocess.run(['build/mut/t'],capture_output=True,text=True,timeout=120,env=env)
        out, rc = p.stdout, p.returncode
    except subprocess.TimeoutExpired:
        out, rc = "FAIL timeout", 99
    n = sum(1 for l in out.splitlines() if l.startswith('FAIL'))
    # A mutant is killed if the test fails OR crashes. (A crash that prints no FAIL
    # line used to be miscounted as "survived", which hid a real flaky test.)
    killed = n > 0 or rc != 0
    how = ('%d failing checks' % n) if n else ('exit code %d' % rc)
    print(f"{name:<52} {'killed by ' + how if killed else 'SURVIVED  <-- test gap'}")
    if not killed: survivors.append(name)
shutil.rmtree('build/mut', ignore_errors=True)
print("survivors:", survivors if survivors else "none")
