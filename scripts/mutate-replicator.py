#!/usr/bin/env python3
"""Mutation test for core/replicator.cpp: remove one protection at a time and check that
tests/replicator_test.cpp (and its crash-injection helper) notice. Each run of the suite takes
about a minute, so run in batches:  mutate-replicator.py <name filter ...>
Tags: [defensive] = guards a state the real device cannot produce; expected to survive, see notes."""
import subprocess, sys, os, shutil
R = 'core/replicator.cpp'
M = [
 # --- who we talk to ---
 ('trust a suspect device', R, 'if (dr->state != "active") return fail("device is " + dr->state + "; reconcile it first");', '', 0),
 ('any device answering at the address', R, 'if (info.device_id != device_id) return fail("this is not the device the ledger expects");', '', 0),
 ('rolled-back device still used', R, 'if (obs == DeviceObservation::Rollback || obs == DeviceObservation::EpochChanged)', 'if (false)', 0),
 ('symlinks followed', R, 'O_RDONLY | O_NOFOLLOW', 'O_RDONLY', 0),
 ('no manifest size guard', R, 'if (n * 80 > MAX_MANIFEST_BLOB - (1u << 20)) return fail("file is too large for one manifest (protocol v3 limit)");', '', 0),
 # --- the file must not change under us ---
 ('pass-1 change check removed', R, 'if (!same(s0, s1)) return changed("the file was modified while it was being read");', '', 0),
 ('pass-2 size check removed', R, 'if (static_cast<uint64_t>(s2.size) != fr->size) return changed("the file\'s size differs from the plan");', '', 0),
 ('pass-2 chunk id check removed', R, 'if (crypto::chunk_id(keys_, buf.data(), buf.size()) != rec.chunk_id) return changed(', 'if (false) return changed(', 0),
 ('pass-2 blob hash check removed', R, '|| crypto::sha256_hex(blob.data(), blob.size()) != rec.blob_sha256) return changed(', '|| false) return changed(', 0),
 ('final change check removed', R, 'if (!same(s2, s3)) return changed("the file was modified while it was being uploaded");', '', 0),
 # --- verifying the device ---
 ('existing chunks trusted unaudited', R, 'if (present || sample.count(idx)) {', 'if (!present && sample.count(idx)) {', 0),
 ('uploaded chunks never sampled', R, 'if (present || sample.count(idx)) {', 'if (present) {', 0),
 ('audit failures ignored', R, 'if (!bad.empty()) {', 'if (false) {', 0),
 ('conflicting existing chunk accepted', R, 'if (pr.sha256_hex != rec.blob_sha256) {', 'if (false) {', 0),
 ('conflicting manifest accepted', R, 'if (mr.sha256_hex != msha) {', 'if (false) {', 0),
 ('manifest audit skipped', R, 'if (!mb.empty()) {', 'if (false) {', 0),
 ('failed audit does not condemn replica', R, 'ledger_.set_replica(file_id, version, device_id, ReplicaState::MISSING);\n        return fail("the device failed its audit: "', ';\n        return fail("the device failed its audit: "', 0),
 # --- bookkeeping ---
 ('challenge pools not created', R, 'if (left < opt_.challenges_per_chunk)\n                ledger_.add_challenges(file_id, version, static_cast<int64_t>(idx),', 'if (false)\n                ledger_.add_challenges(file_id, version, static_cast<int64_t>(idx),', 0),
 ('manifest challenges not created', R, 'if (left < opt_.challenges_per_chunk)\n            ledger_.add_challenges(file_id, version, MANIFEST_CHALLENGE_IDX,', 'if (false)\n            ledger_.add_challenges(file_id, version, MANIFEST_CHALLENGE_IDX,', 0),
 ('manifest hash not recorded', R, 'Res hr = ledger_.set_manifest_hash(file_id, version, msha);', 'Res hr{true, "", ""};', 0),
 ('xattrs dropped', R, 'm.xattrs.emplace_back(name, std::move(value));', '(void)name;', 0),
 ('committed replica not recognised', R, 'if (r.device_id == device_id && r.state == ReplicaState::COMMITTED) {', 'if (false) {', 0),
 ('resume does not finish the file', R, 'if (state == FileState::REPLICATING) {\n                    Res f = ledger_.finish_replication(file_id, version);', 'if (false) {\n                    Res f = ledger_.finish_replication(file_id, version);', 0),
 # --- audits ---
 ('audit answers not compared', R, 'else if (outs[i].response_hex != e.response)', 'else if (false)', 0),
 ('used-up pool not refetched', R, 'if (!ch) { refetch.push_back(c.idx); continue; }', 'if (!ch) { continue; }', 0),
 ('refetched blob not verified', R, 'if (crypto::open_chunk(keys_, volume_, c.chunk_id, blob.data(), blob.size(), plain) != crypto::OpenError::Ok ||\n            crypto::sha256_hex(blob.data(), blob.size()) != c.blob_sha256) {', 'if (false) {', 0),
 # --- reconcile ---
 ('different manifest adopted', R, 'if (*expected != e.sha256_hex) {', 'if (false) {', 0),
 ('lost manifests not noticed', R, 'if (!on_dev.count({r.file_id, r.version})) {', 'if (false) {', 0),
 ('suspect device never cleared', R, 'if (suspect && rep.audit_failed == 0) {', 'if (false) {', 0),
 ('suspect cleared despite failures', R, 'if (suspect && rep.audit_failed == 0) {', 'if (suspect) {', 0),
 ('suspect device not audited', R, 'if (suspect || deep) {', 'if (deep) {', 0),
 ('[defensive] chunk presence not checked', R, 'if (!ids.empty() && dev.has_chunks(ids, have).ok() && have.size() == ids.size()) {', 'if (false) {', 0),
 # --- recall ---
 ('whole-file check removed', R, 'if (fh.finish_hex() != m.file_hmac) return Res{', 'if (false) return Res{', 0),
 ('total size not checked', R, 'if (total != m.size) return Res{', 'if (false) return Res{', 0),
 ('chunk length not checked', R, 'if (plain.size() != c.len) return Res{', 'if (false) return Res{', 0),
 ('chunk crash points removed', R, 'crash_point("repl.before_manifest");', '', 0),
 ('after-manifest crash point removed', R, 'crash_point("repl.after_manifest_put");', '', 0),
]
OS = os.environ.get('OPENSSL_DIR', '/opt/homebrew/opt/openssl@3')
CRYPTO = f'{OS}/lib/libcrypto.a'
BASE = ['c++', '-std=c++17', '-g', '-w', f'-I{OS}/include', '-Icore', '-Itests']
D = 'build/mutr'
def run(cmd, **kw): return subprocess.run(cmd, capture_output=True, text=True, **kw)
def sh(cmd):
    r = run(cmd)
    if r.returncode: sys.exit('build failed: ' + ' '.join(cmd) + '\n' + r.stderr[-500:])
os.makedirs(D, exist_ok=True)
for src, out in [('core/crypto.cpp', 'crypto.o'), ('core/ledger.cpp', 'ledger.o'), ('core/deviceclient.cpp', 'deviceclient.o'), ('core/devicestore.cpp', 'devicestore.o'),
                 ('tests/replicator_test.cpp', 'replicator_test.o'), ('tests/repl_helper.cpp', 'repl_helper.o')]:
    sh(BASE + ['-c', src, '-o', f'{D}/{out}'])
OBJS = ['ledger.o', 'deviceclient.o', 'devicestore.o', 'crypto.o']
filters = sys.argv[1:]
survivors, expected = [], []
for name, path, frm, to, nth in M:
    if filters and not any(f in name for f in filters): continue
    src = open(path).read()
    idx = -1
    for _ in range(nth + 1):
        idx = src.find(frm, idx + 1)
        if idx < 0: break
    if idx < 0:
        print(f'{name:<42} !! pattern not found (stale)'); survivors.append(name + ' (stale)'); continue
    open(f'{D}/mut.cpp', 'w').write(src[:idx] + to + src[idx + len(frm):])
    r = run(BASE + ['-c', f'{D}/mut.cpp', '-o', f'{D}/mut.o'])
    if r.returncode: print(f'{name:<42} (does not compile: {r.stderr.strip().splitlines()[-1][:60]})'); continue
    for out, first in [('mut_test', 'replicator_test.o'), ('mut_helper', 'repl_helper.o')]:
        sh(['c++', '-o', f'{D}/{out}', f'{D}/{first}', f'{D}/mut.o'] + [f'{D}/{o}' for o in OBJS] + [CRYPTO, '-lsqlite3', '-framework', 'CoreFoundation'])
    env = dict(os.environ, TIERFS_REPL_HELPER=f'./{D}/mut_helper')
    def execute():
        subprocess.run(['pkill', '-f', 'tierfs-device'])
        try:
            p = subprocess.run([f'{D}/mut_test'], capture_output=True, text=True, timeout=400, env=env)
            out, rc = p.stdout, p.returncode
        except subprocess.TimeoutExpired:
            out, rc = 'FAIL timeout', 99
        subprocess.run(['pkill', '-f', 'tierfs-device'])
        return out, rc, sum(1 for l in out.splitlines() if l.startswith('FAIL'))
    out, rc, n = execute()
    if n == 0 and rc != 0:
        # Killed only by a crash, with no failing check: could be a flaky crash hiding a survivor. Ask again.
        out2, rc2, n2 = execute()
        print(f'   (first run crashed with {rc}; rerun: {"failing checks=%d" % n2 if n2 else "exit %d" % rc2})')
        out, rc, n = out2, rc2, n2
    killed = n > 0 or rc != 0
    how = ('%d failing checks' % n) if n else ('exit code %d' % rc)
    if name.startswith('[defensive]'):
        print(f'{name:<42} {"killed by " + how if killed else "SURVIVED  (defensive: guards a state a real device cannot produce)"}')
        if not killed: expected.append(name)
    else:
        print(f'{name:<42} {"killed by " + how if killed else "SURVIVED  <-- test gap"}')
        if not killed: survivors.append(name)
shutil.rmtree(D, ignore_errors=True)
print('survivors:', survivors if survivors else 'none', ('| defensive survivors: %d' % len(expected)) if expected else '')
