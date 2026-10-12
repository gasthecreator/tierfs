#!/usr/bin/env python3
"""Tests of `tierctl init` and `tierctl ack-backup`: no mount, no devices. Drives the real binary through pipes."""
import os, re, shutil, stat, subprocess, sys, tempfile
TC = os.environ.get('TIERFS_TIERCTL', './build/tierctl')
fails = 0
def check(name, ok):
    global fails
    print(('PASS  ' if ok else 'FAIL  ') + name)
    if not ok: fails += 1
def run_init(ledger, key, answer):
    """answer(group_number, phrase_groups) -> text typed for that prompt"""
    p = subprocess.Popen([TC, 'init', ledger, key], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out = ''
    phrase = None
    while True:
        ch = p.stdout.read(1)
        if not ch: break
        out += ch
        if phrase is None:
            m = re.search(r'\n\n    ([^\n]+)\n\n', out)
            if m: phrase = m.group(1).strip().split('-')
        m = re.search(r'Type group (\d+) of the phrase: $', out)
        if m and phrase is not None:
            p.stdin.write(answer(int(m.group(1)), phrase) + '\n'); p.stdin.flush()
            out += '\n'
    err = p.stderr.read()
    p.wait()
    return p.returncode, out, err, phrase
def good(g, ph): return ph[g - 1]
def wrong(g, ph): return ph[g - 1][:-1] + ('A' if ph[g - 1][-1] != 'A' else 'B')

d = tempfile.mkdtemp(prefix='tierfs-inittest-')
try:
    L, K = d + '/ledger', d + '/keys/key'
    rc, out, err, phrase = run_init(L, K, wrong)
    check('a wrong group is refused and nothing is saved', rc == 1 and 'not group' in err and not os.path.exists(K) and not os.path.exists(L + '/ledger.db'))
    rc, out, err, phrase = run_init(L, K, lambda g, ph: '')
    check('an empty answer is refused and nothing is saved', rc == 1 and not os.path.exists(K) and not os.path.exists(L + '/ledger.db'))
    rc, out, err, phrase = run_init(L, K, good)
    check('the right groups create the volume', rc == 0 and 'Created volume' in out and os.path.exists(K) and os.path.exists(L + '/ledger.db'))
    check('the phrase has 16 groups of 5', phrase is not None and len(phrase) == 16 and all(len(x) == 5 for x in phrase))
    check('the key file is private (mode 0600) and holds 64 hex characters', stat.S_IMODE(os.stat(K).st_mode) == 0o600 and re.fullmatch(r'[0-9a-f]{64}\n', open(K).read()) is not None)
    check('the phrase is never written to disk', all('-'.join(phrase) not in open(os.path.join(r, f), 'rb').read().decode('latin1') for r, _, fs in os.walk(d) for f in fs if os.path.getsize(os.path.join(r, f)) < 5_000_000))
    st = subprocess.run([TC, 'ledger-status', L], capture_output=True, text=True)
    check('the ledger knows the phrase is acknowledged and no backup yet', 'recovery phrase acknowledged: yes' in st.stdout and 'backup acknowledged: NO' in st.stdout and 'consistency: ok' in st.stdout)
    rc, out, err, _ = run_init(L, d + '/other-key', good)
    check('init refuses an existing ledger and creates nothing', rc == 1 and 'already holds a ledger' in err and not os.path.exists(d + '/other-key'))
    rc, out, err, _ = run_init(d + '/ledger2', K, good)
    check('init refuses an existing key file and creates nothing', rc == 1 and 'already exists' in err and not os.path.exists(d + '/ledger2'))
    # ack-backup
    r = subprocess.run([TC, 'ack-backup', L], capture_output=True, text=True)
    check('ack-backup needs the exact statement', r.returncode == 2 and 'usage' in r.stderr)
    r = subprocess.run([TC, 'ack-backup', L, 'yes'], capture_output=True, text=True)
    check('ack-backup refuses a casual word', r.returncode == 2)
    r = subprocess.run([TC, 'ack-backup', d + '/nowhere', 'I-HAVE-A-BACKUP'], capture_output=True, text=True)
    check('ack-backup does not create a ledger', r.returncode == 1 and not os.path.exists(d + '/nowhere'))
    import time
    before = int(time.time())
    r = subprocess.run([TC, 'ack-backup', L, 'I-HAVE-A-BACKUP'], capture_output=True, text=True)
    st = subprocess.run([TC, 'ledger-status', L], capture_output=True, text=True)
    check('ack-backup records it, with the time', r.returncode == 0 and 'backup acknowledged: yes (recorded' in st.stdout and '0 day(s) ago' in st.stdout and 'EXPIRED' not in st.stdout)
    check('ack-backup tells the owner what the statement means', 'BEFORE this moment' in r.stdout and 'expires after 30 days' in r.stdout)
    import sqlite3
    con = sqlite3.connect(L + '/ledger.db'); at = int(con.execute("select value from meta where key='backup_acked_at'").fetchone()[0]); con.close()
    check('the stored time is now', before - 2 <= at <= int(time.time()) + 2)
    con = sqlite3.connect(L + '/ledger.db'); con.execute("update meta set value='1' where key='backup_acked_at'"); con.commit(); con.close()
    st = subprocess.run([TC, 'ledger-status', L], capture_output=True, text=True)
    check('an ancient statement shows as expired', 'EXPIRED' in st.stdout)
    con = sqlite3.connect(L + '/ledger.db'); con.execute("delete from meta where key='backup_acked_at'"); con.commit(); con.close()
    st = subprocess.run([TC, 'ledger-status', L], capture_output=True, text=True)
    check('a statement without a date is called out', 'NO DATE' in st.stdout)
    subprocess.run([TC, 'ack-backup', L, 'I-HAVE-A-BACKUP'], capture_output=True, text=True)
    # the key file really is the phrase's key: restore needs the phrase, so decoding must succeed against the same ledger's devices (checked by key length only here)
    r = subprocess.run([TC, 'check-phrase', K], input='-'.join(phrase) + '\n', capture_output=True, text=True)
    check('the phrase shown matches the key file', r.returncode == 0 and 'MATCHES' in r.stdout)
    r = subprocess.run([TC, 'check-phrase', K], input=' '.join(p.lower() for p in phrase) + '\n', capture_output=True, text=True)
    check('lowercase and spaces are forgiven', r.returncode == 0 and 'MATCHES' in r.stdout)
    bad = list(phrase); bad[3] = bad[3][:-1] + ('A' if bad[3][-1] != 'A' else 'B')
    r = subprocess.run([TC, 'check-phrase', K], input='-'.join(bad) + '\n', capture_output=True, text=True)
    check('a typo is reported as not valid', r.returncode == 1 and 'NOT VALID' in r.stdout and 'group 4' in r.stdout)
    L2, K2 = d + '/l3', d + '/k3'
    rc, out, err, phrase2 = run_init(L2, K2, good)
    check('a second volume has its own phrase and key', rc == 0 and phrase2 != phrase and open(K2).read() != open(K).read())
    r = subprocess.run([TC, 'check-phrase', K], input='-'.join(phrase2) + '\n', capture_output=True, text=True)
    check("another volume's phrase is recognised as valid but different", r.returncode == 1 and 'DIFFERENT' in r.stdout)
    # check-backup: read-only, driven by fake tmutil programs for each situation
    def fake(body):
        path = d + '/tmutil-' + str(abs(hash(body)))
        open(path, 'w').write('#!/bin/sh\n' + body + '\n'); os.chmod(path, 0o755)
        return path
    def cb(body, *args):
        return subprocess.run([TC, 'check-backup', *args], capture_output=True, text=True, env={**os.environ, 'TIERFS_TMUTIL': fake(body)})
    r = cb('echo "tmutil: No destinations configured."')
    check('check-backup: no destination is NO BACKUP', r.returncode == 3 and 'NO BACKUP' in r.stdout)
    r = cb('echo "Operation not permitted"; exit 1')
    check('check-backup: no permission says so and how to fix it', r.returncode == 3 and 'CANNOT TELL' in r.stdout and 'Full Disk Access' in r.stdout)
    r = cb('case "$1" in destinationinfo) printf "====\\nName          : Backup Disk\\nKind          : Local\\n";; latestbackup) echo "No machine directory found for host."; exit 1;; esac')
    check('check-backup: a destination without a readable backup is CANNOT TELL', r.returncode == 3 and 'Backup Disk' in r.stdout and 'CANNOT TELL' in r.stdout)
    good = 'case "$1" in destinationinfo) printf "====\\nName          : Backup Disk\\n";; latestbackup) echo "/Volumes/Backup Disk/Backups.backupdb/Mac/2026-10-11-120000";; isexcluded) echo "[Included]    $2";; esac'
    r = cb(good)
    check('check-backup: a readable backup is OK', r.returncode == 0 and 'latest backup: 2026-10-11-120000' in r.stdout and 'OK: a backup exists' in r.stdout)
    r = cb(good, '/some/folder')
    check('check-backup: an included folder is reported', r.returncode == 0 and 'is included in Time Machine' in r.stdout)
    r = cb(good.replace('[Included]', '[Excluded]'), '/some/folder')
    check('check-backup: an excluded folder is NOT COVERED', r.returncode == 3 and 'NOT COVERED' in r.stdout)
    r = cb(good.replace('2026-10-11-120000', 'garbage'))
    check('check-backup: an unexpected name is not trusted', r.returncode == 3 and 'unexpected latest-backup name' in r.stdout)
    st = subprocess.run([TC, 'ledger-status', L], capture_output=True, text=True)
    check('check-backup changed nothing', 'backup acknowledged: yes (recorded' in st.stdout)
finally:
    shutil.rmtree(d, ignore_errors=True)
print('\nALL PASSED (0 failures)' if not fails else f'\nFAILED ({fails} failures)')
sys.exit(1 if fails else 0)
