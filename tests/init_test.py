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
    r = subprocess.run([TC, 'ack-backup', L, 'I-HAVE-A-BACKUP'], capture_output=True, text=True)
    st = subprocess.run([TC, 'ledger-status', L], capture_output=True, text=True)
    check('ack-backup records it', r.returncode == 0 and 'backup acknowledged: yes' in st.stdout)
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
finally:
    shutil.rmtree(d, ignore_errors=True)
print('\nALL PASSED (0 failures)' if not fails else f'\nFAILED ({fails} failures)')
sys.exit(1 if fails else 0)
