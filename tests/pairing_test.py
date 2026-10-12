#!/usr/bin/env python3
"""Tests of `tierctl pair` and paired devices in `tierctl restore`, against real tierfs-device processes (no mounts)."""
import os, re, shutil, signal, socket, stat, subprocess, sys, tempfile, time
TC = os.environ.get('TIERFS_TIERCTL', './build/tierctl')
DEV = os.environ.get('TIERFS_DEVICE_SERVER', './build/tierfs-device')
BASE = int(os.environ.get('TIERFS_TEST_PORT', '9601'))
fails = 0
def check(name, ok):
    global fails
    print(('PASS  ' if ok else 'FAIL  ') + name)
    if not ok: fails += 1

def show_code(store):
    r = subprocess.run([DEV, store, '--show-pairing-code'], capture_output=True, text=True)
    m = re.search(r'\n\n    ([0-9A-Z-]+)\n', r.stdout)
    k = re.search(r'key id: ([0-9a-f]{16})', r.stdout)
    return (m.group(1), k.group(1)) if m and k else (None, None)

def start(store, port):
    p = subprocess.Popen([DEV, store, str(port), '127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(('127.0.0.1', port), timeout=0.2).close(); return p
        except OSError: time.sleep(0.05)
    p.kill(); raise SystemExit('device did not start')

def tc(args, stdin='', env=None):
    return subprocess.run([TC, *args], input=stdin, capture_output=True, text=True, env={**os.environ, **(env or {})}, timeout=60)

d = tempfile.mkdtemp(prefix='tierfs-pairtest-')
procs = []
try:
    A, B, O = d + '/devA', d + '/devB', d + '/open'
    codeA, kidA = show_code(A); codeB, kidB = show_code(B)
    check('devices print a code and a key id', codeA and kidA and codeB and kidB and codeA != codeB and kidA != kidB)
    pa, pb, po = BASE, BASE + 1, BASE + 2
    procs += [start(A, pa), start(B, pb), start(O, po)]
    # an open device (never paired) for the refusal case
    KS = d + '/ks'
    r = tc(['pair', f'127.0.0.1:{pa}', '--store', 'dir:' + KS], stdin=codeA + '\n')
    check('pair succeeds with the right code', r.returncode == 0 and 'paired with device' in r.stdout and kidA in r.stdout and f'--device 127.0.0.1:{pa}@{kidA}' in r.stdout)
    keyfile = f'{KS}/pair-{kidA}.key'
    check('the secret is stored under its key id, private', os.path.isfile(keyfile) and stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600)
    check('the stored secret is the device\'s secret', open(keyfile).read().strip() == open(A + '/pairing.key').read().strip())
    r = tc(['pair', f'127.0.0.1:{pa}', '--store', 'dir:' + KS], stdin=codeA.lower().replace('-', ' ') + '\n')
    check('pairing again (even typed loosely) is harmless', r.returncode == 0)
    before = sorted(os.listdir(KS))
    r = tc(['pair', f'127.0.0.1:{pa}', '--store', 'dir:' + KS], stdin=codeB + '\n')
    check("another device's code does not authenticate: nothing is saved", r.returncode == 1 and 'could not authenticate' in r.stderr and 'nothing was saved' in r.stderr and sorted(os.listdir(KS)) == before)
    typo = codeA[:6] + ('A' if codeA[6] != 'A' else 'B') + codeA[7:]
    r = tc(['pair', f'127.0.0.1:{pa}', '--store', 'dir:' + KS], stdin=typo + '\n')
    check('a mistyped code is rejected before any connection', r.returncode == 1 and 'not accepted' in r.stderr)
    r = tc(['pair', f'127.0.0.1:{po}', '--store', 'dir:' + KS], stdin=codeA + '\n')
    check('an unpaired device cannot be paired with a code it does not have', r.returncode == 1 and 'could not authenticate' in r.stderr)
    r = tc(['pair', '127.0.0.1:1', '--store', 'dir:' + KS], stdin=codeA + '\n')
    check('a device that is not there is an error, nothing saved', r.returncode == 1 and sorted(os.listdir(KS)) == before)
    r = tc(['pair', f'127.0.0.1:{pb}', '--store', 'dir:' + KS], stdin=codeB + '\n')
    check('a second device pairs', r.returncode == 0 and f'pair-{kidB}.key' in os.listdir(KS))
    for args, why in [(['pair', f'127.0.0.1:{pa}'], 'no store'), (['pair', f'127.0.0.1:{pa}', '--store', 'bogus'], 'unknown store'), (['pair', 'nonsense', '--store', 'dir:' + KS], 'bad address'),
                      (['pair', f'127.0.0.1:{pa}@{kidA}', '--store', 'dir:' + KS], 'a key id in the address'), (['pair', f'127.0.0.1:{pa}', '--store', KS + '/file'], 'a key file as the store')]:
        r = tc(args, stdin=codeA + '\n')
        check('pair refuses: ' + why, r.returncode == 2)

    # ---- restore with paired devices: it must get past authentication (these devices hold no volume, so the restore itself then says so)
    base = ['restore', '--out', d + '/out', '--dry-run', '--phrase-file', d + '/phrase']
    # a phrase for the restore: any valid phrase works for authentication purposes
    p = subprocess.Popen([TC, 'init', d + '/lp', '--store', 'dir:' + d + '/mk2'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out = ''; phrase = None
    while True:
        ch = p.stdout.read(1)
        if not ch: break
        out += ch
        if phrase is None:
            m = re.search(r'\n\n    ([^\n]+)\n\n', out)
            if m: phrase = m.group(1).strip()
        m = re.search(r'Type group (\d+) of the phrase: $', out)
        if m and phrase:
            p.stdin.write(phrase.split('-')[int(m.group(1)) - 1] + '\n'); p.stdin.flush(); out += '\n'
    p.wait()
    open(d + '/phrase', 'w').write(phrase + '\n')
    dev = lambda port, kid=None: ['--device', f'127.0.0.1:{port}' + (f'@{kid}' if kid else '')]
    r = tc(base + dev(pa, kidA) + dev(pb, kidB) + ['--store', 'dir:' + KS])
    check('restore authenticates to paired devices through the key store', r.returncode == 1 and 'NOTHING WAS RECOVERED' in r.stdout and 'not bound' in r.stdout and 'authentication' not in r.stdout + r.stderr)
    r = tc(base + dev(pa, kidA))
    check('a key id without --store is a clear error', r.returncode == 2 and 'needs --store' in r.stderr)
    r = tc(base + dev(pa, '0123456789abcdef') + ['--store', 'dir:' + KS])
    check('an unknown key id is a clear error', r.returncode == 2 and 'no pairing secret' in r.stderr)
    r = tc(base + dev(pa, 'nothex'))
    check('a malformed key id is refused', r.returncode == 2)
    r = tc(base + dev(pa))
    check('a paired device without any code, with no terminal: tells how to give it', r.returncode == 2 and 'device is paired' in r.stderr and '--pairing-file' in r.stderr)
    open(d + '/codes', 'w').write(f'# the codes shown by each device\n127.0.0.1:{pa} {codeA}\n127.0.0.1:{pb} {codeB.lower()}\n')
    r = tc(base + dev(pa) + dev(pb) + ['--pairing-file', d + '/codes'])
    check('a pairing file supplies the codes (the new-Mac case: nothing stored beforehand)', r.returncode == 1 and 'not bound' in r.stdout and 'NOTHING WAS RECOVERED' in r.stdout)
    open(d + '/wrongcodes', 'w').write(f'127.0.0.1:{pa} {codeB}\n')
    r = tc(base + dev(pa) + ['--pairing-file', d + '/wrongcodes'])
    check('a wrong code in the pairing file stops the restore with a reason', r.returncode == 1 and 'authentication' in (r.stdout + r.stderr).lower())
    open(d + '/badcodes', 'w').write(f'127.0.0.1:{pa} not-a-code\n')
    r = tc(base + dev(pa) + ['--pairing-file', d + '/badcodes'])
    check('a malformed code in the pairing file is reported', r.returncode == 2 and 'not valid' in r.stderr)
    r = tc(base + dev(pa) + ['--pairing-file', d + '/missing-file'])
    check('a missing pairing file is an error', r.returncode == 1 and 'cannot read' in r.stderr)
    r = tc(base + dev(po))
    check('an open device needs no code', r.returncode == 1 and 'not bound' in r.stdout)
    check('nothing was written by any of this', not os.path.exists(d + '/out'))
    # restore secrets never get stored by restore itself
    check('restore stores no secrets', sorted(os.listdir(KS)) == sorted([f'pair-{kidA}.key', f'pair-{kidB}.key']))
finally:
    for p in procs:
        p.kill(); p.wait()
    shutil.rmtree(d, ignore_errors=True)
print('\nALL PASSED (0 failures)' if not fails else f'\nFAILED ({fails} failures)')
sys.exit(1 if fails else 0)
