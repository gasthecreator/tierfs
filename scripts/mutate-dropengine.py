#!/usr/bin/env python3
"""Mutation test for core/dropengine.cpp. Each mutant removes one protection; tests/dropengine_test.cpp (with
fail-fast) and its crash helper must notice. A mutant killed ONLY by a crash is rerun once (a flaky crash must
not hide a survivor). Usage: mutate-dropengine.py [name filters ...]  (run in batches: each mutant takes a while)"""
import subprocess, sys, os, shutil, re
sys.path.insert(0, 'scripts')
from dropengine_mutants import M
OS = os.environ.get('OPENSSL_DIR', '/opt/homebrew/opt/openssl@3')
CRYPTO = f'{OS}/lib/libcrypto.a'
BASE = ['c++', '-std=c++17', '-g', '-w', f'-I{OS}/include', '-Icore', '-Itests']
D = 'build/mutdrop'
def run(cmd, **kw): return subprocess.run(cmd, capture_output=True, text=True, **kw)
def sh(cmd):
    r = run(cmd)
    if r.returncode: sys.exit('build failed: ' + ' '.join(cmd) + '\n' + r.stderr[-500:])
os.makedirs(D, exist_ok=True)
for src, out in [('core/crypto.cpp', 'crypto.o'), ('core/ledger.cpp', 'ledger.o'), ('core/securechannel.cpp', 'securechannel.o'), ('core/deviceclient.cpp', 'deviceclient.o'),
                 ('core/devicestore.cpp', 'devicestore.o'), ('core/replicator.cpp', 'replicator.o'),
                 ('tests/dropengine_test.cpp', 'dropengine_test.o'), ('tests/drop_helper.cpp', 'drop_helper.o')]:
    sh(BASE + ['-c', src, '-o', f'{D}/{out}'])
OBJS = ['replicator.o', 'ledger.o', 'securechannel.o', 'deviceclient.o', 'devicestore.o', 'crypto.o']
filters = sys.argv[1:]
survivors, expected = [], []
for name, path, frm, to in M:
    if filters and not any(f in name for f in filters): continue
    src = open(path).read()
    # whitespace in a pattern matches any whitespace (including none), so reformatting the source does not stale the list
    m = re.search(r'\s*'.join(re.escape(t) for t in frm.split()), src)
    if not m:
        print(f'{name:<66} !! pattern not found (stale)'); survivors.append(name + ' (stale)'); continue
    open(f'{D}/mut.cpp', 'w').write(src[:m.start()] + to + src[m.end():])
    r = run(BASE + ['-c', f'{D}/mut.cpp', '-o', f'{D}/mut.o'])
    if r.returncode: print(f'{name:<66} (does not compile: {r.stderr.strip().splitlines()[-1][:60]})'); continue
    for out, first in [('mut_test', 'dropengine_test.o'), ('mut_helper', 'drop_helper.o')]:
        sh(['c++', '-o', f'{D}/{out}', f'{D}/{first}', f'{D}/mut.o'] + [f'{D}/{o}' for o in OBJS] + [CRYPTO, '-lsqlite3', '-framework', 'CoreFoundation'])
    env = dict(os.environ, TIERFS_DROP_HELPER=f'./{D}/mut_helper', TIERFS_TEST_FAILFAST='1')
    def execute():
        subprocess.run(['pkill', '-f', 'tierfs-device'])
        try:
            p = subprocess.run([f'{D}/mut_test'], capture_output=True, text=True, timeout=500, env=env)
            out, rc = p.stdout, p.returncode
        except subprocess.TimeoutExpired:
            out, rc = 'FAIL timeout', 99
        subprocess.run(['pkill', '-f', 'tierfs-device'])
        return out, rc, [l for l in out.splitlines() if l.startswith('FAIL')]
    out, rc, fails = execute()
    if not fails and rc != 0:
        out, rc, fails = execute()   # killed only by a crash: ask again
    killed = bool(fails) or rc != 0
    how = fails[0][:70] if fails else f'exit code {rc}'
    tagged = name.startswith('[')
    if killed:
        print(f'{name:<66} killed ({how})')
    elif tagged:
        print(f'{name:<66} SURVIVED (expected: {name.split("]")[0][1:]})'); expected.append(name)
    else:
        print(f'{name:<66} SURVIVED  <-- test gap'); survivors.append(name)
shutil.rmtree(D, ignore_errors=True)
print('survivors:', survivors if survivors else 'none', '| expected survivors:', len(expected))
