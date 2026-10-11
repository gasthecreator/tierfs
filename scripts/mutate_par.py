#!/usr/bin/env python3
"""Parallel mutation runner. Each worker has its own build directory, TCP ports, and temp directory, so several
mutants are tested at once (the tests honour TIERFS_TEST_PORT and TIERFS_TEST_TMP).
Usage: mutate_par.py <target> [-j N] [name filters ...]      targets: recovery, overlay
A mutant is killed when the test fails (or crashes; a crash-only kill is rerun once). Survivors are test gaps unless
their name starts with a [reason] tag (an expected survivor, documented in the design doc)."""
import subprocess, sys, os, shutil, threading, importlib
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, 'scripts')
OS = os.environ.get('OPENSSL_DIR', '/opt/homebrew/opt/openssl@3')
CRYPTO = f'{OS}/lib/libcrypto.a'
BASE = ['c++', '-std=c++17', '-g', '-w', f'-I{OS}/include', '-Icore', '-Itests']
COMMON = [('core/crypto.cpp', 'crypto'), ('core/ledger.cpp', 'ledger'), ('core/deviceclient.cpp', 'deviceclient'),
          ('core/devicestore.cpp', 'devicestore'), ('core/replicator.cpp', 'replicator'), ('core/dropengine.cpp', 'dropengine')]
TARGETS = {
    'recovery': dict(mutants='recovery_mutants', mutated='core/recovery.cpp', test='tests/recovery_test.cpp', tmptag='recotest',
                     extra_objs=[('core/chunkcache.cpp', 'chunkcache')], tool='tools/tierctl.cpp', tool_env='TIERFS_TIERCTL', libs=['-lsqlite3']),
    'overlay': dict(mutants='overlay_mutants', mutated='core/overlay.cpp', test='tests/overlay_test.cpp', tmptag='ovtest',
                    extra_objs=[], tool=None, tool_env=None, libs=['-lsqlite3']),
}
if len(sys.argv) < 2 or sys.argv[1] not in TARGETS: sys.exit(__doc__)
T = TARGETS[sys.argv[1]]
args = sys.argv[2:]
jobs = 4
if '-j' in args:
    i = args.index('-j'); jobs = int(args[i + 1]); del args[i:i + 2]
filters = args
M = importlib.import_module(T['mutants']).M
D = f'build/mut_{sys.argv[1]}'
def run(cmd, **kw): return subprocess.run(cmd, capture_output=True, text=True, **kw)
def sh(cmd):
    r = run(cmd)
    if r.returncode: sys.exit('build failed: ' + ' '.join(cmd) + '\n' + r.stderr[-800:])
shutil.rmtree(D, ignore_errors=True)
os.makedirs(D)
for src, out in COMMON + T['extra_objs'] + [(T['test'], 'test_o')] + ([(T['tool'], 'tool_o')] if T['tool'] else []):
    sh(BASE + ['-c', src, '-o', f'{D}/{out}.o'])
OBJS = [o for _, o in COMMON + T['extra_objs']]
results = {}
lock = threading.Lock()

def wipe(path):   # a killed test can leave a directory it had made unreadable (permission tests)
    subprocess.run(['chmod', '-R', 'u+rwx', path], capture_output=True)
    shutil.rmtree(path, ignore_errors=True)

def worker_env(w):
    tmp = f'/tmp/tierfs-mutw{w}'
    return tmp, dict(os.environ, TIERFS_TEST_FAILFAST='1', TIERFS_TEST_PORT=str(9700 + 10 * w), TIERFS_TEST_TMP=tmp)

def test_mutant(job):
    n, (name, path, frm, to) = job
    w = int(threading.current_thread().name.split('_')[-1]) % jobs
    wd = f'{D}/w{w}'
    os.makedirs(wd, exist_ok=True)
    tmp, env = worker_env(w)
    src = open(path).read()
    if frm not in src: return name, 'stale', 'pattern not found'
    open(f'{wd}/mut.cpp', 'w').write(src.replace(frm, to, 1))
    r = run(BASE + ['-c', f'{wd}/mut.cpp', '-o', f'{wd}/mut.o'])
    if r.returncode: return name, 'nocompile', (r.stderr.strip().splitlines() or ['?'])[-1][:70]
    # the mutated file replaces the object of the same name
    objs = [f'{D}/{o}.o' for o in OBJS]
    mutated_obj = os.path.basename(T['mutated'])[:-4]
    objs = [f'{wd}/mut.o' if o.endswith(f'/{mutated_obj}.o') else o for o in objs]
    if not any(o == f'{wd}/mut.o' for o in objs): objs.append(f'{wd}/mut.o')
    sh(['c++', '-o', f'{wd}/mut_test', f'{D}/test_o.o'] + objs + [CRYPTO] + T['libs'])
    if T['tool']:
        sh(['c++', '-o', f'{wd}/mut_tool', f'{D}/tool_o.o'] + objs + [CRYPTO] + T['libs'])
        env[T['tool_env']] = f'./{wd}/mut_tool'
    def execute():
        wipe(tmp); os.makedirs(tmp, exist_ok=True)
        subprocess.run(['pkill', '-f', f'tierfs-device {tmp}/'])
        try:
            p = subprocess.run([f'{wd}/mut_test'], capture_output=True, text=True, timeout=600, env=env)
            out, rc = p.stdout, p.returncode
        except subprocess.TimeoutExpired:
            out, rc = 'FAIL timeout', 99
        subprocess.run(['pkill', '-f', f'tierfs-device {tmp}/'])
        wipe(tmp)
        return rc, [l for l in out.splitlines() if l.startswith('FAIL')]
    rc, fails = execute()
    if not fails and rc != 0: rc, fails = execute()   # killed only by a crash: ask again
    if fails or rc != 0: return name, 'killed', fails[0][:80] if fails else f'exit code {rc}'
    return name, 'survived', ''

jobs_list = [(i, m) for i, m in enumerate(M) if not filters or any(f in m[0] for f in filters)]
survivors, expected, nocompile, stale = [], [], [], []
with ThreadPoolExecutor(max_workers=jobs, thread_name_prefix='mw') as ex:
    for name, status, detail in ex.map(test_mutant, jobs_list):
        tagged = name.startswith('[')
        if status == 'killed': print(f'{name:<70} killed ({detail})', flush=True)
        elif status == 'survived':
            if tagged: print(f'{name:<70} SURVIVED (expected)', flush=True); expected.append(name)
            else: print(f'{name:<70} SURVIVED  <-- test gap', flush=True); survivors.append(name)
        elif status == 'nocompile': print(f'{name:<70} DOES NOT COMPILE ({detail})', flush=True); nocompile.append(name)
        else: print(f'{name:<70} STALE ({detail})', flush=True); stale.append(name)
shutil.rmtree(D, ignore_errors=True)
print('survivors:', survivors or 'none', '| expected:', len(expected), '| not compiling:', nocompile or 'none', '| stale:', stale or 'none')
