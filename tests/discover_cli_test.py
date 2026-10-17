#!/usr/bin/env python3
"""`tierctl discover` against a real announcing device (Bonjour on this machine): what it lists, what it says about trust, and its usage errors.
Skipped (with a note) if the system's mDNS service will not take the announcement."""
import os, re, shutil, signal, socket, subprocess, sys, tempfile, time
TC = os.environ.get('TIERFS_TIERCTL', './build/tierctl')
DEV = os.environ.get('TIERFS_DEVICE_SERVER', './build/tierfs-device')
PORT = int(os.environ.get('TIERFS_TEST_PORT', '9601')) + 30
fails = 0
def check(name, ok):
    global fails
    print(('PASS  ' if ok else 'FAIL  ') + name)
    if not ok: fails += 1
def tc(args, stdin='', timeout=60):
    return subprocess.run([TC, *args], input=stdin, capture_output=True, text=True, timeout=timeout)

d = tempfile.mkdtemp(prefix='tierfs-disc-')
proc = None
try:
    store, ks = d + '/dev', d + '/ks'
    os.makedirs(ks)
    r = subprocess.run([DEV, store, '--add-pairing=cli test'], capture_output=True, text=True)
    code = re.search(r'\n\n    ([0-9A-Z-]+)\n', r.stdout)
    kid = re.search(r'key id: ([0-9a-f]{16})', r.stdout)
    check('the device printed a code and a key id', bool(code and kid))
    code, kid = code.group(1), kid.group(1)
    name = f'tfs-cli-test-{os.getpid()}'
    log = open(d + '/dev.log', 'w')
    proc = subprocess.Popen([DEV, store, str(PORT), '127.0.0.1', f'--advertise={name}'], stdout=subprocess.DEVNULL, stderr=log)
    up = False
    for _ in range(100):
        if proc.poll() is not None: break
        try: socket.create_connection(('127.0.0.1', PORT), timeout=0.2).close(); up = True; break
        except OSError: time.sleep(0.05)
    text = ''
    for _ in range(100):   # the announcement is confirmed by the system a moment after the server starts listening
        text = open(d + '/dev.log').read()
        if 'advertising as' in text or proc.poll() is not None: break
        time.sleep(0.1)
    if not up or 'advertising as' not in text:
        print('      (skipped: the device could not announce itself: %s)' % text.strip()[:200])
    else:
        # not paired with it yet
        r = tc(['discover', '--seconds', '4', '--store', 'dir:' + ks])
        out = r.stdout
        check('discover lists the announced device with its key id', r.returncode == 0 and name in out and f'paired, key id {kid}' in out)
        check('it offers both ways to name the device', f'mdns:{name}@{kid}' in out and f':{PORT}@{kid}' in out)
        check('it says this Mac is not paired with it, and how to fix that', 'is NOT paired with it' in out and 'tierctl pair' in out)
        check('it says that an announcement proves nothing', 'An announcement only says where a device claims to be' in out)
        # pair, and ask again
        r = tc(['pair', f'127.0.0.1:{PORT}', '--store', 'dir:' + ks], stdin=code + '\n')
        check('pairing works', r.returncode == 0 and kid in r.stdout)
        r = tc(['discover', '--seconds', '4', '--store', 'dir:' + ks])
        check('now it says this Mac is paired with it', 'is paired with it' in r.stdout and 'NOT paired' not in r.stdout.replace('NOT PAIRED (no authentication)', ''))
        # without a key store it cannot say
        r = tc(['discover', '--seconds', '3'])
        check('without --store it does not claim anything about pairing', r.returncode == 0 and name in r.stdout and 'this Mac' not in r.stdout)
        # the search time is honoured
        t0 = time.time(); tc(['discover', '--seconds', '1']); took = time.time() - t0
        check('--seconds 1 takes about a second', 0.8 < took < 6)
    # usage errors
    for args in (['discover', '--seconds', '0'], ['discover', '--seconds', '61'], ['discover', '--seconds', 'x'], ['discover', '--bogus'], ['discover', '--store']):
        r = tc(args)
        check('usage error for ' + ' '.join(args[1:]), r.returncode == 2 and ('usage' in r.stderr or '--seconds' in r.stderr))
    # nothing announced
    if proc and proc.poll() is None:
        proc.terminate(); proc.wait(timeout=10)
    proc = None
    time.sleep(1)
    r = tc(['discover', '--seconds', '2'])
    check('nothing announced: says so and how to announce', r.returncode == 0 and 'no tierfs devices answered in 2 seconds' in r.stdout and '--advertise' in r.stdout)
finally:
    if proc and proc.poll() is None: proc.kill()
    shutil.rmtree(d, ignore_errors=True)
print('\n%s (%d failures)' % ('FAILED' if fails else 'ALL PASSED', fails))
sys.exit(1 if fails else 0)
