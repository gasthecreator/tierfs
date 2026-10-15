#!/usr/bin/env python3
"""Tests of `tierctl service` (the LaunchAgent for tierfsd). launchctl is replaced by a script that only writes down how it was called:
nothing here loads an agent, mounts anything, or touches ~/Library."""
import os, plistlib, shutil, stat, subprocess, sys, tempfile
TC = os.environ.get('TIERFS_TIERCTL', './build/tierctl')
fails = 0
def check(name, ok):
    global fails
    print(('PASS  ' if ok else 'FAIL  ') + name)
    if not ok: fails += 1

d = tempfile.mkdtemp(prefix='tierfs-svccli-')
try:
    agents, logs, calls = d + '/agents', d + '/logs', d + '/calls.txt'
    fake = d + '/launchctl'
    with open(fake, 'w') as f:
        f.write('#!/bin/sh\necho "$@" >> "%s"\nexit ${FAKE_RC:-0}\n' % calls)
    os.chmod(fake, 0o755)
    tierfsd = d + '/tierfsd'
    with open(tierfsd, 'w') as f: f.write('#!/bin/sh\nexit 0\n')
    os.chmod(tierfsd, 0o755)
    notexec = d + '/notexec'
    open(notexec, 'w').close()
    uid = os.getuid()
    HOME = d + '/home'
    env = {'TIERFS_LAUNCHCTL': fake, 'HOME': HOME}
    env.pop('TIERFS_I_ACCEPT_A_REBOOT', None)
    def tc(args, extra=None):
        e = {**os.environ, **env, **(extra or {})}
        if extra is None or 'TIERFS_I_ACCEPT_A_REBOOT' not in extra: e.pop('TIERFS_I_ACCEPT_A_REBOOT', None)
        return subprocess.run([TC, 'service', *args], capture_output=True, text=True, env=e, timeout=60)
    def called():
        return open(calls).read().splitlines() if os.path.exists(calls) else []
    base = ['--name', 'proj', '--mountpoint', d + '/mnt', '--binary', tierfsd, '--agents-dir', agents, '--log-dir', logs,
            '-o', 'origin=' + d + '/real', '-o', 'prefix=/Users/me/proj/', '-o', 'ledger=' + d + '/ledger', '-o', 'keyfile=keychain',
            '-o', 'devices=nas:9100@0123456789abcdef+127.0.0.1:9101', '-o', 'namedattr']
    plist_file = agents + '/local.tierfs.proj.plist'

    # plist: printed, valid, changes nothing
    r = tc(['plist', *base])
    p = plistlib.loads(r.stdout.encode()) if r.returncode == 0 else {}
    check('plist prints a valid plist', r.returncode == 0 and p.get('Label') == 'local.tierfs.proj')
    check('it starts tierfsd with its options and the mountpoint', p.get('ProgramArguments') == [tierfsd, '-o',
          f'origin={d}/real,prefix=/Users/me/proj/,ledger={d}/ledger,keyfile=keychain,devices=nas:9100@0123456789abcdef+127.0.0.1:9101,namedattr', d + '/mnt'])
    check('it does not start at login, does not restart itself, logs to the log directory', p.get('RunAtLoad') is False and p.get('KeepAlive') is False and p.get('StandardOutPath') == logs + '/proj.log')
    check('plist wrote nothing', not os.path.exists(agents) and not os.path.exists(logs) and called() == [])
    r = tc(['plist', *base, '--run-at-load'])
    check('--run-at-load is honoured', plistlib.loads(r.stdout.encode()).get('RunAtLoad') is True)

    # refusals (exit 2, nothing written)
    def refuses(args, text):
        r = tc(args)
        return r.returncode == 2 and text in r.stderr and not os.path.exists(agents)
    check('a mountpoint inside the origin is refused', refuses([a if a != d + '/mnt' else d + '/real/mnt' for a in ['install', *base]], 'inside it'))
    check('the origin inside the mountpoint is refused', refuses([a if a != d + '/mnt' else d for a in ['install', *base]], 'inside the mountpoint'))
    check('a missing required option is refused', refuses(['install', '--name', 'p', '--mountpoint', d + '/m', '-o', 'origin=/a'], 'is required'))
    check('a comma in a value is refused', refuses(['install', *base, '-o', 'control=/a,b'], 'comma'))
    check('an unknown option is refused', refuses(['install', *base, '-o', 'frobnicate=1'], 'unknown option'))
    check('a key typed into the plist is refused', refuses(['install', *[a if a != 'keyfile=keychain' else 'keyfile=' + '0123456789abcdef' * 4 for a in base]], 'keyfile must be'))
    check('a bad name is refused', refuses(['install', *[a if a != 'proj' else '../x' for a in base]], 'name must be'))
    check('an unknown action or option is refused', tc(['bogus']).returncode == 2 and tc(['plist', *base, '--bogus']).returncode == 2 and tc([]).returncode == 2)
    check('a missing value is refused', tc(['plist', '--name']).returncode == 2)

    # install without starting
    r = tc(['install', *[a if a != tierfsd else notexec for a in base]])
    check('a binary that cannot run is refused', r.returncode == 1 and 'not an executable' in r.stderr and not os.path.exists(plist_file))
    r = tc(['install', *base])
    mode = stat.S_IMODE(os.stat(plist_file).st_mode) if os.path.exists(plist_file) else 0
    check('install writes the plist (0644), creates the log directory, starts nothing', r.returncode == 0 and mode == 0o644 and os.path.isdir(logs) and called() == []
          and 'not started' in r.stdout and f'launchctl bootstrap gui/{uid} {plist_file}' in r.stdout)
    check('what was written is what plist prints', open(plist_file).read() == tc(['plist', *base]).stdout)
    check('no temporary file is left', not os.path.exists(plist_file + '.new'))
    r = tc(['install', *base])
    check('installing the same thing again changes nothing', r.returncode == 0 and 'already installed' in r.stdout and called() == [])
    r = tc(['install', *base, '-o', 'readahead=0'])
    check('a different plist is not silently replaced', r.returncode == 1 and 'pass --force' in r.stderr and 'readahead' not in open(plist_file).read())
    r = tc(['install', *base, '-o', 'readahead=0', '--force'])
    check('--force replaces it', r.returncode == 0 and 'readahead=0' in open(plist_file).read() and not os.path.exists(plist_file + '.new'))

    # starting it: only with the same acknowledgement the mount scripts demand
    os.remove(plist_file)
    r = tc(['install', *base, '--load'])
    check('--load without the acknowledgement is refused, and nothing is written', r.returncode == 1 and 'TIERFS_I_ACCEPT_A_REBOOT' in r.stderr and not os.path.exists(plist_file) and called() == [])
    r = tc(['install', *base, '--load'], {'TIERFS_I_ACCEPT_A_REBOOT': '1'})
    check('--load with it installs and bootstraps', r.returncode == 0 and 'started local.tierfs.proj' in r.stdout and called() == [f'bootstrap gui/{uid} {plist_file}'])
    os.remove(calls)
    os.remove(plist_file)
    r = tc(['install', *base, '--load'], {'TIERFS_I_ACCEPT_A_REBOOT': '1', 'FAKE_RC': '5'})
    check('a failing launchctl is reported', r.returncode == 1 and 'bootstrap failed (5)' in r.stderr)

    # status
    r = tc(['status', '--name', 'proj', '--agents-dir', agents])
    check('status: present and loaded', r.returncode == 0 and 'present' in r.stdout and 'loaded' in r.stdout and 'not loaded' not in r.stdout and called()[-1] == f'print gui/{uid}/local.tierfs.proj')
    r = tc(['status', '--name', 'proj', '--agents-dir', agents], {'FAKE_RC': '113'})
    check('status: present and not loaded', 'present' in r.stdout and 'not loaded' in r.stdout)
    r = tc(['status', '--name', 'other', '--agents-dir', agents], {'FAKE_RC': '113'})
    check('status: absent', 'absent' in r.stdout and 'not loaded' in r.stdout)
    check('status needs a sane name', tc(['status', '--agents-dir', agents]).returncode == 2 and tc(['status', '--name', '../x', '--agents-dir', agents]).returncode == 2)

    # uninstall
    os.remove(calls)
    r = tc(['uninstall', '--name', 'proj', '--agents-dir', agents])
    check('uninstall stops the agent and removes the plist', r.returncode == 0 and not os.path.exists(plist_file) and called() == [f'bootout gui/{uid}/local.tierfs.proj']
          and 'stopped' in r.stdout and 'removed' in r.stdout)
    r = tc(['uninstall', '--name', 'proj', '--agents-dir', agents], {'FAKE_RC': '3'})
    check('uninstalling what is not there is not an error', r.returncode == 0 and 'was not installed' in r.stdout)
    with open(plist_file, 'w') as f: f.write('<plist>somebody else\'s file</plist>')
    r = tc(['uninstall', '--name', 'proj', '--agents-dir', agents])
    check('a file that is not this service\'s plist is left alone', r.returncode == 1 and os.path.exists(plist_file) and 'leaving it alone' in r.stderr)
    check('uninstall needs a sane name', tc(['uninstall', '--agents-dir', agents]).returncode == 2 and tc(['uninstall', '--name', '.x', '--agents-dir', agents]).returncode == 2)
finally:
    shutil.rmtree(d, ignore_errors=True)
print('\n%s (%d failures)' % ('FAILED' if fails else 'ALL PASSED', fails))
sys.exit(1 if fails else 0)
