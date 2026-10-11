#!/usr/bin/env python3
"""Mutation test for the device side: core/devicestore.cpp, backend/device_server.cpp,
core/deviceclient.cpp. Removes one protection at a time and checks the suites notice.

 - store mutants run tests/devicestore_test.cpp (crash helper rebuilt from the mutant)
 - server mutants run the real network suite against a server built from the mutant
 - client mutants run the network suite with the mutated client library
A crashing run counts as killed. Mutants tagged [power-loss] remove an fsync: no test can
see those without cutting the power, so they are expected to survive and are listed apart.
Usage: mutate-device.py [store|server|client] [name filter ...]"""
import subprocess, sys, os, shutil

S, V, C = 'core/devicestore.cpp', 'backend/device_server.cpp', 'core/deviceclient.cpp'
M = [
 # --- store ---
 ('store', 'chunk hash claim unchecked', S, 'if (claimed != actual) return fail(EBADMSG, "blob does not match its claimed hash (damaged in transit)");', '', 0),
 ('store', 'existing chunk overwritten', S, 'if (q.row()) {   // append-only: keep the original, say so, and tell the sender what we hold', 'if (false) {', 0),
 ('store', 'put: chunk id unchecked', S, 'if (!valid_chunk_id(id)) return fail(EINVAL, "bad chunk id");', '', 0),
 ('store', 'get: chunk id unchecked', S, 'if (!valid_chunk_id(id)) { if (msg) *msg = "bad chunk id"; return EINVAL; }', '', 0),
 ('store', 'get serves unverified bytes', S, 'if (rc == 0 && crypto::sha256_hex(out.data(), out.size()) != want_sha) rc = EIO;', '', 0),
 ('store', '[equivalent] get ignores stored size (hash check also rejects it)', S, 'int rc = read_file(chunk_path(serve_id), out, size);', 'int rc = read_file(chunk_path(serve_id), out);', 0),
 ('store', 'manifest without its chunks', S, 'if (!q.row()) return fail(ENOENT, "chunk " + c + " is not present on this device");', '', 0),
 ('store', 'manifest versions mutable', S, 'if (q.row()) {   // versions are immutable: the first manifest stays, the sender learns its hash and seq', 'if (false) {', 0),
 ('store', 'seq not incremented', S, 'seq = strtoull(meta_get("seq").c_str(), nullptr, 10) + 1;', 'seq = strtoull(meta_get("seq").c_str(), nullptr, 10) + 0;', 0),
 ('store', 'list newest first', S, 'ORDER BY seq LIMIT ?2', 'ORDER BY seq DESC LIMIT ?2', 0),
 ('store', 'list includes since', S, 'WHERE seq>?1 ORDER BY', 'WHERE seq>=?1 ORDER BY', 0),
 ('store', 'volume can be rebound', S, 'if (!cur.empty()) { if (msg) *msg = "device is bound to a different volume"; return EPERM; }', '', 0),
 ('store', 'chunks deletable (trigger)', S, '"CREATE TRIGGER chunks_append_only_d BEFORE DELETE ON chunks BEGIN SELECT RAISE(ABORT,\'append-only\'); END",', '', 0),
 ('store', 'seq may go down (trigger)', S, '"CREATE TRIGGER meta_seq_monotonic BEFORE UPDATE ON meta WHEN OLD.key=\'seq\' AND CAST(NEW.value AS INTEGER)<=CAST(OLD.value AS INTEGER)"\n        " BEGIN SELECT RAISE(ABORT,\'commit sequence only goes up\'); END",', '', 0),
 ('store', 'staging not cleaned at start', S, 'for (auto& e : fs::directory_iterator(dir + "/tmp", ec)) fs::remove(e.path(), ec);', '', 0),
 ('store', 'no exclusive lock', S, 'if (flock(d->lock_fd_, LOCK_EX | LOCK_NB) != 0) return bad("device store is in use by another process");', '', 0),
 ('store', 'schema version unchecked', S, 'if (version != 0 && version != SCHEMA_VERSION) {', 'if (false) {', 0),
 ('store', 'empty chunk accepted', S, 'if (blob.empty() || blob.size() > MAX_CHUNK_BLOB) return fail(EMSGSIZE, "blob size out of range");', 'if (blob.size() > MAX_CHUNK_BLOB) return fail(EMSGSIZE, "blob size out of range");', 0),
 ('store', 'manifest version unchecked', S, 'if (version < 1 || version > (1ll << 40)) return fail(EINVAL, "bad version");', '', 0),
 ('store', 'manifest chunk count unchecked', S, 'if (chunk_ids.size() > MAX_MANIFEST_CHUNKS) return fail(EMSGSIZE, "too many chunks");', '', 0),
 ('store', 'audit hashes nothing', S, 'a.response_hex = crypto::audit_response_hex(it.nonce, data.data(), data.size());', 'a.response_hex = crypto::audit_response_hex(it.nonce, nullptr, 0);', 0),
 ('store', 'audit: lost file not "missing"', S, 'if (rc == ENOENT) { a.status = 1; out.push_back(a); continue; }', '', 0),
 ('store', 'chunk upload ignores free space', S, 'blob.size() + min_free_', '0', 0),
 ('store', 'manifest upload ignores free space', S, 'blob.size() + min_free_', '0', 1),
 ('store', 'unbounded file reads', S, 'if (st.st_size < 0 || static_cast<uint64_t>(st.st_size) > MAX_MANIFEST_BLOB) { close(fd); return EIO; }', '', 0),
 ('store', 'chunk crash point removed', S, 'crash_point("device.chunk.after_rename");', '', 0),
 ('store', 'manifest crash point removed', S, 'crash_point("device.manifest.before_commit");', '', 0),
 ('store', '[power-loss] file not fsynced', S, 'if (!err) full_sync(fd);', '', 0),
 ('store', '[power-loss] directory not fsynced', S, '        if (!err) sync_dir(parent);', '', 0),
 ('store', '[power-loss] plain fsync, not F_FULLFSYNC', S, 'if (fcntl(fd, F_FULLFSYNC) != 0) fsync(fd);', 'fsync(fd);', 0),
 # --- server ---
 ('server', 'hello version unchecked', V, 'if (r.u16() != DEVICE_PROTO_VERSION) {', 'if (r.u16() == 9999) {', 0),
 ('server', 'requests before hello allowed', V, '} else if (!greeted) {', '} else if (false) {', 0),
 ('server', 'has_chunks count unbounded', V, 'if (n > 1024) return reply_err(fd, f.id, EMSGSIZE, "too many ids in one request");', '', 0),
 ('server', 'audit count unbounded', V, 'if (n > MAX_AUDIT_ITEMS) return reply_err(fd, f.id, EMSGSIZE, "too many audit items");', '', 0),
 ('server', 'audit kind unchecked', V, 'if (a.kind > 1) return reply_err(fd, f.id, EINVAL, "bad audit kind");', '', 0),
 ('server', 'manifest chunk count unbounded', V, 'if (n > MAX_MANIFEST_CHUNKS) return reply_err(fd, f.id, EMSGSIZE, "too many chunks");', '', 0),
 ('server', 'no connection cap', V, 'if (g_conns.load() >= MAX_CONNECTIONS) { close(c); continue; }', '', 0),
 ('server', 'listens on any address', V, 'if (!insecure && bind_addr != "127.0.0.1") {', 'if (false) {', 0),
 ('server', 'bad fault names ignored', V, 'if (!DeviceFaults::parse(faults_csv, &faults, &ferr)) {', 'if (false) {', 0),
 ('server', '"existed" never reported', V, 'w.u8(o.existed ? 1 : 0);', 'w.u8(0);', 0),
 ('server', 'no idle timeout', V, 'timeval tv{g_idle_s, 0};', 'timeval tv{0, 0};', 0),
 # --- client ---
 ('client', 'upload hash not sent', C, 'put_hash(w, crypto::sha256_hex(blob.data(), blob.size()));', 'put_hash(w, std::string(64, \'0\'));', 0),
 ('client', 'has_chunks not paged', C, 'size_t n = std::min<size_t>(1024, ids.size() - std::min(off, ids.size()));', 'size_t n = ids.size();', 0),
 ('client', 'no whole-request deadline', C, 'int64_t deadline = now_ms() + timeout_ms_ + static_cast<int64_t>((expect_bytes + payload.size()) * 1000 / MIN_RATE_BYTES_PER_SEC);', 'int64_t deadline = 0;', 0),
 ('client', 'retries even on a fresh connection', C, 'if (!had_conn) return res;', '', 0),
 ('client', 'audit nonce length unchecked', C, 'if (a.nonce.size() != 32) return {EINVAL, "audit nonce must be 32 bytes"};', '', 0),
 ('client', 'audit size unchecked', C, 'if (items.size() > MAX_AUDIT_ITEMS) return {EMSGSIZE, "too many items in one audit"};', '', 0),
 ('client', 'oversized manifest sent anyway', C, 'if (w.b.size() + 5 > MAX_FRAME) return {EMSGSIZE, "manifest too large for one request (file too big for protocol v3)"};', '', 0),
]
OS = os.environ.get('OPENSSL_DIR', '/opt/homebrew/opt/openssl@3')
CRYPTO = f'{OS}/lib/libcrypto.a'
BASE = ['c++', '-std=c++17', '-g', '-w', f'-I{OS}/include', '-Icore', '-Itests']
D = 'build/mutd'

def run(cmd, **kw): return subprocess.run(cmd, capture_output=True, text=True, **kw)
def build_plain():
    os.makedirs(D, exist_ok=True)
    steps = [
      BASE + ['-c', 'core/crypto.cpp', '-o', f'{D}/crypto.o'],
      BASE + ['-c', S, '-o', f'{D}/devicestore.o'],
      BASE + ['-c', C, '-o', f'{D}/deviceclient.o'],
      BASE + ['-c', 'tests/devicestore_test.cpp', '-o', f'{D}/devicestore_test.o'],
      BASE + ['-c', 'tests/device_helper.cpp', '-o', f'{D}/device_helper.o'],
      BASE + ['-c', 'tests/devicenet_test.cpp', '-o', f'{D}/devicenet_test.o'],
    ]
    for s in steps:
        r = run(s)
        if r.returncode: sys.exit('setup failed: ' + ' '.join(s) + '\n' + r.stderr[-400:])
    link = lambda out, objs: run(['c++', '-o', out] + objs + [CRYPTO, '-lsqlite3', '-framework', 'Security', '-framework', 'CoreFoundation'])
    for out, objs in [(f'{D}/devicestore_test', ['devicestore_test.o', 'devicestore.o', 'crypto.o']),
                      (f'{D}/device_helper', ['device_helper.o', 'devicestore.o', 'crypto.o']),
                      (f'{D}/devicenet_test', ['devicenet_test.o', 'deviceclient.o', 'devicestore.o', 'crypto.o'])]:
        r = link(out, [f'{D}/{o}' for o in objs])
        if r.returncode: sys.exit('link failed ' + out + r.stderr[-400:])
    r = run(BASE + [V, f'{D}/devicestore.o', f'{D}/crypto.o', CRYPTO, '-lsqlite3', '-o', f'{D}/server'])
    if r.returncode: sys.exit('server build failed' + r.stderr[-400:])

def replace_nth(src, frm, to, n):
    idx = -1
    for _ in range(n + 1):
        idx = src.find(frm, idx + 1)
        if idx < 0: return None
    return src[:idx] + to + src[idx + len(frm):]

def execute(binary, env_extra, timeout=300):
    env = dict(os.environ, **env_extra)
    try:
        p = subprocess.run([binary], capture_output=True, text=True, timeout=timeout, env=env)
        return p.stdout, p.returncode
    except subprocess.TimeoutExpired:
        subprocess.run(['pkill', '-f', 'mutd/server'])
        return 'FAIL timeout', 99

group = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] in ('store', 'server', 'client') else None
filters = [a for a in sys.argv[1:] if a not in ('store', 'server', 'client')]
build_plain()
survivors, expected_survivors = [], []
for g, name, path, frm, to, nth in M:
    if group and g != group: continue
    if filters and not any(f in name for f in filters): continue
    src = open(path).read()
    mutated = replace_nth(src, frm, to, nth)
    if mutated is None:
        print(f'{name:<44} !! pattern not found (mutant list is stale)'); survivors.append(name + ' (stale)'); continue
    open(f'{D}/mut.cpp', 'w').write(mutated)
    if g == 'store':
        r1 = run(BASE + ['-c', f'{D}/mut.cpp', '-o', f'{D}/mut.o'])
        if r1.returncode: print(f'{name:<44} (does not compile)'); continue
        for out, o in [('mut_store_test', 'devicestore_test.o'), ('mut_helper', 'device_helper.o')]:
            run(['c++', '-o', f'{D}/{out}', f'{D}/{o}', f'{D}/mut.o', f'{D}/crypto.o', CRYPTO, '-lsqlite3'])
        out, rc = execute(f'{D}/mut_store_test', {'TIERFS_DEVICE_HELPER': f'./{D}/mut_helper'})
    elif g == 'server':
        r1 = run(BASE + [f'{D}/mut.cpp', f'{D}/devicestore.o', f'{D}/crypto.o', CRYPTO, '-lsqlite3', '-o', f'{D}/mut_server'])
        if r1.returncode: print(f'{name:<44} (does not compile: {r1.stderr.strip().splitlines()[-1][:60]})'); continue
        out, rc = execute(f'{D}/devicenet_test', {'TIERFS_DEVICE_SERVER': f'./{D}/mut_server'})
    else:
        r1 = run(BASE + ['-c', f'{D}/mut.cpp', '-o', f'{D}/mut.o'])
        if r1.returncode: print(f'{name:<44} (does not compile)'); continue
        run(['c++', '-o', f'{D}/mut_net_test', f'{D}/devicenet_test.o', f'{D}/mut.o', f'{D}/devicestore.o', f'{D}/crypto.o', CRYPTO, '-lsqlite3'])
        out, rc = execute(f'{D}/mut_net_test', {'TIERFS_DEVICE_SERVER': f'./{D}/server'})
    n = sum(1 for l in out.splitlines() if l.startswith('FAIL'))
    killed = n > 0 or rc != 0
    how = ('%d failing checks' % n) if n else ('exit code %d' % rc)
    tag = 'killed by ' + how if killed else 'SURVIVED'
    if name.startswith('[equivalent]'):
        print(f'{name:<44} {tag}  (equivalent mutant: behaviour is identical)')
    elif name.startswith('[power-loss]'):
        print(f'{name:<44} {tag}  (expected to survive: needs a power cut to observe)')
        if not killed: expected_survivors.append(name)
    else:
        print(f'{name:<44} {tag + "  <-- test gap" if not killed else tag}')
        if not killed: survivors.append(name)
subprocess.run(['pkill', '-f', 'mutd/'])
shutil.rmtree(D, ignore_errors=True)
print('survivors:', survivors if survivors else 'none')
if expected_survivors: print('power-loss mutants (untestable without cutting power):', len(expected_survivors))
