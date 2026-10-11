#!/usr/bin/env python3
"""Mutation test for core/crypto.cpp: remove one protection at a time and check that
tests/crypto_test.cpp notices. A SURVIVOR is a hole in the tests (or an equivalent
mutant, which must then be explained). A crashing test run counts as killed."""
import subprocess, sys, os, shutil
M = [
 ("chunk AAD dropped",                  'return "tfs1:chunk:" + volume_id + ":" + chunk_id;', 'return "";'),
 ("chunk AAD without chunk id",         'return "tfs1:chunk:" + volume_id + ":" + chunk_id;', 'return "tfs1:chunk:" + volume_id;'),
 ("chunk AAD without volume",           'return "tfs1:chunk:" + volume_id + ":" + chunk_id;', 'return "tfs1:chunk:" + chunk_id;'),
 ("manifest AAD dropped",               'return "tfs1:manifest:" + volume_id + ":" + file_id + ":" + std::to_string(version);', 'return "";'),
 ("manifest AAD without version",       'return "tfs1:manifest:" + volume_id + ":" + file_id + ":" + std::to_string(version);', 'return "tfs1:manifest:" + volume_id + ":" + file_id;'),
 ("manifest AAD without file id",       'return "tfs1:manifest:" + volume_id + ":" + file_id + ":" + std::to_string(version);', 'return "tfs1:manifest:" + volume_id + ":" + std::to_string(version);'),
 ("GCM tag not verified",               'good = good && EVP_DecryptFinal_ex(ctx, plain.data() + len, &n) == 1;', 'good = good;'),
 ("SIV ignores the plaintext",          '{plain, len}});', '{plain, 0}});'),
 ("SIV ignores the AAD",                '{reinterpret_cast<const uint8_t*>(aad.data()), aad.size()},', '{reinterpret_cast<const uint8_t*>(aad.data()), 0},'),
 ("SIV has no AAD length prefix",       'std::string head = "tfs1:siv:" + std::to_string(aad.size()) + ":";', 'std::string head = "tfs1:siv:";'),
 ("SIV under the wrong key",            'hmac_sha256_parts(k.nonce().data(), KEY_LEN,', 'hmac_sha256_parts(k.id().data(), KEY_LEN,'),
 ("SIV nonce keeps only 16 bits",       'Bytes nonce(mac.begin(), mac.begin() + NONCE_LEN);', 'Bytes nonce(NONCE_LEN, 0); std::copy(mac.begin(), mac.begin() + 2, nonce.begin());'),
 ("nonce key reuses the id label",      'derive("nonce", nonce_);', 'derive("id", nonce_);'),
 ("snapshot key reuses data label",     'derive("snapshot", snapshot_);', 'derive("data", snapshot_);'),
 ("audit key reuses id label",          'derive("audit", audit_);', 'derive("id", audit_);'),
 ("chunk id is an unkeyed hash",        'Bytes h = hmac_sha256(k.id().data(), KEY_LEN, plain, len);', 'Bytes h = sha256(plain, len);'),
 ("open_chunk skips the id check",      'if (actual.size() != cid.size() || !ct_equal(actual.data(), cid.data(), cid.size())) {', 'if (false) {'),
 ("open_manifest skips slot check",     'if (m.file_id != file_id || m.version != version) return OpenError::IdMismatch;', ''),
 ("file HMAC under the wrong key",      'EVP_MAC_init(impl_->ctx, k.file().data(), KEY_LEN, params)', 'EVP_MAC_init(impl_->ctx, k.id().data(), KEY_LEN, params)'),
 ("audit nonce ignores counter",        'std::string m = "tfs1:audit:" + cid + ":" + std::to_string(n);', 'std::string m = "tfs1:audit:" + cid;'),
 ("audit response ignores nonce",       'EVP_DigestUpdate(ctx, nonce.data(), nonce.size()) == 1 &&', 'true &&'),
 ("recovery: group checks skipped",     'if (group_check_char(g, four) != norm[5 * g + 4])', 'if (false)'),
 ("recovery: checksum skipped",         'bool good = ct_equal(sum.data(), payload + KEY_LEN, 8);', 'bool good = true;'),
 ("recovery: O not read as 0",          "if (c == 'O') c = '0';", ''),
 ("recovery: group index not in check", 'm += static_cast<char>(group0);', ''),
 ("confirm always accepts",             'return ct_equal(p.data() + 5 * (g - 1), t.data(), 5);', 'return true;'),
 ("confirm groups not shuffled",        'std::swap(all[i], all[rand_below(static_cast<uint32_t>(i + 1))]);', ''),
 ("SecretKey not wiped on destroy",     'SecretKey::~SecretKey() { OPENSSL_cleanse(b_.data(), KEY_LEN); }', 'SecretKey::~SecretKey() {}'),
 ("moved-from key keeps a copy",        'b_ = o.b_;\n    OPENSSL_cleanse(o.b_.data(), KEY_LEN);\n}\nSecretKey& SecretKey::operator=', 'b_ = o.b_;\n}\nSecretKey& SecretKey::operator='),
 ("SecretKey::valid always true",       'return acc != 0;', 'return true;'),
 ("keystore overwrites keys",           'O_WRONLY | O_CREAT | O_EXCL', 'O_WRONLY | O_CREAT | O_TRUNC'),
 ("keystore ignores file permissions",  'if (fstat(fd, &st) != 0 || (st.st_mode & 077) != 0 || st.st_uid != getuid()) { close(fd); return std::nullopt; }', 'if (fstat(fd, &st) != 0) { close(fd); return std::nullopt; }'),
 ("keystore accepts any volume id",     "if (!isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') return \"\";", ''),
 ("xattr value cap removed",            'if (x.second.size() > MAX_XATTR_VALUE) return {};', ''),
 ("xattr total cap removed",            'if (xtotal > MAX_XATTR_TOTAL) return {};\n    Writer w;', 'Writer w;'),
 ("manifest trailing bytes allowed",    'if (r.remaining() != 0) throw std::runtime_error("trailing bytes");', ''),
 ("format version not checked",         'if (blob[0] != FORMAT_V1) return OpenError::Unsupported;', ''),
 ("HKDF ignores the salt",              'Bytes prk = salt_len ? hmac_sha256(salt, salt_len, ikm, ikm_len) : hmac_sha256(zeros, 32, ikm, ikm_len);', 'Bytes prk = hmac_sha256(zeros, 32, ikm, ikm_len);'),
 ("HKDF block counter stuck",           'msg.push_back(i);', 'msg.push_back(1);'),
 ("random_bytes returns zeros",         'if (n && RAND_bytes(b.data(), static_cast<int>(n)) != 1) return {};', ''),
]
only = sys.argv[1:]
src = open('core/crypto.cpp').read()
os.makedirs('build/mutc', exist_ok=True)
OS = os.environ.get('OPENSSL_DIR', '/opt/homebrew/opt/openssl@3')
survivors = []
for name, frm, to in M:
    if only and not any(o in name for o in only): continue
    if frm not in src:
        print(f"{name:<40} !! pattern not found (mutant list is stale)"); survivors.append(name + " (stale)"); continue
    open('build/mutc/crypto.cpp', 'w').write(src.replace(frm, to, 1))
    for h in ('crypto.hpp', 'wire.hpp'): shutil.copy('core/' + h, 'build/mutc/' + h)
    r = subprocess.run(['c++', '-std=c++17', '-g', '-w', f'-I{OS}/include', '-Ibuild/mutc', '-Itests', 'tests/crypto_test.cpp', 'build/mutc/crypto.cpp',
                        'core/keychain_mac.cpp', f'{OS}/lib/libcrypto.a', '-framework', 'Security', '-framework', 'CoreFoundation', '-o', 'build/mutc/t'],
                       capture_output=True, text=True)
    if r.returncode:
        print(f"{name:<40} (does not compile: {r.stderr.strip().splitlines()[-1][:70] if r.stderr.strip() else '?'})"); continue
    try:
        p = subprocess.run(['build/mutc/t'], capture_output=True, text=True, timeout=180)
        out, rc = p.stdout, p.returncode
    except subprocess.TimeoutExpired:
        out, rc = 'FAIL timeout', 99
    n = sum(1 for l in out.splitlines() if l.startswith('FAIL'))
    killed = n > 0 or rc != 0
    how = ('%d failing checks' % n) if n else ('exit code %d' % rc)
    print(f"{name:<40} {'killed by ' + how if killed else 'SURVIVED  <-- test gap'}")
    if not killed: survivors.append(name)
shutil.rmtree('build/mutc', ignore_errors=True)
print("survivors:", survivors if survivors else "none")
