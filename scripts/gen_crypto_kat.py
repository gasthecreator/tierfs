#!/usr/bin/env python3
"""Generates tests/crypto_kat.hpp: known-answer vectors for core/crypto.cpp.

Independence: AES-256-GCM is computed here by a from-scratch pure-Python AES + GHASH
(no crypto library), and is first checked against the published NIST GCM test case 16
so the reference itself is trusted before it vouches for the C++ code. HMAC and HKDF
come from Python's stdlib and are also checked against RFC 4231 / RFC 5869 vectors.
Re-run:  python3 -I scripts/gen_crypto_kat.py
"""
import hashlib, hmac, random

# ---- pure Python AES-256 (encrypt only; GCM needs nothing else) ------------------
def xtime(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1
def gmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a = xtime(a); b >>= 1
    return r
INV = [0] * 256
for a in range(1, 256):
    for b in range(1, 256):
        if gmul(a, b) == 1: INV[a] = b; break
def rotl8(x, n): return ((x << n) | (x >> (8 - n))) & 0xFF
SBOX = []
for a in range(256):
    x = INV[a]
    SBOX.append(x ^ rotl8(x, 1) ^ rotl8(x, 2) ^ rotl8(x, 3) ^ rotl8(x, 4) ^ 0x63)

def expand_key(key):
    nk, nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]; t = [SBOX[b] for b in t]; t[0] ^= rcon; rcon = xtime(rcon)
        elif i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [sum((w[4 * r + c] for c in range(4)), []) for r in range(nr + 1)]

def aes_encrypt_block(rk, block):
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 15):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]            # ShiftRows (column-major state)
        if rnd != 14:                                                 # MixColumns
            n = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                n += [gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3], a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3],
                      a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3), gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)]
            s = n
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
    return bytes(s)

def ghash_mult(x, y):
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1: z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z

def gcm_encrypt(key, iv, plain, aad):
    assert len(iv) == 12
    rk = expand_key(key)
    H = int.from_bytes(aes_encrypt_block(rk, bytes(16)), 'big')
    j0 = iv + b'\x00\x00\x00\x01'
    ct = b''
    ctr = int.from_bytes(j0, 'big')
    for off in range(0, len(plain), 16):
        ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)
        ks = aes_encrypt_block(rk, ctr.to_bytes(16, 'big'))
        ct += bytes(p ^ k for p, k in zip(plain[off:off + 16], ks))
    def pad(b): return b + bytes(-len(b) % 16)
    data = pad(aad) + pad(ct) + (len(aad) * 8).to_bytes(8, 'big') + (len(ct) * 8).to_bytes(8, 'big')
    y = 0
    for off in range(0, len(data), 16):
        y = ghash_mult(y ^ int.from_bytes(data[off:off + 16], 'big'), H)
    tag = bytes(a ^ b for a, b in zip(aes_encrypt_block(rk, j0), y.to_bytes(16, 'big')))
    return ct, tag

# ---- trust the reference before using it -----------------------------------------
# NIST / McGrew-Viega GCM test case 16 (AES-256, 96-bit IV, with AAD).
K16 = bytes.fromhex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308')
IV16 = bytes.fromhex('cafebabefacedbaddecaf888')
P16 = bytes.fromhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
A16 = bytes.fromhex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
C16 = bytes.fromhex('522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662')
T16 = bytes.fromhex('76fc6ece0f4e1768cddf8853bb2d551b')
ct, tag = gcm_encrypt(K16, IV16, P16, A16)
assert ct == C16 and tag == T16, "reference AES-GCM does not match NIST test case 16"
# NIST test case 13 (AES-256, empty plaintext, no AAD): tag only
ct, tag = gcm_encrypt(bytes(32), bytes(12), b'', b'')
assert tag == bytes.fromhex('530f8afbc74536b9a963b4f1c4cb738b'), "reference mismatch on empty-message case"
# RFC 4231 test case 1 and RFC 5869 test case 1 against the stdlib
assert hmac.new(b'\x0b' * 20, b'Hi There', hashlib.sha256).hexdigest() == 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
def hkdf(ikm, salt, info, n):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest(); okm = b''; t = b''; i = 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); okm += t; i += 1
    return okm[:n]
assert hkdf(b'\x0b' * 22, bytes(range(13)), bytes(range(0xf0, 0xfa)), 42).hex() == '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
print("reference implementation validated against NIST GCM 13/16, RFC 4231, RFC 5869")

# ---- vectors for the C++ tests ----------------------------------------------------
rng = random.Random(20261011)
def rb(n): return bytes(rng.randrange(256) for _ in range(n))
def arr(name, b): return f"static const unsigned char {name}[] = {{{', '.join('0x%02x' % x for x in b) or '0'}}};\nstatic const size_t {name}_len = {len(b)};\n"

out = ["// GENERATED by scripts/gen_crypto_kat.py -- do not edit.\n#pragma once\n#include <cstddef>\n\n"]
out.append(arr("kat_gcm16_key", K16) + arr("kat_gcm16_iv", IV16) + arr("kat_gcm16_plain", P16) + arr("kat_gcm16_aad", A16)
           + arr("kat_gcm16_ct", C16) + arr("kat_gcm16_tag", T16))
# a spread of sizes, including block boundaries, with AAD shaped like ours
cases = []
for i, (plen, alen) in enumerate([(0, 11), (1, 40), (15, 40), (16, 40), (17, 65), (255, 70), (1000, 70), (4096, 80)]):
    key, iv, plain, aad = rb(32), rb(12), rb(plen), rb(alen)
    ct, tag = gcm_encrypt(key, iv, plain, aad)
    cases.append((key, iv, plain, aad, ct, tag))
    for nm, v in (("key", key), ("iv", iv), ("plain", plain), ("aad", aad), ("ct", ct), ("tag", tag)):
        out.append(arr(f"kat_case{i}_{nm}", v))
out.append(f"static const int kat_cases = {len(cases)};\n")
# HKDF/HMAC cross-check with the exact labels the product uses
master = rb(32)
salt = b"tfs1-hkdf-salt"
prk_labels = ["id", "data", "manifest", "snapshot", "file", "audit"]
out.append(arr("kat_master", master))
for lab in prk_labels:
    out.append(arr(f"kat_key_{lab}", hkdf(master, salt, b"tfs1:" + lab.encode(), 32)))
kid = hkdf(master, salt, b"tfs1:id", 32)
plain = rb(1000)
out.append(arr("kat_chunk_plain", plain))
out.append(arr("kat_chunk_id", hmac.new(kid, plain, hashlib.sha256).digest()))
out.append(arr("kat_fingerprint", hmac.new(kid, b"tfs1:fingerprint", hashlib.sha256).digest()))
kaud = hkdf(master, salt, b"tfs1:audit", 32)
cid = hmac.new(kid, plain, hashlib.sha256).hexdigest()
out.append(arr("kat_audit_nonce3", hmac.new(kaud, b"tfs1:audit:" + cid.encode() + b":3", hashlib.sha256).digest()))
blob = rb(777)
out.append(arr("kat_audit_blob", blob))
out.append(arr("kat_audit_response", hashlib.sha256(hmac.new(kaud, b"tfs1:audit:" + cid.encode() + b":3", hashlib.sha256).digest() + blob).digest()))
# recovery phrase: independent encoder
ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
payload = master + hashlib.sha256(b"tfs1:recovery" + master).digest()[:8]
bits = ''.join(f'{b:08b}' for b in payload)
chars = ''.join(ALPH[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))
assert len(chars) == 64
groups = []
for g in range(16):
    data = chars[4 * g:4 * g + 4]
    chk = ALPH[hashlib.sha256(b"tfs1:group" + bytes([g]) + data.encode()).digest()[0] & 31]
    groups.append(data + chk)
phrase = '-'.join(groups)
out.append(f'static const char* kat_phrase = "{phrase}";\n')
open('tests/crypto_kat.hpp', 'w').write(''.join(out))
print("wrote tests/crypto_kat.hpp;", len(cases), "GCM cases;", "phrase", phrase[:23] + "...")
