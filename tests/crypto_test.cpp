// Tests for the crypto layer: published vectors, vectors from an independent AES-GCM
// implementation (scripts/gen_crypto_kat.py), and attempts to break the guarantees.
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <set>
#include <thread>

#include "../core/crypto.hpp"
#include "crypto_kat.hpp"

using namespace tierfs::crypto;
namespace fs = std::filesystem;

static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) { printf("FAIL  line %d: %s\n", __LINE__, #cond); failures++; } \
        else printf("PASS  %s\n", #cond);                                          \
    } while (0)

#define B(name) Bytes(name, name + name##_len)
static Bytes bytes_of(const std::string& s) { return Bytes(s.begin(), s.end()); }
static std::string hex(const Bytes& b) { return to_hex(b.data(), b.size()); }
static bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }

struct GcmCase { Bytes key, iv, plain, aad, ct, tag; };
#define GC(i) {B(kat_case##i##_key), B(kat_case##i##_iv), B(kat_case##i##_plain), B(kat_case##i##_aad), B(kat_case##i##_ct), B(kat_case##i##_tag)}

static Bytes pattern(size_t n, uint8_t seed) {
    Bytes v(n);
    for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(seed + i * 131 + (i >> 8));
    return v;
}

int main() {
    {
        printf("== primitives against published vectors\n");
        Bytes abc = bytes_of("abc");
        CHECK(sha256_hex(abc.data(), abc.size()) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        CHECK(sha256_hex(nullptr, 0) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        Bytes k1(20, 0x0b), d1 = bytes_of("Hi There");   // RFC 4231 test case 1
        CHECK(hex(hmac_sha256(k1.data(), k1.size(), d1.data(), d1.size())) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        Bytes k2 = bytes_of("Jefe"), d2 = bytes_of("what do ya want for nothing?");   // test case 2
        CHECK(hex(hmac_sha256(k2.data(), k2.size(), d2.data(), d2.size())) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        Bytes ikm(22, 0x0b), salt, info;
        for (int i = 0; i < 13; i++) salt.push_back(static_cast<uint8_t>(i));
        for (int i = 0xf0; i <= 0xf9; i++) info.push_back(static_cast<uint8_t>(i));
        CHECK(hex(hkdf_sha256(ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(), info.size(), 42)) ==
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");   // RFC 5869 case 1
        CHECK(hex(hkdf_sha256(ikm.data(), ikm.size(), nullptr, 0, nullptr, 0, 42)) ==
              "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");    // case 3: no salt, no info
        CHECK(hkdf_sha256(ikm.data(), ikm.size(), nullptr, 0, nullptr, 0, 255 * 32 + 1).empty());       // beyond the RFC limit
        CHECK(to_hex(abc.data(), 3) == "616263" && from_hex("616263").value() == abc && !from_hex("6g").has_value() && !from_hex("123").has_value());
        CHECK(ct_equal("abcd", "abcd", 4) && !ct_equal("abcd", "abce", 4));
    }

    {
        printf("== AES-256-GCM against NIST test case 16 and an independent implementation\n");
        SecretKey k16(kat_gcm16_key);
        std::string aad16(reinterpret_cast<const char*>(kat_gcm16_aad), kat_gcm16_aad_len);
        Bytes blob = testing::aead_seal_fixed_nonce(k16, B(kat_gcm16_iv), aad16, kat_gcm16_plain, kat_gcm16_plain_len);
        Bytes want = {FORMAT_V1};
        for (auto part : {B(kat_gcm16_iv), B(kat_gcm16_ct), B(kat_gcm16_tag)}) want.insert(want.end(), part.begin(), part.end());
        CHECK(blob == want);
        Bytes plain;
        CHECK(testing::aead_open(k16, aad16, blob.data(), blob.size(), plain) == OpenError::Ok && plain == B(kat_gcm16_plain));

        GcmCase cases[] = {GC(0), GC(1), GC(2), GC(3), GC(4), GC(5), GC(6), GC(7)};
        int agree = 0, opened = 0;
        for (auto& c : cases) {
            SecretKey key(c.key.data());
            std::string aad(c.aad.begin(), c.aad.end());
            Bytes b = testing::aead_seal_fixed_nonce(key, c.iv, aad, c.plain.data(), c.plain.size());
            Bytes w = {FORMAT_V1};
            w.insert(w.end(), c.iv.begin(), c.iv.end());
            w.insert(w.end(), c.ct.begin(), c.ct.end());
            w.insert(w.end(), c.tag.begin(), c.tag.end());
            agree += b == w;
            Bytes pl;
            opened += testing::aead_open(key, aad, w.data(), w.size(), pl) == OpenError::Ok && pl == c.plain;
        }
        CHECK(agree == 8 && opened == 8);   // sizes 0,1,15,16,17,255,1000,4096: every block boundary
    }

    {
        printf("== key derivation, chunk ids, audits match the independent reference\n");
        SecretKey master(kat_master);
        Keys k(master);
        CHECK(Bytes(k.id().data(), k.id().data() + 32) == B(kat_key_id));
        CHECK(Bytes(k.data().data(), k.data().data() + 32) == B(kat_key_data));
        CHECK(Bytes(k.manifest().data(), k.manifest().data() + 32) == B(kat_key_manifest));
        CHECK(Bytes(k.snapshot().data(), k.snapshot().data() + 32) == B(kat_key_snapshot));
        CHECK(Bytes(k.file().data(), k.file().data() + 32) == B(kat_key_file));
        CHECK(Bytes(k.audit().data(), k.audit().data() + 32) == B(kat_key_audit));
        std::set<std::string> distinct;
        for (const SecretKey* sk : {&k.id(), &k.data(), &k.manifest(), &k.snapshot(), &k.file(), &k.audit()}) distinct.insert(hex(Bytes(sk->data(), sk->data() + 32)));
        CHECK(distinct.size() == 6);   // no two purposes share a key
        CHECK(chunk_id(k, kat_chunk_plain, kat_chunk_plain_len) == hex(B(kat_chunk_id)));
        CHECK(k.fingerprint() == hex(B(kat_fingerprint)).substr(0, 16));
        std::string cid = chunk_id(k, kat_chunk_plain, kat_chunk_plain_len);
        CHECK(audit_nonce(k, cid, 3) == B(kat_audit_nonce3));
        CHECK(audit_nonce(k, cid, 3) != audit_nonce(k, cid, 4));
        CHECK(audit_response_hex(audit_nonce(k, cid, 3), kat_audit_blob, kat_audit_blob_len) == hex(B(kat_audit_response)));
        SecretKey other = SecretKey::random();
        CHECK(other.valid() && Keys(other).fingerprint() != k.fingerprint());
        CHECK(chunk_id(Keys(other), kat_chunk_plain, kat_chunk_plain_len) != cid);   // ids are keyed: a device cannot compute them
    }

    {
        printf("== sealing chunks: round trip and every way of breaking it\n");
        Keys k(SecretKey::random());
        std::string vol = "vol-1";
        Bytes plain = pattern(100000, 7);
        std::string cid = chunk_id(k, plain.data(), plain.size());
        Bytes blob = seal_chunk(k, vol, cid, plain.data(), plain.size());
        CHECK(blob.size() == 1 + NONCE_LEN + plain.size() + TAG_LEN && blob[0] == FORMAT_V1);
        CHECK(std::search(blob.begin(), blob.end(), plain.begin(), plain.begin() + 64) == blob.end());   // the device sees no plaintext
        Bytes out;
        CHECK(open_chunk(k, vol, cid, blob.data(), blob.size(), out) == OpenError::Ok && out == plain);

        // empty chunk and a one-byte chunk
        std::string cid0 = chunk_id(k, nullptr, 0);
        Bytes b0 = seal_chunk(k, vol, cid0, nullptr, 0);
        CHECK(!b0.empty() && open_chunk(k, vol, cid0, b0.data(), b0.size(), out) == OpenError::Ok && out.empty());

        // wrong key / wrong volume / wrong chunk id
        Keys other(SecretKey::random());
        CHECK(open_chunk(other, vol, cid, blob.data(), blob.size(), out) == OpenError::AuthFailed && out.empty());
        CHECK(open_chunk(k, "vol-2", cid, blob.data(), blob.size(), out) == OpenError::AuthFailed);
        Bytes p2 = pattern(100000, 8);
        std::string cid2 = chunk_id(k, p2.data(), p2.size());
        CHECK(open_chunk(k, vol, cid2, blob.data(), blob.size(), out) == OpenError::AuthFailed);   // device handed back chunk A for chunk B

        // a blob that is authentic but is not the chunk its id claims
        Bytes liar = seal_chunk(k, vol, cid2, plain.data(), plain.size());   // sealed under cid2 but contains `plain`
        CHECK(open_chunk(k, vol, cid2, liar.data(), liar.size(), out) == OpenError::IdMismatch && out.empty());

        // flip every single bit position class: header, nonce, ciphertext start/middle/end, tag
        int detected = 0, tried = 0;
        for (size_t pos : {size_t(0), size_t(1), size_t(5), NONCE_LEN, NONCE_LEN + 1, blob.size() / 2, blob.size() - TAG_LEN - 1, blob.size() - TAG_LEN, blob.size() - 1}) {
            for (int bit : {0, 3, 7}) {
                Bytes t = blob;
                t[pos] ^= static_cast<uint8_t>(1 << bit);
                tried++;
                detected += open_chunk(k, vol, cid, t.data(), t.size(), out) != OpenError::Ok && out.empty();
            }
        }
        CHECK(tried == 27 && detected == 27);
        // truncation and extension
        CHECK(open_chunk(k, vol, cid, blob.data(), blob.size() - 1, out) == OpenError::AuthFailed);
        CHECK(open_chunk(k, vol, cid, blob.data(), 20, out) == OpenError::BadFormat);
        CHECK(open_chunk(k, vol, cid, blob.data(), 0, out) == OpenError::BadFormat);
        CHECK(open_chunk(k, vol, cid, nullptr, 0, out) == OpenError::BadFormat);
        Bytes ext = blob;
        ext.push_back(0);
        CHECK(open_chunk(k, vol, cid, ext.data(), ext.size(), out) == OpenError::AuthFailed);
        Bytes v2 = blob;
        v2[0] = 2;
        CHECK(open_chunk(k, vol, cid, v2.data(), v2.size(), out) == OpenError::Unsupported);

        // a chunk cannot be opened as a manifest or the other way round
        Bytes viaData = testing::aead_seal_fixed_nonce(k.data(), Bytes(12, 1), "tfs1:manifest:vol-1:f:1", plain.data(), 100);
        Manifest mm;
        CHECK(open_manifest(k, vol, "f", 1, viaData.data(), viaData.size(), mm) == OpenError::AuthFailed);   // wrong key purpose
    }

    {
        printf("== nonces are fresh, counted, and bounded\n");
        Keys k(SecretKey::random());
        Bytes p = pattern(64, 1);
        std::string cid = chunk_id(k, p.data(), p.size());
        std::set<std::string> nonces;
        for (int i = 0; i < 20000; i++) {
            Bytes b = seal_chunk(k, "v", cid, p.data(), p.size());
            nonces.insert(hex(Bytes(b.begin() + 1, b.begin() + 1 + NONCE_LEN)));
        }
        CHECK(nonces.size() == 20000);          // never reused
        CHECK(k.seal_count() == 20000);
        k.set_seal_count_for_test(MAX_SEALS_PER_KEY - 1);
        CHECK(!seal_chunk(k, "v", cid, p.data(), p.size()).empty());   // last one allowed
        CHECK(seal_chunk(k, "v", cid, p.data(), p.size()).empty());    // then it refuses rather than risk a nonce collision
        Keys k2(SecretKey::random());
        std::thread t[4];
        for (auto& th : t) th = std::thread([&] { for (int i = 0; i < 500; i++) seal_chunk(k2, "v", cid, p.data(), p.size()); });
        for (auto& th : t) th.join();
        CHECK(k2.seal_count() == 2000);         // thread-safe accounting
    }

    {
        printf("== whole-file HMAC streams identically however the data is split\n");
        Keys k(SecretKey::random());
        Bytes data = pattern(300000, 3);
        Bytes one = hmac_sha256(k.file().data(), 32, data.data(), data.size());
        FileHmac a(k);
        a.update(data.data(), data.size());
        CHECK(a.finish_hex() == hex(one));
        FileHmac b(k);
        for (size_t off = 0; off < data.size(); off += 70001) b.update(data.data() + off, std::min<size_t>(70001, data.size() - off));
        CHECK(b.finish_hex() == hex(one));
        FileHmac c(k);
        c.update(data.data(), data.size() - 1);   // a missing byte changes it
        CHECK(c.finish_hex() != hex(one));
        CHECK(b.finish_hex().empty());            // single use
    }

    {
        printf("== manifests: round trip, binding to file and version, tampering\n");
        Keys k(SecretKey::random());
        Manifest m;
        m.file_id = "0123456789abcdef0123456789abcdef";
        m.version = 4;
        m.prev_version = 3;
        m.path = "/Users/someone/Projects/\xc3\xa9t\xc3\xa9/\xe6\x97\xa5\xe6\x9c\xac.txt";   // non-ASCII path
        m.mode = 0100644;
        m.mtime = 1'700'000'123;
        m.size = 2'500'000;
        m.file_hmac = std::string(64, 'a');
        m.xattrs = {{"com.apple.quarantine", bytes_of("0083;5f;Safari;")}, {"user.empty", {}}, {"user.big", pattern(200000, 9)}};
        for (uint32_t i = 0; i < 3; i++) m.chunks.push_back({std::string(64, char('b' + i)), i < 2 ? (1u << 20) : 402848u});
        Bytes blob = seal_manifest(k, "vol", m);
        CHECK(!blob.empty());
        CHECK(std::search(blob.begin(), blob.end(), m.path.begin(), m.path.end()) == blob.end());   // path names are hidden from the device
        Manifest got;
        CHECK(open_manifest(k, "vol", m.file_id, 4, blob.data(), blob.size(), got) == OpenError::Ok && got == m);
        CHECK(open_manifest(k, "vol", m.file_id, 3, blob.data(), blob.size(), got) == OpenError::AuthFailed);          // another version's slot
        CHECK(open_manifest(k, "vol", "ffffffffffffffffffffffffffffffff", 4, blob.data(), blob.size(), got) == OpenError::AuthFailed);  // another file
        CHECK(open_manifest(k, "other", m.file_id, 4, blob.data(), blob.size(), got) == OpenError::AuthFailed);       // another volume
        Bytes t = blob;
        t[blob.size() / 2] ^= 1;
        CHECK(open_manifest(k, "vol", m.file_id, 4, t.data(), t.size(), got) == OpenError::AuthFailed);
        CHECK(open_manifest(k, "vol", m.file_id, 4, blob.data(), 10, got) == OpenError::BadFormat);
        // authentic, correctly addressed, but describing a different file/version inside
        Manifest liar = m;
        liar.version = 5;
        Bytes lb = seal_manifest(k, "vol", liar);   // sealed in slot 5 ...
        CHECK(open_manifest(k, "vol", m.file_id, 5, lb.data(), lb.size(), got) == OpenError::Ok && got.version == 5);
        // A manifest that is authentic and sits in slot 4 but whose body says it is version 5
        // (only a key holder could build it; the body check is defence in depth).
        Bytes mismatched = testing::seal_manifest_in_slot(k, "vol", m.file_id, 4, liar);
        CHECK(!mismatched.empty() && open_manifest(k, "vol", m.file_id, 4, mismatched.data(), mismatched.size(), got) == OpenError::IdMismatch);
        Bytes padded = testing::seal_manifest_with_trailer(k, "vol", m, Bytes{0x00});
        CHECK(!padded.empty() && open_manifest(k, "vol", m.file_id, 4, padded.data(), padded.size(), got) == OpenError::BadFormat);   // nothing may ride along after the body
        Manifest other_file = m;
        other_file.file_id = "ffffffffffffffffffffffffffffffff";
        Bytes mm2 = testing::seal_manifest_in_slot(k, "vol", m.file_id, 4, other_file);
        CHECK(open_manifest(k, "vol", m.file_id, 4, mm2.data(), mm2.size(), got) == OpenError::IdMismatch);
        Manifest empty;
        empty.file_id = "x"; empty.version = 1;
        Bytes eb = seal_manifest(k, "vol", empty);
        CHECK(open_manifest(k, "vol", "x", 1, eb.data(), eb.size(), got) == OpenError::Ok && got == empty);
        Manifest huge = m;
        huge.xattrs = {{"a", Bytes(MAX_XATTR_VALUE + 1, 0)}};
        CHECK(seal_manifest(k, "vol", huge).empty());   // refused, not truncated
        huge.xattrs.clear();
        for (int i = 0; i < 5; i++) huge.xattrs.push_back({"n" + std::to_string(i), Bytes(MAX_XATTR_VALUE, 0)});
        CHECK(seal_manifest(k, "vol", huge).empty());   // total cap
        // a hostile device cannot make us allocate: lengths inside an authentic-looking body are checked
        Bytes junk = testing::aead_seal_fixed_nonce(k.manifest(), Bytes(12, 2), "tfs1:manifest:vol:x:1", reinterpret_cast<const uint8_t*>("\xff\xff\xff\xff\xff\xff\xff\xff"), 8);
        CHECK(open_manifest(k, "vol", "x", 1, junk.data(), junk.size(), got) == OpenError::BadFormat);
    }

    {
        printf("== recovery phrase\n");
        SecretKey master(kat_master);
        std::string phrase = encode_recovery(master);
        CHECK(phrase == kat_phrase);                          // matches the independent encoder
        CHECK(phrase.size() == 16 * 5 + 15);
        std::string err;
        auto back = decode_recovery(phrase, &err);
        CHECK(back && *back == master);

        // forgiving input: lowercase, spaces instead of hyphens, no separators, I/L/O
        std::string spaced = phrase;
        for (char& c : spaced) if (c == '-') c = ' ';
        std::string lower = phrase;
        for (char& c : lower) c = static_cast<char>(tolower(c));
        std::string nosep;
        for (char c : phrase) if (c != '-') nosep += c;
        CHECK(decode_recovery(spaced, &err) && decode_recovery(lower, &err) && decode_recovery(nosep, &err));
        std::string swapped = phrase;   // 0->O and 1->l must read back as 0 and 1
        for (char& c : swapped) { if (c == '0') c = 'O'; else if (c == '1') c = 'l'; }
        auto sw = decode_recovery(swapped, &err);
        CHECK(sw && *sw == master);

        // typos are pinpointed
        for (int g : {1, 7, 16}) {
            std::string t = phrase;
            size_t pos = static_cast<size_t>((g - 1) * 6 + 1);
            t[pos] = t[pos] == 'A' ? 'B' : 'A';
            CHECK(!decode_recovery(t, &err) && has(err, ("group " + std::to_string(g)).c_str()));
        }
        // two groups swapped (each group is right, the order is not)
        {
            std::string t = phrase;
            std::string g2 = t.substr(6, 5), g3 = t.substr(12, 5);
            t.replace(6, 5, g3);
            t.replace(12, 5, g2);
            CHECK(!decode_recovery(t, &err) && has(err, "group"));
        }
        CHECK(!decode_recovery("", &err) && has(err, "0 characters"));
        CHECK(!decode_recovery(phrase.substr(0, phrase.size() - 6), &err) && has(err, "characters"));   // a group missing
        CHECK(!decode_recovery(phrase + "A", &err));
        CHECK(!decode_recovery("!" + phrase, &err) && has(err, "cannot appear"));
        // a forged phrase whose groups are internally consistent still fails the checksum
        {
            std::string norm;
            for (char c : phrase) if (c != '-') norm += c;
            norm[0] = norm[0] == 'A' ? 'B' : 'A';
            // recompute group 1's check character the way the encoder does (tests the layering, not secrecy)
            std::string four = norm.substr(0, 4);
            std::string m = "tfs1:group";
            m += static_cast<char>(0);
            m += four;
            Bytes h = sha256(reinterpret_cast<const uint8_t*>(m.data()), m.size());
            norm[4] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"[h[0] & 31];
            CHECK(!decode_recovery(norm, &err) && has(err, "checksum"));
        }
        // a different key gives a different phrase and the phrase is not the key
        SecretKey r1 = SecretKey::random(), r2 = SecretKey::random();
        CHECK(encode_recovery(r1) != encode_recovery(r2));
        for (int i = 0; i < 50; i++) {   // many random keys round trip
            SecretKey r = SecretKey::random();
            auto d = decode_recovery(encode_recovery(r), &err);
            if (!d || !(*d == r)) { CHECK(false); break; }
            if (i == 49) CHECK(true);
        }

        // confirmation: the user must retype randomly chosen groups
        auto picks = pick_confirm_groups(3);
        CHECK(picks.size() == 3 && picks[0] != picks[1] && picks[1] != picks[2] && picks[0] != picks[2]);
        bool in_range = true;
        for (int g : picks) in_range &= g >= 1 && g <= 16;
        CHECK(in_range);
        int g = picks[0];
        std::string right = phrase.substr(static_cast<size_t>((g - 1) * 6), 5);
        std::string lowered = right;
        for (char& c : lowered) c = static_cast<char>(tolower(c));
        CHECK(check_confirm_group(phrase, g, right) && check_confirm_group(phrase, g, lowered));
        std::string wrong = right;
        wrong[0] = wrong[0] == 'A' ? 'B' : 'A';
        CHECK(!check_confirm_group(phrase, g, wrong) && !check_confirm_group(phrase, g, "") && !check_confirm_group(phrase, 0, right) &&
              !check_confirm_group(phrase, 17, right));
        std::set<std::string> draws;
        for (int i = 0; i < 20; i++) { auto p = pick_confirm_groups(3); draws.insert(std::to_string(p[0]) + "," + std::to_string(p[1]) + "," + std::to_string(p[2])); }
        CHECK(draws.size() > 5);                              // not always the same three
        CHECK(pick_confirm_groups(99).size() == 16 && pick_confirm_groups(0).empty());
    }

    {
        printf("== keys are wiped from memory when destroyed\n");
        alignas(SecretKey) unsigned char storage[sizeof(SecretKey)];
        auto* k = new (storage) SecretKey(SecretKey::random());
        CHECK(k->valid());
        Bytes before(k->data(), k->data() + 32);
        k->~SecretKey();
        bool zero = true;
        for (size_t i = 0; i < sizeof storage; i++) zero &= storage[i] == 0;   // inspecting storage we still own
        CHECK(zero && before != Bytes(32, 0));

        SecretKey a = SecretKey::random();
        Bytes av(a.data(), a.data() + 32);
        SecretKey b = std::move(a);
        CHECK(Bytes(b.data(), b.data() + 32) == av && !a.valid());   // a moved-from key does not keep a copy
        CHECK(!SecretKey().valid());
    }

    {
        printf("== file key store (development): safe by construction\n");
        char t[] = "/tmp/tierfs-keytest-XXXXXX";
        std::string dir = mkdtemp(t);
        auto ks = make_file_keystore(dir);
        SecretKey key = SecretKey::random();
        CHECK(ks->store("vol-abc_1", key));
        CHECK(!ks->store("vol-abc_1", SecretKey::random()));     // never overwrites a master key
        auto loaded = ks->load("vol-abc_1");
        CHECK(loaded && *loaded == key);
        struct stat st;
        stat((dir + "/vol-abc_1.key").c_str(), &st);
        CHECK((st.st_mode & 0777) == 0600);
        chmod((dir + "/vol-abc_1.key").c_str(), 0640);            // others could now read it
        CHECK(!ks->load("vol-abc_1").has_value());                // so it is refused
        chmod((dir + "/vol-abc_1.key").c_str(), 0600);
        CHECK(!ks->load("nope").has_value());
        for (const char* bad : {"", "../escape", "a/b", "a b", "..", "x\n"}) CHECK(!ks->store(bad, key) && !ks->load(bad));
        CHECK(!ks->store(std::string(65, 'a'), key));
        CHECK(ks->erase("vol-abc_1") && !ks->load("vol-abc_1") && !ks->erase("vol-abc_1"));
        fs::remove_all(dir);
    }

#ifdef __APPLE__
    if (getenv("TIERFS_TEST_KEYCHAIN")) {
        printf("== login Keychain (opt-in: creates then deletes one 'tierfs-master-key' item)\n");
        auto ks = make_keychain_keystore();
        std::string vol = "tierfs-selftest-" + to_hex(random_bytes(6).data(), 6);
        SecretKey key = SecretKey::random();
        CHECK(ks->store(vol, key));
        CHECK(!ks->store(vol, SecretKey::random()));
        auto got = ks->load(vol);
        CHECK(got && *got == key);
        CHECK(ks->erase(vol) && !ks->load(vol).has_value());
    } else {
        printf("(Keychain test skipped; run with TIERFS_TEST_KEYCHAIN=1 to exercise the real login Keychain)\n");
    }
#endif

    printf("---- %d failure(s)\n", failures);
    return failures != 0;
}
