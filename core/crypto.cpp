#include "crypto.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>

#include "wire.hpp"

namespace tierfs {
namespace crypto {

namespace {

constexpr size_t MAX_PLAINTEXT = 64u << 20;  // sanity bound on one sealed message

const char* const HKDF_SALT = "tfs1-hkdf-salt";

void wipe(Bytes& b) {
    if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
}

// ---- AES-256-GCM with a 12-byte random nonce; layout 0x01 || nonce || ct || tag ----

Bytes aead_seal_with(const SecretKey& key, const Bytes& nonce, const std::string& aad, const uint8_t* plain, size_t len) {
    if (len > MAX_PLAINTEXT || (len && !plain) || nonce.size() != NONCE_LEN) return {};

    Bytes out(1 + NONCE_LEN + len + TAG_LEN);
    out[0] = FORMAT_V1;
    memcpy(out.data() + 1, nonce.data(), NONCE_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    bool good = ctx != nullptr;
    int n = 0;
    good = good && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
           EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
           EVP_EncryptUpdate(ctx, nullptr, &n, reinterpret_cast<const uint8_t*>(aad.data()), static_cast<int>(aad.size())) == 1;
    if (good && len) good = EVP_EncryptUpdate(ctx, out.data() + 1 + NONCE_LEN, &n, plain, static_cast<int>(len)) == 1 &&
                            static_cast<size_t>(n) == len;
    uint8_t* tag = out.data() + 1 + NONCE_LEN + len;
    good = good && EVP_EncryptFinal_ex(ctx, tag, &n) == 1 && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) == 1;
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (!good) return {};
    return out;
}

// Production path: a synthetic IV, HMAC(K_nonce, "tfs1:siv:<len(aad)>:" || aad || plaintext)[:12].
// The same (aad, plaintext) always seals to the same bytes; any difference in either gives an
// unrelated nonce, so a nonce is never reused with different data.
Bytes aead_seal(const Keys& k, const SecretKey& key, const std::string& aad, const uint8_t* plain, size_t len) {
    if (len > MAX_PLAINTEXT || (len && !plain)) return {};
    std::string head = "tfs1:siv:" + std::to_string(aad.size()) + ":";
    Bytes mac = hmac_sha256_parts(k.nonce().data(), KEY_LEN,
                                  {{reinterpret_cast<const uint8_t*>(head.data()), head.size()},
                                   {reinterpret_cast<const uint8_t*>(aad.data()), aad.size()},
                                   {plain, len}});
    if (mac.size() != 32) return {};
    Bytes nonce(mac.begin(), mac.begin() + NONCE_LEN);
    return aead_seal_with(key, nonce, aad, plain, len);
}

OpenError aead_open(const SecretKey& key, const std::string& aad, const uint8_t* blob, size_t blen, Bytes& plain) {
    plain.clear();
    if (!blob || blen < 1 + NONCE_LEN + TAG_LEN) return OpenError::BadFormat;
    if (blob[0] != FORMAT_V1) return OpenError::Unsupported;
    size_t len = blen - 1 - NONCE_LEN - TAG_LEN;
    if (len > MAX_PLAINTEXT) return OpenError::BadFormat;
    const uint8_t* nonce = blob + 1;
    const uint8_t* ct = blob + 1 + NONCE_LEN;
    uint8_t tag[TAG_LEN];
    memcpy(tag, ct + len, TAG_LEN);

    plain.resize(len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    bool good = ctx != nullptr;
    int n = 0;
    good = good && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
           EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) == 1 &&
           EVP_DecryptUpdate(ctx, nullptr, &n, reinterpret_cast<const uint8_t*>(aad.data()), static_cast<int>(aad.size())) == 1;
    if (good && len) good = EVP_DecryptUpdate(ctx, plain.data(), &n, ct, static_cast<int>(len)) == 1 && static_cast<size_t>(n) == len;
    good = good && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) == 1;
    // Final verifies the tag. Plaintext must not be used unless it returns 1.
    good = good && EVP_DecryptFinal_ex(ctx, plain.data() + len, &n) == 1;
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (!good) {
        wipe(plain);
        plain.clear();
        return OpenError::AuthFailed;
    }
    return OpenError::Ok;
}

std::string chunk_aad(const std::string& volume_id, const std::string& chunk_id) {
    return "tfs1:chunk:" + volume_id + ":" + chunk_id;
}
std::string manifest_aad(const std::string& volume_id, const std::string& file_id, int64_t version) {
    return "tfs1:manifest:" + volume_id + ":" + file_id + ":" + std::to_string(version);
}

// ---- length-prefixed bytes for manifests ----
void put_bytes32(Writer& w, const Bytes& b) {
    w.u32(static_cast<uint32_t>(b.size()));
    w.bytes(b.data(), b.size());
}
void put_text32(Writer& w, const std::string& s) {
    w.u32(static_cast<uint32_t>(s.size()));
    w.bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
Bytes get_bytes32(Reader& r, size_t max) {
    uint32_t n = r.u32();
    if (n > max) throw std::runtime_error("field too large");
    r.need(n);
    Bytes b(r.p + r.pos, r.p + r.pos + n);
    r.pos += n;
    return b;
}
std::string get_text32(Reader& r, size_t max) {
    Bytes b = get_bytes32(r, max);
    return std::string(b.begin(), b.end());
}

// ---- Crockford base32 ----
const char* const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

int b32_value(char c) {
    const char* p = strchr(B32, c);
    return (p && c) ? static_cast<int>(p - B32) : -1;
}

// Uppercase, drop separators, read O as 0 and I/L as 1. Returns false on a character
// that cannot be part of a phrase.
bool normalize_phrase(const std::string& in, std::string& out, char* bad) {
    out.clear();
    for (unsigned char ch : in) {
        if (ch == ' ' || ch == '-' || ch == '\t' || ch == '\n' || ch == '\r') continue;
        char c = static_cast<char>(toupper(ch));
        if (c == 'O') c = '0';
        if (c == 'I' || c == 'L') c = '1';
        if (b32_value(c) < 0) { if (bad) *bad = static_cast<char>(ch); return false; }
        out += c;
    }
    return true;
}

char group_check_char(int group0, const std::string& four) {
    std::string m = "tfs1:group";
    m += static_cast<char>(group0);
    m += four;
    Bytes h = sha256(reinterpret_cast<const uint8_t*>(m.data()), m.size());
    return B32[h[0] & 31];
}

Bytes recovery_checksum(const uint8_t* master) {
    std::string m = "tfs1:recovery";
    m.append(reinterpret_cast<const char*>(master), KEY_LEN);
    Bytes h = sha256(reinterpret_cast<const uint8_t*>(m.data()), m.size());
    OPENSSL_cleanse(&m[0], m.size());
    h.resize(8);
    return h;
}

// 40 payload bytes -> 64 base32 characters (320 bits, no padding needed).
std::string b32_encode40(const uint8_t* p) {
    std::string out;
    uint32_t acc = 0;
    int bits = 0;
    for (int i = 0; i < 40; i++) {
        acc = (acc << 8) | p[i];
        bits += 8;
        while (bits >= 5) { out += B32[(acc >> (bits - 5)) & 31]; bits -= 5; }
    }
    return out;
}
bool b32_decode64(const std::string& s, uint8_t* out40) {
    if (s.size() != 64) return false;
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (char c : s) {
        int v = b32_value(c);
        if (v < 0) return false;
        acc = (acc << 5) | static_cast<uint32_t>(v);
        bits += 5;
        if (bits >= 8) { out40[o++] = static_cast<uint8_t>((acc >> (bits - 8)) & 0xff); bits -= 8; }
    }
    return o == 40;
}

std::string build_groups(const std::string& chars64) {
    std::string out;
    for (int g = 0; g < RECOVERY_GROUPS; g++) {
        std::string four = chars64.substr(4 * g, 4);
        if (g) out += '-';
        out += four;
        out += group_check_char(g, four);
    }
    return out;
}

uint32_t rand_below(uint32_t n) {  // unbiased
    uint32_t limit = UINT32_MAX - (UINT32_MAX % n);
    for (;;) {
        Bytes r = random_bytes(4);
        if (r.size() != 4) return 0;
        uint32_t v = (uint32_t(r[0]) << 24) | (uint32_t(r[1]) << 16) | (uint32_t(r[2]) << 8) | r[3];
        if (v < limit) return v % n;
    }
}

}  // namespace

// ---------------------------------------------------------------- primitives

Bytes random_bytes(size_t n) {
    Bytes b(n);
    if (n && RAND_bytes(b.data(), static_cast<int>(n)) != 1) return {};
    return b;
}

bool ct_equal(const void* a, const void* b, size_t n) { return CRYPTO_memcmp(a, b, n) == 0; }

std::string to_hex(const uint8_t* p, size_t n) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (size_t i = 0; i < n; i++) { s += hex[p[i] >> 4]; s += hex[p[i] & 15]; }
    return s;
}

std::optional<Bytes> from_hex(const std::string& s) {
    if (s.size() % 2) return std::nullopt;
    Bytes out;
    for (size_t i = 0; i < s.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>(hi * 16 + lo));
    }
    return out;
}

Bytes sha256(const uint8_t* p, size_t n) {
    Bytes out(32);
    unsigned int len = 0;
    uint8_t dummy = 0;
    if (EVP_Digest(p ? p : &dummy, n, out.data(), &len, EVP_sha256(), nullptr) != 1 || len != 32) return {};
    return out;
}

std::string sha256_hex(const uint8_t* p, size_t n) {
    Bytes h = sha256(p, n);
    return to_hex(h.data(), h.size());
}

Bytes hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t n) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = mac ? EVP_MAC_CTX_new(mac) : nullptr;
    Bytes out(32);
    size_t outl = 0;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0), OSSL_PARAM_construct_end()};
    uint8_t dummy = 0;
    bool good = ctx && EVP_MAC_init(ctx, key_len ? key : &dummy, key_len, params) == 1 &&
                EVP_MAC_update(ctx, data ? data : &dummy, n) == 1 &&
                EVP_MAC_final(ctx, out.data(), &outl, out.size()) == 1 && outl == 32;
    if (ctx) EVP_MAC_CTX_free(ctx);
    if (mac) EVP_MAC_free(mac);
    return good ? out : Bytes{};
}

Bytes hmac_sha256_parts(const uint8_t* key, size_t key_len, const std::vector<std::pair<const uint8_t*, size_t>>& parts) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = mac ? EVP_MAC_CTX_new(mac) : nullptr;
    Bytes out(32);
    size_t outl = 0;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0), OSSL_PARAM_construct_end()};
    uint8_t dummy = 0;
    bool good = ctx && EVP_MAC_init(ctx, key_len ? key : &dummy, key_len, params) == 1;
    for (const auto& p : parts)
        if (good && p.second) good = EVP_MAC_update(ctx, p.first, p.second) == 1;
    good = good && EVP_MAC_final(ctx, out.data(), &outl, out.size()) == 1 && outl == 32;
    if (ctx) EVP_MAC_CTX_free(ctx);
    if (mac) EVP_MAC_free(mac);
    return good ? out : Bytes{};
}

// RFC 5869. Extract with the salt (zeros if empty), then expand.
Bytes hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len,
                  const uint8_t* info, size_t info_len, size_t out_len) {
    if (out_len > 255 * 32) return {};
    uint8_t zeros[32] = {0};
    Bytes prk = salt_len ? hmac_sha256(salt, salt_len, ikm, ikm_len) : hmac_sha256(zeros, 32, ikm, ikm_len);
    if (prk.empty()) return {};
    Bytes okm, t;
    for (uint8_t i = 1; okm.size() < out_len; i++) {
        Bytes msg(t);
        msg.insert(msg.end(), info, info + info_len);
        msg.push_back(i);
        t = hmac_sha256(prk.data(), prk.size(), msg.data(), msg.size());
        if (t.empty()) { wipe(prk); return {}; }
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(out_len);
    wipe(prk);
    wipe(t);
    return okm;
}

// ---------------------------------------------------------------- keys

SecretKey::SecretKey() { b_.fill(0); }
SecretKey::SecretKey(const uint8_t* p) { memcpy(b_.data(), p, KEY_LEN); }
SecretKey::~SecretKey() { OPENSSL_cleanse(b_.data(), KEY_LEN); }
SecretKey::SecretKey(SecretKey&& o) noexcept {
    b_ = o.b_;
    OPENSSL_cleanse(o.b_.data(), KEY_LEN);
}
SecretKey& SecretKey::operator=(SecretKey&& o) noexcept {
    if (this != &o) {
        b_ = o.b_;
        OPENSSL_cleanse(o.b_.data(), KEY_LEN);
    }
    return *this;
}
SecretKey SecretKey::random() {
    Bytes r = random_bytes(KEY_LEN);
    SecretKey k;
    if (r.size() == KEY_LEN) memcpy(k.b_.data(), r.data(), KEY_LEN);
    wipe(r);
    return k;
}
bool SecretKey::valid() const {
    uint8_t acc = 0;
    for (uint8_t b : b_) acc |= b;
    return acc != 0;
}

Keys::Keys(const SecretKey& master) {
    auto derive = [&](const char* label, SecretKey& out) {
        std::string info = std::string("tfs1:") + label;
        Bytes k = hkdf_sha256(master.data(), KEY_LEN, reinterpret_cast<const uint8_t*>(HKDF_SALT), strlen(HKDF_SALT),
                              reinterpret_cast<const uint8_t*>(info.data()), info.size(), KEY_LEN);
        if (k.size() == KEY_LEN) out = SecretKey(k.data());
        wipe(k);
    };
    derive("id", id_);
    derive("data", data_);
    derive("manifest", manifest_);
    derive("snapshot", snapshot_);
    derive("file", file_);
    derive("audit", audit_);
    derive("nonce", nonce_);
}

std::string Keys::fingerprint() const {
    static const char msg[] = "tfs1:fingerprint";
    Bytes h = hmac_sha256(id_.data(), KEY_LEN, reinterpret_cast<const uint8_t*>(msg), sizeof msg - 1);
    return to_hex(h.data(), h.size()).substr(0, 16);
}

const char* to_string(OpenError e) {
    switch (e) {
        case OpenError::Ok: return "ok";
        case OpenError::BadFormat: return "malformed data";
        case OpenError::AuthFailed: return "authentication failed (wrong key, wrong context, or tampered data)";
        case OpenError::IdMismatch: return "decrypted data is not what was asked for";
        case OpenError::Unsupported: return "unsupported format version";
    }
    return "?";
}

// ---------------------------------------------------------------- chunks

std::string chunk_id(const Keys& k, const uint8_t* plain, size_t len) {
    Bytes h = hmac_sha256(k.id().data(), KEY_LEN, plain, len);
    return h.empty() ? "" : to_hex(h.data(), h.size());
}

Bytes seal_chunk(const Keys& k, const std::string& volume_id, const std::string& cid, const uint8_t* plain, size_t len) {
    return aead_seal(k, k.data(), chunk_aad(volume_id, cid), plain, len);
}

OpenError open_chunk(const Keys& k, const std::string& volume_id, const std::string& cid,
                     const uint8_t* blob, size_t blob_len, Bytes& plain_out) {
    OpenError e = aead_open(k.data(), chunk_aad(volume_id, cid), blob, blob_len, plain_out);
    if (e != OpenError::Ok) return e;
    std::string actual = chunk_id(k, plain_out.data(), plain_out.size());
    if (actual.size() != cid.size() || !ct_equal(actual.data(), cid.data(), cid.size())) {
        wipe(plain_out);
        plain_out.clear();
        return OpenError::IdMismatch;
    }
    return OpenError::Ok;
}

// ---------------------------------------------------------------- file HMAC

struct FileHmac::Impl {
    EVP_MAC* mac = nullptr;
    EVP_MAC_CTX* ctx = nullptr;
    bool good = false;
};

FileHmac::FileHmac(const Keys& k) : impl_(new Impl) {
    impl_->mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    impl_->ctx = impl_->mac ? EVP_MAC_CTX_new(impl_->mac) : nullptr;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0), OSSL_PARAM_construct_end()};
    impl_->good = impl_->ctx && EVP_MAC_init(impl_->ctx, k.file().data(), KEY_LEN, params) == 1;
}
FileHmac::~FileHmac() {
    if (impl_->ctx) EVP_MAC_CTX_free(impl_->ctx);
    if (impl_->mac) EVP_MAC_free(impl_->mac);
    delete impl_;
}
void FileHmac::update(const uint8_t* p, size_t n) {
    if (impl_->good && n) impl_->good = EVP_MAC_update(impl_->ctx, p, n) == 1;
}
std::string FileHmac::finish_hex() {
    uint8_t out[32];
    size_t outl = 0;
    if (!impl_->good || EVP_MAC_final(impl_->ctx, out, &outl, sizeof out) != 1 || outl != 32) return "";
    impl_->good = false;  // single use
    return to_hex(out, 32);
}

// ---------------------------------------------------------------- audits

Bytes audit_nonce(const Keys& k, const std::string& cid, uint32_t n) {
    std::string m = "tfs1:audit:" + cid + ":" + std::to_string(n);
    return hmac_sha256(k.audit().data(), KEY_LEN, reinterpret_cast<const uint8_t*>(m.data()), m.size());
}

std::string audit_response_hex(const Bytes& nonce, const uint8_t* blob, size_t blob_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    uint8_t out[32];
    unsigned int len = 0;
    bool good = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                EVP_DigestUpdate(ctx, nonce.data(), nonce.size()) == 1 &&
                (blob_len == 0 || EVP_DigestUpdate(ctx, blob, blob_len) == 1) &&
                EVP_DigestFinal_ex(ctx, out, &len) == 1 && len == 32;
    if (ctx) EVP_MD_CTX_free(ctx);
    return good ? to_hex(out, 32) : "";
}

// ---------------------------------------------------------------- manifests

bool Manifest::operator==(const Manifest& o) const {
    if (file_id != o.file_id || version != o.version || prev_version != o.prev_version || path != o.path ||
        mode != o.mode || mtime != o.mtime || size != o.size || file_hmac != o.file_hmac || xattrs != o.xattrs ||
        chunks.size() != o.chunks.size())
        return false;
    for (size_t i = 0; i < chunks.size(); i++)
        if (chunks[i].chunk_id != o.chunks[i].chunk_id || chunks[i].len != o.chunks[i].len) return false;
    return true;
}

static Bytes seal_manifest_slot(const Keys& k, const std::string& volume_id, const std::string& slot_file_id,
                                int64_t slot_version, const Manifest& m, const Bytes& trailer = {}) {
    size_t xtotal = 0;
    for (auto& x : m.xattrs) {
        if (x.second.size() > MAX_XATTR_VALUE) return {};
        xtotal += x.first.size() + x.second.size();
    }
    if (xtotal > MAX_XATTR_TOTAL) return {};
    Writer w;
    put_text32(w, m.file_id);
    w.i64(m.version);
    w.i64(m.prev_version);
    put_text32(w, m.path);
    w.u32(m.mode);
    w.i64(m.mtime);
    w.u64(m.size);
    put_text32(w, m.file_hmac);
    w.u32(static_cast<uint32_t>(m.xattrs.size()));
    for (auto& x : m.xattrs) {
        put_text32(w, x.first);
        put_bytes32(w, x.second);
    }
    w.u32(static_cast<uint32_t>(m.chunks.size()));
    for (auto& c : m.chunks) {
        put_text32(w, c.chunk_id);
        w.u32(c.len);
    }
    w.bytes(trailer.data(), trailer.size());
    Bytes blob = aead_seal(k, k.manifest(), manifest_aad(volume_id, slot_file_id, slot_version), w.b.data(), w.b.size());
    wipe(w.b);
    return blob;
}

Bytes seal_manifest(const Keys& k, const std::string& volume_id, const Manifest& m) {
    return seal_manifest_slot(k, volume_id, m.file_id, m.version, m);
}

OpenError open_manifest(const Keys& k, const std::string& volume_id, const std::string& file_id, int64_t version,
                        const uint8_t* blob, size_t len, Manifest& out) {
    Bytes plain;
    OpenError e = aead_open(k.manifest(), manifest_aad(volume_id, file_id, version), blob, len, plain);
    if (e != OpenError::Ok) return e;
    Manifest m;
    try {
        Reader r(plain);
        m.file_id = get_text32(r, 256);
        m.version = r.i64();
        m.prev_version = r.i64();
        m.path = get_text32(r, 64 * 1024);
        m.mode = r.u32();
        m.mtime = r.i64();
        m.size = r.u64();
        m.file_hmac = get_text32(r, 256);
        uint32_t nx = r.u32();
        size_t xtotal = 0;
        for (uint32_t i = 0; i < nx; i++) {
            std::string name = get_text32(r, 1024);
            Bytes val = get_bytes32(r, MAX_XATTR_VALUE);
            xtotal += name.size() + val.size();
            if (xtotal > MAX_XATTR_TOTAL) throw std::runtime_error("xattrs too large");
            m.xattrs.emplace_back(std::move(name), std::move(val));
        }
        uint32_t nc = r.u32();
        for (uint32_t i = 0; i < nc; i++) {   // no reserve(nc): the count is untrusted
            Manifest::ChunkRef c;
            c.chunk_id = get_text32(r, 256);
            c.len = r.u32();
            m.chunks.push_back(std::move(c));
        }
        if (r.remaining() != 0) throw std::runtime_error("trailing bytes");
    } catch (const std::exception&) {
        wipe(plain);
        return OpenError::BadFormat;
    }
    wipe(plain);
    if (m.file_id != file_id || m.version != version) return OpenError::IdMismatch;
    out = std::move(m);
    return OpenError::Ok;
}

// ---------------------------------------------------------------- recovery phrase

std::string encode_recovery(const SecretKey& master) {
    uint8_t payload[40];
    memcpy(payload, master.data(), KEY_LEN);
    Bytes sum = recovery_checksum(master.data());
    memcpy(payload + KEY_LEN, sum.data(), 8);
    std::string chars = b32_encode40(payload);
    OPENSSL_cleanse(payload, sizeof payload);
    std::string out = build_groups(chars);
    OPENSSL_cleanse(&chars[0], chars.size());
    return out;
}

std::optional<SecretKey> decode_recovery(const std::string& text, std::string* error) {
    auto fail = [&](const std::string& m) -> std::optional<SecretKey> {
        if (error) *error = m;
        return std::nullopt;
    };
    std::string norm;
    char bad = 0;
    if (!normalize_phrase(text, norm, &bad))
        return fail(std::string("the character '") + bad + "' cannot appear in a recovery phrase");
    if (norm.size() != static_cast<size_t>(RECOVERY_GROUPS) * 5)
        return fail("a recovery phrase has " + std::to_string(RECOVERY_GROUPS) + " groups of 5 characters; this has " +
                    std::to_string(norm.size()) + " characters");
    std::string chars;
    for (int g = 0; g < RECOVERY_GROUPS; g++) {
        std::string four = norm.substr(5 * g, 4);
        if (group_check_char(g, four) != norm[5 * g + 4])
            return fail("group " + std::to_string(g + 1) + " has a typo (or the groups are out of order)");
        chars += four;
    }
    uint8_t payload[40];
    if (!b32_decode64(chars, payload)) return fail("the phrase is not valid");
    Bytes sum = recovery_checksum(payload);
    bool good = ct_equal(sum.data(), payload + KEY_LEN, 8);
    std::optional<SecretKey> key;
    if (good) key = SecretKey(payload);
    OPENSSL_cleanse(payload, sizeof payload);
    if (!good) return fail("every group looks fine but the checksum does not match: the phrase is wrong");
    return key;
}

std::vector<int> pick_confirm_groups(int how_many) {
    std::vector<int> all;
    for (int i = 1; i <= RECOVERY_GROUPS; i++) all.push_back(i);
    for (int i = RECOVERY_GROUPS - 1; i > 0; i--) std::swap(all[i], all[rand_below(static_cast<uint32_t>(i + 1))]);
    if (how_many < 0) how_many = 0;
    if (how_many > RECOVERY_GROUPS) how_many = RECOVERY_GROUPS;
    all.resize(static_cast<size_t>(how_many));
    return all;
}

bool check_confirm_group(const std::string& phrase, int g, const std::string& typed) {
    if (g < 1 || g > RECOVERY_GROUPS) return false;
    std::string p, t;
    if (!normalize_phrase(phrase, p, nullptr) || !normalize_phrase(typed, t, nullptr)) return false;
    if (p.size() != static_cast<size_t>(RECOVERY_GROUPS) * 5 || t.size() != 5) return false;
    return ct_equal(p.data() + 5 * (g - 1), t.data(), 5);
}

namespace testing {
Bytes aead_seal_fixed_nonce(const SecretKey& key, const Bytes& nonce, const std::string& aad, const uint8_t* plain, size_t len) {
    return aead_seal_with(key, nonce, aad, plain, len);
}
OpenError aead_open(const SecretKey& key, const std::string& aad, const uint8_t* blob, size_t blob_len, Bytes& plain_out) {
    return crypto::aead_open(key, aad, blob, blob_len, plain_out);
}
Bytes seal_manifest_in_slot(const Keys& k, const std::string& volume_id, const std::string& slot_file_id,
                            int64_t slot_version, const Manifest& m) {
    return seal_manifest_slot(k, volume_id, slot_file_id, slot_version, m);
}
Bytes seal_manifest_with_trailer(const Keys& k, const std::string& volume_id, const Manifest& m, const Bytes& trailer) {
    return seal_manifest_slot(k, volume_id, m.file_id, m.version, m, trailer);
}
}  // namespace testing

// ---------------------------------------------------------------- development key store

namespace {
class FileKeyStore : public KeyStore {
public:
    explicit FileKeyStore(std::string dir) : dir_(std::move(dir)) { mkdir(dir_.c_str(), 0700); }
    bool store(const std::string& vol, const SecretKey& key) override {
        std::string p = path(vol);
        if (p.empty()) return false;
        int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);   // never overwrite a key
        if (fd < 0) return false;
        std::string hex = to_hex(key.data(), KEY_LEN) + "\n";
        bool ok = write(fd, hex.data(), hex.size()) == static_cast<ssize_t>(hex.size()) && fcntl(fd, F_FULLFSYNC) == 0;
        OPENSSL_cleanse(&hex[0], hex.size());
        close(fd);
        if (!ok) unlink(p.c_str());
        return ok;
    }
    std::optional<SecretKey> load(const std::string& vol) override {
        std::string p = path(vol);
        if (p.empty()) return std::nullopt;
        int fd = ::open(p.c_str(), O_RDONLY);
        if (fd < 0) return std::nullopt;
        struct stat st;
        // A key file other users can read is a leaked key: refuse to use it.
        if (fstat(fd, &st) != 0 || (st.st_mode & 077) != 0 || st.st_uid != getuid()) { close(fd); return std::nullopt; }
        char buf[128] = {0};
        ssize_t n = read(fd, buf, sizeof buf - 1);
        close(fd);
        if (n < 64) return std::nullopt;
        auto b = from_hex(std::string(buf, 64));
        OPENSSL_cleanse(buf, sizeof buf);
        if (!b || b->size() != KEY_LEN) return std::nullopt;
        SecretKey k(b->data());
        wipe(*b);
        return k;
    }
    bool erase(const std::string& vol) override {
        std::string p = path(vol);
        return !p.empty() && unlink(p.c_str()) == 0;
    }
private:
    std::string path(const std::string& vol) const {   // volume ids become file names: no separators allowed
        if (vol.empty() || vol.size() > 64) return "";
        for (char c : vol)
            if (!isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') return "";
        return dir_ + "/" + vol + ".key";
    }
    std::string dir_;
};
}  // namespace

std::unique_ptr<KeyStore> make_file_keystore(const std::string& dir) { return std::make_unique<FileKeyStore>(dir); }

}  // namespace crypto
}  // namespace tierfs
