// Cryptography for offloaded data (design doc sections 4 and 11).
//
// Everything a device stores is ciphertext it cannot read, alter, or swap without
// detection:
//   chunk id  = HMAC-SHA256(K_id, plaintext)                      (dedupe, reveals no content hash)
//   chunk blob = 0x01 || nonce(12) || AES-256-GCM(K_data, plaintext) || tag(16)
//                nonce = HMAC(K_nonce, aad || plaintext)[:12]: a synthetic IV, so sealing is
//                DETERMINISTIC. The same chunk sealed twice gives the same bytes, which is what
//                lets a crashed upload resume exactly, and lets "the device already has it" be
//                proven by comparing hashes. The price is that equal plaintexts give equal blobs,
//                which the content-derived chunk id already reveals. Two different plaintexts
//                get different nonces unless a 96-bit HMAC prefix collides (about 2^-97 per pair).
//                AAD = "tfs1:chunk:" || volume_id || ":" || chunk_id
//   manifest   = same layout under K_manifest,
//                AAD = "tfs1:manifest:" || volume_id || ":" || file_id || ":" || version
// Binding the id/volume/file/version into the AAD means a device cannot hand back
// chunk A when asked for chunk B, or version 3's manifest for version 4.
//
// One 32-byte master key per volume. Everything else is derived with HKDF, so
// losing the master key is the only way to lose the data: that is why the
// recovery phrase (below) is mandatory before the first offload.
//
// Backed by OpenSSL (portable to Linux/Android builds); verified against NIST,
// RFC 4231 and RFC 5869 vectors and an independent AES-GCM implementation.
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace tierfs {
namespace crypto {

using Bytes = std::vector<uint8_t>;

constexpr size_t KEY_LEN = 32;
constexpr size_t NONCE_LEN = 12;
constexpr size_t TAG_LEN = 16;
constexpr uint8_t FORMAT_V1 = 1;

// ---- primitives ----
Bytes random_bytes(size_t n);  // empty on failure
bool ct_equal(const void* a, const void* b, size_t n);  // constant time
std::string to_hex(const uint8_t* p, size_t n);
std::optional<Bytes> from_hex(const std::string& s);
Bytes sha256(const uint8_t* p, size_t n);
std::string sha256_hex(const uint8_t* p, size_t n);
Bytes hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t n);
// HMAC over several pieces without concatenating them first.
Bytes hmac_sha256_parts(const uint8_t* key, size_t key_len, const std::vector<std::pair<const uint8_t*, size_t>>& parts);
Bytes hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len,
                  const uint8_t* info, size_t info_len, size_t out_len);

// A 32-byte secret that is wiped when it goes away. Move-only: copies of a key are
// copies that might not get wiped.
class SecretKey {
public:
    SecretKey();  // all zero
    explicit SecretKey(const uint8_t* p32);
    ~SecretKey();
    SecretKey(SecretKey&& o) noexcept;
    SecretKey& operator=(SecretKey&& o) noexcept;
    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    static SecretKey random();  // all zero if the system RNG failed; check valid()
    const uint8_t* data() const { return b_.data(); }
    bool valid() const;         // false for the all-zero key
    bool operator==(const SecretKey& o) const { return ct_equal(b_.data(), o.b_.data(), KEY_LEN); }
private:
    std::array<uint8_t, KEY_LEN> b_;
};

// Keys derived from the master key (distinct HKDF labels: a leak of one purpose
// reveals nothing about another).
class Keys {
public:
    explicit Keys(const SecretKey& master);
    Keys(const Keys&) = delete;            // one place holds the seal counter and the key material
    Keys& operator=(const Keys&) = delete;
    const SecretKey& id() const { return id_; }
    const SecretKey& data() const { return data_; }
    const SecretKey& manifest() const { return manifest_; }
    const SecretKey& snapshot() const { return snapshot_; }
    const SecretKey& file() const { return file_; }
    const SecretKey& audit() const { return audit_; }
    const SecretKey& nonce() const { return nonce_; }
    // Short public tag of the master key, safe to store in the ledger: detects a
    // mistyped recovery phrase before anything is decrypted with a wrong key.
    std::string fingerprint() const;
private:
    SecretKey id_, data_, manifest_, snapshot_, file_, audit_, nonce_;
};

enum class OpenError { Ok, BadFormat, AuthFailed, IdMismatch, Unsupported };
const char* to_string(OpenError e);

// ---- chunks ----
std::string chunk_id(const Keys& k, const uint8_t* plain, size_t len);  // 64 hex chars
// Deterministic. Empty result means failure.
Bytes seal_chunk(const Keys& k, const std::string& volume_id, const std::string& chunk_id,
                 const uint8_t* plain, size_t len);
// Decrypts, authenticates, and then re-derives the id from the plaintext, so a blob
// is accepted only if it is really the chunk that was asked for.
OpenError open_chunk(const Keys& k, const std::string& volume_id, const std::string& chunk_id,
                     const uint8_t* blob, size_t blob_len, Bytes& plain_out);

// ---- whole-file integrity (checked after a full hydrate) ----
class FileHmac {
public:
    explicit FileHmac(const Keys& k);
    ~FileHmac();
    FileHmac(const FileHmac&) = delete;
    FileHmac& operator=(const FileHmac&) = delete;
    void update(const uint8_t* p, size_t n);
    std::string finish_hex();
private:
    struct Impl;
    Impl* impl_;
};

// ---- audits: proving the device still holds the exact blob ----
// SHA-256(blob) alone cannot be challenged without the blob, so audits use
// one-time nonces derived from a secret key: the device cannot know a nonce in
// advance, so it cannot answer without reading the blob NOW. At upload time the
// Mac computes the expected responses for a few nonces and stores them (32 bytes
// each); when they run out it re-derives the pool from a full verified fetch.
Bytes audit_nonce(const Keys& k, const std::string& chunk_id, uint32_t n);
std::string audit_response_hex(const Bytes& nonce, const uint8_t* blob, size_t blob_len);  // runs on the device

// ---- manifests ----
struct Manifest {
    std::string file_id;
    int64_t version = 0;
    int64_t prev_version = 0;
    std::string path;
    uint32_t mode = 0;
    int64_t mtime = 0;
    uint64_t size = 0;
    std::string file_hmac;  // hex, see FileHmac
    std::vector<std::pair<std::string, Bytes>> xattrs;
    struct ChunkRef { std::string chunk_id; uint32_t len; };
    std::vector<ChunkRef> chunks;
    bool operator==(const Manifest& o) const;
};
constexpr size_t MAX_XATTR_VALUE = 1u << 20;
constexpr size_t MAX_XATTR_TOTAL = 4u << 20;
Bytes seal_manifest(const Keys& k, const std::string& volume_id, const Manifest& m);  // empty on failure
// The caller says WHICH file/version it asked the device for; a manifest that
// decrypts but describes something else is rejected.
OpenError open_manifest(const Keys& k, const std::string& volume_id, const std::string& file_id,
                        int64_t version, const uint8_t* blob, size_t len, Manifest& out);

// ---- recovery phrase ----
// The master key plus a checksum, as 16 groups "XXXXC" (4 data characters + 1
// check character), Crockford base32 so I/L read as 1 and O as 0. A typo is
// pinpointed to its group; a transposed or missing group is caught too.
constexpr int RECOVERY_GROUPS = 16;
std::string encode_recovery(const SecretKey& master);
std::optional<SecretKey> decode_recovery(const std::string& text, std::string* error);
std::vector<int> pick_confirm_groups(int how_many);  // distinct, 1-based
bool check_confirm_group(const std::string& phrase, int group_1based, const std::string& typed);

// ---- test hooks: known-answer tests need a fixed nonce, which production never uses ----
namespace testing {
Bytes aead_seal_fixed_nonce(const SecretKey& key, const Bytes& nonce, const std::string& aad, const uint8_t* plain, size_t len);
OpenError aead_open(const SecretKey& key, const std::string& aad, const uint8_t* blob, size_t blob_len, Bytes& plain_out);
// Seals `m` into the slot (slot_file_id, slot_version) regardless of what `m` says about itself.
Bytes seal_manifest_in_slot(const Keys& k, const std::string& volume_id, const std::string& slot_file_id,
                            int64_t slot_version, const Manifest& m);
// Same, with extra bytes appended after the manifest body (a parser must reject them).
Bytes seal_manifest_with_trailer(const Keys& k, const std::string& volume_id, const Manifest& m, const Bytes& trailer);
}

// ---- where the master key lives on this Mac ----
class KeyStore {
public:
    virtual ~KeyStore() = default;
    virtual bool store(const std::string& volume_id, const SecretKey& key) = 0;  // refuses to overwrite
    virtual std::optional<SecretKey> load(const std::string& volume_id) = 0;
    virtual bool erase(const std::string& volume_id) = 0;
};
// Development and tests only: a 0600 file. NOT a secure store.
std::unique_ptr<KeyStore> make_file_keystore(const std::string& dir);
#ifdef __APPLE__
// The login Keychain, "this device only" (never synced to iCloud).
std::unique_ptr<KeyStore> make_keychain_keystore();
#endif

}  // namespace crypto
}  // namespace tierfs
