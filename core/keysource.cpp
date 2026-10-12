#include "keysource.hpp"

#include <fstream>

#include "securechannel.hpp"

namespace tierfs {
namespace {
std::string trim_line(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    size_t i = 0;
    while (i < s.size() && s[i] == ' ') i++;
    return s.substr(i);
}
}  // namespace

std::unique_ptr<crypto::KeyStore> keystore_for(const std::string& source, std::string* err) {
    if (source == "keychain") {
#ifdef __APPLE__
        return crypto::make_keychain_keystore();
#else
        if (err) *err = "the Keychain is only available on macOS";
        return nullptr;
#endif
    }
    if (source.compare(0, 4, "dir:") == 0) {
        if (source.size() == 4) {
            if (err) *err = "dir: needs a path";
            return nullptr;
        }
        return crypto::make_file_keystore(source.substr(4));
    }
    return nullptr;
}

std::optional<crypto::SecretKey> load_master_key(const std::string& source, const std::string& volume_id, std::string* err) {
    auto fail = [&](const std::string& m) -> std::optional<crypto::SecretKey> {
        if (err) *err = m;
        return std::nullopt;
    };
    if (source.empty()) return fail("no key source was given");
    std::string why;
    if (auto ks = keystore_for(source, &why)) {
        auto key = ks->load(volume_id);
        if (!key) return fail("no key for volume " + volume_id + " in " + source + " (is this the right volume, or has the item been removed?)");
        return key;
    }
    if (!why.empty()) return fail(why);
    std::ifstream kf(source);
    std::string hex;
    if (!kf || !std::getline(kf, hex)) return fail("cannot read the key file " + source);
    auto raw = crypto::from_hex(trim_line(hex));
    if (!raw || raw->size() != crypto::KEY_LEN) return fail("the key file must hold 64 hex characters");
    return crypto::SecretKey(raw->data());
}

std::string pairing_account(const std::string& key_id_hex) { return "pair-" + key_id_hex; }

namespace {
bool is_key_id(const std::string& s) {
    if (s.size() != 2 * chan::KEY_ID_LEN) return false;
    for (char ch : s)
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    return true;
}
std::unique_ptr<crypto::KeyStore> pairing_store(const std::string& source, std::string* err) {
    std::string why;
    auto ks = keystore_for(source, &why);
    if (!ks) {
        if (err) *err = why.empty() ? "pairing secrets need a key store: use 'keychain' or 'dir:PATH', not a key file" : why;
        return nullptr;
    }
    return ks;
}
}  // namespace

std::optional<crypto::Bytes> load_pairing_secret(const std::string& source, const std::string& key_id_hex, std::string* err) {
    auto fail = [&](const std::string& m) -> std::optional<crypto::Bytes> {
        if (err) *err = m;
        return std::nullopt;
    };
    if (!is_key_id(key_id_hex)) return fail("a device's key id is 16 hex characters, got \"" + key_id_hex + "\"");
    auto ks = pairing_store(source, err);
    if (!ks) return std::nullopt;
    auto k = ks->load(pairing_account(key_id_hex));
    if (!k) return fail("no pairing secret for key id " + key_id_hex + " in " + source + " (pair this Mac with the device first: tierctl pair)");
    crypto::Bytes secret(k->data(), k->data() + crypto::KEY_LEN);
    if (chan::key_id_hex(secret) != key_id_hex)
        return fail("the stored pairing secret for " + key_id_hex + " does not match its key id (the store was altered)");
    return secret;
}

bool store_pairing_secret(const std::string& source, const crypto::Bytes& secret, std::string* err) {
    if (secret.size() != chan::PSK_LEN) {
        if (err) *err = "a pairing secret is 32 bytes";
        return false;
    }
    auto ks = pairing_store(source, err);
    if (!ks) return false;
    std::string id = chan::key_id_hex(secret);
    if (auto existing = ks->load(pairing_account(id))) {
        if (crypto::Bytes(existing->data(), existing->data() + crypto::KEY_LEN) == secret) return true;  // already paired
        if (err) *err = "a different secret is already stored for key id " + id;
        return false;
    }
    if (!ks->store(pairing_account(id), crypto::SecretKey(secret.data()))) {
        if (err) *err = "could not store the pairing secret in " + source;
        return false;
    }
    return true;
}

}  // namespace tierfs
