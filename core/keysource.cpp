#include "keysource.hpp"

#include <fstream>

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

}  // namespace tierfs
