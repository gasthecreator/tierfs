// Master key storage in the macOS login Keychain.
//
// "This device only": the item is never synced to iCloud, so the Keychain is not
// a second place the key leaks to. It is also not a backup: if the Mac dies the
// Keychain dies with it, which is why the recovery phrase exists.
#ifdef __APPLE__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <memory>

#include "crypto.hpp"

namespace tierfs {
namespace crypto {
namespace {

// Small RAII for CoreFoundation objects.
template <class T>
struct CF {
    T ref = nullptr;
    explicit CF(T r) : ref(r) {}
    CF(CF&& o) noexcept : ref(o.ref) { o.ref = nullptr; }
    ~CF() { if (ref) CFRelease(ref); }
    CF(const CF&) = delete;
    CF& operator=(const CF&) = delete;
};

CF<CFStringRef> cfstr(const std::string& s) {
    return CF<CFStringRef>(CFStringCreateWithBytes(nullptr, reinterpret_cast<const UInt8*>(s.data()), static_cast<CFIndex>(s.size()),
                                                   kCFStringEncodingUTF8, false));
}

constexpr const char* SERVICE = "tierfs-master-key";

CF<CFMutableDictionaryRef> base_query(const std::string& volume_id) {
    CF<CFMutableDictionaryRef> q(CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    auto svc = cfstr(SERVICE);
    auto acct = cfstr(volume_id);
    CFDictionarySetValue(q.ref, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q.ref, kSecAttrService, svc.ref);
    CFDictionarySetValue(q.ref, kSecAttrAccount, acct.ref);
    CFDictionarySetValue(q.ref, kSecAttrSynchronizable, kCFBooleanFalse);
    return q;
}

class KeychainStore : public KeyStore {
public:
    bool store(const std::string& volume_id, const SecretKey& key) override {
        auto q = base_query(volume_id);
        CF<CFDataRef> data(CFDataCreate(nullptr, key.data(), KEY_LEN));
        CFDictionarySetValue(q.ref, kSecValueData, data.ref);
        CFDictionarySetValue(q.ref, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
        // errSecDuplicateItem is a failure on purpose: silently replacing a master
        // key would orphan everything already encrypted under the old one.
        return SecItemAdd(q.ref, nullptr) == errSecSuccess;
    }
    std::optional<SecretKey> load(const std::string& volume_id) override {
        auto q = base_query(volume_id);
        CFDictionarySetValue(q.ref, kSecReturnData, kCFBooleanTrue);
        CFDictionarySetValue(q.ref, kSecMatchLimit, kSecMatchLimitOne);
        CFTypeRef result = nullptr;
        if (SecItemCopyMatching(q.ref, &result) != errSecSuccess || !result) return std::nullopt;
        CF<CFDataRef> data(static_cast<CFDataRef>(result));
        if (CFDataGetLength(data.ref) != static_cast<CFIndex>(KEY_LEN)) return std::nullopt;
        return SecretKey(CFDataGetBytePtr(data.ref));
    }
    bool erase(const std::string& volume_id) override {
        auto q = base_query(volume_id);
        return SecItemDelete(q.ref) == errSecSuccess;
    }
};

}  // namespace

std::unique_ptr<KeyStore> make_keychain_keystore() { return std::make_unique<KeychainStore>(); }

}  // namespace crypto
}  // namespace tierfs

#endif  // __APPLE__
