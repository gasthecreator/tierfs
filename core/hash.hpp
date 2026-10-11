// SHA-256 helper. macOS ships CommonCrypto (hardware accelerated on Apple
// Silicon), so no extra dependency. A Linux/Android build would swap this
// header's body for OpenSSL/BoringSSL; nothing else needs to change.
#pragma once

#include <CommonCrypto/CommonDigest.h>

#include <cstddef>
#include <string>

namespace tierfs {

inline std::string sha256_hex(const void* data, size_t len) {
    unsigned char d[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, static_cast<CC_LONG>(len), d);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(2 * CC_SHA256_DIGEST_LENGTH);
    for (unsigned char b : d) { out += hex[b >> 4]; out += hex[b & 15]; }
    return out;
}

}  // namespace tierfs
