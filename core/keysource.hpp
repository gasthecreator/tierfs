// Where the master key comes from. A "key source" is a short string:
//   "keychain"   the login Keychain, "this device only" (macOS); the account is the volume id
//   "dir:PATH"   one 0600 file per volume under PATH (development and tests; NOT a secure store)
//   anything else is the path of a key file holding 64 hex characters (the original development form)
// The first two go through crypto::KeyStore; they refuse to overwrite a key that is already stored.
#pragma once

#include <memory>
#include <optional>
#include <string>

#include "crypto.hpp"

namespace tierfs {

// The store behind a source, or null for a plain key file (or an unusable source: *err says why).
std::unique_ptr<crypto::KeyStore> keystore_for(const std::string& source, std::string* err);

// Loads the master key for `volume_id` from `source`. Never prints or logs the key.
std::optional<crypto::SecretKey> load_master_key(const std::string& source, const std::string& volume_id, std::string* err);

}  // namespace tierfs
