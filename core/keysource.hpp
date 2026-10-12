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

// ---- pairing secrets (one per paired device), kept in the same store as the master key ----
// The account name is "pair-" + the secret's public key id, so a secret is found by the id a device configuration carries.
std::string pairing_account(const std::string& key_id_hex);
// Loads the secret whose key id is `key_id_hex` from the store behind `source` (not a key file). Verifies it really has that id.
std::optional<crypto::Bytes> load_pairing_secret(const std::string& source, const std::string& key_id_hex, std::string* err);
// Stores a secret under its own key id. Idempotent for the same secret; never replaces a different one.
bool store_pairing_secret(const std::string& source, const crypto::Bytes& secret, std::string* err);

}  // namespace tierfs
