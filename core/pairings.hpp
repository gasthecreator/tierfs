// The pairing secrets a device accepts (docs/adr/0016): one per Mac, each revocable, each with its own right to delete.
//
// Until now a device had one pairing secret, so every Mac shared it: a lost Mac meant replacing the secret and re-pairing every other Mac, and any
// paired Mac could ask the device to delete. Now a store directory can hold several secrets:
//   <store>/pairing.key          the original single secret ("primary", may delete: existing devices behave exactly as before)
//   <store>/pairings/<keyid>.key one per Mac: line 1 the secret (64 hex), then "label=...", "delete=0|1", "created=<unix time>"
// Both are mode 0600 regular files. The key id (a hash of the secret, public) is the file name, so a file cannot be swapped for another one. Removing
// a file revokes that Mac at once: new connections are refused and a connection that is already open ends at its next request.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto.hpp"

namespace tierfs::pairing {

struct Entry {
    crypto::Bytes secret;
    std::string key_id;  // 16 lower-case hex characters
    std::string label;   // for people ("Gideon's MacBook"); "primary" for the original file
    bool allow_delete = false;
    int64_t created = 0;
    std::string file;      // where it lives
    bool primary = false;  // the original <store>/pairing.key
    // Identifies this version of the file, so a connection can tell cheaply whether it was changed or removed.
    int64_t mtime_ns = 0;
    uint64_t inode = 0;
};

constexpr size_t MAX_LABEL = 40;
constexpr size_t MAX_ENTRIES = 64;

// A label is 1 to 40 printable characters, no '=' needed but no newline or control character.
bool valid_label(const std::string& s);

// Every pairing in the store. An entry that is malformed, has loose permissions or a name that is not its key id is NOT returned; `*problems` (if
// given) says why, so a typo never silently disables a Mac and never silently enables one.
std::vector<Entry> list(const std::string& store, std::vector<std::string>* problems = nullptr);

// The entry for this key id, or nullopt (never paired, revoked, or the file is not acceptable).
std::optional<Entry> find(const std::string& store, const crypto::Bytes& key_id);

// Is this exact entry still there, unchanged? (A cheap stat; the file is read again only if it changed, and the entry returned is the new one.)
// nullopt: revoked, or no longer acceptable.
std::optional<Entry> refresh(const Entry& e);

// Makes a new random secret for a Mac. Fails (with *err) when there are already MAX_ENTRIES or the label is invalid.
std::optional<Entry> add(const std::string& store, const std::string& label, bool allow_delete, std::string* err);

// Removes the pairing with this key id (the original pairing.key too). False with *err if there is none.
bool revoke(const std::string& store, const std::string& key_id_hex, std::string* err);

// Replaces the original pairing.key with a new secret (every Mac that used it must pair again), or creates it. The entry returned holds the new
// secret.
std::optional<Entry> set_primary(const std::string& store, bool replace, std::string* err);

}  // namespace tierfs::pairing
