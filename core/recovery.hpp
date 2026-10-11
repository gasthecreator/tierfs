// Disaster recovery: get the files back with nothing but the recovery phrase and one or more devices.
// See docs/DURABLE_STORE.md section 23.
//
// The scenario is "the Mac is gone": no ledger, no keys, no cache, no mount. What survives is the phrase
// (on paper) and the devices. Everything needed is on the devices, sealed under keys derived from the phrase:
// each manifest carries the file's path, size, mode, mtime, extended attributes and chunk list, and the
// devices themselves remember which volume they belong to.
//
// This code only READS from the devices (INFO, LIST_MANIFESTS, GET_MANIFEST, GET_CHUNK). It never binds,
// writes or deletes anything on a device, and it never overwrites anything on the Mac: files that already
// exist are left alone (and counted as identical or as conflicts).
//
// Safety rules that hold whatever the devices say:
//   - every manifest and chunk is authenticated under the phrase's keys; each restored file is also checked
//     against its whole-file HMAC before it is moved into place; a file is never visible half-written
//     (temp file, F_FULLFSYNC, exclusive rename, directory sync);
//   - paths come from the manifests and are treated as hostile: ".." and names that would escape the output
//     directory are refused, and no path component may be a symlink;
//   - chunks are taken from any device that has a good copy, so damage on one device is bridged by another;
//   - if the newest version of a file cannot be rebuilt from anything, the newest older version that can be
//     is restored, and the report says so;
//   - the free space is checked BEFORE anything is written.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "deviceclient.hpp"

namespace tierfs {

struct RecoveryDevice {
    std::string name;       // for messages ("192.168.1.20:9000")
    DeviceClient* client;
};

struct RecoveryOptions {
    bool dry_run = false;            // list what would be restored; write nothing
    std::string path_prefix;         // restore only logical paths under this prefix (empty: everything)
    uint64_t reserve_bytes = 256ull << 20;   // free space to leave untouched
    bool apply_xattrs = true;
    std::function<void(const std::string&)> progress;
};

struct RecoveredFile {
    std::string logical;     // the path the file had on the Mac
    std::string dest;        // where it was (or would be) written
    int64_t version = 0;     // the version restored
    int64_t latest = 0;      // the newest version the devices have a readable manifest for
    uint64_t size = 0;
};

struct RestoreReport {
    bool dry_run = false;
    std::string fatal;                  // non-empty: nothing was done, and this says why
    std::string volume_id;
    size_t devices_reachable = 0;
    size_t manifests_listed = 0, manifests_opened = 0, manifests_unreadable = 0;
    size_t files_found = 0;
    uint64_t bytes_needed = 0, bytes_free = 0;
    std::vector<RecoveredFile> planned;     // everything chosen (also on a real run)
    std::vector<RecoveredFile> restored;    // written now
    std::vector<RecoveredFile> identical;   // already there, byte for byte
    std::vector<RecoveredFile> older;       // restored, but an OLDER version than the newest (the newest was unrecoverable)
    std::vector<std::string> failed;        // could not be rebuilt from any device
    std::vector<std::string> conflicts;     // the destination exists and differs: left alone
    std::vector<std::string> rejected;      // unsafe paths in a manifest
    std::vector<std::string> warnings;

    // Everything asked for was recovered, exactly: nothing failed, conflicted, was refused, or fell back to an older version.
    bool complete() const;
};

// Turns the logical path from a manifest into a relative path that is safe to create under an output
// directory. False (with a reason) for anything that could escape it or collide with our temp names.
bool safe_relative_path(const std::string& logical, std::string* rel, std::string* why);

RestoreReport recover_from_devices(const crypto::SecretKey& master, const std::vector<RecoveryDevice>& devices,
                                    const std::string& out_dir, const RecoveryOptions& opt = {});

std::string format_recovery_report(const RestoreReport& r);

}  // namespace tierfs
