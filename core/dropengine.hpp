// The drop-local engine: the only code that makes local bytes go away. See docs/DURABLE_STORE.md section 7.
//
// A drop never deletes. It MOVES the file into quarantine (one atomic rename on the same volume); the
// bytes are deleted only later, by a separate, separately gated `purge`, after a retention period and a
// FRESH audit. Every irreversible step is preceded by a durable ledger record, and at every possible
// crash the data exists somewhere recoverable: at its original path, or in quarantine, or on verified
// replicas, and `recover()` can tell which and finish or undo the step.
//
//   drop:   freeze writers -> verify the LOCAL bytes still equal the replicated version (chunk by chunk)
//           -> fresh audit of every replica -> ledger begin_drop (all safety rules, one transaction)
//           -> write quarantine metadata -> re-check the file's identity -> rename into quarantine
//           (+ directory syncs) -> ledger complete_drop -> unfreeze.
//   purge:  fresh audits -> ledger begin_purge (retention, weight, gates) -> unlink -> ledger complete_purge.
//   restore: ledger begin_restore -> rename back -> ledger complete_restore.
//
// What replaces the original path afterwards (a stub, a virtual entry) is the filesystem layer's concern.
// Not thread-safe.
#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "deviceclient.hpp"
#include "ledger.hpp"
#include "replicator.hpp"

namespace tierfs {

struct DropPolicy {
    double min_weight = 2.0;                 // replica weight required (design doc section 10)
    int64_t max_audit_age = 300;             // audits must be this fresh when bytes are dropped or purged
    int64_t quarantine_seconds = 7 * 86400;  // how long quarantined bytes are kept before a normal purge
};

// How the engine keeps writers away from a file while it works. The real implementation lives in the
// filesystem layer (refuse opens for write, wait for open writers); the engine only needs the contract:
// when freeze() returns true no new modification can start until unfreeze().
class FileGate {
public:
    virtual ~FileGate() = default;
    virtual bool freeze(const FileRec& file, std::string* why) = 0;
    virtual void unfreeze(const FileRec& file) = 0;
};

using DeviceMap = std::map<std::string, DeviceClient*>;               // device_id -> a connection to it
using OriginResolver = std::function<std::string(const FileRec&)>;    // where a file's local bytes live

struct DropOutcome {
    bool ok = false;
    std::string why;
    std::string intent_id;
    bool file_changed = false;     // the local bytes no longer match the replicated version; nothing was dropped
    size_t replicas_audited = 0, audits_failed = 0;
};
struct PurgeOutcome {
    bool ok = false;
    std::string why;
    size_t replicas_audited = 0, audits_failed = 0;
};
struct RestoreOutcome {
    bool ok = false;
    std::string why;
    bool bytes_verified = false;   // the restored bytes equal the replicated version
};
struct RecoveryReport {
    std::vector<std::string> actions;   // what was finished or undone
    std::vector<std::string> problems;  // what needs a human (never silently ignored)
};

class DropEngine {
public:
    DropEngine(Ledger& ledger, Replicator& replicator, const crypto::Keys& keys, std::string volume_id, DropPolicy policy,
               std::string quarantine_root, OriginResolver resolver);

    DropOutcome drop(const std::string& file_id, const std::string& consent_id, const DeviceMap& devices, FileGate* gate = nullptr);
    PurgeOutcome purge(const std::string& intent_id, const DeviceMap& devices, bool emergency);
    RestoreOutcome restore(const std::string& intent_id, const std::string& reason);

    // After a crash (or at every start): resolve every drop, purge and restore that was interrupted.
    RecoveryReport recover(const DeviceMap& devices);

    // Test hook: called at named points ("frozen", "local_verified", "audited", "before_rename").
    std::function<void(const char*)> on_step;

    std::string quarantine_dir(const std::string& intent_id) const;
    std::string quarantine_object(const std::string& intent_id) const;

private:
    struct Check;
    Check check_against_plan(const std::string& path, const std::string& file_id, int64_t version);
    void audit_all(const DeviceMap& devices, const std::string& file_id, int64_t version, size_t* audited, size_t* failed);
    bool move_back(const std::string& intent_id, const std::string& local_path);
    void remove_quarantine(const std::string& intent_id);

    Ledger& ledger_;
    Replicator& replicator_;
    const crypto::Keys& keys_;
    std::string volume_;
    DropPolicy policy_;
    std::string qroot_;
    OriginResolver resolve_;
};

}  // namespace tierfs
