// Garbage collection on the devices (ADR-0010, docs/DURABLE_STORE.md section 25): give old versions and deleted files back as free space.
//
// Three steps, each safe to stop and repeat:
//   1. DECIDE (ledger): which versions to forget. The ledger enforces the rules (never a live file's current version; a newer version
//      must be held with full replica weight from fresh audits; deleted files only after the retention period). The decision is recorded
//      before any device is touched, and it is permanent.
//   2. DELETE (devices): ask every device that may hold such a manifest to remove it; record each confirmation. A device that is away
//      keeps owing the deletion, and one that returns with a forgotten manifest is never trusted to count it as a copy.
//   3. SWEEP (devices): the device removes chunks that no manifest it still holds lists, after a grace period. A device that stored
//      manifests before chunk lists existed gets them re-sent first (the Mac reads each manifest, which it can decrypt, and sends the list).
//
// Nothing here deletes local bytes, and nothing here runs unless someone asked (the daemon needs gc=on, `tierctl control ... gc-run`).
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "dropengine.hpp"  // DeviceMap
#include "ledger.hpp"
#include "replicator.hpp"

namespace tierfs {

struct GcConfig {
    int keep_versions = 3;  // a live file keeps its newest committed versions (at least 1)
    PruneRules rules;
    uint64_t sweep_min_age = 24 * 3600;  // a chunk must have been unlisted and unmentioned this long before a device sweeps it
    size_t max_decisions = 2000;         // versions to decide on in one run (the rest wait for the next)
    size_t sweep_chunks = 20000;         // chunks one sweep request may delete
    int sweep_rounds = 10;               // sweep requests per device per run
    bool sweep = true;
    bool prepare = true;  // re-send chunk lists to a device that needs them before sweeping it
};

struct GcDeviceReport {
    std::string device_id;
    bool reachable = false;
    bool deletions_allowed = false;
    uint64_t owed = 0;               // manifests this device owed at the start
    uint64_t manifests_deleted = 0;  // confirmed during this run (including "it was not there")
    uint64_t chunks_swept = 0, bytes_swept = 0, strays_removed = 0;
    uint32_t chunk_lists_sent = 0;
    GcStatus status;   // what the device said before the run touched it
    std::string note;  // why it was skipped, or what went wrong
};

struct GcReport {
    bool dry_run = false;
    size_t candidates = 0;             // versions the rules would let go of
    size_t decided = 0;                // recorded in the ledger by this run
    size_t audited = 0;                // successor audits done to make a decision possible
    std::vector<std::string> refused;  // "file_id vN: why", the first few
    size_t owed_total = 0;             // deletions still owed by devices after the run (before it, for a dry run)
    std::vector<GcDeviceReport> devices;
    uint64_t manifests_deleted() const;
    uint64_t chunks_swept() const;
    uint64_t bytes_swept() const;
};

std::string format_gc_report(const GcReport& r);

class GarbageCollector {
public:
    GarbageCollector(Ledger& ledger, Replicator& replicator, const crypto::Keys& keys, GcConfig config = {});

    // Read-only: what a run would decide and ask the devices to do. Changes nothing anywhere.
    GcReport plan(const DeviceMap& devices);
    // Decide, delete, sweep.
    GcReport run(const DeviceMap& devices);

    // Test hook: called at named points ("decided", "deleted", ...), e.g. to stop the run or damage something.
    std::function<void(const char*)> on_step;

private:
    bool check_device(DeviceClient& dev, const std::string& device_id, std::string* why);
    uint32_t send_chunk_lists(DeviceClient& dev, std::string* why);
    void sweep_device(DeviceClient& dev, GcDeviceReport& dr, bool dry_run);
    Ledger& ledger_;
    Replicator& replicator_;
    const crypto::Keys& keys_;
    GcConfig cfg_;
    std::string volume_;
};

}  // namespace tierfs
