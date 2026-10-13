// The replicate engine and reconciliation (docs/DURABLE_STORE.md sections 6, 8, 9).
//
// It copies a local file to a device, proves the device really holds it, and records the result
// in the ledger. It NEVER deletes anything: local bytes stay put, remote data is append-only.
// What it adds is the evidence the later (dangerous) drop step relies on.
//
// How a file gets replicated
//   pass 1  read the file, cut it into 1 MiB chunks, compute each chunk id (keyed HMAC) and seal it;
//           record the PLAN (chunk ids, lengths, blob hashes) in the ledger before anything is sent.
//   pass 2  read the file again, re-seal every chunk, check it still matches the plan (otherwise the
//           file changed under us), upload what the device lacks, and AUDIT chunks the device claims
//           to have already (a stored chunk is never trusted just because its id exists).
//   audit   challenge a random sample of what was just uploaded before committing anything.
//   commit  upload the sealed manifest; ledger: replica COMMITTED, then REPLICATING -> REPLICATED.
// Sealing is deterministic, so a replicate that was interrupted anywhere produces byte-identical data
// when it is run again, and "the device already has it" is checked by comparing hashes.
//
// Not thread-safe; one replicate at a time per Replicator.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "deviceclient.hpp"
#include "ledger.hpp"

namespace tierfs {

constexpr uint32_t REPL_CHUNK = 1u << 20;   // same as the read cache's CHUNK_SIZE

struct ReplicateOptions {
    size_t verify_chunks = 16;       // audit this many newly uploaded chunks (random) before committing
    size_t challenges_per_chunk = 4; // size of each chunk's one-time audit pool
};

struct ReplicateOutcome {
    bool ok = false;
    std::string why;
    int64_t version = 0;
    bool already_done = false;       // this device already held a committed replica of the current version
    bool file_changed = false;       // the file was modified while (or before) it was read; nothing was committed
    uint64_t chunks_total = 0, chunks_uploaded = 0, chunks_already_present = 0, bytes_uploaded = 0;
    size_t chunks_audited = 0;
};

struct ReconcileReport {
    bool ok = false;
    std::string why;
    bool first_contact = false, rolled_back = false, epoch_changed = false;
    std::vector<std::string> adopted;            // "file_id:version" found committed on the device, recorded now
    std::vector<std::string> manifests_missing;  // ledger says committed, the device has no such manifest
    std::vector<std::string> chunks_missing;     // a committed version with chunks absent from the device
    std::vector<std::string> conflicts;          // the device holds a DIFFERENT manifest than the ledger recorded
    std::vector<std::string> unknown_manifests;  // on the device, unknown to the ledger (never adopted blindly)
    std::vector<std::string> pruned_leftovers;   // on the device, but the ledger gave up on that version: never adopted, deletion is owed again (ADR-0010)
    size_t replicas_checked = 0, audited = 0, audit_failed = 0;
    bool suspect_cleared = false;
};

struct AuditReport {
    bool ok = false;
    std::string why;
    size_t items = 0, answered_ok = 0, refetched = 0;
    std::vector<std::string> failures;
};

class Replicator {
public:
    Replicator(Ledger& ledger, const crypto::Keys& keys, std::string volume_id, ReplicateOptions opt = {});

    // Handshake: INFO, BIND to this volume (refused if the device belongs to another), register in
    // the ledger if new, and record what the device says about itself (a rolled-back or re-initialised
    // device becomes suspect, see Ledger::observe_device).
    Res attach(DeviceClient& dev, const std::string& name, const std::string& cls, std::string* device_id,
               DeviceObservation* observation = nullptr);

    // Replicates the file's current version to this device. `local_path` is where the bytes are now.
    ReplicateOutcome replicate(DeviceClient& dev, const std::string& device_id, const std::string& file_id,
                               const std::string& local_path);

    // Compare the ledger with what the device really has; adopt what a crash left uncommitted, flag what
    // is missing or different, and (for a suspect device, or when `deep`) re-audit every committed replica.
    ReconcileReport reconcile(DeviceClient& dev, const std::string& device_id, bool deep);

    // Challenge-audit one replica using the precomputed one-time challenges (or a full verified fetch
    // when a chunk's pool is used up), and record the result in the ledger.
    AuditReport audit_replica(DeviceClient& dev, const std::string& device_id, const std::string& file_id, int64_t version);

    // Download, decrypt and verify an entire version. Each verified chunk is passed to `sink` in order.
    Res fetch_version(DeviceClient& dev, const std::string& file_id, int64_t version,
                      const std::function<bool(const uint8_t*, size_t)>& sink, crypto::Manifest* manifest_out = nullptr);

    // Test hook: called at named points ("pass1_done", "pass2_start", ...), e.g. to modify the file.
    std::function<void(const char*)> on_step;

private:
    struct Impl;
    Ledger& ledger_;
    const crypto::Keys& keys_;
    std::string volume_;
    ReplicateOptions opt_;
};

}  // namespace tierfs
