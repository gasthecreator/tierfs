// The durable ledger: the Mac's authoritative record of which files have
// replicas where, and of every step of every offload. See docs/DURABLE_STORE.md.
//
// Unlike the caches this is NOT disposable:
//  - it is never auto-wiped; a corrupt or too-new ledger makes open() fail and
//    the file is left untouched for a human (or a restore from a device snapshot);
//  - every transaction commits with F_FULLFSYNC (macOS fsync alone does not flush
//    the drive cache);
//  - the safety rules for deleting local bytes are enforced HERE, inside one
//    transaction, so a bug in the engine that calls us still cannot drop a file
//    that is not safely replicated (defence in depth).
//
// Not thread-safe; callers serialise. One process per ledger (flock).
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3;

namespace tierfs {

enum class FileState { LOCAL, REPLICATING, REPLICATED, DROPPING, OFFLOADED, HYDRATING, AT_RISK };
enum class ReplicaState { PENDING, UPLOADED, COMMITTED, AUDIT_FAILED, MISSING };
// What happens to the local bytes after a drop: they are MOVED aside (HELD), then either deleted for good
// (PURGING -> PURGED) or brought back (RESTORING -> RESTORED). PURGED and RESTORED are final.
enum class QuarantineState { HELD, PURGING, PURGED, RESTORING, RESTORED };

const char* to_string(FileState s);
const char* to_string(ReplicaState s);
const char* to_string(QuarantineState s);

struct FileRec {
    std::string file_id, path;
    int64_t current_version = 0;  // 0: no version recorded yet
    int64_t generation = 0;       // bumped by every local modification
    FileState state = FileState::LOCAL;
    uint64_t size = 0;
    int64_t mtime = 0;
    uint32_t mode = 0;
    bool local_present = true;
    int64_t last_access = 0;
};

struct ChunkRec {
    uint32_t idx = 0;
    std::string chunk_id;     // HMAC of the plaintext (see design doc section 4)
    uint32_t len = 0;
    std::string blob_sha256;  // hash of the ciphertext stored on the device
};

struct ReplicaRec {
    std::string device_id;
    ReplicaState state = ReplicaState::PENDING;
    int64_t committed_at = 0, last_audit_at = 0, device_seq = 0;
};

struct IntentRec {
    std::string intent_id, kind, file_id, payload;
    int64_t version = 0, generation = 0;
};

struct DeviceRec {
    std::string device_id, name, cls, state;  // state: active, suspect (restored/reset), retired
    int64_t epoch = 0;     // 0 until first observed
    int64_t last_seq = 0;  // highest commit sequence number seen from the device
};

enum class DeviceObservation {
    Unknown,       // the ledger does not know this device
    First,         // first time we hear from it
    Ok,
    Rollback,      // same epoch, lower sequence: restored from an older copy. Device is now suspect.
    EpochChanged,  // a different epoch: re-initialised or replaced. Device is now suspect.
};

struct Challenge {
    uint32_t n = 0;
    std::string response;  // hex of SHA-256(nonce_n || blob), precomputed when the chunk was sealed
};

struct DeviceReplica {
    std::string file_id;
    int64_t version = 0;
    ReplicaState state = ReplicaState::PENDING;
};

struct QuarantineRec {
    std::string intent_id, file_id, note;
    int64_t version = 0;
    QuarantineState state = QuarantineState::HELD;
    int64_t held_at = 0, resolved_at = 0;
};

constexpr int64_t MANIFEST_CHALLENGE_IDX = -1;  // chunk_challenges.idx used for a version's manifest

// Outcome of an operation that can be refused, with the reason (for logs/UI).
struct Res {
    bool ok = false;
    std::string why;
    std::string id;  // e.g. the new intent id
    explicit operator bool() const { return ok; }
};

class Ledger {
public:
    // Opens (creating if the directory is new). Returns null and fills *err when
    // the ledger is in use, corrupt, from a newer build, or the machine cannot
    // honour full-fsync durability. It never deletes or repairs anything.
    static std::unique_ptr<Ledger> open(const std::string& dir, std::string* err);
    ~Ledger();
    Ledger(const Ledger&) = delete;
    Ledger& operator=(const Ledger&) = delete;

    // Tests inject time; production uses time(nullptr).
    void set_clock(std::function<int64_t()> clock) { clock_ = std::move(clock); }
    int64_t now() const;

    // --- settings and gates ---
    std::optional<std::string> get_meta(const std::string& key);
    bool set_meta(const std::string& key, const std::string& value);  // logged
    std::string volume_id();

    // Bytes preallocated beside the ledger and released when the disk is so full
    // that SQLite cannot write. Offload refuses to start without it.
    bool ensure_reserve(uint64_t bytes);
    bool has_reserve();
    bool release_reserve();

    // --- devices ---
    // cls: "A" server, "B" single disk, "C" mobile/removable (weights 1, 1, 0.5).
    bool register_device(const std::string& device_id, const std::string& name, const std::string& cls);
    bool retire_device(const std::string& device_id);  // replicas on it stop counting
    std::optional<DeviceRec> get_device(const std::string& device_id);
    std::vector<DeviceRec> list_devices();
    // What a device says about itself. A lower sequence under the same epoch (restored from an
    // older copy) or a new epoch (re-initialised) makes it SUSPECT: its replicas stop counting and
    // files that depended on them fall back to replication / AT_RISK until it is re-verified.
    DeviceObservation observe_device(const std::string& device_id, uint64_t epoch, uint64_t seq);
    // After every replica on it has been re-audited. `seq` becomes the new high-water mark.
    Res clear_device_suspect(const std::string& device_id, uint64_t seq);
    std::vector<DeviceReplica> replicas_on_device(const std::string& device_id);

    // --- files ---
    // Starts tracking `path` (returns the existing id if already tracked).
    std::string track_file(const std::string& path, uint64_t size, int64_t mtime, uint32_t mode);
    // Starts tracking many files in ONE transaction (a scan of a big folder would otherwise pay a full fsync per file). Paths that
    // are already tracked are left as they are. Returns how many were new.
    struct NewFile { std::string path; uint64_t size = 0; int64_t mtime = 0; uint32_t mode = 0; };
    size_t track_files(const std::vector<NewFile>& files);
    // The key under which paths are unique: lower-cased and Unicode-decomposed (what APFS treats as the same name), or the path itself on a
    // case-sensitive volume. Two paths with the same fold are ONE name: tracking, renaming and lookup all go through it.
    std::string fold_path(const std::string& path) const;
    bool case_sensitive() const { return case_sensitive_; }
    // Declare the origin volume case-sensitive (default: not, like APFS). Only allowed while no file is tracked.
    Res set_case_sensitive(bool on);
    std::optional<FileRec> get_file(const std::string& file_id);
    std::optional<FileRec> get_file_by_path(const std::string& path);
    std::vector<FileRec> list_files(std::optional<FileState> state = std::nullopt);
    // Every tracked file whose path starts with `prefix` (a directory prefix ending in "/"), ordered by path.
    std::vector<FileRec> list_files_under(const std::string& prefix);
    // The bytes changed locally: bumps generation, invalidating any replication or
    // drop prepared against the old bytes. False if the file is DROPPING/HYDRATING
    // (writers must be frozen) or OFFLOADED (hydrate first).
    Res note_local_modified(const std::string& file_id, uint64_t new_size, int64_t new_mtime);

    // --- the namespace (3h-3): a file the user deleted, renamed, or whose attributes changed ---
    // The user deleted the file. It is not forgotten (the devices keep every version, and history is append-only): its row is
    // parked under a reserved "graveyard" path that also records the former path, which frees the name and keeps every
    // consumer that looks files up by path (the overlay, the policy) from ever seeing it. Not allowed while the file is
    // DROPPING or HYDRATING.
    Res retire_file(const std::string& file_id, const std::string& reason);
    // Brings a deleted OFFLOADED file back to its former path (if that name is free). Only offloaded files can be undeleted:
    // a deleted file with local bytes has no local bytes any more (recover it from the devices with `tierctl restore`).
    Res undelete_file(const std::string& file_id);
    std::vector<FileRec> list_retired();
    static bool is_retired_path(const std::string& path);
    static std::string former_path(const FileRec& f);   // the path before deletion (the path itself for a live file)
    // Moves one tracked file to a free path. A file with local bytes becomes LOCAL again with a new generation (its manifest
    // names the old path, so it must be replicated again); an offloaded file only changes its path.
    Res rename_file(const std::string& file_id, const std::string& new_path);
    // The same for a whole directory: every file under `old_prefix` ("/a/b/") moves to `new_prefix`, in one transaction.
    // Res::id is the number of files moved. Refused if any is DROPPING/HYDRATING or any destination name is taken.
    Res rename_prefix(const std::string& old_prefix, const std::string& new_prefix);
    // chmod / utimens. A file with local bytes becomes LOCAL again (its manifest has the old attributes); an offloaded file
    // only has its recorded attributes changed (they are what stat shows and what hydration restores).
    Res note_attrs_changed(const std::string& file_id, std::optional<uint32_t> mode, std::optional<int64_t> mtime);

    // --- replication (never deletes anything) ---
    // Records version N+1 of the file as it is NOW (snapshots the generation) and
    // moves it to REPLICATING. Returns the version in Res::id.
    Res begin_replication(const std::string& file_id, const std::vector<ChunkRec>& chunks,
                          uint64_t size, int64_t mtime);
    Res set_replica(const std::string& file_id, int64_t version, const std::string& device_id,
                    ReplicaState state, int64_t device_seq = 0);
    // A replica found on a device that the ledger did not know (crash between the
    // device commit and our record, or a restored ledger). Logged as "adopted".
    Res adopt_replica(const std::string& file_id, int64_t version, const std::string& device_id,
                      int64_t device_seq);
    // REPLICATING -> REPLICATED. Fails if the file changed since begin_replication
    // or no replica is COMMITTED.
    Res finish_replication(const std::string& file_id, int64_t version);
    // Result of a challenge audit. A failure demotes the replica; if that leaves an
    // OFFLOADED file with no committed replica it becomes AT_RISK automatically.
    Res record_audit(const std::string& file_id, int64_t version, const std::string& device_id,
                     bool ok, const std::string& detail);
    // Hash of the sealed manifest, recorded BEFORE it is uploaded so that a manifest found on a
    // device can be recognised exactly. Set once; the same value again is fine, another is refused.
    Res set_manifest_hash(const std::string& file_id, int64_t version, const std::string& sha256_hex);
    std::optional<std::string> get_manifest_hash(const std::string& file_id, int64_t version);

    // One-time audit challenges (design doc section 7): responses precomputed when a chunk (or the
    // manifest, idx == MANIFEST_CHALLENGE_IDX) was sealed. Each is usable once.
    Res add_challenges(const std::string& file_id, int64_t version, int64_t idx, const std::vector<Challenge>& cs);
    std::optional<Challenge> take_challenge(const std::string& file_id, int64_t version, int64_t idx);
    size_t challenges_left(const std::string& file_id, int64_t version, int64_t idx);
    uint32_t next_challenge_n(const std::string& file_id, int64_t version, int64_t idx);

    std::vector<ReplicaRec> get_replicas(const std::string& file_id, int64_t version);
    std::vector<ChunkRec> get_chunks(const std::string& file_id, int64_t version);
    bool has_version(const std::string& file_id, int64_t version);   // (an empty file has a version but no chunks)
    // Sum of class weights of COMMITTED replicas audited within `max_audit_age` s.
    double replica_weight(const std::string& file_id, int64_t version, int64_t max_audit_age);
    // Same weights, but counting every COMMITTED replica on an active device whether or not it was audited
    // recently: for PLANNING ("will this file have enough copies?"). Never a basis for deleting anything.
    double committed_weight(const std::string& file_id, int64_t version);

    // --- consent ---
    // Permission for paths starting with scope_prefix (must not be empty).
    std::string create_consent(const std::string& scope_prefix, int64_t ttl_seconds,
                               const std::string& ack_text);

    std::optional<std::string> consent_ack(const std::string& consent_id);   // what the user was shown when they agreed

    // --- dropping local bytes: the dangerous step (design doc section 7) ---
    // Transaction A. Succeeds only if EVERY rule holds, all checked in one
    // transaction: recovery phrase acknowledged, backup acknowledged (or the path is
    // under the `test_prefix` meta value), reserve present, valid consent covering
    // the path, file REPLICATED at `version` with `generation` unchanged and bytes
    // still local, and replica weight >= min_weight from audits younger than
    // max_audit_age. On success the file is DROPPING and an intent is open.
    Res begin_drop(const std::string& file_id, int64_t version, int64_t generation,
                   const std::string& consent_id, double min_weight, int64_t max_audit_age);
    // Transaction B, after the local bytes were moved to quarantine.
    Res complete_drop(const std::string& intent_id);
    // Bytes were restored (e.g. a late audit failed): DROPPING -> REPLICATED.
    Res abort_drop(const std::string& intent_id, const std::string& reason);
    std::vector<IntentRec> open_intents();

    // --- quarantine: the last chance to undo a drop (design doc section 7, steps 4 and 7) ---
    std::optional<QuarantineRec> get_quarantine(const std::string& intent_id);
    std::vector<QuarantineRec> list_quarantine(std::optional<QuarantineState> state = std::nullopt);
    // Permission to delete the quarantined bytes for good, recorded BEFORE the unlink. Enforces: recovery
    // phrase, backup/test-prefix and reserve gates; the file is OFFLOADED or already hydrated (never AT_RISK:
    // that means restore); the quarantine period has elapsed unless `emergency`; and, always, replica weight
    // >= min_weight from audits younger than max_audit_age. Deleting the quarantine is the last chance to
    // restore, so even an emergency cannot skip the fresh evidence. Idempotent while PURGING (a retry).
    Res begin_purge(const std::string& intent_id, int64_t retention_seconds, bool emergency, double min_weight, int64_t max_audit_age);
    Res complete_purge(const std::string& intent_id);   // after the bytes are gone
    // Permission to move the quarantined bytes back. Non-destructive, so no gates; needs the file to be
    // OFFLOADED or AT_RISK and the quarantine HELD. Idempotent while RESTORING.
    Res begin_restore(const std::string& intent_id, const std::string& reason);
    // After the bytes are back. If they were verified against the plan and a committed replica exists the
    // file is REPLICATED; otherwise LOCAL with its generation bumped (nothing prepared before may be reused).
    Res complete_restore(const std::string& intent_id, bool bytes_verified);

    // --- recall ---
    Res begin_hydrate(const std::string& file_id);     // OFFLOADED -> HYDRATING
    Res complete_hydrate(const std::string& file_id);  // HYDRATING -> REPLICATED (bytes local)
    Res abort_hydrate(const std::string& file_id);     // HYDRATING -> OFFLOADED

    // --- risk ---
    Res mark_at_risk(const std::string& file_id, const std::string& reason);
    Res clear_at_risk(const std::string& file_id);  // needs a committed audited replica

    void touch_access(const std::string& file_id, int64_t t);

    // --- integrity ---
    // Everything wrong with the ledger, empty if sound: SQLite integrity, hash
    // chain, contiguous event numbers, and the state invariants of section 5.
    std::vector<std::string> fsck();
    uint64_t event_count();
    // Consistent copy of the ledger (for pushing to a device as a snapshot).
    bool snapshot_to(const std::string& path);

private:
    // Every public method takes this (recursively: they call each other), so the ledger can be shared by the filesystem threads,
    // the policy thread and the engines. It is held only inside one call, never across network or disk-heavy work of the callers.
    mutable std::recursive_mutex mu_;
    Ledger() = default;
    bool case_sensitive_ = false;
    bool migrate_1_to_2(std::string* err);
    bool init_schema(std::string* err);
    void append_event(const std::string& kind, const std::string& file_id, int64_t version,
                      const std::string& device_id, const std::string& detail);
    std::string new_id();
    bool exec(const char* sql);
    // A file whose current version has lost its last committed replica: REPLICATED goes back to
    // REPLICATING (the engine will resume it), OFFLOADED becomes AT_RISK. Inside the caller's txn.
    void demote_if_orphaned(const std::string& file_id, int64_t version, const std::string& device_id, const std::string& why);
    void reevaluate_for_device(const std::string& device_id, const std::string& why);

    sqlite3* db_ = nullptr;
    int lock_fd_ = -1;
    std::string dir_;
    std::function<int64_t()> clock_;
};

}  // namespace tierfs
