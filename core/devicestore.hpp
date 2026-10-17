// The storage side of a replica: what a device (the reference backend today, a phone
// agent later) does with the encrypted chunks and manifests the Mac sends it.
// See docs/DURABLE_STORE.md sections 6, 8, 10 and proto/PROTOCOL.md (device protocol).
//
// Rules this class enforces on the device, because the Mac must be able to trust an ack:
//   - an ack means the bytes are on disk: temp file -> F_FULLFSYNC -> rename ->
//     F_FULLFSYNC of the directory -> only then the index row (also full-fsync);
//   - append-only by default: nothing is overwritten, and nothing is deleted except through the two operations below, which
//     only an authorized Mac can call (docs/adr/0010): delete_manifests (exactly the named versions) and sweep (chunks that
//     no stored manifest lists; a database trigger refuses to delete a listed chunk whatever the code does).
//     Re-sending something that exists returns "existed" and the ORIGINAL's hash,
//     because random nonces make a re-sealed chunk differ from the stored one;
//   - every upload is checked against the hash the sender claims, every download and
//     audit reads the bytes from disk again;
//   - a manifest is accepted only when every chunk it lists is already present;
//   - the device is bound to one volume and refuses another;
//   - commit sequence numbers only go up, so a rolled-back device is detectable.
//
// The device never sees keys or plaintext. Thread-safe.
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3;

namespace tierfs {

// Deliberate misbehaviour for tests ("simulate a lying, forgetful, full device").
struct DeviceFaults {
    bool lie_ack_chunk = false;            // acknowledge a chunk without writing it
    bool lie_ack_manifest = false;         // ... or a manifest
    bool corrupt_on_store = false;         // flip a byte in each chunk file after acknowledging it
    bool truncate_on_store = false;        // cut each chunk file in half after acknowledging it
    bool swap_get = false;                 // answer GET_CHUNK with a different chunk's bytes
    bool lose_manifest_after_commit = false;  // delete the manifest file after committing it
    bool enospc = false;                   // report "disk full" for every write
    bool drop_connection_after_put = false;   // (server) execute a put, then close without replying
    int slow_ms = 0;                       // sleep this long in every operation
    // Comma-separated names, e.g. "corrupt_on_store,slow=50". False + *err on unknown names.
    static bool parse(const std::string& csv, DeviceFaults* out, std::string* err);
};

struct DevInfo {
    std::string device_id;
    uint64_t epoch = 0;     // random, fixed when the store is created
    uint64_t seq = 0;       // commit sequence number of the newest manifest
    std::string volume_id;  // empty until bound
    uint64_t free_bytes = 0;
};

struct PutChunkOut {
    int err = 0;  // 0 or an errno value
    std::string msg;
    bool existed = false;     // true: the ORIGINAL was kept; sha256_hex describes it
    std::string sha256_hex;   // hash of the blob the device holds
};

struct PutManifestOut {
    int err = 0;
    std::string msg;
    bool existed = false;
    uint64_t seq = 0;
    std::string sha256_hex;
};

struct ManifestEntry {
    uint64_t seq = 0;
    std::string file_id;
    int64_t version = 0;
    std::string sha256_hex;
};

struct AuditItem {
    uint8_t kind = 0;      // 0 chunk, 1 manifest
    std::string id;        // chunk id, or file id
    int64_t version = 0;   // manifests only
    std::vector<uint8_t> nonce;  // 32 bytes
};

struct AuditOut {
    uint8_t status = 0;    // 0 answered, 1 missing, 2 unreadable
    std::string response_hex;  // SHA-256(nonce || stored bytes), computed from disk now
};

constexpr size_t MAX_CHUNK_BLOB = 8u << 20;
constexpr size_t MAX_MANIFEST_BLOB = 15u << 20;
constexpr size_t MAX_MANIFEST_CHUNKS = 1u << 20;
constexpr size_t MAX_AUDIT_ITEMS = 64;
constexpr size_t MAX_DELETE_ITEMS = 64;
constexpr size_t MAX_SWEEP_CHUNKS = 100000;
constexpr int64_t DEFAULT_TRASH_RETENTION = 7 * 86400;  // deleted chunks and manifests are kept this long before they are really removed (ADR-0017)
constexpr uint64_t DEFAULT_MIN_SWEEP_AGE = 3600;  // seconds a chunk must be unreferenced and untouched before it may be swept
constexpr size_t MAX_LIST_ENTRIES = 1000;
constexpr uint64_t MIN_FREE_RESERVE = 16u << 20;  // never fill the disk to the last byte

struct DeleteManifestsOut {
    int err = 0;
    std::string msg;
    uint64_t seq = 0;              // the device's commit sequence after the call (deleting bumps it, so rollbacks stay visible)
    std::vector<uint8_t> deleted;  // per item: 1 deleted now, 0 it was not there
};

struct GcStatus {
    bool deletions_allowed = false;
    uint32_t manifests = 0, manifests_without_refs = 0;  // the latter: stored before reference lists existed; sweep is refused while any remain
    uint64_t chunks = 0, chunk_bytes = 0;
    uint64_t unreferenced_chunks = 0, unreferenced_bytes = 0;  // listed by no manifest, whatever their age
    uint64_t manifests_deleted = 0, chunks_deleted = 0;        // lifetime totals, from the device's own log
    uint64_t trash_files = 0, trash_bytes = 0;  // deleted things still kept for a while (ADR-0017): their space comes back when they are purged
    int64_t trash_retention_s = 0;              // how long (0: deletions are final at once)
};

// What the device keeps after a deletion, for a while (ADR-0017).
struct TrashStats {
    uint64_t chunks = 0, chunk_bytes = 0;
    uint64_t manifests = 0, manifest_bytes = 0;  // (manifests with their chunk lists)
    int64_t oldest = 0, newest = 0;              // when things were put there (unix time); 0 if empty
};
struct TrashRestoreOut {
    int err = 0;
    std::string msg;
    uint64_t chunks = 0, manifests = 0;  // put back
    uint64_t skipped = 0;                // already present again, or not restorable
    std::vector<std::string> notes;      // why anything was skipped
};

struct SweepOut {
    int err = 0;
    std::string msg;
    uint64_t chunks_deleted = 0, bytes_deleted = 0;
    uint64_t chunks_left = 0;     // unreferenced chunks still on the device (too young, or over the limit)
    uint64_t strays_removed = 0;  // files with no index row, older than the age (leftovers of a crash)
};

bool valid_chunk_id(const std::string& s);   // 64 lowercase hex
bool valid_file_id(const std::string& s);    // 32 lowercase hex

class DeviceStore {
public:
    // Creates the store if the directory is new. Never wipes or repairs an existing one:
    // a corrupt index or an unknown version makes open() fail with the files untouched.
    // `lock_dir` (optional) is where the lock that keeps two processes from using one store goes, for a store on a filesystem that cannot lock files
    // (shared storage on a phone): it must be on one that can. Always the same directory for the same store.
    static std::unique_ptr<DeviceStore> open(const std::string& dir, std::string* err, const std::string& lock_dir = "");
    ~DeviceStore();
    DeviceStore(const DeviceStore&) = delete;
    DeviceStore& operator=(const DeviceStore&) = delete;

    DevInfo info();
    // First call binds; the same id again is fine; another id is refused (EPERM).
    int bind_volume(const std::string& volume_id, std::string* msg);

    std::vector<bool> has_chunks(const std::vector<std::string>& ids);
    PutChunkOut put_chunk(const std::string& chunk_id, const std::vector<uint8_t>& blob, const std::string& claimed_sha256_hex);
    int get_chunk(const std::string& chunk_id, std::vector<uint8_t>& out, std::string* msg);

    PutManifestOut put_manifest(const std::string& file_id, int64_t version, const std::vector<uint8_t>& blob,
                                const std::string& claimed_sha256_hex, const std::vector<std::string>& chunk_ids);
    int get_manifest(const std::string& file_id, int64_t version, std::vector<uint8_t>& out, std::string* msg);
    int list_manifests(uint64_t since_seq, size_t max, std::vector<ManifestEntry>& out, DevInfo* info_out);

    std::vector<AuditOut> audit(const std::vector<AuditItem>& items);

    // --- garbage collection (ADR-0010) ---
    // Whether this device may delete at all (a paired device, or one started with --allow-delete). Off until enabled: both operations
    // below then answer EPERM.
    void set_deletions_allowed(bool allowed);
    // The floor for the age a sweep may ask for (a request for less is raised to it). Tests lower it.
    void set_min_sweep_age(uint64_t seconds);
    // Removes exactly these manifests (and their reference lists), idempotently, and bumps the commit sequence. The chunks stay until a sweep.
    DeleteManifestsOut delete_manifests(const std::vector<std::pair<std::string, int64_t>>& items);
    GcStatus gc_status();

    // --- the trash (ADR-0017) ---
    // A deletion (sweep, delete_manifests) moves the files into <store>/trash instead of unlinking them, and they are removed for good only after
    // this many seconds. A Mac that lied about a chunk list, or a bug, can then be undone: trash_restore puts things back through the normal
    // upload path. 0 makes deletions final at once (the earlier behaviour). Default: 7 days.
    void set_trash_retention(int64_t seconds);
    int64_t trash_retention();
    TrashStats trash_stats();
    // Removes what has been in the trash for the retention period (or all of it with `everything`). `now` = 0 means the current time. Returns files
    // removed.
    uint64_t trash_purge(int64_t now = 0, bool everything = false);
    // Puts back what went into the trash within the last `newer_than_s` seconds (0: everything in it): chunks first, then manifests with their chunk
    // lists.
    TrashRestoreOut trash_restore(int64_t newer_than_s);
    // Deletes chunks that no stored manifest lists and that were neither uploaded nor reported present within `min_age_s`, at most
    // `max_chunks` of them, and removes stray files older than that. Refused while any manifest lacks its reference list.
    SweepOut sweep(uint64_t min_age_s, size_t max_chunks, bool dry_run);

    // Free space that must remain after a write (default MIN_FREE_RESERVE). Tests raise it to
    // simulate a nearly full disk without filling one.
    void set_free_reserve(uint64_t bytes);
    void set_faults(const DeviceFaults& f);
    DeviceFaults faults();
    uint64_t damaged_reads() const { return damaged_; }

private:
    DeviceStore() = default;
    bool init(std::string* err);
    bool exec(const char* sql);
    std::string meta_get(const std::string& key);
    std::string chunk_path(const std::string& id) const;
    std::string manifest_path(const std::string& file_id, int64_t version) const;
    int durable_write(const std::string& final_path, const std::vector<uint8_t>& data);

    sqlite3* db_ = nullptr;
    int lock_fd_ = -1;
    std::string dir_;
    std::mutex mu_;
    DeviceFaults faults_;
    uint64_t damaged_ = 0;
    uint64_t min_free_ = MIN_FREE_RESERVE;
    bool deletions_allowed_ = false;
    uint64_t min_sweep_age_ = DEFAULT_MIN_SWEEP_AGE;
    int64_t trash_retention_ = DEFAULT_TRASH_RETENTION;
    // Moves a file into the trash under the name that records when (and what it was); false if it could not (the caller then leaves it alone).
    bool trash_file(const std::string& from, const std::string& to);
    bool migrate_1_to_2();
    bool create_gc_schema();
    int count_refless_locked();
    void touch_unreferenced_locked(const std::vector<std::string>& ids);
};

}  // namespace tierfs
