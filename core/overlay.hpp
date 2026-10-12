// The overlay: what a path IS and what its bytes are, joining the origin folder, the ledger and the devices.
// See docs/DURABLE_STORE.md section 24. No FUSE in here: the driver is a thin wrapper around this class.
//
// Slice 3h-1: the READ side.
//   getattr / readdir / read for local files (served from the origin) and remote files (tracked in the ledger,
//   bytes only on the devices), without ever returning wrong bytes: a remote read verifies every chunk it uses.
// Slice 3h-2: the WRITE side.
//   open / create / read_fh / write_fh / release / truncate with file handles; the write gate (a FileGate the drop
//   engine uses to keep writers away while it moves a file); hydration (bringing a remote file back before it is
//   written) and the recovery of an interrupted hydration.
//
// Thread-safe (the ledger is too). Reads of local bytes and device fetches run without any lock held.
#pragma once

#include <cstdint>
#include <condition_variable>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "dropengine.hpp"   // DeviceMap
#include "ledger.hpp"

namespace tierfs {

struct OverlayConfig {
    std::string origin_dir;         // the real folder holding the local bytes
    std::string logical_prefix;     // ledger path = prefix + path relative to the origin, e.g. "/Users/me/Projects/"
    size_t cache_bytes = 64u << 20; // verified remote chunks kept in memory
    int64_t write_wait_ms = 30000;  // how long a writer waits for a drop/hydration of the same file to finish before EBUSY
};

enum class OvKind { Dir, File, Symlink, Other };

struct OvStat {
    OvKind kind = OvKind::File;
    uint64_t size = 0;
    int64_t mtime = 0;              // seconds
    uint32_t mode = 0;              // permission bits only
    bool remote = false;            // the bytes are not in the origin: they live on the devices
    std::string file_id;            // set when the ledger tracks it
};

struct OvEntry {
    std::string name;
    OvKind kind = OvKind::File;
    bool remote = false;
};

struct OverlayRecovery {
    std::vector<std::string> actions;    // what was finished or undone
    std::vector<std::string> problems;   // what needs a human
};

class Overlay {
public:
    // `engine` (optional) lets hydration use the quarantine copy when one is still held; the engine's resolver must map a
    // file to the same origin path this overlay uses.
    Overlay(Ledger& ledger, const crypto::Keys& keys, DeviceMap devices, OverlayConfig cfg, DropEngine* engine = nullptr);

    // Paths are relative to the mount ("/", "/dir/file"). Return 0 or -errno.
    int getattr(const std::string& path, OvStat* out);
    int readdir(const std::string& path, std::vector<OvEntry>* out);
    // Bytes read (0 at/after EOF) or -errno. Network or verification failures are -EIO, never short or wrong data.
    int64_t read(const std::string& path, uint64_t offset, size_t size, uint8_t* buf);
    int readlink(const std::string& path, std::string* target);

    // ---- handles (3h-2) ----
    // open: an existing file. Write access to a remote file hydrates it first; O_TRUNC/O_APPEND count as write access.
    int open(const std::string& path, int flags, uint64_t* fh);
    // create: a new file (it must not exist, locally or remotely). `flags` as for open(2) (O_CREAT/O_EXCL are implied).
    int create(const std::string& path, uint32_t mode, int flags, uint64_t* fh);
    int64_t read_fh(uint64_t fh, uint64_t offset, size_t size, uint8_t* buf);
    int64_t write_fh(uint64_t fh, uint64_t offset, const uint8_t* buf, size_t size);
    int ftruncate(uint64_t fh, uint64_t size);
    int fsync_fh(uint64_t fh);
    // Records the final size/mtime of a written file in the ledger, THEN lets drops proceed again.
    int release(uint64_t fh);
    int truncate(const std::string& path, uint64_t size);

    // Brings a remote file back into the origin (from the quarantine copy if one is held, else from the devices).
    int hydrate(const std::string& path);
    // After a crash: finish or undo every interrupted hydration. Run before serving requests.
    OverlayRecovery recover();

    // What the drop engine needs: while a file has writers it cannot be frozen; once frozen, new writers wait.
    FileGate* gate() { return &gate_; }
    // Hold this while calling the (not thread-safe) drop engine from elsewhere; hydration takes it only briefly and
    // falls back to the network when the engine is busy.
    std::mutex& engine_mutex() { return engine_mu_; }

    // Statistics, for tests and for `tierctl`.
    struct Stats { uint64_t chunk_fetches = 0, cache_hits = 0, bad_chunks_skipped = 0, hydrations_network = 0, hydrations_quarantine = 0; };
    Stats stats();

    const OverlayConfig& config() const { return cfg_; }

    // Resolves a mount path to {origin path, logical path}; false for anything that must not be reachable
    // (".." components, the bookkeeping directory, NUL bytes).
    bool resolve(const std::string& path, std::string* origin_path, std::string* logical_path, std::string* rel = nullptr) const;

private:
    struct Handle {
        int fd = -1;
        bool writable = false, remote = false;
        std::string file_id;
        FileRec snap;   // remote handles read this version, whatever happens to the file afterwards
    };
    class Gate : public FileGate {
    public:
        explicit Gate(Overlay& o) : o_(o) {}
        bool freeze(const FileRec& file, std::string* why) override;
        void unfreeze(const FileRec& file) override;
    private:
        Overlay& o_;
    };
    int begin_write(const std::string& logical, const std::string& origin_path, std::string* file_id, bool* need_hydrate);
    void end_write(const std::string& file_id);
    int hydrate_logical(const std::string& logical, const std::string& origin_path);
    int hydrate_from_network(const FileRec& f, const std::string& origin_path);
    uint64_t add_handle(std::shared_ptr<Handle> h);
    std::shared_ptr<Handle> get_handle(uint64_t fh);
    int64_t read_remote(const FileRec& f, uint64_t offset, size_t size, uint8_t* buf);
    std::shared_ptr<const crypto::Bytes> fetch_chunk(const ChunkRec& c, const std::vector<std::string>& device_order);
    std::vector<std::string> device_order(const FileRec& f);
    static bool is_remote_state(const FileRec& f);

    Ledger& ledger_;
    const crypto::Keys& keys_;
    DeviceMap devices_;
    OverlayConfig cfg_;
    std::string volume_;
    DropEngine* engine_;
    std::mutex engine_mu_;
    Gate gate_{*this};

    std::mutex gate_mu_;                     // guards writers_ and frozen_
    std::condition_variable gate_cv_;
    std::map<std::string, int> writers_;     // file_id -> open writers
    std::set<std::string> frozen_;           // file_ids a drop is working on

    std::mutex handles_mu_;
    std::map<uint64_t, std::shared_ptr<Handle>> handles_;
    uint64_t next_fh_ = 1;

    std::mutex hyd_mu_;                      // one hydration per file at a time
    std::map<std::string, std::shared_ptr<std::mutex>> hyd_locks_;

    // LRU of verified plaintext chunks, keyed by chunk id (content-addressed: never stale).
    std::mutex cache_mu_;
    std::list<std::string> lru_;
    struct Entry { std::shared_ptr<const crypto::Bytes> data; std::list<std::string>::iterator it; };
    std::map<std::string, Entry> cache_;
    size_t cache_used_ = 0;
    Stats stats_;
};

}  // namespace tierfs
