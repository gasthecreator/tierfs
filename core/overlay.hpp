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
// Slice 3h-3: the NAMESPACE.
//   mkdir / rmdir / unlink / rename / symlink / chmod / chown / utimens / statfs / extended attributes / undelete, for local
//   files and for remote ones, with the ledger kept in step (see docs/DURABLE_STORE.md section 24).
//
// Thread-safe (the ledger is too). Reads of local bytes and device fetches run without any lock held.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <optional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "dropengine.hpp"   // DeviceMap
#include "ledger.hpp"
#include "locks.hpp"

namespace tierfs {

struct OverlayConfig {
    std::string origin_dir;         // the real folder holding the local bytes
    std::string logical_prefix;     // ledger path = prefix + path relative to the origin, e.g. "/Users/me/Projects/"
    size_t cache_bytes = 64u << 20; // verified remote chunks kept in memory
    int64_t write_wait_ms = 30000;  // how long a writer waits for a drop/hydration of the same file to finish before EBUSY
    // Read-ahead: once a remote file is being read sequentially (two reads in a row, each starting where the last ended), up to this many of the
    // following chunks are fetched in the background, verified exactly like any other fetch, and kept in the chunk cache. 0 turns it off. The window
    // starts at one chunk and doubles with every sequential read, and never exceeds a quarter of the cache.
    int readahead_chunks = 0;
    int readahead_threads = 2;
};

enum class OvKind { Dir, File, Symlink, Other };

struct OvStat {
    OvKind kind = OvKind::File;
    uint64_t size = 0;
    int64_t mtime = 0;              // seconds
    int64_t mtime_nsec = 0;         // the sub-second part (the kernel decides whether a directory changed by comparing times)
    uint32_t mode = 0;              // permission bits only
    bool remote = false;            // the bytes are not in the origin: they live on the devices
    uint32_t nlink = 1;             // names the file has in the origin (a file with more than one is never offloaded)
    std::string file_id;            // set when the ledger tracks it
    uint64_t ino = 0;               // a stable inode number (see Overlay::file_inode / origin_inode); never 0 or 1
};

struct OvEntry {
    std::string name;
    OvKind kind = OvKind::File;
    bool remote = false;
    uint64_t ino = 0;   // the same number getattr gives for this name
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
    ~Overlay();

    // Inode numbers (ADR-0018). A tracked file with one name has the number of its file id, so it keeps it when it is renamed, offloaded and brought back
    // (the bytes in the origin are a different inode each time). A file with several names, a directory and anything the ledger does not track yet have
    // the number of their place in the origin (device and inode), which is what makes hard links show one number. Never 0 or 1 (0 means "none", and 1
    // is the root of a FUSE mount).
    static uint64_t file_inode(const std::string& file_id);
    // The number made from the first eight bytes of a hash: big-endian, and never 0 or 1 (shifted up by two). Public so the edges can be tested.
    static uint64_t inode_from_hash(const std::vector<uint8_t>& hash);
    static uint64_t origin_inode(uint64_t dev, uint64_t ino);

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

    // ---- namespace (3h-3) ----
    int mkdir(const std::string& path, uint32_t mode);
    int rmdir(const std::string& path);        // ENOTEMPTY while files whose bytes are only on the devices are in it
    int unlink(const std::string& path);       // a remote file is deleted too (its bytes stay on the devices and in quarantine)
    int rename(const std::string& from, const std::string& to);   // files and directories, local and remote; replaces an existing file
    int symlink(const std::string& target, const std::string& linkpath);
    int chmod(const std::string& path, uint32_t mode);
    int chown(const std::string& path, int64_t uid, int64_t gid);   // only to yourself (-1 leaves it)
    // mtime in seconds (nullopt: unchanged); atime is not kept.
    int utimens(const std::string& path, std::optional<int64_t> mtime);
    struct FsStats { uint64_t block_size = 0, blocks = 0, blocks_free = 0, blocks_avail = 0, files = 0, files_free = 0; };
    int statfs(FsStats* out);
    // Extended attributes. Remote files answer get/list from their manifest; set/remove hydrate the file first.
    // getxattr/listxattr: with size 0 return the size needed; a too small buffer is -ERANGE; a missing attribute -ENOATTR.
    int64_t getxattr(const std::string& path, const std::string& name, uint8_t* buf, size_t size);
    int64_t listxattr(const std::string& path, char* buf, size_t size);
    int setxattr(const std::string& path, const std::string& name, const uint8_t* value, size_t size, int flags);
    int removexattr(const std::string& path, const std::string& name);
    // Brings a deleted OFFLOADED file back at its former path (`path`), if nothing is there now.
    int undelete(const std::string& path);
    // A second name for a regular file (ADR-0011). A file that is only on the devices is brought back first. The new name is a separate tracked
    // file; while a file has more than one name it is never offloaded. Directories and symlinks: -EPERM. An existing destination: -EEXIST.
    int link(const std::string& from, const std::string& to);

    // ---- advisory locks (ADR-0011): emulated here, per file identity and lock owner; the caller waits by polling.
    // getlk: -> `lk->type` becomes Unlock when nothing is in the way, else it is the blocking lock. setlk/flock_op: 0, or -EAGAIN when another owner
    // holds a conflicting lock. An Unlock always succeeds.
    int getlk(uint64_t fh, uint64_t owner, LockInfo* lk);
    int setlk(uint64_t fh, uint64_t owner, const LockRange& lk);
    int flock_op(uint64_t fh, uint64_t owner, LockType type);
    // The owner closed a descriptor of this file (FUSE flush): its byte-range locks on the file go, as POSIX says.
    int unlock_owner(uint64_t fh, uint64_t owner);
    LockTable& locks() { return locks_; }

    // What the drop engine needs: while a file has writers it cannot be frozen; once frozen, new writers wait.
    FileGate* gate() { return &gate_; }
    // For the scanner: run `f` under the namespace lock (no rename, create, write registration or freeze can interleave), and ask,
    // from inside such a call, whether anybody has the file open for writing.
    void locked(const std::function<void()>& f) { std::lock_guard<std::mutex> g(gate_mu_); f(); }
    bool has_writers_locked(const std::string& file_id) const { auto it = writers_.find(file_id); return it != writers_.end() && it->second > 0; }
    // Hold this while calling the (not thread-safe) drop engine from elsewhere; hydration takes it only briefly and
    // falls back to the network when the engine is busy.
    std::mutex& engine_mutex() { return engine_mu_; }

    // Statistics, for tests and for `tierctl`.
    struct Stats {
        uint64_t chunk_fetches = 0, cache_hits = 0, bad_chunks_skipped = 0, hydrations_network = 0, hydrations_quarantine = 0, prefetched = 0;
    };
    Stats stats();

    const OverlayConfig& config() const { return cfg_; }
    // The devices can change while the overlay runs (one comes back, one is replaced).
    void set_devices(DeviceMap devices) { std::lock_guard<std::mutex> g(dev_mu_); devices_ = std::move(devices); }

    // Resolves a mount path to {origin path, logical path}; false for anything that must not be reachable
    // (".." components, the bookkeeping directory, NUL bytes).
    bool resolve(const std::string& path, std::string* origin_path, std::string* logical_path, std::string* rel = nullptr) const;

private:
    struct Handle {
        int fd = -1;
        bool writable = false, remote = false;
        std::string file_id;
        FileRec snap;   // remote handles read this version, whatever happens to the file afterwards
        std::mutex lmu;  // guards the two sets below: the owners that locked through this handle (released with it)
        std::set<uint64_t> range_owners, flock_owners;
    };
    class Gate : public FileGate {
    public:
        explicit Gate(Overlay& o) : o_(o) {}
        bool freeze(const FileRec& file, std::string* why) override;
        void unfreeze(const FileRec& file) override;
    private:
        Overlay& o_;
    };
    int wait_idle(std::unique_lock<std::mutex>& g, const std::string& logical, std::optional<FileRec>* out);
    int remote_xattrs(const FileRec& f, std::vector<std::pair<std::string, crypto::Bytes>>* out);
    int attr_change(const std::string& path, const std::function<int(const std::string& origin_path, bool is_dir)>& apply,
                    std::optional<uint32_t> mode, std::optional<int64_t> mtime, int depth = 0);
    int unlink_impl(const std::string& path, int depth);
    int rename_impl(const std::string& from, const std::string& to, int depth);
    // Registers a writer so that no drop can freeze the file. `modify` false: the file is only being guarded (a hard link is made to it), not
    // changed, so it stays replicated.
    int begin_write(const std::string& logical, const std::string& origin_path, std::string* file_id, bool* need_hydrate, bool modify = true);
    void end_write(const std::string& file_id);
    int hydrate_logical(const std::string& logical, const std::string& origin_path);
    int hydrate_from_network(const FileRec& f, const std::string& origin_path);
    uint64_t add_handle(std::shared_ptr<Handle> h);
    std::shared_ptr<Handle> get_handle(uint64_t fh);
    int64_t read_remote(const FileRec& f, uint64_t offset, size_t size, uint8_t* buf);
    void note_read(const FileRec& f, const std::vector<ChunkRec>& chunks, uint64_t offset, size_t done);
    void readahead_loop();
    std::shared_ptr<const crypto::Bytes> fetch_chunk(const ChunkRec& c, const std::vector<std::string>& device_order);
    std::vector<std::string> device_order(const FileRec& f);
    static bool is_remote_state(const FileRec& f);

    std::string lock_key(Handle& h);
    LockTable locks_;
    Ledger& ledger_;
    const crypto::Keys& keys_;
    mutable std::mutex dev_mu_;   // guards devices_
    DeviceMap devices_;
    DeviceMap devices_snapshot() const { std::lock_guard<std::mutex> g(dev_mu_); return devices_; }
    DeviceClient* client_for(const std::string& id) const { std::lock_guard<std::mutex> g(dev_mu_); auto it = devices_.find(id); return it == devices_.end() ? nullptr : it->second; }
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

    std::mutex xattr_mu_;                    // manifest attributes of remote files, cached per (file, version)
    std::map<std::string, std::vector<std::pair<std::string, crypto::Bytes>>> xattr_cache_;

    std::mutex hyd_mu_;                      // one hydration per file at a time
    std::map<std::string, std::shared_ptr<std::mutex>> hyd_locks_;

    // Read-ahead: what each file's last read was, the queue of chunks to fetch, and the threads that fetch them (started on first use).
    struct Streak {
        uint64_t next = 0;
        int count = 0;
        size_t window = 1;
    };
    struct Ahead {
        ChunkRec chunk;
        std::vector<std::string> order;
    };
    std::mutex ra_mu_;
    std::condition_variable ra_cv_;
    std::map<std::string, Streak> streaks_;
    std::list<Ahead> ra_queue_;
    std::set<std::string> ra_queued_;
    std::vector<std::thread> ra_threads_;
    bool ra_stop_ = false;

    // LRU of verified plaintext chunks, keyed by chunk id (content-addressed: never stale).
    std::mutex cache_mu_;
    std::condition_variable cache_cv_;
    std::set<std::string> inflight_;  // chunks somebody is fetching right now (a second reader waits for it instead of fetching again)
    std::list<std::string> lru_;
    struct Entry { std::shared_ptr<const crypto::Bytes> data; std::list<std::string>::iterator it; };
    std::map<std::string, Entry> cache_;
    size_t cache_used_ = 0;
    Stats stats_;
};

}  // namespace tierfs
