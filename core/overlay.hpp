// The overlay: what a path IS and what its bytes are, joining the origin folder, the ledger and the devices.
// See docs/DURABLE_STORE.md section 24. No FUSE in here: the driver is a thin wrapper around this class.
//
// Slice 3h-1 (this file's first content): the READ side.
//   getattr / readdir / read for local files (served from the origin) and remote files (tracked in the ledger,
//   bytes only on the devices), without ever returning wrong bytes: a remote read verifies every chunk it uses.
//
// Thread-safe: ledger access is serialised internally; reads of local bytes and device fetches run unlocked.
#pragma once

#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <mutex>
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

class Overlay {
public:
    Overlay(Ledger& ledger, const crypto::Keys& keys, DeviceMap devices, OverlayConfig cfg);

    // Paths are relative to the mount ("/", "/dir/file"). Return 0 or -errno.
    int getattr(const std::string& path, OvStat* out);
    int readdir(const std::string& path, std::vector<OvEntry>* out);
    // Bytes read (0 at/after EOF) or -errno. Network or verification failures are -EIO, never short or wrong data.
    int64_t read(const std::string& path, uint64_t offset, size_t size, uint8_t* buf);
    int readlink(const std::string& path, std::string* target);

    // Statistics, for tests and for `tierctl`.
    struct Stats { uint64_t chunk_fetches = 0, cache_hits = 0, bad_chunks_skipped = 0; };
    Stats stats();

    const OverlayConfig& config() const { return cfg_; }

    // Resolves a mount path to {origin path, logical path}; false for anything that must not be reachable
    // (".." components, the bookkeeping directory, NUL bytes).
    bool resolve(const std::string& path, std::string* origin_path, std::string* logical_path, std::string* rel = nullptr) const;

private:
    struct Remote;
    int64_t read_remote(const FileRec& f, uint64_t offset, size_t size, uint8_t* buf);
    std::shared_ptr<const crypto::Bytes> fetch_chunk(const ChunkRec& c, const std::vector<std::string>& device_order);
    std::vector<std::string> device_order(const FileRec& f);
    static bool is_remote_state(const FileRec& f);

    Ledger& ledger_;
    const crypto::Keys& keys_;
    DeviceMap devices_;
    OverlayConfig cfg_;
    std::string volume_;
    std::mutex ledger_mu_;

    // LRU of verified plaintext chunks, keyed by chunk id (content-addressed: never stale).
    std::mutex cache_mu_;
    std::list<std::string> lru_;
    struct Entry { std::shared_ptr<const crypto::Bytes> data; std::list<std::string>::iterator it; };
    std::map<std::string, Entry> cache_;
    size_t cache_used_ = 0;
    Stats stats_;
};

}  // namespace tierfs
