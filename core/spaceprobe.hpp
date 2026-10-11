// How much room is there? The number the whole tiering decision hangs on.
//
// macOS reports two figures: the raw free blocks (statvfs) and "available for important usage", which also
// counts space the system itself can reclaim (purgeable caches, local snapshots it will thin). The OS's own
// low-disk warning uses the second, so we do too: there is no point offloading files because of space the
// system would have freed on its own.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace tierfs {

struct SpaceInfo {
    uint64_t total = 0;
    uint64_t avail_raw = 0;        // statvfs f_bavail
    uint64_t avail_important = 0;  // 0 when the OS gave no answer
    // The figure decisions use: the OS's own, never above the volume size.
    uint64_t avail() const {
        uint64_t a = avail_important ? avail_important : avail_raw;
        return total && a > total ? total : a;
    }
};

class SpaceProbe {
public:
    virtual ~SpaceProbe() = default;
    virtual SpaceInfo measure() = 0;
    // APFS local snapshots (Time Machine) keep deleted blocks alive, so deleting files may not free space.
    virtual int local_snapshots() { return 0; }
};

std::unique_ptr<SpaceProbe> make_system_probe(const std::string& path);

}  // namespace tierfs
