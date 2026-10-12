// The scanner: reconciles the ledger with what is really in the origin folder. See docs/DURABLE_STORE.md section 24.
//
// The overlay keeps the ledger in step with everything done THROUGH the mount. The scanner catches everything else: files created
// or edited while the mount was not running (or from another program that reaches the origin directly), files that vanished,
// attributes changed behind our back. It runs at start and periodically.
//
//   - a regular file in the origin that the ledger does not know is tracked (state LOCAL);
//   - a tracked file whose size or mtime differs from the ledger's is marked modified (its replication stops counting at once);
//     a differing mode is recorded too;
//   - a tracked file with local bytes that is no longer in the origin is "retired" (the user deleted it behind our back; nothing
//     on the devices is touched, and the file can still be recovered with `tierctl restore`);
//   - a file whose bytes are on the devices but that has ALSO appeared in the origin is reported, never resolved by guessing.
//
// Safety: it never deletes or overwrites anything in the origin; every decision is re-checked under the overlay's namespace lock
// (so it cannot race a rename); files with an open writer are skipped; and if a large share of the tracked files seems to be
// missing (the folder may simply be unmounted or on a disconnected drive) it forgets nothing and says so.
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "ledger.hpp"
#include "overlay.hpp"

namespace tierfs {

struct ScanOptions {
    bool track_new = true;
    bool retire_vanished = true;
    double max_vanished_fraction = 0.5;   // more than this share of the tracked local files missing: assume the folder is unavailable
    size_t vanished_floor = 10;           // ... but only when more than this many are missing (a handful is just a handful)
};

struct ScanReport {
    bool aborted = false;
    std::string abort_reason;
    size_t files_seen = 0, tracked_new = 0, marked_modified = 0, attrs_updated = 0, retired_vanished = 0, unchanged = 0;
    size_t skipped_busy = 0;                 // open for writing, or in the middle of a drop/hydration: looked at again next time
    std::vector<std::string> problems;       // things only a person can settle (never resolved by guessing)
    std::vector<std::string> actions;        // what was changed in the ledger, for the log
};

class Scanner {
public:
    Scanner(Ledger& ledger, Overlay& overlay) : ledger_(ledger), overlay_(overlay) {}
    ScanReport scan(const ScanOptions& opt = {});

    // Test hook: called at "walked" (the folder has been listed) and "rows" (the ledger's rows have been read), i.e. exactly where
    // the world can move on under a scan that works from those two snapshots.
    std::function<void(const char*)> on_step;

private:
    Ledger& ledger_;
    Overlay& overlay_;
};

}  // namespace tierfs
