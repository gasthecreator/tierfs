// Named crash points for fault injection.
//
// `TIERFS_CRASH_AT=<name>` makes the process die instantly (like `kill -9` or a
// power cut: no destructors, no flushing) when execution reaches the matching
// crash_point("<name>"). The test suite runs every offload scenario once per
// crash point, restarts, recovers, and checks the invariants. In normal runs the
// variable is unset and each call costs one getenv.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

namespace tierfs {

inline void crash_point(const char* name) {
    const char* want = getenv("TIERFS_CRASH_AT");
    if (want && strcmp(want, name) == 0) {
        fprintf(stderr, "tierfs: injected crash at %s\n", name);
        _exit(137);
    }
}

}  // namespace tierfs
