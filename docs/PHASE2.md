# Phase 2 (in progress): offline metadata and honest errors

## Step 1 result: why offline errors were wrong, and the fix
Symptom (Phase 1): backend down -> `cat` said "No such file or directory" (or
"Permission denied"), whatever errno the driver returned.

Cause: macOS re-does a lookup (our getattr) when FUSE-T's cached attributes
expire. FUSE-T is an NFS server underneath, and a *failed lookup* becomes
"not found" no matter which errno we return. Errno choice only matters once
lookup succeeds.

Fix: the client now keeps a metadata cache (attrs + directory listings), updated
on every successful reply and served only when the backend is unreachable.
Server `ENOENT` replies evict entries, so real deletions still show up.

Measured with scripts/errno-probe.sh (backend dead, file listed but never read):
- EIO       -> "Input/output error"   <- use this
- ESTALE    -> "Stale NFS file handle"
- ENXIO     -> "Device not configured"
- everything else collapses to "Input/output error"
So network failures are reported as EIO, which tools treat as an I/O fault, not
as a deleted file.

## Behaviours to remember
- macOS caches file *data* it has already read, so those files stay readable
  offline. Good for users; means "offline" tests must use never-read files.
- The same NFS attribute cache can hide backend changes for a few seconds.
- The metadata cache is in memory: lost on remount. Next step persists it in
  SQLite so a fresh mount works offline too.

## Remaining Phase 2 work
1. SQLite-backed metadata store (survives remount; also feeds the tiering
   policy's last-access tracking in Phase 3).
2. On-disk chunk cache: 1 MiB chunks keyed by (path, mtime, size, index), LRU
   eviction, byte budget, pinned while a file is open.
3. Sequential readahead.
4. Overall per-request deadline (see PHASE1.md item 6).
5. Test with real tools: git status/clone, a compile, Finder, mmap.
