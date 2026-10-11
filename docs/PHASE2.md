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
- The metadata cache is persistent (step 2 below).

## Step 2 result: persistent metadata cache (SQLite)
core/metastore.{hpp,cpp}; unit tests in tests/metastore_test.cpp (`make test-unit`),
mutation-checked (a boundary bug in subtree deletion was initially NOT caught and
the test was strengthened); integration tests in scripts/phase2-test.sh.

- Location: `-o cache=<dir>` -> `<dir>/meta.db` (WAL, synchronous=NORMAL).
- Tables: attrs, dirs (listing-complete marker), entries (parent/child).
- A listing replaces the old one atomically (one transaction); children that
  vanished are deleted with their whole subtree. Subtree = key range
  [p + "/", p + "0"), not LIKE, so names containing % _ ' are safe.
- It is a CACHE: corrupt file or wrong schema version -> deleted and rebuilt.
  Unopenable location -> runs with no cache. Phase 3's "only copy is on the
  device" state is NOT cache data and must go in a separate durable store.
- Last-access times are recorded on reads (max one write/minute/path) for the
  Phase 3 tiering policy. Refreshing metadata preserves them.

### Bugs this step found
1. **Cold offline mount hung forever.** No cache + dead backend -> getattr("/")
   failed -> `mount_nfs` blocked in uninterruptible state (needed kill -9).
   My own first test mislabelled this "mount refused, acceptable". Fix: the
   client answers getattr("/") itself when the backend is unreachable.
2. **Wrong error text.** A refused connection returned EHOSTUNREACH, which
   FUSE-T shows as "Permission denied" (readdir) or "No such file" (lookup).
   The driver now maps every network failure to EIO by default.
   (readdir errno table: EIO, ESTALE, ENXIO survive; most others become EACCES.)
3. A test that passed for the wrong reason earlier (`timeout` missing on macOS)
   taught us to assert on the error text, not just the exit code.

## Remaining Phase 2 work
1. On-disk chunk cache: 1 MiB chunks keyed by (path, mtime, size, index), LRU
   eviction, byte budget, pinned while a file is open.
2. Sequential readahead.
3. Overall per-request deadline (see PHASE1.md item 6).
4. Test with real tools: git status/clone, a compile, Finder, mmap.

## Finder check (driven via AppleScript, macOS 26.6.2)
Computer-use screen control was not available, so Finder was driven with
`osascript` against a live mount. Covered: listing (0.2 s vs 0.3 s for a normal
folder), opening a window, Finder "duplicate" of a 3 MB file out of the mount
(sha256 identical), no stray `.DS_Store`/`._*` files written onto the read-only
mount, offline listing instant, offline duplicate of a never-read file fails in
<1 s without hanging. NOT covered: icon/thumbnail/Quick Look rendering, Spotlight
indexing, drag-and-drop in the UI, and how errors look in Finder's dialogs.
