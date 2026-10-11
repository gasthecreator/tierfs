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

## Step 3 result: persistent chunk cache + readahead
Code: core/chunkcache.{hpp,cpp}, core/hash.hpp (CommonCrypto SHA-256),
core/sqlutil.hpp (shared SQLite wrappers), client rewrite in core/tierclient.cpp.

### Design
- 1 MiB chunks, one file each under `<cache>/chunks/ab/<sha256-of-key>.chk`, index
  in `<cache>/chunks.db` (path, idx, file size, file mtime, length, SHA-256, LRU tick).
- Key = (path, file size, file mtime, chunk index). A changed file can never be
  served stale chunks; getattr noticing a new version frees the old ones at once.
- Integrity: SHA-256 checked on every read. Bad chunk -> deleted -> refetch when
  online, EIO when offline. Never returned.
- Writes are temp-file + rename; startup sweep removes temp files, unindexed
  files and rows without files (crash recovery).
- LRU eviction under `cachesize=<MB>` (default 512), down to 90% of budget.
  Chunks of OPEN files are pinned (driver open/release) and never evicted.
- Protocol v2: READ reply carries the file's size+mtime, the backend checks them
  before and after pread. Without this, a file changing between stat and read would
  put new bytes in the cache under the old version's key. The client restarts a
  read that spans a version change, so results are never a blend of versions.
- Readahead: sequential reads queue the next 4 chunks; a pool of up to 4 worker
  threads, each with its OWN connection, prefetches them. (One prefetch stream was
  measured: no gain, a single stream is only as fast as the foreground one.)
- A read that fails part-way fails the WHOLE request. Returning the bytes copied
  so far looks like EOF to the kernel and silently truncates cp/cat/git.

### Verified
- `make test-unit`: chunk cache incl. corruption, eviction, pins, crash leftovers.
  Mutation-checked with 7 deliberate bugs, all caught.
- `make test-client` (ASan/UBSan) and `make test-tsan`: real backend process;
  caching, remount-offline, corruption, mid-read failure, version change, eviction +
  pinning, readahead, 6 concurrent readers with eviction. Clean under both.
- scripts/phase2b-test.sh through the mount: persistent cache serves a 6 MB file
  with the backend dead; cat/cp exit non-zero on a mid-file failure; clang compiles
  from the mount; git log, `git fsck --full`, `git clone` (packfiles are mmapped)
  work, and the clone works fully offline from the warm cache.
- Readahead, 12 chunks at 40 ms simulated latency, optimized build: 0.58 s -> 0.20 s.

### Honest limits / things learned
- The mount-level truncation test passes even with the old partial-return driver
  code, because the kernel asks for <=1 MiB per read, so that path never fires
  there. The CLIENT-level test (client_test.cpp) is what guards it (mutation-checked).
- Readahead speed-up depends on latency; on loopback with real work between reads
  the gain is small. Timings under the sanitizer builds are ~3x slower overall.
- Reads trust the cached (size, mtime) until getattr refreshes it (kernel does so
  every few seconds): same staleness window as NFS attribute caching.
- Chunks of deleted files are only freed when getattr/readdir sees the deletion
  at that path or LRU takes them; a listing that silently drops a child does not
  currently invalidate that child's chunks (bounded leak, LRU-collected).
- Test harness bugs found on the way: orphaned backend made "backend dead" a lie;
  a readiness probe was fooled by the offline root special case. Both fixed.
- Not tested: mmap of a file being modified, extremely large files (>4 GiB: chunk
  index is uint32, fine to 4 PiB, but untested), Finder rendering/Spotlight.

## Step 4 result: whole-request deadlines, cache lock, tierctl
- **Deadlines.** A socket timeout restarts on every byte, so a link trickling one byte
  at a time could hold a read open forever. Every request now has an absolute
  deadline: `timeout` plus payload size at a minimum rate of 256 KiB/s (so a 1 MiB
  READ gets timeout + 4 s). Slower counts as unreachable (EIO). Test: a fake server
  that answers correctly one byte per 120 ms: the client gives up at 0.50 s with
  ETIMEDOUT; without the deadline it succeeds after 3.6 s (mutation-checked).
- **One process per cache directory** (flock on `<cache>/lock`): a second mount of the
  same cache is refused instead of corrupting it, and `tierctl` cannot clear a
  mounted cache.
- **tierctl** (tools/tierctl.cpp): `cache-info` (read-only SQLite, safe on a live
  mount; deliberately does NOT open the cache classes because their startup sweep
  deletes "orphan" files, which would be wrong against a running process),
  `cache-verify` (re-hash everything, drop damaged chunks), `cache-clear [--yes]`
  (dry run by default; removes only files tierfs created, so a mistyped path cannot
  delete anything else; refuses folders that do not look like a cache).
- Test-harness hardening: backend output to /dev/null (an orphan used to hold the
  pipe open and make runs look hung), SIGPIPE ignored in the fake server.

Phase 2 is complete. Next: Phase 3 per docs/DURABLE_STORE.md, starting with 3a.
