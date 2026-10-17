---
status: accepted
date: 2026-10-16
decision-makers: Gideon Sanni
---

# 0017. A device keeps what it deleted for a while

## Context and Problem Statement
Garbage collection (ADR-0010) lets a Mac tell a device to delete manifests and to sweep chunks that no stored manifest lists. The device cannot read manifests (they are encrypted), so it
trusts the chunk list the Mac sends with each one: an authenticated Mac that lied or had a bug could make the device sweep chunks that a manifest needs. The deletion is final, and the
Mac may have dropped its local copy: data lost.

## Decision Drivers
- A bad sweep must be undoable, without trusting the Mac that caused it
- The device cannot decrypt anything, so it cannot check a chunk list itself
- Restoring must use the normal upload paths (nothing special to get wrong)
- Space must still come back, only later

## Considered Options
- Have the device verify chunk lists (impossible: it cannot read manifests)
- Two-phase sweep (mark, delete later): detects nothing, the data is still just gone later
- Keep deleted files for a retention period and put them back on request

## Decision Outcome
Chosen option: **a device trash.** `<store>/trash` holds what a deletion removed, for `--trash-days` (default 7; 0 makes deletions final at once):
- swept chunks: `trash/chunks/<chunk id>.<time>.blob`
- deleted manifests: `trash/manifests/<file id>/<version>.<time>.mf` and `.refs` (the manifest's chunk list, one chunk id a line; it was an index row, which is gone, so it is saved before the rows
  are deleted); stray leftovers of a crash go to the trash too (manifests among them have no list and cannot be restored).
- The index rows are deleted exactly as before (so the database triggers and the log are unchanged); only the files are moved instead of unlinked. Files are plain: nothing in the trash
  can be served, audited or listed, so the Mac's audits fail for a trashed chunk, which is how a wrong sweep is noticed.
- `tierfs-device <store> --list-trash | --restore-trash[=SECONDS] | --empty-trash` (the device must be stopped: the store is locked while it runs). **Restore** puts chunks back through
  `put_chunk` and manifests through `put_manifest` with their saved chunk list (a restored manifest is a new commit, so the Mac sees it), skips what is already back, and says why it skipped
  anything. The window `=SECONDS` limits it to what was trashed recently.
- Purge: at start, every hour, and after each sweep, everything older than the retention is removed for good. `GC_STATUS` reports `trash_files`, `trash_bytes` and the retention (appended to
  the reply; older clients ignore it), and `tierctl control <ledger> gc-run` says how much each device holds and when it goes.

### Consequences
- Good: a wrong sweep or a lying Mac costs a restore, not the data; the live store, its triggers and the protocol are unchanged; restore needs no new write path.
- Bad / trade-offs: freed space comes back after the retention period, not at once (set `--trash-days=0` to get the old behaviour); a restored manifest whose chunks were purged separately cannot
  come back (the restore says so); the trash is not encrypted differently from the rest (it holds the same sealed blobs); restore is an operator action on the device, not a Mac command.

### Confirmation
`tests/devicestore_test.cpp` (the trash, window, duplicates, missing and damaged chunk lists, foreign files, retention zero, strays), `tests/gc_test.cpp` ("a garbage collection can be undone": a real GC,
the device stopped, restore from the command line, everything verifies byte for byte again; `--empty-trash`; `--trash-days=0`), mutants in `scripts/devicestore_mutants.py` (`trash:`).
