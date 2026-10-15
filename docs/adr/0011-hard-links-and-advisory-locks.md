---
status: accepted
date: 2026-10-15
decision-makers: Gideon Sanni
---

# 0011. Hard links are kept off the offload path, and advisory locks are emulated in the daemon

## Context and Problem Statement
Programs use two things that a tiering filesystem does not get for free: hard links (`link(2)`, which `git`, `rsync -H`, backup tools and package managers use) and advisory locks
(`flock`, `fcntl(F_SETLK)`, which SQLite and many editors rely on). Until now the driver answered `link` with "not implemented" and had no lock hooks, so locking was whatever the
kernel's NFS-based FUSE-T layer did on its own (unknown, and untestable here without a mount).

The danger with hard links is specific: dropping a file MOVES its inode into quarantine. If another name still points at that inode, a write through the other name changes the
bytes in quarantine, the "last chance to undo" the drop.

## Decision Drivers
- Never weaken the quarantine guarantee, whatever programs do with links
- Programs that cannot get a hard link fall back to copying; that must keep working (a clean errno, no hang)
- Locks must not hang a program forever and must not need a mount to be tested
- The behaviour has to be testable without mounting anything (ADR-0006)

## Decision Outcome
**Hard links**
- `link` works for regular files. The second name is a separate tracked file (its own history on the devices); the first stays as it was. A source that is only on the devices
  is hydrated first, then linked. Directories and symlinks are refused (EPERM, which tools take as "no hard links here"), a destination that exists is EEXIST.
- A file whose inode has more than one name (`st_nlink > 1`) is never dropped (the drop engine refuses, the policy skips it and says why), so the quarantine can never share an inode
  with a live name. When the other names are gone it becomes droppable again. `st_nlink` is passed through to the programs that ask.

**Advisory locks** (emulated inside the daemon, `core/locks.*`)
- Byte-range locks (POSIX) and whole-file locks (flock) are kept in a table inside the overlay, per file identity and per lock owner (the FUSE `lock_owner`), with POSIX
  semantics: shared/exclusive, merging, splitting, conversion, release on close, unlock of a range. They work the same for local and offloaded files (a read lock does not hydrate).
- The core only ever TRIES a lock. Waiting (`F_SETLKW`, `flock` without `LOCK_NB`) is a polling loop in the C driver that stops when the kernel interrupts the request, so a stuck
  lock can be killed instead of hanging for good. There is no deadlock detection: two processes that deadlock wait until one is interrupted.
- Limits, stated plainly: locks are advisory and visible only to processes using the mount (not to one working directly in the origin folder); two hard-linked names are locked
  independently (they are different file identities); locks do not survive a daemon restart. Link counts are reported, but the mount does not give files stable inode numbers,
  so a tool that finds hard links by comparing inodes (`tar`, `rsync -H`, `du`) will see two separate files.

### Consequences
- Good: the quarantine guarantee holds with links; programs get real lock semantics inside the mount; every rule is unit-tested without a mount.
- Bad / trade-offs: hard-linked files are never offloaded; locking across the two names of a hard link is not coordinated; whether FUSE-T routes lock calls to the driver at all is unproven until a mount test (if it does not, the hooks are simply never called).

### Confirmation
`tests/locks_test.cpp` (the table, with every range case), `tests/overlay_ns_test.cpp` (link, lock through handles), `tests/dropengine_test.cpp`, `tests/policy_test.cpp`; mutation tests of each.

## More Information
Builds on ADR-0004 (move, then delete with quarantine) and ADR-0006 (no mount tests on the development machine).
