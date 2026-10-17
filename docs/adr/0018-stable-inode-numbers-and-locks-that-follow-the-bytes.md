---
status: accepted
date: 2026-10-17
decision-makers: Gideon Sanni
---

# 0018. Inode numbers that stay put, and locks that follow the bytes

## Context and Problem Statement
Two things made the mount less like a real filesystem than it should be:
- **Inode numbers.** The driver did not report `st_ino`, so the kernel used per-lookup node ids: not stable across a restart or a forgotten node, and the same for nothing in particular. An offloaded
  file's bytes in the origin are a different inode every time it is brought back, so even the origin's numbers are no help. Tools that compare `(device, inode)` (tar, rsync -H, find -samefile)
  cannot recognise hard links, and NFS-style clients (FUSE-T serves the mount through an NFS translation) lean on stable numbers.
- **Locks and hard links.** Each name of a hard-linked file is tracked as a file of its own (ADR-0011), and locks were keyed by file id, so two names of one file were locked separately.

## Decision Drivers
- A file keeps its number when it is renamed, offloaded and brought back, and across a restart
- All names of a hard-linked file show one number, as POSIX tools expect
- No new ledger state (a schema change and migration for this would be disproportionate)
- It must be testable without a mount

## Decision Outcome
- **Inode numbers** (`Overlay::file_inode`, `origin_inode`): a tracked file with one name has the number of its file id (a 64-bit value taken from a hash of it, never 0 or 1), so it is the same
  in the origin, on the devices, after a rename (the file id does not change) and after a restart. A file with several names, a directory, a symlink and anything the ledger does not track yet have the number
  of their place in the origin (device and inode), which is what makes hard links show one number. `getattr` and `readdir` give the same number for a name, and the driver passes it as `st_ino`
  and asks the kernel to use it (`-o use_ino`; `useino=0` turns that off).
- **Known consequence:** when a file gets its second name its number changes (file id → place in the origin) and changes back when one name is left. A program that has recorded the number across
  that moment sees a different one.
- **Locks**: a file with one name is locked under its file id (the same whether its bytes are in the origin or on the devices, and through a rename); a file with several names under the place of its bytes
  in the origin, which all its names share. When the second name is made, the locks held under the file id move to that place (`LockTable::rekey`), so a lock taken before `ln` still holds.

### Consequences
- Good: `(device, inode)` comparisons work, a file's number survives offload/hydrate/rename/restart, hard-linked names lock together; no ledger change.
- Bad / trade-offs: the number changes at the moment a second name is made or removed; locks taken under the old key while the last-but-one name is removed are not seen by handles opened afterwards
  (rare, and advisory anyway); a 64-bit hash could in principle collide (about one in 10^19 per pair); `-o use_ino` and `st_ino` are passed to FUSE-T but **not verified on a mount** (never mount-tested here, ADR-0006).
- Advisory locks stay advisory by nature: a program that bypasses the mount (works in the origin folder) is not held back by them. That is a property of advisory locks, not a gap to close.

### Confirmation
`tests/overlay_ns_test.cpp` ("inode numbers are stable": tracked, untracked, directories, links, listing equals getattr, rename, offload and hydrate, restart, hard links, one name left; hard-link locks, including a lock taken before the link),
`tests/locks_test.cpp` (rekey), mutants in `scripts/overlay_mutants.py` (`inode:`, `getattr:`, `readdir:`, `lock key:`, `link:`) and `scripts/locks_mutants.py` (`rekey:`).
